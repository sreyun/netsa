package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
)

const (
	maxFeedBytes   = 256 << 20 // 单次拉取的响应上限
	maxFeedEntries = 2_000_000
	maxTAXIIPages  = 200
	feedTimeout    = 2 * time.Minute
)

// FeedStatus 是一个情报源的状态。
type FeedStatus struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Kind      string    `json:"kind,omitempty"`
	Addrs     int       `json:"addrs"`
	Nets      int       `json:"nets"`
	Domains   int       `json:"domains"`
	Skipped   int       `json:"skipped"` // 因不安全而丢弃的条目（内网地址、过宽的网段）
	Updated   time.Time `json:"updated,omitzero"`
	LastError string    `json:"last_error,omitempty"`
}

type feeds struct {
	mu     sync.Mutex
	status map[string]*FeedStatus
}

// FeedStatuses 返回情报源状态。
func (db *DB) FeedStatuses() []FeedStatus {
	db.feeds.mu.Lock()
	defer db.feeds.mu.Unlock()
	out := make([]FeedStatus, 0, len(db.feeds.status))
	for _, s := range db.feeds.status {
		out = append(out, *s)
	}
	return out
}

// entrySet 累积情报条目。外部情报可能出错或被投毒，一条 0.0.0.0/0 或内网网段就会把所有流量标记为恶意：
// 内网和保留地址、短于 /8（IPv6 /32）的网段都丢弃；域名的过滤见 domain.go。
type entrySet struct {
	l       *list
	allow   map[string]bool
	skipped int
	// local 表示管理员维护的本地文件：IP 按原样生效（可以有意写内网地址），域名仍做公共平台过滤
	local bool
}

func newEntrySet(name string, allow map[string]bool) *entrySet {
	return &entrySet{l: &list{name: name, addrs: map[netip.Addr]bool{}, domains: map[string]struct{}{}}, allow: allow}
}

func (s *entrySet) size() int { return len(s.l.addrs) + s.l.count + len(s.l.domains) }

// hostsSink 是 hosts 文件中把恶意域名指向的“黑洞”地址：0.0.0.0 evil.example。
var hostsSink = map[string]bool{"0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true}

// addLine 解析文本情报的一行：IP、网段、域名、URL，或 hosts 文件格式。# 与 ; 之后为注释。
func (s *entrySet) addLine(line string) {
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	switch {
	case len(f) == 0:
	case len(f) >= 2 && hostsSink[f[0]]:
		s.addDomain(f[1])
	default:
		s.addIndicator(f[0])
	}
}

// addIndicator 按内容判断条目是 IP / 网段、URL 还是域名。
func (s *entrySet) addIndicator(v string) {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if v == "" {
		return
	}
	if h := urlHost(v); h != "" {
		v = strings.Trim(h, "[]")
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		s.add(v)
		return
	}
	if _, err := netip.ParseAddr(v); err == nil {
		s.add(v)
		return
	}
	s.addDomain(v)
}

func (s *entrySet) addDomain(v string) {
	if s.size() >= maxFeedEntries {
		return
	}
	if d := normDomain(v, s.allow); d != "" {
		s.l.domains[d] = struct{}{}
		return
	}
	s.skipped++
}

func (s *entrySet) add(v string) {
	v = strings.TrimSpace(v)
	if v == "" || s.size() >= maxFeedEntries {
		return
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		a, aerr := netip.ParseAddr(v)
		if aerr != nil {
			s.skipped++
			return
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	a := p.Addr().Unmap()
	min := 8
	if a.Is6() {
		min = 32
	}
	if !s.local && (a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || p.Bits() < min) {
		s.skipped++
		return
	}
	if p.IsSingleIP() {
		s.l.addrs[a] = true
		return
	}
	s.l.addPrefix(netip.PrefixFrom(a, p.Bits()).Masked())
}

// STIX 指标的模式中取出 IP、域名与 URL：[ipv4-addr:value = '198.51.100.1'] OR [domain-name:value = 'evil.example']。
var stixIPRe = regexp.MustCompile(`(ipv[46]-addr|domain-name|url):value\s*(?:=|IN|ISSUBSET)\s*\(?\s*'([^']+)'((?:\s*,\s*'[^']+')*)`)
var stixQuotedRe = regexp.MustCompile(`'([^']+)'`)

type stixObject struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Pattern    string `json:"pattern"`
	Revoked    bool   `json:"revoked"`
	ValidUntil string `json:"valid_until"`
	Confidence *int   `json:"confidence"`
}

func addSTIXObjects(s *entrySet, objs []stixObject, minConf int, now time.Time) {
	for _, o := range objs {
		switch o.Type {
		case "ipv4-addr", "ipv6-addr":
			s.add(o.Value)
		case "domain-name":
			s.addDomain(o.Value)
		case "url":
			s.addIndicator(o.Value)
		case "indicator":
			if o.Revoked || (minConf > 0 && (o.Confidence == nil || *o.Confidence < minConf)) {
				continue
			}
			if o.ValidUntil != "" {
				if t, err := time.Parse(time.RFC3339, o.ValidUntil); err == nil && now.After(t) {
					continue
				}
			}
			for _, m := range stixIPRe.FindAllStringSubmatch(o.Pattern, -1) {
				s.addIndicator(m[2])
				for _, q := range stixQuotedRe.FindAllStringSubmatch(m[3], -1) {
					s.addIndicator(q[1])
				}
			}
		}
	}
}

func parseSTIX(s *entrySet, body []byte, minConf int, now time.Time) error {
	var b struct {
		Type    string       `json:"type"`
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return fmt.Errorf("不是有效的 STIX: %w", err)
	}
	if b.Type != "" && b.Type != "bundle" {
		return fmt.Errorf("不是 STIX bundle: %q", b.Type)
	}
	addSTIXObjects(s, b.Objects, minConf, now)
	return nil
}

func parseMISP(s *entrySet, body []byte) error {
	var r struct {
		Response struct {
			Attribute []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
				ToIDS bool   `json:"to_ids"`
			} `json:"Attribute"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("不是有效的 MISP 响应: %w", err)
	}
	for _, a := range r.Response.Attribute {
		if !a.ToIDS {
			continue
		}
		switch a.Type {
		case "ip-src", "ip-dst":
			s.add(a.Value)
		case "ip-src|port", "ip-dst|port":
			v, _, _ := strings.Cut(a.Value, "|")
			s.add(v)
		case "domain", "hostname":
			s.addDomain(a.Value)
		case "domain|ip":
			d, ip, _ := strings.Cut(a.Value, "|")
			s.addDomain(d)
			s.add(ip)
		case "url":
			s.addIndicator(a.Value)
		}
	}
	return nil
}

func parseText(s *entrySet, body []byte) {
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		s.addLine(string(line))
	}
}

// fetcher 拉取一个情报源。
type fetcher struct {
	cfg    config.IntelFeedConfig
	token  string
	client *http.Client
	allow  map[string]bool
}

func (f *fetcher) do(ctx context.Context, method, u, accept string, body []byte) ([]byte, http.Header, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", accept)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if f.token != "" {
		switch {
		case f.cfg.TokenHeader != "":
			req.Header.Set(f.cfg.TokenHeader, f.token)
		case f.cfg.Type == "misp":
			req.Header.Set("Authorization", f.token)
		default:
			req.Header.Set("Authorization", "Bearer "+f.token)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxFeedBytes {
		return nil, nil, errors.New("响应超过大小上限")
	}
	return data, resp.Header, nil
}

const taxiiAccept = "application/taxii+json;version=2.1"

// fetchTAXII 分页拉取 TAXII 2.1 集合的 objects。
func (f *fetcher) fetchTAXII(ctx context.Context, s *entrySet, now time.Time) error {
	next := ""
	for page := 0; page < maxTAXIIPages; page++ {
		u, err := url.Parse(f.cfg.URL)
		if err != nil {
			return err
		}
		q := u.Query()
		q.Set("match[type]", "indicator,ipv4-addr,ipv6-addr,domain-name,url")
		if next != "" {
			q.Set("next", next)
		}
		u.RawQuery = q.Encode()
		data, _, err := f.do(ctx, http.MethodGet, u.String(), taxiiAccept, nil)
		if err != nil {
			return err
		}
		var env struct {
			More    bool         `json:"more"`
			Next    string       `json:"next"`
			Objects []stixObject `json:"objects"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			return fmt.Errorf("不是有效的 TAXII 响应: %w", err)
		}
		addSTIXObjects(s, env.Objects, f.cfg.MinConfidence, now)
		if !env.More || env.Next == "" {
			return nil
		}
		next = env.Next
	}
	return fmt.Errorf("TAXII 分页超过 %d 页", maxTAXIIPages)
}

func (f *fetcher) fetch(ctx context.Context, now time.Time) (*entrySet, error) {
	s := newEntrySet(f.cfg.Name, f.allow)
	s.l.kind = f.cfg.Kind
	switch f.cfg.Type {
	case "taxii":
		if err := f.fetchTAXII(ctx, s, now); err != nil {
			return nil, err
		}
	case "misp":
		body, _ := json.Marshal(map[string]any{"returnFormat": "json", "type": []string{"ip-src", "ip-dst", "ip-src|port", "ip-dst|port",
			"domain", "hostname", "domain|ip", "url"}, "to_ids": true, "enforceWarninglist": true})
		data, _, err := f.do(ctx, http.MethodPost, strings.TrimRight(f.cfg.URL, "/")+"/attributes/restSearch", "application/json", body)
		if err != nil {
			return nil, err
		}
		if err := parseMISP(s, data); err != nil {
			return nil, err
		}
	case "stix":
		data, _, err := f.do(ctx, http.MethodGet, f.cfg.URL, "application/json", nil)
		if err != nil {
			return nil, err
		}
		if err := parseSTIX(s, data, f.cfg.MinConfidence, now); err != nil {
			return nil, err
		}
	default:
		data, _, err := f.do(ctx, http.MethodGet, f.cfg.URL, "text/plain", nil)
		if err != nil {
			return nil, err
		}
		parseText(s, data)
	}
	return s, nil
}

// setFeedList 替换同名的情报列表。
func (db *DB) setFeedList(l *list) {
	db.mu.Lock()
	defer db.mu.Unlock()
	for i, cur := range db.lists {
		if cur.name == l.name {
			db.lists[i] = l
			return
		}
	}
	db.lists = append(db.lists, l)
}

func feedCachePath(dir, name string) string {
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)
	return filepath.Join(dir, safe+".txt")
}

func writeFeedCache(path string, l *list) error {
	var b bytes.Buffer
	for a := range l.addrs {
		b.WriteString(a.String())
		b.WriteByte('\n')
	}
	for _, m := range l.nets {
		for p := range m {
			b.WriteString(p.String())
			b.WriteByte('\n')
		}
	}
	for d := range l.domains {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// StartFeeds 启动在线情报源：先加载上次的缓存（情报服务暂时不可用时检测能力不丢失），然后定期更新。
// 拉取失败时保留旧数据。
func (db *DB) StartFeeds(ctx context.Context, cfgs []config.IntelFeedConfig, cacheDir string) {
	db.feeds.mu.Lock()
	if db.feeds.status == nil {
		db.feeds.status = map[string]*FeedStatus{}
	}
	db.feeds.mu.Unlock()
	for _, c := range cfgs {
		f := &fetcher{cfg: c, client: &http.Client{Timeout: feedTimeout}, allow: db.allow}
		if c.TokenEnv != "" {
			f.token = os.Getenv(c.TokenEnv)
		}
		st := &FeedStatus{Name: c.Name, Type: c.Type, Kind: c.Kind}
		db.feeds.mu.Lock()
		db.feeds.status[c.Name] = st
		db.feeds.mu.Unlock()
		cache := ""
		if cacheDir != "" {
			cache = feedCachePath(cacheDir, c.Name)
			if file, err := os.Open(cache); err == nil {
				l, _ := readList(c.Name, file, db.allow, false)
				file.Close()
				l.kind = c.Kind
				db.setFeedList(l)
				db.feeds.mu.Lock()
				st.Addrs, st.Nets, st.Domains = len(l.addrs), l.count, len(l.domains)
				db.feeds.mu.Unlock()
			}
		}
		interval := c.Interval
		if interval <= 0 {
			interval = time.Hour
		}
		go func() {
			db.refreshFeed(ctx, f, st, cache)
			tick := time.NewTicker(interval)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					db.refreshFeed(ctx, f, st, cache)
				}
			}
		}()
	}
}

func (db *DB) refreshFeed(ctx context.Context, f *fetcher, st *FeedStatus, cache string) {
	s, err := f.fetch(ctx, time.Now())
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Printf("[intel] 更新情报源 %s 失败（继续使用旧数据）: %v", f.cfg.Name, err)
		db.feeds.mu.Lock()
		st.LastError = err.Error()
		db.feeds.mu.Unlock()
		return
	}
	db.setFeedList(s.l)
	if cache != "" {
		if err := writeFeedCache(cache, s.l); err != nil {
			log.Printf("[intel] 保存情报源缓存失败: %v", err)
		}
	}
	db.feeds.mu.Lock()
	st.Addrs, st.Nets, st.Domains, st.Skipped, st.Updated, st.LastError = len(s.l.addrs), s.l.count, len(s.l.domains), s.skipped, time.Now(), ""
	db.feeds.mu.Unlock()
	log.Printf("[intel] 情报源 %s 已更新：%s 个 IP、%s 个网段、%s 个域名（丢弃 %d 条不安全的条目）", f.cfg.Name,
		strconv.Itoa(len(s.l.addrs)), strconv.Itoa(s.l.count), strconv.Itoa(len(s.l.domains)), s.skipped)
}
