// Package deception 管理诱饵（P3-2）：诱饵路径、诱饵线索、诱饵账号与蜜罐地址。
//
// 诱饵不承载任何业务，正常用户不会碰到：
//   - 诱饵路径：放在站点上、不被任何页面引用的文件或接口（/backup_2026.zip、/.env.bak、/admin_old/）。访问它的来源在主动搜集信息；
//   - 诱饵线索：写在诱饵文件内容里的 URL、域名、接口密钥片段。只有读过诱饵的人才知道，之后使用它的任何地址都是同一个攻击者
//     （换了出口也一样），这些地址互相关联；
//   - 诱饵账号：不分配给任何人、写在诱饵文件或内存凭证里的账号。任何登录尝试都说明凭证已被窃取，使用同一账号的地址互相关联；
//   - 蜜罐地址：没有业务的地址或端口，任何连接都是扫描或横向移动；OpenCanary 等蜜罐自己的日志同样作为命中。
//
// 命中即高置信攻击者：流水线自动确认来源（之后的低危、中危命中升一级），告警等级不受误报校准影响。
// 配置文件中的诱饵与页面中维护的诱饵合并生效，命中记录与页面维护的诱饵保存在同一个文件中。
package deception

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"netsa/internal/config"
	"netsa/internal/model"
)

// 诱饵类型。
const (
	KindPath    = "path"
	KindToken   = "token"
	KindAccount = "account"
	KindHost    = "host"
)

// Category 是诱饵命中的分类。
const Category = "诱饵命中"

const (
	maxDecoys    = 500
	maxAttackers = 5000
	maxLinkIPs   = 200
	keepAttacker = 90 * 24 * time.Hour
	minTokenLen  = 6
)

var kindNames = map[string]string{KindPath: "诱饵路径", KindToken: "诱饵线索", KindAccount: "诱饵账号", KindHost: "蜜罐地址"}

// Decoy 是一个诱饵。
type Decoy struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Value   string    `json:"value"`
	Note    string    `json:"note,omitempty"`
	Creator string    `json:"creator,omitempty"`
	Created time.Time `json:"created"`
	Config  bool      `json:"config,omitempty"` // 来自配置文件（页面中只读）
	Hits    int64     `json:"hits"`
	Sources int       `json:"sources"` // 命中过的不同来源数
	LastHit time.Time `json:"last_hit,omitempty"`

	norm   string // 规范化的值（小写）
	prefix bool   // 路径以 * 结尾：前缀匹配
	net    netip.Prefix
	port   int
}

// Attacker 是命中过诱饵的来源。
type Attacker struct {
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Hits      int64     `json:"hits"`
	Decoys    []string  `json:"decoys"` // 命中的诱饵编号
	Internal  bool      `json:"internal,omitempty"`

	alerted map[string]time.Time // 诱饵 → 最近一次产生告警的时间（同一来源同一诱饵 24 小时内只告警一次）
}

// Manager 管理诱饵与命中记录，可并发匹配。
type Manager struct {
	mu        sync.Mutex
	path      string
	decoys    []*Decoy
	attackers map[string]*Attacker
	links     map[string]map[string]time.Time // 诱饵编号 → 使用过它的来源（线索、账号）
	table     atomic.Pointer[matchTable]
	dirty     bool
	now       func() time.Time
}

// matchTable 是匹配用的只读索引，诱饵变化时整体替换。
type matchTable struct {
	paths    map[string]*Decoy
	prefixes []*Decoy
	tokens   []*Decoy
	accounts map[string]*Decoy
	hosts    []*Decoy
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Load 读取配置中的诱饵与保存的文件（不存在时为空）。file 为空时只保存在内存中。
func Load(cfg config.DeceptionConfig, file string) (*Manager, error) {
	m := &Manager{path: file, attackers: map[string]*Attacker{}, links: map[string]map[string]time.Time{}, now: time.Now}
	if file != "" {
		data, err := os.ReadFile(file)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			var saved struct {
				Decoys    []*Decoy                        `json:"decoys"`
				Attackers []*Attacker                     `json:"attackers"`
				Links     map[string]map[string]time.Time `json:"links"`
			}
			if err := json.Unmarshal(data, &saved); err != nil {
				return nil, fmt.Errorf("解析 %s 失败: %w", file, err)
			}
			for _, d := range saved.Decoys {
				if d != nil && d.ID != "" && d.prepare() == nil {
					m.decoys = append(m.decoys, d)
				}
			}
			for _, a := range saved.Attackers {
				if a != nil && a.IP != "" {
					m.attackers[a.IP] = a
				}
			}
			for k, v := range saved.Links {
				if v != nil {
					m.links[k] = v
				}
			}
		}
	}
	// 配置文件中的诱饵：编号由类型与值决定，重启后命中统计不丢失
	stats := map[string]*Decoy{}
	var ui []*Decoy
	for _, d := range m.decoys {
		if d.Config {
			stats[d.ID] = d
		} else {
			ui = append(ui, d)
		}
	}
	m.decoys = ui
	add := func(kind string, values []string) error {
		for _, v := range values {
			d := &Decoy{Kind: kind, Value: strings.TrimSpace(v), Config: true}
			if err := d.prepare(); err != nil {
				return fmt.Errorf("deception.%ss: %w", kind, err)
			}
			d.ID = "cfg-" + kind + "-" + shortHash(d.norm)
			if old := stats[d.ID]; old != nil {
				d.Hits, d.Sources, d.LastHit, d.Created = old.Hits, old.Sources, old.LastHit, old.Created
			}
			m.decoys = append(m.decoys, d)
		}
		return nil
	}
	for _, x := range []struct {
		kind string
		vals []string
	}{{KindPath, cfg.Paths}, {KindToken, cfg.Tokens}, {KindAccount, cfg.Accounts}, {KindHost, cfg.Hosts}} {
		if err := add(x.kind, x.vals); err != nil {
			return nil, err
		}
	}
	m.reindexLocked()
	return m, nil
}

func shortHash(s string) string {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return strconv.FormatUint(h, 36)
}

// prepare 校验并规范化诱饵的值。
func (d *Decoy) prepare() error {
	v := strings.TrimSpace(d.Value)
	if v == "" || utf8.RuneCountInString(v) > 200 {
		return errors.New("诱饵的值不能为空，最长 200 个字符")
	}
	switch d.Kind {
	case KindPath:
		if !strings.HasPrefix(v, "/") {
			return fmt.Errorf("诱饵路径须以 / 开头: %s", v)
		}
		if strings.HasSuffix(v, "*") {
			d.prefix, v = true, strings.TrimSuffix(v, "*")
			if len(v) < 3 {
				return fmt.Errorf("前缀过短: %s", d.Value)
			}
		} else if v == "/" {
			return errors.New("诱饵路径不能是站点根目录")
		}
		d.norm = strings.ToLower(v)
	case KindToken:
		if len(v) < minTokenLen {
			return fmt.Errorf("诱饵线索至少 %d 个字符（太短会与正常请求重合）: %s", minTokenLen, v)
		}
		d.norm = strings.ToLower(v)
	case KindAccount:
		d.norm = baseUser(v)
		if len(d.norm) < 3 {
			return fmt.Errorf("诱饵账号过短: %s", v)
		}
	case KindHost:
		hostPart, port := v, 0
		if ap, err := netip.ParseAddrPort(v); err == nil {
			hostPart, port = ap.Addr().String(), int(ap.Port())
		} else if i := strings.LastIndexByte(v, ':'); i > 0 && strings.Contains(v[:i], "/") {
			if n, err := strconv.Atoi(v[i+1:]); err == nil && n > 0 && n < 65536 {
				hostPart, port = v[:i], n // 网段:端口
			}
		}
		p, err := netip.ParsePrefix(hostPart)
		if err != nil {
			a, aerr := netip.ParseAddr(hostPart)
			if aerr != nil {
				return fmt.Errorf("蜜罐地址无效（地址、网段或 地址:端口）: %s", v)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4() && p.Bits() < 24 || p.Addr().Is6() && p.Bits() < 64 {
			return fmt.Errorf("蜜罐网段过大（IPv4 至少 /24）: %s", v)
		}
		d.net, d.port, d.norm = p.Masked(), port, strings.ToLower(v)
	default:
		return fmt.Errorf("未知的诱饵类型 %q", d.Kind)
	}
	d.Value = v
	if d.Kind == KindPath && d.prefix {
		d.Value = v + "*"
	}
	return nil
}

// baseUser 去掉账号的域前缀与后缀（CORP\backup_admin、backup_admin@corp.local），转为小写。
func baseUser(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i > 0 {
		u = u[:i]
	}
	return u
}

func (m *Manager) reindexLocked() {
	t := &matchTable{paths: map[string]*Decoy{}, accounts: map[string]*Decoy{}}
	for _, d := range m.decoys {
		switch d.Kind {
		case KindPath:
			if d.prefix {
				t.prefixes = append(t.prefixes, d)
			} else {
				t.paths[d.norm] = d
			}
		case KindToken:
			t.tokens = append(t.tokens, d)
		case KindAccount:
			t.accounts[d.norm] = d
			t.tokens = append(t.tokens, d) // Web 请求中带着诱饵账号（登录表单、接口参数）
		case KindHost:
			t.hosts = append(t.hosts, d)
		}
	}
	m.table.Store(t)
}

// Match 检查事件是否命中诱饵，返回命中（每个事件最多一条）并记录来源。
func (m *Manager) Match(ev *model.Event) []model.Hit {
	if m == nil || ev == nil {
		return nil
	}
	t := m.table.Load()
	if t == nil {
		return nil
	}
	d, how := t.match(ev)
	if d == nil {
		return nil
	}
	src := ev.SrcIP
	if ev.SubjectHost {
		src = ev.DstIP
	}
	internal := isPrivate(src)
	h := model.Hit{RuleID: "decoy-" + d.Kind, Category: Category, Phase: model.PhaseRecon, Result: model.ResultUnknown, Severity: model.SevHigh}
	who := src
	if internal {
		who = "内网主机 " + src
	}
	switch d.Kind {
	case KindPath:
		h.Name = "访问诱饵路径"
		h.Evidence = fmt.Sprintf("%s 访问了诱饵路径 %s（%s；该路径不被任何页面引用，正常访客不会访问）", who, d.Value, how)
		if ev.Status >= 200 && ev.Status < 300 {
			h.Evidence += "，已取得诱饵内容"
		}
	case KindToken:
		h.Name, h.Phase = "使用诱饵线索", model.PhaseExploit
		h.Severity = model.SevCritical
		h.Evidence = fmt.Sprintf("%s %s诱饵线索 %s（只有读过诱饵内容的人才知道）", who, how, d.Value)
	case KindAccount:
		h.Name, h.Phase = "使用诱饵账号", model.PhaseExploit
		h.Evidence = fmt.Sprintf("%s %s诱饵账号 %s（该账号不分配给任何人：凭证已被窃取）", who, how, d.Value)
		if ev.Kind == model.KindAuth && ev.Action == model.ActionAllow {
			h.Severity, h.Result = model.SevCritical, model.ResultSuccess
			h.Evidence += "，登录成功"
		}
	case KindHost:
		h.Name = "连接蜜罐"
		h.Evidence = fmt.Sprintf("%s %s（蜜罐没有任何业务，连接即扫描或横向移动）", who, how)
		if internal {
			h.Phase = model.PhaseExploit // 内网主机扫描蜜罐：横向移动
		} else {
			h.Severity = model.SevMedium
		}
	}
	if d.Note != "" {
		h.Evidence += "；诱饵说明：" + d.Note
	}
	if !m.record(d, src, internal, ev.Time) {
		// 同一来源反复访问同一诱饵：只标记来源，不重复告警
		h.TagOnly, h.Evidence = true, d.Value
	}
	return []model.Hit{h}
}

func (t *matchTable) match(ev *model.Event) (*Decoy, string) {
	if ev.Format == "opencanary" {
		return &Decoy{ID: "opencanary", Kind: KindHost, Value: ev.DstIP}, fmt.Sprintf("触发蜜罐 %s:%d（OpenCanary %s）", ev.DstIP, ev.DstPort, ev.Service)
	}
	switch ev.Kind {
	case model.KindWeb:
		if len(t.paths) > 0 || len(t.prefixes) > 0 {
			p := ev.URI
			if i := strings.IndexByte(p, '?'); i >= 0 {
				p = p[:i]
			}
			if u, err := url.PathUnescape(p); err == nil {
				p = u
			}
			p = strings.ToLower(p)
			if d := t.paths[p]; d != nil {
				return d, ev.Method + " " + ev.Host + p
			}
			if d := t.paths[strings.TrimSuffix(p, "/")]; d != nil && len(p) > 1 {
				return d, ev.Method + " " + ev.Host + p
			}
			for _, d := range t.prefixes {
				if strings.HasPrefix(p, d.norm) {
					return d, ev.Method + " " + ev.Host + p
				}
			}
		}
		if len(t.tokens) > 0 {
			text := strings.ToLower(ev.URI + "\n" + ev.Body + "\n" + ev.Referer + "\n" + ev.UA + "\n" + ev.Host)
			if u, err := url.QueryUnescape(text); err == nil {
				text = u
			}
			for _, d := range t.tokens {
				if d.Kind == KindAccount {
					if accountIn(text, d.norm) {
						return d, "在请求中使用了"
					}
					continue
				}
				if strings.Contains(text, d.norm) {
					return d, "在请求 " + ev.Host + truncate(ev.URI, 80) + " 中使用了"
				}
			}
		}
	case model.KindAuth, model.KindProcess:
		if d := t.accounts[baseUser(ev.User)]; d != nil && ev.User != "" {
			svc := ev.Service
			if svc == "" {
				svc = "登录"
			}
			return d, "以 " + svc + " 方式使用了"
		}
	case model.KindDNS:
		for _, d := range t.tokens {
			if d.Kind == KindToken && strings.Contains(strings.ToLower(ev.Host), d.norm) {
				return d, "解析了含有"
			}
		}
	}
	if (ev.Kind == model.KindFirewall || ev.Kind == model.KindWeb) && len(t.hosts) > 0 && ev.DstIP != "" && !ev.Aux {
		a, err := netip.ParseAddr(ev.DstIP)
		if err != nil {
			return nil, ""
		}
		a = a.Unmap()
		for _, d := range t.hosts {
			if d.net.Contains(a) && (d.port == 0 || d.port == ev.DstPort) {
				return d, fmt.Sprintf("连接蜜罐 %s:%d/%s", ev.DstIP, ev.DstPort, ev.Proto)
			}
		}
	}
	return nil, ""
}

// accountIn 判断请求中是否以参数值的形式出现了诱饵账号（user=backup_admin、"username":"backup_admin"）。
func accountIn(text, acct string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], acct)
		if j < 0 {
			return false
		}
		j += i
		before := byte('=')
		if j > 0 {
			before = text[j-1]
		}
		after := byte('&')
		if e := j + len(acct); e < len(text) {
			after = text[e]
		}
		if (before == '=' || before == '"' || before == ':' || before == '\'' || before == '/') && (after == '&' || after == '"' || after == '\'' ||
			after == '\n' || after == ' ' || after == ',' || after == '}' || after == '@' || after == '%') {
			return true
		}
		i = j + 1
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func isPrivate(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && (a.Unmap().IsPrivate() || a.IsLoopback())
}

// record 记录一次命中，返回是否应产生告警（同一来源同一诱饵 24 小时内的第一次）。
func (m *Manager) record(d *Decoy, src string, internal bool, t time.Time) bool {
	if t.IsZero() || t.After(m.now().Add(time.Hour)) {
		t = m.now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirty = true
	if d.ID != "opencanary" {
		d.Hits++
		if t.After(d.LastHit) {
			d.LastHit = t
		}
	}
	if src == "" {
		return true
	}
	a := m.attackers[src]
	if a == nil {
		if len(m.attackers) >= maxAttackers {
			m.pruneLocked(m.now())
			if len(m.attackers) >= maxAttackers {
				return true
			}
		}
		a = &Attacker{IP: src, FirstSeen: t, LastSeen: t, Internal: internal}
		m.attackers[src] = a
	}
	a.Hits++
	if t.Before(a.FirstSeen) {
		a.FirstSeen = t
	}
	if t.After(a.LastSeen) {
		a.LastSeen = t
	}
	known := false
	for _, x := range a.Decoys {
		known = known || x == d.ID
	}
	if !known && len(a.Decoys) < 20 {
		a.Decoys = append(a.Decoys, d.ID)
		if d.ID != "opencanary" {
			d.Sources++
		}
	}
	// 线索与账号只有拿到诱饵的人才知道：使用同一个的来源互相关联
	if d.Kind == KindToken || d.Kind == KindAccount {
		l := m.links[d.ID]
		if l == nil {
			l = map[string]time.Time{}
			m.links[d.ID] = l
		}
		if _, ok := l[src]; ok || len(l) < maxLinkIPs {
			l[src] = t
		}
	}
	if a.alerted == nil {
		a.alerted = map[string]time.Time{}
	}
	if last, ok := a.alerted[d.ID]; ok && t.Sub(last).Abs() < 24*time.Hour {
		return false
	}
	a.alerted[d.ID] = t
	return true
}

// Links 返回使用同一诱饵线索或诱饵账号的来源（至少两个），键为“诱饵类型 值”，供同源关联与攻击活动归并。
func (m *Manager) Links() map[string][]string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	byID := map[string]*Decoy{}
	for _, d := range m.decoys {
		byID[d.ID] = d
	}
	out := map[string][]string{}
	for id, l := range m.links {
		d := byID[id]
		if d == nil || len(l) < 2 {
			continue
		}
		ips := make([]string, 0, len(l))
		for ip := range l {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		out[kindNames[d.Kind]+" "+d.Value] = ips
	}
	return out
}

// IsAttacker 判断来源是否命中过诱饵。
func (m *Manager) IsAttacker(ip string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.attackers[ip]
	return ok
}

// Status 是诱饵的运行状态。
type Status struct {
	Decoys    []Decoy    `json:"decoys"`
	Attackers []Attacker `json:"attackers"`
	Links     []Link     `json:"links"`
	Total     int64      `json:"total"` // 累计命中次数
}

// Link 是使用同一诱饵的一组来源。
type Link struct {
	Decoy string   `json:"decoy"`
	IPs   []string `json:"ips"`
}

// List 返回诱饵、命中过诱饵的来源（最近的在前，最多 500 个）与关联。
func (m *Manager) List() Status {
	var st Status
	if m == nil {
		return st
	}
	links := m.Links()
	m.mu.Lock()
	for _, d := range m.decoys {
		st.Decoys = append(st.Decoys, *d)
		st.Total += d.Hits
	}
	for _, a := range m.attackers {
		x := *a
		x.Decoys = append([]string(nil), a.Decoys...)
		st.Attackers = append(st.Attackers, x)
	}
	m.mu.Unlock()
	sort.Slice(st.Decoys, func(i, j int) bool {
		if st.Decoys[i].Kind != st.Decoys[j].Kind {
			return st.Decoys[i].Kind < st.Decoys[j].Kind
		}
		return st.Decoys[i].Value < st.Decoys[j].Value
	})
	sort.Slice(st.Attackers, func(i, j int) bool { return st.Attackers[i].LastSeen.After(st.Attackers[j].LastSeen) })
	if len(st.Attackers) > 500 {
		st.Attackers = st.Attackers[:500]
	}
	keys := make([]string, 0, len(links))
	for k := range links {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		st.Links = append(st.Links, Link{Decoy: k, IPs: links[k]})
	}
	return st
}

// Add 增加一个诱饵（页面维护）。
func (m *Manager) Add(kind, value, note, creator string) (Decoy, error) {
	d := &Decoy{Kind: kind, Value: value, Note: strings.TrimSpace(note), Creator: creator}
	if utf8.RuneCountInString(d.Note) > 200 {
		return Decoy{}, errors.New("说明最长 200 个字符")
	}
	if err := d.prepare(); err != nil {
		return Decoy{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.decoys) >= maxDecoys {
		return Decoy{}, fmt.Errorf("诱饵最多 %d 个", maxDecoys)
	}
	for _, x := range m.decoys {
		if x.Kind == d.Kind && x.norm == d.norm {
			return Decoy{}, fmt.Errorf("已经登记过该诱饵: %s", x.Value)
		}
	}
	d.ID, d.Created = newID(), m.now()
	m.decoys = append(m.decoys, d)
	m.reindexLocked()
	m.dirty = true
	return *d, m.saveLocked()
}

// Delete 删除页面维护的诱饵（配置文件中的诱饵只能在配置中删除）。
func (m *Manager) Delete(id string) (Decoy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, d := range m.decoys {
		if d.ID != id {
			continue
		}
		if d.Config {
			return Decoy{}, errors.New("配置文件中的诱饵请在配置文件中删除")
		}
		m.decoys = append(m.decoys[:i], m.decoys[i+1:]...)
		delete(m.links, id)
		m.reindexLocked()
		m.dirty = true
		return *d, m.saveLocked()
	}
	return Decoy{}, errors.New("诱饵不存在")
}

// Count 返回诱饵数。
func (m *Manager) Count() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.decoys)
}

// Flush 保存有变化的命中记录。
func (m *Manager) Flush() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dirty {
		return nil
	}
	m.pruneLocked(m.now())
	return m.saveLocked()
}

func (m *Manager) pruneLocked(now time.Time) {
	for k, a := range m.attackers {
		if now.Sub(a.LastSeen) > keepAttacker {
			delete(m.attackers, k)
		}
	}
	for id, l := range m.links {
		for ip, t := range l {
			if now.Sub(t) > keepAttacker {
				delete(l, ip)
			}
		}
		if len(l) == 0 {
			delete(m.links, id)
		}
	}
}

func (m *Manager) saveLocked() error {
	m.dirty = false
	if m.path == "" {
		return nil
	}
	attackers := make([]*Attacker, 0, len(m.attackers))
	for _, a := range m.attackers {
		attackers = append(attackers, a)
	}
	data, err := json.Marshal(struct {
		Decoys    []*Decoy                        `json:"decoys"`
		Attackers []*Attacker                     `json:"attackers"`
		Links     map[string]map[string]time.Time `json:"links"`
	}{m.decoys, attackers, m.links})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}
