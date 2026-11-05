// Package intel 提供本地威胁情报匹配（IP / 网段 / 域名黑名单、Tor 出口节点）与 rDNS 身份识别。
package intel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
)

// 情报类别：决定命中时的分类与等级（见 store 的情报命中与 pipeline 的域名情报）。
const (
	KindDefault  = ""         // 通用黑名单：按原有方式处理
	KindC2       = "c2"       // 远控 / 僵尸网络控制端：内网主机连接、解析即为失陷迹象
	KindMalware  = "malware"  // 恶意软件投递：连接、解析说明主机可能下载了恶意文件
	KindPhishing = "phishing" // 钓鱼网站
	KindMining   = "mining"   // 矿池
	KindAttacker = "attacker" // 扫描、暴力破解来源：只说明信誉，不单独构成高危
)

// ValidKind 判断情报类别是否有效。
func ValidKind(k string) bool {
	switch k {
	case KindDefault, KindC2, KindMalware, KindPhishing, KindMining, KindAttacker:
		return true
	}
	return false
}

type list struct {
	name    string
	kind    string
	domains map[string]struct{}
	addrs   map[netip.Addr]bool
	// 网段按前缀长度分组：查询时只需对出现过的每种长度做一次掩码与哈希查找（IPv4 最多 32 次），
	// 与网段数量无关。出站流量逐条比对情报时，数千条网段的情报库也不会成为瓶颈。
	nets  map[int]map[netip.Prefix]struct{}
	bits  []int // nets 中出现过的前缀长度
	count int   // 网段数
}

func (l *list) addPrefix(p netip.Prefix) {
	if l.nets == nil {
		l.nets = map[int]map[netip.Prefix]struct{}{}
	}
	m := l.nets[p.Bits()]
	if m == nil {
		m = map[netip.Prefix]struct{}{}
		l.nets[p.Bits()] = m
		l.bits = append(l.bits, p.Bits())
	}
	if _, ok := m[p]; !ok {
		m[p] = struct{}{}
		l.count++
	}
}

func (l *list) contains(a netip.Addr) bool {
	if l.addrs[a] {
		return true
	}
	for _, b := range l.bits {
		if b > a.BitLen() {
			continue
		}
		if p, err := a.Prefix(b); err == nil {
			if _, ok := l.nets[b][p]; ok {
				return true
			}
		}
	}
	return false
}

// DB 是情报库，可并发查询。
type DB struct {
	mu    sync.RWMutex
	lists []*list
	tor   map[netip.Addr]bool
	feeds feeds
	allow map[string]bool // 本单位域名：域名情报中等于或位于其下的条目丢弃
}

// Load 加载配置中的黑名单文件（每行一个 IP、网段或域名，# 开头为注释）。
func Load(cfg config.IntelConfig) (*DB, error) {
	db := &DB{tor: map[netip.Addr]bool{}, allow: map[string]bool{}}
	for _, d := range cfg.DomainAllowlist {
		if d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*."); d != "" {
			db.allow[strings.TrimSuffix(d, ".")] = true
		}
	}
	for _, bl := range cfg.Blocklists {
		f, err := os.Open(bl.Path)
		if err != nil {
			log.Printf("[intel] 跳过情报文件 %s: %v", bl.Path, err)
			continue
		}
		l, _ := readList(bl.Name, f, db.allow, true)
		f.Close()
		l.kind = bl.Kind
		log.Printf("[intel] 已加载 %s: %d 个IP, %d 个网段, %d 个域名", bl.Name, len(l.addrs), l.count, len(l.domains))
		db.lists = append(db.lists, l)
	}
	return db, nil
}

// readList 逐行解析情报列表（IP、网段、域名、URL、hosts 文件格式）；读取中断（网络断开、超长行）时返回已解析的部分与错误。
// local 为管理员维护的本地文件：IP 按原样生效；在线情报的缓存与 Tor 列表丢弃内网、保留地址与过宽的网段。
// 域名一律过滤公共平台与内网后缀。
func readList(name string, r io.Reader, allow map[string]bool, local bool) (*list, error) {
	s := newEntrySet(name, allow)
	s.local = local
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		s.addLine(sc.Text())
	}
	return s.l, sc.Err()
}

// KindOf 返回情报的类别，未知时为通用黑名单。
func (db *DB) KindOf(name string) string {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, l := range db.lists {
		if l.name == name {
			return l.kind
		}
	}
	return KindDefault
}

// Match 返回命中的情报名称列表。
func (db *DB) Match(ip string) []string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	a = a.Unmap()
	db.mu.RLock()
	defer db.mu.RUnlock()
	var hits []string
	for _, l := range db.lists {
		if l.contains(a) {
			hits = append(hits, l.name)
		}
	}
	if db.tor[a] {
		hits = append(hits, "Tor出口节点")
	}
	return hits
}

// StartTor 定期拉取 Tor 出口节点列表。
func (db *DB) StartTor(ctx context.Context, url string) {
	if url == "" {
		return
	}
	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		for {
			if err := db.fetchTor(ctx, client, url); err != nil {
				log.Printf("[intel] 拉取 Tor 出口列表失败: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(6 * time.Hour):
			}
		}
	}()
}

func (db *DB) fetchTor(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 拉取失败时保留上次的列表：此前不检查状态码与读取错误，源站返回错误页（限流、5xx）或下载中途断开时，
	// 会用空的 / 不完整的列表替换掉已有列表，Tor 情报静默失效到下一次拉取（6 小时）
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d，保留上次的列表", resp.StatusCode)
	}
	l, err := readList("tor", io.LimitReader(resp.Body, 32<<20), nil, false)
	if err != nil {
		return fmt.Errorf("读取中断（%v），保留上次的列表", err)
	}
	if len(l.addrs) == 0 {
		return errors.New("返回的内容中没有 IP 地址（可能不是出口节点列表），保留上次的列表")
	}
	db.mu.Lock()
	db.tor = l.addrs
	db.mu.Unlock()
	log.Printf("[intel] Tor 出口节点 %d 个", len(l.addrs))
	return nil
}

// 已知网络空间测绘 / 安全研究机构的 rDNS 特征。
var scannerDomains = map[string]string{
	"shodan.io": "Shodan", "censys-scanner.com": "Censys", "censys.io": "Censys", "binaryedge.ninja": "BinaryEdge",
	"shadowserver.org": "Shadowserver", "stretchoid.com": "Stretchoid", "internet-measurement.com": "Driftnet",
	"rapid7.com": "Rapid7 Sonar", "onyphe.net": "Onyphe", "criminalip.com": "CriminalIP", "leakix.net": "LeakIX",
	"security.ipip.net": "IPIP", "alphastrike.io": "AlphaStrike", "recyber.net": "ReCyber", "bitsight.net": "BitSight",
	"internettl.org": "InterneTTL", "netsystemsresearch.com": "NetSystemsResearch", "intrinsec.com": "Intrinsec",
	"scan.cypex.ai": "Cypex", "ipinfo.io": "IPinfo", "probe.onyphe.net": "Onyphe", "modat.io": "Modat",
	"googlebot.com": "Googlebot", "search.msn.com": "Bingbot", "crawl.baidu.com": "Baiduspider", "spider.sogou.com": "Sogou",
	"yandex.com": "Yandex", "applebot.apple.com": "Applebot",
}

// ClassifyRDNS 根据反向解析域名识别扫描机构或搜索引擎爬虫。
func ClassifyRDNS(rdns string) string {
	rdns = strings.ToLower(strings.TrimSuffix(rdns, "."))
	if rdns == "" {
		return ""
	}
	for d, name := range scannerDomains {
		if rdns == d || strings.HasSuffix(rdns, "."+d) {
			return name
		}
	}
	return ""
}

// IsSearchEngine 判断 rDNS 识别结果是否为正规搜索引擎爬虫。
func IsSearchEngine(name string) bool {
	switch name {
	case "Googlebot", "Bingbot", "Baiduspider", "Sogou", "Yandex", "Applebot":
		return true
	}
	return false
}
