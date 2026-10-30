// Package intel 提供本地威胁情报匹配（IP/网段黑名单、Tor 出口节点）与 rDNS 身份识别。
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

type list struct {
	name  string
	addrs map[netip.Addr]bool
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
}

// Load 加载配置中的黑名单文件（每行一个 IP 或 CIDR，# 开头为注释）。
func Load(cfg config.IntelConfig) (*DB, error) {
	db := &DB{tor: map[netip.Addr]bool{}}
	for _, bl := range cfg.Blocklists {
		f, err := os.Open(bl.Path)
		if err != nil {
			log.Printf("[intel] 跳过情报文件 %s: %v", bl.Path, err)
			continue
		}
		l := parseList(bl.Name, f)
		f.Close()
		log.Printf("[intel] 已加载 %s: %d 个IP, %d 个网段", bl.Name, len(l.addrs), l.count)
		db.lists = append(db.lists, l)
	}
	return db, nil
}

func parseList(name string, r io.Reader) *list {
	l, _ := readList(name, r)
	return l
}

// readList 逐行解析情报列表；读取中断（网络断开、超长行）时返回已解析的部分与错误。
func readList(name string, r io.Reader) (*list, error) {
	l := &list{name: name, addrs: map[netip.Addr]bool{}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if p, err := netip.ParsePrefix(f[0]); err == nil {
			if p.IsSingleIP() {
				l.addrs[p.Addr()] = true
			} else {
				l.addPrefix(p.Masked())
			}
		} else if a, err := netip.ParseAddr(f[0]); err == nil {
			l.addrs[a.Unmap()] = true
		}
	}
	return l, sc.Err()
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
	l, err := readList("tor", io.LimitReader(resp.Body, 32<<20))
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
