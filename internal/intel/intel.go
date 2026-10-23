// Package intel 提供本地威胁情报匹配（IP/网段黑名单、Tor 出口节点）与 rDNS 身份识别。
package intel

import (
	"bufio"
	"context"
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
	name     string
	addrs    map[netip.Addr]bool
	prefixes []netip.Prefix
}

func (l *list) contains(a netip.Addr) bool {
	if l.addrs[a] {
		return true
	}
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
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
		log.Printf("[intel] 已加载 %s: %d 个IP, %d 个网段", bl.Name, len(l.addrs), len(l.prefixes))
		db.lists = append(db.lists, l)
	}
	return db, nil
}

func parseList(name string, r io.Reader) *list {
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
				l.prefixes = append(l.prefixes, p.Masked())
			}
		} else if a, err := netip.ParseAddr(f[0]); err == nil {
			l.addrs[a.Unmap()] = true
		}
	}
	return l
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
	l := parseList("tor", resp.Body)
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
