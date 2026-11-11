package store

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"netsa/internal/model"
)

// 攻击活动归并：单个地址的同源关联（related.go）只回答“谁和这个地址相关”；这里把全部攻击源之间的强关联连通起来，
// 得到一次次攻击活动——分布式扫描、轮换出口的同一攻击者、僵尸网络、同一测绘机构的大量节点。
//
// 为避免全量两两比对，先按能构成强关联的线索分桶（同 /24 网段、同一罕见工具指纹、同一测绘机构、同一 rDNS 主域名、
// 同一 IDC / 云厂商 ASN），只在桶内比对；关联度达到强关联阈值（60）的两个地址连到同一活动。
// 除原有的线索外，增加一条只用于活动归并的依据：同一 IDC / 云厂商的地址在相近时间扫描同一台主机、攻击类型相同，
// 这是分布式扫描的典型形态（每个地址只打几个随机端口，单看手法与端口都不相似）。

// Campaign 是一次攻击活动。
type Campaign struct {
	ID         string           `json:"id"` // 成员中威胁评分最高的地址
	Size       int              `json:"size"`
	Members    []CampaignMember `json:"members"` // 威胁评分最高的前 campaignMembers 个
	Attacks    int64            `json:"attacks"`
	Level      model.Severity   `json:"level"`
	FirstSeen  time.Time        `json:"first_seen"`
	LastSeen   time.Time        `json:"last_seen"`
	Categories []string         `json:"categories"`
	Targets    []string         `json:"targets"`
	Nets       []NetCount       `json:"nets"`
	ASNs       []string         `json:"asns,omitempty"`
	Tools      []string         `json:"tools,omitempty"`
	OAST       []string         `json:"oast,omitempty"`   // 成员共用的带外回连标识（interactsh 关联 ID、dnslog 子域名）
	Decoys     []string         `json:"decoys,omitempty"` // 成员共用的诱饵线索 / 诱饵账号
	Reasons    []string         `json:"reasons"`
	BlockNets  []string         `json:"block_nets,omitempty"` // 建议整体封禁的网段：有 3 个以上成员的 /24
}

// CampaignMember 是活动中的一个攻击源。
type CampaignMember struct {
	IP       string         `json:"ip"`
	Score    float64        `json:"score"`
	Level    model.Severity `json:"level"`
	Attacks  int64          `json:"attacks"`
	Location string         `json:"location,omitempty"`
	LastSeen time.Time      `json:"last_seen"`
}

// NetCount 是网段与其中的成员数。
type NetCount struct {
	Net   string `json:"net"`
	Count int    `json:"count"`
}

// CampaignReport 是攻击活动的归并结果。
type CampaignReport struct {
	Campaigns []*Campaign `json:"campaigns"`
	Total     int         `json:"total"`     // 活动总数
	Members   int         `json:"members"`   // 归入活动的攻击源数
	Scanned   int         `json:"scanned"`   // 参与归并的攻击源数
	Generated time.Time   `json:"generated"` // 计算时间
}

const (
	campaignMax     = 5000 // 参与归并的攻击源上限（按威胁评分取前若干个）
	campaignBucket  = 300  // 单个分桶参与比对的成员上限（取威胁评分最高的）
	campaignMembers = 50
	campaignList    = 200
	campaignTTL     = time.Minute
)

// Campaigns 返回攻击活动归并结果（结果缓存 1 分钟）。
// 缓存过期后先返回上一次的结果、在后台重新归并（同一时间只有一个），请求不再等待整轮归并
// （数千个攻击源约百毫秒以上，全局搜索、攻击活动页面都会调用）；只有第一次调用同步生成。
func (s *Store) Campaigns() *CampaignReport {
	s.campMu.Lock()
	defer s.campMu.Unlock()
	if s.camp == nil {
		s.camp = s.buildCampaigns()
		return s.camp
	}
	if time.Since(s.camp.Generated) >= campaignTTL && !s.campBuilding {
		s.campBuilding = true
		go func() {
			rep := s.buildCampaigns()
			s.campMu.Lock()
			s.camp, s.campBuilding = rep, false
			s.campMu.Unlock()
		}()
	}
	return s.camp
}

type campEdge struct {
	a, b    int
	reasons []string
}

func (s *Store) buildCampaigns() *CampaignReport {
	rep := &CampaignReport{Campaigns: []*Campaign{}, Generated: time.Now()}
	// 评分在读锁内取出：解锁后写者会继续更新画像，不能再读取其字段
	type scored struct {
		p     *IPProfile
		score float64
	}
	s.mu.RLock()
	all := make([]scored, 0, len(s.ips))
	for _, o := range s.ips {
		if isAttacker(o) {
			all = append(all, scored{o, o.Score})
		}
	}
	s.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool { return all[i].score > all[j].score })
	if len(all) > campaignMax {
		all = all[:campaignMax]
	}
	list := make([]*IPProfile, len(all))
	for i := range all {
		list[i] = all[i].p
	}
	rep.Scanned = len(list)

	// UA 的使用人数（评估工具指纹的稀有度）与分桶
	uaUsers, tlsUsers := map[string]int{}, map[string]int{}
	buckets := map[string][]int{}
	s.chunked(list, func(o *IPProfile) {
		for ua := range o.UAs {
			uaUsers[ua]++
		}
		for fp := range o.TLS {
			tlsUsers[fp]++
		}
	})
	for i := 0; i < len(list); i += scanChunk {
		s.mu.RLock()
		for k := i; k < min(i+scanChunk, len(list)); k++ {
			for _, key := range campaignKeys(list[k], uaUsers, tlsUsers, len(list)) {
				if len(buckets[key]) < campaignBucket {
					buckets[key] = append(buckets[key], k)
				}
			}
		}
		s.mu.RUnlock()
	}

	parent := make([]int, len(list))
	for i := range parent {
		parent[i] = i
	}
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	seen := map[uint64]struct{}{}
	var edges []campEdge
	keys := make([]string, 0, len(buckets))
	for k, idx := range buckets {
		if len(idx) >= 2 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys) // 结果与 map 遍历顺序无关
	for _, k := range keys {
		idx := buckets[k]
		s.mu.RLock()
		for a := 0; a < len(idx); a++ {
			i := idx[a]
			cr := newCorrelator(list[i])
			if cr == nil {
				continue
			}
			for u, ua := range cr.uas {
				cr.uaUsers[u] = uaUsers[ua]
			}
			for u, fp := range cr.tls {
				cr.tlsUsers[u] = tlsUsers[fp]
			}
			cr.attackers = len(list)
			hosts := targetHosts(list[i])
			var dummy Correlation
			for b := a + 1; b < len(idx); b++ {
				j := idx[b]
				pk := uint64(min(i, j))<<32 | uint64(max(i, j))
				if _, ok := seen[pk]; ok {
					continue
				}
				seen[pk] = struct{}{}
				c := cr.inspect(list[j], &dummy)
				score, reasons := c.score, []string(nil)
				if score >= relatedStrong {
					_, reasons = cr.score(&c, true)
				} else if c.asn == 2 && sharedScan(list[i], list[j], hosts) {
					// 只有“同一云厂商”这条弱线索时原评分记为 0，这里按其本身的 20 分计
					score = max(score, 20) + 40
					_, reasons = cr.score(&c, true)
					reasons = append(reasons, "同一云厂商的地址在相近时间扫描同一主机")
				}
				if score < relatedStrong {
					continue
				}
				if ra, rb := find(i), find(j); ra != rb {
					parent[ra] = rb
				}
				edges = append(edges, campEdge{i, j, reasons})
			}
		}
		s.mu.RUnlock()
	}

	// 同一 OAST 关联标识（interactsh 关联 ID、dnslog 子域名）：同一次扫描任务的多个出口地址，直接连到同一活动
	// 使用同一诱饵线索、诱饵账号的来源同样直接连到同一活动
	oastOf, decoyOf := map[int][]string{}, map[int][]string{}
	pos := make(map[string]int, len(list))
	for _, src := range []struct {
		fn     func() map[string][]string
		reason string
		tag    map[int][]string
	}{{s.OASTLinks, "同一 OAST 关联标识（同一次扫描任务）", oastOf}, {s.DecoyLinks, "使用同一诱饵线索 / 诱饵账号", decoyOf}} {
		if src.fn == nil {
			continue
		}
		links := src.fn()
		if len(pos) == 0 {
			for i, o := range list {
				pos[o.IP] = i // 地址创建后不再修改，读取无需加锁
			}
		}
		keys := make([]string, 0, len(links))
		for k := range links {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var idx []int
			for _, ip := range links[k] {
				if i, ok := pos[ip]; ok {
					idx = append(idx, i)
				}
			}
			if len(idx) < 2 {
				continue
			}
			for _, i := range idx {
				src.tag[i] = append(src.tag[i], k)
			}
			for _, j := range idx[1:] {
				if ra, rb := find(idx[0]), find(j); ra != rb {
					parent[ra] = rb
				}
				edges = append(edges, campEdge{idx[0], j, []string{src.reason}})
			}
		}
	}

	groups := map[int][]int{}
	for i := range list {
		r := find(i)
		groups[r] = append(groups[r], i)
	}
	reasons := map[int]map[string]int{}
	for _, e := range edges {
		r := find(e.a)
		if reasons[r] == nil {
			reasons[r] = map[string]int{}
		}
		for _, t := range e.reasons {
			reasons[r][t]++
		}
	}
	s.mu.RLock()
	for r, idx := range groups {
		if len(idx) < 2 {
			continue
		}
		rep.Members += len(idx)
		c := buildCampaign(list, idx, reasons[r])
		for _, i := range idx {
			for _, k := range oastOf[i] {
				if !slices.Contains(c.OAST, k) && len(c.OAST) < 5 {
					c.OAST = append(c.OAST, k)
				}
			}
			for _, k := range decoyOf[i] {
				if !slices.Contains(c.Decoys, k) && len(c.Decoys) < 5 {
					c.Decoys = append(c.Decoys, k)
				}
			}
		}
		sort.Strings(c.OAST)
		rep.Campaigns = append(rep.Campaigns, c)
	}
	s.mu.RUnlock()
	sort.Slice(rep.Campaigns, func(i, j int) bool {
		a, b := rep.Campaigns[i], rep.Campaigns[j]
		if a.Level != b.Level {
			return a.Level > b.Level
		}
		if a.Size != b.Size {
			return a.Size > b.Size
		}
		return a.ID < b.ID
	})
	rep.Total = len(rep.Campaigns)
	if len(rep.Campaigns) > campaignList {
		rep.Campaigns = rep.Campaigns[:campaignList]
	}
	return rep
}

// campaignKeys 返回攻击源参与比对的分桶：只有可能构成强关联的线索才分桶。调用方持读锁。
func campaignKeys(o *IPProfile, uaUsers, tlsUsers map[string]int, total int) []string {
	var keys []string
	if a, err := netip.ParseAddr(o.IP); err == nil {
		a = a.Unmap()
		bits := 24
		if a.Is6() {
			bits = 48
		}
		if p, err := a.Prefix(bits); err == nil {
			keys = append(keys, "net:"+p.String())
		}
	}
	if g := o.Geo; g != nil {
		if g.ASN > 0 && g.Hosting {
			keys = append(keys, fmt.Sprintf("asn:%d", g.ASN))
		}
		if d := regDomain(g.RDNS); d != "" {
			keys = append(keys, "rdns:"+d)
		}
	}
	for t := range o.Tags {
		if strings.HasPrefix(t, "网络空间测绘") || strings.HasPrefix(t, "搜索引擎") {
			keys = append(keys, "org:"+t)
		}
	}
	// 工具指纹：非浏览器 UA，且不是被大量攻击源共用的通用客户端（curl、Go-http-client）
	for ua := range o.UAs {
		if ua == "" || ua == "-" || strings.HasPrefix(ua, "Mozilla/") {
			continue
		}
		if n := uaUsers[ua]; n >= 2 && (n <= 20 || n*10 <= total) {
			keys = append(keys, "ua:"+ua)
		}
	}
	// JA3 / JA4 指纹：同一工具换出口也不变
	for fp := range o.TLS {
		if strings.HasPrefix(fp, "tls:") {
			continue
		}
		if n := tlsUsers[fp]; n >= 2 && n <= 20 && n*10 <= total {
			keys = append(keys, "tls:"+fp)
		}
	}
	return keys
}

// targetHosts 返回攻击源打过的主机（目标去掉端口与路径）。调用方持读锁。
func targetHosts(o *IPProfile) map[string]struct{} {
	out := make(map[string]struct{}, len(o.Targets))
	for t := range o.Targets {
		h := t
		if i := strings.IndexAny(h, " :/"); i > 0 {
			h = h[:i]
		}
		out[h] = struct{}{}
	}
	return out
}

// sharedScan 判断两个攻击源是否在相近时间（活动期间相互重叠，或间隔不超过 1 小时）扫描了同一台主机、
// 主要攻击类型相同。调用方持读锁。
func sharedScan(a, b *IPProfile, hostsA map[string]struct{}) bool {
	if a.FirstSeen.After(b.LastSeen.Add(time.Hour)) || b.FirstSeen.After(a.LastSeen.Add(time.Hour)) {
		return false
	}
	if topKey(a.Categories) == "" || topKey(a.Categories) != topKey(b.Categories) {
		return false
	}
	for t := range b.Targets {
		h := t
		if i := strings.IndexAny(h, " :/"); i > 0 {
			h = h[:i]
		}
		if _, ok := hostsA[h]; ok {
			return true
		}
	}
	return false
}

func topKey(m map[string]int) string {
	best, n := "", 0
	for k, v := range m {
		if v > n || v == n && k < best {
			best, n = k, v
		}
	}
	return best
}

// buildCampaign 汇总一个活动。调用方持读锁。
func buildCampaign(list []*IPProfile, idx []int, reasons map[string]int) *Campaign {
	members := make([]*IPProfile, len(idx))
	for k, i := range idx {
		members[k] = list[i]
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].Score != members[j].Score {
			return members[i].Score > members[j].Score
		}
		return members[i].IP < members[j].IP
	})
	c := &Campaign{ID: members[0].IP, Size: len(members), FirstSeen: members[0].FirstSeen}
	cats, tgts, nets, asns, tools := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, o := range members {
		c.Attacks += o.Attacks
		c.Level = max(c.Level, o.Level)
		if o.FirstSeen.Before(c.FirstSeen) {
			c.FirstSeen = o.FirstSeen
		}
		if o.LastSeen.After(c.LastSeen) {
			c.LastSeen = o.LastSeen
		}
		for k, v := range o.Categories {
			cats[k] += v
		}
		for k, v := range o.Targets {
			tgts[k] += v
		}
		if a, err := netip.ParseAddr(o.IP); err == nil && a.Unmap().Is4() {
			p, _ := a.Unmap().Prefix(24)
			nets[p.String()]++
		}
		if g := o.Geo; g != nil && g.ASN > 0 {
			name := fmt.Sprintf("AS%d", g.ASN)
			if org := firstNonEmpty(g.ASOrg, g.ISP); org != "" {
				name += " " + org
			}
			asns[name]++
		}
		for ua := range o.UAs {
			if ua != "" && ua != "-" && !strings.HasPrefix(ua, "Mozilla/") {
				tools[shortUA(ua)]++
			}
		}
		if len(c.Members) < campaignMembers {
			m := CampaignMember{IP: o.IP, Score: o.Score, Level: o.Level, Attacks: o.Attacks, LastSeen: o.LastSeen}
			if o.Geo != nil {
				m.Location = o.Geo.Location()
			}
			c.Members = append(c.Members, m)
		}
	}
	c.Categories = topKeys(cats, 6)
	c.Targets = topKeys(tgts, 5)
	c.ASNs = topKeys(asns, 3)
	for _, n := range topKeys(nets, 8) {
		c.Nets = append(c.Nets, NetCount{n, nets[n]})
		if nets[n] >= 3 {
			c.BlockNets = append(c.BlockNets, n)
		}
	}
	for t, n := range tools {
		if n >= 2 {
			c.Tools = append(c.Tools, t)
		}
	}
	sort.Strings(c.Tools)
	c.Reasons = topKeys(reasons, 5)
	return c
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
