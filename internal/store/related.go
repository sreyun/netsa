package store

import (
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"netsa/internal/model"
)

// RelatedIP 是与目标 IP 存在关联的攻击源。
type RelatedIP struct {
	IP       string         `json:"ip"`
	Score    int            `json:"score"`  // 关联强度 0-100
	Threat   float64        `json:"threat"` // 该 IP 自身的威胁评分
	Level    model.Severity `json:"level"`
	Attacks  int64          `json:"attacks"`
	Location string         `json:"location,omitempty"`
	LastSeen time.Time      `json:"last_seen"`
	Reasons  []string       `json:"reasons"`
}

// Correlation 是同源关联分析结果：网段、ASN、工具指纹、攻击手法、目标与时间等多维线索加权评分。
type Correlation struct {
	Related     []*RelatedIP `json:"related"` // 关联度最高的前 30 个
	Total       int          `json:"total"`   // 达到列出阈值的关联攻击源总数
	Strong      int          `json:"strong"`  // 强关联（疑似同一攻击者 / 团伙）数量
	Subnet      string       `json:"subnet,omitempty"`
	SubnetCount int          `json:"subnet_count"` // 同网段攻击源数（不含自身）
	ASN         uint         `json:"asn,omitempty"`
	ASNCount    int          `json:"asn_count"` // 同 ASN 攻击源数
	Scanned     int          `json:"scanned"`   // 参与比对的攻击源数
}

const (
	relatedMin    = 30 // 低于该分值不列出
	relatedStrong = 60 // 达到该分值视为强关联
	relatedLimit  = 30
	topTargets    = 16   // 目标重合只比对当前 IP 攻击次数最多的若干目标
	scanChunk     = 4096 // 每批比对的攻击源数：批间释放读锁，避免长时间阻塞日志写入
)

// ruleBitN 为规则指纹位数。规则 ID 的取值有限（内置规则、行为检测与设备威胁分类），前 ruleBitN 个
// 出现的规则各占一位，此时规则集合的交集 / 并集可由位运算精确得到；超出后哈希到已有位上（近似）。
const ruleBitN = 256

// sketch 是画像中规则 / 端口集合的位图指纹，关联分析时用位运算代替集合遍历。不持久化，加载快照后重建。
type sketch struct {
	rules [ruleBitN / 64]uint64
	ports uint64 // 端口哈希到 64 位，只用于快速排除，命中后再精确比对
}

func (k *sketch) addRule(bit int) { k.rules[bit>>6] |= 1 << (bit & 63) }

// ruleSim 返回两个规则集合的交集大小与 Jaccard 相似度。
func (k *sketch) ruleSim(o *sketch) (int, float64) {
	and, or := 0, 0
	for i := range k.rules {
		and += bits.OnesCount64(k.rules[i] & o.rules[i])
		or += bits.OnesCount64(k.rules[i] | o.rules[i])
	}
	if or == 0 {
		return 0, 0
	}
	return and, float64(and) / float64(or)
}

// ruleBit 返回规则 ID 对应的指纹位（调用方持写锁）。
func (s *Store) ruleBit(id string) int {
	if b, ok := s.ruleBits[id]; ok {
		return b
	}
	if len(s.ruleBits) < ruleBitN {
		b := len(s.ruleBits)
		s.ruleBits[id] = b
		return b
	}
	h := uint64(14695981039346656037) // FNV-1a
	for i := 0; i < len(id); i++ {
		h ^= uint64(id[i])
		h *= 1099511628211
	}
	return int(h % ruleBitN)
}

func intBit(v int) uint64 { return 1 << (uint64(v) * 0x9E3779B97F4A7C15 >> 58) }

// estJaccard 用 64 位哈希指纹估算两个集合的相似度（哈希碰撞只会让估计值偏高，可安全用于筛除）。
func estJaccard(a, b uint64) float64 {
	u := bits.OnesCount64(a | b)
	if u == 0 {
		return 0
	}
	return float64(bits.OnesCount64(a&b)) / float64(u)
}

// rebuildSketch 根据画像中的集合重建指纹（加载快照后调用，调用方持写锁）。
func (s *Store) rebuildSketch(p *IPProfile) {
	p.sk = sketch{}
	for r := range p.Rules {
		p.sk.addRule(s.ruleBit(r))
	}
	for port := range p.Ports {
		p.sk.ports |= intBit(port)
	}
}

// correlator 保存目标 IP 的比对上下文。
type correlator struct {
	p              *IPProfile // 目标画像（调用方传入的副本，读取无需加锁）
	net24, net16   netip.Prefix
	pfx24, pfx16   string // IPv4 网段的字符串前缀，避免逐个解析地址
	asn            uint
	hosting        bool
	label, rdnsDom string
	uas            []string
	uaUsers        []int
	tls            []string // 客户端 TLS 指纹
	tlsUsers       []int
	orgTags        []string
	targets        []string
	attackers      int
}

// cand 是一个候选者的数值线索；理由文本只为最终列出的候选生成。
type cand struct {
	o          *IPProfile
	net        uint8 // 1 同 /16，2 同 /24
	asn        uint8 // 1 同 ASN，2 同 IDC/云厂商 ASN
	label      bool
	rdns       bool
	org        string
	uaMask     uint16
	tlsMask    uint8
	hoursSim   float64 // 行为节奏相似时的活跃时段、请求间隔相似度（不相似为 0）
	gapsSim    float64
	ruleShared int
	ruleSim    float64
	tgtShared  int
	portShared int
	portSim    float64
	firstSeen  time.Time
	threat     float64
	score      int
}

// correlate 在全部攻击源中查找与 p 同源的地址。p 为画像副本；其他画像分批在读锁内比对，
// 批间释放锁让日志写入继续进行。比对只做常数次比较与少量哈希查找，候选只保留前 30 名。
// newCorrelator 构造目标画像的比对上下文（调用方保证 p 可安全读取）；地址无法解析时返回 nil。
// UA 的使用人数（uaUsers）由调用方填写：单个地址的关联分析现场统计，攻击活动归并使用全局统计。
func newCorrelator(p *IPProfile) *correlator {
	addr, err := netip.ParseAddr(p.IP)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	cr := &correlator{p: p}
	bits24, bits16 := 24, 16
	if addr.Is6() {
		bits24, bits16 = 48, 32
	}
	cr.net24, _ = addr.Prefix(bits24)
	cr.net16, _ = addr.Prefix(bits16)
	if addr.Is4() {
		a := addr.As4()
		cr.pfx24, cr.pfx16 = fmt.Sprintf("%d.%d.%d.", a[0], a[1], a[2]), fmt.Sprintf("%d.%d.", a[0], a[1])
	}
	if g := p.Geo; g != nil {
		cr.asn, cr.hosting, cr.label, cr.rdnsDom = g.ASN, g.Hosting, g.Label, regDomain(g.RDNS)
	}
	for ua := range p.UAs {
		if ua != "" && ua != "-" && len(cr.uas) < 16 {
			cr.uas = append(cr.uas, ua)
		}
	}
	cr.uaUsers = make([]int, len(cr.uas))
	for fp := range p.TLS {
		if fp != "" && len(cr.tls) < 4 {
			cr.tls = append(cr.tls, fp)
		}
	}
	cr.tlsUsers = make([]int, len(cr.tls))
	for t := range p.Tags {
		if strings.HasPrefix(t, "网络空间测绘") || strings.HasPrefix(t, "搜索引擎") {
			cr.orgTags = append(cr.orgTags, t)
		}
	}
	cr.targets = topKeys(p.Targets, topTargets)
	return cr
}

func (s *Store) correlate(p *IPProfile) *Correlation {
	res := &Correlation{Related: []*RelatedIP{}}
	cr := newCorrelator(p)
	if cr == nil {
		return res
	}
	res.Subnet = cr.net24.String()
	res.ASN = cr.asn

	s.mu.RLock()
	list := make([]*IPProfile, 0, len(s.ips))
	for _, o := range s.ips {
		if o.IP != p.IP && isAttacker(o) {
			list = append(list, o)
		}
	}
	s.mu.RUnlock()
	res.Scanned = len(list)
	cr.attackers = len(list) + 1

	// 第一遍：统计共用目标 UA 的攻击源数，用于评估 UA 的稀有度
	if len(cr.uas) > 0 {
		s.chunked(list, func(o *IPProfile) {
			if len(o.UAs) == 0 {
				return
			}
			for i, ua := range cr.uas {
				if o.UAs[ua] > 0 {
					cr.uaUsers[i]++
				}
			}
		})
	}
	if len(cr.tls) > 0 {
		s.chunked(list, func(o *IPProfile) {
			for i, fp := range cr.tls {
				if o.TLS[fp] > 0 {
					cr.tlsUsers[i]++
				}
			}
		})
	}
	// 第二遍：逐个计分，只保留前 relatedLimit 名
	var top []cand
	s.chunked(list, func(o *IPProfile) {
		c := cr.inspect(o, res)
		if c.score < relatedMin {
			return
		}
		res.Total++
		if c.score >= relatedStrong {
			res.Strong++
		}
		top = insertTop(top, c)
	})
	s.mu.RLock()
	for i := range top {
		c := &top[i]
		_, reasons := cr.score(c, true)
		r := &RelatedIP{IP: c.o.IP, Score: min(100, c.score), Threat: c.o.Score, Level: c.o.Level, Attacks: c.o.Attacks, LastSeen: c.o.LastSeen, Reasons: reasons}
		if c.o.Geo != nil {
			r.Location = c.o.Geo.Location()
		}
		res.Related = append(res.Related, r)
	}
	s.mu.RUnlock()
	return res
}

// chunked 分批在读锁内对画像执行 fn。
func (s *Store) chunked(list []*IPProfile, fn func(o *IPProfile)) {
	for i := 0; i < len(list); i += scanChunk {
		end := min(i+scanChunk, len(list))
		s.mu.RLock()
		for _, o := range list[i:end] {
			fn(o)
		}
		s.mu.RUnlock()
	}
}

// insertTop 按（关联度，威胁评分）降序把 c 插入长度不超过 relatedLimit 的列表。
func insertTop(top []cand, c cand) []cand {
	less := func(a, b *cand) bool { // a 排在 b 之后
		if a.score != b.score {
			return a.score < b.score
		}
		return a.threat < b.threat
	}
	if len(top) == relatedLimit && !less(&top[len(top)-1], &c) {
		return top
	}
	i := sort.Search(len(top), func(i int) bool { return less(&top[i], &c) })
	if len(top) < relatedLimit {
		top = append(top, cand{})
	}
	copy(top[i+1:], top[i:len(top)-1])
	top[i] = c
	return top
}

// inspect 收集候选者 o 的各项线索并计分（调用方持读锁）。
func (cr *correlator) inspect(o *IPProfile, res *Correlation) cand {
	c := cand{o: o, firstSeen: o.FirstSeen, threat: o.Score}
	switch ip := o.IP; {
	case cr.pfx24 != "":
		if strings.HasPrefix(ip, cr.pfx24) {
			c.net = 2
		} else if strings.HasPrefix(ip, cr.pfx16) {
			c.net = 1
		}
	case strings.IndexByte(ip, ':') >= 0:
		if oa, err := netip.ParseAddr(ip); err == nil {
			if cr.net24.Contains(oa) {
				c.net = 2
			} else if cr.net16.Contains(oa) {
				c.net = 1
			}
		}
	}
	if c.net == 2 {
		res.SubnetCount++
	}
	if og := o.Geo; og != nil {
		if cr.asn > 0 && og.ASN == cr.asn {
			res.ASNCount++
			c.asn = 1
			if cr.hosting && og.Hosting {
				c.asn = 2
			}
		}
		c.label = cr.label != "" && og.Label == cr.label
		c.rdns = cr.rdnsDom != "" && sameRegDomain(og.RDNS, cr.rdnsDom)
	}
	for _, t := range cr.orgTags {
		if _, ok := o.Tags[t]; ok {
			c.org = t
			break
		}
	}
	if len(o.UAs) > 0 {
		for i, ua := range cr.uas {
			if o.UAs[ua] > 0 {
				c.uaMask |= 1 << i
			}
		}
	}
	if len(o.TLS) > 0 {
		for i, fp := range cr.tls {
			if o.TLS[fp] > 0 {
				c.tlsMask |= 1 << i
			}
		}
	}
	if h, g, ok := cr.p.Rhythm.similar(o.Rhythm); ok {
		c.hoursSim, c.gapsSim = h, g
	}
	p := cr.p
	c.ruleShared, c.ruleSim = p.sk.ruleSim(&o.sk)
	if c.ruleShared > 0 {
		// 手法相似时再看是否攻击了同一批目标
		if c.ruleSim >= 0.5 && len(o.Targets) >= 3 {
			for _, t := range cr.targets {
				if _, ok := o.Targets[t]; ok {
					c.tgtShared++
				}
			}
		}
	}
	if bits.OnesCount64(p.sk.ports&o.sk.ports) >= 5 && estJaccard(p.sk.ports, o.sk.ports) >= 0.5 {
		c.portSim, c.portShared = jaccard(p.Ports, o.Ports)
	}
	c.score, _ = cr.score(&c, false)
	return c
}

// score 计算候选者的关联度；text 为 true 时同时生成理由文本。
// 同 ASN 属于弱线索：大型云厂商 / 运营商下的攻击源很多，单凭 ASN 不构成关联。
func (cr *correlator) score(c *cand, text bool) (int, []string) {
	score, weak := 0, 0
	var reasons []string
	add := func(w int, f string, a ...any) {
		score += w
		if text {
			reasons = append(reasons, fmt.Sprintf(f, a...))
		}
	}
	switch c.net {
	case 2:
		add(40, "同 %s 网段", cr.net24)
	case 1:
		add(12, "同 %s 网段", cr.net16)
	}
	switch c.asn {
	case 2:
		add(20, "同一 IDC/云厂商 AS%d", cr.asn)
		weak += 20
	case 1:
		add(8, "同一自治系统 AS%d", cr.asn)
		weak += 8
	}
	if c.label {
		add(15, "同属自定义网段「%s」", cr.label)
	}
	if c.rdns {
		add(25, "反向解析同属 %s", cr.rdnsDom)
	}
	if c.org != "" {
		add(30, "同属%s", c.org)
	}
	// 多个共同 UA 只计最强的一条。非浏览器 UA 通常为扫描器、脚本或自研工具，共用即为强指纹；
	// 但 curl、Go-http-client 这类被大量攻击源共用的通用工具 UA 区分度低，降低权重。
	best, bestUA := 0, -1
	for i, ua := range cr.uas {
		if c.uaMask&(1<<i) == 0 {
			continue
		}
		n, w := cr.uaUsers[i], 0
		tool := !strings.HasPrefix(ua, "Mozilla/")
		switch {
		case tool && n > 20 && n*10 > cr.attackers:
			w = 10
		case tool:
			w = 30
		case n <= 5 && n*20 < cr.attackers:
			w = 20
		}
		if w > best {
			best, bestUA = w, i
		}
	}
	if best > 0 {
		if strings.HasPrefix(cr.uas[bestUA], "Mozilla/") {
			add(best, "相同的罕见 User-Agent")
		} else {
			add(best, "相同工具指纹 %s", shortUA(cr.uas[bestUA]))
		}
	}
	// TLS 指纹：JA3 / JA4 由客户端的 TLS 实现决定，同一工具换出口也不变；只用协议与加密套件的指纹区分度低，只在极少见时计入
	bestTLS := 0
	for i, fp := range cr.tls {
		if c.tlsMask&(1<<i) == 0 {
			continue
		}
		n, w := cr.tlsUsers[i], 0
		switch {
		case !strings.HasPrefix(fp, "tls:") && n <= 20 && n*10 <= cr.attackers:
			w = 25
		case strings.HasPrefix(fp, "tls:") && n <= 5 && n*20 < cr.attackers:
			w = 8
		}
		bestTLS = max(bestTLS, w)
	}
	if bestTLS > 0 {
		add(bestTLS, "相同的罕见 TLS 指纹")
	}
	if c.ruleShared >= 2 && c.ruleSim >= 0.5 {
		add(int(30*c.ruleSim+0.5), "攻击手法相似度 %d%%（共同规则 %d 条）", int(c.ruleSim*100+0.5), c.ruleShared)
	}
	if c.tgtShared >= 3 {
		add(min(20, 4*c.tgtShared), "攻击了相同的 %d 个目标", c.tgtShared)
	}
	if c.portShared >= 5 && c.portSim >= 0.6 {
		add(20, "扫描端口组合相似（共同端口 %d 个）", c.portShared)
	}
	// 行为节奏（活跃时段与请求间隔）只作辅助线索：大量扫描器的节奏本来就相似，单凭节奏不构成关联
	if c.hoursSim > 0 {
		add(15, "行为节奏相似（活跃时段 %d%%、请求间隔 %d%%）", int(c.hoursSim*100+0.5), int(c.gapsSim*100+0.5))
		weak += 15
	}
	// 已有其他线索时，首次出现时间接近进一步佐证同源
	if dt := c.firstSeen.Sub(cr.p.FirstSeen).Abs(); score-weak >= 20 && dt <= 10*time.Minute {
		add(10, "首次出现时间相近（相差 %s）", dt.Round(time.Second))
	}
	if score == weak {
		return 0, nil
	}
	return score, reasons
}

// topKeys 返回计数最多的 n 个键。
func topKeys(m map[string]int, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// 始终排序（计数降序、同数按键升序）：键数不超过 n 时也按计数排列，结果不随 map 遍历顺序在每次重建时变化
	sort.Slice(keys, func(i, j int) bool {
		if a, b := m[keys[i]], m[keys[j]]; a != b {
			return a > b
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// jaccard 返回两个集合（map 的键）的 Jaccard 相似度与交集大小，只遍历较小的一方。
func jaccard[K comparable, V any](a, b map[K]V) (float64, int) {
	if len(a) == 0 || len(b) == 0 {
		return 0, 0
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	shared := 0
	for k := range a {
		if _, ok := b[k]; ok {
			shared++
		}
	}
	return float64(shared) / float64(len(a)+len(b)-shared), shared
}

// sameRegDomain 判断主机名是否属于注册域 dom：先做无分配的后缀比较，命中后再精确确认。
func sameRegDomain(host, dom string) bool {
	host = strings.TrimSuffix(host, ".")
	n := len(host) - len(dom)
	if n < 2 || host[n-1] != '.' || !strings.EqualFold(host[n:], dom) {
		return false
	}
	return regDomain(host) == dom
}

// regDomain 取反向解析域名的注册域（如 scanner-12.shodan.io → shodan.io，a.b.example.com.cn → example.com.cn）。
func regDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 {
		switch labels[len(labels)-2] {
		case "com", "net", "org", "gov", "edu", "co", "ac", "ne", "or":
			n = 3
		}
	}
	return strings.Join(labels[len(labels)-n:], ".")
}

func shortUA(ua string) string {
	if r := []rune(ua); len(r) > 40 {
		return string(r[:40]) + "…"
	}
	return ua
}

// addOASTMates 把与该地址使用同一 OAST 关联标识的来源列为强关联：同一次扫描任务的其他出口地址；
// 使用同一诱饵线索、诱饵账号的来源同样列为强关联（只有拿到诱饵的人才知道）。
// 这些来源的网段、手法可能完全不同，按特征评分发现不了。
func (s *Store) addOASTMates(ip string, c *Correlation) {
	if c == nil {
		return
	}
	if s.OASTLinks != nil {
		s.addLinkMates(ip, c, s.OASTLinks(), func(k string) string { return "同一 OAST 关联标识 " + k + "（同一次扫描任务）" })
	}
	if s.DecoyLinks != nil {
		s.addLinkMates(ip, c, s.DecoyLinks(), func(k string) string { return "使用同一" + k + "（只有读过诱饵的人才知道）" })
	}
}

// addLinkMates 把 links 中与该地址同组的来源列为强关联（评分 100）。
func (s *Store) addLinkMates(ip string, c *Correlation, links map[string][]string, reason func(string) string) {
	mates := map[string]string{} // 来源 → 共用的标识
	for k, ips := range links {
		if !slices.Contains(ips, ip) {
			continue
		}
		for _, x := range ips {
			if x != ip && (mates[x] == "" || k < mates[x]) {
				mates[x] = k
			}
		}
	}
	if len(mates) == 0 {
		return
	}
	for _, r := range c.Related {
		if k, ok := mates[r.IP]; ok {
			if r.Score < relatedStrong {
				c.Strong++
			}
			r.Score = 100
			r.Reasons = append([]string{reason(k)}, r.Reasons...)
			delete(mates, r.IP)
		}
	}
	extra := make([]string, 0, len(mates))
	for x := range mates {
		extra = append(extra, x)
	}
	sort.Strings(extra)
	s.mu.RLock()
	for _, x := range extra {
		o := s.ips[x]
		if o == nil {
			continue
		}
		r := &RelatedIP{IP: x, Score: 100, Threat: o.Score, Level: o.Level, Attacks: o.Attacks, LastSeen: o.LastSeen, Reasons: []string{reason(mates[x])}}
		if o.Geo != nil {
			r.Location = o.Geo.Location()
		}
		c.Related = append(c.Related, r)
		c.Total++
		c.Strong++
	}
	s.mu.RUnlock()
	sort.SliceStable(c.Related, func(i, j int) bool { return c.Related[i].Score > c.Related[j].Score })
	if len(c.Related) > relatedLimit {
		c.Related = c.Related[:relatedLimit]
	}
}
