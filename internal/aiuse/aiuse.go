// Package aiuse 统计内网终端使用 AI 服务的情况（AI 使用治理第一阶段：看得见）。
//
// 数据来源都是平台已经在接入的日志，不需要新的采集：
//   - DNS 查询日志：终端解析了哪个 AI 服务的域名（查询次数）；
//   - TLS 握手的服务器名称（Zeek ssl.log 的 SNI）：终端与哪个 AI 服务建立了加密连接（连接次数），不经过内网 DNS 时同样能发现；
//   - Web / 流量日志的 Host（Zeek http.log、代理日志）：明文请求；
//   - 会话日志的字节数（Zeek conn.log、防火墙会话日志、NetFlow）：按 SNI 学到的“终端 + 目的地址 → 服务”，
//     把会话的上传 / 下载字节归到 AI 服务。只认 SNI 确认过的终端与地址：AI 服务大多在 Cloudflare、Azure 等
//     共享地址上，只按目的地址归属会把同一地址上的其他网站也算进来。
//
// 与攻击检测完全分开：不产生告警，不建立攻击源画像，不进入评分、失陷研判与自学习，也不经过威胁情报
// （情报加载时会丢弃 googleapis.com、aliyuncs.com 等公共平台的子域名，Gemini API、DashScope 会被漏掉）。
//
// 另外两份清单用于发现目录之外的 AI 服务：
//   - 疑似 AI 域名：域名中含 openai、gpt、claude、llm 等特征词或使用 .ai 顶级域名、又不在目录中的，列为待确认；
//   - AI 接口：Web 日志中出现 /v1/chat/completions、/v1/messages、Ollama 的 /api/generate 等大模型接口路径的站点，
//     用于发现内网自建的模型服务与 API 中转站。
//
// 内存有上限（按天、终端、服务记录，超过 max_records 时先淘汰最早的一天），状态保存在 aiuse.json.gz。
package aiuse

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

const (
	defaultRetention  = 62 // 天：覆盖“上月”月报
	defaultMaxRecords = 300000
	maxFlows          = 200000 // 精确的连接（四元组）→ 服务
	maxPairs          = 100000 // 终端 + 目的地址 → 服务
	flowTTL           = 6 * time.Hour
	pairTTL           = 30 * time.Minute
	maxCandidates     = 2000
	maxEndpoints      = 1000
	maxSetSize        = 64 // 疑似域名、AI 接口记录的不同来源数上限
)

// day 是自然日编号（配置时区下，自 1970-01-01 起的天数）。
type day int32

type cellKey struct {
	d   day
	svc string
	ip  string
}

// cell 是一个终端在一天内使用一个服务的统计。
type cell struct {
	queries int64 // DNS 查询次数
	conns   int64 // TLS 连接 / 明文请求次数
	denied  int64 // 被拦截的尝试：DNS 返回 NXDOMAIN / REFUSED、TLS 握手没有建立
	up      int64 // 上传字节（终端发送）
	down    int64 // 下载字节
	first   int64 // Unix 秒
	last    int64
}

type flowKey struct {
	src, dst     string
	sport, dport uint16
}

type pairKey struct{ src, dst string }

// flowVal 是 SNI 确认的一条连接的服务。at 是握手的日志时间，会话日志按日志时间与它比较（补读积压、离线分析时同样准确）；
// exp 是按当前时间计算的内存回收时间。
type flowVal struct {
	svc string
	at  int64 // 握手的日志时间（Unix 秒）
	exp int64 // 回收时间（Unix 秒，当前时间 + 有效期）
}

func (v flowVal) expiry() int64 { return v.exp }

// span 是一个终端在一段时间内与同一地址建立的、SNI 指向同一服务的握手（日志时间，相隔不超过 pairTTL 的合并为一段）。
type span struct {
	lo, hi int64
	svc    string
}

// pairVal 记录“终端 + 目的地址”最近几段握手。只记最近一次握手时间的话，补读积压、离线分析时 TLS 握手日志
// （文件小、读得快）会先读完，最近时间跑到最后，之前几小时的会话都对不上。
type pairVal struct {
	spans []span
	exp   int64
}

func (v pairVal) expiry() int64 { return v.exp }

const maxSpans = 8

// add 记录一次握手：与同一服务、相隔不超过 pairTTL 的段合并，否则新开一段（超过 maxSpans 时去掉最早的一段）。
func (v *pairVal) add(at int64, svc string) {
	gap := int64(pairTTL / time.Second)
	for i := range v.spans {
		sp := &v.spans[i]
		if sp.svc == svc && at >= sp.lo-gap && at <= sp.hi+gap {
			sp.lo, sp.hi = min(sp.lo, at), max(sp.hi, at)
			return
		}
	}
	if len(v.spans) >= maxSpans {
		oldest := 0
		for i, sp := range v.spans {
			if sp.hi < v.spans[oldest].hi {
				oldest = i
			}
		}
		v.spans = append(v.spans[:oldest], v.spans[oldest+1:]...)
	}
	v.spans = append(v.spans, span{lo: at, hi: at, svc: svc})
}

// find 返回会话开始时间所在（前后各 pairTTL 以内）的段的服务，有多段时取最近的。
func (v pairVal) find(start int64) string {
	gap := int64(pairTTL / time.Second)
	best, dist := "", int64(-1)
	for _, sp := range v.spans {
		if start < sp.lo-gap || start > sp.hi+gap {
			continue
		}
		d := int64(0)
		if start < sp.lo {
			d = sp.lo - start
		} else if start > sp.hi {
			d = start - sp.hi
		}
		if dist < 0 || d < dist {
			best, dist = sp.svc, d
		}
	}
	return best
}

// seen 是一个服务首次 / 最近出现的时间（不受统计保留期限制，用于“新出现的 AI 服务”）。
type seen struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// Candidate 是不在目录中、但域名具有 AI 服务特征的域名（待确认）。
type Candidate struct {
	Domain  string    `json:"domain"` // 注册域名（如 example-gpt.com）
	Sample  string    `json:"sample"` // 一个出现过的完整域名
	Reason  string    `json:"reason"`
	Hits    int64     `json:"hits"`
	Clients int       `json:"clients"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Ignored bool      `json:"ignored,omitempty"`

	clients map[string]struct{}
}

// Endpoint 是 Web 日志中出现大模型接口路径的站点。
type Endpoint struct {
	Host     string    `json:"host"` // Host 头（含端口），没有时为 目的地址:端口
	Kind     string    `json:"kind"` // openai / anthropic / ollama / gemini / dify
	Path     string    `json:"path"` // 一个出现过的路径（不含参数）
	Service  string    `json:"service,omitempty"`
	Internal bool      `json:"internal"` // 服务在内网（目的地址或 Host 是内网地址）
	Hits     int64     `json:"hits"`
	Clients  int       `json:"clients"`
	External int       `json:"external"` // 其中来自外网的来源数
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`

	clients map[string]struct{}
}

// EndpointKindLabel 是接口类型的说明。
var EndpointKindLabel = map[string]string{"openai": "OpenAI 兼容接口", "anthropic": "Anthropic 接口", "ollama": "Ollama 接口", "gemini": "Gemini 接口", "dify": "Dify 应用接口"}

// Options 是统计的配置。
type Options struct {
	Services      []Service         // 配置文件中的服务（与内置同编号时覆盖内置）
	Policies      map[string]string // 配置文件中的策略
	Disable       []string          // 停用的内置服务
	RetentionDays int
	MaxRecords    int
	Location      *time.Location
	Path          string // 状态文件
}

// Manager 统计 AI 服务的使用情况，可并发调用。
type Manager struct {
	mu       sync.Mutex
	loc      *time.Location
	keepDays int
	maxRecs  int
	path     string

	cfgSvcs  []Service         // 内置 + 配置文件
	uiSvcs   []Service         // 页面登记
	cfgPol   map[string]string // 配置文件的策略
	uiPol    map[string]string // 页面设定的策略
	disabled map[string]bool
	services map[string]*Service // 生效的目录（编号 → 服务）
	order    []string            // 目录顺序
	match    atomic.Pointer[matcher]

	cells      map[cellKey]*cell
	minDay     day
	flows      map[flowKey]flowVal
	pairs      map[pairKey]*pairVal
	svcSeen    map[string]*seen
	candidates map[string]*Candidate
	endpoints  map[string]*Endpoint

	dropped   int64 // 超过上限没有记录的
	bytesSeen bool  // 有会话字节被归到 AI 服务（页面据此提示上传量是否可用）
	sniSeen   bool
	dirty     bool
	lastSave  time.Time
	now       func() time.Time
}

// New 创建统计（不读取状态文件，见 Load）。
func New(opt Options) (*Manager, error) {
	m := &Manager{loc: opt.Location, keepDays: opt.RetentionDays, maxRecs: opt.MaxRecords, path: opt.Path,
		cfgPol: map[string]string{}, uiPol: map[string]string{}, disabled: map[string]bool{},
		cells: map[cellKey]*cell{}, flows: map[flowKey]flowVal{}, pairs: map[pairKey]*pairVal{}, svcSeen: map[string]*seen{},
		candidates: map[string]*Candidate{}, endpoints: map[string]*Endpoint{}, now: time.Now}
	if m.loc == nil {
		m.loc = time.Local
	}
	if m.keepDays <= 0 {
		m.keepDays = defaultRetention
	}
	if m.maxRecs <= 0 {
		m.maxRecs = defaultMaxRecords
	}
	for _, id := range opt.Disable {
		m.disabled[strings.TrimSpace(id)] = true
	}
	list := Builtin()
	index := map[string]int{}
	for i, s := range list {
		index[s.ID] = i
	}
	for _, c := range opt.Services {
		c.Source = SourceConfig
		c.Policy = strings.ToLower(strings.TrimSpace(c.Policy))
		c.Category = strings.ToLower(strings.TrimSpace(c.Category))
		c.Region = strings.ToLower(strings.TrimSpace(c.Region))
		if c.ID == "" {
			c.ID = "cfg-" + shortHash(strings.ToLower(strings.TrimSpace(c.Name)))
		}
		if i, ok := index[c.ID]; ok { // 覆盖内置：只替换填写了的字段
			b := list[i]
			if c.Name == "" {
				c.Name = b.Name
			}
			if c.Vendor == "" {
				c.Vendor = b.Vendor
			}
			if c.Category == "" {
				c.Category = b.Category
			}
			if c.Region == "" {
				c.Region = b.Region
			}
			if len(c.Domains) == 0 {
				c.Domains = b.Domains
			}
			if err := c.prepare(); err != nil {
				return nil, errorf("ai_usage.services[%s]: %v", c.ID, err)
			}
			list[i] = c
			continue
		}
		if err := c.prepare(); err != nil {
			return nil, errorf("ai_usage.services[%s]: %v", c.Name, err)
		}
		index[c.ID] = len(list)
		list = append(list, c)
	}
	if len(list) > maxServices {
		return nil, errorf("ai_usage.services 过多（最多 %d 个）", maxServices)
	}
	for i := range list {
		if p := list[i].Policy; p != "" {
			m.cfgPol[list[i].ID] = p
		}
	}
	for id, p := range opt.Policies {
		p = strings.ToLower(strings.TrimSpace(p))
		if err := validPolicy(p); err != nil {
			return nil, errorf("ai_usage.policies[%s]: %v", id, err)
		}
		if _, ok := index[id]; !ok {
			return nil, errorf("ai_usage.policies[%s]: 目录中没有这个服务（编号见 AI 使用 → 服务目录）", id)
		}
		m.cfgPol[id] = p
	}
	m.cfgSvcs = list
	m.rebuildLocked()
	return m, nil
}

func errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }

func shortHash(s string) string {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return strconv.FormatUint(h, 36)
}

// rebuildLocked 按内置、配置与页面登记的服务重建生效的目录与匹配索引（调用方持锁或在初始化中）。
func (m *Manager) rebuildLocked() {
	m.services = map[string]*Service{}
	m.order = m.order[:0]
	var list []*Service
	add := func(s Service) {
		if m.disabled[s.ID] && s.Source == SourceBuiltin {
			return
		}
		if _, dup := m.services[s.ID]; dup {
			return
		}
		cp := s
		cp.Domains = append([]string(nil), s.Domains...)
		cp.Policy, cp.PolicyFrom = "", ""
		if p, ok := m.cfgPol[s.ID]; ok {
			cp.Policy, cp.PolicyFrom = p, SourceConfig
		}
		if p, ok := m.uiPol[s.ID]; ok {
			cp.Policy, cp.PolicyFrom = p, SourceUI
		}
		m.services[s.ID] = &cp
		m.order = append(m.order, s.ID)
		list = append(list, &cp)
	}
	for _, s := range m.uiSvcs { // 页面登记的服务优先匹配：用于把目录里较宽的域名下的具体子域名单独统计
		add(s)
	}
	for _, s := range m.cfgSvcs {
		add(s)
	}
	m.match.Store(newMatcher(list))
}

// dayOf 返回时间所在的自然日编号。
func (m *Manager) dayOf(t time.Time) day {
	y, mo, d := t.In(m.loc).Date()
	return day(time.Date(y, mo, d, 0, 0, 0, 0, time.UTC).Unix() / 86400)
}

// dateOf 返回自然日编号对应的日期（配置时区的零点）。
func (m *Manager) dateOf(d day) time.Time {
	u := time.Unix(int64(d)*86400, 0).UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, m.loc)
}

// internal 判断地址是否为内网终端。
func internal(ip string) bool { return ip != "" && geo.IsPrivate(ip) }

// Observe 统计一条事件。由流水线的汇总协程调用；不匹配任何 AI 服务的事件只做几次查表，不加锁。
func (m *Manager) Observe(ev *model.Event) {
	if m == nil || ev == nil || ev.Replay || ev.Response {
		return
	}
	switch {
	case ev.Kind == model.KindDNS:
		if ev.Flags == "R" || !internal(ev.SrcIP) {
			return
		}
		name := normName(ev.Host)
		if name == "" {
			return
		}
		if svc := m.match.Load().match(name); svc != "" {
			rc := strings.ToUpper(ev.RCode)
			denied := rc == "NXDOMAIN" || rc == "REFUSED"
			m.record(ev.Time, svc, ev.SrcIP, func(c *cell) {
				if denied {
					c.denied++
				} else {
					c.queries++
				}
			})
			return
		}
		m.candidate(ev.Time, name, ev.SrcIP)
	case ev.SNI != "":
		if !internal(ev.SrcIP) || ev.DstIP == "" || internal(ev.DstIP) {
			return
		}
		name := normName(ev.SNI)
		if name == "" {
			return
		}
		svc := m.match.Load().match(name)
		if svc == "" {
			m.candidate(ev.Time, name, ev.SrcIP)
			return
		}
		denied := ev.Reply == model.ReplyNone
		m.mu.Lock()
		m.sniSeen = true
		if !denied {
			m.learnFlowLocked(ev, svc)
		}
		m.recordLocked(ev.Time, svc, ev.SrcIP, func(c *cell) {
			if denied {
				c.denied++
			} else {
				c.conns++
			}
		})
		m.mu.Unlock()
	case ev.Kind == model.KindWeb:
		m.endpoint(ev)
		if !internal(ev.SrcIP) || ev.DstIP != "" && internal(ev.DstIP) {
			return
		}
		name := normName(ev.Host)
		if name == "" {
			return
		}
		svc := m.match.Load().match(name)
		if svc == "" {
			return
		}
		m.record(ev.Time, svc, ev.SrcIP, func(c *cell) {
			c.conns++
			c.up = satAdd(c.up, max(ev.ReqLength, 0))
			c.down = satAdd(c.down, max(ev.Bytes, 0))
		})
	case ev.Kind == model.KindFirewall && !ev.Aux:
		if ev.SentBytes <= 0 && ev.RecvBytes <= 0 || !internal(ev.SrcIP) || ev.DstIP == "" {
			return
		}
		m.attributeBytes(ev)
	}
}

// learnFlowLocked 记录 SNI 确认的连接与“终端 + 目的地址”，之后的会话日志据此把字节归到服务。
func (m *Manager) learnFlowLocked(ev *model.Event, svc string) {
	now := m.now().Unix()
	at := ev.Time.Unix()
	if ev.Time.IsZero() {
		at = now
	}
	if ev.SrcPort > 0 && ev.DstPort > 0 {
		k := flowKey{src: ev.SrcIP, dst: ev.DstIP, sport: uint16(ev.SrcPort), dport: uint16(ev.DstPort)}
		if _, ok := m.flows[k]; !ok {
			if len(m.flows) >= maxFlows {
				sweep(m.flows, now)
			}
			if len(m.flows) < maxFlows {
				k.src, k.dst = strings.Clone(k.src), strings.Clone(k.dst)
				m.flows[k] = flowVal{svc: svc, at: at, exp: now + int64(flowTTL/time.Second)}
			}
		}
	}
	pk := pairKey{src: ev.SrcIP, dst: ev.DstIP}
	v := m.pairs[pk]
	if v == nil {
		if len(m.pairs) >= maxPairs {
			sweep(m.pairs, now)
		}
		if len(m.pairs) >= maxPairs {
			return
		}
		v = &pairVal{}
		pk.src, pk.dst = strings.Clone(pk.src), strings.Clone(pk.dst)
		m.pairs[pk] = v
	}
	v.add(at, svc)
	v.exp = now + int64(pairTTL/time.Second)
}

// sweep 删除过期的条目。
func sweep[K comparable, V interface{ expiry() int64 }](mp map[K]V, now int64) {
	for k, v := range mp {
		if v.expiry() < now {
			delete(mp, k)
		}
	}
}

// attributeBytes 把会话日志的字节数归到此前 SNI 确认过的 AI 服务：先按完整的连接四元组（Zeek conn.log 与 ssl.log
// 是同一条连接），再按“终端 + 目的地址”（防火墙记录的源端口可能与流量探针看到的不同）。
func (m *Manager) attributeBytes(ev *model.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pairs) == 0 {
		return
	}
	// 会话开始的日志时间：会话日志在连接结束时输出，有时长时往前推
	start := ev.Time.Unix()
	if ev.Time.IsZero() {
		start = m.now().Unix()
	}
	if ev.Duration > 0 {
		start -= int64(ev.Duration)
	}
	within := func(v flowVal, ttl time.Duration) bool {
		d := start - v.at
		return d >= -int64(ttl/time.Second) && d <= int64(ttl/time.Second)
	}
	svc := ""
	if ev.SrcPort > 0 && ev.DstPort > 0 {
		k := flowKey{src: ev.SrcIP, dst: ev.DstIP, sport: uint16(ev.SrcPort), dport: uint16(ev.DstPort)}
		if v, ok := m.flows[k]; ok {
			delete(m.flows, k) // 一条连接只有一条会话结束记录
			if within(v, flowTTL) {
				svc = v.svc
			}
		}
	}
	if svc == "" {
		if v := m.pairs[pairKey{src: ev.SrcIP, dst: ev.DstIP}]; v != nil {
			svc = v.find(start)
		}
	}
	if svc == "" {
		return
	}
	m.bytesSeen = true
	m.recordLocked(ev.Time, svc, ev.SrcIP, func(c *cell) {
		c.up = satAdd(c.up, max(ev.SentBytes, 0))
		c.down = satAdd(c.down, max(ev.RecvBytes, 0))
	})
}

func (m *Manager) record(t time.Time, svc, ip string, fn func(*cell)) {
	m.mu.Lock()
	m.recordLocked(t, svc, ip, fn)
	m.mu.Unlock()
}

// recordLocked 更新一个终端在当天使用该服务的统计（调用方持锁）。
func (m *Manager) recordLocked(t time.Time, svc, ip string, fn func(*cell)) {
	now := m.now()
	if t.IsZero() || t.After(now.Add(time.Hour)) || t.Year() < 2000 {
		t = now
	}
	d := m.dayOf(t)
	if d < m.dayOf(now)-day(m.keepDays) {
		return // 早于保留期的历史日志
	}
	if strings.IndexByte(ip, ':') >= 0 { // IPv6 统一写法（大小写、零压缩），页面按规范写法查询
		if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.Unmap().WithZone("").String()
		}
	}
	k := cellKey{d: d, svc: svc, ip: ip}
	c := m.cells[k]
	if c == nil {
		if len(m.cells) >= m.maxRecs && !m.evictOldestLocked(d) {
			m.dropped++
			return
		}
		k.ip = strings.Clone(ip) // 不引用日志原文（否则整行原始日志无法回收）
		c = &cell{first: t.Unix()}
		m.cells[k] = c
		if d < m.minDay || m.minDay == 0 {
			m.minDay = d
		}
	}
	u := t.Unix()
	if u < c.first {
		c.first = u
	}
	if u > c.last {
		c.last = u
	}
	fn(c)
	if s := m.svcSeen[svc]; s == nil {
		m.svcSeen[svc] = &seen{First: t, Last: t}
	} else {
		if t.Before(s.First) {
			s.First = t
		}
		if t.After(s.Last) {
			s.Last = t
		}
	}
	m.dirty = true
}

// evictOldestLocked 记录数达到上限时淘汰最早一天的记录；新记录本身就在最早一天时不淘汰（返回 false）。
func (m *Manager) evictOldestLocked(d day) bool {
	oldest := day(1 << 30)
	for k := range m.cells {
		oldest = min(oldest, k.d)
	}
	if oldest >= d {
		return false
	}
	for k := range m.cells {
		if k.d == oldest {
			delete(m.cells, k)
		}
	}
	m.minDay = oldest + 1
	return true
}

// ---------------- 目录之外的发现 ----------------

// aiWords 是域名中常见于 AI 服务、API 中转站的特征词（按 . - _ 分隔后的完整词，或以它开头）。
var aiWords = []string{"openai", "chatgpt", "gpt", "claude", "anthropic", "deepseek", "llm", "ollama", "aigc", "chatglm", "qwen", "midjourney", "comfyui"}

// candidateReason 判断不在目录中的域名是否像 AI 服务，返回原因。
func candidateReason(name string) string {
	quick := false
	for _, w := range aiWords {
		if strings.Contains(name, w) {
			quick = true
			break
		}
	}
	if quick {
		for _, tok := range strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
			for _, w := range aiWords {
				if tok == w || strings.HasPrefix(tok, w) && (w != "gpt" || len(tok) <= 8) {
					return "域名含 “" + w + "”"
				}
			}
		}
	}
	if strings.HasSuffix(name, ".ai") {
		return "使用 .ai 顶级域名"
	}
	return ""
}

// multiSuffix 是两级的公共后缀：注册域名取三级。
var multiSuffix = map[string]bool{"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true, "ac.cn": true, "co.uk": true,
	"org.uk": true, "co.jp": true, "com.hk": true, "com.tw": true, "com.sg": true, "co.kr": true, "com.au": true}

// registered 返回域名的注册域名（example.com、example.com.cn）。
func registered(name string) string {
	parts := strings.Split(name, ".")
	n := 2
	if len(parts) >= 3 && multiSuffix[parts[len(parts)-2]+"."+parts[len(parts)-1]] {
		n = 3
	}
	if len(parts) <= n {
		return name
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

// candidate 记录疑似 AI 服务的域名。
func (m *Manager) candidate(t time.Time, name, client string) {
	reason := candidateReason(name)
	if reason == "" {
		return
	}
	reg := registered(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.candidates[reg]
	if c == nil {
		if len(m.candidates) >= maxCandidates {
			return
		}
		c = &Candidate{Domain: strings.Clone(reg), Sample: strings.Clone(name), Reason: reason, First: t, Last: t, clients: map[string]struct{}{}}
		m.candidates[c.Domain] = c
	}
	c.Hits++
	if t.After(c.Last) {
		c.Last = t
	}
	if t.Before(c.First) {
		c.First = t
	}
	if _, ok := c.clients[client]; !ok && len(c.clients) < maxSetSize {
		c.clients[strings.Clone(client)] = struct{}{}
		c.Clients = len(c.clients)
	}
	m.dirty = true
}

// endpointKind 按路径识别大模型接口。Ollama 的路径（/api/chat、/api/tags）在其他系统里也常见，只认默认端口 11434。
func endpointKind(path string, port int) string {
	p := strings.ToLower(path)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSuffix(p, "/")
	switch {
	case strings.HasSuffix(p, "/chat/completions"), strings.HasSuffix(p, "/v1/completions"), strings.HasSuffix(p, "/v1/embeddings"),
		strings.HasSuffix(p, "/v1/responses"), strings.HasSuffix(p, "/v1/images/generations"), strings.HasSuffix(p, "/v1/audio/transcriptions"),
		p == "/v1/models":
		return "openai"
	case p == "/v1/messages", p == "/v1/messages/count_tokens", strings.HasSuffix(p, "/anthropic/v1/messages"):
		return "anthropic"
	case strings.Contains(p, ":generatecontent"), strings.Contains(p, ":streamgeneratecontent"):
		return "gemini"
	case strings.HasSuffix(p, "/v1/chat-messages"), strings.HasSuffix(p, "/v1/completion-messages"), strings.HasSuffix(p, "/v1/workflows/run"):
		return "dify"
	}
	if port == 11434 {
		switch p {
		case "/api/generate", "/api/chat", "/api/tags", "/api/pull", "/api/show", "/api/embed", "/api/embeddings", "/api/ps", "/api/create", "/api/push", "/api/version":
			return "ollama"
		}
	}
	return ""
}

// hostPort 取出 Host 头中的端口（没有时返回 0）。
func hostPort(h string) int {
	i := strings.LastIndexByte(h, ':')
	if i < 0 || strings.Count(h, ":") > 1 && !strings.Contains(h, "]") {
		return 0
	}
	n := 0
	for _, c := range h[i+1:] {
		if c < '0' || c > '9' || n > 65535 {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// endpoint 记录 Web 日志中的大模型接口。只记录存在的接口（2xx / 3xx、需要认证的 401 / 403、方法不对的 405、限流的 429）：
// 扫描器在各个网站上探测 /v1/models 时多是 404，不能把这些网站当成模型服务。
func (m *Manager) endpoint(ev *model.Event) {
	if ev.URI == "" || ev.SrcIP == "" {
		return
	}
	if st := ev.Status; st != 0 && !(st >= 200 && st < 404 || st == 405 || st == 429) {
		return
	}
	host := strings.ToLower(model.Printable(ev.Host, 120))
	port := hostPort(host)
	if port == 0 {
		port = ev.DstPort
	}
	kind := endpointKind(ev.URI, port)
	if kind == "" {
		return
	}
	if host == "" {
		if ev.DstIP == "" {
			return
		}
		host = ev.DstIP
		if ev.DstPort > 0 {
			host = net.JoinHostPort(ev.DstIP, strconv.Itoa(ev.DstPort))
		}
	}
	path := ev.URI
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = model.Printable(path, 120)
	h := host
	if i := strings.LastIndexByte(h, ':'); i > 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	isInternal := ev.DstIP != "" && internal(ev.DstIP) || internal(strings.Trim(h, "[]"))
	svc := m.match.Load().match(normName(h))
	t := ev.Time
	key := host + "|" + kind
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.endpoints[key]
	if e == nil {
		if len(m.endpoints) >= maxEndpoints {
			return
		}
		e = &Endpoint{Host: strings.Clone(host), Kind: kind, Path: strings.Clone(path), Service: svc, Internal: isInternal, First: t, Last: t, clients: map[string]struct{}{}}
		m.endpoints[key] = e
	}
	e.Hits++
	if t.After(e.Last) {
		e.Last = t
	}
	if t.Before(e.First) {
		e.First = t
	}
	if _, ok := e.clients[ev.SrcIP]; !ok && len(e.clients) < maxSetSize {
		e.clients[strings.Clone(ev.SrcIP)] = struct{}{}
		e.Clients = len(e.clients)
		if !internal(ev.SrcIP) {
			e.External++
		}
	}
	m.dirty = true
}

// satAdd 是不溢出的加法。
func satAdd(a, b int64) int64 {
	if b > 0 && a > (1<<63-1)-b {
		return 1<<63 - 1
	}
	return a + b
}

// ---------------- 维护 ----------------

// Prune 删除保留期之外的记录与长期没有出现的疑似域名、AI 接口。
func (m *Manager) Prune() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	cut := m.dayOf(now) - day(m.keepDays)
	if m.minDay != 0 && m.minDay < cut {
		for k := range m.cells {
			if k.d < cut {
				delete(m.cells, k)
				m.dirty = true
			}
		}
		m.minDay = cut
	}
	old := now.AddDate(0, 0, -m.keepDays)
	for k, c := range m.candidates {
		if c.Last.Before(old) && !c.Ignored {
			delete(m.candidates, k)
			m.dirty = true
		}
	}
	for k, e := range m.endpoints {
		if e.Last.Before(old) {
			delete(m.endpoints, k)
			m.dirty = true
		}
	}
	sweep(m.flows, now.Unix())
	sweep(m.pairs, now.Unix())
}

// Records 返回当前的记录数（指标与测试使用）。
func (m *Manager) Records() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cells)
}
