package learn

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/detect"
	"netsa/internal/model"
)

// 从正常流量中学习参数的正常取值（参照 naxsi 的学习模式，但不需要人工整理白名单）：
// 按「站点 + 路径形态 + 参数名」统计正常请求中参数取值的形态。
//
//   - 压低误报：SQL 注入 / XSS 规则命中在平时就填写普通文字的参数里（搜索框、标题、备注），而语法分析（libinjection）
//     又判定取值不构成注入，按普通文字处理，最高低危。两个相互独立的依据同时成立才降级，单凭任何一个都不降；
//     只有语法分析认定、没有命中注入规则的 SQL 注入（sqli-syntax）出现在这类参数里，同样按低危处置（引号、括号多的普通文字）。
//     降级只到低危、仍然生成告警，不隐藏；有证据的成功利用、已确认攻击源的请求不降级。
//   - 发现异常：平时只出现数字、编号、单个词的参数，出现了引号、括号、尖括号等注入符号，生成低危观察命中。
//
// 防投毒：只用没有命中攻击规则、来源不是已确认攻击源的请求学习；同一网段（IPv4 /24、IPv6 /48）的来源只算一个，
// 参数要有足够多的正常取值、来自足够多的网段才参与判断。

const (
	maxProfiles      = 20000 // 最多学习的参数个数
	profileMinObs    = 200   // 参数参与判断所需的最少正常取值次数
	profileMinNets   = 20    // 以及最少的来源网段数
	maxProfileNets   = 32
	maxProfileParams = 16 // 每个请求最多学习的参数个数
	profileKeepDays  = 30 // 超过这么多天没再出现的参数不再保留
)

// valueClass 是参数取值的形态。
type valueClass uint8

const (
	vcEmpty  valueClass = iota
	vcNum               // 数字
	vcID                // 十六进制、UUID、字母数字混合的编号
	vcToken             // 不含空格与注入符号的单个词：枚举值、日期、文件名、邮箱、链接
	vcText              // 自由文本：含空格、中文或注入符号
	vcStruct            // JSON、数组等结构化取值
	vcCount
)

// injectMeta 是注入离不开的符号。
const injectMeta = "'\"<>`;()$|\\"

// classify 判断取值的形态，并返回是否含有注入符号。
func classify(v string) (valueClass, bool) {
	meta := strings.ContainsAny(v, injectMeta)
	if v == "" {
		return vcEmpty, false
	}
	if v[0] == '{' || v[0] == '[' {
		return vcStruct, meta
	}
	num, hex, alnum, token := true, true, true, true
	digit, letter := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		isD := c >= '0' && c <= '9'
		isL := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit, letter = digit || isD, letter || isL
		if !isD && c != '.' && (c != '-' || i > 0) {
			num = false
		}
		if !isD && !(c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') && c != '-' {
			hex = false
		}
		if !isD && !isL {
			alnum = false
		}
		if !isD && !isL && !strings.ContainsRune("_-.:,@/+=?&%#~!*", rune(c)) {
			token = false // 空格、注入符号、中文等
		}
	}
	switch {
	case num && digit:
		return vcNum, meta
	case hex && digit && len(v) >= 8, alnum && digit && letter && len(v) >= 10:
		return vcID, meta
	case token:
		return vcToken, meta
	}
	return vcText, meta
}

// paramStat 是一个参数的正常取值统计。
type paramStat struct {
	N      uint32          `json:"n"`
	Class  [vcCount]uint32 `json:"class"`
	Meta   uint32          `json:"meta"` // 含注入符号的正常取值次数
	MaxLen int             `json:"max_len"`
	Nets   []uint32        `json:"nets,omitempty"` // 来源网段的哈希
	Last   time.Time       `json:"last"`
}

func (s *paramStat) mature() bool { return s.N >= profileMinObs && len(s.Nets) >= profileMinNets }

// freeText 判断参数平时就填写普通文字：至少 5% 的正常取值是自由文本。
func (s *paramStat) freeText() bool { return uint64(s.Class[vcText])*20 >= uint64(s.N) }

// strict 判断参数平时只出现数字、编号、单个词：自由文本与结构化取值不到 1%，且从未出现注入符号。
func (s *paramStat) strict() bool {
	return s.Meta == 0 && uint64(s.Class[vcText]+s.Class[vcStruct])*100 < uint64(s.N)
}

// shapeText 描述参数平时的取值形态。
func (s *paramStat) shapeText() string {
	if s.Class[vcNum]+s.Class[vcEmpty] == s.N {
		return "数字"
	}
	if s.Class[vcNum]+s.Class[vcID]+s.Class[vcEmpty] == s.N {
		return "数字或编号"
	}
	return "数字、编号或单个词"
}

// profileState 是参数取值与站点产品的学习状态，有自己的锁：每条正常的 Web 日志都会进来，不与研判反馈争用 l.mu。
// 加锁顺序与攻击行为学习相同：先 l.mu 后 prof.mu。
type profileState struct {
	mu        sync.Mutex
	params    map[string]*paramStat   // 站点 路径形态?参数名
	sites     map[string]*siteStat    // 站点（见 site.go）
	endpoints map[string]*endpointUse // 站点 漏洞接口签名 → 正常访问（见 businessLocked）
	dirty     bool                    // 有接口刚被认定为业务接口，需要落盘

	weak, anomaly, inapplicable, business atomic.Int64 // 本次启动以来生效的次数
}

// 业务接口学习：存在已知漏洞的接口也可能是正常业务在用（致远 OA 的 htmlofficeservlet 就是正文编辑插件的接口）。
// 站点有足够多的正常访问时，同一接口被足够多网段的访客访问、访客此前没有任何攻击记录、请求中也没有攻击载荷，
// 就是正常业务接口（扫描器通常先打过别的探测，不计入）。
// 之后只访问接口、没有载荷的请求降为低危。载荷在请求体里时日志本来就看不到，能看到载荷的照常告警。
// 不要求先识别出产品：不少产品没有专属目录，否则这些产品的站点上正常业务会一直按中危告警。
const (
	endpointNets = 8    // 至少这么多网段的访客正常访问过
	maxEndpoints = 5000 // 最多记录的接口
)

// endpointUse 是一个漏洞接口的正常访问统计。
type endpointUse struct {
	Name  string    `json:"name"` // 签名名称
	Nets  []uint32  `json:"nets"`
	Hits  uint32    `json:"hits"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// businessLocked 记录一次只访问漏洞接口、没有载荷的请求，返回该接口是否已认定为正常业务接口（调用方持 st.mu）。
func (st *profileState) businessLocked(ev *model.Event, host string, h *model.Hit, hits []model.Hit, confirmed bool, prior int64, at time.Time) (*endpointUse, bool) {
	if at.IsZero() {
		at = time.Now()
	}
	k := host + " " + h.RuleID
	u := st.endpoints[k]
	clean := !confirmed && prior == 0 && ev.Status >= 200 && ev.Status < 400
	for _, x := range hits {
		clean = clean && (x.TagOnly || x.Category == detect.CatVulnEndpoint)
	}
	if s := st.sites[host]; clean && s != nil && s.mature() {
		if u == nil && len(st.endpoints) < maxEndpoints {
			if st.endpoints == nil {
				st.endpoints = map[string]*endpointUse{}
			}
			u = &endpointUse{Name: h.Name, First: at}
			st.endpoints[k] = u
		}
		if u != nil {
			u.Hits++
			was := len(u.Nets) >= endpointNets
			addNet(&u.Nets, netHash(ev.SrcIP), 16)
			st.dirty = st.dirty || !was && len(u.Nets) >= endpointNets // 刚认定为业务接口：落盘
			if at.After(u.Last) {
				u.Last = at
			}
		}
	}
	// 降级同样只给此前没有攻击记录的访客：扫描器在真实的 OA 站点上找到了存在漏洞的接口，这个信号不能压低
	return u, u != nil && len(u.Nets) >= endpointNets && !confirmed && prior == 0
}

// netHash 返回来源所在网段（IPv4 /24、IPv6 /48）的哈希，解析失败返回 0。
func netHash(ip string) uint32 {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return 0
	}
	h := uint32(2166136261)
	for _, c := range p.Addr().AsSlice() {
		h ^= uint32(c)
		h *= 16777619
	}
	return h | 1
}

func addNet(list *[]uint32, h uint32, limit int) {
	if h == 0 || len(*list) >= limit {
		return
	}
	for _, x := range *list {
		if x == h {
			return
		}
	}
	*list = append(*list, h)
}

// siteKey 归一站点名：小写、去掉端口，空时为 "-"。
func siteKey(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") && strings.Count(host, ":") == 1 {
		host = host[:i]
	}
	if host == "" || len(host) > 100 {
		return "-"
	}
	return host
}

func paramKey(host, shape, name string) string { return host + " " + shape + "?" + name }

// Profile 在攻击行为学习之前调用：用学到的参数正常取值与站点产品复核命中（降级、标注、发现取值异常），
// 再用正常请求继续学习。train 为 false 时（白名单来源）只复核、不学习。返回的切片为副本，不修改调用方的数据。
func (l *Learner) Profile(ev *model.Event, hits []model.Hit, train bool) []model.Hit {
	if l == nil || ev == nil || ev.Kind != model.KindWeb || ev.URI == "" || ev.URI[0] != '/' {
		return hits
	}
	benign := true
	for _, h := range hits {
		if !h.TagOnly && !h.Weak {
			benign = false
			break
		}
	}
	if benign && !train {
		return hits
	}
	at := ev.Time
	if at.IsZero() {
		at = time.Now()
	}
	_, confirmed := l.confirmedSource(ev.SrcIP, at)
	var prior int64 // 访客此前的攻击次数：只在业务接口学习时查询（在 prof.mu 之外，查询会取状态库的锁）
	if !benign && l.PriorAttacks != nil {
		for _, h := range hits {
			if h.Category == detect.CatVulnEndpoint {
				prior = l.PriorAttacks(ev.SrcIP)
				break
			}
		}
	}
	path, query, _ := strings.Cut(ev.URI, "?")
	lp := strings.ToLower(path)
	host, shape := siteKey(ev.Host), pathShape(lp)
	if len(shape) > 200 {
		return hits
	}
	var ps []detect.Param
	if query != "" {
		ps = detect.QueryParams(ev.URI)
	}
	st := &l.prof
	out, learned := hits, false
	st.mu.Lock()
	switch {
	case !benign:
		out = st.reviewLocked(ev, hits, host, shape, lp, ps, confirmed, prior)
	default:
		if h, ok := st.anomalyLocked(host, shape, ps); ok {
			out = append(hits[:len(hits):len(hits)], h)
			break // 取值异常的请求不用来学习
		}
		if !confirmed { // 已确认攻击源的请求不用来学习
			learned = st.trainLocked(ev, host, shape, lp, ps, at)
		}
	}
	learned, st.dirty = learned || st.dirty, false
	st.mu.Unlock()
	if learned { // 有参数开始生效、识别出新的站点产品或业务接口：落盘
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
	}
	return out
}

// reviewLocked 复核攻击请求的命中（调用方持 st.mu）。
func (st *profileState) reviewLocked(ev *model.Event, hits []model.Hit, host, shape, lp string, ps []detect.Param, confirmed bool, prior int64) []model.Hit {
	var out []model.Hit
	edit := func(i int) *model.Hit {
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		return &out[i]
	}
	for i := range hits {
		h := &hits[i]
		if h.TagOnly || h.Weak || h.Proven {
			continue
		}
		if h.Param != "" && (h.Category == detect.CatSQLi || h.Category == detect.CatXSS) {
			s := st.params[paramKey(host, shape, h.Param)]
			if s == nil || !s.mature() {
				continue
			}
			v := valueOf(ps, h.Param)
			oneSignal := h.Syntax < 0 || h.RuleID == "sqli-syntax" // 规则与语法分析只有一方认定为注入
			switch {
			case oneSignal && !confirmed && s.freeText() && len(v) <= max(2*s.MaxLen, 64):
				e := edit(i)
				e.Weak = true
				if e.Result == model.ResultSuccess {
					e.Result = model.ResultPassed
				}
				why := "语法分析判定不构成注入"
				if h.RuleID == "sqli-syntax" {
					why = "只有语法分析认定、没有命中注入规则"
				}
				e.Evidence += fmt.Sprintf("；自学习：参数 %s 平时就填写普通文字（%d 次正常访问、%d 个网段的访客），%s，按普通文字处理、最高低危",
					h.Param, s.N, len(s.Nets), why)
				st.weak.Add(1)
			case s.strict():
				if c, meta := classify(v); meta || c == vcText || c == vcStruct {
					edit(i).Evidence += fmt.Sprintf("；参数 %s 平时只出现%s（%d 次正常访问），本次取值偏离了正常形态", h.Param, s.shapeText(), s.N)
				}
			}
			continue
		}
		if h.Category == detect.CatVulnEndpoint {
			if u, ok := st.businessLocked(ev, host, h, hits, confirmed, prior, ev.Time); ok {
				e := edit(i)
				e.Weak = true
				e.Evidence += fmt.Sprintf("；自学习：这是站点 %s 上的正常业务接口（%d 个网段的访客访问过、请求中没有攻击载荷），最高低危", host, len(u.Nets))
				st.business.Add(1)
				continue
			}
		}
		if h.Result != model.ResultFailed && h.Result != model.ResultBlocked && h.Result != model.ResultError {
			continue // 只判断没有成功的探测：成功的请求说明目标确实存在，交给响应复核
		}
		techs := requiredTech(h, lp)
		if len(techs) == 0 {
			continue
		}
		s := st.sites[host]
		if s == nil || !s.mature() || s.hasAny(techs) {
			continue
		}
		e := edit(i)
		e.Inapplicable = true
		e.Evidence += fmt.Sprintf("；自学习：站点 %s 已有 %d 次正常访问，从未出现 %s 的访问痕迹，请求也没有成功：攻击针对的产品不存在，最高低危",
			host, s.Reqs, techText(techs))
		st.inapplicable.Add(1)
	}
	if out == nil {
		return hits
	}
	return out
}

// anomalyLocked 检查正常请求（没有命中攻击规则）的参数是否偏离学到的形态（调用方持 st.mu）。
func (st *profileState) anomalyLocked(host, shape string, ps []detect.Param) (model.Hit, bool) {
	for i, p := range ps {
		if i >= maxProfileParams {
			break
		}
		s := st.params[paramKey(host, shape, p.Name)]
		if s == nil || !s.mature() || !s.strict() {
			continue
		}
		if c, meta := classify(p.Value); meta && (c == vcText || c == vcStruct) {
			st.anomaly.Add(1)
			return model.Hit{RuleID: "learn-param", Name: "参数取值偏离正常形态", Category: CatLearned, Severity: model.SevLow,
				Phase: model.PhaseExploit, Result: model.ResultUnknown, Param: p.Name,
				Evidence: fmt.Sprintf("参数 %s 在 %d 次正常访问中只出现%s，本次取值 %s 含有注入符号（自学习）",
					p.Name, s.N, s.shapeText(), detect.Printable(p.Value, 120))}, true
		}
	}
	return model.Hit{}, false
}

// trainLocked 用正常请求学习参数取值与站点产品（调用方持 st.mu），返回是否有参数开始生效或识别出新的产品。
func (st *profileState) trainLocked(ev *model.Event, host, shape, lp string, ps []detect.Param, at time.Time) bool {
	nh := netHash(ev.SrcIP)
	if nh == 0 {
		return false
	}
	if st.params == nil {
		st.params = map[string]*paramStat{}
	}
	changed := false
	for i, p := range ps {
		if i >= maxProfileParams {
			break
		}
		if p.Name == "" || len(p.Name) > 64 {
			continue
		}
		k := paramKey(host, shape, p.Name)
		s := st.params[k]
		if s == nil {
			if len(st.params) >= maxProfiles {
				st.evictParamsLocked()
			}
			s = &paramStat{}
			st.params[k] = s
		}
		was := s.mature()
		s.N++
		c, meta := classify(p.Value)
		s.Class[c]++
		if meta {
			s.Meta++
		}
		s.MaxLen = max(s.MaxLen, len(p.Value))
		addNet(&s.Nets, nh, maxProfileNets)
		s.Last = at
		changed = changed || !was && s.mature()
	}
	if ev.Status >= 200 && ev.Status < 300 || ev.Status == 304 {
		changed = st.observeSiteLocked(host, lp, nh, at) || changed
	}
	return changed
}

// evictParamsLocked 淘汰最久没有出现的一成参数（调用方持 st.mu）。
// 扫描器带着随机参数名的请求也会建立统计，正常接口的参数持续出现，不会被淘汰。
func (st *profileState) evictParamsLocked() {
	type kv struct {
		k    string
		last time.Time
	}
	list := make([]kv, 0, len(st.params))
	for k, s := range st.params {
		list = append(list, kv{k, s.Last})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].last.Before(list[j].last) })
	for _, x := range list[:len(list)/10+1] {
		delete(st.params, x.k)
	}
}

func valueOf(ps []detect.Param, name string) string {
	for _, p := range ps {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// ---------------- 状态与报告 ----------------

// profilePersist 是持久化的参数与站点学习结果：只保存已经生效的参数，未生效的重启后重新统计。
type profilePersist struct {
	Params    map[string]paramStat   `json:"params,omitempty"`
	Sites     map[string]siteStat    `json:"sites,omitempty"`
	Endpoints map[string]endpointUse `json:"endpoints,omitempty"` // 已认定的业务接口
}

// profilePersistLocked 复制需要落盘的学习结果（调用方持 l.mu）。复制而不是引用：落盘序列化时不持 prof.mu。
func (l *Learner) profilePersistLocked() *profilePersist {
	st := &l.prof
	st.mu.Lock()
	defer st.mu.Unlock()
	p := &profilePersist{}
	for k, s := range st.params {
		if s.mature() {
			if p.Params == nil {
				p.Params = map[string]paramStat{}
			}
			c := *s
			c.Nets = append([]uint32(nil), s.Nets...)
			p.Params[k] = c
		}
	}
	for k, s := range st.sites {
		if s.mature() || len(s.Tech) > 0 {
			if p.Sites == nil {
				p.Sites = map[string]siteStat{}
			}
			p.Sites[k] = s.clone()
		}
	}
	for k, u := range st.endpoints {
		if len(u.Nets) >= endpointNets {
			if p.Endpoints == nil {
				p.Endpoints = map[string]endpointUse{}
			}
			c := *u
			c.Nets = append([]uint32(nil), u.Nets...)
			p.Endpoints[k] = c
		}
	}
	if p.Params == nil && p.Sites == nil && p.Endpoints == nil {
		return nil
	}
	return p
}

func (l *Learner) loadProfileLocked(p *profilePersist) {
	if p == nil {
		return
	}
	st := &l.prof
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.params == nil {
		st.params = map[string]*paramStat{}
	}
	if st.sites == nil {
		st.sites = map[string]*siteStat{}
	}
	for k, s := range p.Params {
		if len(st.params) >= maxProfiles {
			break
		}
		s := s
		st.params[k] = &s
	}
	for k, s := range p.Sites {
		if len(st.sites) >= maxSites {
			break
		}
		s := s
		st.sites[k] = &s
	}
	for k, u := range p.Endpoints {
		if st.endpoints == nil {
			st.endpoints = map[string]*endpointUse{}
		}
		if len(st.endpoints) >= maxEndpoints {
			break
		}
		u := u
		st.endpoints[k] = &u
	}
}

// pruneProfileLocked 清理长期没有出现的参数与站点（调用方持 l.mu）。
func (l *Learner) pruneProfileLocked(now time.Time) {
	st := &l.prof
	cut := now.Add(-profileKeepDays * 24 * time.Hour)
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, s := range st.params {
		if s.Last.Before(cut) {
			delete(st.params, k)
		}
	}
	for k, s := range st.sites {
		if s.Last.Before(cut) {
			delete(st.sites, k)
		}
	}
	for k, u := range st.endpoints {
		if u.Last.Before(cut) {
			delete(st.endpoints, k)
		}
	}
}

// ProfileReport 是参数正常取值与站点产品学习的概览。
type ProfileReport struct {
	Params    int          `json:"params"`    // 正在统计的参数
	Mature    int          `json:"mature"`    // 已参与判断的参数
	FreeText  int          `json:"free_text"` // 其中平时填写普通文字的
	Strict    int          `json:"strict"`    // 其中平时只出现数字、编号、单个词的
	Samples   []ParamShape `json:"samples"`   // 已生效参数的示例（每类最多 20 个，正常访问最多的在前）
	Sites     []SiteReport `json:"sites"`     // 站点与识别出的产品（最多 100 个，访问最多的在前）
	SiteTotal int          `json:"site_total"`
	Weak      int64        `json:"weak"`         // 按普通文字降级的命中（本次启动以来）
	Anomaly   int64        `json:"anomaly"`      // 发现的取值异常
	Inapplic  int64        `json:"inapplicable"` // 产品不存在、判为不适用的探测
	Business  int64        `json:"business"`     // 业务接口上只访问接口、降为低危的命中
	Endpoints []Endpoint   `json:"endpoints"`    // 已认定的业务接口（最多 50 个，访问最多的在前）
	EndpointN int          `json:"endpoint_total"`
	VulnSigs  int          `json:"vuln_sigs"` // 内置的国产 OA、中间件漏洞接口签名数
}

// Endpoint 是一个已认定为正常业务的漏洞接口。
type Endpoint struct {
	Host string    `json:"host"`
	Rule string    `json:"rule"`
	Name string    `json:"name"`
	Nets int       `json:"nets"`
	Hits uint32    `json:"hits"`
	Last time.Time `json:"last"`
}

// ParamShape 是一个已生效参数的学习结果。
type ParamShape struct {
	Key   string `json:"key"`   // 站点 路径形态?参数名
	Shape string `json:"shape"` // text：普通文字；strict：只出现数字、编号、单个词；mixed：其他
	N     uint32 `json:"n"`
	Nets  int    `json:"nets"`
}

func (l *Learner) profileReportLocked() ProfileReport {
	st := &l.prof
	r := ProfileReport{Samples: []ParamShape{}, Sites: []SiteReport{}, Endpoints: []Endpoint{}, Weak: st.weak.Load(), Anomaly: st.anomaly.Load(),
		Inapplic: st.inapplicable.Load(), Business: st.business.Load(), VulnSigs: detect.VulnSigCount()}
	st.mu.Lock()
	for k, u := range st.endpoints {
		if len(u.Nets) < endpointNets {
			continue
		}
		r.EndpointN++
		host, rule, _ := strings.Cut(k, " ")
		r.Endpoints = append(r.Endpoints, Endpoint{Host: host, Rule: rule, Name: u.Name, Nets: len(u.Nets), Hits: u.Hits, Last: u.Last})
	}
	r.Params = len(st.params)
	var text, strict []ParamShape
	for k, s := range st.params {
		if !s.mature() {
			continue
		}
		r.Mature++
		ps := ParamShape{Key: k, N: s.N, Nets: len(s.Nets)}
		switch {
		case s.freeText():
			r.FreeText++
			ps.Shape = "text"
			text = append(text, ps)
		case s.strict():
			r.Strict++
			ps.Shape = "strict"
			strict = append(strict, ps)
		}
	}
	r.SiteTotal = len(st.sites)
	for host, s := range st.sites {
		r.Sites = append(r.Sites, s.report(host))
	}
	st.mu.Unlock()
	for _, list := range [][]ParamShape{text, strict} {
		sort.Slice(list, func(i, j int) bool { return list[i].N > list[j].N })
		r.Samples = append(r.Samples, list[:min(len(list), 20)]...)
	}
	sort.Slice(r.Sites, func(i, j int) bool { return r.Sites[i].Reqs > r.Sites[j].Reqs })
	if len(r.Sites) > 100 {
		r.Sites = r.Sites[:100]
	}
	sort.Slice(r.Endpoints, func(i, j int) bool { return r.Endpoints[i].Hits > r.Endpoints[j].Hits })
	if len(r.Endpoints) > 50 {
		r.Endpoints = r.Endpoints[:50]
	}
	return r
}
