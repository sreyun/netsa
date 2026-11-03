package learn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"netsa/internal/model"
)

// 从日志与 AI 研判中自动学习攻击行为，不需要分析员的结论。
//
// 原则：学到的东西只让检测更敏感，不会降低任何告警的等级。学错的代价是多几条告警，而不是漏掉攻击，
// 所以可以自动生效：
//   - 自动确认攻击源：有证据的成功利用、模型以高置信判为攻击。有效期内（策略中的 escalate_days）该来源的
//     低危 / 中危命中升一级，最高高危；分析员之后把该来源判为误报的，以分析员为准；
//   - 攻击活动关联：不同来源的载荷里出现同一个带外回连标识（interactsh 关联 ID、dnslog 子域名），
//     说明是同一个操作者；其中有已确认的攻击源时，其他来源一并确认；
//   - 未知攻击发现：只出现在已确认攻击源、没有命中任何规则、正常访客从未使用过的请求形态，
//     在多个攻击源中出现后生成观察规则（低危），可在页面停用。

// CatLearned 是自学习发现的攻击请求的分类。
const CatLearned = "未知攻击（自学习）"

const (
	aiConfirmConfidence = 85 // 模型判为攻击、自动确认来源所需的最低置信度
	maxAutoSources      = 20000
	maxCampaigns        = 2000
	maxCampaignIPs      = 50
	maxCandidates       = 5000
	maxLearnedRules     = 500
	discoverSources     = 3 // 同一请求形态至少被这么多已确认攻击源使用过，才生成观察规则
	maxBenignIPs        = 4 // 每种请求形态最多记录这么多正常使用的来源，再多就是正常访客普遍在用
)

// AutoSource 是自动确认的攻击来源。
type AutoSource struct {
	IP     string    `json:"ip"`
	Kind   string    `json:"kind"` // evidence：有证据的成功利用；ai：模型高置信判为攻击；campaign：与已确认攻击源属于同一攻击活动
	Reason string    `json:"reason"`
	Time   time.Time `json:"time"`
}

// Campaign 是由同一带外回连标识关联起来的攻击活动。
type Campaign struct {
	Key    string    `json:"key"`    // 回连标识（interactsh 关联 ID、dnslog 子域名）
	IPs    []string  `json:"ips"`    // 使用过该标识的来源
	Sample string    `json:"sample"` // 载荷样例
	Events int       `json:"events"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
}

// LearnedRule 是自学习发现的观察规则。
type LearnedRule struct {
	ID       string    `json:"id"`
	Shape    string    `json:"shape"`   // 请求形态：方法 路径（数字、ID 已归一）?参数名
	Example  string    `json:"example"` // 攻击者的请求样例
	Sources  []string  `json:"sources"` // 使用过该形态的已确认攻击源
	Time     time.Time `json:"time"`
	Disabled bool      `json:"disabled,omitempty"`
	Hits     int64     `json:"hits"` // 生成后匹配的次数（本次启动以来）
}

type candidate struct {
	example string
	sources []string // 使用过的已确认攻击源

	last time.Time
}

// attackState 是攻击行为学习的状态，有自己的锁：热路径上每条 Web 日志都可能进来，不与研判反馈争用 l.mu。
type attackState struct {
	mu        sync.Mutex
	campaigns map[string]*Campaign
	cand      map[string]*candidate
	rules     map[string]*LearnedRule // 请求形态 → 规则
	// benign 记录每种请求形态被哪些“未确认、也没有命中攻击规则”的来源用过（每种最多记 maxBenignIPs 个，再多只记为“很多”）。
	// 所有正常请求都要记，按形态的哈希存放、分两代轮换，内存有上限
	benign, benignPrev map[uint64]*benignUse
}

type benignUse struct {
	ips  []string
	many bool
}

const maxBenignShapes = 100000

func shapeHash(shape string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(shape); i++ {
		h ^= uint64(shape[i])
		h *= 1099511628211
	}
	return h
}

// noteBenign 记录一次正常使用（调用方持 st.mu）。
func (st *attackState) noteBenign(h uint64, ip string) {
	if st.benign == nil {
		st.benign = map[uint64]*benignUse{}
	}
	u := st.benign[h]
	if u == nil {
		if len(st.benign) >= maxBenignShapes {
			st.benignPrev, st.benign = st.benign, map[uint64]*benignUse{}
		}
		u = &benignUse{}
		if old := st.benignPrev[h]; old != nil { // 上一代记过：沿用，轮换不丢失近期的使用记录
			u.ips, u.many = append([]string(nil), old.ips...), old.many
		}
		st.benign[h] = u
	}
	if u.many || slices.Contains(u.ips, ip) {
		return
	}
	if len(u.ips) >= maxBenignIPs {
		u.many = true
		return
	}
	u.ips = append(u.ips, ip)
}

// benignUsers 返回用过该形态的未确认来源（调用方持 st.mu）。
func (st *attackState) benignUsers(h uint64) ([]string, bool) {
	var ips []string
	many := false
	for _, m := range []map[uint64]*benignUse{st.benign, st.benignPrev} {
		if u := m[h]; u != nil {
			many = many || u.many
			for _, ip := range u.ips {
				if !slices.Contains(ips, ip) {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, many
}

// ConfirmSource 自动确认一个攻击来源，返回是否为新确认。已确认的来源刷新时间（有效期从最近一次证据算起）。
func (l *Learner) ConfirmSource(ip, kind, reason string, at time.Time) bool {
	if l == nil || ip == "" {
		return false
	}
	if at.IsZero() {
		at = time.Now()
	}
	l.mu.Lock()
	old := l.auto[ip]
	if old != nil {
		if at.After(old.Time) {
			old.Time = at
			l.dirty = true
			l.publishAutoLocked()
		}
		l.mu.Unlock()
		return false
	}
	if len(l.auto) >= maxAutoSources {
		l.evictAutoLocked()
	}
	l.auto[ip] = &AutoSource{IP: ip, Kind: kind, Reason: reason, Time: at}
	l.dirty = true
	l.publishAutoLocked()
	c := Change{Time: time.Now(), Kind: "confirm_auto", User: "自学习", Detail: "自动确认攻击源 " + ip + "：" + reason}
	l.logLocked(c)
	l.mu.Unlock()
	l.emit([]Change{c})
	return true
}

// evictAutoLocked 淘汰最早的一成自动确认来源（调用方持锁）。
func (l *Learner) evictAutoLocked() {
	list := make([]*AutoSource, 0, len(l.auto))
	for _, a := range l.auto {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Time.Before(list[j].Time) })
	for _, a := range list[:len(list)/10+1] {
		delete(l.auto, a.IP)
	}
}

// publishAutoLocked 发布热路径使用的只读副本（写时复制；新增确认很少见）。
func (l *Learner) publishAutoLocked() {
	m := make(map[string]AutoSource, len(l.auto))
	for ip, a := range l.auto {
		m[ip] = *a
	}
	l.autoSnap.Store(&m)
}

// confirmedSource 判断来源在 at 时刻是否为已确认的攻击源（人工确认或自动确认），返回依据。无锁。
func (l *Learner) confirmedSource(ip string, at time.Time) (string, bool) {
	m := l.calib.Load()
	if m == nil || !m.escalate || ip == "" {
		return "", false
	}
	within := func(t time.Time) bool {
		age := at.Sub(t)
		return age >= -time.Hour && age <= time.Duration(m.days)*24*time.Hour
	}
	if c, ok := m.sources[ip]; ok && within(c.time) {
		return fmt.Sprintf("该来源曾被分析员确认为攻击（事件 #%d）", c.incident), true
	}
	p := l.autoSnap.Load()
	if p == nil {
		return "", false
	}
	a, ok := (*p)[ip]
	if !ok || !within(a.Time) {
		return "", false
	}
	if t, cleared := m.cleared[ip]; cleared && t.After(a.Time) {
		return "", false // 分析员之后判为误报：以人的结论为准
	}
	return "该来源已被自动确认为攻击源（" + a.Reason + "）", true
}

// ObserveAttack 在规则检测之后、校准之前调用：记录攻击活动、收集未知攻击的候选请求、匹配学到的观察规则。
// 只可能追加命中，不修改已有命中。
func (l *Learner) ObserveAttack(ev *model.Event, hits []model.Hit) []model.Hit {
	if l == nil || ev == nil {
		return hits
	}
	at := ev.Time
	if at.IsZero() {
		at = time.Now()
	}
	attack := false
	for _, h := range hits {
		if !h.TagOnly && !h.Weak && h.Severity >= model.SevLow {
			attack = true
			break
		}
	}
	if attack {
		if key, sample, ok := callbackKey(ev); ok {
			l.observeCampaign(ev.SrcIP, key, sample, at)
		}
	}
	if ev.Kind != model.KindWeb || ev.SrcIP == "" {
		return hits
	}
	st := &l.atk
	shape, ok := requestShape(ev)
	if !ok {
		return hits
	}
	_, confirmed := l.confirmedSource(ev.SrcIP, at)
	st.mu.Lock()
	if r := st.rules[shape]; r != nil && !r.Disabled {
		r.Hits++
		n, learned := len(r.Sources), r.Time
		st.mu.Unlock()
		return append(hits, model.Hit{RuleID: r.ID, Name: "自学习发现的攻击请求", Category: CatLearned, Severity: model.SevLow,
			Phase: model.PhaseExploit, Result: model.ResultUnknown,
			Evidence: fmt.Sprintf("请求形态 %s 此前只出现在 %d 个已确认攻击源的请求中，正常访客从未使用（%s 自动学习）",
				clipShape(shape), n, learned.Format("2006-01-02"))})
	}
	if attack {
		st.mu.Unlock()
		return hits // 已被规则识别的攻击不需要再学
	}
	var ch *Change
	c := st.cand[shape]
	switch {
	case confirmed:
		if c == nil && len(st.cand) < maxCandidates {
			c = &candidate{example: clipShape(ev.Method + " " + ev.URI)}
			st.cand[shape] = c
		}
		if c != nil {
			c.last = at
			if !slices.Contains(c.sources, ev.SrcIP) && len(c.sources) < 16 {
				c.sources = append(c.sources, ev.SrcIP)
			}
			ch = l.promoteLocked(st, shape, c, at)
		}
	default:
		// 不是已确认攻击源、也没有命中攻击规则的请求：记下谁用过这个形态，用过的来源没有全部被确认为攻击源，就不学
		st.noteBenign(shapeHash(shape), ev.SrcIP)
	}
	st.mu.Unlock()
	if ch != nil {
		// 不持 st.mu 写进化日志：保存状态时是先 l.mu 后 st.mu，反过来会死锁
		l.mu.Lock()
		l.logLocked(*ch)
		l.mu.Unlock()
		l.emit([]Change{*ch})
	}
	return hits
}

// promoteLocked 判断候选请求形态能否生成观察规则（调用方持 st.mu），生成时返回进化日志。
func (l *Learner) promoteLocked(st *attackState, shape string, c *candidate, at time.Time) *Change {
	if len(c.sources) < discoverSources || len(st.rules) >= maxLearnedRules {
		return nil
	}
	// 用过这个形态的其他来源：当时还没被确认、后来被确认的攻击源不算正常访客；用过的来源太多也不学
	users, many := st.benignUsers(shapeHash(shape))
	if many {
		return nil
	}
	for _, ip := range users {
		if _, ok := l.confirmedSource(ip, at); !ok {
			return nil
		}
	}
	sum := sha256.Sum256([]byte(shape))
	r := &LearnedRule{ID: "learn-" + hex.EncodeToString(sum[:4]), Shape: shape, Example: c.example,
		Sources: append([]string(nil), c.sources...), Time: at}
	st.rules[shape] = r
	delete(st.cand, shape)
	return &Change{Time: time.Now(), Kind: "discover", Rule: r.ID, User: "自学习",
		Detail: fmt.Sprintf("发现未知攻击请求 %s：%d 个已确认攻击源使用过、没有命中任何规则、正常访客从未使用，生成观察规则（低危）", clipShape(shape), len(c.sources))}
}

// observeCampaign 记录一次带外回连标识的使用；与已确认攻击源属于同一活动的其他来源一并确认。
func (l *Learner) observeCampaign(ip, key, sample string, at time.Time) {
	st := &l.atk
	st.mu.Lock()
	c := st.campaigns[key]
	if c == nil {
		if len(st.campaigns) >= maxCampaigns {
			st.mu.Unlock()
			return
		}
		c = &Campaign{Key: key, Sample: sample, First: at}
		st.campaigns[key] = c
	}
	c.Events++
	if at.After(c.Last) {
		c.Last = at
	}
	isNew := false
	if !slices.Contains(c.IPs, ip) && len(c.IPs) < maxCampaignIPs {
		c.IPs = append(c.IPs, ip)
		isNew = true
	}
	ips := append([]string(nil), c.IPs...)
	st.mu.Unlock()
	if !isNew || len(ips) < 2 {
		return
	}
	l.mu.Lock()
	l.dirty = true
	l.mu.Unlock()
	// 活动中有已确认的攻击源：其他来源一并确认
	var anchor string
	for _, x := range ips {
		if _, ok := l.confirmedSource(x, at); ok {
			anchor = x
			break
		}
	}
	if anchor == "" {
		return
	}
	for _, x := range ips {
		if x == anchor {
			continue
		}
		if _, ok := l.confirmedSource(x, at); !ok {
			l.ConfirmSource(x, "campaign", fmt.Sprintf("与已确认的攻击源 %s 使用同一带外回连标识 %s，属于同一攻击活动", anchor, key), at)
		}
	}
}

// SetLearnedRule 停用 / 启用一条自学习发现的观察规则。
func (l *Learner) SetLearnedRule(id, user string, enabled bool) bool {
	if l == nil || !strings.HasPrefix(id, "learn-") {
		return false
	}
	st := &l.atk
	st.mu.Lock()
	var found *LearnedRule
	for _, r := range st.rules {
		if r.ID == id {
			found = r
		}
	}
	if found == nil || found.Disabled == !enabled {
		st.mu.Unlock()
		return found != nil
	}
	found.Disabled = !enabled
	shape := found.Shape
	st.mu.Unlock()
	verb := "停用"
	if enabled {
		verb = "启用"
	}
	c := Change{Time: time.Now(), Kind: "discover_" + map[bool]string{true: "enable", false: "disable"}[enabled], Rule: id, User: user,
		Detail: verb + "自学习发现的观察规则 " + clipShape(shape)}
	l.mu.Lock()
	l.logLocked(c)
	l.mu.Unlock()
	l.emit([]Change{c})
	return true
}

// ---------------- 特征提取 ----------------

// 带外回连服务。interactsh 的子域名前 20 位是客户端的关联 ID，同一次扫描（同一个操作者）不变，其余是每个载荷的随机串。
var (
	reInteractsh = regexp.MustCompile(`([a-z0-9]{20})[a-z0-9]{0,20}\.(?:oast\.(?:me|pro|fun|site|online|live)|interact\.sh|interactsh\.com|oastify\.com)`)
	reDNSLog     = regexp.MustCompile(`([a-z0-9][a-z0-9-]{3,40})\.(dnslog\.cn|dnslog\.link|ceye\.io|burpcollaborator\.net|requestrepo\.com)`)
)

// callbackKey 从请求中提取带外回连标识。只在请求命中攻击规则时调用。
func callbackKey(ev *model.Event) (key, sample string, ok bool) {
	text := strings.ToLower(ev.URI + " " + ev.UA + " " + ev.Referer)
	if !strings.Contains(text, "oast") && !strings.Contains(text, "interact") && !strings.Contains(text, "dnslog") &&
		!strings.Contains(text, "ceye") && !strings.Contains(text, "collaborator") && !strings.Contains(text, "requestrepo") {
		if !strings.Contains(text, "%") {
			return "", "", false
		}
	}
	if u, err := url.QueryUnescape(text); err == nil {
		text = u
	}
	if m := reInteractsh.FindStringSubmatch(text); m != nil {
		return m[1] + ".oast", clipShape(ev.URI), true
	}
	if m := reDNSLog.FindStringSubmatch(text); m != nil {
		return m[1] + "." + m[2], clipShape(ev.URI), true
	}
	return "", "", false
}

var staticExt = []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4"}

// requestShape 把请求归一为形态：方法 + 路径（纯数字段、长十六进制段替换为占位符）+ 排序后的参数名。
// 静态资源、首页等正常访客必然访问的路径不参与。
func requestShape(ev *model.Event) (string, bool) {
	if ev.Method == "" || ev.URI == "" || ev.URI[0] != '/' {
		return "", false
	}
	path, query, _ := strings.Cut(ev.URI, "?")
	lp := strings.ToLower(path)
	if lp == "/" && query == "" || lp == "/favicon.ico" || lp == "/robots.txt" {
		return "", false
	}
	for _, e := range staticExt {
		if strings.HasSuffix(lp, e) {
			return "", false
		}
	}
	segs := strings.Split(lp, "/")
	for i, s := range segs {
		switch {
		case s == "":
		case allDigits(s):
			segs[i] = "{n}"
		case len(s) >= 16 && isHexish(s):
			segs[i] = "{id}"
		case len(s) > 48:
			segs[i] = "{s}"
		}
	}
	var keys []string
	for _, kv := range strings.Split(query, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k != "" && len(keys) < 16 && !slices.Contains(keys, k) {
			keys = append(keys, strings.ToLower(k))
		}
	}
	sort.Strings(keys)
	shape := ev.Method + " " + strings.Join(segs, "/")
	if len(keys) > 0 {
		shape += "?" + strings.Join(keys, "&")
	}
	if len(shape) > 300 {
		return "", false
	}
	return shape, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func isHexish(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c == '-') {
			return false
		}
	}
	return true
}

func clipShape(s string) string {
	if len(s) > 160 {
		s = s[:160]
		for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 {
			s = s[:len(s)-1]
		}
		return s + "…"
	}
	return s
}

// ---------------- 状态与报告 ----------------

// attackPersist 是持久化的攻击行为学习结果。
type attackPersist struct {
	Auto      []AutoSource  `json:"auto_sources,omitempty"`
	Campaigns []Campaign    `json:"campaigns,omitempty"`
	Rules     []LearnedRule `json:"learned_rules,omitempty"`
}

func (l *Learner) attackPersistLocked() attackPersist {
	var p attackPersist
	for _, a := range l.auto {
		p.Auto = append(p.Auto, *a)
	}
	sort.Slice(p.Auto, func(i, j int) bool { return p.Auto[i].Time.Before(p.Auto[j].Time) })
	st := &l.atk
	st.mu.Lock()
	for _, c := range st.campaigns {
		if len(c.IPs) >= 2 { // 只有一个来源的标识没有关联意义，不落盘
			p.Campaigns = append(p.Campaigns, *c)
		}
	}
	for _, r := range st.rules {
		p.Rules = append(p.Rules, *r)
	}
	st.mu.Unlock()
	sort.Slice(p.Campaigns, func(i, j int) bool { return p.Campaigns[i].Key < p.Campaigns[j].Key })
	sort.Slice(p.Rules, func(i, j int) bool { return p.Rules[i].ID < p.Rules[j].ID })
	return p
}

func (l *Learner) loadAttackLocked(p attackPersist) {
	for i := range p.Auto {
		if a := p.Auto[i]; a.IP != "" {
			l.auto[a.IP] = &a
		}
	}
	l.publishAutoLocked()
	st := &l.atk
	st.mu.Lock()
	for i := range p.Campaigns {
		if c := p.Campaigns[i]; c.Key != "" {
			st.campaigns[c.Key] = &c
		}
	}
	for i := range p.Rules {
		if r := p.Rules[i]; r.Shape != "" && r.ID != "" {
			st.rules[r.Shape] = &r
		}
	}
	st.mu.Unlock()
}

// AttackReport 是攻击行为学习的概览。
type AttackReport struct {
	AutoSources []AutoSource  `json:"auto_sources"` // 最近自动确认的攻击源（最多 50 条）
	AutoTotal   int           `json:"auto_total"`
	Campaigns   []Campaign    `json:"campaigns"` // 关联到多个来源的攻击活动（最多 50 条）
	Rules       []LearnedRule `json:"learned_rules"`
	Candidates  int           `json:"candidates"` // 正在观察的候选请求形态
}

func (l *Learner) attackReportLocked() AttackReport {
	r := AttackReport{AutoSources: []AutoSource{}, Campaigns: []Campaign{}, Rules: []LearnedRule{}, AutoTotal: len(l.auto)}
	for _, a := range l.auto {
		r.AutoSources = append(r.AutoSources, *a)
	}
	sort.Slice(r.AutoSources, func(i, j int) bool { return r.AutoSources[i].Time.After(r.AutoSources[j].Time) })
	if len(r.AutoSources) > 50 {
		r.AutoSources = r.AutoSources[:50]
	}
	st := &l.atk
	st.mu.Lock()
	for _, c := range st.campaigns {
		if len(c.IPs) >= 2 {
			r.Campaigns = append(r.Campaigns, *c)
		}
	}
	for _, x := range st.rules {
		r.Rules = append(r.Rules, *x)
	}
	r.Candidates = len(st.cand)
	st.mu.Unlock()
	sort.Slice(r.Campaigns, func(i, j int) bool { return len(r.Campaigns[i].IPs) > len(r.Campaigns[j].IPs) })
	if len(r.Campaigns) > 50 {
		r.Campaigns = r.Campaigns[:50]
	}
	sort.Slice(r.Rules, func(i, j int) bool { return r.Rules[i].Time.After(r.Rules[j].Time) })
	return r
}

// pruneAttackLocked 清理过期的自动确认来源、长期不活跃的候选与攻击活动（调用方持 l.mu）。
func (l *Learner) pruneAttackLocked(now time.Time, days int) {
	keep := time.Duration(max(days, 1)) * 24 * time.Hour * 2
	changed := false
	for ip, a := range l.auto {
		if now.Sub(a.Time) > keep {
			delete(l.auto, ip)
			changed = true
		}
	}
	if changed {
		l.dirty = true
		l.publishAutoLocked()
	}
	st := &l.atk
	st.mu.Lock()
	for k, c := range st.cand {
		if now.Sub(c.last) > keep {
			delete(st.cand, k)
		}
	}
	for k, c := range st.campaigns {
		if now.Sub(c.Last) > keep {
			delete(st.campaigns, k)
		}
	}
	st.mu.Unlock()
}
