// Package store 维护态势感知的内存状态：攻击者画像、告警、时间序列与攻击面，并支持快照持久化。
package store

import (
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"netsa/internal/geo"
	"netsa/internal/model"
	"netsa/internal/risk"
	"netsa/internal/safe"
)

// IPProfile 是单个来源 IP 的画像。
type IPProfile struct {
	IP         string                    `json:"ip"`
	FirstSeen  time.Time                 `json:"first_seen"`
	LastSeen   time.Time                 `json:"last_seen"`
	Events     int64                     `json:"events"`
	WebReqs    int64                     `json:"web_reqs"`
	FwEvents   int64                     `json:"fw_events"`
	Denied     int64                     `json:"denied"`
	Attacks    int64                     `json:"attacks"`
	Successes  int64                     `json:"successes"`
	Score      float64                   `json:"score"`
	Level      model.Severity            `json:"level"`
	MaxSev     model.Severity            `json:"max_severity"`
	Categories map[string]int            `json:"categories"`
	CatSev     map[string]model.Severity `json:"cat_sev"`
	CatPhase   map[string]string         `json:"cat_phase"`
	Rules      map[string]int            `json:"rules"`       // 命中次数（含按规则节流、未生成告警的重复命中）
	RuleAlerts map[string]int            `json:"rule_alerts"` // 生成告警的条数（受 alerts_per_rule 节流）
	RuleNames  map[string]string         `json:"rule_names"`
	RuleSev    map[string]model.Severity `json:"rule_sev"`
	Phases     map[string]int            `json:"phases"`
	PhaseFirst map[string]time.Time      `json:"phase_first"`
	Results    map[string]int            `json:"results"`
	Targets    map[string]int            `json:"targets"`
	Ports      map[int]int               `json:"ports"`
	Status     map[int]int               `json:"status"`
	UAs        map[string]int            `json:"uas"`
	Proxies    map[string]int            `json:"proxies,omitempty"` // 经由的 CDN/反向代理
	LastXFF    string                    `json:"last_xff,omitempty"`
	Tags       map[string]string         `json:"tags"`
	Intel      []string                  `json:"intel,omitempty"`
	Geo        *geo.Info                 `json:"geo"`
	Recent     []*model.Alert            `json:"recent"`

	throttle map[string]*window
	sk       sketch // 规则 / 端口集合指纹，用于同源关联分析的快速筛选

	// 以下为增量统计的簿记字段，不持久化（快照恢复后由 rebuild 重建）
	inAgg    bool   `json:"-"`
	aggMask  uint64 `json:"-"` // 已计入 ATT&CK 矩阵的技术位
	aggFlags uint8  `json:"-"` // 已计入的攻击手法标记
}

type window struct {
	start time.Time
	n     int
}

func newProfile(ip string, t time.Time) *IPProfile {
	return &IPProfile{IP: ip, FirstSeen: t, LastSeen: t}
}

// ensureAttackMaps 在首次出现攻击时分配攻击相关的统计结构，正常访客不占用这部分内存。
func (p *IPProfile) ensureAttackMaps() {
	if p.Categories != nil && p.CatSev != nil && p.PhaseFirst != nil {
		return
	}
	initMap(&p.Categories)
	initMap(&p.CatSev)
	initMap(&p.CatPhase)
	initMap(&p.Rules)
	initMap(&p.RuleNames)
	initMap(&p.RuleSev)
	initMap(&p.Phases)
	initMap(&p.PhaseFirst)
	initMap(&p.Results)
	initMap(&p.Targets)
}

func initMap[K comparable, V any](m *map[K]V) {
	if *m == nil {
		*m = map[K]V{}
	}
}

// incBounded 是有上限的计数器：超过上限后只累加已有键；map 为 nil 时自动分配。返回该键是否被计入。
func incBounded[K comparable](m *map[K]int, k K, limit int) bool {
	if *m == nil {
		*m = map[K]int{}
	}
	if _, ok := (*m)[k]; ok || len(*m) < limit {
		(*m)[k]++
		return true
	}
	return false
}

var sevWeight = [...]float64{0, 5, 12, 25, 45}

// levelFloor 为各等级对应的最低威胁评分（低危 >0、中危 25、高危 50、严重 80）。
var levelFloor = [...]float64{0, 1, 25, 50, 80}

// recompute 根据命中规则重新计算威胁分（0-100）与等级。
// 按攻击分类累计：同类重复命中按对数递增（最多 2 倍），侦察类打 6 折，避免单一扫描器刷高分；
// 疑似成功、多阶段攻击链、情报命中额外加分。
func (p *IPProfile) recompute() {
	sum := 0.0
	for cat, n := range p.Categories {
		c := sevWeight[p.CatSev[cat]] * math.Min(1+math.Log2(float64(n))/3, 2)
		if p.CatPhase[cat] == model.PhaseRecon {
			c *= 0.6
		}
		sum += c
	}
	if p.Successes > 0 {
		sum += 20
	}
	phases := 0
	for ph, n := range p.Phases {
		if n > 0 && ph != model.PhaseRecon {
			phases++
		}
	}
	if phases >= 2 {
		sum += 10 * float64(phases-1)
	}
	if len(p.Intel) > 0 {
		sum += 30
	}
	p.Score = math.Round(math.Min(sum, 100)*10) / 10
	// 攻击源等级不低于其触发过的最高告警等级：触发过高危告警的 IP 必然计入“高危以上攻击源”，
	// 与告警事件中的等级一致。评分同步抬升到该等级的下限，保证评分、等级与排序相互一致。
	//
	// 严重级额外要求佐证：单条「严重」告警若既没有成功命中、也没有失陷迹象类分类
	// （带外、远控、挖矿、主机事件），只按高危封顶。否则一条误判的设备告警就能把
	// 任意 IP 抬到严重，污染整体评级与处置排序。
	floorSev := p.MaxSev
	if floorSev >= model.SevCritical && p.Successes == 0 && !p.hasCompromiseEvidence() {
		floorSev = model.SevHigh
	}
	if f := levelFloor[floorSev]; p.Score < f {
		p.Score = f
	}
	lvl := model.SevInfo
	switch {
	case p.Score >= 80:
		lvl = model.SevCritical
	case p.Score >= 50:
		lvl = model.SevHigh
	case p.Score >= 25:
		lvl = model.SevMedium
	case p.Score > 0:
		lvl = model.SevLow
	}
	p.Level = lvl
}

// hasCompromiseEvidence 判断画像是否出现过「观察即证据」的失陷迹象分类。
func (p *IPProfile) hasCompromiseEvidence() bool {
	for cat, sev := range p.CatSev {
		if sev >= model.SevHigh && risk.CompromiseEvidence(cat) {
			return true
		}
	}
	return false
}

// Bucket 是一分钟粒度的统计桶。
type Bucket struct {
	T       int64    `json:"t"`
	Web     int64    `json:"web"`
	Fw      int64    `json:"fw"`
	Attacks int64    `json:"attacks"`
	Blocked int64    `json:"blocked"`
	Success int64    `json:"success,omitempty"` // 疑似攻击成功的命中
	Sev     [5]int64 `json:"sev"`
}

// Totals 是全局计数。
type Totals struct {
	Events   int64 `json:"events"`
	Web      int64 `json:"web"`
	Firewall int64 `json:"firewall"`
	Outbound int64 `json:"outbound"`
	DNS      int64 `json:"dns,omitempty"`    // DNS 查询日志
	Auth     int64 `json:"auth,omitempty"`   // 主机 / VPN 认证日志
	Egress   int64 `json:"egress,omitempty"` // 防火墙日志中内网主机访问公网的流量
	Attacks  int64 `json:"attacks"`
	Alerts   int64 `json:"alerts"`
	Blocked  int64 `json:"blocked"`
	Success  int64 `json:"success"`
	// Untracked 为画像数超过上限期间未建立画像的正常访问（仍计入总量与攻击面统计）
	Untracked int64 `json:"untracked,omitempty"`
}

// Store 是线程安全的态势状态库。
type Store struct {
	mu         sync.RWMutex
	maxIPs     int
	maxAlerts  int
	perRule    int
	retention  time.Duration
	ips        map[string]*IPProfile
	alerts     []*model.Alert
	alertHead  int
	nextID     uint64
	buckets    map[int64]*Bucket
	totals     Totals
	categories map[string]int64
	rules      map[string]int64
	ruleNames  map[string]string
	sevCount   [5]int64
	phases     map[string]int64
	results    map[string]int64
	minTime    time.Time
	maxTime    time.Time
	surf       *surface
	ruleBits   map[string]int       // 规则 ID → 指纹位下标（同源关联分析用）
	scores     []ScorePoint         // 安全评分历史（每小时一次）
	incidents  map[uint64]*Incident // 安全事件（同一来源的告警合并处置）
	incByKey   map[string]uint64    // 来源 IP → 最近的事件
	nextInc    uint64
	agg        *aggregate          // 总览增量统计（国家/省份/城市/等级/目标/近 1 小时）
	days       map[string]*DayStat // 按自然日的汇总（周报 / 月报）
	curDay     *DayStat
	dayStart   int64
	dayEnd     int64
	loc        *time.Location

	// GeoLookup / IntelMatch 在创建新画像时调用。
	GeoLookup  func(ip string) *geo.Info
	IntelMatch func(ip string) []string
	// PortPublished 判断公网目标端口是否确实对外发布（DNAT 映射）。为 nil 时视为全部发布（保持原有行为）。
	// 用于避免「防火墙默认策略放行过一次探测」被误判为「该端口对公网开放」，进而影响暴露面评估与安全评分。
	PortPublished func(dstIP string, port int, proto string) bool
}

func New(maxIPs, maxAlerts, alertsPerRule int, retention time.Duration) *Store {
	return &Store{
		maxIPs: maxIPs, maxAlerts: maxAlerts, perRule: alertsPerRule, retention: retention,
		ips: map[string]*IPProfile{}, buckets: map[int64]*Bucket{},
		categories: map[string]int64{}, rules: map[string]int64{}, ruleNames: map[string]string{},
		phases: map[string]int64{}, results: map[string]int64{}, surf: newSurface(), ruleBits: map[string]int{},
		incidents: map[uint64]*Incident{}, incByKey: map[string]uint64{},
		agg: newAggregate(), days: map[string]*DayStat{},
	}
}

// RecordResult 描述一次记录产生的变化。
type RecordResult struct {
	Alerts  []*model.Alert
	Level   model.Severity
	Score   float64 // 记录后的威胁评分
	LevelUp bool    // 等级提升
	NewIP   bool
	Profile string
}

const throttleWindow = 10 * time.Minute

// alertRuleCap 是单个画像记录的规则数上限（规则总量有限，预留余量防止自定义规则过多时内存膨胀）。
const alertRuleCap = 500

// Record 记录一个事件及其检测命中。
func (s *Store) Record(ev *model.Event, hits []model.Hit) RecordResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordLocked(ev, hits)
}

// RecordBatch 在一次加锁内记录一批事件，hits[i] 对应 evs[i]。
func (s *Store) RecordBatch(evs []*model.Event, hits [][]model.Hit) []RecordResult {
	out := make([]RecordResult, len(evs))
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ev := range evs {
		out[i] = s.safeRecord(ev, hits[i])
	}
	return out
}

// safeRecord 记录单条事件；个别畸形数据触发的异常只跳过该条，不影响同批其他事件与整个服务。
func (s *Store) safeRecord(ev *model.Event, hits []model.Hit) (res RecordResult) {
	defer func() {
		if r := recover(); r != nil {
			safe.Report("记录事件 "+ev.SrcIP, r)
			res = RecordResult{}
		}
	}()
	return s.recordLocked(ev, hits)
}

func (s *Store) recordLocked(ev *model.Event, hits []model.Hit) RecordResult {
	var res RecordResult

	s.totals.Events++
	// 外连威胁情报地址：内网主机（或本机）主动连接已知恶意地址是典型的失陷迹象（木马回连 C2、挖矿、数据外传）。
	// 普通出站流量不作为攻击来源统计；命中情报的出站连接以发起连接的主机为主体记录告警。
	var c2 *model.Hit
	if ev.Kind == model.KindFirewall && s.IntelMatch != nil {
		c2 = s.c2Hit(ev)
	}
	if ev.Outbound {
		s.totals.Outbound++
		if c2 == nil && !hasAttack(hits) { // 出站流量只记录外连恶意地址、周期性外连等失陷迹象
			return res
		}
	}
	if c2 != nil {
		hits = append(hits[:len(hits):len(hits)], *c2) // 不修改调用方的切片
	}
	// 统计用时间：设备时钟错误或解析异常产生的未来 / 远古时间按当前时间统计，
	// 否则一条异常日志就会把时间窗口推到未来，导致趋势数据被保留期清理、“近 1 小时”统计失真。
	t := ev.Time
	if now := time.Now(); t.After(now.Add(time.Hour)) || t.Year() < 2000 {
		t = now
	}
	if s.minTime.IsZero() || t.Before(s.minTime) {
		s.minTime = t
	}
	if t.After(s.maxTime) {
		s.maxTime = t
	}
	minute := t.Unix() / 60
	b := s.buckets[minute]
	if b == nil {
		b = &Bucket{T: minute * 60}
		s.buckets[minute] = b
	}
	day := s.dayLocked(t)
	day.Events++
	switch ev.Kind {
	case model.KindWeb:
		s.totals.Web++
		b.Web++
		day.Web++
	case model.KindDNS, model.KindAuth:
		// DNS 查询与认证日志量大，只记录总量；命中异常时才以主体（内网主机 / 登录来源）建立画像
		if ev.Kind == model.KindDNS {
			day.DNS++
		} else {
			day.Auth++
		}
		if ev.Kind == model.KindDNS {
			s.totals.DNS++
		} else {
			s.totals.Auth++
		}
		if !hasAttack(hits) {
			return res
		}
	default:
		s.totals.Firewall++
		b.Fw++
		day.Firewall++
		if ev.DstIP != "" && geo.IsPrivate(ev.SrcIP) && !geo.IsPrivate(ev.DstIP) {
			s.totals.Egress++ // 内网主机访问公网的出站流量（外连检测的数据基础）
		}
	}

	p := s.ips[ev.SrcIP]
	if p == nil {
		// 画像数的硬上限：定期维护之间若遇到大量不同来源（伪造源地址的扫描、大规模爬虫），
		// 正常访问只计入总量与攻击面，不再建立画像；攻击者则立即淘汰低价值画像腾出空间。
		if len(s.ips) >= s.maxIPs+s.maxIPs/4 {
			if !hasAttack(hits) {
				s.totals.Untracked++
				if ev.Kind == model.KindWeb {
					s.surf.observeWeb(ev, hits, false)
				} else {
					s.surf.observeFw(ev, s.published(ev))
				}
				return res
			}
			s.evictLocked()
		}
		p = newProfile(ev.SrcIP, ev.Time)
		if s.GeoLookup != nil {
			p.Geo = s.GeoLookup(ev.SrcIP)
		}
		if s.IntelMatch != nil {
			p.Intel = s.IntelMatch(ev.SrcIP)
		}
		s.ips[ev.SrcIP] = p
		res.NewIP = true
		s.agg.add(p) // 威胁情报命中时创建即为攻击源；普通访客由首次攻击时补登记
		if len(p.Intel) > 0 {
			hits = append(hits, model.Hit{RuleID: "intel", Name: "威胁情报命中", Category: "威胁情报", Severity: model.SevHigh,
				Phase: model.PhaseRecon, Evidence: strings.Join(p.Intel, ", "), Result: model.ResultUnknown})
		}
	}
	oldLevel, oldSeen, oldFirst := p.Level, p.LastSeen, p.FirstSeen
	p.Events++
	if ev.Time.After(p.LastSeen) {
		p.LastSeen = ev.Time
	}
	if ev.Time.Before(p.FirstSeen) {
		p.FirstSeen = ev.Time
	}
	s.agg.moveLastSeen(p, oldSeen)
	s.agg.moveFirstSeen(p, oldFirst)
	if ev.Kind == model.KindWeb {
		p.WebReqs++
		incBounded(&p.Status, ev.Status, 50)
		if ev.UA != "" {
			incBounded(&p.UAs, truncate(ev.UA, 200), 10)
		}
		if ev.PeerIP != "" {
			incBounded(&p.Proxies, ev.PeerIP, 20)
			p.LastXFF = ev.XFF
		}
	} else {
		p.FwEvents++
		if ev.Action == model.ActionDeny {
			p.Denied++
		}
		if ev.DstPort > 0 && incBounded(&p.Ports, ev.DstPort, 500) {
			p.sk.ports |= intBit(ev.DstPort)
		}
	}

	if ev.Kind == model.KindWeb && ev.Status >= 200 && ev.Status < 300 {
		hits = s.verifySuccess(ev, hits)
	}
	// 入库前最后一道等级裁决：复核可能把「疑似成功」改判为「未成功」，
	// 等级必须随之回落，避免严重级告警只靠一次误判的 2xx 长期滞留。
	for i := range hits {
		risk.Finalize(&hits[i])
	}
	wasAttacker := p.Attacks > 0
	attacked := false
	for _, h := range hits {
		if h.TagOnly {
			p.setTag(h.Name, h.Evidence)
			continue
		}
		p.ensureAttackMaps()
		if !attacked && p.Attacks == 0 {
			// 首次攻击时重新匹配情报（Tor 列表等可能在画像创建后才加载）
			if len(p.Intel) == 0 && s.IntelMatch != nil {
				p.Intel = s.IntelMatch(ev.SrcIP)
			}
		}
		attacked = true
		s.totals.Attacks++
		day.recordHit(&h)
		b.Attacks++
		b.Sev[h.Severity]++
		s.sevCount[h.Severity]++
		s.categories[h.Category]++
		s.rules[h.RuleID]++
		s.ruleNames[h.RuleID] = h.Name
		s.phases[h.Phase]++
		s.results[h.Result]++
		if h.Result == model.ResultBlocked {
			s.totals.Blocked++
			b.Blocked++
		}
		if h.Result == model.ResultSuccess {
			s.totals.Success++
			b.Success++
			p.Successes++
		}
		p.Attacks++
		firstCat := p.Categories[h.Category] == 0
		p.Categories[h.Category]++
		oldCatSev := p.CatSev[h.Category]
		if h.Severity > p.CatSev[h.Category] {
			p.CatSev[h.Category] = h.Severity
		}
		// 同步安全评估的增量统计：新增攻击类型、同类攻击出现更高等级
		if firstCat {
			s.agg.addCategory(p, h.Category, p.CatSev[h.Category])
		} else if h.Severity > oldCatSev {
			s.agg.setCategorySeverity(p, h.Category, oldCatSev, p.CatSev[h.Category])
		}
		if _, ok := p.CatPhase[h.Category]; !ok {
			p.CatPhase[h.Category] = h.Phase
		}
		p.Rules[h.RuleID]++
		p.sk.addRule(s.ruleBit(h.RuleID))
		p.RuleNames[h.RuleID] = h.Name
		if h.Severity > p.RuleSev[h.RuleID] {
			p.RuleSev[h.RuleID] = h.Severity
		}
		if h.Severity > p.MaxSev {
			p.MaxSev = h.Severity
		}
		p.Phases[h.Phase]++
		if t, ok := p.PhaseFirst[h.Phase]; !ok || ev.Time.Before(t) {
			p.PhaseFirst[h.Phase] = ev.Time
		}
		p.Results[h.Result]++
		if target := truncate(ev.Target(), 200); incBounded(&p.Targets, target, 100) {
			s.agg.addTarget(p, target)
		}

		if s.allowAlert(p, h.RuleID, ev.Time) {
			incBounded(&p.RuleAlerts, h.RuleID, alertRuleCap)
			a := s.newAlert(ev, &h, p)
			res.Alerts = append(res.Alerts, a)
		} else {
			// 同一规则在节流窗口内的重复命中：仍然计入「命中」，但不生成告警。
			// 事件里单独累计，避免出现「命中 10 次、告警 6 条」却无处解释的口径差异。
			s.muteIncidentLocked(ev.SrcIP, incidentHit{
				rule: h.RuleID, category: h.Category, phase: h.Phase, result: h.Result,
				target: truncate(ev.Target(), 300), asset: ev.Asset, at: ev.Time,
			})
		}
	}
	if attacked {
		bump(&day.Attackers, ev.SrcIP, 1, maxDayAttackers)
		if p.Geo != nil && p.Geo.Country != "" {
			bump(&day.Countries, p.Geo.Country, 1, maxDayCountries)
		}
		if !wasAttacker {
			day.NewAttackers++
		}
		day.Alerts += int64(len(res.Alerts))
	}
	if attacked && !p.inAgg {
		s.agg.add(p) // 兜底：确保首次攻击一定进入总览统计（目标表已满时 addTarget 可能未被调用）
	}
	if attacked || len(p.Intel) > 0 {
		p.recompute()
		s.agg.setLevel(p, oldLevel)
	}
	if ev.Kind == model.KindWeb {
		s.surf.observeWeb(ev, hits, attacked)
	} else if ev.Kind == model.KindDNS || ev.Kind == model.KindAuth {
		s.hostFinding(ev, hits)
	} else if c2 == nil && (geo.IsPrivate(ev.SrcIP) || ev.Outbound) && hasCategory(hits, CatBeacon) {
		// 按固定间隔回连同一外部地址：疑似 C2 心跳，置信度低于命中情报的外连
		h := hitOf(hits, CatBeacon)
		s.surf.finding("beacon:"+ev.SrcIP+">"+ev.DstIP, "内网主机周期性外连（疑似 C2 心跳）", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
			"核查该主机上连接该地址的进程（netstat / 任务管理器 / EDR），确认是否为正常软件的更新或监控；无法解释时按失陷处置并封禁该地址", ev.DstIP, ev.Time)
	} else if c2 == nil && geo.IsPrivate(ev.SrcIP) && hasCategory(hits, CatMalware) {
		// 安全设备报出内网主机的恶意软件 / 远控通信，同样是失陷迹象
		h := hitOf(hits, CatMalware)
		s.surf.finding("c2:"+ev.SrcIP, "内网主机触发恶意软件 / 远控告警", "失陷迹象", h.Severity, ev.SrcIP, h.Name+"："+h.Evidence,
			"隔离该主机并使用终端安全软件全盘查杀，排查恶意进程、自启动项与外连；确认感染途径后修复", ev.DstIP, ev.Time)
		s.surf.observeFw(ev, s.published(ev))
	} else if c2 != nil {
		s.surf.finding("c2:"+ev.SrcIP, "内网主机外连威胁情报地址", "失陷迹象", c2.Severity, ev.SrcIP, c2.Evidence,
			"立即隔离该主机，排查恶意进程、计划任务、自启动项与可疑账号；在出口防火墙封禁该地址，并核查同网段其他主机是否存在相同外连", ev.DstIP, ev.Time)
	} else {
		s.surf.observeFw(ev, s.published(ev))
	}
	res.Level, res.Score = p.Level, p.Score
	res.LevelUp = p.Level > oldLevel
	res.Profile = p.IP
	return res
}

func (p *IPProfile) setTag(tag, detail string) {
	if p.Tags == nil {
		p.Tags = map[string]string{}
	}
	if _, ok := p.Tags[tag]; ok || len(p.Tags) < 32 {
		p.Tags[tag] = detail
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// 在字符边界截断，避免把多字节字符（中文路径、URL 编码解码后的载荷）截成非法 UTF-8
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// allowAlert 对同一 IP 同一规则的告警做节流，命中仍然计数。
func (s *Store) allowAlert(p *IPProfile, rule string, t time.Time) bool {
	if p.throttle == nil {
		p.throttle = map[string]*window{}
	}
	w := p.throttle[rule]
	if w == nil || t.Sub(w.start) > throttleWindow || w.start.Sub(t) > throttleWindow {
		w = &window{start: t}
		p.throttle[rule] = w
	}
	w.n++
	return w.n <= s.perRule
}

func (s *Store) newAlert(ev *model.Event, h *model.Hit, p *IPProfile) *model.Alert {
	s.nextID++
	s.totals.Alerts++
	a := &model.Alert{
		ID: s.nextID, Time: ev.Time, Kind: ev.Kind, SrcIP: ev.SrcIP, RuleID: h.RuleID, Name: h.Name,
		Category: h.Category, Severity: h.Severity, Phase: h.Phase, Result: h.Result, Target: truncate(ev.Target(), 300),
		Method: ev.Method, Status: ev.Status, Evidence: h.Evidence, UA: truncate(ev.UA, 200), Source: ev.Source,
	}
	if r := ev.Asset; r != nil {
		a.Asset, a.AssetLevel, a.Owner = r.Name, r.Level, r.Owner
	}
	a.Vuln = h.Vuln
	if p.Geo != nil {
		a.Location = p.Geo.Location()
		if p.Geo.HasCoord {
			a.Lat, a.Lon = p.Geo.Lat, p.Geo.Lon
		}
	}
	a.IncidentID = s.attachIncidentLocked(a, p)
	if len(s.alerts) < s.maxAlerts {
		s.alerts = append(s.alerts, a)
	} else {
		s.alerts[s.alertHead] = a
		s.alertHead = (s.alertHead + 1) % s.maxAlerts
	}
	p.Recent = append(p.Recent, a)
	if len(p.Recent) > 50 {
		p.Recent = p.Recent[len(p.Recent)-50:]
	}
	return a
}

// UpdateGeo 在异步溯源完成后更新画像。
func (s *Store) UpdateGeo(ip string, info *geo.Info) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.ips[ip]; p != nil {
		old := p.Geo
		p.Geo = info
		s.agg.setGeo(p, old)
	}
}

// RefreshGeo 用 relocate 重新定位全部画像（定位库热更新、快照恢复后调用），返回位置发生变化的画像数。
// 定位在锁外进行，只在写回时短暂持锁。
func (s *Store) RefreshGeo(relocate func(ip string, old *geo.Info) *geo.Info) int {
	type item struct {
		ip  string
		old *geo.Info
	}
	s.mu.RLock()
	list := make([]item, 0, len(s.ips))
	for ip, p := range s.ips {
		list = append(list, item{ip, p.Geo})
	}
	s.mu.RUnlock()
	n := 0
	for _, it := range list {
		info := relocate(it.ip, it.old)
		if info == nil || info == it.old {
			continue
		}
		s.mu.Lock()
		if p := s.ips[it.ip]; p != nil && p.Geo == it.old {
			if !geo.SameLocation(it.old, info) {
				n++
			}
			p.Geo = info
			s.agg.setGeo(p, it.old)
		}
		s.mu.Unlock()
	}
	return n
}

// Tag 给 IP 打标签。
func (s *Store) Tag(ip, tag, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.ips[ip]; p != nil {
		p.setTag(tag, detail)
	}
}

// Maintain 清理过期时间桶并在 IP 数量超限时淘汰低价值画像。
func (s *Store) Maintain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.maxTime.IsZero() {
		cut := s.maxTime.Add(-s.retention).Unix() / 60
		for k := range s.buckets {
			if k < cut {
				delete(s.buckets, k)
			}
		}
		// 「近 1 小时」只用到 60 分钟，保留 2 小时的分钟桶即可
		s.agg.prune(s.maxTime.Add(-2 * time.Hour))
	}
	if len(s.ips) > s.maxIPs {
		s.evictLocked()
	}
}

// published 判断防火墙事件的目标端口是否真实对外开放；内网目标视为已发布（已过 DNAT 或东西向流量）。
func (s *Store) published(ev *model.Event) bool {
	if s.PortPublished == nil || ev.DstIP == "" || geo.IsPrivate(ev.DstIP) {
		return true
	}
	return s.PortPublished(ev.DstIP, ev.DstPort, ev.Proto)
}

// hasAttack 判断命中中是否包含攻击（仅打标签的命中不算）。
func hasAttack(hits []model.Hit) bool {
	for _, h := range hits {
		if !h.TagOnly {
			return true
		}
	}
	return false
}

// evictLocked 淘汰评分最低、最久未活动的画像，使数量回到上限的 90%（调用方持写锁）。
//
// 只淘汰 maxIPs/10 个，因此用「定长大顶堆 + 部分选择」而不是为全部画像分配切片再全量排序：
// 20 万画像时比较次数从 O(N log N) 降到 O(N log K)、额外内存从 O(N) 降到 O(K)，
// 写锁持有时长同步下降（该函数运行在日志入库的写锁内，停顿越小越好）。
func (s *Store) evictLocked() {
	n := len(s.ips) - s.maxIPs + s.maxIPs/10
	if n <= 0 {
		return
	}
	// 堆中保存「最该淘汰的 n 个」，堆顶是其中最不该淘汰的一个（评分最高 / 最近活动）
	h := make([]*IPProfile, 0, min(n, len(s.ips)))
	for _, p := range s.ips {
		if len(h) < n {
			h = append(h, p)
			heapSiftUp(h, len(h)-1)
			continue
		}
		if evictsAfter(h[0], p) { // 堆顶比新候选更值得保留 → 用新候选替换堆顶
			h[0] = p
			heapSiftDown(h, 0)
		}
	}
	for _, p := range h {
		s.agg.remove(p)
		delete(s.ips, p.IP)
	}
}

// evictsAfter 判断 a 是否应比 b 更晚被淘汰：评分高者优先保留，评分相同时更近活动者优先保留。
func evictsAfter(a, b *IPProfile) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.LastSeen.After(b.LastSeen)
}

// heapSiftUp / heapSiftDown 维护按 evictsAfter 排序的大顶堆。
func heapSiftUp(h []*IPProfile, i int) {
	for i > 0 {
		parent := (i - 1) / 2
		if !evictsAfter(h[i], h[parent]) {
			return
		}
		h[i], h[parent] = h[parent], h[i]
		i = parent
	}
}

func heapSiftDown(h []*IPProfile, i int) {
	for {
		left, right, top := 2*i+1, 2*i+2, i
		if left < len(h) && evictsAfter(h[left], h[top]) {
			top = left
		}
		if right < len(h) && evictsAfter(h[right], h[top]) {
			top = right
		}
		if top == i {
			return
		}
		h[i], h[top] = h[top], h[i]
		i = top
	}
}

// Profile 返回 IP 画像的副本指针（只读使用）。
func (s *Store) Profile(ip string) *IPProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ips[ip]
}
