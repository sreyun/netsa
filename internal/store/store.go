// Package store 维护态势感知的内存状态：攻击者画像、告警、时间序列与攻击面，并支持快照持久化。
package store

import (
	"maps"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"netsa/internal/detect"
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
	TLS        map[string]int            `json:"tls,omitempty"`     // 客户端 TLS 指纹（JA3 / JA4，或协议/加密套件）
	Rhythm     *Rhythm                   `json:"rhythm,omitempty"`  // 行为节奏：活跃时段与请求间隔（攻击源才记录）
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
	// retractedOnly 表示全部命中都来自已停用的误报规则（如被业务轮询停用的自学习观察规则）：不再算作攻击源，
	// 不进入总览、地图与攻击源列表。出现其他规则的命中后恢复。不持久化：启动时由纠错重放重新计算
	retractedOnly bool `json:"-"`
}

type window struct {
	start time.Time
	n     int
	// 窗口内已生成告警的最高等级，以及是否已有疑似成功、有证据的告警：
	// 等级更高、第一次成功、第一次有证据的命中不是“重复命中”，不受节流
	top            model.Severity
	success, proof bool
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

// ruleMeta 是规则的攻击类型与阶段（第一次命中时记录）。
type ruleMeta struct {
	Category string `json:"category"`
	Phase    string `json:"phase"`
}

// scoreInputs 返回评分使用的攻击类型计数、类型等级、阶段计数与最高等级。被判定为误报而停用的规则（ex）的命中不计入：
// 例如被业务轮询停用的自学习观察规则，员工出口地址因它累计了数万次命中，不剔除会一直显示为高危攻击源。
// 原始计数保持不变（停用的规则重新启用后恢复计入）；画像中没有这些规则的命中时直接返回原始统计。
func (p *IPProfile) scoreInputs(ex map[string]bool, meta map[string]ruleMeta) (cats map[string]int, catSev map[string]model.Severity, phases map[string]int, maxSev model.Severity) {
	cats, catSev, phases, maxSev = p.Categories, p.CatSev, p.Phases, p.MaxSev
	hit := false
	for r := range ex {
		if p.Rules[r] > 0 {
			hit = true
			break
		}
	}
	if !hit {
		return
	}
	cats, phases = maps.Clone(p.Categories), maps.Clone(p.Phases)
	catSev = maps.Clone(p.CatSev)
	touched := map[string]bool{}
	for r := range ex {
		n := p.Rules[r]
		if n <= 0 {
			continue
		}
		m := meta[r]
		if m.Category != "" {
			if cats[m.Category] -= n; cats[m.Category] <= 0 {
				delete(cats, m.Category)
				delete(catSev, m.Category)
			} else {
				touched[m.Category] = true
			}
		}
		if m.Phase != "" {
			if phases[m.Phase] -= n; phases[m.Phase] <= 0 {
				delete(phases, m.Phase)
			}
		}
	}
	// 类型等级与最高等级按其余规则重新取最大值（类型的其余命中来自没有记录类型的规则时保持原值）
	maxSev = model.SevInfo
	bySev := map[string]model.Severity{}
	for r, n := range p.Rules {
		if n <= 0 || ex[r] {
			continue
		}
		sev := p.RuleSev[r]
		maxSev = max(maxSev, sev)
		if c := meta[r].Category; touched[c] {
			bySev[c] = max(bySev[c], sev)
		}
	}
	for c := range touched {
		if sev, ok := bySev[c]; ok {
			catSev[c] = sev
		}
	}
	return
}

// recompute 根据命中规则重新计算威胁分（0-100）与等级。
// 按攻击分类累计：同类重复命中按对数递增（最多 2 倍），侦察类打 6 折，避免单一扫描器刷高分；
// 疑似成功、多阶段攻击链、情报命中额外加分。ex 中的规则（停用的误报规则）的命中不计入，见 scoreInputs。
func (p *IPProfile) recompute(ex map[string]bool, meta map[string]ruleMeta) {
	cats, catSev, phaseCount, maxSev := p.scoreInputs(ex, meta)
	sum := 0.0
	for cat, n := range cats {
		c := sevWeight[catSev[cat]] * math.Min(1+math.Log2(float64(n))/3, 2)
		if p.CatPhase[cat] == model.PhaseRecon {
			c *= 0.6
		}
		sum += c
	}
	if p.Successes > 0 {
		sum += 20
	}
	phases := 0
	for ph, n := range phaseCount {
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
	floorSev := maxSev
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
	// 严重级攻击源同样要求佐证：出现过严重告警（严重告警本身要求成功证据）或失陷迹象。
	// 扫描器把各类漏洞载荷都试一遍、全部没有成功时，按攻击类型累加的评分会顶到 100，但它不是严重威胁
	if lvl == model.SevCritical && floorSev < model.SevCritical {
		lvl = model.SevHigh
		p.Score = min(p.Score, levelFloor[model.SevCritical]-0.1)
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
	DNS      int64 `json:"dns,omitempty"`     // DNS 查询日志
	Auth     int64 `json:"auth,omitempty"`    // 主机 / VPN 认证日志
	Process  int64 `json:"process,omitempty"` // 主机进程日志（EDR / HIDS）
	Aux      int64 `json:"aux,omitempty"`     // 流量日志的辅助记录（TLS 握手、传输的文件）
	Egress   int64 `json:"egress,omitempty"`  // 防火墙日志中内网主机访问公网的流量
	Attacks  int64 `json:"attacks"`
	Alerts   int64 `json:"alerts"`
	Blocked  int64 `json:"blocked"`
	Success  int64 `json:"success"`
	// Untracked 为画像数超过上限期间未建立画像的正常访问（仍计入总量与攻击面统计）
	Untracked int64 `json:"untracked,omitempty"`
}

// Store 是线程安全的态势状态库。
type Store struct {
	mu           sync.RWMutex
	campMu       sync.Mutex      // 攻击活动归并结果的缓存（campaign.go），计算期间不持有 mu
	camp         *CampaignReport // 最近一次归并结果
	campBuilding bool            // 后台正在重新归并（campMu 保护）
	maxIPs       int
	maxAlerts    int
	perRule      int
	retention    time.Duration
	ips          map[string]*IPProfile
	alerts       []*model.Alert
	alertHead    int
	nextID       uint64
	buckets      map[int64]*Bucket
	totals       Totals
	categories   map[string]int64
	rules        map[string]int64
	ruleNames    map[string]string
	ruleMeta     map[string]ruleMeta     // 规则 → 攻击类型与阶段（剔除误报规则的命中时按此调整评分与排行）
	excluded     map[string]bool         // 命中不计入攻击源评分与排行的规则：被判定为误报而停用的自学习观察规则
	retracted    map[string]bool         // 全部命中都来自停用规则的画像（retractedOnly），数量很少，总览据此修正排行
	tally        map[string]*ruleTally   // 自学习观察规则的命中构成：停用后从总览的攻击次数、等级、研判结果与目标排行中剔除
	outbound     map[string]*OutboundDst // 内部对外的攻击与异常连接的外部目标（地图上从受保护资产飞出的线）
	sevCount     [5]int64
	phases       map[string]int64
	results      map[string]int64
	minTime      time.Time
	maxTime      time.Time
	surf         *surface
	ruleBits     map[string]int       // 规则 ID → 指纹位下标（同源关联分析用）
	scores       []ScorePoint         // 安全评分历史（每小时一次）
	incidents    map[uint64]*Incident // 安全事件（同一来源的告警合并处置）
	incByKey     map[string]uint64    // 来源 IP → 最近的事件
	journal      *os.File             // 处置记录预写日志，见 journal.go
	journalPath  string
	nextInc      uint64
	agg          *aggregate          // 总览增量统计（国家/省份/城市/等级/目标/近 1 小时）
	days         map[string]*DayStat // 按自然日的汇总（周报 / 月报）
	curDay       *DayStat
	dayStart     int64
	dayEnd       int64
	loc          *time.Location
	chains       map[chainKey]*chainTrack // 资产攻击链路（chain.go）
	noSrcSeen    map[string]time.Time     // 没有来源的设备威胁的告警节流（nosource.go）

	// AssetOf 返回地址或站点域名对应的台账资产（资产攻击链路识别外连、横向的内网主机），为 nil 时只按地址与域名区分资产。
	// 调用时持有状态库的写锁，不能回调状态库
	AssetOf func(ip, host string) *model.AssetRef
	// OASTLinks 返回被多个来源使用过的带外回连标识 → 来源（learn.Learner.OASTLinks），攻击活动归并与同源关联据此
	// 把同一次扫描任务的多个出口地址连在一起。在状态库的锁之外调用
	OASTLinks func() map[string][]string
	// DecoyLinks 返回使用同一诱饵线索、诱饵账号的来源（deception.Manager.Links），同样直接关联。在状态库的锁之外调用
	DecoyLinks func() map[string][]string
	// IntelKind 返回情报的类别（c2 / malware / phishing / mining / attacker，空为通用黑名单），决定情报命中的等级
	IntelKind func(name string) string
	// Calibrate 是自学习校准（learn.Learner.Calibrate）：状态库自己生成的情报命中（入站情报、外连情报地址）
	// 不经过流水线，同样要按情报源的准确率下调。不能回调状态库（调用时持有状态库的写锁）
	Calibrate func(ev *model.Event, hits []model.Hit) []model.Hit
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
		categories: map[string]int64{}, rules: map[string]int64{}, ruleNames: map[string]string{}, ruleMeta: map[string]ruleMeta{}, excluded: map[string]bool{}, retracted: map[string]bool{}, tally: map[string]*ruleTally{}, outbound: map[string]*OutboundDst{},
		phases: map[string]int64{}, results: map[string]int64{}, surf: newSurface(), ruleBits: map[string]int{},
		incidents: map[uint64]*Incident{}, incByKey: map[string]uint64{},
		agg: newAggregate(), days: map[string]*DayStat{}, chains: map[chainKey]*chainTrack{},
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
	// NewOutbound 是本次新记录的内部对外目标（外部地址），由调用方发起在线溯源以便在地图上定位
	NewOutbound string
}

const throttleWindow = 10 * time.Minute

// alertRuleCap 是单个画像记录的规则数上限（规则总量有限，预留余量防止自定义规则过多时内存膨胀）。
const alertRuleCap = 500

// maxRuleIDs 是全局规则统计表记录的不同规则编号数上限。
const maxRuleIDs = 4096

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

// countEvent 计入事件量（总量、分钟桶、每日统计）。
func (s *Store) countEvent(ev *model.Event, b *Bucket, day *DayStat) {
	day.Events++
	switch ev.Kind {
	case model.KindWeb:
		s.totals.Web++
		b.Web++
		day.Web++
	case model.KindDNS:
		day.DNS++
		s.totals.DNS++
	case model.KindAuth:
		day.Auth++
		s.totals.Auth++
	case model.KindProcess:
		s.totals.Process++
	default:
		s.totals.Firewall++
		b.Fw++
		day.Firewall++
		if ev.DstIP != "" && geo.IsPrivate(ev.SrcIP) && !geo.IsPrivate(ev.DstIP) {
			s.totals.Egress++ // 内网主机访问公网的出站流量（外连检测的数据基础）
		}
	}
}

func (s *Store) recordLocked(ev *model.Event, hits []model.Hit) RecordResult {
	var res RecordResult
	// 端口只取 1~65535：解析器按整数读取，字段错位或伪造的日志会带来任意整数，以端口为键的统计因此无上限增长
	if ev.DstPort < 0 || ev.DstPort > 65535 {
		ev.DstPort = 0
	}
	if ev.SrcPort < 0 || ev.SrcPort > 65535 {
		ev.SrcPort = 0
	}
	hits = s.dropSelfRefLocked(ev, hits)

	count := !ev.Replay && !ev.Aux // 补发命中的事件副本已经计入过事件量；辅助记录描述的是已经计入的连接
	if count {
		s.totals.Events++
	}
	if ev.Aux && !ev.Replay {
		s.totals.Aux++
		if !hasAttack(hits) {
			// 没有命中的 TLS 握手：只给已有的画像记录客户端指纹（同源关联），不建立新画像
			if p := s.ips[ev.SrcIP]; p != nil && ev.TLSFinger != "" {
				incBounded(&p.TLS, truncate(ev.TLSFinger, 80), 4)
			}
			return res
		}
	}
	// 外连威胁情报地址：内网主机（或本机）主动连接已知恶意地址是典型的失陷迹象（木马回连 C2、挖矿、数据外传）。
	// 普通出站流量不作为攻击来源统计；命中情报的出站连接以发起连接的主机为主体记录告警。
	var c2 *model.Hit
	if ev.Kind == model.KindFirewall && s.IntelMatch != nil && count && !ev.Response { // 单向流的应答方向：服务端回复访客，不是主动外连
		if c2 = s.c2Hit(ev); c2 != nil {
			*c2 = s.calibrated(ev, *c2)
		}
	}
	if ev.Outbound || ev.Response {
		if count && ev.Outbound {
			s.totals.Outbound++
		}
		if c2 == nil && !hasAttack(hits) { // 出站流量只记录外连恶意地址、周期性外连等失陷迹象；单向流的应答方向只计入总量
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
	if count {
		s.countEvent(ev, b, day)
	}
	if (ev.Kind == model.KindDNS || ev.Kind == model.KindAuth || ev.Kind == model.KindProcess) && !hasAttack(hits) {
		return res // DNS 查询与认证日志量大，只记录总量；命中异常时才以主体（内网主机 / 登录来源）建立画像
	}

	if ev.SrcIP == "" {
		// 设备只记录了被攻击的目的地址（多源洪泛）：不建立来源画像
		if hasAttack(hits) {
			return s.recordNoSourceLocked(ev, hits, b, day)
		}
		return res
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
			// 情报只说明来源的信誉：流量已被拦截、或会话证据表明没有到达任何服务时按中危记录，
			// 其余情况（可能已到达服务）按高危；后续真实的攻击命中会照常抬升等级。
			sev, res, note := model.SevHigh, model.ResultUnknown, ""
			switch {
			case ev.Kind == model.KindFirewall && ev.Action == model.ActionDeny:
				sev, res, note = model.SevMedium, model.ResultBlocked, "（流量已被防火墙拦截）"
			case ev.Reach == model.ReachNo:
				sev, res, note = model.SevMedium, model.ResultFailed, "（防火墙会话证据表明未到达任何服务）"
			}
			// 扫描、暴力破解来源的名单只说明信誉，真实的攻击由规则判断；钓鱼、矿池地址主动来访不常见，只作提示
			switch s.intelKind(p.Intel) {
			case "attacker":
				sev = pick(res != model.ResultUnknown, model.SevLow, model.SevMedium)
			case "phishing", "mining":
				sev = model.SevLow
			}
			hits = append(hits, s.calibrated(ev, model.Hit{RuleID: "intel", Name: "威胁情报命中", Category: "威胁情报", Severity: sev,
				Phase: model.PhaseRecon, Evidence: strings.Join(p.Intel, ", ") + note, Result: res, Feeds: feedNames(p.Intel)}))
		}
	}
	oldLevel, oldSeen, oldFirst := p.Level, p.LastSeen, p.FirstSeen
	if count {
		p.Events++
	}
	if ev.Time.After(p.LastSeen) {
		p.LastSeen = ev.Time
	}
	if ev.Time.Before(p.FirstSeen) {
		p.FirstSeen = ev.Time
	}
	s.agg.moveLastSeen(p, oldSeen)
	s.agg.moveFirstSeen(p, oldFirst)
	switch {
	case !count: // 补发的命中不再计入访问统计
	case ev.Kind == model.KindWeb:
		p.WebReqs++
		incBounded(&p.Status, ev.Status, 50)
		if ev.UA != "" {
			incBounded(&p.UAs, printable(truncate(ev.UA, 200)), 10)
		}
		if ev.PeerIP != "" {
			incBounded(&p.Proxies, ev.PeerIP, 20)
			p.LastXFF = printable(truncate(ev.XFF, 300)) // 请求头内容，可能被伪造成任意字节
		}
	default:
		p.FwEvents++
		if ev.Action == model.ActionDeny {
			p.Denied++
		}
		if ev.DstPort > 0 && incBounded(&p.Ports, ev.DstPort, 500) {
			p.sk.ports |= intBit(ev.DstPort)
		}
	}

	if ev.TLSFinger != "" {
		incBounded(&p.TLS, truncate(ev.TLSFinger, 80), 4)
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
	var roles chainRoles // 资产攻击链路中的角色，第一次攻击命中时计算
	var alertID, incID uint64
	for _, h := range hits {
		if h.TagOnly {
			p.setTag(h.Name, h.Evidence)
			continue
		}
		p.ensureAttackMaps()
		// 规则编号以规则库为主、数量有限，但第三方告警（EDR、设备威胁）的编号来自日志：全局的规则表设上限，
		// 超出后并入一个溢出编号（仍计入攻击总量），这些表与画像上以规则为键的统计都不会无上限增长
		if _, ok := s.rules[h.RuleID]; !ok && len(s.rules) >= maxRuleIDs {
			h.RuleID, h.Name = "rule-overflow", "其他规则（规则编号过多）"
		}
		if p.retractedOnly && !s.excluded[h.RuleID] { // 出现了其他规则的命中：重新算作攻击源（随后的 add 一次性计入统计）
			p.retractedOnly = false
			delete(s.retracted, p.IP)
		}
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
		if _, ok := s.ruleMeta[h.RuleID]; !ok {
			s.ruleMeta[h.RuleID] = ruleMeta{Category: h.Category, Phase: h.Phase}
		}
		s.phases[h.Phase]++
		s.results[h.Result]++
		if strings.HasPrefix(h.RuleID, "learn-") {
			s.tallyLocked(&h, truncate(ev.Target(), 200))
		}
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

		if s.allowAlert(p, &h, ev.Time) {
			incBounded(&p.RuleAlerts, h.RuleID, alertRuleCap)
			a := s.newAlert(ev, &h, p)
			res.Alerts = append(res.Alerts, a)
			alertID, incID = a.ID, a.IncidentID
		} else {
			// 同一规则在节流窗口内的重复命中：仍然计入「命中」，但不生成告警。
			// 事件里单独累计，避免出现「命中 10 次、告警 6 条」却无处解释的口径差异。
			s.muteIncidentLocked(ev.SrcIP, incidentHit{
				rule: h.RuleID, category: h.Category, phase: h.Phase, result: h.Result, proven: h.Proven,
				target: truncate(ev.Target(), 300), asset: ev.Asset, at: ev.Time, feeds: h.Feeds,
			})
			alertID, incID = 0, s.incByKey[ev.SrcIP]
		}
		// 资产攻击链路按命中口径记录（含被节流的重复命中）
		if !roles.done {
			roles = s.chainRolesOf(ev)
		}
		s.chainHitLocked(ev, &h, &roles, t, alertID, incID)
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
	if attacked && count {
		if s.observeOutboundLocked(ev, hits, t) { // 内部对外的攻击与异常连接：记录外部目标（攻击来源地图的外连飞线）
			res.NewOutbound = ev.DstIP
		}
	}
	if attacked && !p.inAgg {
		s.agg.add(p) // 兜底：确保首次攻击一定进入总览统计（目标表已满时 addTarget 可能未被调用）
	}
	if attacked || len(p.Intel) > 0 {
		p.recompute(s.excluded, s.ruleMeta)
		s.agg.setLevel(p, oldLevel)
	}
	if p.Attacks > 0 && count { // 攻击源的行为节奏（活跃时段与请求间隔），同源关联据此比对轮换出口的同一攻击者
		if p.Rhythm == nil {
			p.Rhythm = &Rhythm{}
		}
		p.Rhythm.observe(t, s.location())
	}
	if ev.Kind == model.KindWeb {
		s.surf.observeWeb(ev, hits, attacked)
	} else if ev.Kind == model.KindDNS || ev.Kind == model.KindAuth || ev.Kind == model.KindProcess || ev.Aux {
		s.hostFinding(ev, hits)
	} else if c2 == nil && (geo.IsPrivate(ev.SrcIP) || ev.Outbound) && hasCategory(hits, CatBeacon) {
		// 按固定间隔回连同一外部地址：疑似 C2 心跳，置信度低于命中情报的外连
		h := hitOf(hits, CatBeacon)
		s.surf.finding("beacon:"+ev.SrcIP+">"+ev.DstIP, "内网主机周期性外连（疑似 C2 心跳）", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
			"核查该主机上连接该地址的进程（netstat / 任务管理器 / EDR），确认是否为正常软件的更新或监控；无法解释时按失陷处置并封禁该地址", ev.DstIP, ev.Time)
	} else if c2 == nil && hasCategory(hits, CatCallback) {
		// 遭受 Web 攻击之后连接攻击者、或攻击载荷中的回连地址（防火墙与 Web 日志联动）
		h := hitOf(hits, CatCallback)
		s.surf.finding("callback:"+ev.SrcIP+">"+ev.DstIP, "内网主机在遭受攻击后连接攻击者（"+h.Name+"）", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
			"立即排查该主机上连接该地址的进程与最近新增的文件、计划任务、账号；确认被利用的漏洞并修复，在出口防火墙封禁该地址", ev.DstIP, ev.Time)
	} else if c2 == nil && geo.IsPrivate(ev.SrcIP) && hasCategory(hits, CatMalware) {
		// 安全设备报出内网主机的恶意软件 / 远控通信，同样是失陷迹象
		h := hitOf(hits, CatMalware)
		s.surf.finding("c2:"+ev.SrcIP, "内网主机触发恶意软件 / 远控告警", "失陷迹象", h.Severity, ev.SrcIP, h.Name+"："+h.Evidence,
			"隔离该主机并使用终端安全软件全盘查杀，排查恶意进程、自启动项与外连；确认感染途径后修复", ev.DstIP, ev.Time)
		s.surf.observeFw(ev, s.published(ev))
	} else if c2 != nil && (c2.Category == CatC2 || c2.Category == CatMining || c2.Category == CatMalDomain) {
		// 钓鱼网站、攻击来源类情报只告警，不作为失陷迹象登记
		s.surf.finding("c2:"+ev.SrcIP, "内网主机外连威胁情报地址", "失陷迹象", c2.Severity, ev.SrcIP, c2.Evidence,
			"立即隔离该主机，排查恶意进程、计划任务、自启动项与可疑账号；在出口防火墙封禁该地址，并核查同网段其他主机是否存在相同外连", ev.DstIP, ev.Time)
	} else if count {
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
		p.Tags[tag] = printable(detail) // 说明来自日志（UA、主机名）
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
// allowAlert 判断一次命中是否生成告警：同一来源、同一规则在节流窗口内最多 alerts_per_rule 条。
// 结果更严重的命中不算重复：等级高于窗口内已告警的、窗口内第一次疑似成功、第一次有证据的，照常生成告警
// （典型如连续几次失败的注入之后有一次成功：不能因为前面已经告警过 5 次就只记一次命中，事件等级也不升）。
func (s *Store) allowAlert(p *IPProfile, h *model.Hit, t time.Time) bool {
	if p.throttle == nil {
		p.throttle = map[string]*window{}
	}
	w := p.throttle[h.RuleID]
	if w == nil || t.Sub(w.start) > throttleWindow || w.start.Sub(t) > throttleWindow {
		w = &window{start: t}
		p.throttle[h.RuleID] = w
	}
	w.n++
	success := h.Result == model.ResultSuccess
	allow := w.n <= s.perRule || h.Severity > w.top || success && !w.success || h.Proven && !w.proof
	if allow {
		w.top = max(w.top, h.Severity)
		w.success = w.success || success
		w.proof = w.proof || h.Proven
	}
	return allow
}

func (s *Store) newAlert(ev *model.Event, h *model.Hit, p *IPProfile) *model.Alert {
	s.nextID++
	s.totals.Alerts++
	a := &model.Alert{
		ID: s.nextID, Time: ev.Time, Kind: ev.Kind, SrcIP: ev.SrcIP, RuleID: h.RuleID, Name: h.Name,
		Category: h.Category, Severity: h.Severity, Phase: h.Phase, Result: h.Result, Target: truncate(ev.Target(), 300),
		Method: ev.Method, Status: ev.Status, Evidence: printable(h.Evidence), UA: printable(truncate(ev.UA, 200)), Source: ev.Source, Proven: h.Proven, Learned: h.Learned,
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
	if inc := s.incidents[a.IncidentID]; inc != nil && len(h.Feeds) > 0 {
		inc.addFeeds(h.Feeds)
	}
	s.appendAlertLocked(a)
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
	if d := s.outbound[ip]; d != nil { // 内部对外的外部目标同样更新归属地（地图定位）
		d.Geo = info
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
				// 该来源的事件同样更新归属（否则要等下一条告警才更新）
				if inc := s.incidents[s.incByKey[it.ip]]; inc != nil {
					inc.Location = info.Location()
				}
			}
			p.Geo = info
			s.agg.setGeo(p, it.old)
		}
		s.mu.Unlock()
	}
	// 内部对外的外部目标同样按当前定位库重新定位：它们不在画像里（主体是发起连接的内网主机），
	// 不重新定位的话，地图上外连目标的位置在定位库或定位规则更新后一直是旧的
	s.mu.RLock()
	list = list[:0]
	for ip, d := range s.outbound {
		list = append(list, item{ip, d.Geo})
	}
	s.mu.RUnlock()
	for _, it := range list {
		info := relocate(it.ip, it.old)
		if info == nil || info == it.old {
			continue
		}
		s.mu.Lock()
		if d := s.outbound[it.ip]; d != nil && d.Geo == it.old {
			d.Geo = info
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
		s.pruneChainsLocked(s.maxTime)
		s.pruneOutboundLocked(s.maxTime)
	}
	if len(s.ips) > s.maxIPs {
		s.evictLocked()
	}
}

// published 判断防火墙事件的目标端口是否真实对外开放；内网目标视为已发布（已过 DNAT 或东西向流量）。
// 防火墙日志带有会话证据时以证据为准：放行但没有转发到内部服务（如 untrust → untrust）的端口不是对外服务。
func (s *Store) published(ev *model.Event) bool {
	switch ev.Reach {
	case model.ReachNo:
		return false
	case model.ReachYes, model.ReachDevice:
		return true
	}
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
		delete(s.retracted, p.IP)
	}
}

// dropSelfRefLocked 丢弃参数地址指向本站的“远程文件包含”命中（调用方持锁）：只在请求的 Host 是已登记的资产、
// 或首页有稳定的正常访问（真实存在的站点）时丢弃。Host 头由客户端提供，攻击者把它改成自己的域名时，
// 那个域名在这里没有任何正常访问，命中照常保留。
func (s *Store) dropSelfRefLocked(ev *model.Event, hits []model.Hit) []model.Hit {
	idx := -1
	for i := range hits {
		if hits[i].SelfRef {
			idx = i
			break
		}
	}
	if idx < 0 {
		return hits
	}
	known := ev.Asset != nil || ev.Host != "" && !detect.FakeSiteHost(ev.Host) && s.surf.hasHomeBaseline(ev.Host)
	out := make([]model.Hit, 0, len(hits))
	for _, h := range hits {
		if h.SelfRef {
			if known {
				continue
			}
			h.SelfRef = false
		}
		out = append(out, h)
	}
	return out
}

// ruleTally 是一条自学习观察规则的命中构成（等级、研判结果、主要目标）。观察规则的数量有上限（learn.maxLearnedRules）。
type ruleTally struct {
	Sev     [5]int64         `json:"sev"`
	Results map[string]int64 `json:"results,omitempty"`
	Targets map[string]int64 `json:"targets,omitempty"` // 最多 maxTallyTargets 个
}

const (
	maxTallies      = 1000
	maxTallyTargets = 20
)

func (s *Store) tallyLocked(h *model.Hit, target string) {
	t := s.tally[h.RuleID]
	if t == nil {
		if len(s.tally) >= maxTallies {
			return
		}
		t = &ruleTally{Results: map[string]int64{}, Targets: map[string]int64{}}
		s.tally[h.RuleID] = t
	}
	if h.Severity >= model.SevInfo && h.Severity <= model.SevCritical {
		t.Sev[h.Severity]++
	}
	if t.Results == nil {
		t.Results = map[string]int64{}
	}
	t.Results[h.Result]++
	if t.Targets == nil {
		t.Targets = map[string]int64{}
	}
	if _, ok := t.Targets[target]; ok || len(t.Targets) < maxTallyTargets {
		t.Targets[target]++
	}
}

// retractedOnlyOf 判断画像的全部命中是否都来自 ex 中的规则（且没有情报命中）。
func retractedOnlyOf(p *IPProfile, ex map[string]bool) bool {
	if len(ex) == 0 || p.Attacks == 0 || len(p.Intel) > 0 {
		return false
	}
	any := false
	for r, n := range p.Rules {
		if n <= 0 {
			continue
		}
		if !ex[r] {
			return false
		}
		any = true
	}
	return any
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
