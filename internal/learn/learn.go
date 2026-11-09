// Package learn 是平台的自学习模块：从分析员的研判结论与平台自身的运行数据中持续学习。
//
// 设计边界（自学习不能变成新的风险来源）：
//   - 只从人的结论学习：分析员把事件处置为「已处置」（确认攻击）或「误报」时才计入样本，AI 与系统自动生成的状态不参与；
//   - 自动调整每次最多一级，且可随时撤销（锁定规则 / 关闭策略）：
//     下调分两种粒度：规则整体准确率持续偏低时整体下调，只在个别目标上反复误报时只下调该目标（规则 + 目标），
//     最多低于攻击分类底线一级，响应证明利用成功时仍升为严重；
//     上调只针对分析员确认过的攻击来源（有效期内复现），只升低危 / 中危，最多到高危；
//   - 外部模型的结论不作为样本，只用分析员的结论评估模型的一致率，并把历史人工结论提供给模型作研判参考；
//   - 会隐藏告警的动作（误报抑制）只生成建议，必须由人确认采纳；
//   - 从正常流量学习参数的正常取值与站点产品（见 profile.go、site.go）：降级只到低危、仍生成告警，
//     且要两个相互独立的依据同时成立（参数平时就是普通文字 + 语法分析不构成注入；站点没有该产品 + 请求没有成功），
//     依据写在告警证据中，学习结果在「自学习」页面展示；
//   - 每一次自动调整都记入「进化日志」并写入审计链。
package learn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/model"
)

// Options 是自学习参数。
type Options struct {
	Path         string  `json:"-"`             // 学习状态文件（为空时只保存在内存中）
	Calibrate    bool    `json:"calibrate"`     // 按研判准确率自动校准规则等级
	MinVerdicts  int     `json:"min_verdicts"`  // 规则参与自动校准所需的最少研判样本数（默认 5）
	MaxPrecision float64 `json:"max_precision"` // 准确率不高于该值时自动下调一级（默认 0.2）
	Sentinel     bool    `json:"sentinel"`      // 学习平台账号的行为基线并告警异常操作
	Compliance   bool    `json:"compliance"`    // 持续合规自检
	// CtxMinFP 是「规则 + 目标」精细校准所需的最少误报次数（由 MinVerdicts 推导：max(3, MinVerdicts-2)）
	CtxMinFP int `json:"ctx_min_fp"`
	// Escalate 已被分析员确认为攻击的来源在 EscalateDays 天内再次出现时，攻击命中升级一级（不超过高危）
	Escalate     bool `json:"escalate"`
	EscalateDays int  `json:"escalate_days"` // 默认 30
	// WindowDays 学习窗口（天）：更早的结论不再参与校准与建议，环境变化后旧结论自动失效。0 取默认 180，负数不限
	WindowDays int `json:"window_days"`
	// ArchiveOff 关闭自动归档已结束的低风险事件；ArchiveDays 事件多少天没有活动后归档（0 取默认 3）
	ArchiveOff  bool `json:"archive_off,omitempty"`
	ArchiveDays int  `json:"archive_days,omitempty"`
}

// Policy 是可在 Web 管理页面调整的自学习策略，保存在学习状态中，优先于配置文件。
type Policy struct {
	Calibrate    bool      `json:"calibrate"`
	MinVerdicts  int       `json:"min_verdicts"`
	MaxPrecision float64   `json:"max_precision"`
	Escalate     bool      `json:"escalate"`
	EscalateDays int       `json:"escalate_days"`
	WindowDays   int       `json:"window_days"`            // 0 表示不限
	ArchiveOff   bool      `json:"archive_off,omitempty"`  // 关闭自动归档（零值为开启：旧版本保存的策略没有这一项）
	ArchiveDays  int       `json:"archive_days,omitempty"` // 0 取默认 3 天
	UpdatedBy    string    `json:"updated_by,omitempty"`
	Updated      time.Time `json:"updated,omitzero"`
}

func (p Policy) check() error {
	switch {
	case p.MinVerdicts < 2 || p.MinVerdicts > 1000:
		return errors.New("规则校准的最少样本数应在 2 ~ 1000 之间")
	case p.MaxPrecision <= 0 || p.MaxPrecision >= 1:
		return errors.New("准确率阈值应在 1% ~ 99% 之间")
	case p.EscalateDays < 1 || p.EscalateDays > 365:
		return errors.New("确认攻击源的有效天数应在 1 ~ 365 之间")
	case p.WindowDays < 0 || (p.WindowDays > 0 && p.WindowDays < 7) || p.WindowDays > 3650:
		return errors.New("学习窗口应为 0（不限）或 7 ~ 3650 天")
	case p.ArchiveDays < 0 || p.ArchiveDays > 90:
		return errors.New("自动归档的天数应在 1 ~ 90 之间")
	}
	return nil
}

// apply 把策略写入运行参数（调用方持锁）。
func (o *Options) apply(p Policy) {
	o.Calibrate, o.MinVerdicts, o.MaxPrecision, o.Escalate, o.EscalateDays = p.Calibrate, p.MinVerdicts, p.MaxPrecision, p.Escalate, p.EscalateDays
	o.WindowDays = p.WindowDays
	if o.WindowDays == 0 {
		o.WindowDays = -1
	}
	o.ArchiveOff, o.ArchiveDays = p.ArchiveOff, p.ArchiveDays
	o.CtxMinFP = max(3, o.MinVerdicts-2)
}

// Applied 统计自学习结果在检测中自动生效的次数（本次启动以来）。
type Applied struct {
	Rule      int64     `json:"rule"`      // 按规则整体校准下调的命中
	Target    int64     `json:"target"`    // 按「规则 + 目标」精细校准下调的命中
	Escalated int64     `json:"escalated"` // 已确认攻击来源复现、升级的命中
	Feed      int64     `json:"feed"`      // 按情报源准确率下调的情报命中
	Since     time.Time `json:"since"`
}

type appliedCounters struct {
	rule, target, escalated, feed atomic.Int64
	since                         time.Time
}

// Verdict 是分析员对一个安全事件的结论。
type Verdict string

const (
	VerdictNone Verdict = ""   // 撤回 / 忽略：不作为样本
	VerdictTP   Verdict = "tp" // 已处置：确认是真实攻击
	VerdictFP   Verdict = "fp" // 误报
)

// Case 是一次研判样本（一个安全事件的结论）。
type Case struct {
	Incident uint64         `json:"incident"`
	Source   string         `json:"source"`
	Rules    map[string]int `json:"rules"`             // 规则 → 命中次数
	Targets  []string       `json:"targets,omitempty"` // 事件的主要攻击目标
	Verdict  Verdict        `json:"verdict"`
	User     string         `json:"user"`
	Note     string         `json:"note,omitempty"` // 分析员的处置说明，作为相似案例提供给外部模型
	Time     time.Time      `json:"time"`
	Feeds    []string       `json:"feeds,omitempty"` // 事件命中的威胁情报源，用于统计情报源的准确率
}

// FeedStat 是一个威胁情报源的研判统计：命中过该情报源的事件被分析员确认 / 判为误报的次数。
type FeedStat struct {
	Feed       string  `json:"feed"`
	TP         int     `json:"tp"`
	FP         int     `json:"fp"`
	Precision  float64 `json:"precision"`  // 样本不足时为 -1
	Calibrated bool    `json:"calibrated"` // 准确率持续偏低，命中自动下调一级
	Pinned     bool    `json:"pinned"`
}

// focused 判断样本是否只涉及少数规则：误报结论只有在规则很少时才能归因到规则本身；
// 涉及大量规则的误报通常是对来源的判断（授权扫描、内部渗透测试），按来源学习。
func (c *Case) focused() bool { return len(c.Rules) <= 2 }

// RuleStat 是一条规则的研判统计。
type RuleStat struct {
	Rule       string  `json:"rule"`
	TP         int     `json:"tp"`
	FP         int     `json:"fp"`
	Precision  float64 `json:"precision"`  // 准确率；样本不足时为 -1
	Calibrated bool    `json:"calibrated"` // 已自动下调一级
	Pinned     bool    `json:"pinned"`     // 已锁定：不参与自动校准
}

// ContextStat 是一条规则在一个目标上的研判统计（精细校准与历史研判参考）。
//
// 同一条规则往往只在个别接口上误报（如搜索接口的参数天然带引号），按规则整体下调会连带削弱
// 该规则在其他目标上的告警；按「规则 + 目标」校准只影响反复误报的那个接口。
type ContextStat struct {
	Rule      string   `json:"rule"`
	Target    string   `json:"target"`
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	Incidents []uint64 `json:"incidents,omitempty"`
}

// snapshot 是热路径使用的校准快照（无锁读取）。
type snapshot struct {
	rules   map[string]RuleStat
	ctx     map[[2]string]ContextStat // 规则 + 归一化目标
	sources map[string]confirmed      // 最近一次结论为「确认攻击」的来源
	days    int                       // 确认攻击源的有效天数
	// cleared 是最近一次人工结论为「误报」的来源及其时间：此后的自动确认不再生效（以人的结论为准）
	cleared  map[string]time.Time
	escalate bool
	feeds    map[string]FeedStat // 准确率持续偏低、已下调的威胁情报源
}

// confirmed 是来源最近一次被确认为攻击的事件。
type confirmed struct {
	incident uint64
	time     time.Time
}

// Suggestion 是一条需要人工确认的误报抑制建议。
type Suggestion struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"` // context：规则 + 目标；source：来源（疑似授权扫描 / 内部测试）
	RuleID    string   `json:"rule_id,omitempty"`
	Target    string   `json:"target,omitempty"`
	IP        string   `json:"ip,omitempty"`
	FP        int      `json:"fp"`
	Incidents []uint64 `json:"incidents"`
	Reason    string   `json:"reason"`
	Origin    string   `json:"origin,omitempty"` // ai：来自可信模型的判断，尚无分析员结论
}

// Change 是一条进化日志：自动校准、撤销、锁定、采纳建议等。
type Change struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // calibrate / restore / calibrate_ctx / restore_ctx / pin / unpin / apply / dismiss
	Rule   string    `json:"rule,omitempty"`
	IP     string    `json:"ip,omitempty"` // 涉及的来源（撤销自动确认等）
	Detail string    `json:"detail"`
	User   string    `json:"user"`
}

const (
	maxCases   = 20000
	maxChanges = 500
)

// Learner 是自学习状态。热路径（Calibrate）无锁读取校准快照。
type Learner struct {
	opt Options

	mu         sync.Mutex
	cases      map[uint64]*Case
	pinned     map[string]bool
	handled    map[string]string // 已采纳 / 已忽略的建议 ID → 处理结果
	changes    []Change
	stats      []RuleStat
	feedStats  []FeedStat    // 威胁情报源的研判统计
	ctxStats   []ContextStat // 已精细校准的「规则 + 目标」
	sugs       []Suggestion
	ai         map[uint64]*AIRecord // 外部模型的研判结论（见 aitrust.go），只用于评估模型，不作为样本
	aiStats    []AIStat
	users      map[string]*userBase // 平台账号的行为基线（见 sentinel.go）
	anomalies  []Anomaly
	comp       map[string]string      // 合规测评项 → 上次结果（见 compliance.go）
	nets       map[string]*LearnedNet // 从防火墙日志自动学习的内网网段（见 netlearn.go）
	netPending map[string]*netObs
	auto       map[string]*AutoSource // 自动确认的攻击源（见 attacklearn.go）
	outcomes   map[string]*Outcome    // 来源的客观结论（见 loop.go）
	loop       LoopStats              // 自我纠错与自动处置的统计
	autoSnap   atomic.Pointer[map[string]AutoSource]
	atk        attackState
	prof       profileState // 参数的正常取值与站点产品（见 profile.go、site.go）
	compHist   []CompPoint
	dirty      bool

	sent    sentinelState
	calib   atomic.Pointer[snapshot]
	applied appliedCounters
	policy  *Policy // 界面设置的策略（为空表示使用配置文件）
	// saveMu 串行化落盘：后台定时保存与界面操作（处置、锁定、采纳建议）可能同时触发，
	// 不串行时两次写入共用同一个临时文件，较旧的状态可能最后改名生效、覆盖较新的状态
	saveMu sync.Mutex

	// OnChange 在产生进化日志时调用（写入审计链），调用时不持锁。
	OnChange func(Change)
	// AttackerLike 判断来源的行为本身像攻击者（模型判断经核实误判较多时，只自动确认这样的来源）。为空时视为否。
	AttackerLike func(ip string) bool
	// OnRetract 在撤销自动确认、停用观察规则后调用（异步），由状态库回溯修正仍在处置的事件。
	OnRetract func(rule, ip, why string)
	// OnRestore 在纠错本身被纠正后调用（异步）：管理员重新启用观察规则、被撤销自动确认的来源出现了攻击的客观证据，
	// 由状态库恢复撤销的告警。
	OnRestore func(rule, ip, why string)

	// PriorAttacks 返回来源此前的攻击次数（业务接口学习只用此前没有攻击记录的访客），为空时视为 0。
	PriorAttacks func(ip string) int64
	// RegularUser 判断来源是否为站点的常客（大量正常访问、攻击命中占比很低）。模型只看到告警、看不到这些正常访问，
	// 常客被模型判为攻击多半是业务请求触发了误报：不凭模型的判断自动确认，已确认的撤销。为空时不做判断。
	RegularUser func(ip string) bool
}

// state 是持久化的学习状态。
type state struct {
	Cases     []*Case              `json:"cases"`
	Pinned    []string             `json:"pinned,omitempty"`
	Handled   map[string]string    `json:"handled,omitempty"`
	Changes   []Change             `json:"changes,omitempty"`
	Users     map[string]*userBase `json:"users,omitempty"`
	Anomalies []Anomaly            `json:"anomalies,omitempty"`
	Comp      map[string]string    `json:"compliance,omitempty"`
	CompHist  []CompPoint          `json:"compliance_history,omitempty"`
	AI        map[uint64]*AIRecord `json:"ai,omitempty"`
	Policy    *Policy              `json:"policy,omitempty"`
	Intranet  []LearnedNet         `json:"intranet,omitempty"`
	Attack    *attackPersist       `json:"attack,omitempty"`
	Profile   *profilePersist      `json:"profile,omitempty"`
	Outcomes  []Outcome            `json:"outcomes,omitempty"`
	Loop      *LoopStats           `json:"loop,omitempty"`
}

// Load 读取学习状态（文件不存在时从零开始）。
func Load(opt Options) (*Learner, error) {
	if opt.MinVerdicts <= 0 {
		opt.MinVerdicts = 5
	}
	if opt.MaxPrecision <= 0 || opt.MaxPrecision >= 1 {
		opt.MaxPrecision = 0.2
	}
	if opt.EscalateDays <= 0 {
		opt.EscalateDays = 30
	}
	if opt.WindowDays == 0 {
		opt.WindowDays = 180
	}
	opt.CtxMinFP = max(3, opt.MinVerdicts-2)
	l := &Learner{opt: opt, cases: map[uint64]*Case{}, pinned: map[string]bool{}, handled: map[string]string{},
		users: map[string]*userBase{}, comp: map[string]string{}, ai: map[uint64]*AIRecord{}, nets: map[string]*LearnedNet{}, netPending: map[string]*netObs{}, auto: map[string]*AutoSource{}, outcomes: map[string]*Outcome{},
		atk: attackState{campaigns: map[string]*Campaign{}, cand: map[string]*candidate{}, rules: map[string]*LearnedRule{}}}
	l.applied.since = time.Now()
	if opt.Path != "" {
		data, err := os.ReadFile(opt.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			var st state
			if err := json.Unmarshal(data, &st); err != nil {
				return nil, fmt.Errorf("解析 %s 失败: %w", opt.Path, err)
			}
			for _, c := range st.Cases {
				if c != nil && c.Incident != 0 && (c.Verdict == VerdictTP || c.Verdict == VerdictFP) {
					l.cases[c.Incident] = c
				}
			}
			for _, r := range st.Pinned {
				l.pinned[r] = true
			}
			if st.Handled != nil {
				l.handled = st.Handled
			}
			l.changes, l.anomalies, l.compHist = st.Changes, st.Anomalies, st.CompHist
			if st.Users != nil {
				l.users = st.Users
			}
			if st.Comp != nil {
				l.comp = st.Comp
			}
			for id, r := range st.AI {
				if id != 0 && r != nil {
					l.ai[id] = r
				}
			}
			for i := range st.Intranet {
				if n := st.Intranet[i]; n.Prefix != "" {
					l.nets[n.Prefix] = &n
				}
			}
			if st.Attack != nil {
				l.loadAttackLocked(*st.Attack)
			}
			l.loadProfileLocked(st.Profile)
			for i := range st.Outcomes {
				if o := st.Outcomes[i]; o.IP != "" {
					l.outcomes[o.IP] = &o
				}
			}
			if st.Loop != nil {
				l.loop = *st.Loop
			}
			if p := st.Policy; p != nil && p.check() == nil { // 界面设置的策略优先于配置文件
				l.policy = p
				l.opt.apply(*p)
			}
		}
	}
	n := len(l.changes)
	l.recomputeLocked(time.Now(), "")
	l.changes, l.dirty = l.changes[:n], false // 启动时重建快照，不重复记录进化日志
	if l.migrateLoopLocked() {
		// 从进化日志补齐的客观结论可能让模型的自动确认收紧：这次变化写入进化日志
		l.refreshAIStatsLocked(time.Now())
	}
	l.dropDeviceNetsLocked() // 旧版本依据防火墙自身 local 域学到的内网网段：撤销
	return l, nil
}

// Save 在状态有变化时写入文件（原子替换）。
func (l *Learner) Save() error {
	if l == nil || l.opt.Path == "" {
		return nil
	}
	l.saveMu.Lock()
	defer l.saveMu.Unlock()
	l.mu.Lock()
	if !l.dirty {
		l.mu.Unlock()
		return nil
	}
	st := state{Handled: l.handled, Changes: l.changes, Users: l.users, Anomalies: l.anomalies, Comp: l.comp, CompHist: l.compHist, AI: l.ai, Policy: l.policy}
	st.Intranet = l.learnedNetsLocked()
	ap := l.attackPersistLocked()
	st.Attack = &ap
	st.Profile = l.profilePersistLocked()
	st.Outcomes = l.outcomeListLocked()
	loop := l.loop
	st.Loop = &loop
	for _, c := range l.cases {
		st.Cases = append(st.Cases, c)
	}
	sort.Slice(st.Cases, func(i, j int) bool { return st.Cases[i].Incident < st.Cases[j].Incident })
	for r := range l.pinned {
		st.Pinned = append(st.Pinned, r)
	}
	sort.Strings(st.Pinned)
	data, err := json.Marshal(st)
	l.dirty = false
	l.mu.Unlock()
	if err == nil {
		err = writeFile(l.opt.Path, data)
	}
	if err != nil {
		l.mu.Lock()
		l.dirty = true // 写入失败：保留未保存标记，由下一次定时保存重试
		l.mu.Unlock()
	}
	return err
}

// writeFile 先写临时文件再原子替换。
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Feedback 记录分析员对事件的结论（同一事件再次处置时替换之前的结论；VerdictNone 表示撤回）。
// 批量处置时一次传入全部结论：规则统计只重算一次、状态只落盘一次（每次落盘都要写出全部样本）。
func (l *Learner) Feedback(list ...Case) {
	if l == nil {
		return
	}
	now := time.Now()
	l.mu.Lock()
	changed, user := false, ""
	for _, c := range list {
		if l.feedbackLocked(c, now) {
			changed, user = true, c.User
		}
	}
	if !changed {
		l.mu.Unlock()
		return
	}
	l.dirty = true
	changes := l.recomputeLocked(now, user)
	l.mu.Unlock()
	l.emit(changes)
	if err := l.Save(); err != nil {
		log.Printf("[learn] 保存学习状态失败: %v", err)
	}
}

// feedbackLocked 记录一条结论，返回样本是否发生变化（调用方持锁）。
func (l *Learner) feedbackLocked(c Case, now time.Time) bool {
	if c.Incident == 0 {
		return false
	}
	if c.Time.IsZero() {
		c.Time = now
	}
	old := l.cases[c.Incident]
	switch {
	case c.Verdict == VerdictNone:
		if old == nil {
			return false
		}
		delete(l.cases, c.Incident)
	case old != nil && old.Verdict == c.Verdict:
		return false
	default:
		for k := range c.Rules {
			if len(k) > 128 {
				delete(c.Rules, k)
			}
		}
		if len(c.Targets) > 5 {
			c.Targets = c.Targets[:5]
		}
		c.Note = clipNote(c.Note)
		l.cases[c.Incident] = &c
		if len(l.cases) > maxCases {
			l.evictLocked()
		}
	}
	return true
}

// evictLocked 淘汰最早的样本，使数量回到上限的 90%。
func (l *Learner) evictLocked() {
	list := make([]*Case, 0, len(l.cases))
	for _, c := range l.cases {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Time.Before(list[j].Time) })
	for _, c := range list[:len(list)-maxCases*9/10] {
		delete(l.cases, c.Incident)
	}
}

func (l *Learner) emit(changes []Change) {
	if l.OnChange == nil {
		return
	}
	for _, c := range changes {
		l.OnChange(c)
	}
}

func (l *Learner) logLocked(c Change) {
	l.changes = append(l.changes, c)
	if len(l.changes) > maxChanges {
		l.changes = append([]Change(nil), l.changes[len(l.changes)-maxChanges:]...)
	}
	l.dirty = true
}

// suggestionID 返回建议的稳定 ID（条件相同则 ID 相同，采纳 / 忽略后不再重复提示）。
func suggestionID(kind, rule, target, ip string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + rule + "\x00" + target + "\x00" + ip))
	return hex.EncodeToString(h[:6])
}

// targetKey 把事件目标归一为可用于抑制规则的文本：去掉查询参数（参数值各不相同）。
func targetKey(t string) string {
	if i := strings.IndexAny(t, "?#"); i >= 0 {
		t = t[:i]
	}
	t = strings.TrimSpace(t)
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

// targets 返回样本中归一化后的不同目标：同一接口不同参数的多个目标只算一次，避免一个事件被重复计数。
func (c *Case) targets() []string {
	var out []string
	for _, t := range c.Targets {
		k := targetKey(t)
		if k != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

type ctxStat struct {
	fp, tp    int
	incidents []uint64
}

// recomputeLocked 根据全部样本重新计算规则统计、校准快照与建议，返回新产生的进化日志。
func (l *Learner) recomputeLocked(now time.Time, user string) []Change {
	tp, fp := map[string]int{}, map[string]int{}
	ctx := map[[2]string]*ctxStat{}
	src := map[string]*ctxStat{}
	ftp, ffp := map[string]int{}, map[string]int{}
	for _, c := range l.cases {
		if l.expiredLocked(c, now) {
			continue
		}
		// 情报源：确认攻击说明情报准确；误报说明情报把正常来源（授权扫描、合作方、公共服务）标记成了恶意，
		// 不要求事件只涉及少数规则——判的就是这个来源
		for _, f := range c.Feeds {
			switch c.Verdict {
			case VerdictTP:
				ftp[f]++
			case VerdictFP:
				ffp[f]++
			}
		}
		s := src[c.Source]
		if s == nil {
			s = &ctxStat{}
			src[c.Source] = s
		}
		switch {
		case c.Verdict == VerdictTP:
			s.tp++
			for r := range c.Rules {
				tp[r]++
				for _, t := range c.targets() {
					k := [2]string{r, t}
					if ctx[k] == nil {
						ctx[k] = &ctxStat{}
					}
					ctx[k].tp++
				}
			}
		case c.Verdict == VerdictFP && c.focused():
			for r := range c.Rules {
				fp[r]++
				for _, t := range c.targets() {
					k := [2]string{r, t}
					cs := ctx[k]
					if cs == nil {
						cs = &ctxStat{}
						ctx[k] = cs
					}
					cs.fp++
					if len(cs.incidents) < 10 {
						cs.incidents = append(cs.incidents, c.Incident)
					}
				}
			}
		case c.Verdict == VerdictFP:
			s.fp++
			if len(s.incidents) < 10 {
				s.incidents = append(s.incidents, c.Incident)
			}
		}
	}

	// 规则统计与自动校准
	rules := map[string]bool{}
	for r := range tp {
		rules[r] = true
	}
	for r := range fp {
		rules[r] = true
	}
	old := l.calib.Load()
	if old == nil {
		old = &snapshot{}
	}
	calib := map[string]RuleStat{}
	stats := make([]RuleStat, 0, len(rules))
	var changes []Change
	for r := range rules {
		st := RuleStat{Rule: r, TP: tp[r], FP: fp[r], Precision: -1, Pinned: l.pinned[r]}
		n := st.TP + st.FP
		if n > 0 {
			st.Precision = float64(st.TP) / float64(n)
		}
		st.Calibrated = l.opt.Calibrate && !st.Pinned && n >= l.opt.MinVerdicts && st.FP >= l.opt.MinVerdicts-1 && st.Precision <= l.opt.MaxPrecision
		if st.Calibrated {
			calib[r] = st
		}
		was := old.rules[r].Calibrated
		switch {
		case st.Calibrated && !was:
			changes = append(changes, Change{Time: now, Kind: "calibrate", Rule: r, User: "自学习",
				Detail: fmt.Sprintf("规则 %s 研判 %d 次中 %d 次为误报（准确率 %.0f%%），等级自动下调一级（最多低于攻击分类底线一级，利用成功仍为严重）", r, n, st.FP, st.Precision*100)})
		case !st.Calibrated && was:
			why := "准确率已回升"
			if st.Pinned {
				why = "规则已被锁定"
			}
			if user == "" {
				user = "自学习"
			}
			changes = append(changes, Change{Time: now, Kind: "restore", Rule: r, User: user,
				Detail: fmt.Sprintf("规则 %s 恢复原等级（%s：研判 %d 次，误报 %d 次）", r, why, n, st.FP)})
		}
		stats = append(stats, st)
	}
	for _, r := range sortedKeys(old.rules) { // 样本被撤回后规则不再出现在统计中
		if !rules[r] {
			changes = append(changes, Change{Time: now, Kind: "restore", Rule: r, User: "自学习", Detail: "规则 " + r + " 恢复原等级（研判样本已撤回或超过学习窗口）"})
		}
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].FP != stats[j].FP {
			return stats[i].FP > stats[j].FP
		}
		return stats[i].Rule < stats[j].Rule
	})
	l.stats = stats
	ctxCal, ctxChanges := l.calibrateContextsLocked(ctx, old, now, user)
	changes = append(changes, ctxChanges...)
	feedCal, feedChanges := l.calibrateFeedsLocked(ftp, ffp, old, now, user)
	changes = append(changes, feedChanges...)
	l.calib.Store(&snapshot{rules: calib, ctx: ctxCal, sources: l.confirmedSourcesLocked(), cleared: l.clearedSourcesLocked(),
		days: l.opt.EscalateDays, escalate: l.opt.Escalate, feeds: feedCal})
	for _, c := range changes {
		l.logLocked(c)
	}

	changes = append(changes, l.refreshAIStatsLocked(now)...) // 客观结论变化后，模型的评估与自动确认的收紧状态随之更新

	// 建议：同一规则在同一目标上多次被研判为误报、且从未确认为攻击；同一来源多次被整体研判为误报
	var sugs []Suggestion
	for k, cs := range ctx {
		if cs.fp < 2 || cs.tp > 0 || k[1] == "" {
			continue
		}
		s := Suggestion{Kind: "context", RuleID: k[0], Target: k[1], FP: cs.fp, Incidents: cs.incidents,
			Reason: fmt.Sprintf("自学习建议：规则 %s 在 %s 上 %d 次被研判为误报，从未确认为攻击", k[0], k[1], cs.fp)}
		s.ID = suggestionID(s.Kind, s.RuleID, s.Target, "")
		if l.handled[s.ID] == "" {
			sugs = append(sugs, s)
		}
	}
	for ip, s := range src {
		if s.fp < 2 || s.tp > 0 || ip == "" {
			continue
		}
		sg := Suggestion{Kind: "source", IP: ip, FP: s.fp, Incidents: s.incidents,
			Reason: fmt.Sprintf("自学习建议：来源 %s 的事件 %d 次被整体研判为误报（疑似授权扫描 / 内部测试），从未确认为攻击", ip, s.fp)}
		sg.ID = suggestionID(sg.Kind, "", "", ip)
		if l.handled[sg.ID] == "" {
			sugs = append(sugs, sg)
		}
	}
	sugs = append(sugs, l.aiSuggestionsLocked(ctx, sugs, now)...)
	sort.Slice(sugs, func(i, j int) bool {
		if sugs[i].FP != sugs[j].FP {
			return sugs[i].FP > sugs[j].FP
		}
		return sugs[i].ID < sugs[j].ID
	})
	if len(sugs) > 100 {
		sugs = sugs[:100]
	}
	l.sugs = sugs
	return changes
}

// lowFeeds 判断命中的情报源是否全部是准确率持续偏低的情报源（有一个准确的情报源同时标记就不下调），
// 返回其中误报最多的一个用于说明。
func lowFeeds(cal map[string]FeedStat, feeds []string) (FeedStat, bool) {
	var worst FeedStat
	for _, f := range feeds {
		st, ok := cal[f]
		if !ok {
			return FeedStat{}, false
		}
		if st.FP > worst.FP {
			worst = st
		}
	}
	return worst, len(feeds) > 0
}

// calibrateFeedsLocked 计算威胁情报源的准确率：样本不少于 MinVerdicts、准确率不高于 MaxPrecision 的情报源，
// 之后只由它产生的命中（其他情报源没有同时标记）下调一级。情报“不在多而在准”：长期误报的情报源
// 不再把正常来源顶成高危，但仍然生成告警；准确率回升、样本过期、锁定后自动恢复。
func (l *Learner) calibrateFeedsLocked(tp, fp map[string]int, old *snapshot, now time.Time, user string) (map[string]FeedStat, []Change) {
	cal := map[string]FeedStat{}
	var stats []FeedStat
	var changes []Change
	seen := map[string]bool{}
	for _, m := range []map[string]int{tp, fp} {
		for f := range m {
			if seen[f] {
				continue
			}
			seen[f] = true
			st := FeedStat{Feed: f, TP: tp[f], FP: fp[f], Precision: -1, Pinned: l.pinned["feed:"+f]}
			n := st.TP + st.FP
			if n > 0 {
				st.Precision = float64(st.TP) / float64(n)
			}
			st.Calibrated = l.opt.Calibrate && !st.Pinned && n >= l.opt.MinVerdicts && st.FP >= l.opt.MinVerdicts-1 && st.Precision <= l.opt.MaxPrecision
			if st.Calibrated {
				cal[f] = st
			}
			switch was := old.feeds[f].Calibrated; {
			case st.Calibrated && !was:
				changes = append(changes, Change{Time: now, Kind: "calibrate_feed", Rule: "feed:" + f, User: "自学习",
					Detail: fmt.Sprintf("情报源 %s 命中的事件研判 %d 次中 %d 次为误报（准确率 %.0f%%），只由它产生的情报命中等级自动下调一级", f, n, st.FP, st.Precision*100)})
			case !st.Calibrated && was:
				why := "准确率已回升"
				if st.Pinned {
					why = "情报源已被锁定"
				}
				if user == "" {
					user = "自学习"
				}
				changes = append(changes, Change{Time: now, Kind: "restore_feed", Rule: "feed:" + f, User: user,
					Detail: fmt.Sprintf("情报源 %s 恢复原等级（%s：研判 %d 次，误报 %d 次）", f, why, n, st.FP)})
			}
			stats = append(stats, st)
		}
	}
	for _, f := range sortedKeys(old.feeds) {
		if !seen[f] {
			changes = append(changes, Change{Time: now, Kind: "restore_feed", Rule: "feed:" + f, User: "自学习", Detail: "情报源 " + f + " 恢复原等级（研判样本已撤回或超过学习窗口）"})
		}
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].FP != stats[j].FP {
			return stats[i].FP > stats[j].FP
		}
		return stats[i].Feed < stats[j].Feed
	})
	l.feedStats = stats
	return cal, changes
}

// calibrateContextsLocked 计算「规则 + 目标」精细校准：同一规则在同一目标上被研判为误报不少于 CtxMinFP 次、
// 且在该目标上从未确认为攻击时，该规则在这个目标上的命中自动下调一级。与规则整体校准相互独立，
// 一次命中最多下调一级；锁定规则同时停止两种校准。返回新的校准表与进化日志。
func (l *Learner) calibrateContextsLocked(ctx map[[2]string]*ctxStat, old *snapshot, now time.Time, user string) (map[[2]string]ContextStat, []Change) {
	cal := map[[2]string]ContextStat{}
	if l.opt.Calibrate {
		for k, cs := range ctx {
			if k[1] != "" && cs.tp == 0 && cs.fp >= l.opt.CtxMinFP && !l.pinned[k[0]] {
				cal[k] = ContextStat{Rule: k[0], Target: k[1], TP: cs.tp, FP: cs.fp, Incidents: cs.incidents}
			}
		}
	}
	var changes []Change
	for _, k := range sortedCtxKeys(cal) {
		if _, was := old.ctx[k]; !was {
			changes = append(changes, Change{Time: now, Kind: "calibrate_ctx", Rule: k[0], User: "自学习",
				Detail: fmt.Sprintf("规则 %s 在 %s 上 %d 次被研判为误报、从未确认为攻击，该规则在此目标上的命中等级自动下调一级（最多低于攻击分类底线一级，其他目标不受影响）", k[0], k[1], cal[k].FP)})
		}
	}
	for _, k := range sortedCtxKeys(old.ctx) {
		if _, still := cal[k]; still {
			continue
		}
		why, who := "研判样本已撤回或超过学习窗口", "自学习"
		switch cs := ctx[k]; {
		case l.pinned[k[0]]:
			why = "规则已被锁定"
		case !l.opt.Calibrate:
			why = "自动校准已关闭"
		case cs != nil && cs.tp > 0:
			why = "该目标上出现确认的攻击"
		}
		if user != "" {
			who = user
		}
		changes = append(changes, Change{Time: now, Kind: "restore_ctx", Rule: k[0], User: who,
			Detail: fmt.Sprintf("规则 %s 在 %s 上恢复原等级（%s）", k[0], k[1], why)})
	}
	list := make([]ContextStat, 0, len(cal))
	for _, k := range sortedCtxKeys(cal) {
		list = append(list, cal[k])
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].FP > list[j].FP })
	l.ctxStats = list
	return cal, changes
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCtxKeys[V any](m map[[2]string]V) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// Calibrate 对准确率持续偏低的规则、以及在事件目标上反复误报的「规则 + 目标」下调一级
// （只下调攻击命中，一次最多一级，不低于低危；分类底线由统一的等级裁决保证）。
// ev 用于取攻击目标，可为 nil（只按规则整体校准）。返回的切片为副本，不修改调用方的数据。
func (l *Learner) Calibrate(ev *model.Event, hits []model.Hit) []model.Hit {
	if l == nil {
		return hits
	}
	m := l.calib.Load()
	autoP := l.autoSnap.Load()
	hasAuto := autoP != nil && len(*autoP) > 0
	if m == nil || len(m.rules)+len(m.ctx)+len(m.sources)+len(m.feeds) == 0 && !hasAuto {
		return hits
	}
	// 已确认的攻击来源（分析员确认或自动确认）在有效期内复现（按事件时间判断，离线回放历史日志时同样准确）
	srcReason, srcOK := "", false
	if ev != nil && (len(m.sources) > 0 || hasAuto) {
		at := ev.Time
		if at.IsZero() {
			at = time.Now()
		}
		srcReason, srcOK = l.confirmedSource(ev.SrcIP, at)
	}
	var out []model.Hit
	target, haveTarget := "", false
	for i := range hits {
		if hits[i].TagOnly {
			continue
		}
		note, delta := "", int8(0)
		if hits[i].Severity > model.SevLow {
			if st, ok := m.rules[hits[i].RuleID]; ok {
				note, delta = "；自学习校准：该规则研判 "+strconv.Itoa(st.TP+st.FP)+" 次中 "+strconv.Itoa(st.FP)+" 次为误报，等级下调一级", -1
				l.applied.rule.Add(1)
			} else if len(m.ctx) > 0 && ev != nil {
				if !haveTarget { // 目标只在需要时计算一次（热路径）
					target, haveTarget = targetKey(ev.Target()), true
				}
				if cs, ok := m.ctx[[2]string{hits[i].RuleID, target}]; ok {
					note, delta = "；自学习校准：该规则在此目标上 "+strconv.Itoa(cs.FP)+" 次被研判为误报、从未确认为攻击，等级下调一级", -1
					l.applied.target.Add(1)
				}
			}
			if delta == 0 && len(m.feeds) > 0 {
				if fs, ok := lowFeeds(m.feeds, hits[i].Feeds); ok {
					note, delta = fmt.Sprintf("；自学习校准：情报源 %s 命中的事件研判 %d 次中 %d 次为误报，等级下调一级", fs.Feed, fs.TP+fs.FP, fs.FP), -1
					l.applied.feed.Add(1)
				}
			}
		}
		// 确认攻击源复现：只升级低危 / 中危的攻击命中，最多到高危；严重级只能由成功利用等证据产生
		if delta == 0 && srcOK && hits[i].Severity >= model.SevLow && hits[i].Severity < model.SevHigh {
			note, delta = "；自学习："+srcReason+"，等级上调一级", 1
			l.applied.escalated.Add(1)
		}
		if delta == 0 {
			continue
		}
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		out[i].Severity += model.Severity(delta)
		out[i].Learned = delta
		out[i].Evidence += note
	}
	if out == nil {
		return hits
	}
	return out
}

// Pin 锁定 / 解锁规则：锁定的规则不参与自动校准（已下调的立即恢复）。
func (l *Learner) Pin(rule, user string, pin bool) {
	if l == nil || rule == "" {
		return
	}
	now := time.Now()
	l.mu.Lock()
	if l.pinned[rule] == pin {
		l.mu.Unlock()
		return
	}
	kind, verb := "pin", "锁定规则 "+rule+"：不参与自动校准"
	if pin {
		l.pinned[rule] = true
	} else {
		delete(l.pinned, rule)
		kind, verb = "unpin", "解锁规则 "+rule+"：恢复自动校准"
	}
	c := Change{Time: now, Kind: kind, Rule: rule, Detail: verb, User: user}
	l.logLocked(c)
	changes := append([]Change{c}, l.recomputeLocked(now, user)...)
	l.mu.Unlock()
	l.emit(changes)
	l.Save()
}

// ErrNoSuggestion 表示建议不存在或已处理。
var ErrNoSuggestion = errors.New("建议不存在或已处理")

// Suggestion 返回指定的建议。
func (l *Learner) Suggestion(id string) (Suggestion, bool) {
	if l == nil {
		return Suggestion{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.sugs {
		if s.ID == id {
			return s, true
		}
	}
	return Suggestion{}, false
}

// Resolve 记录建议已被采纳（apply）或忽略（dismiss），之后不再提示。
func (l *Learner) Resolve(id, user, result string) error {
	if l == nil {
		return ErrNoSuggestion
	}
	now := time.Now()
	l.mu.Lock()
	var found *Suggestion
	for i := range l.sugs {
		if l.sugs[i].ID == id {
			found = &l.sugs[i]
		}
	}
	if found == nil {
		l.mu.Unlock()
		return ErrNoSuggestion
	}
	l.handled[id] = result
	verb := "采纳建议"
	if result == "dismiss" {
		verb = "忽略建议"
	}
	c := Change{Time: now, Kind: result, Rule: found.RuleID, User: user, Detail: verb + "：" + found.Reason}
	l.logLocked(c)
	l.recomputeLocked(now, user)
	l.mu.Unlock()
	l.emit([]Change{c})
	return l.Save()
}

// Report 是自学习状态概览。
type Report struct {
	Cases       int           `json:"cases"` // 研判样本数
	TP          int           `json:"tp"`
	FP          int           `json:"fp"`
	Rules       []RuleStat    `json:"rules"`
	Calibrated  int           `json:"calibrated"`
	Contexts    []ContextStat `json:"contexts"` // 已精细校准的「规则 + 目标」（最多 100 条）
	CtxTotal    int           `json:"ctx_total"`
	AI          []AIStat      `json:"ai"` // 外部模型研判与分析员结论的一致率
	Suggestions []Suggestion  `json:"suggestions"`
	Changes     []Change      `json:"changes"` // 最近的进化日志（新的在前）
	Anomalies   []Anomaly     `json:"anomalies"`
	Compliance  []CompPoint   `json:"compliance"` // 合规符合率趋势
	Options     Options       `json:"options"`
	Policy      Policy        `json:"policy"`    // 当前生效的策略
	PolicyUI    bool          `json:"policy_ui"` // 策略来自界面设置（否则来自配置文件）
	Applied     Applied       `json:"applied"`   // 学习结果在检测中自动生效的次数
	Confirmed   int           `json:"confirmed"` // 最近一次结论为确认攻击的来源数（复现时升级）
	Expired     int           `json:"expired"`   // 超过学习窗口、不再参与校准的样本数
	Trend       []WeekStat    `json:"trend"`     // 近 8 周的人工结论，误报占比下降说明检测在变准
	Intranet    []LearnedNet  `json:"intranet"`  // 从防火墙日志自动学习的内网网段
	Attack      AttackReport  `json:"attack"`    // 从日志与 AI 研判中自动学习的攻击行为
	Profile     ProfileReport `json:"profile"`   // 从正常流量学习的参数取值与站点产品
	Feeds       []FeedStat    `json:"feeds"`     // 威胁情报源的研判统计与自动校准
	Loop        LoopReport    `json:"loop"`      // 自我纠错与自动处置
}

// Report 返回自学习状态概览。
func (l *Learner) Report() Report {
	r := Report{Rules: []RuleStat{}, Contexts: []ContextStat{}, AI: []AIStat{}, Suggestions: []Suggestion{}, Changes: []Change{}, Anomalies: []Anomaly{}, Compliance: []CompPoint{}}
	if l == nil {
		return r
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Options = l.opt
	r.Options.Path = ""
	r.Policy, r.PolicyUI = l.policyLocked(), l.policy != nil
	r.Applied = l.appliedStats()
	if m := l.calib.Load(); m != nil { // 只统计仍在有效期内、复现时会被升级的来源
		cut := time.Now().Add(-time.Duration(m.days) * 24 * time.Hour)
		for _, c := range m.sources {
			if c.time.After(cut) {
				r.Confirmed++
			}
		}
	}
	r.Intranet = l.learnedNetsLocked()
	r.Attack = l.attackReportLocked()
	r.Profile = l.profileReportLocked()
	r.Feeds = append([]FeedStat{}, l.feedStats...)
	r.Loop = l.loopReportLocked()
	r.Cases = len(l.cases)
	now := time.Now()
	r.Trend = weekTrend(l.cases, now)
	for _, c := range l.cases {
		if l.expiredLocked(c, now) {
			r.Expired++
		}
		if c.Verdict == VerdictTP {
			r.TP++
		} else {
			r.FP++
		}
	}
	r.Rules = append(r.Rules, l.stats...)
	for _, s := range l.stats {
		if s.Calibrated {
			r.Calibrated++
		}
	}
	r.CtxTotal = len(l.ctxStats)
	r.Contexts = append(r.Contexts, l.ctxStats[:min(len(l.ctxStats), 100)]...)
	r.AI = append(r.AI, l.aiStats...)
	r.Suggestions = append(r.Suggestions, l.sugs...)
	for i := len(l.changes) - 1; i >= 0 && len(r.Changes) < 100; i-- {
		r.Changes = append(r.Changes, l.changes[i])
	}
	for i := len(l.anomalies) - 1; i >= 0 && len(r.Anomalies) < 100; i-- {
		r.Anomalies = append(r.Anomalies, l.anomalies[i])
	}
	r.Compliance = append(r.Compliance, l.compHist...)
	return r
}
