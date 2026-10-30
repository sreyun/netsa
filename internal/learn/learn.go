// Package learn 是平台的自学习模块：从分析员的研判结论与平台自身的运行数据中持续学习。
//
// 设计边界（自学习不能变成新的风险来源）：
//   - 只从人的结论学习：分析员把事件处置为「已处置」（确认攻击）或「误报」时才计入样本，AI 与系统自动生成的状态不参与；
//   - 自动调整只降不升、每次最多一级、不越过攻击分类的等级底线，且可随时撤销（锁定规则）；
//   - 会隐藏告警的动作（误报抑制）只生成建议，必须由人确认采纳；
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
	Time     time.Time      `json:"time"`
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
}

// Change 是一条进化日志：自动校准、撤销、锁定、采纳建议等。
type Change struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // calibrate / restore / pin / unpin / apply / dismiss
	Rule   string    `json:"rule,omitempty"`
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

	mu        sync.Mutex
	cases     map[uint64]*Case
	pinned    map[string]bool
	handled   map[string]string // 已采纳 / 已忽略的建议 ID → 处理结果
	changes   []Change
	stats     []RuleStat
	sugs      []Suggestion
	users     map[string]*userBase // 平台账号的行为基线（见 sentinel.go）
	anomalies []Anomaly
	comp      map[string]string // 合规测评项 → 上次结果（见 compliance.go）
	compHist  []CompPoint
	dirty     bool

	sent  sentinelState
	calib atomic.Pointer[map[string]RuleStat]
	// saveMu 串行化落盘：后台定时保存与界面操作（处置、锁定、采纳建议）可能同时触发，
	// 不串行时两次写入共用同一个临时文件，较旧的状态可能最后改名生效、覆盖较新的状态
	saveMu sync.Mutex

	// OnChange 在产生进化日志时调用（写入审计链），调用时不持锁。
	OnChange func(Change)
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
}

// Load 读取学习状态（文件不存在时从零开始）。
func Load(opt Options) (*Learner, error) {
	if opt.MinVerdicts <= 0 {
		opt.MinVerdicts = 5
	}
	if opt.MaxPrecision <= 0 || opt.MaxPrecision >= 1 {
		opt.MaxPrecision = 0.2
	}
	l := &Learner{opt: opt, cases: map[uint64]*Case{}, pinned: map[string]bool{}, handled: map[string]string{},
		users: map[string]*userBase{}, comp: map[string]string{}}
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
		}
	}
	n := len(l.changes)
	l.recomputeLocked(time.Now(), "")
	l.changes, l.dirty = l.changes[:n], false // 启动时重建快照，不重复记录进化日志
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
	st := state{Handled: l.handled, Changes: l.changes, Users: l.users, Anomalies: l.anomalies, Comp: l.comp, CompHist: l.compHist}
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
	for _, c := range l.cases {
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
		was := old != nil && (*old)[r].Calibrated
		switch {
		case st.Calibrated && !was:
			changes = append(changes, Change{Time: now, Kind: "calibrate", Rule: r, User: "自学习",
				Detail: fmt.Sprintf("规则 %s 研判 %d 次中 %d 次为误报（准确率 %.0f%%），等级自动下调一级（不低于攻击分类底线）", r, n, st.FP, st.Precision*100)})
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
	if old != nil { // 样本被撤回后规则不再出现在统计中
		for r := range *old {
			if !rules[r] {
				changes = append(changes, Change{Time: now, Kind: "restore", Rule: r, User: "自学习", Detail: "规则 " + r + " 恢复原等级（研判样本已撤回）"})
			}
		}
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].FP != stats[j].FP {
			return stats[i].FP > stats[j].FP
		}
		return stats[i].Rule < stats[j].Rule
	})
	l.stats = stats
	l.calib.Store(&calib)
	for _, c := range changes {
		l.logLocked(c)
	}

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

// Calibrate 对准确率持续偏低的规则下调一级（只下调攻击命中，不低于低危；分类底线由统一的等级裁决保证）。
// 返回的切片为副本，不修改调用方的数据。
func (l *Learner) Calibrate(hits []model.Hit) []model.Hit {
	if l == nil {
		return hits
	}
	m := l.calib.Load()
	if m == nil || len(*m) == 0 {
		return hits
	}
	var out []model.Hit
	for i := range hits {
		st, ok := (*m)[hits[i].RuleID]
		if !ok || hits[i].TagOnly || hits[i].Severity <= model.SevLow {
			continue
		}
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		out[i].Severity--
		out[i].Evidence += "；自学习校准：该规则研判 " + strconv.Itoa(st.TP+st.FP) + " 次中 " + strconv.Itoa(st.FP) + " 次为误报，等级下调一级"
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
	Cases       int          `json:"cases"` // 研判样本数
	TP          int          `json:"tp"`
	FP          int          `json:"fp"`
	Rules       []RuleStat   `json:"rules"`
	Calibrated  int          `json:"calibrated"`
	Suggestions []Suggestion `json:"suggestions"`
	Changes     []Change     `json:"changes"` // 最近的进化日志（新的在前）
	Anomalies   []Anomaly    `json:"anomalies"`
	Compliance  []CompPoint  `json:"compliance"` // 合规符合率趋势
	Options     Options      `json:"options"`
}

// Report 返回自学习状态概览。
func (l *Learner) Report() Report {
	r := Report{Rules: []RuleStat{}, Suggestions: []Suggestion{}, Changes: []Change{}, Anomalies: []Anomaly{}, Compliance: []CompPoint{}}
	if l == nil {
		return r
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Options = l.opt
	r.Options.Path = ""
	r.Cases = len(l.cases)
	for _, c := range l.cases {
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
