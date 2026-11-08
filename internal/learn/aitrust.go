package learn

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// AIRecord 是外部模型对一个事件的研判结论。
//
// 模型结论不作为学习样本（否则模型的错误会被自学习放大），只在分析员给出结论后用来评估模型：
// 一致率让分析员知道这个模型在本单位环境中有多可信，「把确认的攻击判为误报」的次数提示最危险的分歧。
type AIRecord struct {
	Verdict    string    `json:"verdict"` // attack / false_positive / uncertain
	Confidence int       `json:"confidence"`
	Model      string    `json:"model"`
	Rules      []string  `json:"rules,omitempty"` // 事件涉及的规则与目标：可信模型的误报判断据此生成待确认的建议
	Targets    []string  `json:"targets,omitempty"`
	Source     string    `json:"source,omitempty"` // 事件的来源 IP：模型高置信判为攻击时自动确认该来源
	Time       time.Time `json:"time"`
}

// AIStat 是一个模型的研判表现，以分析员的处置结论为准。
type AIStat struct {
	Model     string  `json:"model"`
	Judged    int     `json:"judged"`     // 已有分析员结论、且模型给出了明确判断的事件数
	Agree     int     `json:"agree"`      // 与分析员结论一致
	Rate      float64 `json:"rate"`       // 一致率；样本不足 minAISamples 时为 -1
	Missed    int     `json:"missed"`     // 模型判为误报、分析员确认是攻击（漏判，最需要警惕）
	Overcall  int     `json:"overcall"`   // 模型判为攻击、分析员判为误报
	HighConf  int     `json:"high_conf"`  // 置信度 ≥ 80 的明确判断
	HighAgree int     `json:"high_agree"` // 其中与分析员一致的次数
	Uncertain int     `json:"uncertain"`  // 模型无法判断
	Pending   int     `json:"pending"`    // 尚无分析员结论
}

const (
	maxAIRecords = 20000
	minAISamples = 5
)

// RecordAI 记录模型对事件的研判结论（同一事件再次研判时以最新结论为准）。
func (l *Learner) RecordAI(incident uint64, r AIRecord) {
	if l == nil || incident == 0 || r.Model == "" {
		return
	}
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	if len(r.Rules) > 8 {
		r.Rules = r.Rules[:8]
	}
	if len(r.Targets) > 5 {
		r.Targets = r.Targets[:5]
	}
	l.mu.Lock()
	l.ai[incident] = &r
	if len(l.ai) > maxAIRecords {
		ids := make([]uint64, 0, len(l.ai))
		for id := range l.ai {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return l.ai[ids[i]].Time.Before(l.ai[ids[j]].Time) })
		for _, id := range ids[:len(ids)-maxAIRecords*9/10] {
			delete(l.ai, id)
		}
	}
	l.dirty = true
	changes := l.recomputeLocked(time.Now(), "") // 模型的新判断可能形成待确认的建议
	l.mu.Unlock()
	l.emit(changes)
	// 模型高置信判为攻击：自动确认来源（只会让该来源之后的命中升级，学错的代价是多几条告警）
	// 站点的常客除外：模型看到的只是告警，长连接重连、浏览器插件探测 /.git/HEAD 这类误报会让它把员工的出口地址判为攻击
	if r.Source != "" && r.Verdict == "attack" && r.Confidence >= aiConfirmConfidence && (l.RegularUser == nil || !l.RegularUser(r.Source)) {
		l.ConfirmSource(r.Source, "ai", fmt.Sprintf("模型 %s 以 %d%% 置信度判为攻击（事件 #%d）", r.Model, r.Confidence, incident), r.Time)
	}
}

// revokeRegularAI 撤销只凭模型判断确认、实际是站点常客的攻击源（不持锁调用：RegularUser 查询状态库）。
func (l *Learner) revokeRegularAI(now time.Time) {
	if l.RegularUser == nil {
		return
	}
	l.mu.Lock()
	var ips []string
	for ip, a := range l.auto {
		if a.Kind == "ai" {
			ips = append(ips, ip)
		}
	}
	l.mu.Unlock()
	var drop []string
	for _, ip := range ips {
		if l.RegularUser(ip) {
			drop = append(drop, ip)
		}
	}
	if len(drop) == 0 {
		return
	}
	sort.Strings(drop)
	l.mu.Lock()
	var cs []Change
	for _, ip := range drop {
		if a := l.auto[ip]; a != nil && a.Kind == "ai" {
			delete(l.auto, ip)
			c := Change{Time: now, Kind: "revoke_auto", User: "自学习",
				Detail: "撤销自动确认的攻击源 " + ip + "（" + a.Reason + "）：该来源是站点的常客，大量正常访问、攻击命中占比很低，模型的判断多半来自业务请求触发的误报"}
			l.logLocked(c)
			cs = append(cs, c)
		}
	}
	if len(cs) > 0 {
		l.dirty = true
		l.publishAutoLocked()
	}
	l.mu.Unlock()
	l.emit(cs)
}

// Refresh 按当前时间重新计算校准结果（由后台任务定期调用）：样本超过学习窗口后，相应的校准自动撤销。
func (l *Learner) Refresh(now time.Time) {
	if l == nil {
		return
	}
	l.revokeRegularAI(now) // 先撤销误确认的常客：之后为候选形态生成规则时，它们不再算攻击源
	l.mu.Lock()
	changes := l.recomputeLocked(now, "")
	changes = append(changes, l.pruneAttackLocked(now, l.opt.EscalateDays)...)
	l.pruneProfileLocked(now)
	l.mu.Unlock()
	l.emit(changes)
}

// expiredLocked 判断样本是否超过学习窗口。
func (l *Learner) expiredLocked(c *Case, now time.Time) bool {
	return l.opt.WindowDays > 0 && now.Sub(c.Time) > time.Duration(l.opt.WindowDays)*24*time.Hour
}

func clipNote(s string) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return string(r)
}

const (
	trustedAIRate    = 0.8 // 模型的判断可以形成待确认建议所需的一致率
	trustedAISamples = 10  // 以及已评估的事件数
	aiSuggestMinConf = 80  // 单次判断的最低置信度
	aiSuggestMinFP   = 3   // 同一规则 + 目标上的最少判断次数
)

// aiSuggestionsLocked 让模型帮助发现误报模式：历史一致率足够高的模型，多次以高置信度把同一规则 + 目标判为误报、
// 分析员尚未处置且该目标从未确认过攻击时，生成待确认的抑制建议。只是建议，模型的判断不会自动生效，也不作为学习样本。
func (l *Learner) aiSuggestionsLocked(ctx map[[2]string]*ctxStat, have []Suggestion, now time.Time) []Suggestion {
	trusted := map[string]AIStat{}
	for _, st := range l.aiStats {
		if st.Judged >= trustedAISamples && st.Rate >= trustedAIRate {
			trusted[st.Model] = st
		}
	}
	if len(trusted) == 0 {
		return nil
	}
	exists := map[string]bool{}
	for _, s := range have {
		exists[s.ID] = true
	}
	tally := map[[2]string]*ctxStat{}
	names := map[[2]string]string{}
	for id, r := range l.ai {
		if _, ok := trusted[r.Model]; !ok || r.Verdict != "false_positive" || r.Confidence < aiSuggestMinConf || l.cases[id] != nil || len(r.Rules) == 0 || len(r.Rules) > 2 {
			continue
		}
		if l.opt.WindowDays > 0 && now.Sub(r.Time) > time.Duration(l.opt.WindowDays)*24*time.Hour {
			continue
		}
		seen := (&Case{Targets: r.Targets}).targets()
		for _, rule := range r.Rules {
			for _, t := range seen {
				k := [2]string{rule, t}
				if tally[k] == nil {
					tally[k] = &ctxStat{}
				}
				tally[k].fp++
				if len(tally[k].incidents) < 10 {
					tally[k].incidents = append(tally[k].incidents, id)
				}
				names[k] = r.Model
			}
		}
	}
	var out []Suggestion
	for _, k := range sortedCtxKeys(tally) {
		cs := tally[k]
		if cs.fp < aiSuggestMinFP || (ctx[k] != nil && ctx[k].tp > 0) {
			continue
		}
		st := trusted[names[k]]
		s := Suggestion{Kind: "context", RuleID: k[0], Target: k[1], FP: cs.fp, Incidents: cs.incidents, Origin: "ai",
			Reason: fmt.Sprintf("模型建议（待人工确认）：%s（历史一致率 %.0f%%）%d 次把规则 %s 在 %s 上的命中判为误报，分析员尚未处置", st.Model, st.Rate*100, cs.fp, k[0], k[1])}
		s.ID = suggestionID(s.Kind, s.RuleID, s.Target, "")
		if !exists[s.ID] && l.handled[s.ID] == "" {
			out = append(out, s)
		}
	}
	return out
}

// WeekStat 是一周内分析员结论的统计（第 0 项为最近 7 天）。
type WeekStat struct {
	Start time.Time `json:"start"`
	TP    int       `json:"tp"`
	FP    int       `json:"fp"`
}

// weekTrend 统计近 8 周的人工结论。自学习生效后，告警中误报的占比应逐步下降。
func weekTrend(cases map[uint64]*Case, now time.Time) []WeekStat {
	const weeks = 8
	out := make([]WeekStat, weeks)
	for i := range out {
		out[i].Start = now.AddDate(0, 0, -7*(i+1))
	}
	for _, c := range cases {
		i := int(now.Sub(c.Time) / (7 * 24 * time.Hour))
		if i < 0 || i >= weeks {
			continue
		}
		if c.Verdict == VerdictTP {
			out[i].TP++
		} else {
			out[i].FP++
		}
	}
	return out
}

// SimilarCase 是分析员处理过的相似事件，提供给外部模型作为本单位的经验。
type SimilarCase struct {
	Rule      string  `json:"rule"`
	Target    string  `json:"target"`
	Verdict   Verdict `json:"verdict"`
	Note      string  `json:"note,omitempty"`
	Corrected string  `json:"corrected,omitempty"` // 模型当时的相反判断：分析员纠正过，模型应当重点吸取
}

// Similar 返回与事件最相关的人工处置案例（不含事件自身）：有处置说明或纠正过模型的案例才有参考价值，
// 同一目标优先于只是同一规则，纠正过模型的优先于普通案例。
func (l *Learner) Similar(rules, targets []string, exclude uint64, n int) []SimilarCase {
	if l == nil || n <= 0 {
		return nil
	}
	want := map[string]bool{}
	for _, t := range targets {
		if k := targetKey(t); k != "" {
			want[k] = true
		}
	}
	type scored struct {
		SimilarCase
		score int
		at    time.Time
		id    uint64
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var list []scored
	for id, c := range l.cases {
		if id == exclude || l.expiredLocked(c, now) || (c.Verdict == VerdictFP && !c.focused()) {
			continue
		}
		corrected := ""
		if r := l.ai[id]; r != nil && (r.Verdict == "attack" || r.Verdict == "false_positive") && (r.Verdict == "attack") != (c.Verdict == VerdictTP) {
			corrected = r.Verdict
		}
		if c.Note == "" && corrected == "" {
			continue
		}
		rule := ""
		for _, r := range rules {
			if _, ok := c.Rules[r]; ok {
				rule = r
				break
			}
		}
		if rule == "" {
			continue
		}
		s := scored{SimilarCase: SimilarCase{Rule: rule, Verdict: c.Verdict, Note: c.Note, Corrected: corrected}, score: 1, at: c.Time, id: id}
		ts := c.targets()
		if len(ts) > 0 {
			s.Target = ts[0]
		}
		for _, t := range ts {
			if want[t] {
				s.Target = t
				s.score += 2
				break
			}
		}
		if corrected != "" {
			s.score++
		}
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].score != list[j].score {
			return list[i].score > list[j].score
		}
		if !list[i].at.Equal(list[j].at) {
			return list[i].at.After(list[j].at)
		}
		return list[i].id > list[j].id
	})
	out := make([]SimilarCase, 0, min(n, len(list)))
	for i := 0; i < len(list) && i < n; i++ {
		out = append(out, list[i].SimilarCase)
	}
	return out
}

// aiStatsLocked 按分析员结论计算各模型的研判表现（调用方持锁）。
func (l *Learner) aiStatsLocked() []AIStat {
	m := map[string]*AIStat{}
	for id, r := range l.ai {
		st := m[r.Model]
		if st == nil {
			st = &AIStat{Model: r.Model}
			m[r.Model] = st
		}
		c := l.cases[id]
		switch {
		case r.Verdict != "attack" && r.Verdict != "false_positive":
			st.Uncertain++
		case c == nil:
			st.Pending++
		default:
			st.Judged++
			agree := (r.Verdict == "attack") == (c.Verdict == VerdictTP)
			switch {
			case agree:
				st.Agree++
			case c.Verdict == VerdictTP:
				st.Missed++
			default:
				st.Overcall++
			}
			if r.Confidence >= 80 {
				st.HighConf++
				if agree {
					st.HighAgree++
				}
			}
		}
	}
	out := make([]AIStat, 0, len(m))
	for _, st := range m {
		st.Rate = -1
		if st.Judged >= minAISamples {
			st.Rate = float64(st.Agree) / float64(st.Judged)
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Judged != out[j].Judged {
			return out[i].Judged > out[j].Judged
		}
		return out[i].Model < out[j].Model
	})
	return out
}

// Trust 返回模型在本单位的历史一致率说明，写在 AI 研判记录中供分析员判断可信度；样本不足时返回空字符串。
func (l *Learner) Trust(model string) string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, st := range l.aiStats {
		if st.Model != model || st.Rate < 0 {
			continue
		}
		s := fmt.Sprintf("自学习评估：该模型历史研判与分析员结论一致率 %.0f%%（%d 个事件）", st.Rate*100, st.Judged)
		if st.Missed > 0 {
			s += fmt.Sprintf("，其中 %d 次把确认的攻击判为误报", st.Missed)
		}
		if st.Judged >= trustedAISamples && st.Rate < 0.5 {
			s += "；一致率明显偏低，请以人工复核为准"
		}
		return s
	}
	return ""
}

// History 是平台对相关来源、规则与目标的历史人工结论，作为外部模型研判的参考。
type History struct {
	SourceTP int           `json:"source_tp"`
	SourceFP int           `json:"source_fp"`
	Contexts []ContextStat `json:"contexts"` // 同一规则在同一目标上的历史结论（最多 8 条，样本多的在前）
}

// History 汇总与事件相关的历史人工结论（不含事件自身）。误报只统计归因到少数规则的样本，
// 与精细校准的口径一致：涉及大量规则的误报通常是对来源的判断，不代表规则在该目标上误报。
func (l *Learner) History(source string, rules, targets []string, exclude uint64) History {
	var h History
	if l == nil {
		return h
	}
	want := map[string]bool{}
	for _, t := range targets {
		if k := targetKey(t); k != "" {
			want[k] = true
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx := map[[2]string]*ContextStat{}
	for id, c := range l.cases {
		if id == exclude {
			continue
		}
		if source != "" && c.Source == source {
			if c.Verdict == VerdictTP {
				h.SourceTP++
			} else {
				h.SourceFP++
			}
		}
		if c.Verdict == VerdictFP && !c.focused() {
			continue
		}
		for r := range c.Rules {
			if !slices.Contains(rules, r) {
				continue
			}
			for _, t := range c.targets() {
				if !want[t] {
					continue
				}
				k := [2]string{r, t}
				cs := ctx[k]
				if cs == nil {
					cs = &ContextStat{Rule: r, Target: t}
					ctx[k] = cs
				}
				if c.Verdict == VerdictTP {
					cs.TP++
				} else {
					cs.FP++
				}
			}
		}
	}
	for _, k := range sortedCtxKeys(ctx) {
		h.Contexts = append(h.Contexts, *ctx[k])
	}
	sort.SliceStable(h.Contexts, func(i, j int) bool { return h.Contexts[i].TP+h.Contexts[i].FP > h.Contexts[j].TP+h.Contexts[j].FP })
	if len(h.Contexts) > 8 {
		h.Contexts = h.Contexts[:8]
	}
	return h
}

// TrustRate 返回模型与分析员结论的一致率；评估样本不足时 known 为 false。
func (l *Learner) TrustRate(model string) (rate float64, known bool) {
	if l == nil {
		return 0, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, st := range l.aiStats {
		if st.Model == model && st.Rate >= 0 {
			return st.Rate, true
		}
	}
	return 0, false
}
