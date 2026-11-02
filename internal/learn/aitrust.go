package learn

import (
	"fmt"
	"slices"
	"sort"
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
	l.mu.Lock()
	defer l.mu.Unlock()
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
	l.aiStats = l.aiStatsLocked()
	l.dirty = true
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
