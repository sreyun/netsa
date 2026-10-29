package learn

import (
	"time"
)

// 持续合规自检：定期重算等保测评项，任何一项结果下降（符合 → 部分符合 / 不符合）立即告警，
// 避免配置被改动（例如缩短日志留存、关闭双因素认证、数据源断流）后直到年度测评才发现。

// CompItem 是一个测评项的检查结果（由 API 层的等保检查生成）。
type CompItem struct {
	Control  string
	Status   string // pass / partial / fail / na
	Label    string
	Evidence string
	Advice   string
}

// CompChange 是一个测评项的结果变化。
type CompChange struct {
	Control  string `json:"control"`
	From     string `json:"from"`
	To       string `json:"to"`
	Label    string `json:"label"`
	Evidence string `json:"evidence"`
	Advice   string `json:"advice,omitempty"`
	Degraded bool   `json:"degraded"`
}

// CompPoint 是一次自检的符合率。
type CompPoint struct {
	Time time.Time `json:"time"`
	Rate float64   `json:"rate"`
	Fail int       `json:"fail"`
}

const maxCompHist = 24 * 30 // 每小时一次，保留 30 天

var compRank = map[string]int{"fail": 0, "partial": 1, "pass": 2}

// CheckCompliance 记录一次合规自检结果，返回与上次相比发生变化的测评项（首次自检只建立基线）。
func (l *Learner) CheckCompliance(items []CompItem, rate float64, at time.Time) []CompChange {
	if l == nil || !l.opt.Compliance {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	first := len(l.comp) == 0
	var out []CompChange
	fail := 0
	for _, it := range items {
		if it.Status == "fail" {
			fail++
		}
		prev, ok := l.comp[it.Control]
		l.comp[it.Control] = it.Status
		if first || !ok || prev == it.Status || it.Status == "na" || prev == "na" {
			continue
		}
		out = append(out, CompChange{Control: it.Control, From: prev, To: it.Status, Label: it.Label, Evidence: it.Evidence,
			Advice: it.Advice, Degraded: compRank[it.Status] < compRank[prev]})
	}
	l.compHist = append(l.compHist, CompPoint{Time: at, Rate: rate, Fail: fail})
	if len(l.compHist) > maxCompHist {
		l.compHist = append([]CompPoint(nil), l.compHist[len(l.compHist)-maxCompHist:]...)
	}
	l.dirty = true
	return out
}
