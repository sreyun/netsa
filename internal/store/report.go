package store

import (
	"sort"
	"time"

	"netsa/internal/model"
)

// ScorePoint 是一次安全评分记录（每小时一次），用于展示评分趋势与整改效果。
type ScorePoint struct {
	T           time.Time      `json:"t"`
	Score       int            `json:"score"`
	Grade       string         `json:"grade"`
	Dims        map[string]int `json:"dims"` // 维度 → 得分（-1 为未接入）
	P0          int            `json:"p0"`
	Compromised int            `json:"compromised"`
}

// maxScorePoints 保留最近 30 天的小时级评分。
const maxScorePoints = 30 * 24

// RecordScore 记录一次评分；与上一条相隔不足 50 分钟时覆盖上一条（重启后补记等情况）。
func (s *Store) RecordScore(a *Assessment) {
	p := ScorePoint{T: time.Now(), Score: a.Score, Grade: a.Grade, Dims: map[string]int{}, P0: a.ActionCount["P0"], Compromised: len(a.Compromised)}
	for _, d := range a.Dimensions {
		p.Dims[d.Key] = d.Score
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.scores); n > 0 && absDur(p.T.Sub(s.scores[n-1].T)) < 50*time.Minute {
		s.scores[n-1] = p
	} else {
		s.scores = append(s.scores, p)
	}
	if len(s.scores) > maxScorePoints {
		s.scores = append([]ScorePoint(nil), s.scores[len(s.scores)-maxScorePoints:]...)
	}
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// ScoreHistory 返回评分历史（按时间先后）。
func (s *Store) ScoreHistory() []ScorePoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ScorePoint{}, s.scores...)
}

// Daily 是安全日报所需的统计（以最新日志时间为基准的最近一个周期，与前一个周期对比）。
type Daily struct {
	From, To     time.Time
	Attacks      int64 // 攻击命中次数
	PrevAttacks  int64
	Blocked      int64
	Success      int64
	Attackers    int // 周期内活动的攻击源
	NewAttackers int // 周期内首次出现的攻击源
	HighActive   int // 周期内活动的高危以上攻击源
	TopCats      []KV
	TopAttackers []AttackerSummary
}

// DailySummary 统计最近 period（通常为 24 小时）的攻击态势。攻击类型按周期内保留的告警统计。
func (s *Store) DailySummary(period time.Duration) *Daily {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := &Daily{To: s.maxTime, From: s.maxTime.Add(-period)}
	if s.maxTime.IsZero() {
		return d
	}
	cut, prevCut := d.From.Unix()/60, d.From.Add(-period).Unix()/60
	for k, b := range s.buckets {
		switch {
		case k > cut:
			d.Attacks += b.Attacks
			d.Blocked += b.Blocked
			d.Success += b.Success
		case k > prevCut:
			d.PrevAttacks += b.Attacks
		}
	}
	var active []*IPProfile
	for _, p := range s.ips {
		if !isAttacker(p) || !p.LastSeen.After(d.From) {
			continue
		}
		d.Attackers++
		active = append(active, p)
		if p.FirstSeen.After(d.From) {
			d.NewAttackers++
		}
		if p.Level >= model.SevHigh {
			d.HighActive++
		}
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].Score != active[j].Score {
			return active[i].Score > active[j].Score
		}
		return active[i].Attacks > active[j].Attacks
	})
	for _, p := range active[:min(3, len(active))] {
		d.TopAttackers = append(d.TopAttackers, summarize(p))
	}
	cats := map[string]int64{}
	for _, a := range s.alerts {
		if a.Time.After(d.From) {
			cats[a.Category]++
		}
	}
	d.TopCats = topN(cats, 3, ident)
	return d
}
