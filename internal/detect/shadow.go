package detect

import (
	"sync"
	"time"
)

// 影子运行：规则设为 shadow 时照常匹配，但命中只记在这里，不产生告警、不计入攻击统计与研判。
// 新规则（页面编写、Sigma 导入）先影子运行一段时间，看清它在现场流量上命中什么，再转为正式生效：
// 一条写宽了的规则直接上线，会在几分钟内刷出成千上万条告警并拉高评分。

const (
	maxShadowRules   = 512 // 记录命中的影子规则数上限（托管规则本身最多 500 条）
	maxShadowSamples = 5   // 每条规则保留的最近命中样本数
)

// ShadowStat 是一条影子规则的命中统计。
type ShadowStat struct {
	Hits    int64     `json:"hits"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Samples []string  `json:"samples,omitempty"` // 最近几次命中（站点、请求与证据），新的在前
}

// ShadowStats 记录影子规则的命中，在规则引擎重建（规则变更）之间保留；并发安全。
type ShadowStats struct {
	mu sync.Mutex
	m  map[string]*ShadowStat
}

// NewShadowStats 创建影子运行统计。
func NewShadowStats() *ShadowStats { return &ShadowStats{m: map[string]*ShadowStat{}} }

func (s *ShadowStats) note(id, sample string) {
	if s == nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.m[id]
	if st == nil {
		if len(s.m) >= maxShadowRules {
			return
		}
		st = &ShadowStat{First: now}
		s.m[id] = st
	}
	st.Hits++
	st.Last = now
	st.Samples = append([]string{Printable(sample, 300)}, st.Samples...)
	if len(st.Samples) > maxShadowSamples {
		st.Samples = st.Samples[:maxShadowSamples]
	}
}

// Snapshot 返回各影子规则的命中统计（副本）。
func (s *ShadowStats) Snapshot() map[string]ShadowStat {
	out := map[string]ShadowStat{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, st := range s.m {
		c := *st
		c.Samples = append([]string(nil), st.Samples...)
		out[id] = c
	}
	return out
}

// Reset 清除一条规则的统计（规则的匹配条件改变后，此前的命中不再代表它的效果）。
func (s *ShadowStats) Reset(ids ...string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.m, id)
	}
}

// Keep 只保留仍处于影子运行的规则的统计。
func (s *ShadowStats) Keep(ids []string) {
	if s == nil {
		return
	}
	keep := make(map[string]bool, len(ids))
	for _, id := range ids {
		keep[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.m {
		if !keep[id] {
			delete(s.m, id)
		}
	}
}

// SetShadow 设置记录影子规则命中的统计（规则管理在每次重建引擎时传入同一个实例）。为空时影子规则只是不生效。
func (e *Engine) SetShadow(s *ShadowStats) { e.shadow = s }
