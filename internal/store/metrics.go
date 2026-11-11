package store

import "time"

// MetricsData 是 Prometheus 指标所需的状态库统计（一次读锁内完成）。
type MetricsData struct {
	Totals    Totals
	SevCount  [5]int64 // 各等级的攻击命中数
	Profiles  int      // 画像数（含正常访客）
	Attackers [5]int   // 各威胁等级的攻击源数
	Alerts    int      // 内存中保留的告警数
	Incidents IncidentCounts
	Score     *ScorePoint // 最近一次安全评分
	MaxTime   time.Time   // 最新日志时间
}

// Metrics 返回指标统计。
func (s *Store) Metrics() MetricsData {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := MetricsData{Totals: s.totals, SevCount: s.sevCount, Profiles: len(s.ips), Alerts: len(s.alerts), Incidents: s.incidentCountsLocked(now), MaxTime: s.maxTime}
	m.Attackers = s.agg.levels // 增量维护的攻击源等级分布（与总览同一口径），不再每次抓取都遍历全部画像
	if n := len(s.scores); n > 0 {
		sp := s.scores[n-1]
		m.Score = &sp
	}
	return m
}
