package store

import (
	"sort"
	"time"

	"netsa/internal/model"
)

// DayStat 是一天的汇总（按 timezone 的自然日），用于周报 / 月报。随快照持久化，最多保留 maxDays 天，
// 不受时间序列保留时长（storage.retention）的限制。
type DayStat struct {
	Date         string           `json:"date"` // YYYY-MM-DD
	Events       int64            `json:"events"`
	Web          int64            `json:"web"`
	Firewall     int64            `json:"firewall"`
	DNS          int64            `json:"dns,omitempty"`
	Auth         int64            `json:"auth,omitempty"`
	Attacks      int64            `json:"attacks"`
	Blocked      int64            `json:"blocked"`
	Success      int64            `json:"success"`
	Alerts       int64            `json:"alerts"`
	Sev          [5]int64         `json:"sev"`
	NewAttackers int64            `json:"new_attackers"`
	Categories   map[string]int64 `json:"categories"`
	Attackers    map[string]int64 `json:"attackers"` // 来源 IP → 攻击次数（有上限）
	Countries    map[string]int64 `json:"countries"`
}

const (
	maxDays          = 400
	maxDayAttackers  = 2000
	maxDayCategories = 100
	maxDayCountries  = 200
)

func bump(m *map[string]int64, k string, n int64, limit int) {
	if *m == nil {
		*m = map[string]int64{}
	}
	if _, ok := (*m)[k]; ok || len(*m) < limit {
		(*m)[k] += n
	}
}

// SetLocation 设置按天汇总使用的时区（与日志时区一致）。
func (s *Store) SetLocation(loc *time.Location) {
	s.mu.Lock()
	s.loc, s.dayEnd = loc, 0
	s.mu.Unlock()
}

// dayLocked 返回时间所在自然日的汇总（调用方持写锁）：当天的汇总按时间范围缓存，热路径不格式化日期。
func (s *Store) dayLocked(t time.Time) *DayStat {
	u := t.Unix()
	if s.curDay != nil && u >= s.dayStart && u < s.dayEnd {
		return s.curDay
	}
	loc := s.loc
	if loc == nil {
		loc = time.Local
	}
	lt := t.In(loc)
	start := time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, loc)
	key := start.Format("2006-01-02")
	d := s.days[key]
	if d == nil {
		d = &DayStat{Date: key}
		s.days[key] = d
		if len(s.days) > maxDays+10 {
			s.pruneDaysLocked()
		}
	}
	// 缓存最近访问的一天：实时日志与按时间顺序导入的历史日志都只在跨天时查表
	s.curDay, s.dayStart, s.dayEnd = d, start.Unix(), start.AddDate(0, 0, 1).Unix()
	return d
}

func (s *Store) pruneDaysLocked() {
	keys := make([]string, 0, len(s.days))
	for k := range s.days {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys[:max(len(keys)-maxDays, 0)] {
		if s.curDay != nil && s.curDay.Date == k {
			s.curDay, s.dayEnd = nil, 0
		}
		delete(s.days, k)
	}
}

// Days 返回 [from, to] 日期范围内的日汇总（日期格式 YYYY-MM-DD，按日期先后）。
func (s *Store) Days(from, to string) []DayStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []DayStat
	for k, d := range s.days {
		if k >= from && k <= to {
			c := *d
			c.Categories, c.Attackers, c.Countries = copyMap64(d.Categories), copyMap64(d.Attackers), copyMap64(d.Countries)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date < out[j].Date })
	return out
}

func copyMap64(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// recordDayHit 记录一次攻击命中到日汇总（调用方持写锁）。
func (d *DayStat) recordHit(h *model.Hit) {
	d.Attacks++
	d.Sev[max(min(int(h.Severity), 4), 0)]++
	bump(&d.Categories, h.Category, 1, maxDayCategories)
	switch h.Result {
	case model.ResultBlocked:
		d.Blocked++
	case model.ResultSuccess:
		d.Success++
	}
}
