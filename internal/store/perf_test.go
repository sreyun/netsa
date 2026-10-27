package store

import (
	"fmt"
	"math"
	"sort"
	"testing"
	"time"

	"netsa/internal/model"
)

// TestEvictKeepsHighestScored 校验部分选择淘汰与全量排序语义一致：
// 只淘汰评分最低的若干个，剩余画像数量为上限的 90%。
func TestEvictKeepsHighestScored(t *testing.T) {
	const total, maxIPs = 1000, 900
	s := New(maxIPs, 100, 5, time.Hour)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		s.ips[ip] = &IPProfile{IP: ip, Score: float64(i), LastSeen: base.Add(time.Duration(i) * time.Second)}
	}
	s.Maintain()

	evicted := total - maxIPs + maxIPs/10
	wantRemain := total - evicted
	if len(s.ips) != wantRemain {
		t.Fatalf("应保留 %d 个画像，实际 %d", wantRemain, len(s.ips))
	}
	minScore := math.MaxFloat64
	for _, p := range s.ips {
		if p.Score < minScore {
			minScore = p.Score
		}
	}
	if minScore != float64(evicted) {
		t.Fatalf("应淘汰评分最低的 %d 个，剩余最低分应为 %d，实际 %.0f", evicted, evicted, minScore)
	}
}

// TestEvictPrefersStaleOnTie 评分相同时优先淘汰更久未活动的画像。
func TestEvictPrefersStaleOnTie(t *testing.T) {
	s := New(10, 100, 5, time.Hour)
	now := time.Now()
	for i := 0; i < 12; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		s.ips[ip] = &IPProfile{IP: ip, Score: 10, LastSeen: now.Add(time.Duration(i) * time.Minute)}
	}
	s.Maintain()
	// 淘汰 12-10+1=3 个：最近活动时间最早的三个
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		if s.Profile(ip) != nil {
			t.Fatalf("%s 应被优先淘汰", ip)
		}
	}
	if len(s.ips) != 9 {
		t.Fatalf("应保留 9 个画像，实际 %d", len(s.ips))
	}
}

// TestAttackersPaginationStable 分页结果不重复、不遗漏，且按评分降序。
func TestAttackersPaginationStable(t *testing.T) {
	s := New(1000, 100, 5, time.Hour)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		s.ips[ip] = &IPProfile{IP: ip, Score: float64(i % 40), Attacks: int64(i + 1), Level: model.SevMedium,
			FirstSeen: base, LastSeen: base.Add(time.Duration(i) * time.Second), Categories: map[string]int{"高危服务探测": 1}}
	}
	seen := map[string]bool{}
	var prevScore float64 = math.MaxFloat64
	for offset := 0; offset < 200; offset += 50 {
		page, total := s.Attackers(AttackerQuery{Limit: 50, Offset: offset})
		if total != 200 || len(page) != 50 {
			t.Fatalf("offset=%d total=%d len=%d", offset, total, len(page))
		}
		for _, it := range page {
			if seen[it.IP] {
				t.Fatalf("分页重复: %s", it.IP)
			}
			seen[it.IP] = true
			if it.Score > prevScore {
				t.Fatalf("应按评分降序: %v > %v", it.Score, prevScore)
			}
			prevScore = it.Score
		}
	}
	if len(seen) != 200 {
		t.Fatalf("分页遗漏: %d/200", len(seen))
	}
}

// makeProfiles 构造用于基准测试的画像集合。
func makeProfiles(n int) []*IPProfile {
	base := time.Now().Add(-time.Hour)
	out := make([]*IPProfile, 0, n)
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		out = append(out, &IPProfile{IP: ip, Score: float64(i % 100), Attacks: 1,
			Level: model.SevLow, FirstSeen: base, LastSeen: base.Add(time.Duration(i) * time.Second)})
	}
	return out
}

// evictFullSortBaseline 是改造前的实现，仅用于基准对比。
func evictFullSortBaseline(s *Store) {
	type cand struct {
		ip    string
		score float64
		last  time.Time
	}
	var cs []cand
	for ip, p := range s.ips {
		cs = append(cs, cand{ip, p.Score, p.LastSeen})
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].score != cs[j].score {
			return cs[i].score < cs[j].score
		}
		return cs[i].last.Before(cs[j].last)
	})
	n := len(s.ips) - s.maxIPs + s.maxIPs/10
	for i := 0; i < n && i < len(cs); i++ {
		delete(s.ips, cs[i].ip)
	}
}

func benchmarkEvict(b *testing.B, fn func(*Store)) {
	const total, maxIPs = 50000, 40000
	base := makeProfiles(total)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := &Store{maxIPs: maxIPs, ips: make(map[string]*IPProfile, total)}
		for _, p := range base {
			s.ips[p.IP] = p
		}
		b.StartTimer()
		fn(s)
	}
}

func BenchmarkEvictPartialSelect(b *testing.B) {
	benchmarkEvict(b, func(s *Store) { s.evictLocked() })
}

func BenchmarkEvictFullSortBaseline(b *testing.B) {
	benchmarkEvict(b, evictFullSortBaseline)
}

func BenchmarkAttackers(b *testing.B) {
	s := New(60000, 1000, 5, time.Hour)
	for _, p := range makeProfiles(50000) {
		p.Categories = map[string]int{"高危服务探测": 1}
		s.ips[p.IP] = p
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if list, total := s.Attackers(AttackerQuery{Limit: 50}); total != 50000 || len(list) != 50 {
			b.Fatalf("total=%d len=%d", total, len(list))
		}
	}
}
