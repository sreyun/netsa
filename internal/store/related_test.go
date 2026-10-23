package store

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

func TestCorrelate(t *testing.T) {
	s := New(1000, 100, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info {
		info := &geo.Info{IP: ip, Country: "美国", CountryCode: "US", ASN: 14061, Hosting: true}
		if strings.HasPrefix(ip, "192.0.2.") || strings.HasPrefix(ip, "10.9.") {
			info.ASN, info.Hosting = 4134, false
		}
		return info
	}
	now := time.Now()
	hit := func(ip, ua string, rules ...string) {
		for _, r := range rules {
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/" + r, Status: 404, UA: ua, Time: now},
				[]model.Hit{attackHit(r, "扫描", model.SevMedium, model.ResultFailed)})
		}
	}
	tool := "nuclei-custom/2.9 (team-x)"
	hit("198.51.100.10", tool, "a", "b", "c")
	hit("198.51.100.11", tool, "a", "b", "c") // 同网段 + 同工具 + 同手法：强关联
	hit("203.0.113.7", tool, "a", "b")        // 不同网段，同工具 + 同手法
	hit("192.0.2.9", "Mozilla/5.0", "z")      // 无关
	for i := 0; i < 3; i++ {
		hit("10.9.0."+string(rune('1'+i)), "Mozilla/5.0", "q") // 背景攻击源
	}

	d := s.IPDetail("198.51.100.10")
	if d == nil || d.Related == nil {
		t.Fatal("缺少关联分析结果")
	}
	r := d.Related
	if r.Subnet != "198.51.100.0/24" || r.SubnetCount != 1 || r.ASNCount != 2 || r.Scanned != 6 {
		t.Fatalf("统计错误: %+v", r)
	}
	if len(r.Related) != 2 || r.Related[0].IP != "198.51.100.11" || r.Related[0].Score < relatedStrong || r.Strong < 1 {
		t.Fatalf("关联排序错误: %+v", r.Related)
	}
	joined := strings.Join(r.Related[0].Reasons, "；")
	for _, want := range []string{"198.51.100.0/24", "工具指纹", "攻击手法相似度", "AS14061"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("关联理由缺少 %q: %s", want, joined)
		}
	}
	if r.Related[1].IP != "203.0.113.7" {
		t.Fatalf("同工具同手法应关联: %+v", r.Related[1])
	}

	// 快照恢复后指纹需重建，关联结果保持一致
	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := New(1000, 100, 5, time.Hour)
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	if r2 := s2.IPDetail("198.51.100.10").Related; len(r2.Related) != 2 || r2.Related[0].Score != r.Related[0].Score || r2.Related[1].Score != r.Related[1].Score {
		t.Fatalf("快照恢复后关联结果不一致: %+v", r2.Related)
	}
}

func TestRegDomain(t *testing.T) {
	for in, want := range map[string]string{
		"scanner-12.census.shodan.io.": "shodan.io",
		"a.b.example.com.cn":           "example.com.cn",
		"localhost":                    "",
		"crawl-66-249.googlebot.com":   "googlebot.com",
	} {
		if got := regDomain(in); got != want {
			t.Errorf("regDomain(%q)=%q want %q", in, got, want)
		}
	}
}

// benchStore 构造 20 万攻击源。zipf 为 true 时规则 / 目标 / UA 按长尾分布抽取（贴近真实扫描流量）；
// 为 false 时所有攻击源几乎共用同一批规则与目标（最坏情况：每个攻击源都需要做目标比对）。
func benchStore(b *testing.B, zipf bool, n int) *Store {
	s := New(300000, 100, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info { return &geo.Info{IP: ip, ASN: uint(len(ip) % 50)} }
	rnd := rand.New(rand.NewSource(1))
	zr := rand.NewZipf(rnd, 1.2, 4, 59)
	zt := rand.NewZipf(rnd, 1.1, 4, 1999)
	zu := rand.NewZipf(rnd, 1.3, 4, 199)
	now := time.Now()
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("%d.%d.%d.%d", 1+i%200, (i/200)%250, (i/50000)%250, 1+i%250)
		var ua string
		if zipf {
			ua = fmt.Sprintf("agent-%d", zu.Uint64())
		} else {
			ua = fmt.Sprintf("Mozilla/5.0 build-%d", rnd.Intn(50))
		}
		if i%3 == 0 {
			ua = "Mozilla/5.0 " + ua
		}
		n := 3 + rnd.Intn(30)
		for j := 0; j < n; j++ {
			r, t := fmt.Sprintf("rule-%d", zr.Uint64()), fmt.Sprintf("/p%d", zt.Uint64())
			if !zipf {
				r, t = fmt.Sprintf("rule-%d", rnd.Intn(60)/8*8+j%8), fmt.Sprintf("/p%d", rnd.Intn(300))
			}
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: t, Status: 404, UA: ua, Time: now},
				[]model.Hit{attackHit(r, "扫描", model.SevMedium, model.ResultFailed)})
		}
		if i%10 == 0 {
			for j := 0; j < 20; j++ {
				s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: ip, DstPort: rnd.Intn(1000), Action: model.ActionDeny, Time: now}, nil)
			}
		}
	}
	return s
}

func benchCorrelate(b *testing.B, zipf bool, n int) {
	s := benchStore(b, zipf, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := s.IPDetail("1.0.0.1"); d == nil || d.Related.Scanned < n/2 {
			b.Fatal("样本不足")
		}
	}
}

func BenchmarkCorrelate(b *testing.B)      { benchCorrelate(b, true, 200000) }
func BenchmarkCorrelate20k(b *testing.B)   { benchCorrelate(b, true, 20000) }
func BenchmarkCorrelateWorst(b *testing.B) { benchCorrelate(b, false, 200000) }
