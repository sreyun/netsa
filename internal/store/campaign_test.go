package store

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

// 攻击活动归并：同一工具与手法的多个出口、同一云厂商的地址轮换扫描同一主机，各归为一个活动；无关的地址不归并。
func TestCampaigns(t *testing.T) {
	s := New(10000, 1000, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info {
		switch {
		case strings.HasPrefix(ip, "45.79.") || strings.HasPrefix(ip, "50.116."): // 同一云厂商
			return &geo.Info{IP: ip, Country: "美国", ASN: 63949, ASOrg: "Akamai Connected Cloud", Hosting: true}
		case strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113."):
			return &geo.Info{IP: ip, Country: "美国", ASN: 14061, Hosting: true}
		}
		return &geo.Info{IP: ip, Country: "中国", ASN: 4134}
	}
	now := time.Now()
	web := func(ip, ua string, rules ...string) {
		for _, r := range rules {
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "www.example.com", Method: "GET", URI: "/" + r, Status: 404, UA: ua, Time: now},
				[]model.Hit{attackHit(r, "扫描", model.SevMedium, model.ResultFailed)})
		}
	}
	// 活动 A：同一自研工具、同一手法，分布在两个网段
	tool := "redteam-scanner/3.1"
	web("198.51.100.10", tool, "a", "b", "c")
	web("198.51.100.11", tool, "a", "b", "c")
	web("203.0.113.7", tool, "a", "b", "c")
	// 活动 B：同一云厂商的 8 个地址在相近时间扫描同一主机的随机端口（每个地址的端口都不同）
	for i := range 8 {
		ip := fmt.Sprintf("45.79.%d.%d", 10+i, 20+i)
		if i >= 4 {
			ip = fmt.Sprintf("50.116.%d.%d", i, 30+i)
		}
		for k := range 3 {
			s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: ip, DstIP: "43.242.97.44", DstPort: 10000 + i*100 + k, Proto: "tcp",
				Action: model.ActionDeny, Time: now.Add(time.Duration(i) * time.Minute)},
				[]model.Hit{{RuleID: "bhv-portscan", Name: "端口扫描", Category: "端口扫描", Severity: model.SevLow, Phase: model.PhaseRecon, Result: model.ResultBlocked}})
		}
	}
	// 无关的攻击源：不同运营商、不同手法
	web("192.0.2.9", "Mozilla/5.0", "z")
	web("192.0.2.77", "Mozilla/5.0 (X11)", "y")

	r := s.Campaigns()
	if r.Total != 2 {
		for _, c := range r.Campaigns {
			t.Logf("%s %d %v %v", c.ID, c.Size, c.Members, c.Reasons)
		}
		t.Fatalf("应归并出 2 个活动: %d", r.Total)
	}
	var a, b *Campaign
	for _, c := range r.Campaigns {
		switch c.Size {
		case 3:
			a = c
		case 8:
			b = c
		}
	}
	if a == nil || b == nil {
		t.Fatalf("活动成员数不对: %+v", r.Campaigns)
	}
	if len(a.Tools) != 1 || !strings.Contains(strings.Join(a.Reasons, "；"), "工具指纹") || len(a.Nets) != 2 {
		t.Fatalf("活动 A: %+v", a)
	}
	if !strings.Contains(strings.Join(b.Reasons, "；"), "同一云厂商的地址在相近时间扫描同一主机") || len(b.ASNs) != 1 ||
		!strings.Contains(b.ASNs[0], "Akamai") || b.Attacks != 24 {
		t.Fatalf("活动 B: %+v", b)
	}
	if r.Members != 11 || r.Scanned != 13 {
		t.Fatalf("统计: members=%d scanned=%d", r.Members, r.Scanned)
	}
	// 结果缓存：1 分钟内返回同一份
	if s.Campaigns() != r {
		t.Fatal("应返回缓存的结果")
	}
}

// 5000 个攻击源（其中 2000 个属于同一云厂商 ASN，形成上限大小的分桶）的归并耗时。
func BenchmarkCampaigns(b *testing.B) {
	s := New(20000, 1000, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info {
		if strings.HasPrefix(ip, "45.") {
			return &geo.Info{IP: ip, ASN: 63949, Hosting: true}
		}
		return &geo.Info{IP: ip, ASN: uint(len(ip))}
	}
	now := time.Now()
	for i := range 5000 {
		ip := fmt.Sprintf("%d.%d.%d.%d", 60+i%3, i/250%250, i%250, 1+i%7)
		if i < 2000 {
			ip = fmt.Sprintf("45.%d.%d.%d", i/250%250, i%250, 1+i%7)
		}
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: ip, DstIP: "43.242.97.44", DstPort: 1000 + i%500, Proto: "tcp", Action: model.ActionDeny, Time: now},
			[]model.Hit{{RuleID: "bhv-portscan", Name: "端口扫描", Category: "端口扫描", Severity: model.SevLow, Phase: model.PhaseRecon, Result: model.ResultBlocked}})
	}
	b.ResetTimer()
	for range b.N {
		r := s.buildCampaigns()
		if r.Scanned != 5000 {
			b.Fatal(r.Scanned)
		}
	}
}
