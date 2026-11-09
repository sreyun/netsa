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

// 同一次 nuclei 扫描的多个出口地址：网段、运营商、手法都不同，只有载荷中的 interactsh 关联 ID 相同，归为一个活动；
// 单个地址的同源关联中也列为强关联。
func TestCampaignsOAST(t *testing.T) {
	s := New(10000, 1000, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info { return &geo.Info{IP: ip, Country: "美国", ASN: uint(len(ip)) * 1000} }
	links := map[string][]string{"c59e3crp82ke7bcnedq0.oast": {"198.51.100.10", "203.0.113.200", "192.0.2.55"}, "only-one.dnslog.cn": {"192.0.2.99"}}
	s.OASTLinks = func() map[string][]string { return links }
	now := time.Now()
	for i, ip := range []string{"198.51.100.10", "203.0.113.200", "192.0.2.55", "192.0.2.99"} {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: fmt.Sprintf("s%d.example.com", i), URI: "/x", Status: 404, UA: fmt.Sprintf("ua-%d", i), Time: now.Add(time.Duration(i) * time.Hour)},
			[]model.Hit{attackHit(fmt.Sprintf("r%d", i), fmt.Sprintf("类型%d", i), model.SevMedium, model.ResultFailed)})
	}
	r := s.buildCampaigns()
	if r.Total != 1 || r.Campaigns[0].Size != 3 {
		t.Fatalf("共用 interactsh 关联 ID 的 3 个地址应归为一个活动: %+v", r.Campaigns)
	}
	c := r.Campaigns[0]
	if len(c.OAST) != 1 || c.OAST[0] != "c59e3crp82ke7bcnedq0.oast" || !strings.Contains(strings.Join(c.Reasons, "；"), "OAST") {
		t.Fatalf("应注明关联标识与依据: %+v", c)
	}
	d := s.IPDetail("203.0.113.200")
	n := 0
	for _, x := range d.Related.Related {
		if (x.IP == "198.51.100.10" || x.IP == "192.0.2.55") && x.Score == 100 && strings.Contains(x.Reasons[0], "OAST") {
			n++
		}
	}
	if n != 2 || d.Related.Strong < 2 {
		t.Fatalf("同源关联应列出同一扫描任务的其他出口: %+v", d.Related)
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

// TLS 指纹与行为节奏：网段、运营商、UA 都不同的两个出口，JA3 相同且罕见时列为关联；行为节奏只作辅助线索。
func TestCorrelateTLSAndRhythm(t *testing.T) {
	s := New(10000, 1000, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info { return &geo.Info{IP: ip, Country: "美国", ASN: uint(len(ip)) * 1000} }
	now := time.Now()
	base := time.Date(now.Year(), now.Month(), now.Day()-4, 2, 0, 0, 0, time.Local) // 过去的时间：未来的时间会按当前时间统计
	rec := func(ip, ua, ja3 string, start time.Time, gap time.Duration, n int) {
		pfx := "r"
		if ja3 == "" {
			pfx = ip // 没有指纹的地址用各自的规则与目标：只看节奏
		}
		for i := range n {
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: pfx + ".example.com", URI: fmt.Sprintf("/%s%d", pfx, i), Status: 404, UA: ua, TLSFinger: ja3,
				Time: start.Add(time.Duration(i) * gap)}, []model.Hit{attackHit(fmt.Sprintf("%s%d", pfx, i%3), "扫描", model.SevLow, model.ResultFailed)})
		}
	}
	ja3 := "ja3:72a589da586844d7f0818ce684948eea"
	rec("198.51.100.10", "Mozilla/5.0 (A)", ja3, base, 3*time.Second, 60)
	rec("203.0.113.20", "Mozilla/5.0 (B)", ja3, base.Add(24*time.Hour), 3*time.Second, 60)
	rec("192.0.2.30", "Mozilla/5.0 (C)", "", base.Add(48*time.Hour), 3*time.Second, 60) // 只有节奏相似
	for i := range 30 {                                                                 // 其他攻击源，让 JA3 显得罕见
		rec(fmt.Sprintf("100.%d.1.1", 64+i), fmt.Sprintf("tool-%d", i), "", base, time.Minute, 2)
	}
	d := s.IPDetail("198.51.100.10")
	var tls, rhythm *RelatedIP
	for _, r := range d.Related.Related {
		switch r.IP {
		case "203.0.113.20":
			tls = r
		case "192.0.2.30":
			rhythm = r
		}
	}
	if tls == nil || !strings.Contains(strings.Join(tls.Reasons, "；"), "TLS 指纹") || !strings.Contains(strings.Join(tls.Reasons, "；"), "行为节奏") {
		t.Fatalf("JA3 相同的出口应列为关联并注明节奏相似: %+v", tls)
	}
	if rhythm != nil {
		t.Fatalf("只有节奏相似不构成关联: %+v", rhythm)
	}
	if p := s.Profile("198.51.100.10"); p.Rhythm == nil || p.Rhythm.N != 60 || p.Rhythm.Hours[2] == 0 || p.Rhythm.Gaps[2] == 0 {
		t.Fatalf("行为节奏: %+v", p.Rhythm)
	}
}

// 缓存过期后先返回上一次的结果，在后台重新归并；重新归并完成后返回新结果，同一时间只有一个后台归并。
func TestCampaignsStaleWhileRevalidate(t *testing.T) {
	s := newTestStore()
	first := s.Campaigns()
	if first == nil || s.Campaigns() != first {
		t.Fatal("有效期内应返回缓存")
	}
	s.campMu.Lock()
	first.Generated = time.Now().Add(-2 * campaignTTL)
	s.campMu.Unlock()
	if got := s.Campaigns(); got != first {
		t.Fatal("过期后应先返回上一次的结果，不等待重新归并")
	}
	s.Campaigns() // 后台归并进行中：不再启动第二个
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.campMu.Lock()
		cur, building := s.camp, s.campBuilding
		s.campMu.Unlock()
		if cur != first && !building {
			if time.Since(cur.Generated) > campaignTTL {
				t.Fatal("后台归并的结果应是新的")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("后台归并没有完成")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
