package pipeline

import (
	"context"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/store"
)

func TestRealIP(t *testing.T) {
	r := NewRealIP(config.RealIPConfig{TrustedProxies: []string{"10.0.0.0/8", "127.0.0.1"}})

	cases := []struct{ peer, xff, want string }{
		{"10.0.0.2", "1.1.1.1, 198.51.100.7, 10.0.0.3", "198.51.100.7"}, // 跳过可信代理，忽略左侧可伪造部分
		{"10.0.0.2", "198.51.100.8:51234", "198.51.100.8"},              // 带端口
		{"10.0.0.2", `"[2001:db8::7]:443", 10.0.0.3`, "2001:db8::7"},    // IPv6 方括号+端口
		{"10.0.0.2", "unknown, 198.51.100.9", "198.51.100.9"},           // 混淆标识
		{"10.0.0.2", "::ffff:198.51.100.10", "198.51.100.10"},           // IPv4 映射地址
		{"10.0.0.2", "10.0.0.5, 10.0.0.6", "10.0.0.5"},                  // 全部可信时取最左侧
	}
	for _, c := range cases {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: c.peer, XFF: c.xff}
		r.Apply(ev)
		if ev.SrcIP != c.want || ev.PeerIP != c.peer {
			t.Errorf("xff=%q => src=%s peer=%s, want %s", c.xff, ev.SrcIP, ev.PeerIP, c.want)
		}
	}

	// 非可信直连：忽略 XFF，若伪造回环地址则产生命中
	ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", XFF: "127.0.0.1"}
	if h := r.Apply(ev); h == nil || h.RuleID != "spoof-xff" || ev.SrcIP != "203.0.113.9" {
		t.Fatalf("应识别 XFF 伪造且不改写来源: %+v %+v", h, ev)
	}

	// Cloudflare 预设 + CF-Connecting-IP 优先，并识别绕过 CDN 直连源站
	cf := NewRealIP(config.RealIPConfig{Headers: []string{"cf_connecting_ip", "x_forwarded_for"}, TrustedPresets: []string{"cloudflare"}, CDNOnly: true})
	ev = &model.Event{Kind: model.KindWeb, SrcIP: "162.158.1.2", XFF: "203.0.113.50", ClientHeaders: map[string]string{"cf_connecting_ip": "198.51.100.66"}}
	cf.Apply(ev)
	if ev.SrcIP != "198.51.100.66" {
		t.Fatalf("应采用 CF-Connecting-IP: %+v", ev)
	}
	ev = &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.77"}
	if h := cf.Apply(ev); h == nil || h.RuleID != "cdn-bypass" {
		t.Fatalf("应识别绕过 CDN 直连: %+v", h)
	}

	// RFC 7239 Forwarded
	fw := NewRealIP(config.RealIPConfig{Headers: []string{"forwarded"}, TrustedProxies: []string{"10.0.0.0/8"}})
	ev = &model.Event{Kind: model.KindWeb, SrcIP: "10.0.0.2", ClientHeaders: map[string]string{"forwarded": `for=192.0.2.60;proto=https, for="[2001:db8:cafe::17]:4711"`}}
	fw.Apply(ev)
	if ev.SrcIP != "2001:db8:cafe::17" {
		t.Fatalf("Forwarded 解析错误: %s", ev.SrcIP)
	}
}

func TestPipelineEndToEnd(t *testing.T) {
	cfg := config.Default()
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(1000, 1000, 5, time.Hour)
	var alerts []*model.Alert
	p := &Pipeline{
		Engine: eng, Behavior: detect.NewBehavior(cfg.Detect.Thresholds), Store: st,
		RealIP: NewRealIP(cfg.RealIP), OnAlert: func(a *model.Alert) { alerts = append(alerts, a) },
	}
	p.SetWhitelist([]string{"192.0.2.0/24"})

	in := make(chan []*model.Event, 100)
	done := p.Run(context.Background(), in, 2)
	now := time.Now()
	in <- []*model.Event{&model.Event{Kind: model.KindWeb, SrcIP: "10.0.0.2", XFF: "198.51.100.7", Method: "GET", URI: "/.git/config", Status: 200, Bytes: 300, Time: now}}
	in <- []*model.Event{&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.8", Method: "GET", URI: "/p?id=1%20union%20select%201,2", Status: 403, Time: now}, &model.Event{Kind: model.KindWeb, SrcIP: "192.0.2.5", Method: "GET", URI: "/p?id=1%20union%20select%201,2", Status: 200, Time: now}}
	close(in)
	<-done

	if p.Processed() != 3 {
		t.Fatalf("processed=%d", p.Processed())
	}
	if prof := st.Profile("198.51.100.7"); prof == nil || prof.Successes != 1 || prof.Level < model.SevMedium {
		t.Fatalf("真实 IP 画像异常: %+v", prof)
	}
	if prof := st.Profile("192.0.2.5"); prof == nil || prof.Attacks != 0 {
		t.Fatalf("白名单 IP 不应产生攻击: %+v", prof)
	}
	if len(alerts) == 0 {
		t.Fatal("未产生告警")
	}
	sf := st.Surface()
	if len(sf.Findings) == 0 {
		t.Fatal("应产生 .git 泄露的攻击面发现")
	}
	o := st.Overview()
	if o.Totals.Blocked != 1 || o.Attackers != 2 {
		t.Fatalf("overview: %+v", o.Totals)
	}
}
