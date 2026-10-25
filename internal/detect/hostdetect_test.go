package detect

import (
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

func dnsEv(name, qtype, rcode string) *model.Event {
	return &model.Event{Kind: model.KindDNS, SrcIP: "10.0.0.5", Host: name, QType: qtype, RCode: rcode, Time: time.Now()}
}

func TestInspectDNS(t *testing.T) {
	cases := map[string]string{
		"a1b2c3.dnslog.cn":       "dns-oob",
		"x.abcdef.ceye.io":       "dns-oob",
		"pool.minexmr.com":       "dns-mining",
		"xmr-asia1.nanopool.org": "dns-mining",
		"mzxw6ytboi2dqmjqgezdgnbvgy3tqojqgeztsmzsgq2tmnzyhe4dama.t.example.com": "dns-tunnel",
		"evil.duckdns.org":     "dns-dyn",
		"xjvkqzpwmtrhb.com":    "dns-dga",
		"qx7kz9vbn2wpl4rt.net": "dns-dga",
	}
	for name, want := range cases {
		hits := inspectDNS(dnsEv(name, "A", ""))
		if len(hits) != 1 || hits[0].RuleID != want {
			t.Errorf("%s: 期望 %s，得到 %+v", name, want, hits)
		}
	}
	// 常见正常域名不误报
	for _, name := range []string{"www.google.com", "api.weixin.qq.com", "d1a2b3c4d5e6f7.cloudfront.net", "s3-us-west-2.amazonaws.com",
		"img-blog.csdnimg.cn", "update.microsoft.com", "time.windows.com", "googleusercontent.com", "login.microsoftonline.com",
		"www.example.com.cn", "kubernetes.default.svc.cluster.local", "safebrowsing.googleapis.com", "e1234.dscb.akamaiedge.net",
		"wpad.corp.example.com", "_ldap._tcp.dc._msdcs.corp.example.com"} {
		if hits := inspectDNS(dnsEv(name, "A", "")); len(hits) != 0 {
			t.Errorf("误报 %s: %+v", name, hits)
		}
	}
	if h := inspectDNS(dnsEv("xjvkqzpwmtrhb.com", "A", "NXDOMAIN")); h[0].Severity != model.SevHigh {
		t.Fatal("不存在的随机域名应为高危")
	}
	if inspectDNS(&model.Event{Kind: model.KindDNS, Host: "a.dnslog.cn", Flags: "R"}) != nil {
		t.Fatal("响应记录不重复检测")
	}
}

func TestInspectAuth(t *testing.T) {
	ev := func(id int, user, uri string) *model.Event {
		return &model.Event{Kind: model.KindAuth, EventID: id, User: user, URI: uri, Host: "DC01", SrcIP: "10.0.0.2", SubjectHost: true, Action: model.ActionAllow}
	}
	for _, c := range []struct {
		ev   *model.Event
		rule string
	}{
		{ev(1102, "eve", ""), "host-log-cleared"},
		{ev(4720, "backdoor", ""), "host-user-created"},
		{ev(4732, "backdoor", "Administrators"), "host-admin-group"},
		{ev(4732, "bob", "Remote Desktop Users"), ""},
		{ev(7045, "", "evilsvc"), "host-service-installed"},
		{&model.Event{Kind: model.KindAuth, SrcIP: "198.51.100.7", User: "root", Service: "SSH", Action: model.ActionAllow}, "auth-priv-external"},
		{&model.Event{Kind: model.KindAuth, SrcIP: "10.0.0.9", User: "root", Service: "SSH", Action: model.ActionAllow}, ""},
		{&model.Event{Kind: model.KindAuth, SrcIP: "198.51.100.7", User: "deploy", Service: "SSH", Action: model.ActionAllow}, ""},
	} {
		hits := inspectAuth(c.ev)
		got := ""
		if len(hits) > 0 {
			got = hits[0].RuleID
		}
		if got != c.rule {
			t.Errorf("%+v: 期望 %q，得到 %q", c.ev, c.rule, got)
		}
	}
}

func TestBehaviorAuthAndDNS(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	now := time.Now()
	login := func(i int, user, act string) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindAuth, SrcIP: "198.51.100.7", User: user, Service: "SSH", Host: "web01", Action: act, Time: now.Add(time.Duration(i) * time.Second)})
	}
	var rules []string
	for i, u := range []string{"root", "admin", "test", "oracle", "ubuntu", "root", "root", "root", "root", "root"} {
		for _, h := range login(i, u, model.ActionDeny) {
			rules = append(rules, h.RuleID)
		}
	}
	if len(rules) != 2 || rules[0] != "auth-spray" || rules[1] != "auth-brute" {
		t.Fatalf("密码喷洒（5 个账号）与暴力破解（10 次失败）: %v", rules)
	}
	if h := login(11, "root", model.ActionDeny); len(h) != 0 {
		t.Fatal("同一窗口内只告警一次")
	}
	h := login(12, "root", model.ActionAllow)
	if len(h) != 1 || h[0].RuleID != "auth-brute-ok" || h[0].Result != model.ResultSuccess || h[0].Severity != model.SevCritical {
		t.Fatalf("暴力破解成功: %+v", h)
	}
	// 正常运维：少量失败后成功不告警
	b2 := NewBehavior(config.Default().Detect.Thresholds)
	b2.Observe(&model.Event{Kind: model.KindAuth, SrcIP: "10.0.0.9", User: "ops", Action: model.ActionDeny, Time: now})
	if h := b2.Observe(&model.Event{Kind: model.KindAuth, SrcIP: "10.0.0.9", User: "ops", Action: model.ActionAllow, Time: now}); len(h) != 0 {
		t.Fatalf("输错一次密码不应告警: %+v", h)
	}

	// DNS：大量 NXDOMAIN
	var nx []model.Hit
	for i := 0; i < 70; i++ {
		ev := dnsEv("r"+itoa(i)+"q8x.com", "A", "NXDOMAIN")
		ev.Time = now.Add(time.Duration(i) * time.Second)
		nx = append(nx, b.Observe(ev)...)
	}
	if len(nx) != 1 || nx[0].RuleID != "dns-nxdomain" {
		t.Fatalf("NXDOMAIN 风暴: %+v", nx)
	}
	// DNS：同一主域名下大量不同子域名（每个子域名都不长，单条检测发现不了）
	var tun []model.Hit
	for i := 0; i < 200; i++ {
		ev := dnsEv("c"+itoa(i*7919)+".data.exfil.example", "A", "")
		ev.SrcIP, ev.Time = "10.0.0.6", now.Add(time.Duration(i)*time.Second)
		tun = append(tun, b.Observe(ev)...)
	}
	if len(tun) != 1 || tun[0].RuleID != "dns-tunnel-volume" {
		t.Fatalf("DNS 隧道（数量）: %+v", tun)
	}
	// 反向解析与 DNSBL 查询量大属正常
	var fp []model.Hit
	for i := 0; i < 300; i++ {
		ev := dnsEv(itoa(i)+".1.0.10.in-addr.arpa", "PTR", "")
		ev.SrcIP, ev.Time = "10.0.0.25", now
		fp = append(fp, b.Observe(ev)...)
		ev2 := dnsEv(itoa(i)+".100.51.198.zen.spamhaus.org", "A", "")
		ev2.SrcIP, ev2.Time = "10.0.0.25", now
		fp = append(fp, b.Observe(ev2)...)
	}
	if len(fp) != 0 {
		t.Fatalf("反向解析 / DNSBL 不应误报: %+v", fp[0])
	}
}
