package store

import (
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 防火墙会话证据优先于映射清单：放行但没有转发到内部服务的端口不是对外服务；有证据到达的即使未登记也是。
func TestSurfaceUsesReachEvidence(t *testing.T) {
	s := New(1000, 1000, 100, time.Hour)
	s.PortPublished = func(string, int, string) bool { return port443Only }
	fw := func(port int, reach model.Reach) {
		s.Record(&model.Event{Time: time.Now(), Kind: model.KindFirewall, SrcIP: "195.184.76.97", DstIP: "43.242.97.35",
			DstPort: port, Proto: "tcp", Action: model.ActionAllow, Reach: reach}, nil)
	}
	fw(23, model.ReachNo) // untrust → untrust：只计入被探测端口
	if rep := s.Surface(); len(rep.Services) != 0 || len(rep.Findings) != 0 {
		t.Fatalf("未到达服务的放行不应登记为对外服务: %+v %+v", rep.Services, rep.Findings)
	}
	fw(5432, model.ReachYes) // 经 DNAT 到达内网：即使清单未登记也是真实暴露
	rep := s.Surface()
	if len(rep.Services) != 1 || !rep.Services[0].Exposed || len(rep.Findings) != 1 {
		t.Fatalf("有会话证据的对外服务应登记并提示风险: %+v %+v", rep.Services, rep.Findings)
	}
}

var port443Only = false

// 单页应用 / 统一错误页把所有路径都返回同一个页面：敏感文件探测拿到的 200 不是真实内容。
func TestCatchAll200(t *testing.T) {
	s := New(1000, 1000, 100, time.Hour)
	web := func(ip, uri string, bytes int64, hits []model.Hit) RecordResult {
		return s.Record(&model.Event{Time: time.Now(), Kind: model.KindWeb, SrcIP: ip, Host: "spa.example.com", Method: "GET", URI: uri,
			Status: 200, Bytes: bytes}, hits)
	}
	for i := 0; i < 6; i++ { // 首页的正常访问：大小稳定
		web("198.51.100.1", "/", 2310, nil)
	}
	probe := func(uri string, bytes int64) *model.Alert {
		res := web("203.0.113.66", uri, bytes, []model.Hit{{RuleID: "sens-env", Name: "敏感文件探测", Category: "敏感文件探测",
			Severity: model.SevHigh, Phase: model.PhaseRecon, Result: model.ResultSuccess, Evidence: uri}})
		if len(res.Alerts) == 0 {
			return nil
		}
		return res.Alerts[0]
	}
	if a := probe("/.env", 2310); a == nil || a.Result != model.ResultPassed || a.Severity > model.SevMedium || !strings.Contains(a.Evidence, "兜底页面") {
		t.Fatalf("与首页大小相同的 200 应判定为未取到内容: %+v", a)
	}
	for _, f := range s.Surface().Findings {
		if f.Category == "敏感资源暴露" {
			t.Fatalf("兜底页面不应报敏感资源暴露: %+v", f)
		}
	}
	// 没有首页基线的站点：3 个不同敏感路径返回完全相同的大小
	s2 := New(1000, 1000, 100, time.Hour)
	var last RecordResult
	for _, uri := range []string{"/.git/config", "/backup.sql", "/.env"} {
		last = s2.Record(&model.Event{Time: time.Now(), Kind: model.KindWeb, SrcIP: "203.0.113.67", Host: "spa2.example.com", Method: "GET",
			URI: uri, Status: 200, Bytes: 5120}, []model.Hit{{RuleID: "sens", Name: "敏感文件探测", Category: "敏感文件探测",
			Severity: model.SevHigh, Phase: model.PhaseRecon, Result: model.ResultSuccess}})
	}
	if len(last.Alerts) == 0 || last.Alerts[0].Result != model.ResultPassed {
		t.Fatalf("第 3 个相同大小的探测应识别为兜底页面: %+v", last.Alerts)
	}
	// 真实存在的敏感文件（大小与首页不同）照常判定
	if a := probe("/backup.zip", 9_876_543); a == nil || a.Result != model.ResultSuccess || a.Severity < model.SevHigh {
		t.Fatalf("真实的敏感文件仍应判定为取到内容: %+v", a)
	}
	// 绕过 WAF 的路径变体反复读取同一个真实文件：大小相同是因为同一个文件，不是兜底页面
	for _, uri := range []string{"/.git/config", "//.git/config", "/./.git/config", "/.git/config;.css", "/%2egit/config", "/.git//config/"} {
		if a := probe(uri, 7_777); a == nil || a.Result != model.ResultSuccess {
			t.Fatalf("%s：同一资源的路径变体不应判为兜底页面: %+v", uri, a)
		}
	}
}

func TestResourceKey(t *testing.T) {
	for in, want := range map[string]string{
		"/.env": "/.env", "//.env": "/.env", "/./.env": "/.env", "/a/../.env": "/.env", "/.env/": "/.env", "/.env;.css": "/.env",
		"/%2e%65nv": "/.env", "/app;jsessionid=1/.env": "/app/.env", "": "/", "/": "/", "/%zz": "/%zz",
	} {
		if got := resourceKey(in); got != want {
			t.Errorf("resourceKey(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 外连威胁情报地址：会话日志记录对端无应答时，连接未建立，与被拦截同级。
func TestC2ReplyEvidence(t *testing.T) {
	for _, c := range []struct {
		reply model.Reply
		sev   model.Severity
		res   string
		text  string
	}{
		{model.ReplyNone, model.SevHigh, model.ResultFailed, "连接未建立"},
		{model.ReplyYes, model.SevCritical, model.ResultAllowed, "连接已建立"},
		{model.ReplyUnknown, model.SevCritical, model.ResultAllowed, "已放行"},
	} {
		s := New(1000, 1000, 100, time.Hour)
		s.IntelMatch = func(ip string) []string {
			if ip == "198.51.100.66" {
				return []string{"C2 地址"}
			}
			return nil
		}
		res := s.Record(&model.Event{Time: time.Now(), Kind: model.KindFirewall, SrcIP: "10.0.0.8", DstIP: "198.51.100.66", DstPort: 443,
			Proto: "tcp", Action: model.ActionAllow, Outbound: true, Reply: c.reply}, nil)
		if len(res.Alerts) != 1 || res.Alerts[0].Severity != c.sev || res.Alerts[0].Result != c.res || !strings.Contains(res.Alerts[0].Evidence, c.text) {
			t.Fatalf("应答 %d: %+v", c.reply, res.Alerts)
		}
	}
}

// 威胁情报来源首次出现时流量已被拦截 / 未到达服务：按中危记录，而不是直接高危。
func TestIntelSeverityByEvidence(t *testing.T) {
	for _, c := range []struct {
		action string
		reach  model.Reach
		sev    model.Severity
	}{
		{model.ActionDeny, model.ReachUnknown, model.SevMedium},
		{model.ActionAllow, model.ReachNo, model.SevMedium},
		{model.ActionAllow, model.ReachYes, model.SevHigh},
	} {
		s := New(1000, 1000, 100, time.Hour)
		s.IntelMatch = func(string) []string { return []string{"恶意扫描"} }
		res := s.Record(&model.Event{Time: time.Now(), Kind: model.KindFirewall, SrcIP: "198.51.100.77", DstIP: "43.242.97.35", DstPort: 23,
			Proto: "tcp", Action: c.action, Reach: c.reach}, nil)
		if res.Level != c.sev {
			t.Fatalf("%s / %d: 等级 %v，期望 %v", c.action, c.reach, res.Level, c.sev)
		}
	}
}
