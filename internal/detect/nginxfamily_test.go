package detect

import (
	"strings"
	"testing"

	"netsa/internal/model"
)

// WAF（ModSecurity、naxsi、Lua WAF）与 nginx 限流记录的判定：只按设备判定生成一条命中，不重复匹配 URI 规则。
func TestWAFVerdictEvents(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		ev     model.Event
		cat    string
		sev    model.Severity
		result string
	}{
		{"modsecurity 拦截注入", model.Event{Format: "modsecurity", Threat: "SQL Injection Attack Detected via libinjection",
			ThreatCategory: "ModSecurity 942100 attack-sqli", ThreatSeverity: "high", Action: model.ActionDeny, Status: 403, URI: "/?id=1'+or+1=1"},
			CatSQLi, model.SevHigh, model.ResultBlocked},
		{"modsecurity 只告警、应用返回 200", model.Event{Format: "nginx_error", Threat: "Remote Command Execution: Unix Shell Code Found",
			ThreatCategory: "ModSecurity 932160 attack-rce", ThreatSeverity: "high", Action: model.ActionLog, Status: 200, Bytes: 900, URI: "/?c=/bin/bash"},
			CatCmdExec, model.SevHigh, model.ResultPassed},
		{"naxsi 拦截", model.Event{Format: "nginx_error", Threat: "naxsi 规则 1000", ThreatCategory: "naxsi sql injection", ThreatSeverity: "high",
			Action: model.ActionDeny, Status: 403, URI: "/?id=1+union+select"}, CatSQLi, model.SevHigh, model.ResultBlocked},
		{"limit_req 限流", model.Event{Format: "nginx_error", Threat: "nginx 限流拒绝（limit_req one）", ThreatCategory: "rate limit",
			ThreatSeverity: "low", Action: model.ActionDeny, Status: 503, URI: "/login"}, CatCC, model.SevMedium, model.ResultBlocked},
		{"Lua WAF 拦截 CC", model.Event{Format: "lua_waf", Threat: "Lua WAF 拦截（CC_Attack）", ThreatCategory: "cc attack ", ThreatSeverity: "medium",
			Action: model.ActionDeny, Status: 403, URI: "/"}, CatCC, model.SevMedium, model.ResultBlocked},
		{"WAF 识别出扫描器", model.Event{Format: "modsecurity", Threat: "Found User-Agent associated with security scanner",
			ThreatCategory: "ModSecurity 913100 attack-reputation-scanner", ThreatSeverity: "high", Action: model.ActionDeny, Status: 403, URI: "/"},
			CatScanner, model.SevHigh, model.ResultBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := c.ev
			ev.Kind, ev.SrcIP, ev.Method, ev.UA = model.KindWeb, "203.0.113.70", "GET", "Mozilla/5.0"
			hits := e.Inspect(&ev)
			if len(hits) != 1 {
				t.Fatalf("应只有设备判定一条命中: %+v", hits)
			}
			h := hits[0]
			if h.RuleID != "dev-"+ev.Format || h.Category != c.cat || h.Severity != c.sev || h.Result != c.result || h.Proven {
				t.Fatalf("%+v", h)
			}
		})
	}
}

func TestNginxFamilyRules(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("a=1&", 110)
	for _, c := range []struct{ method, uri, rule string }{
		{"GET", "/static../etc/passwd", "trav-dotdot"}, // alias 缺少结尾斜杠
		{"GET", "/assets../.git/config", "trav-dotdot"},
		{"GET", "/nginx_status", "sens-debug"},
		{"GET", "/check_status", "sens-debug"},              // Tengine 上游健康检查
		{"GET", "/req_status", "sens-debug"},                // Tengine reqstat
		{"GET", "/status/format/json", "sens-debug"},        // nginx-module-vts
		{"GET", "/apisix/prometheus/metrics", "sens-debug"}, // APISIX 指标
		{"GET", "/apisix/admin/services", "admin-probe"},    // APISIX Admin API
		{"PUT", "/apisix/admin/routes/index?api_key=edd1c9f034335f136f87ad84b625c8f1", "cve-apisix-key"},
		{"GET", "/x?cmd=os.execute('id')", "code-lua"},
		{"GET", "/x?f=io.popen(%22id%22)", "code-lua"},
		{"GET", "/x?s=require('os').execute('id')", "code-lua"},
		{"GET", "/search?" + pad + "id=1", "proto-manyargs"}, // CVE-2018-9230
		{"GET", "/upload/1.jpg/.php", "parse-vuln"},          // nginx 文件解析漏洞
		{"GET", "/upload/1.gif%20%00.php", "null-byte"},      // CVE-2013-4547
		{"POST", "/apisix/batch-requests", "vp-cve-2022-24112"},
		{"GET", "/apisix/admin/migrate/export", "vp-cve-2021-45232"},
		{"GET", "/api/backup", "vp-cve-2026-27944"}, // Nginx UI 未授权下载备份
		{"POST", "/mcp_message", "vp-cve-2026-33032"},
	} {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.71", Method: c.method, URI: c.uri, Status: 404, UA: "Mozilla/5.0"}
		if _, ok := hitIDs(e.Inspect(ev))[c.rule]; !ok {
			t.Errorf("%s %s 应命中 %s：%v", c.method, c.uri, c.rule, ruleIDs(e.Inspect(ev)))
		}
	}
}

// nginx 系产品的正常请求不应告警：Tengine 的资源合并（concat）、APISIX 转发的普通接口、普通的相对路径。
func TestNginxFamilyBenign(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{
		"/??jquery.js,bootstrap.js",
		"/static/??a.css,b.css,c.css?v=20261105",
		"/combo/??mod/a.js,mod/b.js",
		"/assets/../assets/app.js",
		"/api/user?io=open&os=linux",
		"/docs/lua?q=os.execute+example",
		"/search?" + strings.Repeat("tag=a&", 40) + "page=2",
		"/status",
		"/apisix/status",
	} {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.72", Method: "GET", URI: uri, Status: 200, Bytes: 5000, UA: "Mozilla/5.0"}
		for _, h := range e.Inspect(ev) {
			if !h.TagOnly && h.Severity >= model.SevMedium {
				t.Errorf("%s 不应告警: %+v", uri, h)
			}
		}
	}
}

func ruleIDs(hits []model.Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.RuleID)
	}
	return out
}
