package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
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

// 生产环境发现的误报：同站点的 pdf.js 预览地址、二进制协议探测、App 过期令牌的 401、高速扫描。
func TestProductionFalsePositives(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	web := func(method, uri string, status int) []model.Hit {
		return e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.90", Host: "app.example.com", Method: method, URI: uri, Status: status, Bytes: 5000, UA: "Mozilla/5.0"})
	}
	if h := hitIDs(web("GET", "/static/pdf/web/viewer.html?file=https://app.example.com:443/group1/M00/0B/53/a.pdf", 200)); h["rfi"].RuleID != "" {
		t.Errorf("本站的 pdf 预览地址不是远程文件包含: %+v", h["rfi"])
	}
	if h := hitIDs(web("GET", "/static/pdf/web/viewer.html?file=https://files.example.com/a.pdf", 200)); h["rfi"].RuleID != "" {
		t.Errorf("同一主域名的地址不是远程文件包含: %+v", h["rfi"])
	}
	// Host 头带端口、参数中的域名大写：仍是本站
	if h := hitIDs(e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.90", Host: "App.Example.com:443", Method: "GET",
		URI: "/static/pdf/web/viewer.html?file=https://APP.example.com:443/a.pdf", Status: 200, Bytes: 5000, UA: "Mozilla/5.0"})); h["rfi"].RuleID != "" {
		t.Errorf("Host 头带端口时本站的 pdf 预览地址不是远程文件包含: %+v", h["rfi"])
	}
	for _, uri := range []string{"/x.php?file=http://evil.example/shell.txt", "/x.php?file=http://app.example.com@evil.example/s.txt", "/x.php?page=http://app.example.com.evil.example/s.txt"} {
		if _, ok := hitIDs(web("GET", uri, 200))["rfi"]; !ok {
			t.Errorf("%s 应命中远程文件包含", uri)
		}
	}
	// 二进制协议发往 HTTP 端口：只是协议探测（低危），不是空字节截断
	hits := e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.91", URI: "\x00m\x00\x00\x01\x00\x00\x00\x018\x01,(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=x))))", Status: 400})
	if len(hits) != 1 || hits[0].RuleID != "proto-nonhttp" || hits[0].Name != "Oracle TNS协议探测" || hits[0].Severity > model.SevLow {
		t.Errorf("二进制协议探测: %+v", hits)
	}
}

// 高速扫描不是洪泛；集中打向一个目标的大量连接仍是洪泛。过期令牌的 401 不是暴力破解，Basic 认证与登录接口的 401 是。
func TestBehaviorScanFloodAnd401(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	now := time.Now()
	fired := func(src string, evs func(i int) *model.Event, n int) map[string]bool {
		out := map[string]bool{}
		for i := 0; i < n; i++ {
			ev := evs(i)
			ev.SrcIP, ev.Time = src, now.Add(time.Duration(i)*time.Millisecond*50)
			for _, h := range b.Observe(ev) {
				out[h.RuleID] = true
			}
		}
		return out
	}
	scan := fired("79.124.58.130", func(i int) *model.Event {
		return &model.Event{Kind: model.KindFirewall, DstIP: fmt.Sprintf("43.242.97.%d", 30+i%20), DstPort: 1024 + i*7%60000, Action: model.ActionAllow}
	}, th.FloodEvents+10)
	if scan["bhv-flood"] || !scan["bhv-portscan"] {
		t.Errorf("高速扫描应判为端口扫描而不是洪泛: %v", scan)
	}
	flood := fired("198.51.100.66", func(i int) *model.Event {
		return &model.Event{Kind: model.KindFirewall, DstIP: "43.242.97.38", DstPort: 443, Action: model.ActionAllow}
	}, th.FloodEvents+10)
	if !flood["bhv-flood"] {
		t.Errorf("集中打向一个目标应判为洪泛: %v", flood)
	}
	// 被放行、服务端正常应答的 HTTPS 连接（NAT 后面的大量用户、不断重连的长连接）：交给 Web 日志的 CC 检测，不判洪泛；
	// 没有应答的大量连接（SYN 洪泛）照常判定
	served := fired("60.2.41.105", func(i int) *model.Event {
		return &model.Event{Kind: model.KindFirewall, DstIP: "10.34.44.88", DstPort: 443, Action: model.ActionAllow, Reply: model.ReplyYes}
	}, th.FloodEvents+10)
	if served["bhv-flood"] {
		t.Errorf("正常应答的 Web 连接不应判为洪泛: %v", served)
	}
	// 策略匹配日志没有应答信息：该来源同时出现在 Web 日志中（正常访问站点）时，同样交给 CC 检测
	for i := range 20 {
		b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "60.2.41.106", Host: "mg.example.com", Method: "GET", URI: "/websocket/1/x/websocket",
			Status: 200, Time: now.Add(time.Duration(i) * time.Second)})
	}
	policyOnly := fired("60.2.41.106", func(i int) *model.Event {
		return &model.Event{Kind: model.KindFirewall, DstIP: "10.34.44.88", DstPort: 443, Action: model.ActionAllow}
	}, th.FloodEvents+10)
	if policyOnly["bhv-flood"] {
		t.Errorf("同时在 Web 日志中正常访问的来源，不应按防火墙连接数判为洪泛: %v", policyOnly)
	}
	syn := fired("198.51.100.67", func(i int) *model.Event {
		return &model.Event{Kind: model.KindFirewall, DstIP: "10.34.44.88", DstPort: 443, Action: model.ActionAllow, Reply: model.ReplyNone}
	}, th.FloodEvents+10)
	if !syn["bhv-flood"] {
		t.Errorf("没有应答的大量连接应判为洪泛: %v", syn)
	}
	// 内部来源（反向代理回源、内部漏洞扫描器）集中连接自己的服务：业务本身，不是洪泛
	for _, src := range []string{"10.34.45.31", "192.0.2.10"} {
		zone := ""
		if src == "192.0.2.10" {
			zone = "trust" // 内部安全域中的公网段地址
		}
		own := fired(src, func(i int) *model.Event {
			return &model.Event{Kind: model.KindFirewall, DstIP: "10.34.44.88", DstPort: 443, Action: model.ActionAllow, SrcZone: zone}
		}, th.FloodEvents+10)
		if own["bhv-flood"] {
			t.Errorf("内部来源 %s 的大量连接不应判为洪泛: %v", src, own)
		}
	}
	paths := []string{"/message/api/bulletins", "/uaa/api/app-menus/homepage", "/uaa/api/users/current", "/base/api/app-patches"}
	app := fired("223.160.231.63", func(i int) *model.Event {
		return &model.Event{Kind: model.KindWeb, Method: "GET", URI: paths[i%len(paths)], Status: 401}
	}, 40)
	if app["bhv-webbrute"] {
		t.Errorf("过期令牌的 401 不是暴力破解: %v", app)
	}
	basic := fired("198.51.100.67", func(i int) *model.Event {
		return &model.Event{Kind: model.KindWeb, Method: "GET", URI: "/admin/", Status: 401, User: fmt.Sprintf("user%d", i)}
	}, 40)
	if !basic["bhv-webbrute"] {
		t.Errorf("Basic 认证反复失败应判为暴力破解: %v", basic)
	}
	// 线上实例：开发人员的脚本不带令牌轮询 GET /auth/bootstrap（401），页面每输入一个字符校验一次口令强度、
	// 登录前预检是否需要验证码。都不是提交口令。
	for name, mk := range map[string]func(i int) *model.Event{
		"会话引导轮询": func(int) *model.Event {
			return &model.Event{Kind: model.KindWeb, Method: "GET", URI: "/waterbuddy/api/waterbuddy/auth/bootstrap", Status: 401}
		},
		"口令强度校验": func(int) *model.Event {
			return &model.Event{Kind: model.KindWeb, Method: "POST", URI: "/uaa/api/users/validate-password-strength", Status: 200}
		},
		"验证码预检": func(int) *model.Event {
			return &model.Event{Kind: model.KindWeb, Method: "POST", URI: "/auth/hasCodeValidate", Status: 200}
		},
	} {
		if got := fired("113.57.107.46", mk, 40); got["bhv-webbrute"] {
			t.Errorf("%s不是暴力破解: %v", name, got)
		}
	}
	form := fired("198.51.100.68", func(int) *model.Event {
		return &model.Event{Kind: model.KindWeb, Method: "POST", URI: "/auth/login", Status: 200}
	}, 40)
	if !form["bhv-webbrute"] {
		t.Errorf("反复提交登录表单应判为暴力破解: %v", form)
	}
}

// 周期性外连：ICMP 定时 ping 与多台主机同规律连接同一地址（统一部署的代理）降为低危，单台主机的 TCP 心跳仍为中危。
func TestBeaconNoiseReduced(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	now := time.Now()
	beacon := func(src, dst string, port int, proto string) []model.Hit {
		var out []model.Hit
		for i := 0; i < th.BeaconConns+2; i++ {
			ev := &model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: proto, Action: model.ActionAllow,
				Outbound: true, Time: now.Add(time.Duration(i) * 5 * time.Minute)}
			out = append(out, b.Observe(ev)...)
		}
		return out
	}
	sev := func(hits []model.Hit) model.Severity {
		for _, h := range hits {
			if h.RuleID == "bhv-beacon" {
				return h.Severity
			}
		}
		return -1
	}
	if s := sev(beacon("10.0.0.50", "198.51.100.80", 443, "tcp")); s != model.SevMedium {
		t.Errorf("单台主机的定时外连应为中危: %v", s)
	}
	if s := sev(beacon("10.0.0.51", "198.51.100.81", 2048, "icmp")); s != model.SevLow {
		t.Errorf("定时 ping 应为低危: %v", s)
	}
	beacon("10.0.0.52", "34.120.177.193", 443, "tcp")
	beacon("10.0.0.53", "34.120.177.193", 443, "tcp")
	if s := sev(beacon("10.0.0.54", "34.120.177.193", 443, "tcp")); s != model.SevLow {
		t.Errorf("第 3 台以同样规律连接同一地址的主机应为低危: %v", s)
	}
}
