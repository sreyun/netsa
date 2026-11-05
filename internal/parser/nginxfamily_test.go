package parser

import (
	"testing"

	"netsa/internal/model"
)

// Tengine、OpenResty、Kong 的访问日志与 nginx 相同；APISIX、Nginx Proxy Manager 的默认格式不同，均应自动识别。
func TestNginxFamilyAccessLogs(t *testing.T) {
	cases := []struct {
		name, line, format, src, host, method, uri, ua string
		status                                         int
		bytes                                          int64
		reqTime                                        float64
	}{
		{"tengine", `203.0.113.5 - - [05/Nov/2026:10:00:00 +0800] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "curl/8.0" "-"`,
			"nginx_combined", "203.0.113.5", "", "GET", "/index.php?id=1", "curl/8.0", 200, 512, 0},
		{"kong", `203.0.113.6 - - [05/Nov/2026:10:00:00 +0800] "GET /orders?id=2 HTTP/1.1" 200 41 "-" "curl/8.0" kong_request_id: "8f1e2a7c5b0d4e6f9a3c1b2d4e6f8a0c"`,
			"nginx_combined", "203.0.113.6", "", "GET", "/orders?id=2", "curl/8.0", 200, 41, 0},
		{"apisix", `203.0.113.7 - - [05/Nov/2026:10:00:00 +0800] api.example.com:9080 "GET /hello?x=1 HTTP/1.1" 200 12 0.002 "-" "curl/8.0" 10.0.0.5:8080 200 0.001 "http://10.0.0.5:8080/hello?x=1"`,
			"apisix", "203.0.113.7", "api.example.com", "GET", "/hello?x=1", "curl/8.0", 200, 12, 0.002},
		{"apisix 无上游", `203.0.113.8 - - [05/Nov/2026:10:00:00 +0800] - "GET /nope HTTP/1.1" 404 47 0.000 "-" "Mozilla/5.0 (X11)" - - - "http://-"`,
			"apisix", "203.0.113.8", "", "GET", "/nope", "Mozilla/5.0 (X11)", 404, 47, 0},
		{"nginx proxy manager", `[05/Nov/2026:10:00:00 +0800] - 200 200 - GET https shop.example.com "/item.php?id=1%27" [Client 203.0.113.9] [Length 1234] [Gzip 3.21] [Sent-to 10.0.0.6] "Mozilla/5.0" "https://shop.example.com/"`,
			"nginx_proxy_manager", "203.0.113.9", "shop.example.com", "GET", "/item.php?id=1%27", "Mozilla/5.0", 200, 1234, 0},
		{"nginx proxy manager standard", `[05/Nov/2026:10:00:00 +0800] 404 - POST http 198.51.100.3 "/.env" [Client 203.0.113.10] [Length 150] [Gzip -] "python-requests/2.31" "-"`,
			"nginx_proxy_manager", "203.0.113.10", "198.51.100.3", "POST", "/.env", "python-requests/2.31", 404, 150, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mustAuto(t, "auto", "")
			ev, ok := p.Parse(c.line)
			if !ok {
				t.Fatalf("未能解析: %s", c.line)
			}
			if ev.Format != c.format || ev.Kind != model.KindWeb || ev.SrcIP != c.src || ev.Host != c.host || ev.Method != c.method ||
				ev.URI != c.uri || ev.UA != c.ua || ev.Status != c.status || ev.Bytes != c.bytes || ev.ReqTime != c.reqTime {
				t.Fatalf("%+v", ev)
			}
			if ev.Time.Year() != 2026 {
				t.Fatalf("时间: %v", ev.Time)
			}
		})
	}
}

// Tengine 的毫秒、微秒耗时与 Unix 时间变量。
func TestTengineLogFormatVars(t *testing.T) {
	p := mustAuto(t, "nginx", `$remote_addr:$remote_port $unix_time "$request" $status $body_bytes_sent $request_time_msec "$http_user_agent" $host`)
	ev, ok := p.Parse(`203.0.113.5:51234 1793930400 "GET /a HTTP/1.1" 200 33 1250 "UA" shop.example.com`)
	if !ok {
		t.Fatal("解析失败")
	}
	if ev.ReqTime != 1.25 || ev.SrcPort != 51234 || ev.Time.Unix() != 1793930400 || ev.Host != "shop.example.com" {
		t.Fatalf("%+v", ev)
	}
	p = mustAuto(t, "nginx", `$remote_addr [$time_local] "$request" $status $body_bytes_sent $request_time_usec`)
	if ev, ok = p.Parse(`203.0.113.5 [05/Nov/2026:10:00:00 +0800] "GET /a HTTP/1.1" 200 33 2500000`); !ok || ev.ReqTime != 2.5 {
		t.Fatalf("%v %+v", ok, ev)
	}
}

// APISIX、Kong 日志插件的 JSON：请求、响应是嵌套对象，时间是毫秒时间戳，耗时以毫秒计。
func TestGatewayJSONLogs(t *testing.T) {
	cases := []struct {
		name, line, host, uri, ua string
		status                    int
		reqTime                   float64
	}{
		{"apisix", `{"client_ip":"203.0.113.20","route_id":"1","request":{"method":"GET","uri":"/api/user?id=1","url":"http://api.example.com:9080/api/user?id=1","size":86,"headers":{"host":"api.example.com","user-agent":"curl/8.0"},"querystring":{"id":"1"}},"response":{"status":200,"size":120,"headers":{}},"upstream":"10.0.0.5:8080","latency":12.5,"apisix_latency":1.2,"start_time":1793930400123,"server":{"hostname":"gw01","version":"3.9.0"}}`,
			"api.example.com", "/api/user?id=1", "curl/8.0", 200, 0.0125},
		{"kong", `{"client_ip":"203.0.113.21","started_at":1793930400456,"request":{"method":"POST","uri":"/login","url":"https://kong.example.com:8443/login","size":120,"querystring":{},"headers":{"host":"kong.example.com","user-agent":"Mozilla/5.0"}},"response":{"status":401,"size":64,"headers":{}},"latencies":{"request":35,"kong":2,"proxy":33},"route":{"id":"r1"},"service":{"id":"s1"}}`,
			"kong.example.com", "/login", "Mozilla/5.0", 401, 0.035},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := mustAuto(t, "auto", "").Parse(c.line)
			if !ok {
				t.Fatalf("未能解析: %s", c.line)
			}
			if ev.Host != c.host || ev.URI != c.uri || ev.UA != c.ua || ev.Status != c.status || ev.ReqTime != c.reqTime || ev.Time.Unix() != 1793930400 {
				t.Fatalf("%+v", ev)
			}
		})
	}
}

// ModSecurity JSON 审计日志（v3 与 v2）：取出说明攻击类型的规则作为 WAF 的判定。
func TestModSecurityAuditJSON(t *testing.T) {
	v3 := `{"transaction":{"client_ip":"203.0.113.30","time_stamp":"Thu Nov  5 10:00:00 2026","server_id":"x","client_port":51000,"host_ip":"172.17.0.2","host_port":80,"unique_id":"177","request":{"method":"GET","http_version":1.1,"uri":"/?id=1%27%20or%201=1","headers":{"Host":"www.example.com","User-Agent":"sqlmap/1.8"}},"response":{"http_code":403,"headers":{}},"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)","connector":"ModSecurity-nginx v1.0.3","secrules_engine":"Enabled","components":["OWASP_CRS/4.4.0"]},"messages":[{"message":"Inbound Anomaly Score Exceeded (Total Score: 10)","details":{"ruleId":"949110","severity":"0","tags":["anomaly-evaluation"]}},{"message":"SQL Injection Attack Detected via libinjection","details":{"ruleId":"942100","severity":"2","tags":["application-multi","attack-sqli","paranoia-level/1"]}}]}}`
	ev, ok := mustAuto(t, "auto", "").Parse(v3)
	if !ok {
		t.Fatal("v3 未能解析")
	}
	if ev.Format != "modsecurity" || ev.SrcIP != "203.0.113.30" || ev.Status != 403 || ev.Host != "www.example.com" || ev.UA != "sqlmap/1.8" ||
		ev.Threat != "SQL Injection Attack Detected via libinjection" || ev.Action != model.ActionDeny || ev.ThreatSeverity != "high" ||
		ev.ThreatCategory != "ModSecurity 942100 attack-sqli" || ev.Time.Year() != 2026 {
		t.Fatalf("%+v", ev)
	}
	v2 := `{"transaction":{"time":"05/Nov/2026:10:00:00.123456 +0800","transaction_id":"abc","remote_address":"203.0.113.31","remote_port":51001,"local_address":"10.0.0.2","local_port":80},"request":{"request_line":"GET /index.php?file=../../etc/passwd HTTP/1.1","headers":{"Host":"www.example.com","User-Agent":"curl/8.0"}},"response":{"protocol":"HTTP/1.1","status":403,"headers":{}},"audit_data":{"messages":["Warning. Matched phrase \"etc/passwd\" at ARGS:file. [file \"/etc/crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf\"] [line \"97\"] [id \"930120\"] [msg \"OS File Access Attempt\"] [data \"Matched Data: etc/passwd found within ARGS:file: ../../etc/passwd\"] [severity \"CRITICAL\"] [ver \"OWASP_CRS/3.3.5\"] [tag \"attack-lfi\"]","Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. [id \"949110\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 5)\"] [severity \"CRITICAL\"]"],"action":{"intercepted":true,"phase":2},"producer":["ModSecurity for Apache/2.9.7","OWASP_CRS/3.3.5"],"engine_mode":"ENABLED"}}`
	ev, ok = mustAuto(t, "auto", "").Parse(v2)
	if !ok {
		t.Fatal("v2 未能解析")
	}
	if ev.Format != "modsecurity" || ev.SrcIP != "203.0.113.31" || ev.Method != "GET" || ev.URI != "/index.php?file=../../etc/passwd" ||
		ev.Threat != "OS File Access Attempt" || ev.Action != model.ActionDeny || ev.Time.Year() != 2026 {
		t.Fatalf("%+v", ev)
	}
	// 只因响应码被审计记录（没有规则命中）：按普通访问处理
	plain := `{"transaction":{"client_ip":"203.0.113.32","time_stamp":"Thu Nov  5 10:00:00 2026","request":{"method":"GET","uri":"/missing","headers":{"Host":"www.example.com"}},"response":{"http_code":500},"producer":{"secrules_engine":"Enabled"},"messages":[]}}`
	if ev, ok = mustAuto(t, "auto", "").Parse(plain); !ok || ev.Threat != "" || ev.Status != 500 || ev.URI != "/missing" {
		t.Fatalf("%v %+v", ok, ev)
	}
}

// OpenResty Lua WAF（unixhot/waf）的拦截日志：没有状态码，记录的都是已拦截的请求。
func TestLuaWAFLog(t *testing.T) {
	line := `{"client_ip":"203.0.113.40","local_time":"2026-11-05 10:00:00","server_name":"www.example.com","user_agent":"sqlmap/1.8","attack_method":"Deny_URL_Args","req_url":"/index.php?id=1 union select 1","req_data":"-","rule_tag":"select.+(from|limit)"}`
	ev, ok := mustAuto(t, "auto", "").Parse(line)
	if !ok {
		t.Fatal("未能解析")
	}
	if ev.Format != "lua_waf" || ev.SrcIP != "203.0.113.40" || ev.Status != 403 || ev.Action != model.ActionDeny || ev.URI != "/index.php?id=1 union select 1" ||
		ev.Host != "www.example.com" || ev.Threat == "" || ev.Time.Year() != 2026 {
		t.Fatalf("%+v", ev)
	}
}

// nginx / Tengine / OpenResty 的错误日志：WAF 拦截与限流产生事件，其余错误识别为可跳过的行。
func TestNginxErrorLog(t *testing.T) {
	p := mustAuto(t, "auto", "")
	cases := []struct {
		name, line, src, host, uri, threat, action string
		status                                     int
	}{
		{"modsecurity v3 拦截", `2026/11/05 10:00:00 [error] 31#31: *1 [client 203.0.113.50] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator ` + "`Ge'" + ` with parameter ` + "`5'" + ` against variable ` + "`TX:ANOMALY_SCORE'" + ` (Value: ` + "`5'" + ` ) [file "/etc/nginx/modsec/coreruleset/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "80"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data ""] [severity "2"] [ver "OWASP_CRS/3.3.4"] [maturity "0"] [accuracy "0"] [tag "anomaly-evaluation"] [hostname "172.17.0.2"] [uri "/"] [unique_id "1700000000"] [ref ""], client: 203.0.113.50, server: localhost, request: "GET /?id=1%27%20or%201=1 HTTP/1.1", host: "www.example.com"`,
			"203.0.113.50", "www.example.com", "/?id=1%27%20or%201=1", "Inbound Anomaly Score Exceeded (Total Score: 5)", model.ActionDeny, 403},
		{"modsecurity v3 告警", `2026/11/05 10:00:00 [warn] 31#31: *2 ModSecurity: Warning. detected SQLi using libinjection. [file "/etc/nginx/modsec/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "46"] [id "942100"] [rev ""] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: s&sos found within ARGS:id: 1' or 1=1"] [severity "2"] [ver "OWASP_CRS/3.3.4"] [tag "attack-sqli"] [hostname "172.17.0.2"] [uri "/"] [unique_id "1700000001"] [ref "v8,10"], client: 203.0.113.51, server: localhost, request: "GET /?id=1%27%20or%201=1 HTTP/1.1", host: "www.example.com:8080"`,
			"203.0.113.51", "www.example.com", "/?id=1%27%20or%201=1", "SQL Injection Attack Detected via libinjection", model.ActionLog, 0},
		{"naxsi", `2026/11/05 10:00:00 [error] 12#0: *3 NAXSI_FMT: ip=203.0.113.52&server=www.example.com&uri=/index.php&vers=1.3&total_processed=10&total_blocked=1&config=block&cscore0=$SQL&score0=8&zone0=ARGS&id0=1000&var_name0=id, client: 203.0.113.52, server: www.example.com, request: "GET /index.php?id=1%20union%20select HTTP/1.1", host: "www.example.com"`,
			"203.0.113.52", "www.example.com", "/index.php?id=1%20union%20select", "naxsi 规则 1000", model.ActionDeny, 403},
		{"limit_req", `2026/11/05 10:00:00 [error] 12#0: *4 limiting requests, excess: 20.500 by zone "one", client: 203.0.113.53, server: www.example.com, request: "POST /login HTTP/1.1", host: "www.example.com", referrer: "https://www.example.com/"`,
			"203.0.113.53", "www.example.com", "/login", "nginx 限流拒绝（limit_req one）", model.ActionDeny, 503},
		{"limit_conn", `2026/11/05 10:00:00 [error] 12#0: *5 limiting connections by zone "addr", client: 203.0.113.54, server: www.example.com, request: "GET /video.mp4 HTTP/1.1", host: "www.example.com"`,
			"203.0.113.54", "www.example.com", "/video.mp4", "nginx 限流拒绝（limit_conn addr）", model.ActionDeny, 503},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := p.Parse(c.line)
			if !ok {
				t.Fatalf("未能解析: %s", c.line)
			}
			if ev.Format != "nginx_error" || ev.Kind != model.KindWeb || ev.SrcIP != c.src || ev.Host != c.host || ev.URI != c.uri ||
				ev.Threat != c.threat || ev.Action != c.action || ev.Status != c.status || ev.Time.Year() != 2026 {
				t.Fatalf("%+v", ev)
			}
		})
	}
	// 与安全无关的错误、只记录评分汇总的告警：不产生事件，但属于已识别的格式
	for _, line := range []string{
		`2026/11/05 10:00:00 [error] 12#0: *6 open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory), client: 203.0.113.55, server: localhost, request: "GET /favicon.ico HTTP/1.1", host: "www.example.com"`,
		`2026/11/05 10:00:00 [error] 12#0: *7 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 203.0.113.56, server: www.example.com, request: "GET /api HTTP/1.1", upstream: "http://10.0.0.5:8080/api", host: "www.example.com"`,
		`2026/11/05 10:00:00 [notice] 1#1: signal process started`,
		`2026/11/05 10:00:00 [warn] 1#1: *8 a client request body is buffered to a temporary file /var/cache/nginx/client_temp/0000000001, client: 203.0.113.57, server: www.example.com, request: "POST /upload HTTP/1.1", host: "www.example.com"`,
		`2026/11/05 10:00:00 [warn] 31#31: *9 ModSecurity: Warning. Matched "Operator ` + "`Ge'" + `" [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"], client: 203.0.113.58, server: localhost, request: "GET / HTTP/1.1", host: "www.example.com"`,
		`2026/11/05 10:00:00 [warn] 12#0: *10 delaying request, excess: 0.500, by zone "one", client: 203.0.113.59, server: www.example.com, request: "GET / HTTP/1.1", host: "www.example.com"`,
		`2026/11/05 10:00:00 [error] 7#7: *11 [lua] init.lua:12: something failed, client: 203.0.113.60, server: www.example.com, request: "GET / HTTP/1.1", host: "www.example.com"`,
	} {
		if ev, ok := p.Parse(line); ok {
			t.Errorf("不应产生事件: %+v", ev)
		}
		if !p.Known(line) {
			t.Errorf("应识别为可跳过的行: %s", line)
		}
	}
	// 经 syslog 转发的错误日志
	if !p.Known(`<187>Nov  5 10:00:00 web01 nginx: 2026/11/05 10:00:00 [error] 12#0: *6 open() "/x" failed (2: No such file or directory), client: 203.0.113.55, server: localhost, request: "GET /x HTTP/1.1"`) {
		t.Error("syslog 转发的错误日志应识别")
	}
	if p.Known("garbage line that is not a log") || p.Known(`203.0.113.5 - - [bad`) {
		t.Error("不认识的行不能当作已知格式")
	}
}

// 只排除数字形式的 request（嵌套字段的耗时），非 HTTP 请求行、"-" 照常解析。
func TestJSONRequestNotNumeric(t *testing.T) {
	for line, uri := range map[string]string{
		`{"remote_addr":"203.0.113.80","request":"-","status":"400","body_bytes_sent":"0"}`:                        "",
		`{"remote_addr":"203.0.113.81","request":"\u0016\u0003\u0001\u0000","status":"400","body_bytes_sent":"0"}`: "\x16\x03\x01\x00",
	} {
		ev, ok := mustAuto(t, "auto", "").Parse(line)
		if !ok || ev.URI != uri {
			t.Errorf("%v %+v", ok, ev)
		}
	}
}

// 华为、H3C 的运维日志（命令记录等）没有地址字段：计为跳过；带地址字段却解析失败的仍算失败。
func TestHuaweiOperationLogsSkipped(t *testing.T) {
	p := mustAuto(t, "auto", "")
	for _, line := range []string{
		`<190>2026/11/5 04:22:59 USG6300 %%01SHELL/6/DISPLAY_CMDRECORD(s)[82531]:记录显示命令信息。（任务＝FW，地址＝**，VPN实例名=，用户＝_system_，认证方式="Null"，命令＝"display ipsec backup statistics send"）`,
		`<190>Nov  5 2026 04:44:58 USG6630E %%01SHELL/6/DISPLAY_CMDRECORD(s)[108663]:Recorded display command information. (Task=FW, Ip=**, VpnName=, User=_system_, AuthenticationMethod="Null", Command="display firewall statistics system normal")`,
		`<188>Nov  5 2026 04:45:00 H3C %%10IFNET/3/PHY_UPDOWN: Physical state on the interface GigabitEthernet1/0/1 changed to down.`,
	} {
		if _, ok := p.Parse(line); ok {
			t.Errorf("不应产生事件: %s", line)
		}
		if !p.Known(line) {
			t.Errorf("应识别为可跳过的运维日志: %s", line)
		}
	}
	if p.Known(`<190>Nov  5 2026 04:45:00 USG %%01SECIF/6/POLICYDENY(l)[0]:SourceIP=bad-value`) {
		t.Error("带地址字段却解析失败的行应计为失败")
	}
}
