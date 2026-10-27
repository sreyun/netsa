package parser

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHexToJSON(t *testing.T) {
	for in, want := range map[string]string{
		`a\x22b`:                   `a\"b`,
		`a\x5Cb`:                   `a\\b`,
		`\xE4\xB8\xAD\xE6\x96\x87`: "中文",
		`a\x0Ab`:                   `a\u000ab`,
		`a\\x22b`:                  `a\\x22b`, // 已转义的反斜杠后的 x22 是普通文本
		`a\xZZb`:                   `a\xZZb`,
		`a\"b\n`:                   `a\"b\n`,
		`tail\x2`:                  `tail\x2`,
	} {
		if got := string(hexToJSON(in)); got != want {
			t.Errorf("hexToJSON(%s) = %s，期望 %s", in, got, want)
		}
	}
}

func TestNginxJSONDefaultEscape(t *testing.T) {
	// log_format 未加 escape=json：引号、中文被写成 \xHH，整行不是合法 JSON
	line := `{"time_local":"26/Oct/2026:10:00:00 +0800","remote_addr":"198.51.100.12","request":"GET /?q=\x22><script>alert(1)</script>&name=\xE4\xB8\xAD\xE6\x96\x87 HTTP/1.1","status":"200","http_user_agent":"Mozilla/5.0 \x22quoted\x22 \x5C","http_referer":"-"}`
	ev, ok := NginxJSON{}.Parse(line)
	if !ok {
		t.Fatal("未加 escape=json 的 JSON 日志应能解析")
	}
	if ev.URI != `/?q="><script>alert(1)</script>&name=中文` || ev.UA != `Mozilla/5.0 "quoted" \` || ev.Method != "GET" || ev.SrcIP != "198.51.100.12" || ev.Referer != "" {
		t.Fatalf("字段还原错误: uri=%q ua=%q method=%s ip=%s ref=%q", ev.URI, ev.UA, ev.Method, ev.SrcIP, ev.Referer)
	}
	// 合法 JSON 中的 \\x22 是字面文本，不做还原
	ev, ok = NginxJSON{}.Parse(`{"remote_addr":"198.51.100.12","request":"GET /a?b=\\x22 HTTP/1.1","status":"200"}`)
	if !ok || ev.URI != `/a?b=\x22` {
		t.Fatalf("合法 JSON 不应改动: %+v", ev)
	}
}

func TestNginxJSONECS(t *testing.T) {
	// Elastic ECS：url.original 与 user_agent.original、source.ip 与 host.ip、url.path 与 log.file.path 的最后一级键同名
	line := `{"@timestamp":"2026-10-26T02:00:00Z","source":{"ip":"198.51.100.15"},"host":{"ip":["10.0.0.5"],"name":"web01"},` +
		`"log":{"file":{"path":"/var/log/nginx/access.log"}},"http":{"version":"1.1","request":{"method":"GET","referrer":"https://ref.example/"},` +
		`"response":{"status_code":404,"body":{"bytes":153}}},"url":{"original":"/wp-login.php?x=1","path":"/wp-login.php","domain":"www.example.com"},` +
		`"user_agent":{"original":"Mozilla/5.0"}}`
	for i := 0; i < 20; i++ { // 字段展开顺序随机，多次解析结果须一致
		ev, ok := NginxJSON{}.Parse(line)
		if !ok || ev.SrcIP != "198.51.100.15" || ev.URI != "/wp-login.php?x=1" || ev.UA != "Mozilla/5.0" || ev.Status != 404 || ev.Bytes != 153 ||
			ev.HTTPProto != "HTTP/1.1" || ev.Host != "www.example.com" || ev.Referer != "https://ref.example/" || ev.Method != "GET" {
			t.Fatalf("ECS 字段: %+v", ev)
		}
	}
	// 只有 url.path / url.query 时拼出完整路径
	ev, ok := NginxJSON{}.Parse(`{"source":{"ip":"198.51.100.16"},"http":{"request":{"method":"GET"},"response":{"status_code":200}},"url":{"path":"/s","query":"q=1"}}`)
	if !ok || ev.URI != "/s?q=1" {
		t.Fatalf("url.path + url.query: %+v", ev)
	}
}

func TestFlattenLower(t *testing.T) {
	var m map[string]any
	json.Unmarshal([]byte(`{"a":{"Name":"deep"},"name":"top","b":{"c":{"name":"deeper"}},"ip":"","x":{"ip":"1.2.3.4"}}`), &m)
	kv := flattenLower(m)
	if kv["name"] != "top" || kv["a.name"] != "deep" || kv["b.c.name"] != "deeper" || kv["ip"] != "1.2.3.4" || kv["x.ip"] != "1.2.3.4" {
		t.Fatalf("展开结果: %v", kv)
	}
	// 深层嵌套：限制层级，不拼接超长的路径键
	deep := strings.Repeat(`{"a":`, 5000) + `1` + strings.Repeat(`}`, 5000)
	m = nil
	if err := json.Unmarshal([]byte(deep), &m); err != nil {
		t.Fatal(err)
	}
	for k := range flattenLower(m) {
		if len(k) > 2*maxFlattenDepth {
			t.Fatalf("路径键过长: %d", len(k))
		}
	}
}

const wrapNginx = `203.0.113.5 - - [26/Oct/2026:10:15:01 +0800] "GET /index.php?id=1%27%20or%201=1 HTTP/1.1" 200 512 "-" "sqlmap/1.7"`

func marshalStr(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAutoWrapped(t *testing.T) {
	docker := marshalStr(t, map[string]string{"log": wrapNginx + "\n", "stream": "stdout", "time": "2026-10-26T02:15:01.123456789Z"})
	filebeat := `{"@timestamp":"2026-10-26T02:00:00Z","log":{"offset":1,"file":{"path":"/var/log/nginx/access.json"}},` +
		`"message":"{\"remote_addr\":\"198.51.100.14\",\"request\":\"GET /.env HTTP/1.1\",\"status\":\"404\"}","host":{"name":"web01","ip":["10.0.0.5"]}}`
	cri := `2026-10-26T10:15:01.123456789+08:00 stdout F ` + wrapNginx
	nested := marshalStr(t, map[string]string{"message": docker}) // 采集器转发的 Docker 日志：两层包装

	for _, c := range []struct {
		name, line, detected, ip string
	}{
		{"Docker json-file", docker, "nginx（log 字段包装）", "203.0.113.5"},
		{"Filebeat message", filebeat, "nginx_json（message 字段包装）", "198.51.100.14"},
		{"CRI", cri, "nginx（容器 CRI 包装）", "203.0.113.5"},
		{"两层包装", nested, "nginx（message 字段包装）", "203.0.113.5"},
	} {
		p := mustAuto(t, "auto", "")
		for i := 0; i < 5; i++ {
			ev, ok := p.Parse(c.line)
			if !ok || ev.SrcIP != c.ip || ev.Kind != "web" || strings.HasPrefix(ev.Raw, "{") && c.name != "Filebeat message" {
				t.Fatalf("%s: ok=%v %+v", c.name, ok, ev)
			}
		}
		if d := p.Detected(); d != c.detected {
			t.Errorf("%s: 识别为 %q，期望 %q", c.name, d, c.detected)
		}
		// 识别出包装后，未包装的日志照常解析
		if ev, ok := p.Parse(`198.51.100.99 - - [26/Oct/2026:10:15:02 +0800] "GET / HTTP/1.1" 200 1 "-" "curl/8.0"`); c.detected[:5] == "nginx" && c.ip == "203.0.113.5" && (!ok || ev.SrcIP != "198.51.100.99") {
			t.Errorf("%s: 未包装的日志应照常解析", c.name)
		}
	}
	// Docker 包装的原始日志在留存中保存为包装内的原文
	p := mustAuto(t, "auto", "")
	if ev, ok := p.Parse(docker); !ok || ev.Raw != wrapNginx {
		t.Fatalf("Raw 应为包装内的原始日志: %q", ev.Raw)
	}
	// CRI 的时间前缀不能被当成 syslog 头（否则主机名会被记为 stdout）
	ev, ok := mustAuto(t, "auto", "").Parse(`2026-10-26T10:15:01.123+08:00 stdout F Oct 26 10:15:01 web01 sshd[123]: Failed password for root from 203.0.113.9 port 22 ssh2`)
	if !ok || ev.Host != "web01" || ev.SrcIP != "203.0.113.9" || strings.HasPrefix(ev.Raw, "2026-10-26T") {
		t.Fatalf("CRI 包装的认证日志: %+v", ev)
	}
	// 普通应用 JSON 日志（msg 为说明文字）不误识别
	if _, ok := mustAuto(t, "auto", "").Parse(`{"level":"info","msg":"user login ok","user":"bob"}`); ok {
		t.Fatal("应用日志不应被识别")
	}
	for _, s := range []string{`{"log":""}`, `{"log":123}`, `{"message":null}`, `2026-10-26T10:15:01.1+08:00 stdout`, `{"log":"{\"log\":\"{\\\"log\\\":\\\"x\\\"}\"}"}`} {
		if _, ok := mustAuto(t, "auto", "").Parse(s); ok {
			t.Errorf("%s 不应解析成功", s)
		}
	}
}

func BenchmarkAutoDockerWrapped(b *testing.B) {
	line, _ := json.Marshal(map[string]string{"log": wrapNginx + "\n", "stream": "stdout", "time": "2026-10-26T02:15:01.123456789Z"})
	p, _ := NewAuto("auto", "")
	for i := 0; i < 5; i++ {
		p.Parse(string(line))
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.Parse(string(line))
	}
}

func BenchmarkAutoNginxJSONDefaultEscape(b *testing.B) {
	line := `{"time_local":"26/Oct/2026:10:00:00 +0800","remote_addr":"198.51.100.12","request":"GET /?q=\x22><script> HTTP/1.1","status":"200","http_user_agent":"Mozilla/5.0"}`
	p, _ := NewAuto("auto", "")
	for i := 0; i < 5; i++ {
		p.Parse(line)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.Parse(line)
	}
}
