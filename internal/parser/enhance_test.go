package parser

import (
	"testing"
)

// nginx 增强字段：JSON、自定义 log_format 与 combined 之后的 key=value 三种写法。
func TestEnhancedFields(t *testing.T) {
	js := `{"time_iso8601":"2026-11-05T10:15:01+08:00","remote_addr":"198.51.100.7","request":"POST /upload.php HTTP/1.1","status":"200","body_bytes_sent":"512",` +
		`"request_length":"8812","upstream_status":"502, 200","upstream_response_time":"0.012, 0.034","ssl_protocol":"TLSv1.3","ssl_cipher":"TLS_AES_256_GCM_SHA384","http_user_agent":"curl/8.4"}`
	ev, ok := NginxJSON{}.Parse(js)
	if !ok || ev.ReqLength != 8812 || ev.Upstream != 200 || ev.UpstreamTime != 0.034 || ev.TLSProto != "TLSv1.3" ||
		ev.TLSFinger != "tls:TLSv1.3/TLS_AES_256_GCM_SHA384" {
		t.Fatalf("JSON: %+v", ev)
	}
	lf, err := CompileLogFormat(`$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_length $upstream_status $ssl_protocol $ssl_cipher $http_ssl_ja3`)
	if err != nil {
		t.Fatal(err)
	}
	ev, ok = lf.Parse(`198.51.100.7 - - [05/Nov/2026:10:15:01 +0800] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0" 312 - TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 e7d705a3286e19ea42f587b344ee6865`)
	if !ok || ev.ReqLength != 312 || ev.Upstream != -1 || ev.TLSCipher != "ECDHE-RSA-AES128-GCM-SHA256" || ev.TLSFinger != "ja3:e7d705a3286e19ea42f587b344ee6865" {
		t.Fatalf("log_format: %+v", ev)
	}
	ev, ok = Nginx{}.Parse(`198.51.100.7 - - [05/Nov/2026:10:15:01 +0800] "GET /api/x HTTP/1.1" 200 100 "-" "Mozilla/5.0" rt=0.010 rl=420 us=504 ssl=TLSv1.3`)
	if !ok || ev.ReqTime != 0.010 || ev.ReqLength != 420 || ev.Upstream != 504 || ev.TLSProto != "TLSv1.3" {
		t.Fatalf("key=value: %+v", ev)
	}
	for v, want := range map[string]int{"-": -1, "200": 200, "502, 200": 200, "404 : 200": 200, "502, -": -1, "abc": 0, "": -1} {
		if got := upstreamStatus(v); got != want {
			t.Errorf("upstreamStatus(%q) = %d，应为 %d", v, got, want)
		}
	}
}
