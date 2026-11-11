package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/pipeline"
)

// 封禁列表导出：写错的等级返回 400，不当成“全部”；原始参数不写进生成的脚本。
func TestBlocklistLevelStrict(t *testing.T) {
	s, st := testServer(t, "", "")
	h := s.Handler()
	now := time.Now()
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.61", Host: "a.com", Method: "GET", URI: "/x?id=1", Status: 403, Time: now},
		[]model.Hit{{RuleID: "sqli", Name: "SQL注入", Category: "SQL注入", Severity: model.SevCritical, Phase: model.PhaseExploit, Result: model.ResultBlocked}})
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.62", Host: "a.com", Method: "GET", URI: "/.env", Status: 404, Time: now},
		[]model.Hit{{RuleID: "sens", Name: "敏感文件", Category: "敏感文件探测", Severity: model.SevLow, Phase: model.PhaseRecon, Result: model.ResultFailed}})
	if rec := get(h, "/api/export/blocklist?format=txt&level=hihg"); rec.Code != 400 {
		t.Fatalf("写错的等级应返回 400: %d %s", rec.Code, rec.Body.String())
	}
	rec := get(h, "/api/export/blocklist?format=iptables&level=high%0Atouch%20/tmp/pwned%0A")
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "touch") {
		t.Fatalf("带换行的等级不能写进脚本: %d %s", rec.Code, rec.Body.String())
	}
	rec = get(h, "/api/export/blocklist?format=iptables")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "198.51.100.61") || strings.Contains(rec.Body.String(), "198.51.100.62") ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "netsa-blocklist-high.sh") {
		t.Fatalf("默认导出高危及以上: %d %s", rec.Code, rec.Body.String())
	}
}

// 报告时间写成一位小时（9:00）：规范为 09:00，调度按 HH:MM 比较时能匹配。
func TestReportTimeNormalized(t *testing.T) {
	if _, hm, ok, err := config.ParseWeekly("mon 9:00"); !ok || err != nil || hm != "09:00" {
		t.Fatalf("周报时间应规范为 09:00: %q %v %v", hm, ok, err)
	}
	if _, hm, ok, err := config.ParseMonthly("1 8:30"); !ok || err != nil || hm != "08:30" {
		t.Fatalf("月报时间应规范为 08:30: %q %v %v", hm, ok, err)
	}
	cfg := config.Default()
	cfg.Alert.ReportTime = "9:00"
	if err := cfg.Validate(); err != nil || cfg.Alert.ReportTime != "09:00" {
		t.Fatalf("日报时间应规范为 09:00: %q %v", cfg.Alert.ReportTime, err)
	}
}

// 可信代理把自己的 X-Forwarded-For 另起一行追加时，采信代理追加的值，而不是客户端自己写的第一行。
func TestClientIPMergesForwardedLines(t *testing.T) {
	s, _ := testServer(t, "", "")
	s.Pipeline = &pipeline.Pipeline{Engine: s.Pipeline.Engine, Store: s.Pipeline.Store,
		RealIP: pipeline.NewRealIP(config.RealIPConfig{Headers: []string{"x_forwarded_for"}, TrustedProxies: []string{"10.0.0.2"}})}
	s.Cfg.Server.AllowNetworks = []string{"10.8.0.0/16"}
	h := s.Handler()
	r := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	r.RemoteAddr = "10.0.0.2:4433"
	r.Header.Add("X-Forwarded-For", "127.0.0.1")    // 客户端自己写的
	r.Header.Add("X-Forwarded-For", "198.51.100.9") // 代理追加的真实来源
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 403 {
		t.Fatalf("客户端伪造的第一行不应被采信（来源白名单之外应返回 403）: %d", rec.Code)
	}
}

// 放在改写 Host 的反向代理之后：浏览器的 Sec-Fetch-Site 为 same-origin 时，Origin 与 Host 不同也不算跨站。
func TestSameOriginBehindProxy(t *testing.T) {
	ok := sameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	req := func(hdr ...string) int {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/auth/login", strings.NewReader("{}"))
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		rec := httptest.NewRecorder()
		ok.ServeHTTP(rec, r)
		return rec.Code
	}
	if c := req("Origin", "https://netsa.example.com", "Sec-Fetch-Site", "same-origin"); c != 204 {
		t.Fatalf("同源请求（代理改写了 Host）应放行: %d", c)
	}
	if c := req("Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site"); c != 403 {
		t.Fatalf("跨站请求应拒绝: %d", c)
	}
	if c := req("Origin", "https://evil.example"); c != 403 {
		t.Fatalf("没有 Sec-Fetch-Site 时按 Origin 与 Host 判断: %d", c)
	}
	if c := req(); c != 204 {
		t.Fatalf("非浏览器客户端（没有 Origin）放行: %d", c)
	}
}
