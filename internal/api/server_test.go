package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/auth"
	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/ingest"
	"netsa/internal/model"
	"netsa/internal/pipeline"
	"netsa/internal/store"
)

func testServer(t *testing.T, user, pass string) (*Server, *store.Store) {
	t.Helper()
	cfg := config.Default()
	cfg.Server.Username, cfg.Server.Password = user, pass
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	gaz, err := geo.LoadGazetteer(os.DirFS("../../web/static"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(1000, 1000, 5, time.Hour)
	res := geo.NewResolver(geo.Options{Gazetteer: gaz})
	st.GeoLookup = res.Lookup
	pipe := &pipeline.Pipeline{Engine: eng, Store: st}
	s := &Server{Cfg: cfg, Store: st, Ingest: ingest.NewManager(1), Pipeline: pipe, Geo: res, Engine: eng,
		Static: os.DirFS("../../web/static"), Version: "test", Broker: NewBroker()}
	if user != "" { // 配置了账号时开启登录；为空时视为关闭登录认证
		m, _, err := auth.New(auth.Options{ConfigUser: user, ConfigPassword: pass})
		if err != nil {
			t.Fatal(err)
		}
		s.Auth = m
	}
	return s, st
}

func get(h http.Handler, path string, auth ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if len(auth) == 2 {
		req.SetBasicAuth(auth[0], auth[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthAndHealth(t *testing.T) {
	s, _ := testServer(t, "admin", "secret")
	h := s.Handler()
	if rec := get(h, "/healthz"); rec.Code != 200 {
		t.Fatalf("健康检查不应需要认证: %d", rec.Code)
	}
	if rec := get(h, "/api/overview"); rec.Code != 401 {
		t.Fatalf("未认证访问 API 应返回 401: %d", rec.Code)
	}
	if rec := get(h, "/api/overview", "admin", "wrong"); rec.Code != 401 {
		t.Fatalf("错误口令应返回 401: %d", rec.Code)
	}
	rec := get(h, "/api/overview", "admin", "secret")
	if rec.Code != 200 || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("认证后应可访问且带安全响应头: %d", rec.Code)
	}
	if rec := get(h, "/", "admin", "secret"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "网络安全态势感知平台") {
		t.Fatalf("首页: %d", rec.Code)
	}
	if rec := get(h, "/vendor/china/guangdong.json", "admin", "secret"); rec.Code != 200 {
		t.Fatalf("省级地图: %d", rec.Code)
	}
}

func TestMetaMapAndExport(t *testing.T) {
	s, st := testServer(t, "", "")
	h := s.Handler()
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.20", Method: "GET", URI: "/x", Status: 403, Time: time.Now()},
		[]model.Hit{{RuleID: "r", Name: "r", Category: "SQL注入", Severity: model.SevCritical, Phase: model.PhaseExploit, Result: model.ResultBlocked}})

	var meta map[string]any
	json.Unmarshal(get(h, "/api/meta").Body.Bytes(), &meta)
	if maps, _ := meta["china_maps"].(map[string]any); len(maps) != 34 {
		t.Fatalf("meta 中省级地图索引异常: %v", meta["china_maps"])
	}
	if rec := get(h, "/api/map"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"points"`) {
		t.Fatalf("地图接口: %d %s", rec.Code, rec.Body.String())
	}
	rec := get(h, "/api/export/blocklist?format=csv&level=high")
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(rec.Body.String(), "\xEF\xBB\xBF")))
	rows, err := r.ReadAll()
	if err != nil || len(rows) != 2 || rows[1][0] != "198.51.100.20" {
		t.Fatalf("CSV 导出异常: %v %v", err, rows)
	}
	if rec := get(h, "/api/export/blocklist?format=iptables&level=high"); !strings.Contains(rec.Body.String(), "iptables -C INPUT -s 198.51.100.20 -j DROP") {
		t.Fatalf("iptables 导出应幂等: %s", rec.Body.String())
	}
	if rec := get(h, "/api/ip/203.0.113.250"); rec.Code != 404 {
		t.Fatalf("不存在的 IP 应返回 404: %d", rec.Code)
	}
	if rec := get(h, "/api/attackers?limit=999999"); rec.Code != 200 {
		t.Fatalf("超大 limit 应被限制而非报错: %d", rec.Code)
	}
}

// 服务模式下取消 ctx 后流水线应立即退出，而不是等待输入通道关闭。
func TestPipelineStopsOnCancel(t *testing.T) {
	s, _ := testServer(t, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan []*model.Event)
	done := s.Pipeline.Run(ctx, in, 2)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消后流水线未退出")
	}
}

func do(h http.Handler, method, path, body string, cookies []*http.Cookie, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func login(t *testing.T, h http.Handler, user, pass string) []*http.Cookie {
	t.Helper()
	rec := do(h, http.MethodPost, "/api/auth/login", `{"username":"`+user+`","password":"`+pass+`"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("登录 %s 失败: %d %s", user, rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()
}

// 登录页、会话 Cookie、强制修改初始密码、只读角色、退出登录与跨站请求拦截。
func TestLoginFlow(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	h := s.Handler()
	if rec := do(h, http.MethodGet, "/", "", nil); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login.html" {
		t.Fatalf("未登录访问首页应跳转登录页: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(h, http.MethodGet, "/login.html", "", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "登录") {
		t.Fatalf("登录页应可公开访问: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/app.js", "", nil); rec.Code != 401 {
		t.Fatalf("未登录不应获取大屏资源: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/auth/login", `{"username":"admin","password":"wrong"}`, nil); rec.Code != 401 || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("错误密码: %d", rec.Code)
	}
	rec := do(h, http.MethodPost, "/api/auth/login", `{"username":"admin","password":"Adm1n-secret"}`, nil)
	sc := rec.Header().Get("Set-Cookie")
	if rec.Code != 200 || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Lax") {
		t.Fatalf("登录成功应下发 HttpOnly Cookie: %d %s", rec.Code, sc)
	}
	admin := rec.Result().Cookies()
	if rec := do(h, http.MethodGet, "/api/overview", "", admin); rec.Code != 200 {
		t.Fatalf("登录后访问 API: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/", "", admin); rec.Code != 200 {
		t.Fatalf("登录后访问首页: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/login.html", "", admin); rec.Code != http.StatusFound {
		t.Fatalf("已登录访问登录页应跳回首页: %d", rec.Code)
	}
	// 管理员创建只读账号
	if rec := do(h, http.MethodPost, "/api/auth/users", `{"name":"screen","role":"viewer","password":"Scr33n-pass"}`, admin); rec.Code != 200 {
		t.Fatalf("创建账号: %d %s", rec.Code, rec.Body.String())
	}
	viewer := login(t, h, "screen", "Scr33n-pass")
	if rec := do(h, http.MethodGet, "/api/overview", "", viewer); rec.Code != 403 || !strings.Contains(rec.Body.String(), "must_change_password") {
		t.Fatalf("初始密码登录后须先修改密码: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(h, http.MethodPost, "/api/auth/password", `{"current":"Scr33n-pass","new":"N3w-screen-pass"}`, viewer)
	if rec.Code != 200 {
		t.Fatalf("修改密码: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/overview", "", viewer); rec.Code != 401 {
		t.Fatalf("修改密码后旧会话应失效: %d", rec.Code)
	}
	viewer = rec.Result().Cookies()
	if rec := do(h, http.MethodGet, "/api/overview", "", viewer); rec.Code != 200 {
		t.Fatalf("修改密码后的新会话: %d", rec.Code)
	}
	// 只读账号不能修改配置、查看账号
	if rec := do(h, http.MethodPost, "/api/alert/robots", `{"name":"x"}`, viewer); rec.Code != 403 {
		t.Fatalf("只读账号不能添加机器人: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/auth/users", "", viewer); rec.Code != 403 {
		t.Fatalf("只读账号不能查看账号列表: %d", rec.Code)
	}
	// 跨站提交被拦截
	if rec := do(h, http.MethodPost, "/api/auth/logout", "", admin, "Origin", "http://evil.example"); rec.Code != 403 {
		t.Fatalf("跨站请求应被拦截: %d", rec.Code)
	}
	// 退出登录
	if rec := do(h, http.MethodPost, "/api/auth/logout", "", admin); rec.Code != 200 {
		t.Fatalf("退出登录: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/overview", "", admin); rec.Code != 401 {
		t.Fatalf("退出后会话应失效: %d", rec.Code)
	}
	// 登录审计
	var audit []auth.Record
	json.Unmarshal(do(h, http.MethodGet, "/api/auth/audit", "", login(t, h, "admin", "Adm1n-secret")).Body.Bytes(), &audit)
	if len(audit) < 4 {
		t.Fatalf("登录审计记录不足: %d", len(audit))
	}
}

// 安全加固：CSV 公式注入、安全响应头、未登录的会话查询、操作审计。
func TestSecurityHardening(t *testing.T) {
	row := csvSafe([]string{"198.51.100.1", "=HYPERLINK(\"http://evil\")", "+1", "-2", "@SUM(A1)", "\tx", "正常"})
	for i, want := range []string{"198.51.100.1", "'=HYPERLINK(\"http://evil\")", "'+1", "'-2", "'@SUM(A1)", "'\tx", "正常"} {
		if row[i] != want {
			t.Errorf("csvSafe[%d]=%q want %q", i, row[i], want)
		}
	}
	s, _ := testServer(t, "admin", "Adm1n-secret")
	h := s.Handler()
	rec := do(h, http.MethodGet, "/api/auth/session", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"authenticated":false`) {
		t.Fatalf("未登录查询会话应返回 200 与 authenticated=false: %d %s", rec.Code, rec.Body.String())
	}
	for _, hdr := range []string{"Content-Security-Policy", "X-Frame-Options", "Permissions-Policy", "Cross-Origin-Opener-Policy", "X-Content-Type-Options"} {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("缺少安全响应头 %s", hdr)
		}
	}
	admin := login(t, h, "admin", "Adm1n-secret")
	do(h, http.MethodPost, "/api/auth/users", `{"name":"ops2","role":"viewer","password":"Op5-pass-1"}`, admin)
	do(h, http.MethodGet, "/api/export/blocklist?format=csv&level=high", "", admin)
	var audit []auth.Record
	json.Unmarshal(do(h, http.MethodGet, "/api/auth/audit", "", admin).Body.Bytes(), &audit)
	got := map[string]bool{}
	for _, a := range audit {
		got[a.Action] = true
	}
	if !got["创建账号"] || !got["导出封禁列表"] {
		t.Fatalf("操作审计缺失: %+v", audit)
	}
}

// 实时告警长连接：退出登录后，已建立的连接在下一次心跳时断开，不再继续推送告警。
func TestStreamClosesAfterLogout(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	s.Broker.PingEvery = 50 * time.Millisecond
	h := s.Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	cookies := login(t, h, "admin", "Adm1n-secret")
	// 配置文件账号首次登录也可直接使用（MustChange 仅对自动生成的初始密码生效）
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/stream", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("建立实时告警连接失败: %v %v", err, resp)
	}
	defer resp.Body.Close()
	ended := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := resp.Body.Read(buf); err != nil {
				close(ended)
				return
			}
		}
	}()
	select {
	case <-ended:
		t.Fatal("会话有效时连接不应断开")
	case <-time.After(200 * time.Millisecond):
	}
	if rec := do(h, http.MethodPost, "/api/auth/logout", "", cookies, "Origin", "http://example.com", "Host", "example.com"); rec.Code != 200 {
		t.Fatalf("退出登录: %d", rec.Code)
	}
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("退出登录后实时告警连接未断开")
	}
}

// 态势总览下钻参数：攻击源按地域 / 网络类型 / 攻击类型筛选，告警按阶段 / 目标 / 时间段筛选。
func TestDrillDownParams(t *testing.T) {
	s, st := testServer(t, "", "")
	h := s.Handler()
	now := time.Now()
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.30", Host: "a.com", Method: "GET", URI: "/login", Status: 403, Time: now.Add(-30 * time.Minute)},
		[]model.Hit{{RuleID: "r1", Name: "r1", Category: "SQL注入", Severity: model.SevHigh, Phase: model.PhaseExploit, Result: model.ResultBlocked}})
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.31", Host: "a.com", Method: "GET", URI: "/admin", Status: 404, Time: now.Add(-5 * time.Minute)},
		[]model.Hit{{RuleID: "r2", Name: "r2", Category: "暴力破解", Severity: model.SevMedium, Phase: model.PhaseCredential, Result: model.ResultFailed}})
	total := func(q string) int {
		var r struct{ Total int }
		json.Unmarshal(get(h, "/api/attackers?"+q).Body.Bytes(), &r)
		return r.Total
	}
	count := func(q string) int {
		var r []map[string]any
		json.Unmarshal(get(h, "/api/alerts?"+q).Body.Bytes(), &r)
		return len(r)
	}
	if total("category=SQL注入") != 1 || total("phase=credential") != 1 || total("category=XSS") != 0 || total("") != 2 {
		t.Fatal("攻击源下钻参数无效")
	}
	if count("phase=exploit") != 1 || count("target=a.com+/admin") != 1 || count("from="+strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)) != 1 ||
		count("to="+url.QueryEscape(now.Add(-10*time.Minute).Format(time.RFC3339))) != 1 || count("from=bad") != 2 {
		t.Fatal("告警下钻参数无效")
	}
}
