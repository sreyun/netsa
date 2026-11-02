package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/auth"
	"netsa/internal/backup"
	"netsa/internal/block"
	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/pipeline"
	"netsa/internal/rulemgr"
	"netsa/internal/sso"
)

func TestBlockAPI(t *testing.T) {
	s, _ := testServer(t, "admin", "secret")
	var err error
	s.Block, err = block.New(block.Options{Cfg: config.BlockConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	admin := login(t, h, "admin", "secret")
	analyst := newLocalUser(t, h, admin, "anna", auth.RoleAnalyst)
	viewer := newLocalUser(t, h, admin, "vera", auth.RoleViewer)
	req := `{"ip":"203.0.113.9","reason":"暴力破解","ttl_hours":2,"incident_id":7}`
	if rec := do(h, http.MethodPost, "/api/block", req, viewer); rec.Code != http.StatusForbidden {
		t.Fatalf("只读账号不能申请: %d", rec.Code)
	}
	rec := do(h, http.MethodPost, "/api/block", req, analyst)
	var it block.Item
	decode(t, rec.Body.Bytes(), &it)
	if rec.Code != 200 || it.Status != block.StatusPending || it.RequestedBy != "anna" || it.TTL != 2*time.Hour {
		t.Fatalf("申请: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/block", `{"ip":"10.0.0.1","reason":"x"}`, analyst); rec.Code != 400 {
		t.Fatalf("内网地址应拒绝: %d", rec.Code)
	}
	path := "/api/block/1/approve"
	if rec := do(h, http.MethodPost, path, "", analyst); rec.Code != http.StatusForbidden {
		t.Fatalf("分析员不能审批: %d", rec.Code)
	}
	if rec := get(h, "/api/block/edl", "admin", "secret"); strings.TrimSpace(rec.Body.String()) != "" {
		t.Fatalf("审批前名单应为空: %q", rec.Body.String())
	}
	if rec := do(h, http.MethodPost, path, "", admin); rec.Code != 200 {
		t.Fatalf("审批: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/block/edl", "", viewer); rec.Code != 200 || rec.Body.String() != "203.0.113.9\n" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("名单: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, path, "", admin); rec.Code != http.StatusConflict {
		t.Fatalf("重复审批: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/block/1/nonsense", "", admin); rec.Code != 404 {
		t.Fatalf("未知操作: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/block/1/release", `{"note":"误封"}`, admin); rec.Code != 200 {
		t.Fatalf("解除: %d", rec.Code)
	}
	var list struct {
		Enabled bool
		Items   []block.Item
		Pending int
		Active  int
	}
	decode(t, do(h, http.MethodGet, "/api/block", "", analyst).Body.Bytes(), &list)
	if !list.Enabled || list.Active != 0 || len(list.Items) != 1 || list.Items[0].Note != "误封" {
		t.Fatalf("列表: %+v", list)
	}
}

func TestBlockDisabled(t *testing.T) {
	s, _ := testServer(t, "", "")
	h := s.Handler()
	if rec := do(h, http.MethodPost, "/api/block", `{"ip":"203.0.113.9","reason":"x"}`, nil); rec.Code != 404 {
		t.Fatalf("未启用: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/block/edl", "", nil); rec.Code != 404 {
		t.Fatalf("未启用: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/block", "", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("列表: %d %s", rec.Code, rec.Body.String())
	}
}

// 规则运营：页面上保存的规则立即作用于流水线。
func TestRuleOpsAPI(t *testing.T) {
	s, st := testServer(t, "", "")
	var err error
	p := &pipeline.Pipeline{Engine: s.Engine, Store: st}
	s.Pipeline = p
	s.Rules, err = rulemgr.New(rulemgr.Options{Path: filepath.Join(t.TempDir(), "r.json"), MinBytes: 1, OnChange: p.SetEngine})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	var test rulemgr.TestResult
	rec := do(h, http.MethodPost, "/api/rules/test", `{"pattern":"acme-marker","sample":"/x?a=ACME%2Dmarker"}`, nil)
	decode(t, rec.Body.Bytes(), &test)
	if !test.Matched {
		t.Fatalf("试运行: %s", rec.Body.String())
	}
	before := len(s.engine().Rules())
	if rec := do(h, http.MethodPost, "/api/rules/managed", `{"id":"acme","name":"内部规则","category":"已知漏洞利用","severity":"high","pattern":"acme-marker"}`, nil); rec.Code != 200 {
		t.Fatalf("保存: %d %s", rec.Code, rec.Body.String())
	}
	if got := len(s.engine().Rules()); got != before+1 {
		t.Fatalf("应热更新: %d -> %d", before, got)
	}
	found := false
	for _, h := range p.CurrentEngine().Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.1", Method: "GET", URI: "/acme-marker", Status: 404, UA: "m"}) {
		found = found || h.RuleID == "acme"
	}
	if !found {
		t.Fatal("流水线应使用新规则")
	}
	if rec := do(h, http.MethodPost, "/api/rules/managed", `{"id":"bad","pattern":"("}`, nil); rec.Code != 400 {
		t.Fatalf("错误的表达式: %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/rules/managed/acme", "", nil); rec.Code != 200 {
		t.Fatalf("删除: %d", rec.Code)
	}
	// Sigma：预览不生效，确认后才生效
	yaml, _ := json.Marshal(map[string]any{"yaml": "title: T\nlogsource: {category: webserver}\ndetection:\n  selection: {cs-uri-query|contains: sigma-marker}\n  condition: selection\n"})
	var preview struct {
		Rules   []map[string]any
		Applied int
	}
	decode(t, do(h, http.MethodPost, "/api/rules/sigma", string(yaml), nil).Body.Bytes(), &preview)
	if len(preview.Rules) != 1 || preview.Applied != 0 {
		t.Fatalf("预览: %+v", preview)
	}
	if rules, _ := s.Rules.List(); len(rules) != 0 {
		t.Fatalf("预览不应生效: %+v", rules)
	}
	yaml, _ = json.Marshal(map[string]any{"apply": true, "yaml": "title: T\nlogsource: {category: webserver}\ndetection:\n  selection: {cs-uri-query|contains: sigma-marker}\n  condition: selection\n"})
	decode(t, do(h, http.MethodPost, "/api/rules/sigma", string(yaml), nil).Body.Bytes(), &preview)
	if rules, _ := s.Rules.List(); preview.Applied != 1 || len(rules) != 1 || rules[0].Source != "sigma" {
		t.Fatalf("导入: %+v %+v", preview, rules)
	}
}

func TestAdminBackup(t *testing.T) {
	s, _ := testServer(t, "", "")
	dir := t.TempDir()
	s.StateDir = dir
	os.WriteFile(filepath.Join(dir, "state.json.gz"), []byte("snapshot"), 0o600)
	h := s.Handler()
	rec := do(h, http.MethodGet, "/api/admin/backup", "", nil)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/gzip" || !strings.Contains(rec.Header().Get("Content-Disposition"), "netsa-") {
		t.Fatalf("备份: %d %v", rec.Code, rec.Header())
	}
	out := t.TempDir()
	m, err := backup.Restore(strings.NewReader(rec.Body.String()), out, false)
	if err != nil || len(m.Files) != 1 {
		t.Fatalf("下载的备份应能恢复: %v %+v", err, m)
	}
	s.StateDir = ""
	if rec := do(s.Handler(), http.MethodGet, "/api/admin/backup", "", nil); rec.Code != 404 {
		t.Fatalf("没有状态目录: %d", rec.Code)
	}
}

// 单点登录的完整流程：跳转、回调、校验 state、签发会话。
func TestOIDCFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding
	var nonce string
	groups := []string{"soc"}
	var idp *httptest.Server
	mux := http.NewServeMux()
	idp = httptest.NewServer(mux)
	defer idp.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/auth", "token_endpoint": idp.URL + "/token", "jwks_uri": idp.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k", "n": b64.EncodeToString(key.N.Bytes()), "e": b64.EncodeToString([]byte{1, 0, 1})}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k"})
		c, _ := json.Marshal(map[string]any{"iss": idp.URL, "aud": "netsa", "nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "preferred_username": "alice", "groups": groups})
		msg := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
		sum := sha256.Sum256([]byte(msg))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		json.NewEncoder(w).Encode(map[string]string{"id_token": msg + "." + b64.EncodeToString(sig)})
	})
	s, _ := testServer(t, "admin", "secret")
	s.OIDC = sso.NewOIDC(config.OIDCConfig{Issuer: idp.URL, ClientID: "netsa", DisplayName: "企业微信", RedirectURL: "https://soc.example.com/api/auth/oidc/callback",
		RoleMap: config.RoleMap{AnalystGroups: []string{"soc"}}})
	h := s.Handler()
	// 登录页据此显示按钮
	if rec := do(h, http.MethodGet, "/api/auth/session", "", nil); !strings.Contains(rec.Body.String(), "企业微信") {
		t.Fatalf("会话接口: %s", rec.Body.String())
	}
	begin := func() (state string, cookie *http.Cookie) {
		rec := do(h, http.MethodGet, "/api/auth/oidc/start", "", nil)
		if rec.Code != http.StatusFound {
			t.Fatalf("跳转: %d %s", rec.Code, rec.Body.String())
		}
		u, _ := url.Parse(rec.Header().Get("Location"))
		state, nonce = u.Query().Get("state"), u.Query().Get("nonce")
		for _, c := range rec.Result().Cookies() {
			if c.Name == oidcStateCookie {
				cookie = c
			}
		}
		if cookie == nil || !cookie.HttpOnly {
			t.Fatalf("应写入 HttpOnly 的 state Cookie: %+v", rec.Result().Cookies())
		}
		return state, cookie
	}
	callback := func(state string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		return do(h, http.MethodGet, "/api/auth/oidc/callback?code=c&state="+url.QueryEscape(state), "", cookies)
	}
	// 没有绑定浏览器的回调（登录 CSRF）被拒绝
	state, cookie := begin()
	if rec := callback(state, nil); !strings.Contains(rec.Header().Get("Location"), "sso_error=state") {
		t.Fatalf("没有 Cookie: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := callback("forged", []*http.Cookie{cookie}); !strings.Contains(rec.Header().Get("Location"), "sso_error=state") {
		t.Fatalf("state 不符: %s", rec.Header().Get("Location"))
	}
	// 正常登录
	state, cookie = begin()
	rec := callback(state, []*http.Cookie{cookie})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("回调: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	var session []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			session = append(session, c)
		}
	}
	var me struct {
		Authenticated bool
		User, Role    string
	}
	decode(t, do(h, http.MethodGet, "/api/auth/session", "", session).Body.Bytes(), &me)
	if !me.Authenticated || me.User != "alice" || me.Role != "analyst" {
		t.Fatalf("会话: %+v", me)
	}
	// 组映射不到角色
	groups = []string{"sales"}
	state, cookie = begin()
	if rec := callback(state, []*http.Cookie{cookie}); !strings.Contains(rec.Header().Get("Location"), "sso_error=denied") {
		t.Fatalf("没有权限: %s", rec.Header().Get("Location"))
	}
	// 未配置时接口不存在
	s2, _ := testServer(t, "admin", "secret")
	if rec := do(s2.Handler(), http.MethodGet, "/api/auth/oidc/start", "", nil); rec.Code != 404 {
		t.Fatalf("未配置: %d", rec.Code)
	}
}

func TestIntegrationsStatus(t *testing.T) {
	s, _ := testServer(t, "", "")
	rec := do(s.Handler(), http.MethodGet, "/api/integrations", "", nil)
	var r struct {
		Playbooks struct{ Enabled bool }
		SSO       struct{ LDAP, OIDC bool }
	}
	decode(t, rec.Body.Bytes(), &r)
	if rec.Code != 200 || r.Playbooks.Enabled || r.SSO.OIDC {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
