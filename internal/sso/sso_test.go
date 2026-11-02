package sso

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
)

var b64 = base64.RawURLEncoding

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any, alg string) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid})
	c, _ := json.Marshal(claims)
	msg := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sum := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return msg + "." + b64.EncodeToString(sig)
}

// fakeIdP 是一个最小的 OIDC 身份提供方。token 决定令牌端点返回什么。
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	token    func(nonce string) string
	nonce    string
	verifier string
	jwksHits int
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key}
	mux := http.NewServeMux()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/auth", "token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		p.jwksHits++
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "n": b64.EncodeToString(key.N.Bytes()), "e": b64.EncodeToString([]byte{1, 0, 1})}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.verifier = r.Form.Get("code_verifier")
		json.NewEncoder(w).Encode(map[string]string{"id_token": p.token(p.nonce)})
	})
	return p
}

func (p *fakeIdP) claims(nonce string) map[string]any {
	return map[string]any{"iss": p.srv.URL, "aud": "netsa", "nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"preferred_username": "alice", "groups": []string{"soc-admins"}}
}

func newClient(p *fakeIdP) *OIDC {
	return NewOIDC(config.OIDCConfig{Issuer: p.srv.URL, ClientID: "netsa", RedirectURL: "https://soc.example.com/api/auth/oidc/callback",
		RoleMap: config.RoleMap{AdminGroups: []string{"soc-admins"}, AnalystGroups: []string{"analysts"}}})
}

func (p *fakeIdP) start(t *testing.T, o *OIDC) string {
	t.Helper()
	redirect, state, err := o.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	q := u.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" || q.Get("state") != state || q.Get("nonce") == "" {
		t.Fatalf("跳转参数不完整: %s", redirect)
	}
	p.nonce = q.Get("nonce")
	return state
}

func TestOIDCLogin(t *testing.T) {
	p := newIdP(t)
	p.token = func(n string) string { return signRS256(t, p.key, "k1", p.claims(n), "RS256") }
	o := newClient(p)
	state := p.start(t, o)
	id, err := o.Finish(context.Background(), state, "code")
	if err != nil || id.Username != "alice" || id.Role != "admin" {
		t.Fatalf("登录: %+v %v", id, err)
	}
	if sum := sha256.Sum256([]byte(p.verifier)); p.verifier == "" || b64.EncodeToString(sum[:]) == "" {
		t.Fatal("应发送 PKCE verifier")
	}
	// state 只能用一次
	if _, err := o.Finish(context.Background(), state, "code"); err == nil {
		t.Fatal("state 不能重放")
	}
	if _, err := o.Finish(context.Background(), "unknown", "code"); err == nil {
		t.Fatal("未知的 state 应被拒绝")
	}
}

// 伪造或不合规的 ID Token 都不能登录。
func TestOIDCRejectsBadTokens(t *testing.T) {
	p := newIdP(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	mutate := func(f func(c map[string]any)) func(string) string {
		return func(n string) string {
			c := p.claims(n)
			f(c)
			return signRS256(t, p.key, "k1", c, "RS256")
		}
	}
	none := func(n string) string {
		h, _ := json.Marshal(map[string]string{"alg": "none", "kid": "k1"})
		c, _ := json.Marshal(p.claims(n))
		return b64.EncodeToString(h) + "." + b64.EncodeToString(c) + "."
	}
	for _, c := range []struct {
		name  string
		token func(string) string
	}{
		{"其他密钥签名", func(n string) string { return signRS256(t, other, "k1", p.claims(n), "RS256") }},
		{"未知 kid", func(n string) string { return signRS256(t, p.key, "nope", p.claims(n), "RS256") }},
		{"alg none", none},
		{"alg 与密钥不符", func(n string) string { return signRS256(t, p.key, "k1", p.claims(n), "ES256") }},
		{"签发者不符", mutate(func(c map[string]any) { c["iss"] = "https://evil.example" })},
		{"受众不符", mutate(func(c map[string]any) { c["aud"] = "other" })},
		{"nonce 不符", mutate(func(c map[string]any) { c["nonce"] = "x" })},
		{"缺少 nonce", mutate(func(c map[string]any) { delete(c, "nonce") })},
		{"已过期", mutate(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })},
		{"缺少 exp", mutate(func(c map[string]any) { delete(c, "exp") })},
		{"来自未来", mutate(func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() })},
		{"组映射不到角色", mutate(func(c map[string]any) { c["groups"] = []string{"sales"} })},
		{"没有用户名", mutate(func(c map[string]any) { delete(c, "preferred_username") })},
		{"格式错误", func(string) string { return "not-a-jwt" }},
	} {
		p.token = c.token
		o := newClient(p)
		state := p.start(t, o)
		if id, err := o.Finish(context.Background(), state, "code"); err == nil {
			t.Errorf("%s 应被拒绝: %+v", c.name, id)
		}
	}
}

func TestOIDCIssuerMismatch(t *testing.T) {
	p := newIdP(t)
	o := NewOIDC(config.OIDCConfig{Issuer: p.srv.URL + "/other", ClientID: "netsa"})
	if _, _, err := o.Start(context.Background()); err == nil {
		t.Fatal("发现文档的 issuer 与配置不一致时应拒绝")
	}
}

func TestJWKPublicKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	buf := func(n int, b []byte) string {
		out := make([]byte, n)
		copy(out[n-len(b):], b)
		return b64.EncodeToString(out)
	}
	if _, err := (jwk{Kty: "EC", Crv: "P-256", X: buf(32, ec.X.Bytes()), Y: buf(32, ec.Y.Bytes())}).publicKey(); err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]jwk{
		"bad-curve": {Kty: "EC", Crv: "P-256", X: buf(32, []byte{1}), Y: buf(32, []byte{1})},
		"p384":      {Kty: "EC", Crv: "P-384"},
		"short-rsa": {Kty: "RSA", N: b64.EncodeToString(make([]byte, 16)), E: b64.EncodeToString([]byte{1, 0, 1})},
		"oct":       {Kty: "oct"},
	} {
		if _, err := k.publicKey(); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
}

func TestMapRole(t *testing.T) {
	m := config.RoleMap{AdminGroups: []string{"CN=Admins,OU=g,DC=x"}, AnalystGroups: []string{"soc"}, ViewerGroups: []string{"staff"}}
	for _, c := range []struct {
		groups []string
		def    string
		want   string
	}{
		{[]string{"cn=admins,ou=g,dc=x"}, "", "admin"},
		{[]string{"CN=SOC,OU=g,DC=x"}, "", "analyst"},
		{[]string{"staff", "soc"}, "", "analyst"},
		{[]string{"staff"}, "", "viewer"},
		{[]string{"sales"}, "", ""},
		{nil, "viewer", "viewer"},
	} {
		m.DefaultRole = c.def
		if got := MapRole(m, c.groups); got != c.want {
			t.Errorf("%v: %q，期望 %q", c.groups, got, c.want)
		}
	}
}

func TestNewClientsUnconfigured(t *testing.T) {
	if NewOIDC(config.OIDCConfig{}) != nil {
		t.Error("未配置 OIDC 应返回 nil")
	}
	if l, err := NewLDAP(config.LDAPConfig{}); l != nil || err != nil {
		t.Error("未配置 LDAP 应返回 nil")
	}
	if !strings.Contains(newClient(&fakeIdP{srv: &httptest.Server{URL: "https://x"}}).DisplayName(), "单点") {
		t.Error("默认按钮名称")
	}
}
