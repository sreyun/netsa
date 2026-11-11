package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"netsa/internal/auth"
)

// totpNow 按 RFC 6238 计算当前的 6 位验证码（测试用）。
func totpNow(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

func require2FAServer(t *testing.T) (*Server, *auth.Manager) {
	t.Helper()
	s, _ := testServer(t, "", "")
	m, _, err := auth.New(auth.Options{InitialAdmin: "Adm1n-pass!x", Require2FA: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Auth = m
	return s, m
}

func errCode(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Code string `json:"code"`
	}
	json.Unmarshal([]byte(body), &e)
	return e.Code
}

// require_2fa 开启时，新建账号（或重置了密码的账号）要先改初始密码、再绑定身份验证器：
// 两道前置检查按顺序生效，不能互相卡死。
func TestRequire2FAWithInitialPassword(t *testing.T) {
	s, m := require2FAServer(t)
	h := s.Handler()
	if err := m.CreateUser("ops", auth.RoleAnalyst, "Init-pass!123"); err != nil {
		t.Fatal(err)
	}
	ck := login(t, h, "ops", "Init-pass!123")
	if rec := do(h, http.MethodGet, "/api/overview", "", ck); rec.Code != 403 || errCode(t, rec.Body.String()) != "must_change_password" {
		t.Fatalf("先要求修改初始密码: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/auth/2fa/setup", "", ck); rec.Code != 403 || errCode(t, rec.Body.String()) != "must_change_password" {
		t.Fatalf("改密之前不能绑定: %d %s", rec.Code, rec.Body.String())
	}
	rec := do(h, http.MethodPost, "/api/auth/password", `{"current":"Init-pass!123","new":"N3w-pass!4567"}`, ck)
	if rec.Code != 200 {
		t.Fatalf("同时要求改密与绑定时应能修改密码: %d %s", rec.Code, rec.Body.String())
	}
	ck = rec.Result().Cookies()
	if rec := do(h, http.MethodGet, "/api/overview", "", ck); rec.Code != 403 || errCode(t, rec.Body.String()) != "must_enroll_2fa" {
		t.Fatalf("改密后要求绑定身份验证器: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(h, http.MethodPost, "/api/auth/2fa/setup", "", ck)
	if rec.Code != 200 {
		t.Fatalf("改密后应能开始绑定: %d %s", rec.Code, rec.Body.String())
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(rec.Body.Bytes(), &setup)
	rec = do(h, http.MethodPost, "/api/auth/2fa/enable", `{"code":"`+totpNow(t, setup.Secret)+`"}`, ck)
	if rec.Code != 200 {
		t.Fatalf("绑定: %d %s", rec.Code, rec.Body.String())
	}
	ck = rec.Result().Cookies()
	if rec := do(h, http.MethodGet, "/api/overview", "", ck); rec.Code != 200 {
		t.Fatalf("改密并绑定后可以正常使用: %d %s", rec.Code, rec.Body.String())
	}
}

// API 令牌只代表受限的权限：不能用来给所属账号绑定身份验证器、修改密码，也不会换来完整权限的登录会话。
func TestTokenCannotManageCredentials(t *testing.T) {
	s, m := require2FAServer(t)
	h := s.Handler()
	if err := m.CreateUser("bot", auth.RoleAdmin, "Init-pass!123"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ChangePassword("bot", "Init-pass!123", "B0t-pass!4567"); err != nil {
		t.Fatal(err)
	}
	raw, _, err := m.CreateToken("bot", "grafana", auth.RoleViewer, "admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/api/auth/2fa/setup", "/api/auth/2fa/enable", "/api/auth/2fa/disable", "/api/auth/password"} {
		rec := do(h, http.MethodPost, p, `{"code":"123456"}`, nil, "Authorization", "Bearer "+raw)
		if rec.Code != 403 || errCode(t, rec.Body.String()) != "interactive_only" || rec.Header().Get("Set-Cookie") != "" {
			t.Fatalf("%s 不应允许令牌调用: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	// HTTP Basic 同样不能修改凭据（脚本用的认证方式）
	rec := do(h, http.MethodPost, "/api/auth/password", `{"current":"B0t-pass!4567","new":"Other-pass!890"}`, nil,
		"Authorization", "Basic "+basicAuth("bot", "B0t-pass!4567"))
	if rec.Code != 403 {
		t.Fatalf("Basic 认证不应能修改密码: %d %s", rec.Code, rec.Body.String())
	}
}

// require_2fa 开启时，没有绑定身份验证器的账号用 HTTP Basic 认证同样每次都被拦住（成功结果的缓存不能绕过）。
func TestBasicCacheKeepsEnrollRequirement(t *testing.T) {
	s, m := require2FAServer(t)
	h := s.Handler()
	if err := m.CreateUser("bot", auth.RoleAdmin, "Init-pass!123"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ChangePassword("bot", "Init-pass!123", "B0t-pass!4567"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rec := do(h, http.MethodGet, "/api/auth/users", "", nil, "Authorization", "Basic "+basicAuth("bot", "B0t-pass!4567"))
		if rec.Code != 403 || errCode(t, rec.Body.String()) != "must_enroll_2fa" {
			t.Fatalf("第 %d 次 Basic 请求应要求绑定身份验证器: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
}

func basicAuth(user, pass string) string {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
}
