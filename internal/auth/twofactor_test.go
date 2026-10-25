package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 6238 附录 B 的 SHA1 测试向量（取后 6 位）。
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		if got := hotp(key, uint64(ts/30), 6); got != want {
			t.Errorf("t=%d got %s want %s", ts, got, want)
		}
	}
	secret := b32.EncodeToString(key)
	now := time.Unix(59, 0)
	if step, ok := verifyTOTP(secret, "287082", now, 0); !ok || step != 1 {
		t.Fatal("验证码校验失败")
	}
	if _, ok := verifyTOTP(secret, "287082", now, 1); ok {
		t.Fatal("同一时间片的验证码不能重复使用")
	}
	if _, ok := verifyTOTP(secret, "287082", now.Add(20*time.Second), 0); !ok {
		t.Fatal("应允许前后 1 个时间片的时钟偏差")
	}
	if _, ok := verifyTOTP(secret, "287082", now.Add(95*time.Second), 0); ok {
		t.Fatal("超出偏差范围的验证码应拒绝")
	}
	if u := OTPAuthURL("netsa", "ops@corp", secret); !strings.HasPrefix(u, "otpauth://totp/netsa:ops@corp?") || !strings.Contains(u, "secret="+secret) {
		t.Fatalf("otpauth 地址: %s", u)
	}
}

// codeAt 生成账号在 t 时刻的验证码。
func codeAt(t *testing.T, secret string, at time.Time) string {
	key, err := decodeSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	return hotp(key, uint64(at.Unix()/30), 6)
}

// 绑定、两步登录、防重放、恢复码、错误锁定、关闭与管理员重置。
func TestTwoFactorFlow(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	m, _ := newMgr(t, Options{File: file, InitialAdmin: "Adm1n-pass!"})
	m.nowFunc = func() time.Time { return now }
	if err := m.CreateUser("ops", RoleAnalyst, "0ps-pass!x"); err != nil {
		t.Fatal(err)
	}
	secret, uri, err := m.BeginTOTP("ops")
	if err != nil || !strings.Contains(uri, secret) {
		t.Fatal(err)
	}
	if _, _, err := m.EnableTOTP("ops", "000000"); !errors.Is(err, ErrTOTPCode) {
		t.Fatalf("错误验证码不能完成绑定: %v", err)
	}
	recovery, tok, err := m.EnableTOTP("ops", codeAt(t, secret, now))
	if err != nil || len(recovery) != 8 || tok == "" {
		t.Fatalf("绑定: %v", err)
	}
	if s, _, ok := m.Verify(tok); !ok || !s.TwoFactor || s.Role != RoleAnalyst {
		t.Fatal("绑定后当前会话换发新令牌")
	}

	// 第一步：口令正确也不签发会话，只返回挑战凭据
	_, _, err = m.Login("ops", "0ps-pass!x", "10.0.0.1", "ua")
	var tfr *TwoFactorRequired
	if !errors.As(err, &tfr) || tfr.Challenge == "" {
		t.Fatalf("应要求双因素验证: %v", err)
	}
	if _, _, ok := m.Verify(tfr.Challenge); ok {
		t.Fatal("挑战凭据不能当作会话令牌使用")
	}
	// 绑定时用过的验证码（同一时间片）不能再次使用
	if _, _, err := m.Login2FA(tfr.Challenge, codeAt(t, secret, now), "10.0.0.1", "ua"); err == nil {
		t.Fatal("同一时间片的验证码不能重放")
	}
	now = now.Add(30 * time.Second)
	s, tok, err := m.Login2FA(tfr.Challenge, codeAt(t, secret, now), "10.0.0.1", "ua")
	if err != nil || s.User != "ops" || tok == "" {
		t.Fatalf("第二步验证: %v", err)
	}
	if _, _, err := m.Login2FA(tfr.Challenge, codeAt(t, secret, now.Add(30*time.Second)), "10.0.0.1", "ua"); err == nil {
		t.Fatal("挑战凭据只能使用一次")
	}
	// 恢复码可登录一次
	_, _, err = m.Login("ops", "0ps-pass!x", "10.0.0.1", "ua")
	errors.As(err, &tfr)
	if _, _, err := m.Login2FA(tfr.Challenge, strings.ToUpper(recovery[0]), "10.0.0.1", "ua"); err != nil {
		t.Fatalf("恢复码登录: %v", err)
	}
	_, _, err = m.Login("ops", "0ps-pass!x", "10.0.0.1", "ua")
	errors.As(err, &tfr)
	if _, _, err := m.Login2FA(tfr.Challenge, recovery[0], "10.0.0.1", "ua"); err == nil {
		t.Fatal("恢复码只能使用一次")
	}
	// 验证码连续错误计入锁定
	var locked *LockedError
	for i := 0; i < pairMaxFail+1; i++ {
		_, _, err = m.Login2FA(tfr.Challenge, "123456", "10.0.0.9", "ua")
	}
	if !errors.As(err, &locked) {
		t.Fatalf("验证码多次错误应锁定: %v", err)
	}
	// 启用双因素后不能用 Basic 认证
	if _, err := m.CheckBasic("ops", "0ps-pass!x", "10.0.0.2"); !errors.Is(err, ErrBasic2FA) {
		t.Fatalf("Basic 认证: %v", err)
	}
	// 重启后保留
	m2, _ := newMgr(t, Options{File: file})
	if v := userView(m2, "ops"); !v.TwoFactor || v.Recovery != 7 {
		t.Fatalf("重启后双因素状态: %+v", v)
	}
	// 关闭需要口令与验证码
	now = now.Add(2 * time.Minute)
	if _, err := m.DisableTOTP("ops", "wrong", codeAt(t, secret, now)); err == nil {
		t.Fatal("口令错误不能关闭")
	}
	if _, err := m.DisableTOTP("ops", "0ps-pass!x", codeAt(t, secret, now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Login("ops", "0ps-pass!x", "10.0.0.1", "ua"); err != nil {
		t.Fatalf("关闭后只需口令: %v", err)
	}
	// 管理员重置
	secret, _, _ = m.BeginTOTP("ops")
	m.EnableTOTP("ops", codeAt(t, secret, now))
	if err := m.ResetTOTP("ops"); err != nil || userView(m, "ops").TwoFactor {
		t.Fatalf("管理员重置: %v", err)
	}
}

func userView(m *Manager, name string) UserView {
	for _, u := range m.Users() {
		if u.Name == name {
			return u
		}
	}
	return UserView{}
}

// 强制双因素策略：未启用的本地账号登录后须先绑定。
func TestRequire2FA(t *testing.T) {
	m, _ := newMgr(t, Options{InitialAdmin: "Adm1n-pass!", Require2FA: true})
	s, tok, err := m.Login("admin", "Adm1n-pass!", "10.0.0.1", "")
	if err != nil || !s.MustEnroll {
		t.Fatalf("应要求绑定: %+v %v", s, err)
	}
	if v, _, _ := m.Verify(tok); !v.MustEnroll {
		t.Fatal("会话应保持待绑定状态")
	}
	secret, _, _ := m.BeginTOTP("admin")
	_, tok, err = m.EnableTOTP("admin", codeAt(t, secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if v, _, _ := m.Verify(tok); v.MustEnroll || !v.TwoFactor {
		t.Fatal("绑定后解除限制")
	}
}

// API 令牌：权限不超过所属账号、过期与吊销、所属账号删除或降权后随之变化、重启后保留。
func TestAPITokens(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	now := time.Now()
	m, _ := newMgr(t, Options{File: file, InitialAdmin: "Adm1n-pass!"})
	m.nowFunc = func() time.Time { return now }
	m.CreateUser("bot", RoleAnalyst, "B0t-pass!x")
	if _, _, err := m.CreateToken("bot", "soar", RoleAdmin, "admin", 0); !errors.Is(err, ErrTokenRole) {
		t.Fatalf("令牌权限不能超过账号权限: %v", err)
	}
	raw, v, err := m.CreateToken("bot", "soar", RoleAnalyst, "admin", 30)
	if err != nil || !strings.HasPrefix(raw, TokenPrefix) || v.Prefix != raw[:12] || v.Expires.IsZero() {
		t.Fatalf("创建令牌: %v %+v", err, v)
	}
	s, ok := m.VerifyToken(raw, "10.0.0.5")
	if !ok || s.User != "bot" || s.Role != RoleAnalyst || s.Via != "token" {
		t.Fatalf("令牌认证: %+v", s)
	}
	if _, ok := m.VerifyToken(raw+"x", ""); ok {
		t.Fatal("错误令牌")
	}
	metrics, _, _ := m.CreateToken("admin", "prometheus", RoleMetrics, "admin", 0)
	if s, ok := m.VerifyToken(metrics, ""); !ok || s.Role != RoleMetrics {
		t.Fatal("监控令牌")
	}
	// 重启后保留，且文件中只有哈希
	m2, _ := newMgr(t, Options{File: file})
	if _, ok := m2.VerifyToken(raw, ""); !ok {
		t.Fatal("重启后令牌应保留")
	}
	if data, _ := readFile(file); strings.Contains(data, raw) {
		t.Fatal("账号文件中不能保存令牌明文")
	}
	// 账号降权后令牌权限随之降低
	m.UpdateUser("bot", RoleViewer, "")
	if s, _ := m.VerifyToken(raw, ""); s.Role != RoleViewer {
		t.Fatalf("降权: %s", s.Role)
	}
	// 过期
	now = now.Add(31 * 24 * time.Hour)
	if _, ok := m.VerifyToken(raw, ""); ok {
		t.Fatal("过期令牌应失效")
	}
	// 吊销与随账号删除
	if _, err := m.DeleteToken(v.ID); err != nil {
		t.Fatal(err)
	}
	raw2, _, _ := m.CreateToken("bot", "t2", RoleViewer, "admin", 0)
	m.DeleteUser("bot")
	if _, ok := m.VerifyToken(raw2, ""); ok || len(m.Tokens()) != 1 {
		t.Fatal("账号删除后其令牌应失效")
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
