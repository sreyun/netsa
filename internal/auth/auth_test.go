package auth

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	pbkdf2Iter = 1000 // 测试中降低迭代次数
	os.Exit(m.Run())
}

// PBKDF2-HMAC-SHA256 公开测试向量。
func TestPBKDF2Vectors(t *testing.T) {
	for _, c := range []struct {
		iter int
		want string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	} {
		if got := hex.EncodeToString(pbkdf2([]byte("password"), []byte("salt"), c.iter, 32)); got != c.want {
			t.Errorf("iter=%d got %s", c.iter, got)
		}
	}
}

func TestPasswordHashing(t *testing.T) {
	h := HashPassword("S3cret!pass")
	if !IsHash(h) || !VerifyPassword(h, "S3cret!pass") || VerifyPassword(h, "S3cret!pasS") {
		t.Fatal("哈希校验错误")
	}
	if HashPassword("S3cret!pass") == h {
		t.Fatal("相同密码的哈希应因随机盐而不同")
	}
	if !VerifyPassword("plain-config-pw", "plain-config-pw") || VerifyPassword("", "") {
		t.Fatal("明文密码校验错误")
	}
	for pw, ok := range map[string]bool{"short1!": false, "onlyletters": false, "12345678": false, "abcd1234": true, "Abcd!efgh": true} {
		if (CheckStrength("u", pw) == nil) != ok {
			t.Errorf("强度 %q 应为 %v", pw, ok)
		}
	}
	if CheckStrength("admin123", "Admin123") == nil {
		t.Error("密码不能与用户名相同")
	}
	if p := RandomPassword(); len(p) != 16 || CheckStrength("admin", p) != nil {
		t.Errorf("随机密码不合格: %s", p)
	}
}

func newMgr(t *testing.T, opt Options) (*Manager, string) {
	t.Helper()
	m, initial, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	return m, initial
}

func TestBootstrapAndLogin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	m, initial := newMgr(t, Options{File: file})
	if initial == "" {
		t.Fatal("首次启动应生成管理员初始密码")
	}
	if fi, err := os.Stat(file); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("账号文件权限应为 0600: %v", err)
	}
	if _, _, err := m.Login("admin", "wrong", "1.1.1.1", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("错误密码: %v", err)
	}
	if _, _, err := m.Login("nobody", "x", "1.1.1.1", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("不存在的账号应返回相同错误: %v", err)
	}
	s, tok, err := m.Login("admin", initial, "1.1.1.1", "ua")
	if err != nil || !s.MustChange || s.Role != RoleAdmin {
		t.Fatalf("初始密码登录: %+v %v", s, err)
	}
	if v, _, ok := m.Verify(tok); !ok || v.User != "admin" {
		t.Fatal("令牌校验失败")
	}
	// 篡改令牌
	bad := strings.Replace(tok, tok[3:4], string(rune(tok[3]^1)), 1)
	if _, _, ok := m.Verify(bad); ok {
		t.Fatal("篡改的令牌应被拒绝")
	}
	// 修改密码后旧令牌失效、强制修改标记清除
	newTok, err := m.ChangePassword("admin", initial, "N3w-Passw0rd")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Verify(tok); ok {
		t.Fatal("修改密码后旧令牌应失效")
	}
	if v, _, ok := m.Verify(newTok); !ok || v.MustChange {
		t.Fatal("新令牌应有效且无需再改密码")
	}
	// 重启后（重新加载文件）新令牌仍有效，不再生成初始密码
	m2, again := newMgr(t, Options{File: file})
	if again != "" {
		t.Fatal("已有管理员时不应再生成初始密码")
	}
	if _, _, ok := m2.Verify(newTok); !ok {
		t.Fatal("重启后令牌应仍有效")
	}
	// 退出登录后令牌失效（且重启后仍失效）
	v, _, _ := m2.Verify(newTok)
	m2.Logout(v)
	if _, _, ok := m2.Verify(newTok); ok {
		t.Fatal("退出后令牌应失效")
	}
	if m3, _ := newMgr(t, Options{File: file}); func() bool { _, _, ok := m3.Verify(newTok); return ok }() {
		t.Fatal("退出状态应持久化")
	}
	if len(m2.Audit(10)) < 3 {
		t.Fatal("应记录登录审计")
	}
}

func TestLockout(t *testing.T) {
	m, initial := newMgr(t, Options{})
	for i := 0; i < pairMaxFail; i++ {
		m.Login("admin", "bad", "2.2.2.2", "")
	}
	_, _, err := m.Login("admin", initial, "2.2.2.2", "")
	var le *LockedError
	if !errors.As(err, &le) || !errors.Is(err, ErrLocked) {
		t.Fatalf("同一来源连续失败后应锁定（即使密码正确）: %v", err)
	}
	// 攻击者不能借此把管理员锁在门外：其他来源仍可登录
	if _, _, err := m.Login("admin", initial, "3.3.3.3", ""); err != nil {
		t.Fatalf("其他来源应能正常登录: %v", err)
	}
	// 锁定到期后恢复
	m.nowFunc = func() time.Time { return time.Now().Add(lockTime + time.Minute) }
	if _, _, err := m.Login("admin", initial, "2.2.2.2", ""); err != nil {
		t.Fatalf("锁定到期后应能登录: %v", err)
	}
	// 分布式暴力破解：同一账号来自大量不同来源的失败
	m3, initial3 := newMgr(t, Options{})
	for i := 0; i < userMaxFail; i++ {
		m3.Login("admin", "bad", "10.1."+string(rune('0'+i/10))+"."+string(rune('0'+i%10)), "")
	}
	if _, _, err := m3.Login("admin", initial3, "8.8.8.8", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("分布式暴力破解后账号应锁定: %v", err)
	}
	// 同一 IP 尝试大量不同账号：按 IP 锁定
	m2, _ := newMgr(t, Options{})
	for i := 0; i < ipMaxFail; i++ {
		m2.Login("user"+string(rune('a'+i%26))+"x", "bad", "9.9.9.9", "")
	}
	if _, _, err := m2.Login("admin", "whatever", "9.9.9.9", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("撞库来源 IP 应被锁定: %v", err)
	}
}

func TestUserManagementAndRoles(t *testing.T) {
	m, _ := newMgr(t, Options{InitialAdmin: "Adm1n-pass"})
	if err := m.CreateUser("viewer1", RoleViewer, "View3r-pass"); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateUser("viewer1", RoleViewer, "View3r-pass"); !errors.Is(err, ErrUserExists) {
		t.Fatal("重复账号")
	}
	if err := m.CreateUser("bad name", RoleViewer, "View3r-pass"); !errors.Is(err, ErrBadName) {
		t.Fatal("非法用户名")
	}
	s, tok, err := m.Login("viewer1", "View3r-pass", "1.1.1.1", "")
	if err != nil || s.Role != RoleViewer || !s.MustChange {
		t.Fatalf("新账号首次登录须改密码: %+v %v", s, err)
	}
	// 角色变化后旧令牌失效
	if err := m.UpdateUser("viewer1", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Verify(tok); ok {
		t.Fatal("角色变化后旧令牌应失效")
	}
	// 不能删除 / 降级最后一个管理员
	m.DeleteUser("viewer1")
	if err := m.DeleteUser("admin"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("最后一个管理员: %v", err)
	}
	if err := m.UpdateUser("admin", RoleViewer, ""); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("最后一个管理员降级: %v", err)
	}
	// 通过环境变量指定的初始密码无需强制修改
	if s, _, err := m.Login("admin", "Adm1n-pass", "1.1.1.1", ""); err != nil || s.MustChange {
		t.Fatalf("指定初始密码: %+v %v", s, err)
	}
}

func TestConfigUserAndBasic(t *testing.T) {
	m, initial := newMgr(t, Options{ConfigUser: "ops", ConfigPassword: "Ops-pass1"})
	if initial != "" {
		t.Fatal("配置了管理员时不应生成初始密码")
	}
	if _, err := m.ChangePassword("ops", "Ops-pass1", "New-pass12"); !errors.Is(err, ErrReadOnly) {
		t.Fatal("配置文件账号只读")
	}
	if s, err := m.CheckBasic("ops", "Ops-pass1", "1.1.1.1"); err != nil || s.Role != RoleAdmin {
		t.Fatalf("Basic 认证: %v", err)
	}
	if _, err := m.CheckBasic("ops", "nope", "1.1.1.1"); err == nil {
		t.Fatal("错误的 Basic 认证应失败")
	}
}

func TestSlidingRefresh(t *testing.T) {
	m, initial := newMgr(t, Options{TTL: time.Hour, MaxAge: 3 * time.Hour})
	_, tok, _ := m.Login("admin", initial, "1.1.1.1", "")
	base := time.Now()
	m.nowFunc = func() time.Time { return base.Add(40 * time.Minute) }
	_, refresh, ok := m.Verify(tok)
	if !ok || refresh == "" {
		t.Fatal("剩余有效期不足一半时应续期")
	}
	m.nowFunc = func() time.Time { return base.Add(70 * time.Minute) }
	if _, _, ok := m.Verify(tok); ok {
		t.Fatal("旧令牌到期后应失效")
	}
	if _, _, ok := m.Verify(refresh); !ok {
		t.Fatal("续期后的令牌应有效")
	}
	m.nowFunc = func() time.Time { return base.Add(4 * time.Hour) }
	if _, _, ok := m.Verify(refresh); ok {
		t.Fatal("超过最长有效期后必须重新登录")
	}
}

// 命令行重置密码后，运行中的服务自动加载新的账号文件。
func TestSetPasswordReload(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	m, _ := newMgr(t, Options{File: file})
	time.Sleep(20 * time.Millisecond) // 确保修改时间变化
	if err := SetPassword(file, "admin", "Reset-pass9"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Login("admin", "Reset-pass9", "1.1.1.1", ""); err != nil {
		t.Fatalf("应使用命令行重置后的密码: %v", err)
	}
}
