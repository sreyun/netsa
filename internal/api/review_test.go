package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/ingest"
	"netsa/internal/learn"
)

// 交付前复查发现的接口问题：未知操作、缺少字段、配置缺失时的返回
func TestReviewHardening(t *testing.T) {
	s, _ := testServer(t, "", "")
	s.Learn, _ = learn.Load(learn.Options{Calibrate: true})
	var err error
	if s.Ingest.Senders, err = ingest.NewSenders(config.SyslogConfig{}, "", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	rule := s.engine().Rules()[0].ID

	// 规则锁定：只接受 pin / unpin，锁定的规则必须存在
	if rec := aiuseCall(h, http.MethodPost, "/api/learn/rules/"+rule+"/zzz", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("未知操作应返回 404：%d %s", rec.Code, rec.Body.String())
	}
	if rec := aiuseCall(h, http.MethodPost, "/api/learn/rules/no-such-rule/pin", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("锁定不存在的规则应返回 404：%d", rec.Code)
	}
	if rec := aiuseCall(h, http.MethodPost, "/api/learn/rules/"+rule+"/pin", ""); rec.Code != http.StatusOK {
		t.Fatalf("锁定已有规则：%d %s", rec.Code, rec.Body.String())
	}
	if rec := aiuseCall(h, http.MethodPost, "/api/learn/rules/no-such-rule/unpin", ""); rec.Code != http.StatusOK {
		t.Fatalf("解锁不检查规则是否存在（清理旧的锁定）：%d", rec.Code)
	}

	// 发送端白名单：缺少开关时不能当作关闭
	if rec := aiuseCall(h, http.MethodPut, "/api/syslog/policy", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺少 allowlist 应返回 400：%d %s", rec.Code, rec.Body.String())
	}
	if rec := aiuseCall(h, http.MethodPut, "/api/syslog/policy", `{"allowlist":false}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allowlist":false`) {
		t.Fatalf("明确关闭：%d %s", rec.Code, rec.Body.String())
	}

	// 发送报告邮件：没有配置邮件服务器是配置问题（400），不是发信失败（502）
	rec := aiuseCall(h, http.MethodPost, "/api/reports/email", `{"period":"week","range":"recent"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "未配置邮件服务器") {
		t.Fatalf("未配置邮件服务器：%d %s", rec.Code, rec.Body.String())
	}
	s.Cfg.Report.SMTP.Host, s.Cfg.Report.SMTP.From = "127.0.0.1", "netsa@example.com"
	if rec := aiuseCall(h, http.MethodPost, "/api/reports/email", `{"period":"week"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "没有收件人") {
		t.Fatalf("没有收件人：%d %s", rec.Code, rec.Body.String())
	}
}

// 配置文件账号不能在页面修改密码：会话信息中带上原因，页面打开“修改密码”时直接提示
// 公开演示环境：未登录的会话带演示账号；没有开启时不带
func TestSessionDemoLogin(t *testing.T) {
	s, _ := testServer(t, "admin", "Demo-pass-2026")
	h := s.Handler()
	if rec := do(h, http.MethodGet, "/api/auth/session", "", nil); strings.Contains(rec.Body.String(), "demo") {
		t.Fatalf("没有开启 demo_login 时不应返回演示账号：%s", rec.Body.String())
	}
	s.Cfg.Server.DemoLogin = true
	rec := do(h, http.MethodGet, "/api/auth/session", "", nil)
	var v struct {
		Authenticated bool              `json:"authenticated"`
		Demo          map[string]string `json:"demo"`
	}
	decode(t, rec.Body.Bytes(), &v)
	if v.Authenticated || v.Demo["username"] != "admin" || v.Demo["password"] != "Demo-pass-2026" {
		t.Fatalf("开启 demo_login 后未登录的会话应带演示账号：%s", rec.Body.String())
	}
	if rec := get(h, "/api/auth/session", "admin", "Demo-pass-2026"); strings.Contains(rec.Body.String(), "Demo-pass-2026") {
		t.Fatalf("已登录的会话不需要再返回密码：%s", rec.Body.String())
	}
}

func TestSessionPasswordNote(t *testing.T) {
	s, _ := testServer(t, "admin", "secret")
	h := s.Handler()
	rec := get(h, "/api/auth/session", "admin", "secret")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "请在配置文件中修改") {
		t.Fatalf("配置文件账号的会话应带 password_note：%d %s", rec.Code, rec.Body.String())
	}
	if err := s.Auth.CreateUser("analyst1", "analyst", "Strong-pass-2026!"); err != nil {
		t.Fatal(err)
	}
	if note := s.Auth.PasswordNote("analyst1"); note != "" {
		t.Fatalf("本地账号可以修改密码，不应有提示：%q", note)
	}
}
