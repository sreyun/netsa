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

	"netsa/internal/config"
	"netsa/internal/ingest"
	"netsa/internal/model"
	"netsa/internal/store"
	"netsa/internal/suppress"
)

// totpAt 按 RFC 6238 计算验证码（测试中模拟身份验证器）。
func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

func decode(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("解析响应失败: %v %s", err, body)
	}
}

// newLocalUser 由管理员创建本地账号并完成首次改密，返回其会话。
func newLocalUser(t *testing.T, h http.Handler, admin []*http.Cookie, name, role string) []*http.Cookie {
	t.Helper()
	if rec := do(h, http.MethodPost, "/api/auth/users", `{"name":"`+name+`","role":"`+role+`","password":"Init-pass-123"}`, admin); rec.Code != 200 {
		t.Fatalf("创建账号 %s: %d %s", name, rec.Code, rec.Body.String())
	}
	c := login(t, h, name, "Init-pass-123")
	rec := do(h, http.MethodPost, "/api/auth/password", `{"current":"Init-pass-123","new":"Strong-pass-456"}`, c)
	if rec.Code != 200 {
		t.Fatalf("修改密码: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()
}

// 双因素认证：绑定、两步登录、错误验证码、恢复码一次性使用。
func TestTwoFactorHTTP(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	ops := newLocalUser(t, h, admin, "ops", "admin")

	var setup struct{ Secret, URI string }
	rec := do(h, http.MethodPost, "/api/auth/2fa/setup", `{}`, ops)
	decode(t, rec.Body.Bytes(), &setup)
	if rec.Code != 200 || setup.Secret == "" || !strings.HasPrefix(setup.URI, "otpauth://totp/") {
		t.Fatalf("绑定密钥: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/auth/2fa/enable", `{"code":"000000"}`, ops); rec.Code != 400 {
		t.Fatalf("错误验证码不能启用: %d", rec.Code)
	}
	now := time.Now()
	rec = do(h, http.MethodPost, "/api/auth/2fa/enable", `{"code":"`+totpAt(t, setup.Secret, now)+`"}`, ops)
	var en struct{ Recovery []string }
	decode(t, rec.Body.Bytes(), &en)
	if rec.Code != 200 || len(en.Recovery) != 8 {
		t.Fatalf("启用: %d %s", rec.Code, rec.Body.String())
	}
	ops = rec.Result().Cookies()
	if rec := do(h, http.MethodGet, "/api/auth/session", "", ops); !strings.Contains(rec.Body.String(), `"two_factor":true`) {
		t.Fatalf("启用后会话应标记双因素: %s", rec.Body.String())
	}

	// 两步登录：口令正确后不下发会话，只返回一次性挑战
	step1 := func() string {
		rec := do(h, http.MethodPost, "/api/auth/login", `{"username":"ops","password":"Strong-pass-456"}`, nil)
		var r struct {
			Need2FA   bool `json:"need_2fa"`
			Challenge string
		}
		decode(t, rec.Body.Bytes(), &r)
		if rec.Code != 200 || !r.Need2FA || r.Challenge == "" || rec.Header().Get("Set-Cookie") != "" {
			t.Fatalf("第一步: %d %s", rec.Code, rec.Body.String())
		}
		return r.Challenge
	}
	ch := step1()
	if rec := do(h, http.MethodGet, "/api/overview", "", nil, "Cookie", "netsa_session="+ch); rec.Code != 401 {
		t.Fatalf("挑战不能当作会话使用: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/auth/login/2fa", `{"challenge":"`+ch+`","code":"123456"}`, nil); rec.Code != 401 {
		t.Fatalf("错误验证码: %d", rec.Code)
	}
	// 下一个时间步的验证码（启用时用过的不能重放）
	rec = do(h, http.MethodPost, "/api/auth/login/2fa", `{"challenge":"`+ch+`","code":"`+totpAt(t, setup.Secret, now.Add(30*time.Second))+`"}`, nil)
	if rec.Code != 200 || rec.Header().Get("Set-Cookie") == "" {
		t.Fatalf("第二步: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/overview", "", rec.Result().Cookies()); rec.Code != 200 {
		t.Fatalf("两步登录后的会话: %d", rec.Code)
	}
	// 恢复码只能使用一次；挑战也只能使用一次
	ch = step1()
	if rec := do(h, http.MethodPost, "/api/auth/login/2fa", `{"challenge":"`+ch+`","code":"`+en.Recovery[0]+`"}`, nil); rec.Code != 200 {
		t.Fatalf("恢复码登录: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/auth/login/2fa", `{"challenge":"`+ch+`","code":"`+en.Recovery[1]+`"}`, nil); rec.Code != 401 {
		t.Fatalf("挑战不能重复使用: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/auth/login/2fa", `{"challenge":"`+step1()+`","code":"`+en.Recovery[0]+`"}`, nil); rec.Code != 401 {
		t.Fatalf("恢复码不能重复使用: %d", rec.Code)
	}
	// 开启双因素后 Basic 认证被拒绝（不能绕过第二因素）
	if rec := get(h, "/api/overview", "ops", "Strong-pass-456"); rec.Code != 401 {
		t.Fatalf("双因素账号不能使用 Basic 认证: %d", rec.Code)
	}
	// 管理员可重置
	if rec := do(h, http.MethodPut, "/api/auth/users/ops", `{"reset_2fa":true}`, admin); rec.Code != 200 {
		t.Fatalf("重置双因素: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/auth/login", `{"username":"ops","password":"Strong-pass-456"}`, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "need_2fa") {
		t.Fatalf("重置后直接登录: %d %s", rec.Code, rec.Body.String())
	}
}

// API 令牌与角色：Bearer 访问、运营分析员只能处置事件、指标令牌只能读 /metrics、吊销后失效。
func TestTokensAndRoles(t *testing.T) {
	s, st := testServer(t, "admin", "Adm1n-secret")
	s.Suppress, _ = suppress.Load("")
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	ana := newLocalUser(t, h, admin, "ana", "analyst")
	viewer := newLocalUser(t, h, admin, "eye", "viewer")
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.50", URI: "/x", Time: time.Now()},
		[]model.Hit{{RuleID: "r1", Name: "r1", Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultPassed}})

	// 运营分析员：可处置事件、添加误报抑制，不能修改系统配置
	if rec := do(h, http.MethodPost, "/api/incidents/1", `{"status":"investigating","note":"排查中"}`, ana); rec.Code != 200 {
		t.Fatalf("分析员处置事件: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/suppressions", `{"rule_id":"r1","ip":"203.0.113.50","reason":"测试"}`, ana); rec.Code != 200 {
		t.Fatalf("分析员添加抑制: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/alert/robots", `{"name":"x"}`, ana); rec.Code != 403 {
		t.Fatalf("分析员不能修改机器人: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/incidents/1", `{"note":"x"}`, viewer); rec.Code != 403 {
		t.Fatalf("只读账号不能处置: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/incidents", "", viewer); rec.Code != 200 {
		t.Fatalf("只读账号可查看事件: %d", rec.Code)
	}
	// 负责人必须有处置权限
	if rec := do(h, http.MethodPost, "/api/incidents/1", `{"assignee":"eye"}`, ana); rec.Code != 400 {
		t.Fatalf("不能指派给只读账号: %d", rec.Code)
	}
	var who []map[string]string
	decode(t, do(h, http.MethodGet, "/api/incidents/assignees", "", ana).Body.Bytes(), &who)
	if len(who) != 2 { // admin + ana
		t.Fatalf("可指派的负责人: %+v", who)
	}
	if rec := do(h, http.MethodGet, "/api/incidents/assignees", "", viewer); rec.Code != 403 {
		t.Fatalf("只读账号不能查看账号列表: %d", rec.Code)
	}

	// 令牌：只有管理员能创建；角色不能超过所属账号
	if rec := do(h, http.MethodPost, "/api/auth/tokens", `{"name":"t","user":"ana","role":"analyst"}`, ana); rec.Code != 403 {
		t.Fatalf("分析员不能创建令牌: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/auth/tokens", `{"name":"t","user":"eye","role":"admin"}`, admin); rec.Code == 200 {
		t.Fatal("令牌角色不能超过所属账号")
	}
	var tok struct {
		Token string
		Info  struct{ ID string }
	}
	rec := do(h, http.MethodPost, "/api/auth/tokens", `{"name":"soar","user":"ana","role":"analyst","days":30}`, admin)
	decode(t, rec.Body.Bytes(), &tok)
	if rec.Code != 200 || !strings.HasPrefix(tok.Token, "nsa_") {
		t.Fatalf("创建令牌: %d %s", rec.Code, rec.Body.String())
	}
	bearer := []string{"Authorization", "Bearer " + tok.Token}
	if rec := do(h, http.MethodGet, "/api/overview", "", nil, bearer...); rec.Code != 200 {
		t.Fatalf("Bearer 访问: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/incidents/bulk", `{"ids":[1],"status":"resolved","note":"SOAR 自动封禁"}`, nil, bearer...); rec.Code != 200 {
		t.Fatalf("Bearer 处置: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/alert/robots", `{"name":"x"}`, nil, bearer...); rec.Code != 403 {
		t.Fatalf("分析员令牌不能修改配置: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/overview", "", nil, "Authorization", "Bearer nsa_invalid"); rec.Code != 401 {
		t.Fatalf("无效令牌: %d", rec.Code)
	}
	// 指标令牌
	var mt struct{ Token string }
	decode(t, do(h, http.MethodPost, "/api/auth/tokens", `{"name":"prom","user":"admin","role":"metrics"}`, admin).Body.Bytes(), &mt)
	rec = do(h, http.MethodGet, "/metrics", "", nil, "Authorization", "Bearer "+mt.Token)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") ||
		!strings.Contains(body, `netsa_build_info{version="test"} 1`) || !strings.Contains(body, `netsa_incidents{status="resolved"} 1`) ||
		!strings.Contains(body, "netsa_suppression_rules 1") || !strings.Contains(body, "# TYPE netsa_alerts_total counter") {
		t.Fatalf("指标: %d\n%s", rec.Code, body)
	}
	if rec := do(h, http.MethodGet, "/api/overview", "", nil, "Authorization", "Bearer "+mt.Token); rec.Code != 403 {
		t.Fatalf("指标令牌只能读 /metrics: %d", rec.Code)
	}
	if rec := get(h, "/metrics"); rec.Code != 401 {
		t.Fatalf("未认证不能读取指标: %d", rec.Code)
	}
	// 吊销
	if rec := do(h, http.MethodDelete, "/api/auth/tokens/"+tok.Info.ID, "", admin); rec.Code != 200 {
		t.Fatalf("吊销令牌: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/overview", "", nil, bearer...); rec.Code != 401 {
		t.Fatalf("吊销后令牌应失效: %d", rec.Code)
	}
	// 审计记录了处置与令牌操作
	rec = do(h, http.MethodGet, "/api/auth/audit", "", admin)
	for _, want := range []string{"处置安全事件", "添加误报抑制", "创建 API 令牌", "吊销 API 令牌"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("审计中缺少 %s", want)
		}
	}
}

// 事件处置与误报抑制接口（未开启登录）。
func TestIncidentAndSuppressionAPI(t *testing.T) {
	s, st := testServer(t, "", "")
	s.Suppress, _ = suppress.Load("")
	h := s.Handler()
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		st.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, URI: "/x", Time: time.Now()},
			[]model.Hit{{RuleID: "r1", Name: "SQL 注入", Category: "SQL注入", Severity: model.Severity(2 + i%3), Result: model.ResultPassed}})
	}
	var list struct {
		Incidents []store.IncidentView
		Total     int
		Counts    store.IncidentCounts
	}
	decode(t, do(h, http.MethodGet, "/api/incidents?status=active", "", nil).Body.Bytes(), &list)
	if list.Total != 3 || list.Counts.Open != 3 || list.Incidents[0].Severity != model.SevCritical {
		t.Fatalf("事件列表（严重的在前）: %+v", list)
	}
	if rec := do(h, http.MethodPost, "/api/incidents/1", `{"status":"false_positive"}`, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "说明") {
		t.Fatalf("关闭事件须填写说明: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/incidents/99", `{"note":"x"}`, nil); rec.Code != 404 {
		t.Fatalf("事件不存在: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/incidents/bulk", `{"ids":[],"note":"x"}`, nil); rec.Code != 400 {
		t.Fatalf("批量处置须选择事件: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/incidents/bulk", `{"ids":[1,2],"status":"ignored","note":"测试流量"}`, nil); rec.Code != 200 {
		t.Fatalf("批量处置: %d %s", rec.Code, rec.Body.String())
	}
	var d store.IncidentDetail
	decode(t, do(h, http.MethodGet, "/api/incidents/1", "", nil).Body.Bytes(), &d)
	if d.Status != store.IncIgnored || len(d.Notes) != 1 || len(d.AlertList) != 1 || d.AlertList[0].IncidentID != 1 {
		t.Fatalf("事件详情: %+v", d)
	}
	decode(t, do(h, http.MethodGet, "/api/incidents?status=closed", "", nil).Body.Bytes(), &list)
	if list.Total != 2 {
		t.Fatalf("已关闭: %d", list.Total)
	}
	if rec := do(h, http.MethodGet, "/api/alerts", "", nil); !strings.Contains(rec.Body.String(), `"incident_id":1`) {
		t.Fatal("告警应带上所属事件编号")
	}

	// 误报抑制
	if rec := do(h, http.MethodPost, "/api/suppressions", `{"rule_id":"r1"}`, nil); rec.Code != 400 {
		t.Fatalf("抑制须填写原因: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/suppressions", `{"category":"SQL注入","reason":"x"}`, nil); rec.Code != 400 {
		t.Fatalf("只按类型抑制范围过大: %d", rec.Code)
	}
	var rule suppress.Rule
	rec := do(h, http.MethodPost, "/api/suppressions", `{"rule_id":"r1","target":"/x","reason":"业务接口误报","days":7}`, nil)
	decode(t, rec.Body.Bytes(), &rule)
	if rec.Code != 200 || rule.ID == "" || rule.Expires.IsZero() {
		t.Fatalf("添加抑制: %d %s", rec.Code, rec.Body.String())
	}
	var sl struct {
		Rules []suppress.Rule
		Total int64
	}
	decode(t, do(h, http.MethodGet, "/api/suppressions", "", nil).Body.Bytes(), &sl)
	if len(sl.Rules) != 1 {
		t.Fatalf("抑制列表: %+v", sl)
	}
	if rec := do(h, http.MethodDelete, "/api/suppressions/"+rule.ID, "", nil); rec.Code != 200 {
		t.Fatalf("删除抑制: %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/suppressions/"+rule.ID, "", nil); rec.Code != 404 {
		t.Fatalf("重复删除: %d", rec.Code)
	}
}

// syslog 发送端管理接口：登记、白名单开关（空白名单保护）、配置文件登记只读、权限。
func TestSyslogSendersAPI(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	var err error
	s.Ingest.Senders, err = ingest.NewSenders(config.SyslogConfig{Senders: []config.SyslogSender{{CIDR: "10.9.0.0/16", Action: "block"}}}, "", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	ana := newLocalUser(t, h, admin, "ana", "analyst")
	if rec := do(h, http.MethodPut, "/api/syslog/policy", `{"allowlist":true}`, admin); rec.Code != 400 || !strings.Contains(rec.Body.String(), "白名单中没有允许的发送端") {
		t.Fatalf("空白名单不能开启: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/syslog/senders", `{"cidr":"10.1.1.1","name":"核心防火墙","group":"防火墙"}`, ana); rec.Code != 403 {
		t.Fatalf("登记发送端需要管理员: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/syslog/senders", `{"cidr":"0.0.0.0/0","name":"all"}`, admin); rec.Code != 400 {
		t.Fatalf("范围过大的网段: %d", rec.Code)
	}
	var r ingest.SenderRule
	rec := do(h, http.MethodPost, "/api/syslog/senders", `{"cidr":"10.1.1.1","name":"核心防火墙","group":"防火墙","silence":"10m"}`, admin)
	decode(t, rec.Body.Bytes(), &r)
	if rec.Code != 200 || r.ID == "" || r.Action != "allow" {
		t.Fatalf("登记: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/syslog/senders", `{"cidr":"10.1.1.1"}`, admin); rec.Code != 409 {
		t.Fatalf("重复登记: %d", rec.Code)
	}
	if rec := do(h, http.MethodPut, "/api/syslog/senders/cfg-1", `{"cidr":"10.9.0.0/16"}`, admin); rec.Code != 403 {
		t.Fatalf("配置文件中的登记只读: %d", rec.Code)
	}
	if rec := do(h, http.MethodPut, "/api/syslog/policy", `{"allowlist":true}`, admin); rec.Code != 200 {
		t.Fatalf("开启白名单: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Report ingest.SenderReport
	}
	decode(t, do(h, http.MethodGet, "/api/syslog/senders", "", ana).Body.Bytes(), &out)
	rep := out.Report
	if !rep.Allowlist || len(rep.Rules) != 2 || len(rep.Senders) != 1 || rep.Senders[0].Status != "offline" || rep.Senders[0].Group != "防火墙" {
		t.Fatalf("发送端报告: %+v", rep)
	}
	if rec := do(h, http.MethodPut, "/api/syslog/senders/"+r.ID, `{"cidr":"10.1.1.1","name":"核心防火墙-A","group":"防火墙","action":"block"}`, admin); rec.Code != 200 {
		t.Fatalf("修改: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodDelete, "/api/syslog/senders/"+r.ID, "", admin); rec.Code != 200 {
		t.Fatalf("删除: %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/syslog/senders/"+r.ID, "", admin); rec.Code != 404 {
		t.Fatalf("重复删除: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/auth/audit", "", admin); !strings.Contains(rec.Body.String(), "登记 syslog 发送端") || !strings.Contains(rec.Body.String(), "syslog 发送端白名单") {
		t.Fatal("发送端操作应记录审计")
	}
}
