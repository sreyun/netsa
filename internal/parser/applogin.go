package parser

import (
	"strings"

	"netsa/internal/model"
)

// AppLogin 解析业务系统、统一身份认证、SSO 网关输出的 JSON 登录日志（P3-3），用于账号盗用检测
// （不可能的旅行、首次从新的国家登录、多地并发登录）与暴力破解、撞库检测。字段按常见键名识别：
// 事件类型（event / action / type / operation 中含 login、logon、signin、authenticate、登录）、账号、来源地址、
// 结果（success / failed …）与系统名称。要求同时出现这几类字段，其他 JSON 日志不会被误认。
type AppLogin struct{}

func (AppLogin) Name() string { return "app_login" }

var (
	loginEventKeys = []string{"event", "action", "event_type", "eventtype", "type", "operation", "op", "event_name", "eventname", "event.action", "category", "activity"}
	loginUserKeys  = []string{"username", "user_name", "user", "account", "login_name", "loginname", "login", "userid", "user_id", "uid", "email", "principal", "user.name"}
	loginIPKeys    = []string{"client_ip", "clientip", "src_ip", "source_ip", "sourceip", "remote_addr", "remote_ip", "remoteip", "login_ip", "loginip", "client.ip", "source.ip", "ip", "ip_address", "ipaddress"}
	loginResKeys   = []string{"result", "outcome", "event.outcome", "status", "login_result", "loginresult", "success", "state", "succeeded"}
	loginAppKeys   = []string{"app", "application", "app_name", "appname", "system", "service", "client", "client_id", "product", "service.name"}
)

func loginWord(v string) bool {
	v = strings.ToLower(v)
	for _, w := range []string{"login", "logon", "signin", "sign_in", "sign-in", "authenticat", "登录", "认证"} {
		if strings.Contains(v, w) {
			return !strings.Contains(v, "logout") && !strings.Contains(v, "logoff") && !strings.Contains(v, "signout") && !strings.Contains(v, "退出")
		}
	}
	return false
}

func (AppLogin) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return nil, false
	}
	l := strings.ToLower(line)
	if !strings.Contains(l, "login") && !strings.Contains(l, "logon") && !strings.Contains(l, "sign") &&
		!strings.Contains(l, "authenticat") && !strings.Contains(line, "登录") && !strings.Contains(line, "认证") {
		return nil, false
	}
	m, ok := unmarshalLog(line)
	if !ok {
		return nil, false
	}
	kv := flattenLower(m)
	isLogin := false
	for _, k := range loginEventKeys {
		if v, ok := kv[k]; ok && loginWord(v) {
			isLogin = true
			break
		}
	}
	user, ip := pick(kv, loginUserKeys...), ""
	for _, k := range loginIPKeys {
		v := strings.TrimSpace(kv[k])
		if i := strings.IndexByte(v, ','); i > 0 {
			v = strings.TrimSpace(v[:i]) // X-Forwarded-For 取第一个
		}
		if isIP(v) {
			ip = v
			break
		}
	}
	if !isLogin || user == "" || ip == "" {
		return nil, false
	}
	okRes, known := loginResult(pick(kv, loginResKeys...))
	if !known {
		return nil, false // 没有结果的事件（登录页访问）不计入
	}
	svc := "应用登录"
	if app := pick(kv, loginAppKeys...); app != "" {
		svc = "应用登录（" + Printable(app, 40) + "）"
	}
	ev := authEvent("app_login", svc, ip, Printable(user, 80), okRes)
	ev.Host = strings.ToLower(pick(kv, "host", "hostname", "server", "domain"))
	if mfa := strings.ToLower(pick(kv, "mfa", "2fa", "auth_method", "method", "factor")); mfa != "" {
		ev.URI = mfa // 认证方式（证据中注明）
	}
	ev.Time = ParseTime(pick(kv, "@timestamp", "timestamp", "time", "login_time", "event_time", "created_at", "datetime"))
	return ev, true
}

// loginResult 识别登录结果，第二个返回值为 false 表示无法判断。
func loginResult(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "success", "succeeded", "successful", "ok", "true", "1", "pass", "passed", "allow", "allowed", "成功", "登录成功", "200":
		return true, true
	case "fail", "failed", "failure", "false", "0", "denied", "deny", "error", "invalid", "rejected", "失败", "登录失败", "401", "403", "locked":
		return false, true
	}
	return false, false
}
