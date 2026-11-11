package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"netsa/internal/audit"
	"netsa/internal/auth"
	"netsa/internal/qr"
	"netsa/internal/sso"
)

const sessionCookie = "netsa_session"

type sessionKey struct{}

// sessionOf 返回请求的登录会话（未登录为 nil）。
func sessionOf(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(sessionKey{}).(*auth.Session)
	return s
}

// publicPaths 不需要登录即可访问（登录页及其资源、登录接口）。
var publicPaths = map[string]bool{
	"/api/auth/oidc/start": true, "/api/auth/oidc/callback": true, "/login.html": true, "/login.js": true, "/login.css": true, "/api/auth/login": true, "/api/auth/login/2fa": true, "/api/auth/session": true,
}

// mustChangeAllowed 是使用初始密码登录、尚未修改密码时仍可访问的接口。
var mustChangeAllowed = map[string]bool{"/api/auth/session": true, "/api/auth/password": true, "/api/auth/logout": true}

// mustEnrollAllowed 是策略要求启用双因素认证、尚未绑定时仍可访问的接口。
var mustEnrollAllowed = map[string]bool{"/api/auth/session": true, "/api/auth/logout": true, "/api/auth/2fa/setup": true, "/api/auth/2fa/enable": true}

// credentialPaths 是修改本账号凭据的接口：只能在交互式登录的会话里操作。API 令牌只代表一组受限的权限，
// 不能用来给所属账号绑定 / 关闭身份验证器或修改密码（这些接口会换发完整权限的登录会话）。
var credentialPaths = map[string]bool{"/api/auth/password": true, "/api/auth/2fa/setup": true, "/api/auth/2fa/enable": true, "/api/auth/2fa/disable": true}

// selfService 是任何已登录账号都可以执行的写操作（只作用于自己的账号）。
var selfService = map[string]bool{
	"/api/auth/login": true, "/api/auth/login/2fa": true, "/api/auth/logout": true, "/api/auth/password": true,
	"/api/auth/2fa/setup": true, "/api/auth/2fa/enable": true, "/api/auth/2fa/disable": true,
}

// requiredRole 返回请求所需的最低角色：查看为只读；事件处置与误报抑制为运营分析员；
// 账号、令牌、审计与其余配置变更为管理员；空字符串表示任何已登录账号均可（自助操作）。
func requiredRole(r *http.Request) string {
	p := r.URL.Path
	// 性能剖析包含内存与协程内容，只允许管理员使用
	if strings.HasPrefix(p, "/debug/pprof") {
		return auth.RoleAdmin
	}
	if !strings.HasPrefix(p, "/api/") {
		return auth.RoleViewer
	}
	// 备份包含密码哈希和模型密钥；对接状态包含内部系统的地址
	if strings.HasPrefix(p, "/api/admin") || strings.HasPrefix(p, "/api/integrations") {
		return auth.RoleAdmin
	}
	// 封禁申请由分析员提交（名单中有处置原因），审批与解除由管理员进行（/api/block/{id}/...，见最后的默认值）
	if p == "/api/block" {
		return auth.RoleAnalyst
	}
	// 锁定 / 解锁自学习校准会改变检测等级：只允许管理员；外部模型配置决定事件内容发往哪里（查看也只允许管理员）
	if strings.HasPrefix(p, "/api/auth/users") || p == "/api/auth/audit" || strings.HasPrefix(p, "/api/audit") || strings.HasPrefix(p, "/api/auth/tokens") ||
		strings.HasPrefix(p, "/api/compliance") || strings.HasPrefix(p, "/api/learn/rules") || p == "/api/learn/policy" || strings.HasPrefix(p, "/api/ai/") {
		return auth.RoleAdmin
	}
	// 原始日志可能包含 Cookie、令牌、个人信息等敏感内容：检索与导出需要运营分析员权限
	// 可指派账号列表（平台用户名与角色）只提供给能处置事件的角色；自学习包含平台账号的登录异常与研判记录
	// 取证包包含原始日志
	if strings.HasPrefix(p, "/api/incidents/") && strings.HasSuffix(p, "/evidence") {
		return auth.RoleAnalyst
	}
	if strings.HasPrefix(p, "/api/rawlog/search") || strings.HasPrefix(p, "/api/rawlog/export") || p == "/api/incidents/assignees" || strings.HasPrefix(p, "/api/learn") {
		return auth.RoleAnalyst
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return auth.RoleViewer
	}
	if selfService[p] {
		return ""
	}
	if strings.HasPrefix(p, "/api/incidents") || strings.HasPrefix(p, "/api/suppressions") || strings.HasPrefix(p, "/api/authscans") || strings.HasPrefix(p, "/api/deception") || strings.HasPrefix(p, "/api/learn/suggestions") || r.Method == http.MethodPut && strings.HasPrefix(p, "/api/vulns/") {
		return auth.RoleAnalyst
	}
	return auth.RoleAdmin
}

var roleLabel = map[string]string{auth.RoleAdmin: "管理员", auth.RoleAnalyst: "运营分析员", auth.RoleViewer: "只读"}

// authenticate 校验登录状态，并按角色控制访问。未开启登录时所有请求视为管理员。
func (s *Server) authenticate(next http.Handler) http.Handler {
	if s.Auth == nil {
		anon := &auth.Session{User: "anonymous", Role: auth.RoleAdmin}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, anon)))
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.currentSession(w, r)
		path := r.URL.Path
		if sess == nil {
			switch {
			case publicPaths[path]:
				next.ServeHTTP(w, r)
			case err != nil:
				writeErrorCode(w, http.StatusUnauthorized, err.Error(), "unauthenticated")
			case strings.HasPrefix(path, "/api/"):
				writeErrorCode(w, http.StatusUnauthorized, "未登录或登录已过期，请重新登录", "unauthenticated")
			case path == "/" || path == "/index.html":
				http.Redirect(w, r, "/login.html", http.StatusFound)
			default:
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
			return
		}
		if path == "/login.html" {
			http.Redirect(w, r, "/", http.StatusFound) // 已登录
			return
		}
		if sess.MustChange && strings.HasPrefix(path, "/api/") && !mustChangeAllowed[path] {
			writeErrorCode(w, http.StatusForbidden, "请先修改初始密码", "must_change_password")
			return
		}
		// 两道检查按顺序生效：先改初始密码，改完（换发的新会话不再要求改密）再绑定身份验证器。
		// 同时检查会互相卡死：改密接口被绑定检查拦住、绑定接口被改密检查拦住
		if !sess.MustChange && sess.MustEnroll && strings.HasPrefix(path, "/api/") && !mustEnrollAllowed[path] {
			writeErrorCode(w, http.StatusForbidden, "安全策略要求启用双因素认证，请先绑定身份验证器", "must_enroll_2fa")
			return
		}
		if credentialPaths[path] && sess.Via != "session" {
			writeErrorCode(w, http.StatusForbidden, "修改密码与双因素认证只能在登录页面登录后操作，不能使用 API 令牌或 HTTP Basic 认证", "interactive_only")
			return
		}
		// 监控令牌只能读取 /metrics
		if sess.Role == auth.RoleMetrics {
			if path != "/metrics" {
				writeErrorCode(w, http.StatusForbidden, "该令牌只能用于读取 /metrics 监控指标", "forbidden")
				return
			}
		} else if need := requiredRole(r); need != "" && !auth.RoleAtLeast(sess.Role, need) {
			writeErrorCode(w, http.StatusForbidden, "当前账号（"+roleLabel[sess.Role]+"）无权执行该操作，需要"+roleLabel[need]+"权限", "forbidden")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

// currentSession 依次检查 API 令牌（Authorization: Bearer）、会话 Cookie 与 HTTP Basic 认证。
func (s *Server) currentSession(w http.ResponseWriter, r *http.Request) (*auth.Session, error) {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		if sess, ok := s.Auth.VerifyToken(strings.TrimSpace(h[7:]), s.clientIP(r)); ok {
			return sess, nil
		}
		return nil, errors.New("API 令牌无效、已过期或已吊销")
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if sess, refresh, ok := s.Auth.Verify(c.Value); ok {
			if refresh != "" {
				s.setCookie(w, r, refresh, sess.Expires)
			}
			return sess, nil
		}
	}
	if u, p, ok := r.BasicAuth(); ok {
		if !s.acquireHash() {
			return nil, errors.New("登录请求过多，请稍后重试")
		}
		defer s.releaseHash()
		sess, err := s.Auth.CheckBasic(u, p, s.clientIP(r))
		if err != nil {
			return nil, err
		}
		return sess, nil
	}
	return nil, nil
}

// sessionAlive 返回检查请求所用登录会话是否仍然有效的函数（用于 SSE 等长连接）；未开启登录时返回 nil。
func (s *Server) sessionAlive(r *http.Request) func() bool {
	if s.Auth == nil {
		return nil
	}
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		tok, ip := strings.TrimSpace(h[7:]), s.clientIP(r)
		return func() bool { _, ok := s.Auth.VerifyToken(tok, ip); return ok }
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		token := c.Value
		return func() bool { _, _, ok := s.Auth.Verify(token); return ok }
	}
	if u, _, ok := r.BasicAuth(); ok { // Basic 认证不重复计算密码哈希，只检查账号仍然存在
		return func() bool { return s.Auth.HasUser(u) }
	}
	return func() bool { return false }
}

// acquireHash 限制同时进行的密码哈希计算（每次约数百毫秒 CPU），防止大量登录请求耗尽 CPU。
func (s *Server) acquireHash() bool {
	select {
	case s.hashSem <- struct{}{}:
		return true
	case <-time.After(3 * time.Second):
		return false
	}
}

func (s *Server) releaseHash() { <-s.hashSem }

func (s *Server) clientIP(r *http.Request) string {
	if s.Pipeline != nil && s.Pipeline.RealIP != nil {
		// 同名请求头的多行等价于一行逗号分隔的列表（RFC 9110）：HAProxy 等代理把自己的值另起一行追加，
		// 只取第一行会采信客户端自己写的值（绕过来源白名单与登录锁定、伪造审计中的地址）
		return s.Pipeline.RealIP.ClientIP(r.RemoteAddr, strings.Join(r.Header.Values("X-Forwarded-For"), ","))
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// setCookie 下发登录 Cookie：HttpOnly 防脚本读取；SameSite=Lax 使从群聊中的告警链接进入时保持登录，
// 跨站的写请求另由 sameOrigin 拦截；通过 HTTPS 访问时加 Secure。
func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"), Expires: exp,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
		Secure: r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")})
}

// audit 记录一次操作审计（未开启登录时不记录）。err 不为空表示操作失败。
func (s *Server) audit(r *http.Request, action, detail string, err error) {
	if s.Auth == nil && s.Trail == nil {
		return
	}
	user := ""
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	if s.Auth == nil { // 未开启登录：直接写入审计链
		s.Trail.AppendAudit(auth.Record{User: "anonymous", IP: s.clientIP(r), Action: action, Detail: detail, OK: err == nil, Reason: reason})
		return
	}
	s.Auth.LogAction(user, s.clientIP(r), action, detail, err == nil, reason)
}

func writeErrorCode(w http.ResponseWriter, code int, msg, reason string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": reason})
}

func sessionView(sess *auth.Session, enabled bool) map[string]any {
	return map[string]any{"authenticated": true, "user": sess.User, "role": sess.Role, "must_change": sess.MustChange, "auth_enabled": enabled,
		"expires": sess.Expires, "two_factor": sess.TwoFactor, "must_enroll": sess.MustEnroll, "via": sess.Via}
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, sessionView(sessionOf(r), false))
		return
	}
	var f struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	f.Username = strings.TrimSpace(f.Username)
	// 账号名最长 32 个字符：超长的用户名不可能存在，不进入锁定统计（避免任意长度的键撑大失败计数表）
	if f.Username == "" || f.Password == "" || len(f.Password) > 256 || len(f.Username) > 64 {
		writeErrorCode(w, http.StatusBadRequest, "请输入用户名和密码", "bad_request")
		return
	}
	if !s.acquireHash() {
		writeErrorCode(w, http.StatusTooManyRequests, "登录请求过多，请稍后重试", "busy")
		return
	}
	sess, token, err := s.Auth.Login(f.Username, f.Password, s.clientIP(r), r.UserAgent())
	s.releaseHash()
	var le *auth.LockedError
	var tfr *auth.TwoFactorRequired
	switch {
	case errors.As(err, &tfr):
		// 口令正确，第二步输入身份验证器中的验证码（或恢复码）
		writeJSON(w, map[string]any{"authenticated": false, "need_2fa": true, "challenge": tfr.Challenge})
		return
	case errors.As(err, &le):
		w.Header().Set("Retry-After", strconv.Itoa(int(le.Wait.Seconds())+1))
		writeErrorCode(w, http.StatusTooManyRequests, err.Error(), "locked")
		return
	case err != nil:
		writeErrorCode(w, http.StatusUnauthorized, err.Error(), "bad_credentials")
		return
	}
	s.setCookie(w, r, token, sess.Expires)
	writeJSON(w, sessionView(sess, true))
}

// authLogin2FA 是两步登录的第二步：挑战凭据 + 验证码 / 恢复码。
func (s *Server) authLogin2FA(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		return
	}
	var f struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	sess, token, err := s.Auth.Login2FA(f.Challenge, f.Code, s.clientIP(r), r.UserAgent())
	var le *auth.LockedError
	switch {
	case errors.As(err, &le):
		w.Header().Set("Retry-After", strconv.Itoa(int(le.Wait.Seconds())+1))
		writeErrorCode(w, http.StatusTooManyRequests, err.Error(), "locked")
		return
	case err != nil:
		writeErrorCode(w, http.StatusUnauthorized, err.Error(), "bad_code")
		return
	}
	s.setCookie(w, r, token, sess.Expires)
	writeJSON(w, sessionView(sess, true))
}

// auth2FASetup 生成绑定密钥（验证码确认前不生效）。
func (s *Server) auth2FASetup(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		return
	}
	secret, uri, err := s.Auth.BeginTOTP(sessionOf(r).User)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	resp := map[string]any{"secret": secret, "uri": uri}
	if code, err := qr.Encode([]byte(uri)); err == nil {
		resp["qr_svg"] = code.SVG(5)
	}
	writeJSON(w, resp)
}

// auth2FAEnable 用验证码确认绑定，返回一次性恢复码（只显示这一次）。
func (s *Server) auth2FAEnable(w http.ResponseWriter, r *http.Request) {
	var f struct {
		Code string `json:"code"`
	}
	if s.Auth == nil || !decodeForm(w, r, &f) {
		return
	}
	recovery, token, err := s.Auth.EnableTOTP(sessionOf(r).User, f.Code)
	s.audit(r, "启用双因素认证", "", err)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	if ns, _, ok := s.Auth.Verify(token); ok && sessionOf(r).Via == "session" { // 不把令牌、Basic 凭据换成登录会话
		s.setCookie(w, r, token, ns.Expires)
	}
	writeJSON(w, map[string]any{"ok": true, "recovery": recovery})
}

// auth2FADisable 关闭自己的双因素认证（需口令与验证码）。
func (s *Server) auth2FADisable(w http.ResponseWriter, r *http.Request) {
	var f struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if s.Auth == nil || !decodeForm(w, r, &f) {
		return
	}
	if !s.acquireHash() {
		writeErrorCode(w, http.StatusTooManyRequests, "请求过多，请稍后重试", "busy")
		return
	}
	token, err := s.Auth.DisableTOTP(sessionOf(r).User, f.Password, f.Code)
	s.releaseHash()
	s.audit(r, "关闭双因素认证", "", err)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	if ns, _, ok := s.Auth.Verify(token); ok && sessionOf(r).Via == "session" { // 不把令牌、Basic 凭据换成登录会话
		s.setCookie(w, r, token, ns.Expires)
	}
	writeJSON(w, map[string]any{"ok": true})
}

// authTokens 列出 API 令牌（管理员）。
func (s *Server) authTokens(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, []auth.TokenView{})
		return
	}
	writeJSON(w, s.Auth.Tokens())
}

// authTokenCreate 创建 API 令牌，明文只在响应中返回这一次。
func (s *Server) authTokenCreate(w http.ResponseWriter, r *http.Request) {
	var f struct {
		Name string `json:"name"`
		User string `json:"user"`
		Role string `json:"role"`
		Days int    `json:"days"`
	}
	if s.Auth == nil || !decodeForm(w, r, &f) {
		if s.Auth == nil {
			writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		}
		return
	}
	raw, v, err := s.Auth.CreateToken(f.User, f.Name, f.Role, sessionOf(r).User, f.Days)
	s.audit(r, "创建 API 令牌", f.Name+"（"+f.User+" · "+f.Role+"）", err)
	if err != nil {
		writeErrorCode(w, statusFor(err), err.Error(), "bad_request")
		return
	}
	writeJSON(w, map[string]any{"token": raw, "info": v})
}

// authTokenDelete 吊销 API 令牌。
func (s *Server) authTokenDelete(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		return
	}
	v, err := s.Auth.DeleteToken(r.PathValue("id"))
	s.audit(r, "吊销 API 令牌", v.Name+" "+v.Prefix, err)
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, err.Error(), "not_found")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if sess == nil { // 未登录不视为错误（登录页据此判断），避免浏览器控制台出现 401 报错
		res := map[string]any{"authenticated": false, "auth_enabled": true}
		if s.OIDC != nil {
			res["oidc"] = s.OIDC.DisplayName()
		}
		writeJSON(w, res)
		return
	}
	writeJSON(w, sessionView(sess, s.Auth != nil))
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if s.Auth != nil {
		s.audit(r, "退出登录", "", nil)
		s.Auth.Logout(sessionOf(r))
	}
	s.clearCookie(w, r)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) authPassword(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		return
	}
	var f struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	sess := sessionOf(r)
	if !s.acquireHash() {
		writeErrorCode(w, http.StatusTooManyRequests, "请求过多，请稍后重试", "busy")
		return
	}
	token, err := s.Auth.ChangePassword(sess.User, f.Current, f.New)
	s.releaseHash()
	s.audit(r, "修改密码", "", err)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	// 修改密码后其他会话全部失效，当前会话换发新令牌
	if ns, _, ok := s.Auth.Verify(token); ok && sessionOf(r).Via == "session" { // 不把令牌、Basic 凭据换成登录会话
		s.setCookie(w, r, token, ns.Expires)
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) authUsers(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, map[string]any{"users": []auth.UserView{}, "auth_enabled": false})
		return
	}
	writeJSON(w, map[string]any{"users": s.Auth.Users(), "auth_enabled": true, "me": sessionOf(r).User})
}

func (s *Server) authUserCreate(w http.ResponseWriter, r *http.Request) {
	var f struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if s.Auth == nil || !decodeForm(w, r, &f) {
		if s.Auth == nil {
			writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		}
		return
	}
	err := s.Auth.CreateUser(strings.TrimSpace(f.Name), f.Role, f.Password)
	s.audit(r, "创建账号", strings.TrimSpace(f.Name)+"（"+f.Role+"）", err)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), "bad_request")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) authUserUpdate(w http.ResponseWriter, r *http.Request) {
	var f struct {
		Role     string `json:"role"`
		Password string `json:"password"`
		Reset2FA bool   `json:"reset_2fa"`
	}
	if s.Auth == nil || !decodeForm(w, r, &f) {
		if s.Auth == nil {
			writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		}
		return
	}
	if f.Reset2FA {
		err := s.Auth.ResetTOTP(r.PathValue("name"))
		s.audit(r, "重置双因素认证", r.PathValue("name"), err)
		if err != nil {
			writeErrorCode(w, statusFor(err), err.Error(), "bad_request")
			return
		}
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	err := s.Auth.UpdateUser(r.PathValue("name"), f.Role, f.Password)
	detail := r.PathValue("name")
	if f.Role != "" {
		detail += " 角色改为 " + f.Role
	}
	if f.Password != "" {
		detail += " 重置密码"
	}
	s.audit(r, "修改账号", detail, err)
	if err != nil {
		writeErrorCode(w, statusFor(err), err.Error(), "bad_request")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) authUserDelete(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		return
	}
	name := r.PathValue("name")
	err := s.Auth.DeleteUser(name)
	s.audit(r, "删除账号", name, err)
	if err != nil {
		writeErrorCode(w, statusFor(err), err.Error(), "bad_request")
		return
	}
	if name == sessionOf(r).User {
		s.clearCookie(w, r)
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) authAudit(w http.ResponseWriter, r *http.Request) {
	if s.Trail != nil { // 优先使用审计链（记录更完整，可按条件检索）
		writeJSON(w, s.Trail.Search(audit.Query{Limit: clamp(qint(r, "limit", 100), 1, 2000), Action: r.URL.Query().Get("action")}))
		return
	}
	if s.Auth == nil {
		writeJSON(w, []auth.Record{})
		return
	}
	writeJSON(w, s.Auth.Audit(clamp(qint(r, "limit", 100), 1, 500)))
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, auth.ErrNoUser), errors.Is(err, auth.ErrNoToken):
		return http.StatusNotFound
	case errors.Is(err, auth.ErrReadOnly), errors.Is(err, auth.ErrLastAdmin):
		return http.StatusForbidden
	}
	return http.StatusBadRequest
}

const oidcStateCookie = "netsa_oidc_state"

// oidcStart 跳转到身份提供方。state 写入只用于回调路径的 Cookie，回调时与参数比对，把登录绑定到发起它的浏览器。
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil || s.Auth == nil {
		http.NotFound(w, r)
		return
	}
	redirect, state, err := s.OIDC.Start(r.Context())
	if err != nil {
		log.Printf("[oidc] %v", err)
		http.Redirect(w, r, "/login.html#sso_error=unavailable", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: state, Path: "/api/auth/oidc", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600,
		Secure: r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")})
	http.Redirect(w, r, redirect, http.StatusFound)
}

// oidcCallback 处理身份提供方的回调：校验 state 与 ID Token，签发平台会话。
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil || s.Auth == nil {
		http.NotFound(w, r)
		return
	}
	fail := func(reason string) {
		http.Redirect(w, r, "/login.html#sso_error="+reason, http.StatusFound)
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/auth/oidc", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	q := r.URL.Query()
	c, err := r.Cookie(oidcStateCookie)
	state := q.Get("state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		fail("state")
		return
	}
	if e := q.Get("error"); e != "" || q.Get("code") == "" {
		log.Printf("[oidc] 身份提供方返回错误: %q", clip(e, 80))
		fail("idp")
		return
	}
	id, err := s.OIDC.Finish(r.Context(), state, q.Get("code"))
	switch {
	case errors.Is(err, sso.ErrDenied):
		log.Printf("[oidc] 登录被拒绝: %v", err)
		fail("denied")
		return
	case err != nil:
		log.Printf("[oidc] 登录失败: %v", err)
		s.audit(r, "单点登录", "", err)
		fail("invalid")
		return
	}
	sess, token, err := s.Auth.ExternalLogin(id.Username, id.Role, s.clientIP(r), r.UserAgent())
	if err != nil {
		log.Printf("[oidc] %v", err)
		fail("conflict")
		return
	}
	s.setCookie(w, r, token, sess.Expires)
	http.Redirect(w, r, "/", http.StatusFound)
}

func clip(s string, n int) string {
	if len(s) > n {
		for n > 0 && !utf8.RuneStart(s[n]) { // 不截断多字节字符
			n--
		}
		return s[:n]
	}
	return s
}
