package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsa/internal/auth"
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
	"/login.html": true, "/login.js": true, "/login.css": true, "/api/auth/login": true, "/api/auth/session": true,
}

// mustChangeAllowed 是使用初始密码登录、尚未修改密码时仍可访问的接口。
var mustChangeAllowed = map[string]bool{"/api/auth/session": true, "/api/auth/password": true, "/api/auth/logout": true}

// needsAdmin 判断请求是否需要管理员权限：除登录相关接口外的所有写操作，以及账号与审计查询。
func needsAdmin(r *http.Request) bool {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/api/") {
		return false
	}
	if strings.HasPrefix(p, "/api/auth/users") || p == "/api/auth/audit" {
		return true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return false
	}
	return !mustChangeAllowed[p] && p != "/api/auth/login"
}

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
		if needsAdmin(r) && sess.Role != auth.RoleAdmin {
			writeErrorCode(w, http.StatusForbidden, "当前账号为只读权限，无法执行该操作", "forbidden")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

// currentSession 依次检查会话 Cookie 与 HTTP Basic 认证（供脚本调用 API）。
func (s *Server) currentSession(w http.ResponseWriter, r *http.Request) (*auth.Session, error) {
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
		return s.Pipeline.RealIP.ClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
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
	if s.Auth == nil {
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
	s.Auth.LogAction(user, s.clientIP(r), action, detail, err == nil, reason)
}

func writeErrorCode(w http.ResponseWriter, code int, msg, reason string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": reason})
}

func sessionView(sess *auth.Session, enabled bool) map[string]any {
	return map[string]any{"authenticated": true, "user": sess.User, "role": sess.Role, "must_change": sess.MustChange, "auth_enabled": enabled, "expires": sess.Expires}
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
	if f.Username == "" || f.Password == "" || len(f.Password) > 256 {
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
	switch {
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

func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r)
	if sess == nil { // 未登录不视为错误（登录页据此判断），避免浏览器控制台出现 401 报错
		writeJSON(w, map[string]any{"authenticated": false, "auth_enabled": true})
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
	if ns, _, ok := s.Auth.Verify(token); ok {
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
	}
	if s.Auth == nil || !decodeForm(w, r, &f) {
		if s.Auth == nil {
			writeErrorCode(w, http.StatusBadRequest, "未开启登录认证", "auth_disabled")
		}
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
	if s.Auth == nil {
		writeJSON(w, []auth.Record{})
		return
	}
	writeJSON(w, s.Auth.Audit(clamp(qint(r, "limit", 100), 1, 500)))
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, auth.ErrNoUser):
		return http.StatusNotFound
	case errors.Is(err, auth.ErrReadOnly), errors.Is(err, auth.ErrLastAdmin):
		return http.StatusForbidden
	}
	return http.StatusBadRequest
}
