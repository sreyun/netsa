package api

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"netsa/internal/auth"
)

// 权限矩阵：每条路由需要的角色都显式写在这里。新增路由时这个测试会失败，强制想清楚谁能访问。
// 默认值（GET 只读、其他管理员）对查询敏感数据的接口是不够的，这正是要人工确认的原因。
var routePolicy = map[string]string{
	// 不需要登录（登录页需要），或任何已登录账号的自助操作
	"GET /api/auth/oidc/start": "public", "GET /api/auth/oidc/callback": "public", "GET /api/auth/session": "public",
	"POST /api/auth/login": "public", "POST /api/auth/login/2fa": "public",
	"POST /api/auth/logout": "self", "POST /api/auth/password": "self",
	"POST /api/auth/2fa/setup": "self", "POST /api/auth/2fa/enable": "self", "POST /api/auth/2fa/disable": "self",

	// 只读：态势与统计
	"GET /api/meta": auth.RoleViewer, "GET /api/overview": auth.RoleViewer, "GET /api/timeline": auth.RoleViewer, "GET /api/attackers": auth.RoleViewer, "GET /api/campaigns": auth.RoleViewer, "GET /api/search": auth.RoleViewer,
	"GET /api/chains": auth.RoleViewer, "GET /api/chains/detail": auth.RoleViewer,
	"GET /api/ip/{ip}": auth.RoleViewer, "GET /api/ip/{ip}/rdap": auth.RoleViewer, "GET /api/alerts": auth.RoleViewer, "GET /api/alerts/summary": auth.RoleViewer,
	"GET /api/map": auth.RoleViewer, "GET /api/surface": auth.RoleViewer, "GET /api/assessment": auth.RoleViewer, "GET /api/sources": auth.RoleViewer,
	"GET /api/rules": auth.RoleViewer, "GET /api/rules/stats": auth.RoleViewer, "GET /api/rules/managed": auth.RoleViewer, "GET /api/exposure": auth.RoleViewer,
	"GET /api/stream": auth.RoleViewer, "GET /api/export/blocklist": auth.RoleViewer, "GET /api/report": auth.RoleViewer, "GET /api/archive/status": auth.RoleViewer,
	"GET /api/archive/alerts": auth.RoleViewer, "GET /api/archive/stats": auth.RoleViewer, "GET /api/archive/export": auth.RoleViewer, "GET /api/incidents": auth.RoleViewer,
	"GET /api/incidents/{id}": auth.RoleViewer, "GET /metrics": auth.RoleViewer, "GET /api/assets": auth.RoleViewer, "GET /api/assets/template": auth.RoleViewer,
	"GET /api/assets/{id}": auth.RoleViewer, "GET /api/vulns": auth.RoleViewer, "GET /api/reports/periodic": auth.RoleViewer, "GET /api/rawlog/status": auth.RoleViewer,
	"GET /api/syslog/senders": auth.RoleViewer, "GET /api/suppressions": auth.RoleViewer, "GET /api/authscans": auth.RoleViewer, "GET /api/deception": auth.RoleViewer, "GET /api/alert/robots": auth.RoleViewer, // 机器人地址中的令牌已隐藏
	"GET /api/block/edl": auth.RoleViewer, // 防火墙用只读令牌拉取

	// 运营分析员：处置事件、误报抑制、原始日志（可能有 Cookie、令牌、个人信息）、平台账号的学习记录
	"GET /api/incidents/assignees": auth.RoleAnalyst, "GET /api/incidents/{id}/evidence": auth.RoleAnalyst, "POST /api/incidents/bulk": auth.RoleAnalyst, "POST /api/incidents/ai-batch": auth.RoleAnalyst,
	"POST /api/incidents/{id}": auth.RoleAnalyst, "POST /api/incidents/{id}/ai": auth.RoleAnalyst, "GET /api/learn": auth.RoleAnalyst,
	"POST /api/learn/suggestions/{id}/{action}": auth.RoleAnalyst, "GET /api/rawlog/search": auth.RoleAnalyst, "GET /api/rawlog/export": auth.RoleAnalyst,
	"POST /api/suppressions": auth.RoleAnalyst, "DELETE /api/suppressions/{id}": auth.RoleAnalyst,
	"POST /api/authscans": auth.RoleAnalyst, "POST /api/authscans/{id}/end": auth.RoleAnalyst, "DELETE /api/authscans/{id}": auth.RoleAnalyst, "POST /api/deception": auth.RoleAnalyst, "DELETE /api/deception/{id}": auth.RoleAnalyst, "PUT /api/vulns/{id}": auth.RoleAnalyst,
	"GET /api/block": auth.RoleAnalyst, "POST /api/block": auth.RoleAnalyst,

	// 管理员：账号、审计、配置、会改变检测结果的操作、审批封禁、备份
	"GET /api/admin/backup": auth.RoleAdmin, "GET /api/integrations": auth.RoleAdmin, "GET /api/ai/settings": auth.RoleAdmin, "PUT /api/ai/settings": auth.RoleAdmin,
	"POST /api/ai/test": auth.RoleAdmin, "POST /api/ai/models": auth.RoleAdmin, "GET /api/audit": auth.RoleAdmin, "GET /api/audit/export": auth.RoleAdmin,
	"POST /api/audit/verify": auth.RoleAdmin, "GET /api/auth/audit": auth.RoleAdmin, "GET /api/auth/users": auth.RoleAdmin, "POST /api/auth/users": auth.RoleAdmin,
	"PUT /api/auth/users/{name}": auth.RoleAdmin, "DELETE /api/auth/users/{name}": auth.RoleAdmin, "GET /api/auth/tokens": auth.RoleAdmin, "POST /api/auth/tokens": auth.RoleAdmin,
	"DELETE /api/auth/tokens/{id}": auth.RoleAdmin, "GET /api/compliance/mlps": auth.RoleAdmin, "POST /api/alert/robots": auth.RoleAdmin, "PUT /api/alert/robots/{id}": auth.RoleAdmin,
	"DELETE /api/alert/robots/{id}": auth.RoleAdmin, "POST /api/alert/robots/{id}/test": auth.RoleAdmin, "POST /api/alert/robots/{id}/report": auth.RoleAdmin, "POST /api/alert/test": auth.RoleAdmin,
	"POST /api/assets": auth.RoleAdmin, "POST /api/assets/import": auth.RoleAdmin, "PUT /api/assets/{id}": auth.RoleAdmin, "DELETE /api/assets/{id}": auth.RoleAdmin,
	"DELETE /api/vulns/{id}": auth.RoleAdmin, "POST /api/block/{id}/{action}": auth.RoleAdmin, "POST /api/learn/rules/{rule}/{action}": auth.RoleAdmin, "PUT /api/learn/policy": auth.RoleAdmin,
	"POST /api/rawlog/verify": auth.RoleAdmin, "POST /api/reports/email": auth.RoleAdmin, "POST /api/rules/managed": auth.RoleAdmin, "DELETE /api/rules/managed/{id}": auth.RoleAdmin,
	"POST /api/rules/packs": auth.RoleAdmin, "DELETE /api/rules/packs/{name}": auth.RoleAdmin, "POST /api/rules/sigma": auth.RoleAdmin, "POST /api/rules/test": auth.RoleAdmin,
	"POST /api/syslog/senders": auth.RoleAdmin, "PUT /api/syslog/senders/{id}": auth.RoleAdmin, "DELETE /api/syslog/senders/{id}": auth.RoleAdmin, "PUT /api/syslog/policy": auth.RoleAdmin,
	"GET /debug/pprof/": auth.RoleAdmin, "GET /debug/pprof/cmdline": auth.RoleAdmin, "GET /debug/pprof/profile": auth.RoleAdmin, "GET /debug/pprof/symbol": auth.RoleAdmin,
	"POST /debug/pprof/symbol": auth.RoleAdmin, "GET /debug/pprof/trace": auth.RoleAdmin,
}

var routeRe = regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) ([^"]+)"`)

func routePath(p string) string {
	return strings.NewReplacer("{ip}", "198.51.100.1", "{id}", "1", "{name}", "nobody", "{rule}", "r", "{action}", "approve").Replace(p)
}

func TestAuthzMatrix(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testServer(t, "admin", "secret")
	s.Cfg.Server.Pprof = true
	h := s.Handler()
	admin := login(t, h, "admin", "secret")
	sessions := map[string][]*http.Cookie{
		auth.RoleViewer:  newLocalUser(t, h, admin, "vera", auth.RoleViewer),
		auth.RoleAnalyst: newLocalUser(t, h, admin, "anna", auth.RoleAnalyst),
	}
	rank := map[string]int{auth.RoleViewer: 1, auth.RoleAnalyst: 2, auth.RoleAdmin: 3}
	seen := map[string]bool{}
	routes := routeRe.FindAllStringSubmatch(string(src), -1)
	if len(routes) < 100 {
		t.Fatalf("只解析到 %d 条路由，解析方式可能失效", len(routes))
	}
	for _, m := range routes {
		method, path := m[1], m[2]
		key := method + " " + path
		seen[key] = true
		want, ok := routePolicy[key]
		if !ok {
			t.Errorf("路由 %s 没有写入权限矩阵：请确认谁应该能访问", key)
			continue
		}
		url := routePath(path)
		body := ""
		if method != http.MethodGet {
			body = "{}"
		}
		// 未登录：只有公开接口可以访问
		if want != "public" {
			if rec := do(h, method, url, body, nil); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s 未登录应返回 401，实际 %d", key, rec.Code)
			}
		}
		if rank[want] == 0 { // 公开接口和自助操作不区分角色
			continue
		}
		// 低于要求的角色被拒绝（请求不会到达处理函数，可以安全地遍历写操作）
		for role, cookies := range sessions {
			if rank[role] >= rank[want] {
				continue
			}
			if rec := do(h, method, url, body, cookies); rec.Code != http.StatusForbidden {
				t.Errorf("%s 对 %s 应返回 403，实际 %d", key, role, rec.Code)
			}
		}
	}
	for key := range routePolicy {
		if !seen[key] {
			t.Errorf("权限矩阵中的路由 %s 已不存在", key)
		}
	}
}

// 达到要求的角色确实能通过权限检查：防止矩阵因为所有人都被拒绝而“通过”。
func TestAuthzAllowsSufficientRole(t *testing.T) {
	s, _ := testServer(t, "admin", "secret")
	h := s.Handler()
	admin := login(t, h, "admin", "secret")
	viewer := newLocalUser(t, h, admin, "vera", auth.RoleViewer)
	analyst := newLocalUser(t, h, admin, "anna", auth.RoleAnalyst)
	for _, c := range []struct {
		method, path string
		cookies      []*http.Cookie
	}{
		{http.MethodGet, "/api/overview", viewer},
		{http.MethodGet, "/api/incidents", viewer},
		{http.MethodGet, "/api/rawlog/search", analyst},
		{http.MethodGet, "/api/auth/users", admin},
		{http.MethodGet, "/api/integrations", admin},
	} {
		if rec := do(h, c.method, c.path, "", c.cookies); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Errorf("%s %s 不应被权限检查拒绝: %d", c.method, c.path, rec.Code)
		}
	}
}
