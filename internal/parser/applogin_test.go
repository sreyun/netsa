package parser

import (
	"testing"

	"netsa/internal/model"
)

// 应用登录日志：识别登录事件、账号、来源与结果；退出登录、没有结果的事件与其他 JSON 日志不识别。
func TestAppLogin(t *testing.T) {
	a, _ := NewAuto("auto", "")
	ev, ok := a.Parse(`{"time":"2026-11-01T09:00:00+08:00","event":"user_login","username":"zhangsan","client_ip":"1.1.1.1, 10.0.0.2","result":"success","app":"OA"}`)
	if !ok || ev.Kind != model.KindAuth || ev.Format != "app_login" || ev.User != "zhangsan" || ev.SrcIP != "1.1.1.1" || ev.Action != model.ActionAllow ||
		ev.Service != "应用登录（OA）" {
		t.Fatalf("应用登录: %+v", ev)
	}
	ev, ok = a.Parse(`{"@timestamp":"2026-11-01T01:00:00Z","event":{"action":"signin","outcome":"failure"},"user":{"name":"admin"},"source":{"ip":"45.33.1.2"},"service":{"name":"sso"}}`)
	if !ok || ev.User != "admin" || ev.Action != model.ActionDeny || ev.SrcIP != "45.33.1.2" {
		t.Fatalf("ECS 格式的登录失败: %+v", ev)
	}
	for _, l := range []string{
		`{"event":"logout","username":"zhangsan","ip":"1.1.1.1","result":"success"}`,
		`{"event":"login_page_view","username":"zhangsan","ip":"1.1.1.1"}`,
		`{"msg":"user login","level":"info","duration":3}`,
	} {
		if ev, ok := a.Parse(l); ok && ev.Format == "app_login" {
			t.Fatalf("不应识别为登录: %s → %+v", l, ev)
		}
	}
}
