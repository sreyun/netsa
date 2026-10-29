package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"netsa/internal/audit"
	"netsa/internal/auth"
	"netsa/internal/learn"
	"netsa/internal/model"
	"netsa/internal/suppress"
)

// 自学习闭环：分析员把事件处置为误报 → 生成抑制建议 → 采纳后创建抑制规则；重新打开事件撤回结论。
func TestLearnFeedbackAPI(t *testing.T) {
	s, st := testServer(t, "", "")
	s.Suppress, _ = suppress.Load("")
	s.Learn, _ = learn.Load(learn.Options{Calibrate: true, Sentinel: true, Compliance: true})
	h := s.Handler()
	for i := 1; i <= 2; i++ {
		st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100." + strconv.Itoa(i), Host: "shop.example.com", Method: "GET",
			URI: "/api/search?kw=" + strconv.Itoa(i), Time: time.Now()},
			[]model.Hit{{RuleID: "sqli-bool", Name: "SQL注入（布尔盲注）", Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultPassed}})
	}
	if rec := do(h, http.MethodPost, "/api/incidents/bulk", `{"ids":[1,2],"status":"false_positive","note":"搜索接口的正常查询"}`, nil); rec.Code != 200 {
		t.Fatalf("处置: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Enabled bool
		Report  learn.Report
	}
	decode(t, do(h, http.MethodGet, "/api/learn", "", nil).Body.Bytes(), &resp)
	if !resp.Enabled || resp.Report.FP != 2 || len(resp.Report.Suggestions) != 1 || resp.Report.Suggestions[0].RuleID != "sqli-bool" {
		t.Fatalf("学习结果: %+v", resp.Report)
	}
	sg := resp.Report.Suggestions[0]
	if rec := do(h, http.MethodPost, "/api/learn/suggestions/"+sg.ID+"/apply", "", nil); rec.Code != 200 {
		t.Fatalf("采纳建议: %d %s", rec.Code, rec.Body.String())
	}
	if list := s.Suppress.List(); len(list) != 1 || list[0].RuleID != "sqli-bool" || list[0].Target != sg.Target {
		t.Fatalf("应创建抑制规则: %+v", list)
	}
	decode(t, do(h, http.MethodGet, "/api/learn", "", nil).Body.Bytes(), &resp)
	if len(resp.Report.Suggestions) != 0 {
		t.Fatal("采纳后不应再提示")
	}
	if rec := do(h, http.MethodPost, "/api/learn/suggestions/"+sg.ID+"/apply", "", nil); rec.Code != 404 {
		t.Fatalf("重复采纳: %d", rec.Code)
	}
	// 重新打开事件：撤回误报结论
	do(h, http.MethodPost, "/api/incidents/1", `{"status":"open"}`, nil)
	decode(t, do(h, http.MethodGet, "/api/learn", "", nil).Body.Bytes(), &resp)
	if resp.Report.FP != 1 {
		t.Fatalf("撤回后: %+v", resp.Report)
	}
	// 后台任务：首次合规自检建立基线（未配置推送与审计链时不应出错）
	s.learnTick(time.Now())
	if len(s.Learn.Report().Compliance) != 1 {
		t.Fatal("应记录一次合规自检")
	}
}

func TestLearnRoles(t *testing.T) {
	for _, c := range []struct {
		method, path, role string
	}{
		{http.MethodGet, "/api/learn", auth.RoleAnalyst},
		{http.MethodPost, "/api/learn/suggestions/abc/apply", auth.RoleAnalyst},
		{http.MethodPost, "/api/learn/rules/xss-dom/pin", auth.RoleAdmin},
	} {
		if got := requiredRole(httptest.NewRequest(c.method, c.path, nil)); got != c.role {
			t.Errorf("%s %s: %s，期望 %s", c.method, c.path, got, c.role)
		}
	}
}

// 平台行为基线经由账号管理的审计链生效：创建管理员账号会产生「高危变更」异常，并写入审计链。
func TestLearnSentinelWired(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	s.Learn, _ = learn.Load(learn.Options{Sentinel: true})
	trail, err := audit.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Trail = trail
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	if rec := do(h, http.MethodPost, "/api/auth/users", `{"name":"ops2","role":"admin","password":"Init-pass-123"}`, admin); rec.Code != 200 {
		t.Fatalf("创建账号: %d %s", rec.Code, rec.Body.String())
	}
	an := s.Learn.Report().Anomalies
	if len(an) != 1 || an[0].Kind != "sensitive" || an[0].User != "admin" {
		t.Fatalf("应识别高危变更: %+v", an)
	}
	found := false
	for _, e := range trail.Search(audit.Query{Limit: 20}) {
		found = found || e.Action == "平台安全异常"
	}
	if !found {
		t.Fatal("异常应写入审计链")
	}
}
