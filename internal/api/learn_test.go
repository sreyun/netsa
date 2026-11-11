package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/audit"
	"netsa/internal/auth"
	"netsa/internal/authscan"
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
	// 后台任务：启动后的预热期内不做合规自检（数据源的格式还没有识别出来）
	s.learnTick(time.Now())
	if len(s.Learn.Report().Compliance) != 0 {
		t.Fatal("预热期内不应做合规自检")
	}
	// 预热之后首次合规自检建立基线（未配置推送与审计链时不应出错）
	s.started = time.Now().Add(-compWarmup)
	s.learnTick(time.Now())
	if len(s.Learn.Report().Compliance) != 1 {
		t.Fatal("应记录一次合规自检")
	}
}

// 学习后的自动处置：后台任务按策略自动归档已结束的低风险事件，写入进化日志；登记授权扫描成为模型评估的客观结论；
// 自动归档的事件不作为分析员的研判样本。
func TestLearnTickAutoArchiveAndOutcome(t *testing.T) {
	s, st := testServer(t, "", "")
	s.Learn, _ = learn.Load(learn.Options{Calibrate: true})
	old := time.Now().Add(-5 * 24 * time.Hour)
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.40", Host: "shop.example.com", Method: "GET", URI: "/.env", Status: 404, Time: old},
		[]model.Hit{{RuleID: "bhv-dirscan", Name: "目录扫描", Category: "目录扫描", Severity: model.SevLow, Phase: model.PhaseRecon, Result: model.ResultFailed}})
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.41", Host: "shop.example.com", Method: "GET", URI: "/x?id=1'", Status: 200, Time: old},
		[]model.Hit{{RuleID: "sqli-bool", Name: "SQL注入", Category: "SQL注入", Severity: model.SevHigh, Phase: model.PhaseExploit, Result: model.ResultPassed}})
	s.learnTick(time.Now())
	r := s.Learn.Report()
	if r.Loop.Archived != 1 || r.Cases != 0 {
		t.Fatalf("应归档 1 个侦察事件且不作为研判样本: %+v cases=%d", r.Loop, r.Cases)
	}
	if r.Changes[0].Kind != "auto_archive" || !strings.Contains(r.Changes[0].Detail, "#1") {
		t.Fatalf("进化日志: %+v", r.Changes[0])
	}
	h := s.Handler()
	rec := do(h, http.MethodGet, "/api/incidents?status=active", "", nil)
	if !strings.Contains(rec.Body.String(), "198.51.100.41") || strings.Contains(rec.Body.String(), "198.51.100.40") {
		t.Fatalf("待处置列表应只剩越过侦察的事件: %s", rec.Body.String())
	}
	// 登记授权扫描：成为该来源“不是攻击者”的客观结论，模型此前的判断据此评估
	s.AuthScan, _ = authscan.Load("")
	if rec := do(h, http.MethodPost, "/api/authscans", `{"ip":"10.20.0.5","hours":24,"note":"每周漏扫"}`, nil); rec.Code != 200 {
		t.Fatalf("登记授权扫描: %d %s", rec.Code, rec.Body.String())
	}
	if n := s.Learn.Report().Loop.Outcomes; n != 1 {
		t.Fatalf("登记授权扫描应记为客观结论: %d", n)
	}
	// 关闭自动归档后不再归档
	p, _ := s.Learn.Policy()
	p.ArchiveOff = true
	if err := s.Learn.SetPolicy(p, "admin"); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.Learn.ArchivePolicy(); on {
		t.Fatal("策略关闭后不应归档")
	}
}

func TestLearnRoles(t *testing.T) {
	for _, c := range []struct {
		method, path, role string
	}{
		{http.MethodGet, "/api/learn", auth.RoleAnalyst},
		{http.MethodPost, "/api/learn/suggestions/abc/apply", auth.RoleAnalyst},
		{http.MethodPost, "/api/learn/rules/xss-dom/pin", auth.RoleAdmin},
		{http.MethodPut, "/api/learn/policy", auth.RoleAdmin},
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

// 自学习策略在 Web 页面修改：立即生效、无效值拒绝、记入审计与进化日志；自动生效次数出现在报告与监控指标中。
func TestLearnPolicyAPI(t *testing.T) {
	s, _ := testServer(t, "", "")
	s.Learn, _ = learn.Load(learn.Options{Calibrate: true, Escalate: true})
	trail, err := audit.Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Trail = trail
	h := s.Handler()
	if rec := do(h, http.MethodPut, "/api/learn/policy", `{"calibrate":true,"min_verdicts":5,"max_precision":1.5,"escalate":true,"escalate_days":30}`, nil); rec.Code != 400 {
		t.Fatalf("无效的准确率阈值应拒绝: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPut, "/api/learn/policy", `{"calibrate":false,"min_verdicts":6,"max_precision":0.15,"escalate":false,"escalate_days":14}`, nil); rec.Code != 200 {
		t.Fatalf("修改策略: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Report learn.Report }
	decode(t, do(h, http.MethodGet, "/api/learn", "", nil).Body.Bytes(), &resp)
	if p := resp.Report.Policy; !resp.Report.PolicyUI || p.Calibrate || p.Escalate || p.MinVerdicts != 6 || p.EscalateDays != 14 || resp.Report.Options.Calibrate {
		t.Fatalf("策略应立即生效: %+v", resp.Report)
	}
	found := false
	for _, e := range trail.Search(audit.Query{Limit: 20}) {
		found = found || e.Action == "修改自学习策略"
	}
	if !found {
		t.Fatal("策略修改应记入审计")
	}
	if m := do(h, http.MethodGet, "/metrics", "", nil).Body.String(); !strings.Contains(m, `netsa_learn_applied_total{kind="target"}`) {
		t.Fatalf("监控指标应包含自学习生效次数:\n%s", m)
	}
}
