package learn

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/auth"
	"netsa/internal/model"
)

func newLearner(t *testing.T, path string) *Learner {
	t.Helper()
	l, err := Load(Options{Path: path, Calibrate: true, Sentinel: true, Compliance: true})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func fpCase(id uint64, rules map[string]int, target, src string, v Verdict) Case {
	return Case{Incident: id, Source: src, Rules: rules, Targets: []string{target}, Verdict: v, User: "ana"}
}

// 准确率持续偏低的规则自动下调一级；确认为攻击的样本增加、或管理员锁定后恢复。
func TestCalibrationLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	l := newLearner(t, path)
	var logged []Change
	l.OnChange = func(c Change) { logged = append(logged, c) }
	for i := 1; i <= 4; i++ {
		l.Feedback(fpCase(uint64(i), map[string]int{"xss-dom": 3}, "www.example.com/search?q="+strconv.Itoa(i), "198.51.100."+strconv.Itoa(i), VerdictFP))
	}
	hit := []model.Hit{{RuleID: "xss-dom", Severity: model.SevMedium, Evidence: "x"}}
	if got := l.Calibrate(hit); got[0].Severity != model.SevMedium {
		t.Fatal("样本不足时不应校准")
	}
	l.Feedback(fpCase(5, map[string]int{"xss-dom": 1}, "www.example.com/search", "198.51.100.5", VerdictFP))
	got := l.Calibrate(hit)
	if got[0].Severity != model.SevLow || !strings.Contains(got[0].Evidence, "自学习校准") || hit[0].Severity != model.SevMedium {
		t.Fatalf("5 次误报后应下调一级且不修改调用方数据: %+v", got)
	}
	if len(logged) != 1 || logged[0].Kind != "calibrate" {
		t.Fatalf("应记录一条进化日志: %+v", logged)
	}
	// 不影响其他规则与仅打标签的命中
	other := []model.Hit{{RuleID: "sqli-union", Severity: model.SevHigh}, {RuleID: "xss-dom", Severity: model.SevMedium, TagOnly: true}}
	if g := l.Calibrate(other); g[0].Severity != model.SevHigh || g[1].Severity != model.SevMedium {
		t.Fatalf("其他规则与标签不应变化: %+v", g)
	}

	// 重启后状态保持，且不重复记录进化日志
	l2 := newLearner(t, path)
	if g := l2.Calibrate(hit); g[0].Severity != model.SevLow {
		t.Fatal("重启后校准应保持")
	}
	if r := l2.Report(); len(r.Changes) != 1 || r.Cases != 5 || r.FP != 5 || r.Calibrated != 1 {
		t.Fatalf("重启后的状态: %+v", r)
	}

	// 管理员锁定规则：立即恢复
	l2.Pin("xss-dom", "admin", true)
	if g := l2.Calibrate(hit); g[0].Severity != model.SevMedium {
		t.Fatal("锁定后应恢复原等级")
	}
	l2.Pin("xss-dom", "admin", false)
	// 确认为攻击的样本增加，准确率回升后恢复
	for i := 6; i <= 7; i++ {
		l2.Feedback(Case{Incident: uint64(i), Source: "203.0.113.9", Rules: map[string]int{"xss-dom": 1}, Verdict: VerdictTP, User: "ana"})
	}
	if g := l2.Calibrate(hit); g[0].Severity != model.SevMedium {
		t.Fatal("准确率回升后应恢复")
	}
	// 撤回结论（事件重新打开）
	l2.Feedback(Case{Incident: 6, Verdict: VerdictNone})
	if r := l2.Report(); r.TP != 1 || r.Cases != 6 {
		t.Fatalf("撤回后样本: %+v", r)
	}
}

// 误报模式建议：同一规则在同一目标上多次误报；同一来源多次被整体判为误报（涉及大量规则时不归因到规则）。
func TestSuggestions(t *testing.T) {
	l := newLearner(t, "")
	l.Feedback(fpCase(1, map[string]int{"sqli-bool": 2}, "shop.example.com/api/search?kw=a", "198.51.100.1", VerdictFP))
	l.Feedback(fpCase(2, map[string]int{"sqli-bool": 1}, "shop.example.com/api/search?kw=b", "198.51.100.2", VerdictFP))
	broad := map[string]int{"sqli-union": 1, "xss-script": 1, "trav-dotdot": 1, "ua-scanner": 5}
	l.Feedback(fpCase(3, broad, "shop.example.com/", "10.0.8.8", VerdictFP))
	l.Feedback(fpCase(4, broad, "shop.example.com/admin", "10.0.8.8", VerdictFP))
	r := l.Report()
	if len(r.Suggestions) != 2 {
		t.Fatalf("建议: %+v", r.Suggestions)
	}
	var ctx, src Suggestion
	for _, s := range r.Suggestions {
		if s.Kind == "context" {
			ctx = s
		} else {
			src = s
		}
	}
	if ctx.RuleID != "sqli-bool" || ctx.Target != "shop.example.com/api/search" || ctx.FP != 2 || src.IP != "10.0.8.8" || src.FP != 2 {
		t.Fatalf("建议内容: %+v / %+v", ctx, src)
	}
	for _, s := range r.Rules {
		if s.Rule == "sqli-union" && s.FP != 0 {
			t.Fatal("涉及大量规则的误报不应计入单条规则")
		}
	}
	if err := l.Resolve(ctx.ID, "ana", "apply"); err != nil {
		t.Fatal(err)
	}
	if err := l.Resolve(ctx.ID, "ana", "apply"); err != ErrNoSuggestion {
		t.Fatal("已处理的建议不应再出现")
	}
	if r := l.Report(); len(r.Suggestions) != 1 || r.Changes[0].Kind != "apply" {
		t.Fatalf("采纳后: %+v", r)
	}
	// 同一目标出现过确认攻击：不建议抑制
	l.Feedback(Case{Incident: 9, Source: "203.0.113.1", Rules: map[string]int{"sqli-bool": 1}, Targets: []string{"shop.example.com/api/order"}, Verdict: VerdictTP})
	l.Feedback(fpCase(10, map[string]int{"sqli-bool": 1}, "shop.example.com/api/order", "198.51.100.3", VerdictFP))
	l.Feedback(fpCase(11, map[string]int{"sqli-bool": 1}, "shop.example.com/api/order", "198.51.100.4", VerdictFP))
	for _, s := range l.Report().Suggestions {
		if s.Target == "shop.example.com/api/order" {
			t.Fatal("确认过攻击的目标不应建议抑制")
		}
	}
}

func rec(user, ip, action, detail string, ok bool, at time.Time) auth.Record {
	return auth.Record{Time: at, User: user, IP: ip, Action: action, Detail: detail, OK: ok, Reason: "密码错误"}
}

// 平台账号行为基线：新地址登录、暴力破解、批量导出与高危变更。
func TestSentinel(t *testing.T) {
	l := newLearner(t, "")
	base := time.Date(2026, 10, 29, 10, 0, 0, 0, time.Local)
	kinds := func(list []Anomaly) []string {
		var out []string
		for _, a := range list {
			out = append(out, a.Kind)
		}
		return out
	}
	for i := 0; i < 6; i++ {
		if a := l.ObserveAudit(rec("admin", "10.0.0."+strconv.Itoa(10+i), "", "", true, base.Add(time.Duration(i)*time.Hour/6))); len(a) != 0 {
			t.Fatalf("学习期与同网段登录不应告警: %+v", a)
		}
	}
	a := l.ObserveAudit(rec("admin", "203.0.113.9", "", "", true, base.Add(2*time.Hour)))
	if len(a) != 1 || a[0].Kind != "new_net" || a[0].Severity != model.SevHigh {
		t.Fatalf("公网新地址登录应为高危: %+v", a)
	}
	if a := l.ObserveAudit(rec("admin", "203.0.113.9", "", "", true, base.Add(3*time.Hour))); len(a) != 0 {
		t.Fatalf("已学习的地址不再告警: %+v", a)
	}
	var got []Anomaly
	for i := 0; i < failBurst+2; i++ {
		got = append(got, l.ObserveAudit(rec("ops", "198.51.100.7", "", "", false, base.Add(time.Duration(i)*time.Minute)))...)
	}
	if k := kinds(got); len(k) != 1 || k[0] != "login_fail" {
		t.Fatalf("登录失败暴增应告警一次: %v", k)
	}
	got = nil
	for i := 0; i < exportBurst; i++ {
		got = append(got, l.ObserveAudit(rec("ana", "10.0.0.5", "导出原始日志", "近 1 天", true, base.Add(time.Duration(i)*time.Minute)))...)
	}
	if k := kinds(got); len(k) != 1 || k[0] != "bulk_export" {
		t.Fatalf("批量导出: %v", k)
	}
	for _, c := range []struct {
		action, detail string
		want           bool
	}{
		{"关闭双因素认证", "admin", true},
		{"修改账号", "bob 角色改为 admin", true},
		{"修改账号", "bob 重置密码", false},
		{"添加误报抑制", "来源 10.0.0.0/8 原因：内网", true},
		{"添加误报抑制", "规则 xss-dom，目标 /search 原因：业务正常", false},
		{"创建 API 令牌", "prom（metrics · metrics）", false},
	} {
		a := l.ObserveAudit(rec("admin", "10.0.0.10", c.action, c.detail, true, base.Add(5*time.Hour)))
		if (len(a) == 1) != c.want {
			t.Errorf("%s %s: %+v", c.action, c.detail, a)
		}
	}
	if r := l.Report(); len(r.Anomalies) < 6 {
		t.Fatalf("异常应记录: %d", len(r.Anomalies))
	}
}

// 合规自检：首次只建立基线，之后结果下降时报告变化。
func TestComplianceWatch(t *testing.T) {
	l := newLearner(t, "")
	now := time.Now()
	items := []CompItem{{Control: "8.1.4.3 安全审计 c)", Status: "pass"}, {Control: "8.1.3.3 入侵防范", Status: "partial"}}
	if ch := l.CheckCompliance(items, 0.75, now); len(ch) != 0 {
		t.Fatalf("首次自检只建立基线: %+v", ch)
	}
	items[0].Status, items[1].Status = "fail", "pass"
	ch := l.CheckCompliance(items, 0.5, now.Add(time.Hour))
	if len(ch) != 2 || !ch[0].Degraded || ch[1].Degraded || ch[0].From != "pass" {
		t.Fatalf("变化: %+v", ch)
	}
	if r := l.Report(); len(r.Compliance) != 2 || r.Compliance[1].Fail != 1 {
		t.Fatalf("趋势: %+v", r.Compliance)
	}
}

// 同一事件的多个目标只是参数不同（同一接口）：只计一次误报，相关事件不重复。
func TestSuggestionDedupTargets(t *testing.T) {
	l := newLearner(t, "")
	for id := uint64(1); id <= 2; id++ {
		l.Feedback(Case{Incident: id, Source: "198.51.100." + strconv.Itoa(int(id)), Rules: map[string]int{"sqli-bool": 3}, Verdict: VerdictFP,
			Targets: []string{"shop /api/search?p=1", "shop /api/search?p=2", "shop /api/search?p=3"}})
	}
	s := l.Report().Suggestions
	if len(s) != 1 || s[0].FP != 2 || len(s[0].Incidents) != 2 {
		t.Fatalf("应按事件去重: %+v", s)
	}
}
