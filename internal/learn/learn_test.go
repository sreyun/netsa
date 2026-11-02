package learn

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

func changeKinds(list []Change) string {
	var k []string
	for _, c := range list {
		k = append(k, c.Kind)
	}
	return strings.Join(k, ",")
}

func webEvent(host, uri string) *model.Event {
	return &model.Event{Kind: model.KindWeb, Host: host, URI: uri}
}

// 规则 + 目标精细校准：规则整体准确率正常、只在个别接口上反复误报时，只下调该接口上的命中。
func TestContextCalibration(t *testing.T) {
	l := newLearner(t, "")
	var logged []Change
	l.OnChange = func(c Change) { logged = append(logged, c) }
	// 规则在下单接口上多次确认为攻击，整体准确率正常
	for i := 1; i <= 6; i++ {
		l.Feedback(fpCase(uint64(i), map[string]int{"sqli-bool": 1}, "shop /api/order?id="+strconv.Itoa(i), "203.0.113."+strconv.Itoa(i), VerdictTP))
	}
	// 搜索接口的参数天然带引号：两次误报还不够，第三次后精细校准
	for i := 7; i <= 8; i++ {
		l.Feedback(fpCase(uint64(i), map[string]int{"sqli-bool": 2}, "shop /api/search?kw="+strconv.Itoa(i), "198.51.100."+strconv.Itoa(i), VerdictFP))
	}
	hit := []model.Hit{{RuleID: "sqli-bool", Severity: model.SevHigh, Evidence: "x"}}
	if g := l.Calibrate(webEvent("shop", "/api/search?kw=a'b"), hit); g[0].Severity != model.SevHigh {
		t.Fatal("误报次数不足时不应校准")
	}
	// 涉及大量规则的误报是对来源的判断，不计入规则在该目标上的误报
	broad := map[string]int{"sqli-bool": 1, "xss-script": 1, "trav-dotdot": 1}
	l.Feedback(fpCase(20, broad, "shop /api/search", "10.0.8.8", VerdictFP))
	if r := l.Report(); r.CtxTotal != 0 {
		t.Fatalf("涉及大量规则的误报不应触发精细校准: %+v", r.Contexts)
	}
	l.Feedback(fpCase(9, map[string]int{"sqli-bool": 1}, "shop /api/search?kw=9", "198.51.100.9", VerdictFP))
	r := l.Report()
	if r.Calibrated != 0 || r.CtxTotal != 1 || r.Contexts[0].Target != "shop /api/search" || r.Contexts[0].FP != 3 {
		t.Fatalf("应只校准搜索接口: calibrated=%d %+v", r.Calibrated, r.Contexts)
	}
	g := l.Calibrate(webEvent("shop", "/api/search?kw=zzz"), hit)
	if g[0].Severity != model.SevMedium || !strings.Contains(g[0].Evidence, "此目标上 3 次被研判为误报") || hit[0].Severity != model.SevHigh {
		t.Fatalf("搜索接口（参数不同）应下调一级: %+v", g)
	}
	if g := l.Calibrate(webEvent("shop", "/api/order?id=1"), hit); g[0].Severity != model.SevHigh {
		t.Fatal("其他目标不受影响")
	}
	if g := l.Calibrate(nil, hit); g[0].Severity != model.SevHigh {
		t.Fatal("没有目标时只按规则整体校准")
	}
	// 锁定规则：两种校准都停止；解锁后恢复
	l.Pin("sqli-bool", "admin", true)
	if g := l.Calibrate(webEvent("shop", "/api/search"), hit); g[0].Severity != model.SevHigh {
		t.Fatal("锁定后应恢复原等级")
	}
	l.Pin("sqli-bool", "admin", false)
	if g := l.Calibrate(webEvent("shop", "/api/search"), hit); g[0].Severity != model.SevMedium {
		t.Fatal("解锁后应恢复精细校准")
	}
	// 该接口上出现确认的攻击：自动恢复
	l.Feedback(fpCase(10, map[string]int{"sqli-bool": 1}, "shop /api/search?kw=union", "203.0.113.50", VerdictTP))
	if g := l.Calibrate(webEvent("shop", "/api/search"), hit); g[0].Severity != model.SevHigh {
		t.Fatal("出现确认攻击后应恢复")
	}
	want := "calibrate_ctx,pin,restore_ctx,unpin,calibrate_ctx,restore_ctx"
	if k := changeKinds(logged); k != want || !strings.Contains(logged[len(logged)-1].Detail, "出现确认的攻击") {
		t.Fatalf("进化日志: %s\n%+v", k, logged)
	}
}

// 外部模型的一致率：以分析员结论为准评估模型，结论不作为学习样本；重启后保留。
func TestAITrust(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	l := newLearner(t, path)
	verdicts := []struct {
		ai      string
		conf    int
		analyst Verdict
	}{
		{"attack", 90, VerdictTP}, {"attack", 85, VerdictTP}, {"false_positive", 80, VerdictFP}, {"attack", 60, VerdictFP},
		{"false_positive", 90, VerdictTP}, {"uncertain", 30, VerdictTP}, {"attack", 95, VerdictTP},
	}
	for i, v := range verdicts {
		id := uint64(i + 1)
		l.RecordAI(id, AIRecord{Verdict: v.ai, Confidence: v.conf, Model: "deepseek-chat"})
		if i < 4 && l.Trust("deepseek-chat") != "" {
			t.Fatal("样本不足 5 个时不应给出一致率")
		}
		l.Feedback(fpCase(id, map[string]int{"r" + strconv.Itoa(i): 1}, "t", "198.51.100.1", v.analyst))
	}
	l.RecordAI(99, AIRecord{Verdict: "attack", Confidence: 70, Model: "deepseek-chat"}) // 尚无分析员结论
	r := l.Report()
	if r.Cases != 7 || len(r.AI) != 1 {
		t.Fatalf("模型结论不应成为样本: cases=%d ai=%+v", r.Cases, r.AI)
	}
	st := r.AI[0]
	if st.Judged != 6 || st.Agree != 4 || st.Missed != 1 || st.Overcall != 1 || st.Uncertain != 1 || st.Pending != 1 || st.HighConf != 5 || st.HighAgree != 4 {
		t.Fatalf("统计: %+v", st)
	}
	if tr := l.Trust("deepseek-chat"); !strings.Contains(tr, "一致率 67%（6 个事件）") || !strings.Contains(tr, "1 次把确认的攻击判为误报") {
		t.Fatalf("可信度说明: %s", tr)
	}
	if l.Trust("qwen-max") != "" {
		t.Fatal("没有记录的模型不应给出一致率")
	}
	// 分析员撤回结论：该事件回到「尚无分析员结论」
	l.Feedback(Case{Incident: 1, Verdict: VerdictNone})
	if st := l.Report().AI[0]; st.Judged != 5 || st.Pending != 2 {
		t.Fatalf("撤回后: %+v", st)
	}
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	if st := newLearner(t, path).Report().AI; len(st) != 1 || st[0].Judged != 5 {
		t.Fatalf("重启后: %+v", st)
	}
}

// 历史人工结论：来源与「规则 + 目标」，不含事件自身，供外部模型研判参考。
func TestHistory(t *testing.T) {
	l := newLearner(t, "")
	l.Feedback(fpCase(1, map[string]int{"sqli-bool": 1}, "shop /api/search?kw=1", "198.51.100.7", VerdictFP))
	l.Feedback(fpCase(2, map[string]int{"sqli-bool": 1}, "shop /api/search?kw=2", "198.51.100.8", VerdictFP))
	l.Feedback(fpCase(3, map[string]int{"sqli-bool": 1, "xss-dom": 1}, "shop /api/order", "198.51.100.7", VerdictTP))
	l.Feedback(fpCase(4, map[string]int{"sqli-bool": 1}, "shop /api/search", "198.51.100.7", VerdictFP))
	h := l.History("198.51.100.7", []string{"sqli-bool"}, []string{"shop /api/search?kw=x", "shop /api/order"}, 4)
	if h.SourceTP != 1 || h.SourceFP != 1 {
		t.Fatalf("来源历史（不含事件自身）: %+v", h)
	}
	if len(h.Contexts) != 2 || h.Contexts[0].Target != "shop /api/search" || h.Contexts[0].FP != 2 || h.Contexts[1].TP != 1 {
		t.Fatalf("规则 + 目标历史: %+v", h.Contexts)
	}
	if h := l.History("", []string{"xss-script"}, []string{"shop /api/search"}, 0); h.SourceTP+h.SourceFP != 0 || len(h.Contexts) != 0 {
		t.Fatalf("无关规则不应返回历史: %+v", h)
	}
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
	if got := l.Calibrate(nil, hit); got[0].Severity != model.SevMedium {
		t.Fatal("样本不足时不应校准")
	}
	l.Feedback(fpCase(5, map[string]int{"xss-dom": 1}, "www.example.com/search", "198.51.100.5", VerdictFP))
	got := l.Calibrate(nil, hit)
	if got[0].Severity != model.SevLow || !strings.Contains(got[0].Evidence, "自学习校准") || hit[0].Severity != model.SevMedium {
		t.Fatalf("5 次误报后应下调一级且不修改调用方数据: %+v", got)
	}
	// 5 次误报都在同一接口上：第 3 次时先触发「规则 + 目标」精细校准，第 5 次时规则整体校准
	if k := changeKinds(logged); k != "calibrate_ctx,calibrate" {
		t.Fatalf("进化日志: %s %+v", k, logged)
	}
	// 不影响其他规则与仅打标签的命中
	other := []model.Hit{{RuleID: "sqli-union", Severity: model.SevHigh}, {RuleID: "xss-dom", Severity: model.SevMedium, TagOnly: true}}
	if g := l.Calibrate(nil, other); g[0].Severity != model.SevHigh || g[1].Severity != model.SevMedium {
		t.Fatalf("其他规则与标签不应变化: %+v", g)
	}

	// 重启后状态保持，且不重复记录进化日志
	l2 := newLearner(t, path)
	if g := l2.Calibrate(nil, hit); g[0].Severity != model.SevLow {
		t.Fatal("重启后校准应保持")
	}
	if r := l2.Report(); len(r.Changes) != 2 || r.Cases != 5 || r.FP != 5 || r.Calibrated != 1 || r.CtxTotal != 1 {
		t.Fatalf("重启后的状态: %+v", r)
	}

	// 管理员锁定规则：立即恢复
	l2.Pin("xss-dom", "admin", true)
	if g := l2.Calibrate(nil, hit); g[0].Severity != model.SevMedium {
		t.Fatal("锁定后应恢复原等级")
	}
	l2.Pin("xss-dom", "admin", false)
	// 确认为攻击的样本增加，准确率回升后恢复
	for i := 6; i <= 7; i++ {
		l2.Feedback(Case{Incident: uint64(i), Source: "203.0.113.9", Rules: map[string]int{"xss-dom": 1}, Verdict: VerdictTP, User: "ana"})
	}
	if g := l2.Calibrate(nil, hit); g[0].Severity != model.SevMedium {
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

// 批量处置：一次传入多个结论只产生一次重算与进化日志；后台定时保存与界面操作并发落盘时，文件始终是完整的最新状态。
func TestFeedbackBatchAndConcurrentSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	l := newLearner(t, path)
	var logged []Change
	l.OnChange = func(c Change) { logged = append(logged, c) }
	var batch []Case
	for i := 1; i <= 6; i++ {
		batch = append(batch, fpCase(uint64(i), map[string]int{"xss-dom": 1}, "www.example.com/s", "198.51.100."+strconv.Itoa(i), VerdictFP))
	}
	batch = append(batch, Case{Incident: 99, Verdict: VerdictNone}) // 撤回不存在的结论：忽略
	l.Feedback(batch...)
	if r := l.Report(); r.Cases != 6 || r.Calibrated != 1 || changeKinds(logged) != "calibrate,calibrate_ctx" {
		t.Fatalf("批量结论: cases=%d calibrated=%d changes=%+v", r.Cases, r.Calibrated, logged)
	}

	l.OnChange = nil
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			l.Feedback(Case{Incident: uint64(100 + i), Source: "203.0.113.1", Rules: map[string]int{"sqli-bool": 1}, Verdict: VerdictTP, User: "ana"})
		}(i)
		go func() {
			defer wg.Done()
			l.ObserveAudit(rec("admin", "10.0.0.1", "", "", true, time.Now()))
			if err := l.Save(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	if r := newLearner(t, path).Report(); r.Cases != 14 || r.TP != 8 {
		t.Fatalf("并发保存后重新加载: cases=%d tp=%d", r.Cases, r.TP)
	}
}

// 登录失败的账号名由请求方任意填写：大量不同账号名时跟踪记录有上限，过期的会被清理。
func TestSentinelTrackedBounded(t *testing.T) {
	l := newLearner(t, "")
	base := time.Date(2026, 10, 29, 10, 0, 0, 0, time.Local)
	for i := 0; i < maxTracked+500; i++ {
		l.ObserveAudit(rec("u"+strconv.Itoa(i), "198.51.100.7", "", "", false, base))
	}
	if n := len(l.sent.fails); n > maxTracked {
		t.Fatalf("跟踪的账号名应有上限: %d", n)
	}
	// 1 小时后旧记录过期，新账号名可以继续跟踪
	later := base.Add(2 * time.Hour)
	var got []Anomaly
	for i := 0; i < failBurst; i++ {
		got = append(got, l.ObserveAudit(rec("ops", "198.51.100.8", "", "", false, later.Add(time.Duration(i)*time.Second)))...)
	}
	if len(got) != 1 || got[0].Kind != "login_fail" || len(l.sent.fails) > maxTracked {
		t.Fatalf("过期清理后应能继续发现暴力破解: %+v（跟踪 %d 个）", got, len(l.sent.fails))
	}
	// 同一账号被锁定后仍被持续尝试：每个账号保留的记录数有上限
	for i := 0; i < maxRecent*3; i++ {
		l.ObserveAudit(rec("ops", "198.51.100.8", "", "", false, later.Add(time.Minute+time.Duration(i)*time.Millisecond)))
	}
	if n := len(l.sent.fails["ops"]); n != maxRecent {
		t.Fatalf("单个账号的记录数应有上限: %d", n)
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

// 确认攻击源复现升级：只看来源最近一次人工结论，按事件时间判断有效期；只升低危 / 中危，最多到高危。
// 策略可在界面修改，立即生效并在重启后保持。
func TestEscalationAndPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	l, err := Load(Options{Path: path, Calibrate: true, Escalate: true, EscalateDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Feedback(Case{Incident: 7, Source: "203.0.113.7", Rules: map[string]int{"sqli-union": 1}, Verdict: VerdictTP, User: "ana", Time: now.Add(-time.Hour)})
	ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.7", Host: "shop", URI: "/.git/config", Time: now}
	hits := []model.Hit{
		{RuleID: "sens-vcs", Severity: model.SevMedium, Evidence: "e"},
		{RuleID: "sqli-union", Severity: model.SevHigh},
		{RuleID: "ua-scanner", Severity: model.SevLow},
		{RuleID: "ua-automation", Severity: model.SevInfo, TagOnly: true},
	}
	g := l.Calibrate(ev, hits)
	if g[0].Severity != model.SevHigh || g[0].Learned != 1 || !strings.Contains(g[0].Evidence, "事件 #7") {
		t.Fatalf("中危应升级为高危: %+v", g[0])
	}
	if g[1].Severity != model.SevHigh || g[1].Learned != 0 {
		t.Fatalf("高危不再升级（严重只能来自成功利用等证据）: %+v", g[1])
	}
	if g[2].Severity != model.SevMedium || g[3].Severity != model.SevInfo || g[3].Learned != 0 {
		t.Fatalf("低危升一级、标签命中不变: %+v %+v", g[2], g[3])
	}
	if hits[0].Severity != model.SevMedium {
		t.Fatal("不应修改调用方的数据")
	}
	// 有效期按事件时间判断：离线回放 40 天后的日志不再升级
	if g := l.Calibrate(&model.Event{SrcIP: "203.0.113.7", Time: now.Add(40 * 24 * time.Hour)}, hits[:1]); g[0].Severity != model.SevMedium {
		t.Fatal("超过有效期不应升级")
	}
	if g := l.Calibrate(&model.Event{SrcIP: "203.0.113.8", Time: now}, hits[:1]); g[0].Severity != model.SevMedium {
		t.Fatal("其他来源不应升级")
	}
	if r := l.Report(); r.Confirmed != 1 || r.Applied.Escalated != 2 {
		t.Fatalf("统计: confirmed=%d applied=%+v", r.Confirmed, r.Applied)
	}
	// 同一来源后来被判为误报（如确认是授权扫描）：不再升级
	l.Feedback(Case{Incident: 8, Source: "203.0.113.7", Rules: map[string]int{"ua-scanner": 1, "sens-vcs": 1, "x": 1}, Verdict: VerdictFP, User: "ana", Time: now})
	if g := l.Calibrate(ev, hits[:1]); g[0].Severity != model.SevMedium {
		t.Fatal("最近一次结论为误报的来源不应升级")
	}

	// 界面策略：校验、立即生效、记入进化日志、重启后保持
	if err := l.SetPolicy(Policy{Calibrate: true, MinVerdicts: 1, MaxPrecision: 0.2, Escalate: true, EscalateDays: 30}, "admin"); err == nil {
		t.Fatal("应拒绝过小的样本数")
	}
	l.Feedback(Case{Incident: 9, Source: "203.0.113.9", Rules: map[string]int{"r": 1}, Verdict: VerdictTP, User: "ana", Time: now})
	if err := l.SetPolicy(Policy{Calibrate: true, MinVerdicts: 8, MaxPrecision: 0.1, Escalate: false, EscalateDays: 7}, "admin"); err != nil {
		t.Fatal(err)
	}
	if g := l.Calibrate(&model.Event{SrcIP: "203.0.113.9", Time: now}, hits[:1]); g[0].Severity != model.SevMedium {
		t.Fatal("关闭升级后应立即停止")
	}
	r := l.Report()
	if !r.PolicyUI || r.Policy.MinVerdicts != 8 || r.Options.CtxMinFP != 6 || r.Policy.UpdatedBy != "admin" || r.Changes[0].Kind != "policy" {
		t.Fatalf("策略: %+v %+v %+v", r.Policy, r.Options, r.Changes[0])
	}
	l2, err := Load(Options{Path: path, Calibrate: true, Escalate: true})
	if err != nil {
		t.Fatal(err)
	}
	if p, ui := l2.Policy(); !ui || p.Escalate || p.MinVerdicts != 8 || p.EscalateDays != 7 {
		t.Fatalf("重启后应保持界面策略: %+v %v", p, ui)
	}
}

// 学习窗口：超过窗口的结论不再参与校准，定期刷新时自动撤销校准；策略改为不限后恢复。
func TestLearningWindow(t *testing.T) {
	l, err := Load(Options{Calibrate: true, WindowDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	var logged []Change
	l.OnChange = func(c Change) { logged = append(logged, c) }
	now := time.Now()
	for i := 1; i <= 3; i++ {
		c := fpCase(uint64(i), map[string]int{"sqli-bool": 1}, "shop /api/search", "198.51.100."+strconv.Itoa(i), VerdictFP)
		c.Time = now.Add(-20 * 24 * time.Hour)
		l.Feedback(c)
	}
	hit := []model.Hit{{RuleID: "sqli-bool", Severity: model.SevHigh}}
	ev := &model.Event{Kind: model.KindWeb, Host: "shop", URI: "/api/search"}
	if g := l.Calibrate(ev, hit); g[0].Severity != model.SevMedium {
		t.Fatal("窗口内的结论应生效")
	}
	l.Refresh(now.Add(15 * 24 * time.Hour)) // 样本已过去 35 天
	if g := l.Calibrate(ev, hit); g[0].Severity != model.SevHigh {
		t.Fatal("超过学习窗口后校准应撤销")
	}
	if last := logged[len(logged)-1]; last.Kind != "restore_ctx" || !strings.Contains(last.Detail, "学习窗口") {
		t.Fatalf("撤销应记入进化日志: %+v", last)
	}
	if r := l.Report(); r.Cases != 3 || r.Policy.WindowDays != 30 || len(r.Trend) != 8 || r.Trend[2].FP != 3 {
		t.Fatalf("样本保留、趋势统计: cases=%d window=%d trend=%+v", r.Cases, r.Policy.WindowDays, r.Trend)
	}
	if err := l.SetPolicy(Policy{Calibrate: true, MinVerdicts: 5, MaxPrecision: 0.2, EscalateDays: 30, WindowDays: 0}, "admin"); err != nil {
		t.Fatal(err)
	}
	l.Refresh(now.Add(15 * 24 * time.Hour))
	if g := l.Calibrate(ev, hit); g[0].Severity != model.SevMedium {
		t.Fatal("窗口改为不限后校准应恢复")
	}
	if err := l.SetPolicy(Policy{Calibrate: true, MinVerdicts: 5, MaxPrecision: 0.2, EscalateDays: 30, WindowDays: 3}, "admin"); err == nil {
		t.Fatal("应拒绝过短的学习窗口")
	}
}

// 相似案例：同一目标、纠正过模型的优先；没有说明也没有纠正的案例没有参考价值。
func TestSimilarCases(t *testing.T) {
	l := newLearner(t, "")
	withNote := func(id uint64, rule, target, note string, v Verdict) Case {
		c := fpCase(id, map[string]int{rule: 1}, target, "198.51.100.1", v)
		c.Note = note
		return c
	}
	l.Feedback(withNote(1, "sqli-bool", "shop /api/order", "确认注入，已封禁", VerdictTP))
	l.Feedback(withNote(2, "sqli-bool", "shop /api/search", "搜索词带引号，正常业务", VerdictFP))
	l.Feedback(withNote(3, "sqli-bool", "shop /api/search", "", VerdictFP)) // 无说明、无纠正
	l.Feedback(withNote(4, "xss-dom", "shop /api/search", "无关规则", VerdictFP))
	l.Feedback(withNote(5, "sqli-bool", "shop /api/other", "", VerdictFP))
	l.RecordAI(5, AIRecord{Verdict: "attack", Confidence: 90, Model: "m"}) // 分析员纠正过模型
	got := l.Similar([]string{"sqli-bool"}, []string{"shop /api/search?kw=x"}, 99, 5)
	if len(got) != 3 || got[0].Target != "shop /api/search" || got[0].Note == "" {
		t.Fatalf("相似案例: %+v", got)
	}
	if got[1].Corrected != "attack" || got[1].Target != "shop /api/other" {
		t.Fatalf("纠正过模型的案例应排在只是同规则的案例之前: %+v", got)
	}
	if g := l.Similar([]string{"sqli-bool"}, []string{"shop /api/search"}, 2, 1); len(g) != 1 || g[0].Note == "搜索词带引号，正常业务" {
		t.Fatalf("应排除事件自身并限制数量: %+v", g)
	}
	long := withNote(6, "r", "t", strings.Repeat("长", 500), VerdictFP)
	l.Feedback(long)
	if g := l.Similar([]string{"r"}, nil, 0, 1); len([]rune(g[0].Note)) > 201 {
		t.Fatalf("说明应截断: %d", len([]rune(g[0].Note)))
	}
}

// 可信模型的误报判断形成待确认的建议：一致率不够不生成，不作为样本，不影响校准；确认过攻击的目标不建议。
func TestAISuggestions(t *testing.T) {
	l := newLearner(t, "")
	// 建立模型的可信度：10 个事件全部与分析员一致
	for i := 1; i <= 10; i++ {
		id := uint64(i)
		l.RecordAI(id, AIRecord{Verdict: "attack", Confidence: 90, Model: "m"})
		l.Feedback(fpCase(id, map[string]int{"r" + strconv.Itoa(i): 1}, "x"+strconv.Itoa(i), "203.0.113.1", VerdictTP))
	}
	fp := func(id uint64, model, target string) {
		l.RecordAI(id, AIRecord{Verdict: "false_positive", Confidence: 85, Model: model, Rules: []string{"sqli-bool"}, Targets: []string{target}})
	}
	fp(101, "m", "shop /api/search?a=1")
	fp(102, "m", "shop /api/search?a=2")
	if len(l.Report().Suggestions) != 0 {
		t.Fatal("判断次数不足时不应生成建议")
	}
	fp(103, "m", "shop /api/search?a=3")
	r := l.Report()
	if len(r.Suggestions) != 1 || r.Suggestions[0].Origin != "ai" || r.Suggestions[0].Target != "shop /api/search" || r.Suggestions[0].FP != 3 || !strings.Contains(r.Suggestions[0].Reason, "待人工确认") {
		t.Fatalf("模型建议: %+v", r.Suggestions)
	}
	hit := []model.Hit{{RuleID: "sqli-bool", Severity: model.SevHigh}}
	if g := l.Calibrate(&model.Event{Kind: model.KindWeb, Host: "shop", URI: "/api/search"}, hit); g[0].Severity != model.SevHigh || r.Cases != 10 || r.CtxTotal != 0 {
		t.Fatalf("模型判断不应成为样本或影响校准: %+v", r)
	}
	// 没有可信度的模型不生成
	for i := uint64(201); i <= 203; i++ {
		fp(i, "other", "shop /api/pay")
	}
	for _, s := range l.Report().Suggestions {
		if s.Target == "shop /api/pay" {
			t.Fatal("可信度不足的模型不应生成建议")
		}
	}
	// 该目标确认过攻击：不再建议
	l.Feedback(fpCase(300, map[string]int{"sqli-bool": 1}, "shop /api/search", "203.0.113.2", VerdictTP))
	if s := l.Report().Suggestions; len(s) != 0 {
		t.Fatalf("确认过攻击的目标不应建议: %+v", s)
	}
}
