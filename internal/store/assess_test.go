package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/detect"
	"netsa/internal/model"
)

func intelStub(ip string) []string {
	switch {
	case strings.HasPrefix(ip, "203.0.113."):
		return []string{"演示威胁情报"}
	case ip == "198.51.100.250":
		return []string{"Tor出口节点"}
	}
	return nil
}

// 所有内置检测类型都映射到 ATT&CK 技术（威胁情报命中、自定义规则除外），映射的技术都有定义。
func TestAttackMapping(t *testing.T) {
	for _, cat := range []string{detect.CatSQLi, detect.CatXSS, detect.CatTraversal, detect.CatCmdExec, detect.CatExpr, detect.CatSSRF,
		detect.CatXXE, detect.CatDeser, detect.CatWebShell, detect.CatCVE, detect.CatSensitive, detect.CatAdminProbe, detect.CatScanner,
		detect.CatMapping, detect.CatAutomation, detect.CatProtocol, detect.CatCC, detect.CatDirScan, detect.CatBruteForce, detect.CatPortScan,
		detect.CatHostSweep, detect.CatFlood, detect.CatIoT, detect.CatRiskService, detect.CatSpoof, detect.CatCrawl, detect.CatBeacon, CatC2, CatMalware} {
		ts := categoryTechniques[cat]
		if len(ts) == 0 {
			t.Errorf("攻击类型 %s 未映射到 ATT&CK", cat)
		}
		for _, id := range ts {
			tech, ok := techniques[id]
			if !ok || tacticIndex(tech.Tactic) >= len(tactics) {
				t.Errorf("%s 映射的技术 %s 未定义或战术无效", cat, id)
			}
		}
	}
	for id := range techniques {
		if len(techniqueCategories[id]) == 0 {
			t.Errorf("技术 %s 没有对应的检测类型", id)
		}
	}
}

// 内网主机外连威胁情报地址：放行为严重、拦截为高危；只命中 Tor 为中危；普通出站流量不产生告警，
// 也不计入网络服务暴露面。
func TestC2Egress(t *testing.T) {
	s := newTestStore()
	s.IntelMatch = intelStub
	now := time.Now()
	fw := func(src, dst string, port int, act string, out bool) RecordResult {
		return s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Action: act, Outbound: out, Time: now}, nil)
	}
	if r := fw("10.0.0.31", "203.0.113.66", 443, model.ActionAllow, false); len(r.Alerts) != 1 || r.Alerts[0].Severity != model.SevCritical ||
		r.Alerts[0].Category != CatC2 || r.Alerts[0].Result != model.ResultAllowed {
		t.Fatalf("放行的外连应产生严重告警: %+v", r.Alerts)
	}
	if r := fw("10.0.0.32", "203.0.113.99", 3333, model.ActionDeny, false); len(r.Alerts) != 1 || r.Alerts[0].Severity != model.SevHigh {
		t.Fatalf("被拦截的外连应为高危: %+v", r.Alerts)
	}
	// 本机出站流量（iptables OUTPUT 链），源地址为公网地址
	if r := fw("192.0.2.10", "203.0.113.5", 8080, model.ActionAllow, true); len(r.Alerts) != 1 {
		t.Fatalf("本机外连恶意地址应告警: %+v", r)
	}
	if r := fw("10.0.0.33", "198.51.100.250", 9001, model.ActionAllow, false); len(r.Alerts) != 1 || r.Alerts[0].Severity != model.SevMedium {
		t.Fatalf("只命中 Tor 出口应为中危: %+v", r.Alerts)
	}
	// 普通出站流量与公网入站流量
	if r := fw("10.0.0.45", "8.8.8.8", 443, model.ActionAllow, false); len(r.Alerts) != 0 {
		t.Fatal("普通出站流量不应告警")
	}
	if r := fw("203.0.113.66", "10.0.0.10", 443, model.ActionAllow, false); len(r.Alerts) != 1 || r.Alerts[0].Category != "威胁情报" {
		t.Fatalf("情报地址的入站访问由情报命中规则处理，不应判为外连: %+v", r.Alerts)
	}
	sf := s.Surface()
	for _, sv := range sf.Services {
		if sv.DstIP == "8.8.8.8" || sv.DstIP == "203.0.113.66" {
			t.Fatalf("出站访问的公网地址不应计入暴露面: %+v", sv)
		}
	}
	comp := s.CompromisedAssets()
	if len(comp) != 4 || comp[0].Kind != "host" || comp[0].Confidence != "high" || len(comp[0].IPs) == 0 {
		t.Fatalf("失陷主机: %+v", comp)
	}
	if s.Overview().Totals.Outbound != 1 {
		t.Fatal("出站计数")
	}
	// 外连告警计入 ATT&CK 命令与控制
	m := s.AttackMatrix()
	var c2 *TechniqueStat
	for _, tc := range m.Tactics {
		for i := range tc.Techniques {
			if tc.Techniques[i].ID == "T1071" {
				c2 = &tc.Techniques[i]
			}
		}
	}
	if c2 == nil || c2.Hits != 4 || c2.Attackers != 4 || c2.MaxSeverity != model.SevCritical {
		t.Fatalf("ATT&CK 外连统计: %+v", c2)
	}
	if n, _ := s.Attackers(AttackerQuery{Technique: "T1071"}); len(n) != 4 {
		t.Fatal("按技术筛选攻击源")
	}
	if n := len(s.Alerts(AlertQuery{Technique: "T1071"})); n != 4 {
		t.Fatalf("按技术筛选告警: %d", n)
	}
}

// 内网主机触发安全设备的恶意软件 / 远控告警时同样记为失陷迹象。
func TestMalwareFromDevice(t *testing.T) {
	s := newTestStore()
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.50", DstIP: "198.51.100.8", DstPort: 443, Action: model.ActionDeny, Time: time.Now()},
		[]model.Hit{{RuleID: "dev-threat", Name: "Trojan.Gen C2 Beacon", Category: CatMalware, Severity: model.SevCritical, Phase: model.PhasePersistence, Result: model.ResultBlocked}})
	if c := s.CompromisedAssets(); len(c) != 1 || c[0].Asset != "10.0.0.50" || c[0].Confidence != "high" {
		t.Fatalf("设备报出的内网恶意软件应记为失陷: %+v", c)
	}
}

// 安全评估：无风险时高分；出现高置信失陷时总评降为“危险”并给出 P0 应急处置建议；
// 严重暴露面给出 P0 建议；未接入的数据维度不参与评分。
func TestAssessment(t *testing.T) {
	full := Visibility{ParseRate: 1, PreciseGeo: true, Intel: 1, Robots: 1, Archive: true, AuthEnabled: true, HTTPS: true}
	s := newTestStore()
	now := time.Now()
	// 只有正常访问
	for i := 0; i < 50; i++ {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: "/", Status: 200, Time: now}, nil)
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.1", DstIP: "10.0.0.10", DstPort: 443, Action: model.ActionAllow, Time: now}, nil)
	}
	a := s.Assess(full)
	if a.Score < 90 || a.Grade != "A" || len(a.Compromised) != 0 || a.Matrix == nil || len(a.Dimensions) != 7 {
		t.Fatalf("无风险时应为优秀: %d %s %+v", a.Score, a.Grade, a.Actions)
	}
	for _, act := range a.Actions {
		if act.Priority < "P2" {
			t.Fatalf("无风险时不应有 P0/P1 建议: %+v", act)
		}
	}
	// 未接入防火墙日志时边界防护不参与评分，并提示补齐
	s2 := newTestStore()
	s2.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: "/", Status: 200, Time: now}, nil)
	a2 := s2.Assess(Visibility{ParseRate: 1})
	if p := dimByKey(a2.Dimensions, "perimeter"); p.Score != -1 || p.Level != "na" {
		t.Fatalf("缺少防火墙日志: %+v", p)
	}
	if v := dimByKey(a2.Dimensions, "visibility"); v.Score >= 50 || len(v.Advice) == 0 {
		t.Fatalf("可见性: %+v", v)
	}

	// 严重暴露面：.git 目录可下载，Redis 对公网开放
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.9", Host: "a.com", Method: "GET", URI: "/.git/config", Status: 200, Bytes: 300, Time: now},
		[]model.Hit{{RuleID: "sens-git", Name: "源码仓库泄露探测", Category: detect.CatSensitive, Severity: model.SevHigh, Phase: model.PhaseRecon, Result: model.ResultSuccess}})
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.9", DstIP: "10.0.0.21", DstPort: 6379, Proto: "tcp", Action: model.ActionAllow, Time: now}, nil)
	a = s.Assess(full)
	if a.Score > 59 || a.Actions[0].Priority != "P0" || !strings.Contains(a.Verdict, "严重暴露面") {
		t.Fatalf("严重暴露面: %d %s %+v", a.Score, a.Verdict, a.Actions[0])
	}
	var redis bool
	for _, act := range a.Actions {
		if act.Priority == "P0" && strings.Contains(act.Reason, "Redis") {
			redis = true
		}
	}
	if !redis {
		t.Fatalf("Redis 对公网开放应为 P0: %+v", a.Actions)
	}

	// 高置信失陷：WebShell 交互成功
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.66", Host: "a.com", Method: "POST", URI: "/upload/x.php", Status: 200, Bytes: 80, Time: now},
		[]model.Hit{{RuleID: "webshell", Name: "WebShell 交互", Category: detect.CatWebShell, Severity: model.SevCritical, Phase: model.PhasePersistence, Result: model.ResultSuccess}})
	a = s.Assess(full)
	if a.Score > 35 || a.Grade != "E" || len(a.Compromised) != 1 || a.Compromised[0].Confidence != "high" || a.ActionCount["P0"] < 3 {
		t.Fatalf("高置信失陷: %d %s %+v", a.Score, a.Grade, a.Compromised)
	}
	first := a.Actions[0]
	if first.Priority != "P0" || first.Dimension != "compromise" || first.Drill == nil || first.Drill.Params["q"] != "/upload/x.php" ||
		!strings.Contains(strings.Join(first.Steps, " "), "198.51.100.66") {
		t.Fatalf("失陷处置建议: %+v", first)
	}
	if c := dimByKey(a.Dimensions, "compromise"); c.Level != "risk" || c.Score > 60 {
		t.Fatalf("失陷维度: %+v", c)
	}
}

// 总览态势研判：近 60 分钟与再往前 60 分钟对比、新增攻击源、活跃高危攻击源与疑似成功攻击。
func TestOverviewSituation(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	hit := func(ip string, at time.Time, cat string, sev model.Severity, res string) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/x", Status: 200, Time: at},
			[]model.Hit{{RuleID: "r" + sev.String(), Name: "r", Category: cat, Severity: sev, Phase: model.PhaseExploit, Result: res}})
	}
	hit("198.51.100.1", now.Add(-90*time.Minute), detect.CatXSS, model.SevMedium, model.ResultBlocked)
	hit("198.51.100.1", now.Add(-80*time.Minute), detect.CatXSS, model.SevMedium, model.ResultBlocked)
	hit("198.51.100.2", now.Add(-10*time.Minute), detect.CatSQLi, model.SevCritical, model.ResultSuccess)
	// 低危来源用端口扫描：SQL 注入的分类底线是高危，构造不出低危攻击源
	hit("198.51.100.3", now.Add(-5*time.Minute), detect.CatPortScan, model.SevLow, model.ResultBlocked)
	o := s.Overview()
	if o.Prev.Attacks != 2 || o.Recent.Attacks != 2 || o.NewAttackers != 2 || o.ActiveHigh != 1 || o.RecentSuccess != 1 || o.Compromised != 1 {
		t.Fatalf("态势研判: prev=%d recent=%d new=%d high=%d succ=%d comp=%d", o.Prev.Attacks, o.Recent.Attacks, o.NewAttackers, o.ActiveHigh, o.RecentSuccess, o.Compromised)
	}
	if o.Prev.ThreatIndex <= 0 || o.ThreatIndex <= o.Prev.ThreatIndex {
		t.Fatalf("威胁指数环比: %v %v", o.Prev.ThreatIndex, o.ThreatIndex)
	}
	d := s.IPDetail("198.51.100.2")
	if len(d.Techniques) != 1 || d.Techniques[0].ID != "T1190" || d.Techniques[0].TacticName != "初始访问" {
		t.Fatalf("IP 详情中的 ATT&CK 技术: %+v", d.Techniques)
	}
}

// 基于接口正常响应基线复核“疑似成功”：响应与正常页面一致时改判为未拦截；响应明显不同或接口响应本身波动大时保留。
func TestSuccessBaseline(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	visit := func(uri string, bytes int64) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.com", Method: "GET", URI: uri, Status: 200, Bytes: bytes, Time: now}, nil)
	}
	for i := 0; i < 10; i++ {
		visit("/item?id="+itoa(i), 5000+int64(i*10))    // 模板页面：大小稳定
		visit("/search?q="+itoa(i), int64(1000+i*3000)) // 搜索结果：大小波动大
	}
	sqli := func(uri string, bytes int64) model.Hit {
		r := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.9", Host: "a.com", Method: "GET", URI: uri, Status: 200, Bytes: bytes, Time: now},
			[]model.Hit{{RuleID: "sqli", Name: "SQL注入", Category: detect.CatSQLi, Severity: model.SevCritical, Phase: model.PhaseExploit, Result: model.ResultSuccess}})
		return model.Hit{Result: r.Alerts[0].Result, Severity: r.Alerts[0].Severity, Evidence: r.Alerts[0].Evidence}
	}
	if h := sqli("/item?id=1'+or+'1'='1", 5040); h.Result != model.ResultPassed || !strings.Contains(h.Evidence, "正常响应一致") {
		t.Fatalf("响应与正常页面一致应改判为未拦截: %+v", h)
	}
	s.perRule = 100
	if h := sqli("/item?id=-1+union+select+password", 48000); h.Result != model.ResultSuccess {
		t.Fatalf("响应明显不同应保留疑似成功: %+v", h)
	}
	if h := sqli("/search?q=1'+and+sleep(5)", 4000); h.Result != model.ResultSuccess {
		t.Fatalf("响应大小波动大的接口无法判断，应保留疑似成功: %+v", h)
	}
}

// 周期性外连（无情报命中）：记录告警并作为中置信失陷迹象；出站流量本身不计入攻击源统计。
func TestBeaconCompromise(t *testing.T) {
	s := newTestStore()
	ev := &model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.31", DstIP: "198.51.100.66", DstPort: 443, Action: model.ActionAllow, Outbound: true, Time: time.Now()}
	r := s.Record(ev, []model.Hit{{RuleID: "bhv-beacon", Name: "周期性外连", Category: detect.CatBeacon, Severity: model.SevMedium, Phase: model.PhasePersistence, Result: model.ResultAllowed, Evidence: "每隔约 7 分钟"}})
	if len(r.Alerts) != 1 {
		t.Fatalf("出站流量命中周期性外连应告警: %+v", r)
	}
	c := s.CompromisedAssets()
	if len(c) != 1 || c[0].Asset != "10.0.0.31" || c[0].Confidence != "medium" || c[0].IPs[0] != "198.51.100.66" {
		t.Fatalf("周期性外连应为中置信失陷: %+v", c)
	}
	if s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.31", DstIP: "1.1.1.1", DstPort: 443, Outbound: true, Time: time.Now()}, nil).NewIP {
		t.Fatal("普通出站流量不应建立画像")
	}
}

// assessBenchStore 构造 5 万个攻击源的状态库（每个攻击源命中 3 类攻击）。
func assessBenchStore(b *testing.B) *Store {
	s := New(100000, 20000, 5, 7*24*time.Hour)
	cats := []string{detect.CatSQLi, detect.CatXSS, detect.CatScanner, detect.CatDirScan, detect.CatBruteForce, detect.CatPortScan, detect.CatCmdExec, detect.CatSensitive}
	now := time.Now()
	evs := make([]*model.Event, 0, 1024)
	hits := make([][]model.Hit, 0, 1024)
	for i := 0; i < 50000; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256)
		for j := 0; j < 3; j++ {
			c := cats[(i+j)%len(cats)]
			evs = append(evs, &model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/x", Status: 403, Time: now})
			hits = append(hits, []model.Hit{{RuleID: c, Name: c, Category: c, Severity: model.Severity(1 + (i+j)%4), Phase: model.PhaseExploit, Result: model.ResultBlocked}})
		}
		if len(evs) >= 1000 {
			s.RecordBatch(evs, hits)
			evs, hits = evs[:0], hits[:0]
		}
	}
	s.RecordBatch(evs, hits)
	return s
}

func BenchmarkAttackMatrix(b *testing.B) {
	s := assessBenchStore(b)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.AttackMatrix()
	}
}

func BenchmarkAssess(b *testing.B) {
	s := assessBenchStore(b)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Assess(Visibility{ParseRate: 1})
	}
}

func BenchmarkOverview(b *testing.B) {
	s := assessBenchStore(b)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Overview()
	}
}

// 评分历史：同一小时内覆盖、超过 30 天截断，并随快照保存与恢复；日报统计近 24 小时的攻击态势。
func TestScoreHistoryAndDaily(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	hit := func(ip string, at time.Time, sev model.Severity) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/x", Status: 403, Time: at},
			[]model.Hit{{RuleID: "r", Name: "r", Category: detect.CatSQLi, Severity: sev, Phase: model.PhaseExploit, Result: model.ResultBlocked}})
	}
	hit("198.51.100.1", now.Add(-30*time.Hour), model.SevMedium)
	hit("198.51.100.1", now.Add(-2*time.Hour), model.SevHigh)
	hit("198.51.100.2", now.Add(-1*time.Hour), model.SevCritical)
	d := s.DailySummary(24 * time.Hour)
	if d.Attacks != 2 || d.PrevAttacks != 1 || d.Attackers != 2 || d.NewAttackers != 1 || d.Blocked != 2 || len(d.TopAttackers) != 2 || d.TopCats[0].Name != detect.CatSQLi {
		t.Fatalf("日报统计: %+v", d)
	}
	a := s.Assess(Visibility{ParseRate: 1})
	s.RecordScore(a)
	s.RecordScore(a) // 同一小时内覆盖
	if h := s.ScoreHistory(); len(h) != 1 || h[0].Score != a.Score || h[0].Dims["compromise"] != 100 {
		t.Fatalf("评分历史: %+v", h)
	}
	s.mu.Lock()
	for i := 0; i < maxScorePoints+5; i++ {
		s.scores = append(s.scores, ScorePoint{T: now.Add(-time.Duration(maxScorePoints+10-i) * time.Hour), Score: i % 100})
	}
	s.mu.Unlock()
	s.RecordScore(a)
	if n := len(s.ScoreHistory()); n != maxScorePoints {
		t.Fatalf("评分历史应截断为 %d 条: %d", maxScorePoints, n)
	}
	path := filepath.Join(t.TempDir(), "s.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore()
	if err := s2.Load(path); err != nil || len(s2.ScoreHistory()) != maxScorePoints || len(s2.Assess(Visibility{}).History) != maxScorePoints {
		t.Fatalf("评分历史应随快照恢复: %v", err)
	}
}
