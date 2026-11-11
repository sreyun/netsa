package store

import (
	"testing"
	"time"

	"netsa/internal/model"
)

func learnHit() model.Hit {
	return model.Hit{RuleID: "learn-4b5c24a2", Name: "自学习发现的攻击请求", Category: "未知攻击（自学习）", Severity: model.SevLow,
		Phase: model.PhaseExploit, Result: model.ResultUnknown, Evidence: "请求形态 GET /uaa/api/ht/sid"}
}

func webEv(ip, uri string, t time.Time) *model.Event {
	return &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "GET", URI: uri, Status: 200, Time: t}
}

// 生产环境：被业务轮询停用的自学习观察规则累计了几万次命中。停用后：
//   - 只有这条规则命中的来源不再算作攻击源（总览、地图、攻击源列表）；
//   - 总览的攻击次数、等级分布、研判结果与目标排行剔除这条规则的命中，与攻击类型排行口径一致；
//   - 已关闭事件里的告警同样标记为已撤销；规则重新启用后全部恢复。
func TestRetractedRuleLeavesStatistics(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	sqli := hit("sqli-union", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultUnknown)
	for i := 0; i < 30; i++ {
		s.Record(webEv("45.3.1.1", "/uaa/api/ht/sid", now.Add(time.Duration(i)*time.Second)), []model.Hit{learnHit()}) // 只有观察规则
		s.Record(webEv("45.3.1.2", "/uaa/api/ht/sid", now.Add(time.Duration(i)*time.Second)), []model.Hit{learnHit()}) // 观察规则 + 真实攻击
	}
	s.Record(webEv("45.3.1.2", "/item?id=1", now.Add(time.Minute)), []model.Hit{sqli})
	before := s.Overview()
	if before.Attackers != 2 || before.Totals.Attacks != 61 {
		t.Fatalf("停用前: attackers=%d attacks=%d", before.Attackers, before.Totals.Attacks)
	}
	// 先由分析员把只有观察规则的那个事件关闭为误报（停用规则时事件已不在处置中）
	s.mu.Lock()
	inc := s.incidents[s.incByKey["45.3.1.1"]]
	inc.Status = IncFalsePositive
	s.mu.Unlock()

	s.Retract("learn-4b5c24a2", "", "观察规则 GET /uaa/api/ht/sid 已停用")
	o := s.Overview()
	if o.Attackers != 1 || o.LevelCounts["info"] != 0 {
		t.Fatalf("只有停用规则命中的来源不再算作攻击源: attackers=%d levels=%v", o.Attackers, o.LevelCounts)
	}
	if o.Totals.Attacks != 1 || o.SevCounts["low"] != 0 || o.SevCounts["high"] != 1 || o.Results[model.ResultUnknown] != 1 || o.Phases[model.PhaseExploit] != 1 {
		t.Fatalf("总览剔除停用规则的命中: attacks=%d sev=%v results=%v phases=%v", o.Totals.Attacks, o.SevCounts, o.Results, o.Phases)
	}
	for _, kv := range o.TopTargets {
		if kv.Name == "mg.example.com /uaa/api/ht/sid" {
			t.Fatalf("目标排行不应再有停用规则的目标: %+v", o.TopTargets)
		}
	}
	if m := s.MapData(model.SevInfo); m.Total != 1 {
		t.Fatalf("地图只统计算作攻击源的来源: %d", m.Total)
	}
	if _, total := s.Attackers(AttackerQuery{Limit: 10}); total != 1 {
		t.Fatalf("攻击源列表: %d", total)
	}
	// 已关闭事件里的告警同样标记为已撤销，事件状态不动
	for _, a := range s.Alerts(AlertQuery{IP: "45.3.1.1", Limit: 100}) {
		if a.Retracted == "" {
			t.Fatalf("已关闭事件里的告警也应标记为已撤销: %+v", a)
		}
	}
	// 该来源之后出现了其他规则的命中：重新算作攻击源
	s.Record(webEv("45.3.1.1", "/item?id=2", now.Add(2*time.Minute)), []model.Hit{sqli})
	if o := s.Overview(); o.Attackers != 2 {
		t.Fatalf("出现真实攻击后重新算作攻击源: %d", o.Attackers)
	}
	// 规则重新启用：全部恢复
	s.Restore("learn-4b5c24a2", "", "管理员重新启用")
	if o := s.Overview(); o.Attackers != 2 || o.Totals.Attacks != 62 {
		t.Fatalf("重新启用后恢复: attackers=%d attacks=%d", o.Attackers, o.Totals.Attacks)
	}
}

// 停用规则时，只有这条规则命中的来源从统计中移出；规则重新启用后按新等级计入，统计不重复也不遗漏。
func TestRetractedOnlyAggregateConsistent(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		s.Record(webEv("45.3.2.1", "/uaa/api/ht/sid", now), []model.Hit{learnHit()})
	}
	s.Retract("learn-4b5c24a2", "", "停用")
	s.Restore("learn-4b5c24a2", "", "启用")
	s.Retract("learn-4b5c24a2", "", "停用")
	s.mu.RLock()
	agg := s.agg
	s.mu.RUnlock()
	if agg.attackers != 0 || agg.levels[model.SevLow] != 0 || len(agg.targets) != 0 {
		t.Fatalf("反复停用、启用后统计应一致: attackers=%d levels=%v targets=%v", agg.attackers, agg.levels, agg.targets)
	}
	s.Restore("learn-4b5c24a2", "", "启用")
	s.mu.Lock()
	s.agg.rebuild(s.ips)
	rebuilt := s.agg.attackers
	s.mu.Unlock()
	if o := s.Overview(); o.Attackers != 1 || rebuilt != 1 {
		t.Fatalf("增量统计与重建结果应一致: %d / %d", o.Attackers, rebuilt)
	}
}

// 同一规则在节流窗口内已告警 5 次之后，有证据的成功利用不是“重复命中”：照常生成告警，事件等级随之升高。
func TestThrottleLetsEscalationThrough(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	failed := hit("sqli-union", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultFailed)
	for i := 0; i < 6; i++ {
		s.Record(webEv("45.3.3.1", "/item?id=1", now.Add(time.Duration(i)*time.Second)), []model.Hit{failed})
	}
	ok := hit("sqli-union", "SQL注入", model.PhaseExploit, model.SevCritical, model.ResultSuccess)
	ok.Proven = true
	res := s.Record(webEv("45.3.3.1", "/item?id=1", now.Add(time.Minute)), []model.Hit{ok})
	if len(res.Alerts) != 1 || res.Alerts[0].Severity != model.SevCritical {
		t.Fatalf("有证据的成功利用应生成告警: %+v", res.Alerts)
	}
	s.mu.RLock()
	inc := s.incidents[s.incByKey["45.3.3.1"]]
	sev := inc.Severity
	s.mu.RUnlock()
	if sev != model.SevCritical {
		t.Fatalf("事件等级应升为严重: %s", sev)
	}
	// 之后同样的命中仍按节流处理
	if res := s.Record(webEv("45.3.3.1", "/item?id=1", now.Add(2*time.Minute)), []model.Hit{ok}); len(res.Alerts) != 0 {
		t.Fatalf("同样的命中不再重复告警: %d", len(res.Alerts))
	}
}

// 纠错回溯：事件更早的告警已被淘汰时不下调、不关闭；启动时重放纠错不再把分析员重新打开的事件关掉。
func TestRetractSafety(t *testing.T) {
	s := New(1000, 4, 5, time.Hour) // 告警只保留 4 条
	s.GeoLookup = newTestStore().GeoLookup
	now := time.Now().Add(-time.Hour)
	rce := hit("cmd-exec", "命令执行", model.PhaseExploit, model.SevCritical, model.ResultSuccess)
	rce.Proven = true
	s.Record(webEv("45.3.4.1", "/x.php?c=id", now), []model.Hit{rce})
	for i := 0; i < 4; i++ { // 有证据的成功利用这条告警被淘汰，只剩观察规则的告警
		s.Record(webEv("45.3.4.1", "/uaa/api/ht/sid", now.Add(time.Duration(i+1)*time.Second)), []model.Hit{learnHit()})
	}
	s.Retract("learn-4b5c24a2", "", "停用")
	s.mu.RLock()
	inc := s.incidents[s.incByKey["45.3.4.1"]]
	st, sev := inc.Status, inc.Severity
	s.mu.RUnlock()
	if st == IncFalsePositive || sev != model.SevCritical {
		t.Fatalf("高危告警已被淘汰、无从核对的事件不应下调或关闭: %s %s", st, sev)
	}

	// 只有观察规则的事件：第一次纠错标为误报；分析员重新打开后，重放纠错不再改动
	s2 := newTestStore()
	for i := 0; i < 3; i++ {
		s2.Record(webEv("45.3.4.2", "/uaa/api/ht/sid", now.Add(time.Duration(i)*time.Second)), []model.Hit{learnHit()})
	}
	if n := s2.Retract("learn-4b5c24a2", "", "停用"); n != 1 {
		t.Fatalf("第一次纠错应调整 1 个事件: %d", n)
	}
	s2.mu.Lock()
	inc2 := s2.incidents[s2.incByKey["45.3.4.2"]]
	if inc2.Status != IncFalsePositive {
		s2.mu.Unlock()
		t.Fatalf("全部告警撤销的事件应标为误报: %s", inc2.Status)
	}
	inc2.Status = IncInvestigating // 分析员不同意，重新打开
	s2.mu.Unlock()
	if n := s2.Retract("learn-4b5c24a2", "", "停用"); n != 0 {
		t.Fatalf("重放纠错不应再调整事件: %d", n)
	}
	s2.mu.RLock()
	defer s2.mu.RUnlock()
	if inc2.Status != IncInvestigating {
		t.Fatalf("分析员重新打开的事件不应被再次关闭: %s", inc2.Status)
	}
}

// 越界的端口不进入统计；暴力破解的成功不按接口的正常响应基线判为未成功；模型下调过的高危事件不被自动归档。
func TestPortsBoundAndBruteSuccessKept(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	scan := hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevMedium, model.ResultUnknown)
	for i := 0; i < 50; i++ {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "45.3.5.1", DstIP: "10.0.0.5", DstPort: 70000 + i, Proto: "tcp", Action: model.ActionAllow, Time: now}, []model.Hit{scan})
	}
	s.mu.RLock()
	n := len(s.surf.Ports)
	s.mu.RUnlock()
	if n != 0 {
		t.Fatalf("越界端口不应进入端口统计: %d", n)
	}
	// 登录接口有稳定的正常响应基线
	for i := 0; i < 15; i++ {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.9", Host: "app.example.com", Method: "POST", URI: "/api/login", Status: 200, Bytes: 512, Time: now.Add(time.Duration(i) * time.Second)}, nil)
	}
	brute := hit("bhv-webbrute-ok", "暴力破解", model.PhaseCredential, model.SevCritical, model.ResultSuccess)
	res := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.3.5.2", Host: "app.example.com", Method: "POST", URI: "/api/login", Status: 200, Bytes: 512, Time: now.Add(time.Minute)}, []model.Hit{brute})
	if len(res.Alerts) != 1 || res.Alerts[0].Result != model.ResultSuccess {
		t.Fatalf("暴力破解成功不应按响应基线判为未成功: %+v", res.Alerts)
	}
}

// DNS 日志的目的地址是被查询的 DNS 服务器、访问日志的是记录日志的服务器：都不是内部对外的外部目标。
func TestOutboundOnlyFromConnections(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	dns := hit("intel-dns", "恶意域名", model.PhaseExploit, model.SevHigh, model.ResultUnknown)
	if res := s.Record(&model.Event{Kind: model.KindDNS, SrcIP: "10.0.0.31", DstIP: "8.8.8.8", Host: "evil.example", Time: now}, []model.Hit{dns}); res.NewOutbound != "" {
		t.Fatalf("DNS 服务器不是外部目标: %q", res.NewOutbound)
	}
	web := hit("sqli-union", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultUnknown)
	if res := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "10.0.0.99", DstIP: "203.0.113.10", Host: "www.example.com", URI: "/?id=1", Status: 200, Time: now}, []model.Hit{web}); res.NewOutbound != "" {
		t.Fatalf("访问日志里的服务器地址不是外部目标: %q", res.NewOutbound)
	}
	if res := s.Record(fwOut("10.0.0.31", "45.33.12.122", 443, now), []model.Hit{dns}); res.NewOutbound != "45.33.12.122" {
		t.Fatalf("防火墙记录的出站连接才是外部目标: %q", res.NewOutbound)
	}
}
