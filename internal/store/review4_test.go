package store

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 防火墙管理服务按应答记下的“对公网放行”是当前版本的合法发现：重启（快照恢复）后不能被旧数据清理撤销。
func TestDeviceFindingSurvivesReload(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Minute)
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "203.0.113.9", DstIP: "43.242.97.40", DstPort: 22, Proto: "tcp",
		Action: model.ActionAllow, Reach: model.ReachDevice, Reply: model.ReplyYes, Time: now}, nil)
	s.mu.RLock()
	f := s.surf.Findings["dev:43.242.97.40:22/tcp"]
	s.mu.RUnlock()
	if f == nil {
		t.Fatal("有应答的设备管理服务访问应记为发现")
	}
	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.surf.Findings["dev:43.242.97.40:22/tcp"] == nil {
		t.Fatal("按应答确认的设备管理服务发现在快照恢复后被撤销")
	}
}

// 利用尝试占满步骤之后，有证据的突破步骤仍要记录：否则资产研判停在“未见失陷迹象”。
func TestChainBreachAfterExploitFull(t *testing.T) {
	s := New(100000, 1000, 5, time.Hour)
	now := time.Now().Add(-time.Hour)
	for i := range chainMaxSteps + 5 {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("46.%d.%d.9", i/250+1, i%250), DstIP: "43.242.97.44", DstPort: 6379, Proto: "tcp",
			Action: model.ActionAllow, Time: now}, []model.Hit{hit("redis-exp", "已知漏洞利用", model.PhaseExploit, model.SevHigh, model.ResultAllowed)})
	}
	ok := hit("redis-rce", "已知漏洞利用", model.PhaseExploit, model.SevCritical, model.ResultSuccess)
	ok.Proven = true
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "45.33.10.20", DstIP: "43.242.97.44", DstPort: 6379, Proto: "tcp",
		Action: model.ActionAllow, Time: now.Add(time.Minute)}, []model.Hit{ok})
	s.mu.RLock()
	defer s.mu.RUnlock()
	tr := s.chains[chainKey{"host", "43.242.97.44"}]
	if tr == nil {
		t.Fatal("应有链路记录")
	}
	found := false
	for _, st := range tr.Steps {
		if st.Stage == stBreach && st.Src == "45.33.10.20" {
			found = true
		}
	}
	if !found || len(tr.Steps) > chainMaxSteps || len(tr.idx) != len(tr.Steps) {
		t.Fatalf("步骤满时有证据的突破应为其让位: found=%v steps=%d idx=%d", found, len(tr.Steps), len(tr.idx))
	}
	// 更浅的步骤不会挤掉更深的步骤
	for i := range 20 {
		s.mu.RUnlock()
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("47.0.%d.9", i), DstIP: "43.242.97.44", DstPort: 6379, Proto: "tcp",
			Action: model.ActionAllow, Time: now.Add(2 * time.Minute)}, []model.Hit{hit("redis-exp", "已知漏洞利用", model.PhaseExploit, model.SevHigh, model.ResultAllowed)})
		s.mu.RLock()
	}
	found = false
	for _, st := range tr.Steps {
		found = found || st.Stage == stBreach && st.Src == "45.33.10.20"
	}
	if !found {
		t.Fatal("突破步骤不应为之后的利用尝试让位")
	}
}

// 同名的站点与主机记录（主机名与 HTTP Host 相同）在查询时合并：列表只有一行，详情包含两边的步骤。
func TestChainSameNameMerged(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	mk := func(kind string, stage int, cat string) *chainTrack {
		tr := &chainTrack{Key: "git.example.com", Kind: kind, FirstSeen: now, LastSeen: now, Hits: 1}
		tr.Stages[stage] = stageStat{First: now.Unix(), Last: now.Unix(), Hits: 1, Sev: model.SevHigh}
		tr.Steps = []*chainStep{{Stage: stage, Category: cat, Rule: cat, Name: cat, Src: "203.0.113.50", Severity: model.SevHigh,
			Result: model.ResultSuccess, First: now, Last: now, Count: 1}}
		if stage != stRecon {
			tr.Steps[0].Rule = "auth-brute-ok"
		}
		return tr
	}
	s.mu.Lock()
	s.chains[chainKey{"host", "git.example.com"}] = mk("host", stBreach, "暴力破解")
	s.chains[chainKey{"site", "git.example.com"}] = mk("site", stRecon, "目录扫描")
	s.mu.Unlock()
	l := s.ChainList(ChainQuery{})
	n := 0
	for _, c := range l.Chains {
		if c.Key == "git.example.com" {
			n++
			if len(c.Members) != 1 {
				t.Errorf("同名成员只列一次: %v", c.Members)
			}
		}
	}
	if n != 1 {
		t.Fatalf("同名的站点与主机应合并为一行: %d", n)
	}
	c := s.AssetChain("git.example.com")
	stages := map[string]bool{}
	for _, st := range c.Steps {
		stages[st.Stage] = true
	}
	if !stages["breach"] || !stages["recon"] {
		t.Fatalf("详情应包含两条记录的步骤: %v", stages)
	}
}

// 兜底页面的同大小统计满了以后淘汰，而不是从此不再学习：后台页面的动态大小占满名额后，3 条同大小的探测仍能确认兜底页面。
func TestSoftSizesEvict(t *testing.T) {
	sf := newSurface()
	for i := range maxSoftSizes + 10 {
		sf.catchAll("mg.example.com", "/admin/users", int64(5000+i))
	}
	for _, p := range []string{"/.env", "/.git/config", "/backup.sql"} {
		sf.catchAll("mg.example.com", p, 912)
	}
	if !sf.isFallback("mg.example.com", 912) {
		t.Fatal("同大小统计满了以后 3 个不同探测路径返回同一大小仍应确认为兜底页面")
	}
	for i := range maxSoftHosts + 5 {
		sf.catchAll(fmt.Sprintf("s%d.example.com", i), "/x", 1)
	}
	for _, p := range []string{"/.env", "/.git/config", "/backup.sql"} {
		sf.catchAll("new.example.com", p, 777)
	}
	if !sf.isFallback("new.example.com", 777) {
		t.Fatal("站点数满了以后新站点仍应能学习兜底页面")
	}
}

// 服务、入口达到上限后淘汰一批：新的高危服务暴露照常登记与报出，新站点的首页照常登记基线。
func TestSurfaceTablesEvict(t *testing.T) {
	sf := newSurface()
	old := time.Now().Add(-48 * time.Hour)
	for i := range maxServices {
		k := fmt.Sprintf("10.0.%d.%d:%d/tcp", i/250%250, i%250, 40000+i%20000)
		sf.Services[k] = &Service{DstIP: "10.0.0.5", Port: 40000, Proto: "tcp", LastSeen: old, src: map[string]int32{}}
	}
	sf.observeFw(&model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.9", DstIP: "10.0.9.9", DstPort: 6379, Proto: "tcp",
		Action: model.ActionAllow, Time: time.Now()}, true)
	if sf.Services["10.0.9.9:6379/tcp"] == nil || sf.Findings["svc:10.0.9.9:6379/tcp"] == nil {
		t.Fatal("服务表满后新的高危服务暴露仍应登记并生成发现")
	}
	if len(sf.Services) > maxServices {
		t.Fatalf("服务数不应超过上限: %d", len(sf.Services))
	}
	for i := range maxEndpoints {
		k := fmt.Sprintf("a.example.com /p%d", i)
		sf.Endpoints[k] = &Endpoint{Host: "a.example.com", Path: fmt.Sprintf("/p%d", i), Methods: map[string]int{}, Status: map[int]int{},
			Tech: []string{"PHP"}, LastSeen: old, atk: map[string]struct{}{}}
	}
	sf.Tech["PHP"] = maxEndpoints
	sf.observeWeb(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.10", Host: "shop.example.org", Method: "GET", URI: "/", Status: 200, Bytes: 1234,
		Time: time.Now()}, nil, false)
	if sf.Endpoints["shop.example.org /"] == nil {
		t.Fatal("入口表满后新站点的首页仍应登记")
	}
	n := 0
	for _, ep := range sf.Endpoints {
		if slices.Contains(ep.Tech, "PHP") {
			n++
		}
	}
	if sf.Tech["PHP"] != n {
		t.Fatalf("淘汰入口后技术栈计数应同步: %d / %d", sf.Tech["PHP"], n)
	}
}

// 发现满了以后按证据强弱淘汰：较早的失陷迹象不会被之后大量没有证据的疑似成功挤掉。
func TestFindingsEvictByEvidence(t *testing.T) {
	sf := newSurface()
	t0 := time.Now().Add(-time.Hour)
	sf.finding("intel:10.0.0.31", "外连威胁情报地址", "失陷迹象", model.SevCritical, "10.0.0.31", "x", "y", "45.33.12.122", t0)
	for i := 1; i < maxFindings; i++ {
		sf.finding(fmt.Sprintf("succ:SQL注入:www %d", i), "疑似攻击成功", "攻击成功研判", model.SevHigh, "www", "x", "y", "1.2.3.4", t0.Add(time.Minute))
	}
	for i := range 50 {
		sf.finding(fmt.Sprintf("succ:SQL注入:www new%d", i), "疑似攻击成功", "攻击成功研判", model.SevHigh, "www", "x", "y", "1.2.3.4", t0.Add(2*time.Minute))
	}
	if sf.Findings["intel:10.0.0.31"] == nil {
		t.Fatal("失陷迹象不应被没有证据的疑似成功挤掉")
	}
	if sf.Findings["succ:SQL注入:www new49"] == nil || len(sf.Findings) > maxFindings {
		t.Fatalf("新发现应能登记且总数不超过上限: %d", len(sf.Findings))
	}
	// 比现有记录都早的历史日志不挤掉较新的发现
	n := len(sf.Findings)
	for len(sf.Findings) < maxFindings {
		sf.finding(fmt.Sprintf("fill %d", len(sf.Findings)), "t", "攻击成功研判", model.SevHigh, "www", "x", "y", "", t0.Add(3*time.Minute))
	}
	sf.finding("old", "t", "攻击成功研判", model.SevHigh, "www", "x", "y", "", t0.Add(-24*time.Hour))
	if sf.Findings["old"] != nil {
		t.Fatalf("更早的记录不应挤掉较新的发现（原 %d 条）", n)
	}
}

// 检测判为“敏感文件探测 / 成功”的命中即使不在攻击面的分类规则内，也记为敏感资源暴露（206 同样）。
func TestSensitiveSuccessRecorded(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Minute)
	h := hit("sens-file", "敏感文件探测", model.PhaseRecon, model.SevHigh, model.ResultSuccess)
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.7", Host: "mg.example.com", Method: "GET", URI: "/appsettings.json", Status: 200, Bytes: 8123, Time: now},
		[]model.Hit{h})
	s.mu.RLock()
	defer s.mu.RUnlock()
	f := s.surf.Findings["sens:mg.example.com /appsettings.json"]
	if f == nil || f.Category != "敏感资源暴露" || evidenceBytes(f.Evidence) != 8123 {
		t.Fatalf("成功的敏感文件探测应记为暴露: %+v", f)
	}
	if !s.surf.successKept("敏感文件探测", "mg.example.com /appsettings.json") {
		t.Fatal("链路研判应认为取到了文件")
	}
}

// 设备时钟错误：未来时间的日志在画像、告警中按当前时间记录，不让该来源永远算作“近 1 小时活跃”。
func TestFutureTimeClamped(t *testing.T) {
	s := newTestStore()
	future := time.Now().AddDate(5, 0, 0)
	res := s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "203.0.113.88", DstIP: "43.242.97.40", DstPort: 22, Proto: "tcp",
		Action: model.ActionDeny, Time: future}, []model.Hit{hit("fw-riskport", "高危服务探测", model.PhaseRecon, model.SevHigh, model.ResultBlocked)})
	limit := time.Now().Add(time.Hour)
	if len(res.Alerts) == 0 || res.Alerts[0].Time.After(limit) {
		t.Fatalf("告警时间不应在未来: %+v", res.Alerts)
	}
	p := s.IPDetail("203.0.113.88")
	if p == nil || p.Profile.LastSeen.After(limit) || p.Profile.FirstSeen.After(limit) {
		t.Fatalf("画像时间不应在未来: %+v", p)
	}
	old := time.Date(1970, 1, 1, 0, 5, 0, 0, time.UTC)
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "203.0.113.89", DstIP: "43.242.97.40", DstPort: 22, Proto: "tcp",
		Action: model.ActionDeny, Time: old}, []model.Hit{hit("fw-riskport", "高危服务探测", model.PhaseRecon, model.SevHigh, model.ResultBlocked)})
	if p := s.IPDetail("203.0.113.89"); p == nil || p.Profile.LastSeen.Year() < 2000 {
		t.Fatalf("1970 年的时间应按当前时间记录: %+v", p)
	}
	if o := s.Overview(); o.Recent.Attackers != 2 {
		t.Fatalf("两个来源都应计入近 1 小时活跃: %d", o.Recent.Attackers)
	}
}

// 评估：同一个严重级服务按发现与服务只计一次；认证日志的暴力破解成功计入凭证安全维度。
func TestAssessCountsDeduped(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Minute)
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "203.0.113.9", DstIP: "43.242.97.40", DstPort: 6379, Proto: "tcp",
		Action: model.ActionAllow, Time: now}, nil)
	a := s.Assess(Visibility{ParseRate: 1})
	if !strings.Contains(a.Verdict, "存在 1 项严重暴露面") {
		t.Fatalf("单个严重服务应计 1 项: %s", a.Verdict)
	}
	s.mu.Lock()
	s.surf.finding("auth-ok:db01:root", "暴力破解后登录成功（账号疑似失陷）", "失陷迹象", model.SevCritical, "db01", "x", "y", "203.0.113.50", now)
	d := s.collectAssessLocked()
	s.mu.Unlock()
	if d.bruteSuccess != 1 {
		t.Fatalf("认证日志的暴力破解成功应计入: %d", d.bruteSuccess)
	}
}

// topKeys 始终按计数降序（同数按键）排列，结果不随 map 遍历顺序变化。
func TestTopKeysOrdered(t *testing.T) {
	m := map[string]int{"SQL注入": 3, "端口扫描": 900, "目录扫描": 40, "XSS": 3}
	for range 20 {
		if got := topKeys(m, 6); !slices.Equal(got, []string{"端口扫描", "目录扫描", "SQL注入", "XSS"}) && !slices.Equal(got, []string{"端口扫描", "目录扫描", "XSS", "SQL注入"}) {
			t.Fatalf("应按计数排序: %v", got)
		}
	}
	if got := topKeys(m, 6); got[2] != "SQL注入" && got[2] != "XSS" || got[2] > got[3] {
		t.Fatalf("同数按键升序: %v", got)
	}
}

// 快照文件名为 .gz 但内容未压缩时照常读取；gzip 头损坏时先备份，不被下一次保存覆盖。
func TestLoadGzipSniff(t *testing.T) {
	s := newTestStore()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.20", Method: "GET", URI: "/a", Status: 403, Time: time.Now().Add(-time.Minute)},
		[]model.Hit{attackHit("r1", "XSS跨站脚本", model.SevHigh, model.ResultBlocked)})
	dir := t.TempDir()
	plain := filepath.Join(dir, "state.json")
	if err := s.Save(plain); err != nil {
		t.Fatal(err)
	}
	gz := filepath.Join(dir, "state.json.gz")
	if err := os.Rename(plain, gz); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(gz); err != nil || r.IPDetail("203.0.113.20") == nil {
		t.Fatalf("未压缩的快照改名为 .gz 后应能读取: %v", err)
	}
	bad := filepath.Join(dir, "bad.json.gz")
	os.WriteFile(bad, []byte{0x1f, 0x8b, 0xff, 0xff, 0xff}, 0o600)
	if err := newTestStore().Load(bad); err == nil {
		t.Fatal("gzip 头损坏应返回错误")
	}
	if _, err := os.Stat(bad + ".corrupt.bak"); err != nil {
		t.Fatalf("gzip 头损坏的快照应先备份: %v", err)
	}
}

// 辅助记录（Zeek ssl）上的 C2 命中同样记录外部目标：同一连接的 conn 记录没有命中。
func TestOutboundFromAuxRecord(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Minute)
	s.Record(fwOut("10.0.0.31", "45.33.12.122", 443, now), nil)
	ev := fwOut("10.0.0.31", "45.33.12.122", 443, now)
	ev.Aux = true
	res := s.Record(ev, []model.Hit{hit("intel-tls", "远控通信", model.PhasePersistence, model.SevHigh, model.ResultUnknown)})
	if res.NewOutbound != "45.33.12.122" || s.MapData(model.SevInfo).OutTotal != 1 {
		t.Fatalf("辅助记录的 C2 命中应记录外部目标: %+v", res)
	}
	rp := fwOut("10.0.0.32", "45.33.12.200", 443, now)
	rp.Replay = true
	if res := s.Record(rp, []model.Hit{hit("intel-tls", "远控通信", model.PhasePersistence, model.SevHigh, model.ResultUnknown)}); res.NewOutbound != "" {
		t.Fatal("补发的事件副本不重复记录")
	}
}

// 事件搜索逐字段比较：编号、来源、归属地、攻击类型、资产都能命中；大小写不敏感。
func TestIncidentSearchFields(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Minute)
	res := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "Shop.Example.com", Method: "GET", URI: "/a", Status: 403, Time: now},
		[]model.Hit{attackHit("r1", "SQL注入", model.SevHigh, model.ResultBlocked)})
	id := res.Alerts[0].IncidentID
	for _, q := range []string{"198.51.100.1", "深圳", "sql注入", fmt.Sprint(id), "198.51.100.1 中国"} {
		if l, _, _ := s.Incidents(IncidentQuery{Search: q}); len(l) != 1 {
			t.Errorf("搜索 %q 应命中: %d", q, len(l))
		}
	}
	if l, _, _ := s.Incidents(IncidentQuery{Search: "不存在的关键字"}); len(l) != 0 {
		t.Error("不相关的关键字不应命中")
	}
}

// 地图每个地点只返回评分最高的 10 个攻击源（顺序固定）；指标的攻击源等级分布与总览一致。
func TestMapTopAndMetrics(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Minute)
	for i := range 30 {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		for range i%5 + 1 {
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/a", Status: 403, Time: now},
				[]model.Hit{attackHit("r1", "SQL注入", model.SevHigh, model.ResultBlocked)})
		}
	}
	m := s.MapData(model.SevInfo)
	if len(m.Points) != 1 || len(m.Points[0].IPs) != 10 {
		t.Fatalf("每个地点返回 10 个攻击源: %+v", m.Points)
	}
	ips := m.Points[0].IPs
	for i := 1; i < len(ips); i++ {
		if ips[i].Score > ips[i-1].Score || ips[i].Score == ips[i-1].Score && ips[i].Attacks > ips[i-1].Attacks {
			t.Fatalf("地点内攻击源应按评分排序: %+v", ips)
		}
	}
	mt := s.Metrics()
	o := s.Overview()
	for i, n := range mt.Attackers {
		if o.LevelCounts[model.Severity(i).String()] != n {
			t.Fatalf("指标与总览的等级分布不一致: %v %v", mt.Attackers, o.LevelCounts)
		}
	}
}

// 快照分段编码后与原来一样可以完整恢复：保存、恢复、再保存的内容一致。
func TestSnapshotSegmentedRoundTrip(t *testing.T) {
	s := newTestStore()
	killChain(s, time.Now().Add(-2*time.Hour))
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "203.0.113.9", DstIP: "43.242.97.40", DstPort: 6379, Proto: "tcp",
		Action: model.ActionAllow, Time: time.Now().Add(-time.Minute)}, nil)
	dir := t.TempDir()
	p1, p2 := filepath.Join(dir, "a.json.gz"), filepath.Join(dir, "b.json.gz")
	if err := s.Save(p1); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(p1); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(p2); err != nil {
		t.Fatal(err)
	}
	read := func(p string) map[string]any {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(zr)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("快照应是合法的 JSON: %v", err)
		}
		delete(m, "saved_at")
		return m
	}
	a, b := read(p1), read(p2)
	for _, k := range []string{"alerts", "incidents", "surface", "asset_chains", "profiles", "days", "buckets"} {
		if _, ok := a[k]; !ok {
			t.Errorf("快照缺少 %s", k)
		}
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		for k := range a {
			x, _ := json.Marshal(a[k])
			y, _ := json.Marshal(b[k])
			if !bytes.Equal(x, y) {
				t.Errorf("恢复后再保存的 %s 不一致", k)
			}
		}
	}
	if len(r.ChainList(ChainQuery{}).Chains) != len(s.ChainList(ChainQuery{}).Chains) || len(r.Alerts(AlertQuery{Limit: 1000})) != len(s.Alerts(AlertQuery{Limit: 1000})) {
		t.Fatal("恢复后的链路与告警应一致")
	}
}
