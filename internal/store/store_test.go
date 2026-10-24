package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"netsa/internal/geo"
	"netsa/internal/model"
)

func attackHit(rule, cat string, sev model.Severity, result string) model.Hit {
	return model.Hit{RuleID: rule, Name: rule, Category: cat, Severity: sev, Phase: model.PhaseExploit, Result: result, Evidence: "x"}
}

func newTestStore() *Store {
	s := New(1000, 100, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info {
		switch ip {
		case "198.51.100.1", "198.51.100.2":
			return &geo.Info{IP: ip, Country: "中国", CountryCode: "CN", Province: "广东省", City: "深圳市", WorldName: "China",
				ProvinceMap: "广东", CityMap: "深圳市", Lat: 22.54, Lon: 114.06, HasCoord: true, CoordSource: "city"}
		}
		return &geo.Info{IP: ip, Country: "美国", CountryCode: "US", WorldName: "United States", Lat: 39, Lon: -98, HasCoord: true, CoordSource: "country"}
	}
	return s
}

func TestNormalVisitorIsLightweight(t *testing.T) {
	s := newTestStore()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.5", Status: 200, UA: "Mozilla", Time: time.Now()}, nil)
	p := s.Profile("203.0.113.5")
	if p.Categories != nil || p.Rules != nil || p.Targets != nil {
		t.Fatal("正常访客不应分配攻击统计结构")
	}
}

func TestMapAggregationAndSnapshot(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "203.0.113.9"} {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/x", Status: 403, Time: now},
			[]model.Hit{attackHit("sqli-union", "SQL注入", model.SevHigh, model.ResultBlocked)})
	}
	m := s.MapData(model.SevLow)
	if m.Total != 3 || len(m.Points) != 2 || len(m.Provinces) != 1 || m.Provinces[0].MapName != "广东" || m.Provinces[0].Attackers != 2 {
		t.Fatalf("地图聚合错误: %+v", m)
	}
	var sz *MapPoint
	for _, p := range m.Points {
		if p.City == "深圳市" {
			sz = p
		}
	}
	if sz == nil || sz.Attackers != 2 || len(sz.IPs) != 2 || sz.Name != "中国 广东省 深圳市" {
		t.Fatalf("城市聚合错误: %+v", sz)
	}
	o := s.Overview()
	if len(o.TopCities) == 0 || o.TopCities[0].Name != "广东 深圳市" || o.TopCities[0].Value != 2 {
		t.Fatalf("城市排行错误: %+v", o.TopCities)
	}

	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore()
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	if o2 := s2.Overview(); o2.Attackers != 3 || o2.Totals.Attacks != 3 {
		t.Fatalf("快照恢复错误: %+v", o2.Totals)
	}
	// 恢复后继续记录不应 panic（惰性 map / 节流状态需正确初始化）
	s2.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: "/y", Status: 200, Time: now},
		[]model.Hit{attackHit("xss-script", "XSS跨站脚本", model.SevHigh, model.ResultPassed)})
	if len(s2.Alerts(AlertQuery{IP: "198.51.100.1"})) != 2 {
		t.Fatal("恢复后告警记录异常")
	}
}

func TestAlertRingBuffer(t *testing.T) {
	s := New(1000, 10, 1000, time.Hour)
	now := time.Now()
	for i := 0; i < 25; i++ {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.7", URI: "/x", Status: 403, Time: now},
			[]model.Hit{attackHit("r", "c", model.SevLow, model.ResultBlocked)})
	}
	list := s.Alerts(AlertQuery{Limit: 100})
	if len(list) != 10 || list[0].ID != 25 || list[9].ID != 16 {
		t.Fatalf("环形缓冲区应保留最新 10 条且按新到旧排列: n=%d first=%d last=%d", len(list), list[0].ID, list[len(list)-1].ID)
	}
}

// 攻击源等级不低于其触发过的最高告警等级：告警事件中出现高危时，总览的“高危以上攻击源”必须包含该 IP。
func TestLevelFollowsAlertSeverity(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.1", Method: "GET", URI: "/a", Status: 404, Time: now},
		[]model.Hit{attackHit("rce-probe", "命令执行", model.SevHigh, model.ResultFailed)})
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.2", Method: "GET", URI: "/b", Status: 403, Time: now},
		[]model.Hit{attackHit("log4shell", "表达式注入", model.SevCritical, model.ResultBlocked)})
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.3", Method: "GET", URI: "/c", Status: 404, Time: now},
		[]model.Hit{attackHit("xss", "XSS", model.SevMedium, model.ResultPassed)})
	for ip, want := range map[string]model.Severity{"203.0.113.1": model.SevHigh, "203.0.113.2": model.SevCritical, "203.0.113.3": model.SevMedium} {
		p := s.Profile(ip)
		if p.Level != want || p.Score < levelFloor[want] {
			t.Errorf("%s level=%s score=%.1f want %s", ip, p.Level, p.Score, want)
		}
	}
	o := s.Overview()
	if o.LevelCounts["high"] != 1 || o.LevelCounts["critical"] != 1 || o.SevCounts["high"] != 1 {
		t.Fatalf("总览统计与告警等级不一致: levels=%v sev=%v", o.LevelCounts, o.SevCounts)
	}
	sum := s.AlertSummary()
	if sum.Retained["high"] != 1 || sum.HitsTotal != 3 || sum.RetainedTotal != 3 {
		t.Fatalf("告警汇总错误: %+v", sum)
	}
}

// 画像数硬上限：大量不同来源的正常访问不会无限创建画像，攻击者仍能建立画像。
func TestProfileHardCap(t *testing.T) {
	s := New(8, 100, 5, time.Hour) // 硬上限 8 + 8/4 = 10
	now := time.Now()
	for i := 0; i < 30; i++ {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: fmt.Sprintf("192.0.2.%d", i), Status: 200, Time: now}, nil)
	}
	if n := len(s.ips); n != 10 || s.totals.Untracked != 20 || s.totals.Web != 30 {
		t.Fatalf("profiles=%d untracked=%d web=%d", n, s.totals.Untracked, s.totals.Web)
	}
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.66", Method: "GET", URI: "/x", Status: 404, Time: now},
		[]model.Hit{attackHit("sqli", "SQL注入", model.SevHigh, model.ResultFailed)})
	if p := s.Profile("203.0.113.66"); p == nil || p.Attacks != 1 || len(s.ips) > 10 {
		t.Fatalf("超过上限时攻击者应能建立画像: %v, profiles=%d", p, len(s.ips))
	}
}

// 未来时间的异常日志不能把统计窗口推到未来（否则趋势数据会被保留期清理）。
func TestFutureTimestampClamped(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Status: 200, Time: now}, nil)
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.2", Status: 200, Time: now.AddDate(70, 0, 0)}, nil)
	s.Maintain()
	if s.maxTime.After(time.Now().Add(time.Minute)) || len(s.buckets) == 0 {
		t.Fatalf("maxTime=%v buckets=%d", s.maxTime, len(s.buckets))
	}
}

// 保存快照时分批持锁：大规模状态下，保存期间的日志入库不能被阻塞整个保存过程。
func TestSaveDoesNotBlockWriters(t *testing.T) {
	s := New(100000, 1000, 5, time.Hour)
	now := time.Now()
	for i := 0; i < 60000; i++ {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), Method: "GET", URI: "/a?id=1", Status: 404, UA: "sqlmap", Time: now},
			[]model.Hit{attackHit("sqli", "SQL注入", model.SevHigh, model.ResultFailed)})
	}
	path := filepath.Join(t.TempDir(), "state.json.gz")
	done := make(chan time.Duration)
	go func() {
		start := time.Now()
		if err := s.Save(path); err != nil {
			t.Error(err)
		}
		done <- time.Since(start)
	}()
	var worst time.Duration
	var total time.Duration
	for running := true; running; {
		select {
		case total = <-done:
			running = false
		default:
			t0 := time.Now()
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.1", Status: 200, Time: now}, nil)
			worst = max(worst, time.Since(t0))
			time.Sleep(time.Millisecond)
		}
	}
	t.Logf("保存耗时 %v，期间单次入库最长等待 %v", total, worst)
	if total > 200*time.Millisecond && worst > total/2 {
		t.Fatalf("保存期间入库被长时间阻塞: 最长等待 %v / 保存耗时 %v", worst, total)
	}
	s2 := New(100000, 1000, 5, time.Hour)
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	if len(s2.ips) < 60000 || s2.totals.Attacks < 60000 || s2.Profile("10.0.0.5").Attacks != 1 {
		t.Fatalf("快照恢复不完整: ips=%d attacks=%d", len(s2.ips), s2.totals.Attacks)
	}
}

// 态势总览下钻：点击各排行 / 分布条目后列出的攻击源与告警必须与图表中的数量一致。
func TestOverviewDrillDown(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	long := "/" + strings.Repeat("中", 120) // 超过 200 字节，排行中的目标会被截断
	events := []struct {
		ip, uri, cat, phase string
		sev                 model.Severity
		at                  time.Time
	}{
		{"198.51.100.1", "/login", "SQL注入", model.PhaseExploit, model.SevHigh, now.Add(-30 * time.Minute)},
		{"198.51.100.2", "/login", "暴力破解", model.PhaseCredential, model.SevMedium, now.Add(-20 * time.Minute)},
		{"203.0.113.9", long, "SQL注入", model.PhaseExploit, model.SevCritical, now.Add(-10 * time.Minute)},
	}
	for _, e := range events {
		h := attackHit("r-"+e.cat, e.cat, e.sev, model.ResultBlocked)
		h.Phase = e.phase
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: e.ip, Host: "a.com", Method: "GET", URI: e.uri, Status: 403, Time: e.at}, []model.Hit{h})
	}
	o := s.Overview()
	count := func(q AttackerQuery) int { _, n := s.Attackers(q); return n }
	for _, kv := range o.TopCountries {
		if n := count(AttackerQuery{Country: kv.Name}); int64(n) != kv.Value {
			t.Errorf("国家 %s: 下钻 %d 个，图表 %d 个", kv.Name, n, kv.Value)
		}
	}
	for _, kv := range o.TopCities {
		if n := count(AttackerQuery{City: kv.Name}); int64(n) != kv.Value {
			t.Errorf("城市 %s: 下钻 %d 个，图表 %d 个", kv.Name, n, kv.Value)
		}
	}
	for _, kv := range o.TopNetTypes {
		if n := count(AttackerQuery{NetType: kv.Name}); int64(n) != kv.Value {
			t.Errorf("网络类型 %s: 下钻 %d 个，图表 %d 个", kv.Name, n, kv.Value)
		}
	}
	if count(AttackerQuery{Category: "SQL注入"}) != 2 || count(AttackerQuery{Phase: model.PhaseCredential}) != 1 || count(AttackerQuery{Category: "XSS"}) != 0 {
		t.Fatal("按攻击类型 / 阶段筛选攻击源错误")
	}
	m := s.MapData(model.SevLow)
	for _, p := range m.Points {
		if n := count(AttackerQuery{Place: p.Key}); n != p.Attackers {
			t.Errorf("地图地点 %s: 下钻 %d 个，地图 %d 个", p.Name, n, p.Attackers)
		}
	}
	for _, r := range m.Countries {
		if n := count(AttackerQuery{World: r.MapName}); n != r.Attackers {
			t.Errorf("地图国家 %s: 下钻 %d 个，地图 %d 个", r.MapName, n, r.Attackers)
		}
	}
	if count(AttackerQuery{Province: "广东", CityMap: "深圳市"}) != 2 {
		t.Fatal("按省份 / 地市筛选攻击源错误")
	}
	// 告警：攻击阶段、被攻击目标（含截断的长目标）与时间段
	if n := len(s.Alerts(AlertQuery{Phase: model.PhaseExploit})); n != 2 {
		t.Fatalf("按阶段筛选告警: %d", n)
	}
	for _, kv := range o.TopTargets {
		if n := len(s.Alerts(AlertQuery{Target: kv.Name})); int64(n) != kv.Value {
			t.Errorf("目标 %q: 下钻 %d 条，图表 %d 次", kv.Name, n, kv.Value)
		}
		if !utf8.ValidString(kv.Name) {
			t.Errorf("截断后的目标不是合法 UTF-8: %q", kv.Name)
		}
	}
	if n := len(s.Alerts(AlertQuery{From: now.Add(-25 * time.Minute), To: now.Add(-15 * time.Minute)})); n != 1 {
		t.Fatalf("按时间段筛选告警: %d", n)
	}
	// 关键字搜索覆盖全部攻击类型（不只是列表中展示的前 4 个）
	if count(AttackerQuery{Search: "暴力破解"}) != 1 || count(AttackerQuery{Search: "198.51.100"}) != 2 {
		t.Fatal("攻击源关键字搜索错误")
	}
	// 排序稳定：分页结果不重复
	a, _ := s.Attackers(AttackerQuery{Limit: 2})
	b, _ := s.Attackers(AttackerQuery{Limit: 2, Offset: 2})
	if len(a) != 2 || len(b) != 1 || a[0].IP == b[0].IP || a[1].IP == b[0].IP {
		t.Fatalf("分页: %v %v", a, b)
	}
}
