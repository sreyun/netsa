package store

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

// referenceOverview 是改造前的全量扫描实现，仅用于校验增量统计的一致性。
func referenceOverview(s *Store) *Overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o := &Overview{Attackers: 0, LevelCounts: map[string]int{}}
	countries, provinces, cities, isps, nettypes, targets := map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}
	cutMinute := 0.0
	if !s.maxTime.IsZero() {
		cutMinute = float64(s.maxTime.Add(-time.Hour).Unix() / 60)
	}
	for _, p := range s.ips {
		if !isAttacker(p) {
			continue
		}
		o.Attackers++
		o.LevelCounts[p.Level.String()]++
		if float64(p.LastSeen.Unix()/60) >= cutMinute {
			o.Recent.Attackers++
			if p.Level >= model.SevHigh {
				o.ActiveHigh++
			}
			if float64(p.FirstSeen.Unix()/60) >= cutMinute {
				o.NewAttackers++
			}
		}
		country, prov, city, isp, nt := geoKeys(p)
		countries[country]++
		if prov != "" {
			provinces[prov]++
		}
		if city != "" {
			cities[city]++
		}
		if isp != "" {
			isps[isp]++
		}
		nettypes[nt]++
		for t, n := range p.Targets {
			targets[t] += int64(n)
		}
	}
	o.TopCountries = topN(countries, 15, ident)
	o.TopProvinces = topN(provinces, 15, ident)
	o.TopCities = topN(cities, 15, ident)
	o.CountryCount, o.CityCount = len(countries), len(cities)
	if _, ok := countries["未知"]; ok {
		o.CountryCount--
	}
	o.TopISPs = topN(isps, 10, ident)
	o.TopNetTypes = topN(nettypes, 0, ident)
	o.TopTargets = topN(targets, 10, ident)
	return o
}

func kvMap(list []KV) map[string]int64 {
	out := make(map[string]int64, len(list))
	for _, kv := range list {
		out[kv.Name] = kv.Value
	}
	return out
}

func assertAggregateConsistent(t *testing.T, s *Store) {
	t.Helper()
	got := s.Overview()
	want := referenceOverview(s)

	if got.Attackers != want.Attackers {
		t.Fatalf("攻击源数不一致: 增量=%d 全量=%d", got.Attackers, want.Attackers)
	}
	if !reflect.DeepEqual(got.LevelCounts, want.LevelCounts) {
		t.Fatalf("等级分布不一致: 增量=%v 全量=%v", got.LevelCounts, want.LevelCounts)
	}
	if got.Recent.Attackers != want.Recent.Attackers || got.ActiveHigh != want.ActiveHigh || got.NewAttackers != want.NewAttackers {
		t.Fatalf("近 1 小时不一致: 增量(%d,%d,%d) 全量(%d,%d,%d)", got.Recent.Attackers, got.ActiveHigh, got.NewAttackers,
			want.Recent.Attackers, want.ActiveHigh, want.NewAttackers)
	}
	if got.CountryCount != want.CountryCount || got.CityCount != want.CityCount {
		t.Fatalf("国家/城市数不一致: 增量(%d,%d) 全量(%d,%d)", got.CountryCount, got.CityCount, want.CountryCount, want.CityCount)
	}
	// 安全评估的增量统计同样必须与全量扫描一致
	intel, brute, scanners, cc, port, matrix := referenceAssessCounters(s)
	if a := s.agg; a.intelHits != intel || a.brute != brute || a.scanners != scanners || a.ccSources != cc || a.portScanners != port {
		t.Fatalf("评估统计不一致:\n增量(情报=%d 爆破=%d 扫描=%d CC=%d 端口=%d)\n全量(情报=%d 爆破=%d 扫描=%d CC=%d 端口=%d)",
			a.intelHits, a.brute, a.scanners, a.ccSources, a.portScanners, intel, brute, scanners, cc, port)
	}
	if got := s.buildMatrixLocked(s.agg.matrixAcc()); !reflect.DeepEqual(got, matrix) {
		t.Fatalf("ATT&CK 矩阵不一致:\n增量=%+v\n全量=%+v", got, matrix)
	}
	for name, pair := range map[string][2][]KV{
		"国家":   {got.TopCountries, want.TopCountries},
		"省份":   {got.TopProvinces, want.TopProvinces},
		"城市":   {got.TopCities, want.TopCities},
		"运营商":  {got.TopISPs, want.TopISPs},
		"网络类型": {got.TopNetTypes, want.TopNetTypes},
		"攻击目标": {got.TopTargets, want.TopTargets},
	} {
		if a, b := kvMap(pair[0]), kvMap(pair[1]); !reflect.DeepEqual(a, b) {
			t.Fatalf("%s统计不一致:\n增量=%v\n全量=%v", name, a, b)
		}
	}
}

func testGeo(i int) *geo.Info {
	switch i % 3 {
	case 0:
		return &geo.Info{Country: "中国", ProvinceMap: "广东", Province: "广东省", City: "深圳市", ISP: "电信", NetType: "宽带/企业专线", HasCoord: true}
	case 1:
		return &geo.Info{Country: "美国", Province: "California", City: "Los Angeles", ISP: "Amazon", NetType: "IDC/云主机", HasCoord: true}
	}
	return nil
}

// referenceAssessCounters 是改造前 Assess 中遍历全部画像的统计逻辑，用于校验增量版本。
func referenceAssessCounters(s *Store) (intelHits, brute, scanners, cc, port int, matrix *AttackMatrix) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var acc matrixAcc
	for _, p := range s.ips {
		if !isAttacker(p) {
			continue
		}
		if len(p.Intel) > 0 {
			intelHits++
		}
		var b, sc, c, po bool
		for cat := range p.Categories {
			switch cat {
			case "暴力破解":
				b = true
			case "扫描器", "网络空间测绘", "目录扫描":
				sc = true
			case "CC攻击", "洪水攻击":
				c = true
			case "端口扫描", "主机探测", "高危服务探测":
				po = true
			}
			acc.category(cat, p.CatSev[cat])
		}
		acc.done()
		brute += b2i(b)
		scanners += b2i(sc)
		cc += b2i(c)
		port += b2i(po)
	}
	return intelHits, brute, scanners, cc, port, s.buildMatrixLocked(&acc)
}

var aggCats = []string{"SQL注入", "XSS跨站脚本", "端口扫描", "暴力破解", "扫描器", "CC攻击", "高危服务探测", "目录扫描", "未知手法"}
var aggSevs = []model.Severity{model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical}

// TestAggregateMatchesFullScan 随机写入、乱序、更新归属地、触发淘汰后，
// 增量统计必须与全量扫描逐项一致。
func TestAggregateMatchesFullScan(t *testing.T) {
	s := New(30, 500, 5, time.Hour) // 小上限，确保过程中发生淘汰
	s.GeoLookup = func(ip string) *geo.Info {
		var n int
		fmt.Sscanf(ip, "203.0.113.%d", &n)
		return testGeo(n)
	}
	// 部分来源命中威胁情报，覆盖「情报攻击源」的增量统计
	s.IntelMatch = func(ip string) []string {
		if strings.HasSuffix(ip, ".7") || strings.HasSuffix(ip, ".13") {
			return []string{"Tor 出口节点"}
		}
		return nil
	}
	rnd := rand.New(rand.NewSource(42))
	base := time.Now().Add(-30 * time.Minute)
	targets := []string{"43.242.97.40:1433/tcp", "43.242.97.41:443/tcp", "10.0.0.21:3306/tcp"}

	for i := 0; i < 400; i++ {
		ip := fmt.Sprintf("203.0.113.%d", rnd.Intn(80))                  // 80 个来源，超过上限触发淘汰
		at := base.Add(time.Duration(rnd.Intn(3600)-1800) * time.Second) // ±30 分钟，含乱序
		switch r := rnd.Intn(10); {
		case r < 6: // 攻击事件
			cat := aggCats[rnd.Intn(len(aggCats))]
			sev := aggSevs[rnd.Intn(len(aggSevs))]
			target := targets[rnd.Intn(len(targets))]
			s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: ip, DstIP: "43.242.97.40", DstPort: 1433,
				Proto: "tcp", Action: model.ActionAllow, Time: at},
				[]model.Hit{{RuleID: "r-" + cat, Name: cat, Category: cat, Severity: sev, Phase: model.PhaseExploit, Result: model.ResultBlocked}})
			_ = target
		case r < 9: // 普通访问
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/", Status: 200, Time: at}, nil)
		default: // 归属地更新
			s.UpdateGeo(ip, testGeo(rnd.Intn(3)))
		}
		if i%5 == 0 { // 频繁对账，尽早暴露增量维护的偏差
			s.Maintain()
			assertAggregateConsistent(t, s)
		}
	}
	s.Maintain()
	assertAggregateConsistent(t, s)
}

// TestAggregateAfterGeoRefresh 定位库热更新后，地域统计要随之迁移。
func TestAggregateAfterGeoRefresh(t *testing.T) {
	s := New(1000, 100, 5, time.Hour)
	now := time.Now()
	for i := 0; i < 20; i++ {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("198.51.100.%d", i), DstIP: "43.242.97.40",
			DstPort: 1433, Proto: "tcp", Action: model.ActionAllow, Time: now},
			[]model.Hit{{RuleID: "r", Name: "r", Category: "端口扫描", Severity: model.SevMedium, Phase: model.PhaseRecon}})
	}
	assertAggregateConsistent(t, s)

	// 全部改为美国
	s.RefreshGeo(func(ip string, old *geo.Info) *geo.Info { return testGeo(1) })
	assertAggregateConsistent(t, s)
	if got := s.Overview(); got.TopCountries[0].Name != "美国" {
		t.Fatalf("地域统计未更新: %+v", got.TopCountries)
	}
}

// TestAggregateRestoredFromSnapshot 快照恢复后按画像重建统计。
func TestAggregateRestoredFromSnapshot(t *testing.T) {
	s := New(1000, 100, 5, time.Hour)
	s.GeoLookup = func(ip string) *geo.Info { return testGeo(0) }
	now := time.Now()
	for i := 0; i < 30; i++ {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("198.51.100.%d", i), DstIP: "43.242.97.40",
			DstPort: 1433, Proto: "tcp", Action: model.ActionAllow, Time: now},
			[]model.Hit{{RuleID: "r", Name: "r", Category: "端口扫描", Severity: model.SevMedium, Phase: model.PhaseRecon}})
	}
	path := t.TempDir() + "/state.json"
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := New(1000, 100, 5, time.Hour)
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	assertAggregateConsistent(t, s2)
	if got := s2.Overview(); got.Attackers != 30 {
		t.Fatalf("恢复后攻击源数应为 30，实际 %d", got.Attackers)
	}
}
