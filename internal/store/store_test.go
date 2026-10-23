package store

import (
	"path/filepath"
	"testing"
	"time"

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
