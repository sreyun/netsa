package store

import (
	"testing"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

// 同一地点在不同数据源里的写法不同（“广东省 / 广州市”与“广东 / 广州市”，直辖市“北京市 / 北京市”与“北京市 / 北京”）：
// 地图上应合并为一个标注，展示名取更完整的写法，下钻该地点能列出全部成员；地名库里没有的城市各自成点。
func TestMapPointsMergeSpellings(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	scan := hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevMedium, model.ResultUnknown)
	cn := func(prov, city, provMap, cityMap, src string, lat, lon float64) *geo.Info {
		return &geo.Info{Country: "中国", CountryCode: "CN", Province: prov, City: city, ProvinceMap: provMap, CityMap: cityMap,
			WorldName: "China", Lat: lat, Lon: lon, HasCoord: true, CoordSource: src}
	}
	geos := map[string]*geo.Info{
		"45.1.1.1": cn("广东省", "广州市", "广东", "广州市", "city", 23.13, 113.26),
		"45.1.1.2": cn("广东", "广州市", "广东", "广州市", "ip-api", 23.1317, 113.266),
		"45.1.2.1": cn("北京市", "北京市", "北京", "", "province", 39.9, 116.4),
		"45.1.2.2": cn("北京市", "北京", "北京", "", "ip-api", 39.911, 116.395),
		"45.1.3.1": cn("湖南省", "湘西", "湖南", "", "province", 27.6, 111.7),
		"45.1.3.2": cn("湖南省", "某地", "湖南", "", "province", 27.6, 111.7),
	}
	for ip, g := range geos {
		s.Record(fwOut(ip, "10.0.0.5", 22, now), []model.Hit{scan})
		g.IP = ip
		s.UpdateGeo(ip, g)
	}
	m := s.MapData(model.SevInfo)
	byName := map[string]*MapPoint{}
	for _, p := range m.Points {
		byName[p.Name] = p
	}
	if len(m.Points) != 4 {
		t.Fatalf("应合并为 4 个地点（广州、北京、湘西、某地），得到 %d 个：%v", len(m.Points), keysOf(byName))
	}
	gz := byName["中国 广东省 广州市"]
	if gz == nil || gz.Attackers != 2 || gz.CoordSource != "ip-api" || gz.Lat != 23.1317 {
		t.Fatalf("广州：两种写法合并，展示名取完整写法，坐标取精确值：%+v（全部 %v）", gz, keysOf(byName))
	}
	bj := byName["中国 北京市"]
	if bj == nil || bj.Attackers != 2 || bj.Lat != 39.911 {
		t.Fatalf("北京：直辖市的两种写法合并：%+v（全部 %v）", bj, keysOf(byName))
	}
	if byName["中国 湖南省 湘西"] == nil || byName["中国 湖南省 某地"] == nil {
		t.Fatalf("地名库里没有的城市各自成点：%v", keysOf(byName))
	}
	// 下钻：按地点聚合键能列出该地点的全部攻击源
	if list, total := s.Attackers(AttackerQuery{Place: gz.Key, Limit: 10}); total != 2 || len(list) != 2 {
		t.Fatalf("按地点下钻应列出 2 个攻击源，得到 %d", total)
	}
	// 多次生成结果一致（成员遍历顺序是随机的）
	for i := 0; i < 20; i++ {
		m2 := s.MapData(model.SevInfo)
		for j, p := range m2.Points {
			if q := m.Points[j]; p.Key != q.Key || p.Name != q.Name || p.Lat != q.Lat || p.Lon != q.Lon {
				t.Fatalf("第 %d 次生成的结果不一致：%+v 与 %+v", i, p, q)
			}
		}
	}
}

func keysOf(m map[string]*MapPoint) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPlaceName(t *testing.T) {
	for _, c := range [][4]string{
		{"中国", "广东省", "深圳市", "中国 广东省 深圳市"},
		{"中国", "北京市", "北京市", "中国 北京市"},
		{"中国", "北京市", "北京", "中国 北京市"},
		{"中国", "北京", "北京市", "中国 北京"},
		{"中国", "吉林省", "吉林市", "中国 吉林省 吉林市"},
		{"中国", "吉林省", "吉林", "中国 吉林省 吉林"},
		{"美国", "Texas", "Richardson", "美国 Texas Richardson"},
		{"英国", "England", "", "英国 England"},
		{"广东", "", "广州市", "广东 广州市"},
		{"", "", "", ""},
	} {
		if got := placeName(c[0], c[1], c[2]); got != c[3] {
			t.Errorf("placeName(%q, %q, %q) = %q，应为 %q", c[0], c[1], c[2], got, c[3])
		}
	}
}

// 快照恢复、定位库更新后，内部对外的外部目标与攻击源一样按当前定位规则重新定位。
func TestRefreshGeoCoversOutbound(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	scan := hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevMedium, model.ResultUnknown)
	s.Record(fwOut("10.0.0.31", "45.33.12.122", 443, now), []model.Hit{scan})
	fixed := &geo.Info{IP: "45.33.12.122", Country: "德国", CountryCode: "DE", City: "法兰克福", WorldName: "Germany",
		Lat: 50.1, Lon: 8.7, HasCoord: true, CoordSource: "ip-api"}
	s.RefreshGeo(func(ip string, old *geo.Info) *geo.Info {
		if ip == "45.33.12.122" {
			return fixed
		}
		return old
	})
	m := s.MapData(model.SevInfo)
	if len(m.Outbound) != 1 || m.Outbound[0].Country != "德国" || m.Outbound[0].Lat != 50.1 {
		t.Fatalf("外部目标应按新的定位结果上图：%+v", m.Outbound)
	}
}

// 还缺在线定位的攻击源与外连目标：等级高的在前，拿到在线结果后不再列出，普通访客不列出。
func TestGeoPending(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	scan := hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevMedium, model.ResultUnknown)
	sqli := hit("sqli-union", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultUnknown)
	s.Record(fwOut("45.2.1.1", "10.0.0.5", 22, now), []model.Hit{scan})
	s.Record(fwOut("45.2.1.2", "10.0.0.5", 22, now), []model.Hit{sqli})
	s.Record(fwOut("45.2.1.3", "10.0.0.5", 443, now), nil)                // 普通访客
	s.Record(fwOut("10.0.0.31", "45.2.9.9", 443, now), []model.Hit{scan}) // 内部对外的目标
	needs := func(g *geo.Info) bool {
		for _, sr := range g.Sources {
			if sr.Source == "ip-api" {
				return false
			}
		}
		return !g.Private
	}
	got := s.GeoPending(model.SevLow, needs, 10)
	if len(got) != 3 || got[0] != "45.2.1.2" {
		t.Fatalf("应列出两个攻击源与一个外连目标，高危在前：%v", got)
	}
	if got := s.GeoPending(model.SevLow, needs, 1); len(got) != 1 || got[0] != "45.2.1.2" {
		t.Fatalf("limit 应截取最靠前的：%v", got)
	}
	s.UpdateGeo("45.2.1.2", &geo.Info{IP: "45.2.1.2", Country: "美国", CountryCode: "US", HasCoord: true, Lat: 1, Lon: 2, CoordSource: "ip-api",
		Sources: []geo.SourceResult{{Source: "ip-api"}}})
	if got := s.GeoPending(model.SevLow, needs, 10); len(got) != 2 || got[0] == "45.2.1.2" || got[1] == "45.2.1.2" {
		t.Fatalf("拿到在线结果后不再列出：%v", got)
	}
	if got := s.GeoPending(model.SevLow, nil, 10); got != nil {
		t.Fatalf("没有判断函数时返回空：%v", got)
	}
}
