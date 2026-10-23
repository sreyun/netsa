package geo

import (
	"math"
	"os"
	"testing"
)

func loadGaz(t *testing.T) *Gazetteer {
	t.Helper()
	g, err := LoadGazetteer(os.DirFS("../../web/static"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestGazetteerChina(t *testing.T) {
	g := loadGaz(t)
	maps := g.ChinaMaps()
	if len(maps) != 34 || maps["广东"] != "guangdong" || maps["陕西"] != "shanxi1" || maps["台湾"] != "taiwan" || maps["香港"] != "xianggang" {
		t.Fatalf("省级地图索引异常(%d): %v", len(maps), maps)
	}
	cases := []struct {
		info              Info
		level, prov, city string
		lon, lat          float64
	}{
		{Info{CountryCode: "CN", Country: "中国", Province: "广东省", City: "深圳市"}, "city", "广东", "深圳市", 114.08, 22.54},
		{Info{CountryCode: "CN", Country: "中国", Province: "广西壮族自治区", City: "南宁"}, "city", "广西", "南宁市", 108.3, 22.8},
		{Info{CountryCode: "CN", Country: "中国", Province: "北京市", City: "北京市"}, "province", "北京", "", 116.4, 39.9},
		{Info{CountryCode: "CN", Country: "中国", City: "苏州市"}, "city", "江苏", "苏州市", 120.6, 31.3},
		{Info{CountryCode: "HK", Country: "中国香港"}, "province", "香港", "", 114.17, 22.3},
	}
	for _, c := range cases {
		pl := g.Resolve(&c.info)
		if pl.Level != c.level || pl.ProvinceMap != c.prov || pl.CityMap != c.city || pl.WorldName != "China" ||
			!near(pl.Lon, c.lon, 0.5) || !near(pl.Lat, c.lat, 0.5) {
			t.Errorf("%+v => %+v", c.info, pl)
		}
	}
}

func TestGazetteerWorld(t *testing.T) {
	g := loadGaz(t)
	cases := []struct {
		cc, name string
		lon, lat float64
	}{
		{"US", "United States", -99, 39}, // 本土质心，不应被阿拉斯加拉偏
		{"KR", "Korea", 127.8, 36.4},
		{"CZ", "Czech Rep.", 15.3, 49.8},
		{"FR", "France", 2.5, 46.5}, // 不应被法属圭亚那拉偏
		{"JP", "Japan", 137, 36},
	}
	for _, c := range cases {
		pl := g.Resolve(&Info{CountryCode: c.cc})
		if pl.WorldName != c.name || pl.Level != "country" || !near(pl.Lon, c.lon, 4) || !near(pl.Lat, c.lat, 4) {
			t.Errorf("%s => %+v", c.cc, pl)
		}
	}
	// 只有英文国名（ip2region 境外数据）时同样可以匹配
	if pl := g.Resolve(&Info{Country: "Germany"}, "Germany"); pl.WorldName != "Germany" {
		t.Errorf("Germany => %+v", pl)
	}
}

func TestResolverApproxCoord(t *testing.T) {
	i2r := fakeProvider{"ip2region", map[string]*SourceResult{
		"1.0.8.1": {Source: "ip2region", Country: "中国", CountryCode: "CN", Province: "浙江省", City: "杭州市", ISP: "电信"},
	}}
	r := NewResolver(Options{Providers: []Provider{i2r}, Gazetteer: loadGaz(t)})
	info := r.Lookup("1.0.8.1")
	if !info.HasCoord || info.CoordSource != "city" || info.CityMap != "杭州市" || info.ProvinceMap != "浙江" || !near(info.Lon, 120.15, 0.3) {
		t.Fatalf("离线城市坐标换算失败: %+v", info)
	}
}

func TestCoordFollowsChosenCity(t *testing.T) {
	i2r := fakeProvider{"ip2region", map[string]*SourceResult{
		"1.0.8.1": {Source: "ip2region", Country: "中国", CountryCode: "CN", Province: "广东省", City: "江门市"},
	}}
	mm := fakeProvider{"maxmind", map[string]*SourceResult{
		"1.0.8.1": {Source: "maxmind", Country: "中国", CountryCode: "CN", Province: "广东", City: "广州", Lat: 23.13, Lon: 113.26, AccuracyKM: 50},
	}}
	r := NewResolver(Options{Providers: []Provider{i2r, mm}, Gazetteer: loadGaz(t)})
	info := r.Lookup("1.0.8.1")
	if info.City != "江门市" || info.CoordSource != "city" || !near(info.Lon, 113.08, 0.3) || !near(info.Lat, 22.58, 0.3) {
		t.Fatalf("坐标应跟随采信的城市(江门): %+v", info)
	}
}
