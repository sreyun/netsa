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

// 直辖市在地名库中是省级：坐标来源的省份与采信的省份不一致时，坐标同样要跟随采信的地点。
// 生产环境中归属北京、在线库坐标在上海 / 广州的云主机地址把“北京”的标注拉到了山东。
func TestCoordFollowsChosenProvince(t *testing.T) {
	gaz := loadGaz(t)
	lookup := func(local, online *SourceResult) *Info {
		t.Helper()
		ps := []Provider{fakeProvider{"ip2region", map[string]*SourceResult{"1.0.8.1": local}}}
		if online != nil {
			ps = append(ps, fakeProvider{"ip-api", map[string]*SourceResult{"1.0.8.1": online}})
		}
		return NewResolver(Options{Providers: ps, Gazetteer: gaz}).Lookup("1.0.8.1")
	}
	beijing := &SourceResult{Source: "ip2region", Country: "中国", CountryCode: "CN", Province: "北京市", City: "北京市"}

	// 在线库说在上海：改用北京的中心点
	info := lookup(beijing, &SourceResult{Source: "ip-api", Country: "中国", CountryCode: "CN", Province: "上海市", City: "上海", Lat: 31.2222, Lon: 121.4581})
	if info.ProvinceMap != "北京" || info.CoordSource != "province" || !near(info.Lat, 39.9, 0.5) || !near(info.Lon, 116.4, 0.5) {
		t.Fatalf("归属北京、坐标在上海：应改用北京的中心点，得到 %+v", info)
	}
	// 在线库只在城市字段给出直辖市名（广东 / 广州市 之外的写法）
	info = lookup(beijing, &SourceResult{Source: "ip-api", Country: "中国", CountryCode: "CN", Province: "广东", City: "广州市", Lat: 23.1181, Lon: 113.2539})
	if info.CoordSource != "province" || !near(info.Lat, 39.9, 0.5) {
		t.Fatalf("归属北京、坐标在广州：应改用北京的中心点，得到 %+v", info)
	}
	// 在线库同样说在北京：保留它的精确坐标
	info = lookup(beijing, &SourceResult{Source: "ip-api", Country: "中国", CountryCode: "CN", Province: "北京市", City: "北京", Lat: 39.911, Lon: 116.395})
	if info.CoordSource != "ip-api" || info.Lat != 39.911 || info.Lon != 116.395 {
		t.Fatalf("两个数据源都在北京：应保留精确坐标，得到 %+v", info)
	}
	// 在线库配置为英文：地名认不出来，按到省中心的距离判断
	info = lookup(beijing, &SourceResult{Source: "ip-api", Country: "China", CountryCode: "CN", Province: "Shanghai", City: "Shanghai", Lat: 31.2222, Lon: 121.4581})
	if info.CoordSource != "province" || !near(info.Lat, 39.9, 0.5) {
		t.Fatalf("英文地名、坐标远离北京：应改用北京的中心点，得到 %+v", info)
	}
	info = lookup(beijing, &SourceResult{Source: "ip-api", Country: "China", CountryCode: "CN", Province: "Beijing", City: "Beijing", Lat: 39.911, Lon: 116.395})
	if info.CoordSource != "ip-api" || info.Lat != 39.911 {
		t.Fatalf("英文地名、坐标就在北京：应保留精确坐标，得到 %+v", info)
	}
	// 采信的城市地名库里没有（只能定位到省）、在线库在同一个省：保留精确坐标
	hunan := &SourceResult{Source: "ip2region", Country: "中国", CountryCode: "CN", Province: "湖南省", City: "某不存在的地名"}
	info = lookup(hunan, &SourceResult{Source: "ip-api", Country: "中国", CountryCode: "CN", Province: "湖南", City: "长沙", Lat: 28.1142, Lon: 112.983})
	if info.ProvinceMap != "湖南" || info.CoordSource != "ip-api" || info.Lat != 28.1142 {
		t.Fatalf("同一个省内：应保留精确坐标，得到 %+v", info)
	}
	// 同一个省、在线库在另一个省：改用省中心
	info = lookup(hunan, &SourceResult{Source: "ip-api", Country: "中国", CountryCode: "CN", Province: "广东", City: "深圳", Lat: 22.547, Lon: 114.0859})
	if info.CoordSource != "province" || !near(info.Lat, 27.6, 1.2) {
		t.Fatalf("归属湖南、坐标在深圳：应改用湖南的中心点，得到 %+v", info)
	}
}

func TestDistKM(t *testing.T) {
	if d := distKM(39.9, 116.4, 31.23, 121.47); d < 1000 || d > 1150 {
		t.Fatalf("北京到上海约 1070 公里，得到 %.0f", d)
	}
	if d := distKM(31.23, 121.47, 31.23, 121.47); d != 0 {
		t.Fatalf("同一点距离应为 0，得到 %v", d)
	}
}
