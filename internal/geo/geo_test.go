package geo

import (
	"net/netip"
	"testing"
)

type fakeProvider struct {
	name string
	res  map[string]*SourceResult
}

func (f fakeProvider) Name() string { return f.name }
func (f fakeProvider) Lookup(a netip.Addr) (*SourceResult, error) {
	return f.res[a.String()], nil
}

func TestMergeAgreement(t *testing.T) {
	i2r := fakeProvider{"ip2region", map[string]*SourceResult{
		"1.0.8.1": {Source: "ip2region", Country: "中国", CountryCode: "CN", Province: "广东省", City: "广州市", ISP: "中国电信"},
		"8.8.8.8": {Source: "ip2region", Country: "中国", CountryCode: "HK", Province: "香港特别行政区"},
	}}
	mm := fakeProvider{"maxmind", map[string]*SourceResult{
		"1.0.8.1": {Source: "maxmind", Country: "中国", CountryCode: "CN", Province: "广东", City: "广州", Lat: 23.1, Lon: 113.3, AccuracyKM: 50, ASN: 4134},
		"8.8.8.8": {Source: "maxmind", Country: "美国", CountryCode: "US", Province: "加利福尼亚州", City: "山景城", Lat: 37.4, Lon: -122.1},
	}}
	r := NewResolver(Options{Providers: []Provider{i2r, mm}})

	info := r.Lookup("1.0.8.1")
	if info.Country != "中国" || info.Province != "广东省" || info.City != "广州市" || info.ISP != "中国电信" {
		t.Fatalf("国内地址应优先 ip2region: %+v", info)
	}
	if info.Confidence != "high" || !info.HasCoord || info.ASN != 4134 {
		t.Fatalf("两源城市一致应为高置信度并带坐标/ASN: %+v", info)
	}

	// 国家不一致时不能把不同来源的省市拼在一起
	info = r.Lookup("8.8.8.8")
	if info.Country != "美国" || info.Province != "加利福尼亚州" || info.City != "山景城" || info.Confidence != "low" {
		t.Fatalf("冲突合并错误: %+v", info)
	}

	if info := r.Lookup("192.168.1.10"); !info.Private || info.NetType != "内网" {
		t.Fatalf("内网地址: %+v", info)
	}
}

func TestParseRegion(t *testing.T) {
	sr := parseRegion("中国|广东省|深圳市|电信|CN")
	if sr.Province != "广东省" || sr.City != "深圳市" || sr.ISP != "电信" || sr.CountryCode != "CN" {
		t.Fatalf("新格式: %+v", sr)
	}
	sr = parseRegion("中国|0|浙江省|杭州市|阿里云")
	if sr.Province != "浙江省" || sr.City != "杭州市" || sr.ISP != "阿里云" {
		t.Fatalf("旧格式: %+v", sr)
	}
	if sr := parseRegion("中国|香港特别行政区|0|0|CN"); sr.CountryCode != "HK" {
		t.Fatalf("港澳台归一: %+v", sr)
	}
	if countryNameZH("US") != "美国" || countryNameZH("JP") != "日本" {
		t.Fatal("中文国家名")
	}
}
