package geo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
)

func TestCustomLocations(t *testing.T) {
	custom := NewCustom([]config.CustomLocation{
		{CIDR: "10.1.0.0/16", Name: "北京总部", Country: "中国", Province: "北京市", City: "北京市"},
		{CIDR: "10.1.2.0/24", Name: "研发中心", Country: "中国", Province: "上海市", City: "上海市", Lat: 31.2, Lon: 121.5},
		{CIDR: "203.0.113.0/24", Name: "合作方出口", Country: "中国", Province: "浙江省", City: "杭州市"},
		{CIDR: "bad", Name: "忽略"},
	})
	if custom.Len() != 3 {
		t.Fatalf("应忽略非法网段: %d", custom.Len())
	}
	i2r := fakeProvider{"ip2region", map[string]*SourceResult{
		"203.0.113.9": {Source: "ip2region", Country: "中国", CountryCode: "CN", Province: "江苏省", City: "南京市", ISP: "电信"},
	}}
	r := NewResolver(Options{Providers: []Provider{i2r}, Gazetteer: loadGaz(t), Custom: custom, HomeLat: 39.9, HomeLon: 116.4})

	// 内网网段、无坐标：按地名中心定位（直辖市取省级中心），仍标记为内网
	info := r.Lookup("10.1.9.9")
	if info.Label != "北京总部" || !info.Private || info.NetType != "内网" || info.CoordSource != "province" || !near(info.Lon, 116.4, 0.5) || info.Confidence != "high" {
		t.Fatalf("内网自定义网段: %+v", info)
	}
	if !strings.HasPrefix(info.Location(), "北京总部") {
		t.Fatalf("位置描述应包含网段名: %s", info.Location())
	}
	// 最长前缀优先，并使用配置的坐标
	info = r.Lookup("10.1.2.3")
	if info.Label != "研发中心" || info.City != "上海市" || info.CoordSource != "custom" || info.Lat != 31.2 {
		t.Fatalf("最长前缀匹配: %+v", info)
	}
	// 公网网段：自定义位置优先于离线库，运营商等其他字段仍取离线库
	info = r.Lookup("203.0.113.9")
	if info.Label != "合作方出口" || info.City != "杭州市" || info.ISP != "电信" || info.Private {
		t.Fatalf("公网自定义网段: %+v", info)
	}
	// 未命中的内网地址落在资产所在地
	info = r.Lookup("192.168.1.1")
	if info.Label != "" || !info.Private || info.CoordSource != "private" || info.Lat != 39.9 {
		t.Fatalf("未命中的内网地址: %+v", info)
	}

	// 热更新自定义网段后缓存中的结果随之刷新
	r.SetCustom(NewCustom([]config.CustomLocation{{CIDR: "192.168.1.0/24", Name: "深圳分部", Country: "中国", Province: "广东省", City: "深圳市"}}))
	if info = r.Lookup("192.168.1.1"); info.Label != "深圳分部" || info.City != "深圳市" {
		t.Fatalf("SetCustom 后应刷新缓存: %+v", info)
	}
	if info = r.Lookup("10.1.9.9"); info.Label != "" || info.CoordSource != "private" {
		t.Fatalf("移除的网段应失效: %+v", info)
	}
}

func TestRelocateKeepsOnline(t *testing.T) {
	r := NewResolver(Options{Online: NewIPAPI("", "zh-CN")})
	old := &Info{IP: "198.51.100.7", Enriched: true, RDNS: "scan.example.net", Sources: []SourceResult{
		{Source: "ip-api", Country: "美国", CountryCode: "US", City: "Ashburn", Lat: 39.0, Lon: -77.5},
	}}
	info := r.Relocate("198.51.100.7", old)
	if info.City != "Ashburn" || info.RDNS != "scan.example.net" || !info.Enriched || info.CoordSource != "ip-api" {
		t.Fatalf("Relocate 应沿用在线溯源结果: %+v", info)
	}
	if r.Lookup("198.51.100.7") != info {
		t.Fatal("Relocate 结果应写入缓存")
	}
}

func TestDBFileChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.xdb")
	f := &dbFile{path: path}
	if _, ok := f.changed(); ok {
		t.Fatal("文件不存在时不应加载")
	}
	if err := os.WriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 刚写入的文件可能尚未复制完成，等待下一轮
	if _, ok := f.changed(); ok {
		t.Fatal("刚写入的文件应等待写入完成")
	}
	old := time.Now().Add(-time.Minute)
	os.Chtimes(path, old, old)
	st, ok := f.changed()
	if !ok {
		t.Fatal("文件出现后应加载")
	}
	f.stamp = st
	if _, ok := f.changed(); ok {
		t.Fatal("未变化时不应重新加载")
	}
	os.WriteFile(path, []byte("v2-longer"), 0o644)
	older := time.Now().Add(-30 * time.Second)
	os.Chtimes(path, older, older)
	if _, ok := f.changed(); !ok {
		t.Fatal("文件被替换后应重新加载")
	}
}
