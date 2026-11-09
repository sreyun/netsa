package geo

import (
	"net/netip"
	"testing"
)

func TestInternalAndReservedClassification(t *testing.T) {
	// RFC1918 / CGNAT / 回环 / 链路本地 一直算内网
	for _, ip := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.10", "100.64.1.1", "127.0.0.1", "169.254.1.1"} {
		if !IsPrivate(ip) {
			t.Fatalf("%s 应判为内网", ip)
		}
		if !IsNonPublic(netip.MustParseAddr(ip)) {
			t.Fatalf("%s 应判为非公网", ip)
		}
	}
	// RFC1918 只覆盖 172.16 ~ 172.31：172.168 默认按公网处理，必须由配置补充
	for _, ip := range []string{"172.15.0.1", "172.32.0.1", "172.168.100.5", "8.8.8.8"} {
		if IsPrivate(ip) {
			t.Fatalf("%s 不应判为内网", ip)
		}
	}
	// 保留 / 不可路由段：不是内网，但也不能当作境外公网
	for _, ip := range []string{"0.1.2.3", "240.1.1.1"} {
		a := netip.MustParseAddr(ip)
		if IsPrivate(ip) {
			t.Fatalf("%s 不应判为内网", ip)
		}
		if !IsNonPublic(a) {
			t.Fatalf("%s 应判为非公网", ip)
		}
	}
}

func TestConfiguredIntranet(t *testing.T) {
	eff, bad := SetInternalNetworks([]string{"172.168.100.0/24", "172.168.200.0/24", "oops", ""})
	defer SetInternalNetworks(nil)
	if len(eff) != 2 || len(bad) != 1 || bad[0] != "oops" {
		t.Fatalf("解析结果不符: eff=%v bad=%v", eff, bad)
	}
	for _, ip := range []string{"172.168.100.5", "172.168.200.254"} {
		if !IsPrivate(ip) {
			t.Fatalf("配置后 %s 应判为内网", ip)
		}
	}
	// 相邻网段不受影响
	if IsPrivate("172.168.101.5") || IsPrivate("172.168.201.5") {
		t.Fatal("未配置的相邻网段不应判为内网")
	}
	// 恢复后回到公网
	SetInternalNetworks(nil)
	if IsPrivate("172.168.100.5") {
		t.Fatal("清除配置后应恢复为公网")
	}
}

func TestIntranetNotGeolocated(t *testing.T) {
	SetInternalNetworks([]string{"172.168.100.0/24"})
	defer SetInternalNetworks(nil)
	// 定位库里给该地址配了美国记录，也不允许采信
	p := fakeProvider{"ip2region", map[string]*SourceResult{
		"172.168.100.5": {Source: "ip2region", Country: "美国", CountryCode: "US", City: "Los Angeles", Lat: 34.05, Lon: -118.24},
	}}
	r := NewResolver(Options{Providers: []Provider{p}, HomeLat: 31.23, HomeLon: 121.47})
	info := r.Lookup("172.168.100.5")
	if info.Country != "内网" || info.CountryCode != "" || info.City != "" {
		t.Fatalf("内网地址不应采信定位库: %+v", info)
	}
	if info.NetType != "内网" || !info.Private || !info.HasCoord || info.Lat != 31.23 {
		t.Fatalf("内网地址应落在资产所在地: %+v", info)
	}
}

func TestReservedNotGeolocated(t *testing.T) {
	p := fakeProvider{"ip2region", map[string]*SourceResult{
		"240.1.1.1": {Source: "ip2region", Country: "美国", CountryCode: "US"},
	}}
	r := NewResolver(Options{Providers: []Provider{p}})
	info := r.Lookup("240.1.1.1")
	if info.Country != "保留地址" {
		t.Fatalf("保留地址不应采信定位库: %+v", info)
	}
	if info.HasCoord {
		t.Fatalf("保留地址不应有坐标: %+v", info)
	}
}

func TestDetectLocalNetworks(t *testing.T) {
	for _, p := range DetectLocalNetworks() {
		if _, err := netip.ParsePrefix(p); err != nil {
			t.Fatalf("自动探测返回了非法网段 %q", p)
		}
	}
}

// 自学习新增内网网段后，缓存中的地址要按新网段重新定位，之前的在线定位结果不再采信；移出内网后恢复公网定位、可以重新补全。
func TestReclassifyAfterIntranetChange(t *testing.T) {
	SetInternalNetworks(nil)
	defer SetInternalNetworks(nil)
	const ip = "43.242.97.54"
	p := fakeProvider{"ip2region", map[string]*SourceResult{ip: {Source: "ip2region", Country: "中国", CountryCode: "CN", Province: "上海"}}}
	r := NewResolver(Options{Providers: []Provider{p}, HomeLat: 31.23, HomeLon: 121.47})
	before := r.Lookup(ip)
	if before.Private || before.Country != "中国" {
		t.Fatalf("公网地址: %+v", before)
	}
	r.mu.Lock()
	r.cache[ip].online, r.cache[ip].enriched = &SourceResult{Source: "ip-api", Country: "美国", CountryCode: "US"}, true
	r.mu.Unlock()

	AddInternalNetworks([]string{"43.242.97.0/24"})
	r.Reclassify()
	in := r.Relocate(ip, before)
	if !in.Private || in.Country != "内网" || in.CountryCode != "" {
		t.Fatalf("划入内网后应按内部地址定位，且不再采信在线结果: %+v", in)
	}

	SetInternalNetworks(nil)
	r.Reclassify()
	out := r.Relocate(ip, in)
	if out.Private || out.Country != "中国" {
		t.Fatalf("移出内网后应恢复公网定位: %+v", out)
	}
	r.mu.Lock()
	enriched := r.cache[ip].enriched
	r.mu.Unlock()
	if enriched {
		t.Fatal("移出内网后应允许重新补全在线定位")
	}
}
