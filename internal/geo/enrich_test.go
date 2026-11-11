package geo

import (
	"errors"
	"testing"
	"time"
)

func TestOnlineBackoff(t *testing.T) {
	for tries, want := range map[uint8]time.Duration{0: 0, 1: 10 * time.Minute, 2: 20 * time.Minute, 3: 40 * time.Minute,
		6: 320 * time.Minute, 7: 6 * time.Hour, 200: 6 * time.Hour, 255: 6 * time.Hour} {
		if got := onlineBackoff(tries); got != want {
			t.Errorf("onlineBackoff(%d) = %v，应为 %v", tries, got, want)
		}
	}
}

// 在线定位没有结果（接口没有返回、整批失败）的地址之后可以重试，按间隔退避；拿到结果后不再查询。
// 生产环境中有一批境外攻击源只有离线库的结果（国家级坐标），因为失败后只有等级再次提升才会重试。
func TestEnrichRetriesOnline(t *testing.T) {
	const ip = "104.237.132.58"
	i2r := fakeProvider{"ip2region", map[string]*SourceResult{
		ip: {Source: "ip2region", Country: "United States", CountryCode: "US", Province: "Texas", City: "Richardson"},
	}}
	r := NewResolver(Options{Providers: []Provider{i2r}, Online: NewIPAPI("", "zh-CN"), Gazetteer: loadGaz(t)})
	queued := func() bool {
		select {
		case got := <-r.onlineQ:
			if got != ip {
				t.Fatalf("队列里是 %s", got)
			}
			return true
		default:
			return false
		}
	}
	age := func(d time.Duration) { // 把最近一次查询的时间往前拨
		r.mu.Lock()
		r.cache[ip].onlineAt = time.Now().Add(-d)
		r.mu.Unlock()
	}

	r.Enrich(ip) // 缓存里还没有：先用离线库定位
	if !queued() {
		t.Fatal("第一次调用应发起在线定位")
	}
	if info := r.Lookup(ip); info.CoordSource != "country" || !r.NeedsOnline(info) {
		t.Fatalf("只有离线库结果：国家级坐标、还缺在线定位，得到 %+v", info)
	}
	r.Enrich(ip)
	if queued() {
		t.Fatal("查询进行中不应重复发起")
	}

	// 接口没有返回这个地址
	r.onlineDone(map[string]*SourceResult{}, []string{ip}, nil)
	info := r.Lookup(ip)
	if !info.Enriched || !r.NeedsOnline(info) {
		t.Fatalf("接口没有返回：仍缺在线定位，得到 %+v", info)
	}
	r.Enrich(ip)
	if queued() {
		t.Fatal("十分钟内不应重试")
	}
	age(11 * time.Minute)
	r.Enrich(ip)
	if !queued() {
		t.Fatal("过了退避间隔应重试")
	}

	// 整批失败（网络错误、限流）
	r.onlineDone(nil, []string{ip}, errors.New("HTTP 429"))
	r.mu.Lock()
	still := r.cache[ip].enriched
	r.mu.Unlock()
	if still {
		t.Fatal("失败后应标记为尚未完成溯源")
	}
	age(11 * time.Minute)
	r.Enrich(ip)
	if queued() {
		t.Fatal("第二次失败后的间隔是二十分钟")
	}
	age(21 * time.Minute)
	r.Enrich(ip)
	if !queued() {
		t.Fatal("过了二十分钟应重试")
	}

	// 拿到结果：坐标变为精确坐标，之后不再查询
	r.onlineDone(map[string]*SourceResult{ip: {Source: "ip-api", Country: "美国", CountryCode: "US", Province: "得克萨斯州",
		City: "Richardson", Lat: 32.95, Lon: -96.73}}, []string{ip}, nil)
	info = r.Lookup(ip)
	if info.CoordSource != "ip-api" || info.Lat != 32.95 || r.NeedsOnline(info) || !info.Enriched {
		t.Fatalf("拿到在线结果后应使用精确坐标，得到 %+v", info)
	}
	age(24 * time.Hour)
	r.Enrich(ip)
	if queued() {
		t.Fatal("已有在线结果不应再查询")
	}
}

// 从快照恢复的画像：当时没有拿到在线结果的，恢复后可以补查；反向解析不重复做。
func TestRelocatedEntryCanRetryOnline(t *testing.T) {
	const ip = "50.116.30.65"
	r := NewResolver(Options{Online: NewIPAPI("", "zh-CN"), ReverseDNS: true})
	old := &Info{IP: ip, Enriched: true, RDNS: "li1.members.example.net", Sources: []SourceResult{
		{Source: "ip2region", Country: "United States", CountryCode: "US", Province: "Texas", City: "Richardson"}}}
	info := r.Relocate(ip, old)
	if !r.NeedsOnline(info) {
		t.Fatalf("没有在线结果的画像应标为还缺在线定位: %+v", info)
	}
	r.Enrich(ip)
	if len(r.onlineQ) != 1 || len(r.rdnsQ) != 0 {
		t.Fatalf("应补查在线定位、不重复反向解析：online=%d rdns=%d", len(r.onlineQ), len(r.rdnsQ))
	}
	// 内网地址不查询
	r.Enrich("10.1.2.3")
	if len(r.onlineQ) != 1 {
		t.Fatal("内网地址不应提交在线定位")
	}
	// 没有启用在线库与反向解析时什么也不做
	r2 := NewResolver(Options{})
	r2.Enrich(ip)
	if r2.NeedsOnline(r2.Lookup(ip)) {
		t.Fatal("未启用在线库时不应提示缺少在线定位")
	}
}
