package detect

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/geo"
	"netsa/internal/model"
)

// 带宽型 DDoS：1 分钟内入向流量超过阈值时按目的地址告警（反射协议写入证据），平时流量就很大的地址按自己的基线判断，
// 持续攻击不重复告警；出站流量与内网来源不计入。
func TestBandwidthDDoS(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	flow := func(src, dst string, sport int, bytes int64, at time.Time) {
		b.ObserveHits(&model.Event{Kind: model.KindFirewall, Format: "sflow", SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: 40000, Proto: "udp",
			Action: model.ActionAllow, SentBytes: bytes, Packets: bytes / 500, Sampling: 2048, Time: at}, nil)
	}
	// NTP 反射：200 个反射器 30 秒内共 10 GB
	for i := range 200 {
		flow(fmt.Sprintf("198.51.%d.%d", 100+i/100, i%100+1), "10.0.0.10", 123, 50<<20, t0.Add(time.Duration(i)*150*time.Millisecond))
	}
	late := b.TakeLate()
	if len(late) != 1 {
		t.Fatalf("应按目的地址告警一次: %+v", late)
	}
	ev, h := late[0].Ev, late[0].Hits[0]
	if !ev.NoSource || ev.SrcIP != "" || ev.DstIP != "10.0.0.10" || !ev.Replay || ev.Bps < 1e9 || h.RuleID != "bhv-ddos-bw" || h.Category != CatFlood ||
		!strings.Contains(h.Evidence, "NTP 反射") || !strings.Contains(h.Evidence, "个来源") || !strings.Contains(h.Evidence, "采样率 1:2048") {
		t.Fatalf("带宽型 DDoS: %+v %+v", ev, h)
	}
	// 攻击持续：不重复告警
	for i := range 100 {
		flow(fmt.Sprintf("198.51.102.%d", i+1), "10.0.0.10", 123, 100<<20, t0.Add(time.Minute+time.Duration(i)*100*time.Millisecond))
	}
	if late := b.TakeLate(); len(late) != 0 {
		t.Fatalf("持续攻击不重复告警: %+v", late)
	}
	if c := b.DDoSContext("10.0.0.10", t0.Add(2*time.Minute)); !strings.Contains(c, "入向流量突增") {
		t.Fatalf("设备洪泛判定的印证: %q", c)
	}
	// 平时每分钟约 20 GB 的地址（大文件上传服务）：2.5 Gbps 不是突增
	for m := range 15 {
		for i := range 20 {
			flow(fmt.Sprintf("203.0.113.%d", i+1), "10.0.0.20", 50000, 1<<30, t0.Add(time.Duration(m)*time.Minute+time.Duration(i)*time.Second))
		}
	}
	if late := b.TakeLate(); len(late) != 0 && late[0].Ev.Time.After(t0.Add(10*time.Minute)) {
		t.Fatalf("基线成熟后按自己的平时水平判断: %+v", late[len(late)-1].Hits)
	}
	// 出站与内网来源不计入
	for i := range 50 {
		b.ObserveHits(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.30", DstIP: "10.0.0.40", DstPort: 445, Proto: "tcp", Action: model.ActionAllow,
			SentBytes: 1 << 30, Time: t0.Add(time.Duration(i) * time.Second)}, nil)
	}
	if late := b.TakeLate(); len(late) != 0 {
		t.Fatalf("内网之间的流量不计入: %+v", late)
	}
}

// 账号盗用：不可能的旅行、首次从新的国家登录、多地并发登录；云服务器 / 代理出口与内网来源不参与判断。
func TestAccountTakeover(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	places := map[string]*geo.Info{
		"1.1.1.1":  {Country: "中国", City: "北京市", Lat: 39.9, Lon: 116.4},
		"1.1.1.2":  {Country: "中国", City: "北京市", Lat: 39.9, Lon: 116.4},
		"2.2.2.2":  {Country: "美国", City: "洛杉矶", Lat: 34.05, Lon: -118.24},
		"3.3.3.3":  {Country: "中国", City: "上海市", Lat: 31.23, Lon: 121.47},
		"4.4.4.4":  {Country: "中国", City: "广州市", Lat: 23.13, Lon: 113.26},
		"5.5.5.5":  {Country: "中国", City: "深圳市", Lat: 22.54, Lon: 114.06},
		"6.6.6.6":  {Country: "新加坡", City: "新加坡", Lat: 1.35, Lon: 103.8, Hosting: true},
		"7.7.7.7":  {Country: "日本", City: "东京", Lat: 35.68, Lon: 139.69},
		"8.8.8.10": {Country: "中国", City: "成都市", Lat: 30.57, Lon: 104.07},
	}
	b.Geo = func(ip string) *geo.Info { return places[ip] }
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	login := func(user, ip string, at time.Time) []model.Hit {
		return b.ObserveHits(&model.Event{Kind: model.KindAuth, Format: "app_login", Service: "应用登录（oa）", SrcIP: ip, User: user, Action: model.ActionAllow, Time: at}, nil)
	}
	// 每天从北京登录，持续 8 天
	for d := range 8 {
		if h := ruleHits(login("zhangsan", "1.1.1.1", t0.Add(time.Duration(d)*24*time.Hour)), "auth-new-country"); len(h) != 0 {
			t.Fatalf("同一地点登录不告警: %+v", h)
		}
	}
	at := t0.Add(8 * 24 * time.Hour)
	login("zhangsan", "1.1.1.1", at)
	// 1 小时后从洛杉矶登录：不可能的旅行 + 新国家
	hits := login("zhangsan", "2.2.2.2", at.Add(time.Hour))
	tr, nc := ruleHits(hits, "auth-impossible-travel"), ruleHits(hits, "auth-new-country")
	if len(tr) != 1 || tr[0].Category != CatAccountTakeover || tr[0].Severity != model.SevHigh || !strings.Contains(tr[0].Evidence, "洛杉矶") ||
		len(nc) != 1 || !strings.Contains(nc[0].Evidence, "此前 9 次登录均来自 中国") {
		t.Fatalf("不可能的旅行 / 新国家: %+v", hits)
	}
	// 北京 → 上海 5 小时（高铁可以到达）：不告警
	login("lisi", "1.1.1.2", t0)
	if h := ruleHits(login("lisi", "3.3.3.3", t0.Add(5*time.Hour)), "auth-impossible-travel"); len(h) != 0 {
		t.Fatalf("可以到达的距离不告警: %+v", h)
	}
	// 云服务器出口不参与判断
	if h := login("lisi", "6.6.6.6", t0.Add(5*time.Hour+time.Minute)); len(h) != 0 {
		t.Fatalf("托管地址不参与: %+v", h)
	}
	// 10 分钟内从 3 个城市登录（广州、深圳距离较近，不构成不可能的旅行）
	login("wangwu", "4.4.4.4", t0)
	login("wangwu", "5.5.5.5", t0.Add(3*time.Minute))
	if h := ruleHits(login("wangwu", "8.8.8.10", t0.Add(6*time.Minute)), "auth-concurrent"); len(h) != 1 || !strings.Contains(h[0].Evidence, "3 个不同城市") {
		t.Fatalf("多地并发登录: %+v", h)
	}
	// 失败的登录、内网来源不参与
	if h := b.ObserveHits(&model.Event{Kind: model.KindAuth, Service: "SSH", SrcIP: "7.7.7.7", User: "zhangsan", Action: model.ActionDeny, Time: at.Add(2 * time.Hour)}, nil); len(ruleHits(h, "auth-impossible-travel")) != 0 {
		t.Fatalf("失败的登录不参与: %+v", h)
	}
}

// 长连接结束时一次性报告的字节数按持续时间折算：持续两小时的备份会话不当作一次外传突发，
// 持续一小时的大流量会话不当作带宽型 DDoS；同样的量在几分钟内发生时照常告警。
func TestDurationShare(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	out := func(src string, bytes int64, dur float64, at time.Time) []model.Hit {
		return ruleHits(b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: "203.0.113.50", DstPort: 443, Proto: "tcp", Action: model.ActionAllow,
			Outbound: true, SentBytes: bytes, Duration: dur, Time: at}), "bhv-exfil")
	}
	if h := out("10.0.0.41", 30<<30, 7200, t0); len(h) != 0 {
		t.Fatalf("持续两小时的 30 GB 会话按每 10 分钟约 2.5 GB 折算，不告警: %+v", h)
	}
	if h := out("10.0.0.42", 5<<30, 300, t0); len(h) != 1 {
		t.Fatalf("5 分钟内外发 5 GB 应告警: %+v", h)
	}
	in := func(src, dst string, bytes int64, dur float64, at time.Time) {
		b.ObserveHits(&model.Event{Kind: model.KindFirewall, SrcIP: src, SrcPort: 50000, DstIP: dst, DstPort: 873, Proto: "tcp", Action: model.ActionAllow,
			SentBytes: bytes, Packets: bytes / 1400, Duration: dur, Time: at}, nil)
	}
	in("198.51.100.5", "10.0.0.70", 50<<30, 3600, t0)
	if late := b.TakeLate(); len(late) != 0 {
		t.Fatalf("持续一小时的 50 GB 同步会话不是带宽型 DDoS: %+v", late[0].Hits)
	}
	in("198.51.100.6", "10.0.0.71", 50<<30, 30, t0)
	if late := b.TakeLate(); len(late) != 1 {
		t.Fatal("30 秒内 50 GB 应判为带宽型 DDoS")
	}
}

// 伪造的超大计数：累计封顶而不是溢出成负数，检测照常生效。
func TestHugeCountsSaturate(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var exfil []model.Hit
	for i := range 3 {
		exfil = append(exfil, ruleHits(b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.43", DstIP: "203.0.113.50", DstPort: 443, Proto: "tcp",
			Action: model.ActionAllow, Outbound: true, SentBytes: math.MaxInt64, Time: t0.Add(time.Duration(i) * time.Second)}), "bhv-exfil")...)
	}
	if len(exfil) != 1 || strings.Contains(exfil[0].Evidence, "-") {
		t.Fatalf("超大外发量: %+v", exfil)
	}
	for i := range 3 {
		b.ObserveHits(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("198.51.100.%d", i+1), DstIP: "10.0.0.72", DstPort: 80, Proto: "tcp",
			Action: model.ActionAllow, SentBytes: math.MaxInt64, Packets: math.MaxInt64, Time: t0.Add(time.Duration(i) * time.Second)}, nil)
	}
	if late := b.TakeLate(); len(late) != 1 || late[0].Ev.Bps <= 0 {
		t.Fatalf("超大入向流量: %+v", late)
	}
}
