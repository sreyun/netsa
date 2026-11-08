package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

func countRule(hits []model.Hit, id string) (n int, sev model.Severity) {
	for _, h := range hits {
		if h.RuleID == id {
			n++
			sev = max(sev, h.Severity)
		}
	}
	return
}

// 分布式 CC：站点请求量比平时暴增，且大量来源集中刷同一路径。访问高峰（各种路径）、App 轮询（每个来源频率低）、
// 没有基线时量不够大，都不告警。
func TestDistributedCC(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	t0 := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	web := func(host, ip, uri string, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: host, Method: "GET", URI: uri, Status: 200, Time: at})
	}
	// minute 分钟内的正常访问：50 个来源浏览 20 个不同页面，共 200 次
	normal := func(host string, minute int) {
		for i := range 200 {
			web(host, fmt.Sprintf("45.1.%d.%d", i%50/250, i%50+1), fmt.Sprintf("/page/%d", i%20), t0.Add(time.Duration(minute)*time.Minute+time.Duration(i)*100*time.Millisecond))
		}
	}
	for m := range 15 {
		normal("shop.example.com", m)
		normal("crowd.example.com", m)
		normal("app.example.com", m)
	}
	at := func(m, i int) time.Time {
		return t0.Add(time.Duration(m)*time.Minute + time.Duration(i)*5*time.Millisecond)
	}

	// 攻击：60 个来源各请求 /api/search 60 次（单个来源都低于 cc_requests）
	var hits []model.Hit
	i := 0
	for r := range 60 {
		for s := range 60 {
			hits = append(hits, web("shop.example.com", fmt.Sprintf("61.2.3.%d", s+1), fmt.Sprintf("/api/search?q=%d", r*60+s), at(15, i))...)
			i++
		}
	}
	n, sev := countRule(hits, "bhv-distcc")
	t.Logf("分布式 CC 告警来源数 %d", n)
	if n < 20 || sev != model.SevHigh {
		t.Fatalf("分布式 CC 应告警参与的来源: %d %v", n, sev)
	}
	if n, _ := countRule(hits, "bhv-cc"); n != 0 {
		t.Fatalf("单个来源没有达到 cc_requests，不应触发单源 CC: %d", n)
	}
	for _, h := range hits {
		if h.RuleID == "bhv-distcc" && h.Evidence == "" {
			t.Fatal("证据不能为空")
		}
	}
	// 正常访客在攻击期间的访问不告警
	if n, _ := countRule(web("shop.example.com", "45.1.0.1", "/page/1", at(15, i+1)), "bhv-distcc"); n != 0 {
		t.Fatal("攻击期间正常访客不应告警")
	}

	// 访问高峰：500 个来源各访问 10 个不同页面（5000 次），不集中在同一路径
	hits = nil
	for k := range 5000 {
		hits = append(hits, web("crowd.example.com", fmt.Sprintf("62.%d.%d.%d", k%500/250, k%500%250, 1), fmt.Sprintf("/item/%d", k%37), at(15, k))...)
	}
	if n, _ := countRule(hits, "bhv-distcc"); n != 0 {
		t.Fatalf("访问高峰不是分布式 CC: %d", n)
	}

	// App 轮询：300 个来源每分钟各请求 /api/poll 12 次（3600 次），每个来源频率低
	hits = nil
	for k := range 3600 {
		hits = append(hits, web("app.example.com", fmt.Sprintf("63.1.%d.%d", k%300/250, k%300%250+1), "/api/poll", at(15, k))...)
	}
	if n, _ := countRule(hits, "bhv-distcc"); n != 0 {
		t.Fatalf("低频轮询不是分布式 CC: %d", n)
	}

	// 没有基线的新站点：只在量达到 2 倍阈值后判断
	hits = nil
	for k := range 4000 {
		hits = append(hits, web("new.example.com", fmt.Sprintf("64.1.1.%d", k%50+1), "/api/x", at(15, k))...)
	}
	if n, _ := countRule(hits, "bhv-distcc"); n != 0 {
		t.Fatalf("没有基线时 4000 次不应告警: %d", n)
	}
	for k := 4000; k < 7000; k++ {
		hits = append(hits, web("new.example.com", fmt.Sprintf("64.1.1.%d", k%50+1), "/api/x", at(15, k))...)
	}
	if n, _ := countRule(hits, "bhv-distcc"); n == 0 {
		t.Fatal("没有基线时达到 2 倍阈值应告警")
	}
}

// 多源 DDoS：同一目的地址与端口的事件量比平时暴增，且来自大量来源。繁忙服务的正常增长、没有基线、单一来源都不按 DDoS 告警。
func TestMultiSourceDDoS(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	t0 := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	fw := func(src, dst string, port int, reply model.Reply, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp",
			Action: model.ActionAllow, Reply: reply, Time: at})
	}
	win := th.FwWindow
	at := func(w, i int) time.Time { return t0.Add(time.Duration(w)*win + time.Duration(i)*time.Millisecond) }
	src := func(i int) string { return fmt.Sprintf("45.%d.%d.%d", 10+i/62500, i/250%250, i%250+1) }
	// 繁忙的对外服务：每个窗口 1000 条、300 个来源
	for w := range 12 {
		for i := range 1000 {
			fw(src(i%300), "43.242.97.38", 443, model.ReplyYes, at(w, i))
			fw(src(i%300), "43.242.97.39", 443, model.ReplyYes, at(w, i))
		}
	}
	// 攻击：3 万条来自 3000 个来源、大多没有应答
	var hits []model.Hit
	for i := range 30000 {
		hits = append(hits, fw(src(1000+i%3000), "43.242.97.38", 443, model.ReplyNone, at(12, i))...)
	}
	n, sev := countRule(hits, "bhv-ddos")
	t.Logf("DDoS 告警来源数 %d，等级 %v", n, sev)
	if n == 0 || n > maxDDoSFlags || sev != model.SevHigh {
		t.Fatalf("多源 DDoS 应告警（有上限）: %d %v", n, sev)
	}
	// 同一服务业务量翻 4 倍：低于 ddos_events，不告警
	hits = nil
	for i := range 4000 {
		hits = append(hits, fw(src(i%800), "43.242.97.39", 443, model.ReplyYes, at(12, i))...)
	}
	if n, _ := countRule(hits, "bhv-ddos"); n != 0 {
		t.Fatalf("业务量正常增长不是 DDoS: %d", n)
	}
	// 没有基线的服务：2.5 万条、2000 个来源也不判断（繁忙服务本来就有大量来源）
	hits = nil
	for i := range 25000 {
		hits = append(hits, fw(src(i%2000), "43.242.97.40", 443, model.ReplyYes, at(12, i))...)
	}
	if n, _ := countRule(hits, "bhv-ddos"); n != 0 {
		t.Fatalf("没有基线时不应按 DDoS 告警: %d", n)
	}
	// 内网来源不参与
	if n, _ := countRule(fw("10.0.0.5", "43.242.97.38", 443, model.ReplyNone, at(12, 30001)), "bhv-ddos"); n != 0 {
		t.Fatal("内网来源不应按 DDoS 告警")
	}
}

// 单来源高频请求：外部来源高危；内网来源（未还原真实地址的反向代理、监控、内部扫描器）只是弱证据，低危提示。
func TestCCInternalSource(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	t0 := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	burst := func(ip string) model.Hit {
		for i := range th.CCRequests + 5 {
			for _, h := range b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "GET", URI: fmt.Sprintf("/api/x?i=%d", i),
				Status: 200, Time: t0.Add(time.Duration(i) * 20 * time.Millisecond)}) {
				if h.RuleID == "bhv-cc" {
					return h
				}
			}
		}
		return model.Hit{}
	}
	if h := burst("61.2.3.4"); h.RuleID == "" || h.Severity != model.SevHigh || h.Weak {
		t.Fatalf("外部来源的高频请求应为高危: %+v", h)
	}
	if h := burst("10.34.45.31"); h.RuleID == "" || h.Severity != model.SevLow || !h.Weak {
		t.Fatalf("内网来源的高频请求应为低危的弱证据: %+v", h)
	}
}

// 线上实例：一台安卓手机上的 App（WebView 不缓存）一分钟内反复打开 H5 页面，695 次请求、196 个不同路径、
// 八成以上是脚本与图片，全部 200。这是页面资源加载，不是 CC 攻击；反复请求同一个静态文件的仍按 CC 告警。
func TestCCPageLoad(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	t0 := time.Date(2026, 11, 7, 9, 19, 0, 0, time.UTC)
	burst := func(ip string, uri func(i int) string) model.Hit {
		for i := range th.CCRequests + 5 {
			for _, h := range b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "GET", URI: uri(i),
				Status: 200, Bytes: 4096, Time: t0.Add(time.Duration(i) * 80 * time.Millisecond)}) {
				if h.RuleID == "bhv-cc" {
					return h
				}
			}
		}
		return model.Hit{}
	}
	page := func(i int) string {
		switch {
		case i%8 == 0:
			return fmt.Sprintf("/portal/api/tasks?page=%d", i)
		case i%8 == 1:
			return "/platform-h5/favicon.png"
		}
		return fmt.Sprintf("/platform-h5/static/js/chunk-%d.js", i%60)
	}
	if h := burst("14.31.64.16", page); h.RuleID == "" || h.Severity != model.SevLow || !h.Weak || !strings.Contains(h.Evidence, "页面资源加载") {
		t.Fatalf("页面资源加载应为低危的弱证据: %+v", h)
	}
	if h := burst("14.31.64.17", func(int) string { return "/platform-h5/static/js/index.js" }); h.Severity != model.SevHigh || h.Weak {
		t.Fatalf("反复请求同一个文件仍是 CC: %+v", h)
	}
	if h := burst("14.31.64.18", func(i int) string { return fmt.Sprintf("/search?q=%d", i) }); h.Severity != model.SevHigh || h.Weak {
		t.Fatalf("变换参数请求同一接口仍是 CC: %+v", h)
	}
}
