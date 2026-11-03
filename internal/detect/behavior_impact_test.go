package detect

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

type impactRun struct {
	t     *testing.T
	b     *Behavior
	now   time.Time
	fired map[string][]model.Hit // 来源 → 触发的行为告警
}

func newImpactRun(t *testing.T) *impactRun {
	return &impactRun{t: t, b: NewBehavior(config.Default().Detect.Thresholds), now: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC), fired: map[string][]model.Hit{}}
}

// req 模拟一次请求，at 为相对起点的秒数。
func (r *impactRun) req(at int, ip, method, uri string, status int, ruleHits ...model.Hit) {
	ev := &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "shop.example.com", Method: method, URI: uri, Status: status,
		Time: r.now.Add(time.Duration(at) * time.Second)}
	for _, h := range r.b.ObserveHits(ev, ruleHits) {
		if h.RuleID == "bhv-timeout" || h.RuleID == "bhv-destroy" {
			r.fired[ip] = append(r.fired[ip], h)
		}
	}
}

func (r *impactRun) count(ip, rule string) int {
	n := 0
	for _, h := range r.fired[ip] {
		if h.RuleID == rule {
			n++
		}
	}
	return n
}

// 正常访客：每 10 秒访问一次业务页面
func (r *impactRun) visitors(from, to, status int) {
	for at := from; at < to; at += 10 {
		for i := 1; i <= 5; i++ {
			r.req(at+i, "198.51.100."+strconv.Itoa(i), "GET", "/api/orders", status)
		}
	}
}

// 低速率的慢请求攻击：每 30 秒一次，持续 9 分钟。每分钟 2 次，按 1 分钟窗口统计发现不了。
func TestSlowRequestAttack(t *testing.T) {
	r := newImpactRun(t)
	r.visitors(0, 600, 200)
	for i := 0; i < 20; i++ {
		r.req(i*27, "203.0.113.9", "GET", "/api/report/export?range=all", 504)
	}
	if r.count("203.0.113.9", "bhv-timeout") != 1 {
		t.Fatalf("低速率超时攻击应告警一次: %+v", r.fired)
	}
	h := r.fired["203.0.113.9"][0]
	if h.Category != CatCC || h.Severity != model.SevMedium || !strings.Contains(h.Evidence, "/api/report/export") || !strings.Contains(h.Evidence, "其他访客超时比例 0%") {
		t.Fatalf("告警内容: %+v", h)
	}
	for i := 1; i <= 5; i++ {
		if len(r.fired["198.51.100."+strconv.Itoa(i)]) != 0 {
			t.Fatal("正常访客不应告警")
		}
	}
}

// 请求耗时（nginx $request_time）超过阈值也算超时，即使返回 200。
func TestSlowRequestByDuration(t *testing.T) {
	r := newImpactRun(t)
	r.visitors(0, 300, 200)
	for i := 0; i < 20; i++ {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", Host: "shop.example.com", Method: "GET", URI: "/search?q=" + strconv.Itoa(i),
			Status: 200, ReqTime: 15.2, Time: r.now.Add(time.Duration(i*10) * time.Second)}
		for _, h := range r.b.ObserveHits(ev, nil) {
			r.fired[ev.SrcIP] = append(r.fired[ev.SrcIP], h)
		}
	}
	if r.count("203.0.113.9", "bhv-timeout") != 1 {
		t.Fatalf("耗时超过阈值应计为超时: %+v", r.fired)
	}
}

// 不能误报的场景。
func TestSlowRequestFalsePositives(t *testing.T) {
	// 1. 后端整体故障：所有访客都超时
	r := newImpactRun(t)
	r.visitors(0, 600, 504)
	for i := 0; i < 30; i++ {
		r.req(i*20, "203.0.113.9", "GET", "/api/orders", 504)
	}
	if n := len(r.fired); n != 0 {
		t.Fatalf("后端整体故障不应判定为攻击: %+v", r.fired)
	}
	// 2. 请求量很大的正常客户端，偶尔超时
	r = newImpactRun(t)
	r.visitors(0, 600, 200)
	for i := 0; i < 1000; i++ {
		st := 200
		if i%40 == 0 {
			st = 504
		}
		r.req(i/2, "198.51.100.200", "GET", "/api/items?page="+strconv.Itoa(i), st)
	}
	if len(r.fired) != 0 {
		t.Fatalf("偶尔超时的大客户不应告警: %+v", r.fired)
	}
	// 3. 超时分散在多个窗口
	r = newImpactRun(t)
	for i := 0; i < 30; i++ {
		r.req(i*60, "203.0.113.9", "GET", "/a", 504)
	}
	if len(r.fired) != 0 {
		t.Fatalf("每个窗口内都达不到阈值时不应告警: %+v", r.fired)
	}
}

// 超时攻击之后，业务路径对多个访客失效：在攻击者下一次请求时告警为破坏性攻击。
func TestDestroyAfterSlowAttack(t *testing.T) {
	r := newImpactRun(t)
	r.visitors(0, 300, 200) // 业务路径正常
	for i := 0; i < 20; i++ {
		r.req(200+i*5, "203.0.113.9", "GET", "/api/report/export", 504)
	}
	r.visitors(320, 400, 503) // 之后对所有访客失效
	if r.count("203.0.113.9", "bhv-destroy") != 0 {
		t.Fatal("攻击者再次出现前不应告警（告警必须落在攻击者自己的请求上）")
	}
	r.req(420, "203.0.113.9", "GET", "/api/orders", 503)
	if r.count("203.0.113.9", "bhv-destroy") != 1 {
		t.Fatalf("业务失效后攻击者再次出现应告警: %+v", r.fired)
	}
	h := r.fired["203.0.113.9"][len(r.fired["203.0.113.9"])-1]
	if h.Severity != model.SevHigh || h.Category != CatDestroy || h.Result != model.ResultSuccess || !strings.Contains(h.Evidence, "/api/orders") || !strings.Contains(h.Evidence, "503×") {
		t.Fatalf("告警内容: %+v", h)
	}
	r.req(430, "203.0.113.9", "GET", "/api/orders", 503)
	if r.count("203.0.113.9", "bhv-destroy") != 1 {
		t.Fatal("同一来源只告警一次")
	}
	for i := 1; i <= 5; i++ {
		if len(r.fired["198.51.100."+strconv.Itoa(i)]) != 0 {
			t.Fatal("收到错误的正常访客不应告警")
		}
	}
}

// 攻击之后删除资源成功，随后该资源对其他访客返回 404。
func TestDestroyAfterAttackWrite(t *testing.T) {
	attack := model.Hit{RuleID: "sqli-union", Severity: model.SevHigh}
	run := func(withAttack bool) int {
		r := newImpactRun(t)
		for at := 0; at < 120; at += 10 {
			for i := 1; i <= 4; i++ {
				r.req(at+i, "198.51.100."+strconv.Itoa(i), "GET", "/files/contract-2026.pdf", 200)
			}
		}
		if withAttack {
			r.req(130, "203.0.113.9", "GET", "/admin/files?id=1%27union%20select", 200, attack)
		}
		r.req(140, "203.0.113.9", "DELETE", "/files/contract-2026.pdf", 204)
		for i := 1; i <= 4; i++ {
			r.req(150+i, "198.51.100."+strconv.Itoa(i), "GET", "/files/contract-2026.pdf", 404)
		}
		r.req(200, "203.0.113.9", "GET", "/files/contract-2026.pdf", 404)
		return r.count("203.0.113.9", "bhv-destroy")
	}
	if run(true) != 1 {
		t.Fatal("攻击后删除业务资源应告警")
	}
	if run(false) != 0 {
		t.Fatal("没有攻击命中的删除（如管理员下线内容）不应告警")
	}
}

// 路径失效但没有可疑来源（发布、下线），或只有可疑来源自己收到 404（被拦截）：都不告警。
func TestDestroyFalsePositives(t *testing.T) {
	r := newImpactRun(t)
	r.visitors(0, 200, 200)
	r.visitors(200, 300, 404)
	if len(r.fired) != 0 {
		t.Fatalf("没有可疑来源的路径失效不应告警: %+v", r.fired)
	}

	r = newImpactRun(t)
	r.visitors(0, 600, 200)
	for i := 0; i < 20; i++ {
		r.req(i*5, "203.0.113.9", "GET", "/api/report/export", 504)
	}
	for i := 0; i < 30; i++ { // 攻击者被拦截：只有它自己收到 404
		r.req(120+i*5, "203.0.113.9", "GET", "/api/orders", 404)
	}
	if r.count("203.0.113.9", "bhv-destroy") != 0 {
		t.Fatalf("只有攻击者自己收到 404 不应判定为破坏: %+v", r.fired)
	}

	// 失效的访客凑够了数，但大部分是可疑来源自己（两个攻击者都被拦截，只有一个正常访客碰上错误）
	r = newImpactRun(t)
	r.visitors(0, 600, 200)
	for _, ip := range []string{"203.0.113.9", "203.0.113.10"} {
		for i := 0; i < 20; i++ {
			r.req(i*5, ip, "GET", "/api/report/export", 504)
		}
	}
	r.req(700, "203.0.113.9", "GET", "/api/orders", 404)
	r.req(701, "203.0.113.10", "GET", "/api/orders", 404)
	r.req(702, "198.51.100.1", "GET", "/api/orders", 404)
	r.req(800, "203.0.113.9", "GET", "/", 200)
	if r.count("203.0.113.9", "bhv-destroy") != 0 {
		t.Fatalf("可疑来源以外只有一个访客收到错误，不足以说明业务受损: %+v", r.fired)
	}

	// 从未正常服务过多个访客的路径（扫描器请求不存在的路径）不算业务路径
	r = newImpactRun(t)
	for i := 0; i < 20; i++ {
		r.req(i*5, "203.0.113.9", "GET", "/api/report/export", 504)
	}
	r.req(100, "198.51.100.1", "GET", "/old-page", 200)
	for i := 1; i <= 5; i++ {
		r.req(110+i, "198.51.100."+strconv.Itoa(i), "GET", "/old-page", 404)
	}
	r.req(200, "203.0.113.9", "GET", "/", 200)
	if r.count("203.0.113.9", "bhv-destroy") != 0 {
		t.Fatalf("只对一个访客正常过的路径不算业务路径: %+v", r.fired)
	}
}

// 防火墙安全域标明来源在内部时，即使地址不在私有段（企业把 172.168.0.0/16 用在内网），也按内部来源处理：
// 应用服务器连数据库不是暴力破解；外部来源的同样行为照常告警。
func TestInternalZoneSource(t *testing.T) {
	th := config.Default().Detect.Thresholds
	run := func(src, srcZone string, action string) map[string]bool {
		b := NewBehavior(th)
		e, err := NewEngine("", 1)
		if err != nil {
			t.Fatal(err)
		}
		fired := map[string]bool{}
		now := time.Now()
		for i := 0; i < th.BruteConns+5; i++ {
			ev := &model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: "10.34.44.79", DstPort: 3306, Proto: "tcp", Action: action,
				SrcZone: srcZone, DstZone: "dmz", Time: now.Add(time.Duration(i) * time.Second)}
			for _, h := range append(e.Inspect(ev), b.Observe(ev)...) {
				fired[h.RuleID] = true
			}
		}
		return fired
	}
	if f := run("172.168.100.146", "trust", model.ActionAllow); len(f) != 0 {
		t.Fatalf("内部安全域放行的数据库连接不应告警: %v", f)
	}
	if f := run("10.1.2.3", "", model.ActionAllow); f["bhv-fwbrute"] {
		t.Fatalf("内网地址放行的数据库连接不应判为暴力破解: %v", f)
	}
	if f := run("172.168.100.146", "trust", model.ActionDeny); !f["bhv-fwbrute"] {
		t.Fatalf("内部来源被拒绝的反复连接仍应告警: %v", f)
	}
	if f := run("198.51.100.7", "untrust", model.ActionAllow); !f["bhv-fwbrute"] || !f["fw-riskport"] {
		t.Fatalf("外部来源放行的反复连接应告警: %v", f)
	}
	for zone, want := range map[string]int{"trust": 1, "Trust": 1, "dmz": 1, "inside": 1, "内网": 1, "local": 1, "untrust": -1, "outside": -1, "wan1": -1, "外网": -1, "": 0, "zone-x": 0} {
		if got := zoneSide(zone); got != want {
			t.Errorf("zoneSide(%q) = %d，期望 %d", zone, got, want)
		}
	}
	// 内部安全域访问外部安全域的公网地址是出站连接
	if !IsEgress(&model.Event{Kind: model.KindFirewall, SrcIP: "172.168.100.146", DstIP: "8.8.8.8", SrcZone: "trust", DstZone: "untrust"}) {
		t.Error("内部安全域到外部的连接应判为出站")
	}
}

// 大量站点、路径与来源时内存有上限，过期状态会被清理。
func TestImpactMemoryBounded(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	now := time.Now()
	for i := 0; i < maxHostPaths+500; i++ {
		ip := "198.51." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250)
		b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "a.example.com", Method: "GET", URI: "/p/" + strconv.Itoa(i), Status: 200, Time: now})
		b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "a.example.com", Method: "GET", URI: "/x", Status: 504, Time: now})
	}
	if n := len(b.impact["a.example.com"].paths); n > maxHostPaths {
		t.Fatalf("路径数超过上限: %d", n)
	}
	b.mu.Lock()
	b.prune(now.Add(3 * time.Hour))
	b.mu.Unlock()
	if len(b.impact) != 0 || len(b.slow) != 0 || len(b.attacked) != 0 {
		t.Fatalf("过期状态应清理: impact=%d slow=%d attacked=%d", len(b.impact), len(b.slow), len(b.attacked))
	}
}
