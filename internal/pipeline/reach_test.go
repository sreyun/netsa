package pipeline

import (
	"strconv"
	"strings"
	"testing"

	"netsa/internal/config"
	"netsa/internal/exposure"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/store"
)

// 用户环境中的华为日志：外网探测打到未做映射的公网端口，被出站策略「允许本地上外网」放行（untrust → untrust）
const huaweiUnmapped = `<190>Oct 29 2026 00:49:59 USG6300 %%01POLICY/6/POLICYPERMIT(l):vsys=public, protocol=6, source-ip=195.184.76.97, source-port=11062, destination-ip=43.242.97.35, destination-port=23, time=2026/10/29 08:49:59, source-zone=untrust, destination-zone=untrust, application-name=, rule-name=允许本地上外网.`

func parseLine(t *testing.T, line string) *model.Event {
	t.Helper()
	p, err := parser.NewAuto("auto", "")
	if err != nil {
		t.Fatal(err)
	}
	ev, ok := p.Parse(line)
	if !ok {
		t.Fatalf("未能解析: %s", line)
	}
	return ev
}

func TestReachGateHuaweiUnmapped(t *testing.T) {
	exp, _ := exposure.Load(config.ExposureConfig{}) // 未登记任何映射、enabled 为 false：只靠会话证据
	evs := []*model.Event{parseLine(t, huaweiUnmapped)}
	for i := 0; i < 25; i++ { // 足够多的放行也不应被当成「疑似对外映射」
		ev := parseLine(t, strings.Replace(huaweiUnmapped, "195.184.76.97", "195.184.76."+strconv.Itoa(100+i), 1))
		evs = append(evs, ev)
	}
	st, _ := runOnce(t, exp, evs)
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) != 0 {
		t.Fatalf("未到达服务的端口探测不应告警: %s", got[0].Evidence)
	}
	if p := st.Profile("195.184.76.97"); p == nil || p.Attacks != 0 || len(p.Tags) == 0 {
		t.Fatalf("应仅打标签: %+v", p)
	}
	if exp.Unreached() != 26 {
		t.Fatalf("过滤次数: %d", exp.Unreached())
	}
	pol := exp.Policies()
	if len(pol) != 1 || pol[0].Policy != "允许本地上外网" || pol[0].Permits != 26 || pol[0].SrcZone != "untrust" || pol[0].DstZone != "untrust" {
		t.Fatalf("可疑放行策略: %+v", pol)
	}
	if c := exp.Candidates(); len(c) != 0 {
		t.Fatalf("未到达服务的放行不应生成候选映射: %+v", c)
	}
}

func TestReachGateKeepsReachedProbe(t *testing.T) {
	for _, c := range []struct {
		zone, evidence string
	}{
		{"dmz", "已转发至 dmz 安全域"},
	} {
		exp, _ := exposure.Load(config.ExposureConfig{})
		ev := parseLine(t, strings.Replace(huaweiUnmapped, "destination-zone=untrust", "destination-zone="+c.zone, 1))
		st, _ := runOnce(t, exp, []*model.Event{ev})
		got := st.Alerts(store.AlertQuery{Limit: 10})
		if len(got) != 1 || got[0].Severity != model.SevMedium || !strings.Contains(got[0].Evidence, c.evidence) {
			t.Fatalf("%s：到达服务的放行探测应保持中危告警并注明证据: %+v", c.zone, got)
		}
	}
	// 有会话证据表明到达了服务时，即使手工清单未登记也不过滤
	exp, _ := exposure.Load(config.ExposureConfig{Enabled: true})
	st, _ := runOnce(t, exp, []*model.Event{parseLine(t, strings.Replace(huaweiUnmapped, "destination-zone=untrust", "destination-zone=dmz", 1))})
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) != 1 || exp.Muted() != 0 {
		t.Fatalf("会话证据优先于手工清单: %d 条告警，清单过滤 %d 次", len(got), exp.Muted())
	}
	// 关闭会话证据研判：恢复原有行为
	off := false
	exp, _ = exposure.Load(config.ExposureConfig{ReachCheck: &off})
	st, _ = runOnce(t, exp, []*model.Event{parseLine(t, huaweiUnmapped)})
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) != 1 {
		t.Fatalf("reach_check: false 时应按原有规则告警: %d", len(got))
	}
}

// 证据表明到达了服务的端口自动识别为对外服务；同一端口后续没有证据的日志在开启清单过滤时不被误降级。
func TestReachLearnsPublishedService(t *testing.T) {
	exp, _ := exposure.Load(config.ExposureConfig{Enabled: true})
	dmz := parseLine(t, strings.Replace(huaweiUnmapped, "destination-zone=untrust", "destination-zone=dmz", 1))
	noEvidence := &model.Event{Time: dmz.Time, Kind: model.KindFirewall, SrcIP: "203.0.113.50", DstIP: "43.242.97.35", DstPort: 23,
		Proto: "tcp", Action: model.ActionAllow}
	st, _ := runOnce(t, exp, []*model.Event{dmz, noEvidence})
	if exp.LearnedCount() != 1 || exp.Muted() != 0 {
		t.Fatalf("应自动识别对外服务且不再按清单降级: 识别 %d，降级 %d", exp.LearnedCount(), exp.Muted())
	}
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) != 2 {
		t.Fatalf("两条探测都应告警: %d", len(got))
	}
}

// 未配置可信代理时自动识别内网反向代理：之后按 X-Forwarded-For 还原真实攻击源；公网节点只提示、不自动信任。
func TestRealIPAutoLearn(t *testing.T) {
	r := NewRealIP(config.RealIPConfig{})
	ev := func(peer string, i int) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: peer, XFF: "203.0.113." + strconv.Itoa(i%250+1)}
	}
	var last *model.Event
	for i := 0; i < 40; i++ {
		last = ev("10.0.0.2", i)
		r.Apply(last)
	}
	if last.SrcIP != "203.0.113.40" || last.PeerIP != "10.0.0.2" {
		t.Fatalf("内网负载均衡应被自动信任: src=%s peer=%s", last.SrcIP, last.PeerIP)
	}
	for i := 0; i < 40; i++ {
		last = ev("198.51.100.200", i)
		r.Apply(last)
	}
	if last.SrcIP != "198.51.100.200" {
		t.Fatal("公网节点不应被自动信任（请求头可伪造）")
	}
	// 只携带同一个客户端地址的内网主机（如单个用户经本地代理）不是负载均衡
	for i := 0; i < 40; i++ {
		last = &model.Event{Kind: model.KindWeb, SrcIP: "10.0.0.9", XFF: "203.0.113.7"}
		r.Apply(last)
	}
	if last.SrcIP != "10.0.0.9" {
		t.Fatal("客户端不分散时不应判定为反向代理")
	}
	got := map[string]bool{}
	for _, p := range r.Proxies() {
		got[p.IP] = p.Trusted
	}
	if trusted, ok := got["10.0.0.2"]; !ok || !trusted || got["198.51.100.200"] || len(got) != 2 {
		t.Fatalf("识别结果: %+v", r.Proxies())
	}
	off := false
	r2 := NewRealIP(config.RealIPConfig{AutoLearn: &off})
	for i := 0; i < 40; i++ {
		last = ev("10.0.0.2", i)
		r2.Apply(last)
	}
	if last.SrcIP != "10.0.0.2" {
		t.Fatal("关闭自动识别后不应改写来源")
	}
}

// 打到防火墙自身（local 安全域）：非设备服务端口的探测未到达任何服务，只打标签；管理服务端口的单次探测也只打标签，
// 但「防火墙管理服务对公网放行」作为暴露面风险记录；自定义的设备服务端口（exposure.device_ports）同样识别。
func TestReachGateDeviceLocal(t *testing.T) {
	local := func(port int, src string) *model.Event {
		line := strings.Replace(huaweiUnmapped, "destination-zone=untrust", "destination-zone=local", 1)
		line = strings.Replace(line, "destination-port=23,", "destination-port="+strconv.Itoa(port)+",", 1)
		return parseLine(t, strings.Replace(line, "195.184.76.97", src, 1))
	}
	exp, _ := exposure.Load(config.ExposureConfig{DevicePorts: []int{6443}})
	st, _ := runOnce(t, exp, []*model.Event{local(37215, "79.124.58.130"), local(2323, "205.210.31.58"), local(5432, "85.11.167.7"),
		local(23, "79.124.58.131"), local(6443, "79.124.58.132")})
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) != 0 {
		t.Fatalf("打到防火墙自身的单次探测不应告警: %s", got[0].Evidence)
	}
	rep := st.Surface()
	var titles []string
	for _, f := range rep.Findings {
		titles = append(titles, f.Title)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Title != "防火墙管理服务对公网放行: Telnet" || rep.Findings[0].Severity != model.SevHigh {
		t.Fatalf("应只记录 Telnet 管理服务暴露: %v", titles)
	}
	for _, s := range rep.Services {
		if s.Port == 37215 || s.Port == 2323 || s.Port == 5432 {
			t.Fatalf("非设备服务端口不应登记为对外服务: %+v", s)
		}
	}
	if p := st.Profile("79.124.58.130"); p == nil || p.Attacks != 0 || len(p.Tags) == 0 {
		t.Fatalf("应仅打标签: %+v", p)
	}
	pol := exp.Policies()
	if len(pol) != 1 || pol[0].DstZone != "local" || pol[0].Permits != 3 {
		t.Fatalf("可疑放行策略（local 安全域）: %+v", pol)
	}
}
