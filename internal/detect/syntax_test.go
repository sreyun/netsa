package detect

import (
	"net/url"
	"strings"
	"testing"

	"netsa/internal/model"
)

// 语法分析：规则命中的注入被确认或否定，规则漏掉的 SQL 注入变形由 libinjection 补上。
func TestSyntaxReview(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	q := func(v string) string { return "/item?page=2&id=" + url.QueryEscape(v) }
	for _, c := range []struct {
		uri, rule string
		syntax    int8
		param     string
	}{
		{q("1' or '1'='1"), "sqli-bool", 1, "id"},
		{q("x'||pg_sleep(5)||'"), "sqli-time", 1, "id"},
		{q("how to use select name from users where"), "sqli-func", -1, "id"},
		// 规则没有写到的变形
		{q("1' div 0 -- "), "sqli-syntax", 1, "id"},
		{q("1)) or ((1"), "sqli-syntax", 1, "id"},
		{q("1' or 2 between 1 and 3 -- -"), "sqli-syntax", 1, "id"},
		{q("admin' or 1#"), "sqli-syntax", 1, "id"},
		{q("1 and ascii(substring(user(),1,1))>64"), "sqli-syntax", 1, "id"},
		// 取值中编码的 & 不会把参数拆错
		{"/s?q=" + url.QueryEscape("a&b' or '1'='1") + "&lang=zh", "sqli-bool", 1, "q"},
		{"/s?q=" + url.QueryEscape("<img src=x onerror=alert(1)>"), "xss-event", 1, "q"},
		{"/s?q=" + url.QueryEscape("see document.cookie docs"), "xss-dom", -1, "q"},
	} {
		h, ok := hitIDs(e.Inspect(web("GET", c.uri, 200, "Mozilla/5.0")))[c.rule]
		if !ok {
			t.Errorf("%s 应命中 %s", c.uri, c.rule)
			continue
		}
		if h.Syntax != c.syntax || h.Param != c.param {
			t.Errorf("%s: syntax=%d param=%q，期望 %d %q", c.uri, h.Syntax, h.Param, c.syntax, c.param)
		}
		if c.syntax > 0 && !strings.Contains(h.Evidence, "语法分析") {
			t.Errorf("%s: 证据应注明语法分析结论：%s", c.uri, h.Evidence)
		}
		if c.rule == "sqli-syntax" && h.Severity != model.SevHigh {
			t.Errorf("%s: 等级 %s", c.uri, h.Severity)
		}
	}
	// 正常取值、普通文字、路径里的符号不做语法分析报警
	for _, uri := range []string{
		"/s?q=" + url.QueryEscape("c'est la vie (2nd ed.)"),
		"/s?q=O'Reilly&sort=name",
		"/api/list?filter=" + url.QueryEscape(`{"a":1,"b":"x"}`),
		"/wiki/Rock_'n'_roll_(music)",
		"/s?q=1+or+true",
	} {
		for _, h := range e.Inspect(web("GET", uri, 200, "Mozilla/5.0")) {
			if h.Category == CatSQLi {
				t.Errorf("%s 不应判为 SQL 注入：%+v", uri, h)
			}
		}
	}
}

func TestSplitParams(t *testing.T) {
	ps := splitParams("/a/b%27c?x=1&y=a%26b%3Dc&&z&=v&k=%2541", true)
	want := []Param{{"", "a"}, {"", "b'c"}, {"x", "1"}, {"y", "a&b=c"}, {"z", ""}, {"", "v"}, {"k", "A"}}
	if len(ps) != len(want) {
		t.Fatalf("%+v", ps)
	}
	for i := range want {
		if ps[i] != want[i] {
			t.Errorf("%d: %+v，期望 %+v", i, ps[i], want[i])
		}
	}
	if paramAt("/a?x=1&q=union select", 12) != "q" || paramAt("/a/union?x=1", 3) != "" {
		t.Error("paramAt")
	}
}

func BenchmarkInspectWebNormal(b *testing.B) {
	e, err := NewEngine("", 1)
	if err != nil {
		b.Fatal(err)
	}
	evs := []*model.Event{
		web("GET", "/api/v1/orders?page=2&size=20&sort=created_at%2Cdesc&status=paid", 200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
		web("GET", "/search?q=%E4%BD%A0%E5%A5%BD+world&lang=zh-CN", 200, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
		web("GET", "/static/js/app.3f2a9c.js", 200, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
		web("POST", "/api/login?redirect=%2Fhome%3Ftab%3D1", 200, "okhttp/4.9.0"),
		web("GET", "/s?q=O%27Reilly+(2nd+ed.)&page=1", 200, "Mozilla/5.0"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Inspect(evs[i%len(evs)])
	}
}
