package learn

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/risk"
)

func profEngine(t *testing.T) *detect.Engine {
	t.Helper()
	e, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func siteEv(ip, host, uri string, status int, at time.Time) *model.Event {
	return &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: host, Method: "GET", URI: uri, Status: status, Bytes: 5000, UA: "Mozilla/5.0", Time: at}
}

// run 按流水线的顺序检测、复核并定级。
func run(l *Learner, e *detect.Engine, ev *model.Event) []model.Hit {
	hits := l.Profile(ev, e.Inspect(ev), true)
	for i := range hits {
		risk.Finalize(&hits[i])
	}
	return hits
}

func hitOf(hits []model.Hit, id string) (model.Hit, bool) {
	for _, h := range hits {
		if h.RuleID == id {
			return h, true
		}
	}
	return model.Hit{}, false
}

// train 用 nets 个网段的访客各访问 per 次，fn 给出第 i 次访问的 URI。
func train(l *Learner, e *detect.Engine, host string, nets, per int, at time.Time, fn func(i int) string) {
	n := 0
	for a := 0; a < nets; a++ {
		for b := 0; b < per; b++ {
			run(l, e, siteEv(fmt.Sprintf("198.%d.%d.%d", 18+a/200, a%200, 1+b%250), host, fn(n), 200, at))
			n++
		}
	}
}

var words = []string{"手机 壳", "how to cook rice", "red shoes size 42", "O'Reilly 编程", "iphone (2024)", "夏季 连衣裙", "best laptop 2026", "c'est la vie"}

// 平时填写普通文字的参数：规则命中、语法分析不构成注入时按普通文字处理；真正的注入不受影响。
func TestProfileFreeTextDowngrade(t *testing.T) {
	l, e := attackLearner(t, ""), profEngine(t)
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	prose := "/search?q=" + url.QueryEscape("how to use select name from users where id")
	// 学习之前：按规则判为高危
	if h, ok := hitOf(run(l, e, siteEv("203.0.113.5", "shop.example", prose, 200, now)), "sqli-func"); !ok || h.Severity != model.SevHigh || h.Weak {
		t.Fatalf("学习之前: %+v", h)
	}
	train(l, e, "shop.example", 25, 10, now, func(i int) string {
		return "/search?q=" + url.QueryEscape(words[i%len(words)]) + "&page=" + fmt.Sprint(i%5)
	})
	h, ok := hitOf(run(l, e, siteEv("203.0.113.5", "shop.example", prose, 200, now)), "sqli-func")
	if !ok || !h.Weak || h.Severity != model.SevLow || h.Result == model.ResultSuccess || !strings.Contains(h.Evidence, "平时就填写普通文字") {
		t.Fatalf("普通文字参数中的弱特征应降为低危: %+v", h)
	}
	// 语法分析确认的注入、其他站点、已确认攻击源：不降级
	for _, c := range []struct{ ip, host, uri string }{
		{"203.0.113.5", "shop.example", "/search?q=" + url.QueryEscape("x' or '1'='1")},
		{"203.0.113.5", "other.example", prose},
	} {
		for _, h := range run(l, e, siteEv(c.ip, c.host, c.uri, 200, now)) {
			if h.Category == detect.CatSQLi && (h.Weak || h.Severity < model.SevHigh) {
				t.Errorf("%s%s 不应降级: %+v", c.host, c.uri, h)
			}
		}
	}
	l.ConfirmSource("203.0.113.66", "evidence", "测试", now)
	if h, _ := hitOf(run(l, e, siteEv("203.0.113.66", "shop.example", prose, 200, now)), "sqli-func"); h.Weak {
		t.Fatal("已确认攻击源的请求不降级")
	}
	if r := l.Report().Profile; r.Mature < 1 || r.FreeText < 1 || r.Weak < 1 {
		t.Fatalf("报告: %+v", r)
	}
}

// 防投毒：同一网段的大量请求不能让参数生效。
func TestProfileNeedsManyNets(t *testing.T) {
	l, e := attackLearner(t, ""), profEngine(t)
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 1000; i++ {
		run(l, e, siteEv(fmt.Sprintf("198.51.100.%d", 1+i%250), "shop.example", "/search?q="+url.QueryEscape(words[i%len(words)]), 200, now))
	}
	prose := "/search?q=" + url.QueryEscape("how to use select name from users where id")
	if h, _ := hitOf(run(l, e, siteEv("203.0.113.5", "shop.example", prose, 200, now)), "sqli-func"); h.Weak {
		t.Fatal("只来自一个网段的访客不足以学到正常取值")
	}
}

// 平时只出现数字的参数出现注入符号：生成低危观察命中，规则命中的证据中注明。
func TestProfileStrictAnomaly(t *testing.T) {
	l, e := attackLearner(t, ""), profEngine(t)
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	train(l, e, "shop.example", 25, 10, now, func(i int) string { return fmt.Sprintf("/item?id=%d&from=home", 1000+i) })
	h, ok := hitOf(run(l, e, siteEv("203.0.113.5", "shop.example", "/item?id=1%27&from=home", 200, now)), "learn-param")
	if !ok || h.Severity != model.SevLow || h.Param != "id" || !strings.Contains(h.Evidence, "只出现数字") {
		t.Fatalf("取值异常: %+v", h)
	}
	for _, uri := range []string{"/item?id=abc&from=home", "/item?id=&from=home", "/item?id=42&from=" + url.QueryEscape("a b")} {
		if _, ok := hitOf(run(l, e, siteEv("203.0.113.5", "shop.example", uri, 200, now)), "learn-param"); ok {
			t.Errorf("%s 不应判为取值异常", uri)
		}
	}
	h, _ = hitOf(run(l, e, siteEv("203.0.113.5", "shop.example", "/item?id="+url.QueryEscape("1 union select 1,2")+"&from=home", 200, now)), "sqli-union")
	if h.Severity != model.SevHigh || !strings.Contains(h.Evidence, "平时只出现数字") {
		t.Fatalf("规则命中应注明参数平时的取值: %+v", h)
	}
}

// 站点从未出现过攻击针对的产品、请求也没有成功：最高低危；成功的请求、站点有该产品时不受影响。
func TestSiteInapplicable(t *testing.T) {
	l, e := attackLearner(t, ""), profEngine(t)
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	paths := []string{"/", "/api/v1/items/12", "/static/js/app.3f2a.js", "/login.do", "/user/profile.do?id=3"}
	train(l, e, "java.example", 30, 12, now, func(i int) string { return paths[i%len(paths)] })
	phpunit := "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
	check := func(host, uri string, status int, rule string, want bool) {
		t.Helper()
		h, ok := hitOf(run(l, e, siteEv("203.0.113.5", host, uri, status, now)), rule)
		if !ok {
			t.Fatalf("%s%s 应命中 %s", host, uri, rule)
		}
		if h.Inapplicable != want || want && (h.Severity != model.SevLow || !strings.Contains(h.Evidence, "攻击针对的产品不存在")) {
			t.Errorf("%s%s (%d): inapplicable=%v severity=%s，期望 %v；%s", host, uri, status, h.Inapplicable, h.Severity, want, h.Evidence)
		}
	}
	check("java.example", phpunit, 404, "cve-phpunit", true)
	check("java.example", phpunit, 200, "cve-phpunit", false)                          // 成功的请求不判断
	check("java.example", "/wls-wsat/CoordinatorPortType", 404, "cve-weblogic", false) // 站点有 Java
	check("java.example", "/uploads/shell.php", 404, "webshell-upload", true)
	check("java.example", "/uploads/shell.jsp", 404, "webshell-upload", false)
	check("new.example", phpunit, 404, "cve-phpunit", false) // 没有足够的正常访问，不判断
	r := l.Report().Profile
	if len(r.Sites) == 0 || r.Sites[0].Host != "java.example" || !r.Sites[0].Mature || len(r.Sites[0].Products) == 0 || r.Sites[0].Products[0].Key != "java" {
		t.Fatalf("站点报告: %+v", r.Sites)
	}
}

func TestTechOf(t *testing.T) {
	for p, want := range map[string]string{
		"/wp-content/themes/a/style.css": "wordpress,php",
		"/index.php":                     "php",
		"/user/login.action":             "java,struts",
		"/app;jsessionid=abc":            "java",
		"/default.aspx":                  "aspnet",
		"/seeyon/main.do":                "java,seeyon",
		"/a/b/c/d/wp-content/x":          "",
		"/static/app.js":                 "",
	} {
		if got := strings.Join(techOf(p), ","); got != want {
			t.Errorf("%s: %q，期望 %q", p, got, want)
		}
	}
	for v, want := range map[string]valueClass{
		"": vcEmpty, "123": vcNum, "-1.5": vcNum, "550e8400-e29b-41d4-a716-446655440000": vcID, "a1b2c3d4e5f6": vcID,
		"asc": vcToken, "2026-11-03": vcID, "a@b.com": vcToken, "https://x.example/a?b=1": vcToken,
		"hello world": vcText, "手机": vcText, "O'Reilly": vcText, `{"a":1}`: vcStruct,
	} {
		if got, _ := classify(v); got != want {
			t.Errorf("classify(%q) = %d，期望 %d", v, got, want)
		}
	}
}

// 已生效的参数与站点重启后保留。
func TestProfilePersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	l, e := attackLearner(t, path), profEngine(t)
	now := time.Now()
	train(l, e, "shop.example", 30, 10, now, func(i int) string { return "/search?q=" + url.QueryEscape(words[i%len(words)]) + "&p=" + fmt.Sprint(i) })
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	l2 := attackLearner(t, path)
	prose := "/search?q=" + url.QueryEscape("how to use select name from users where id")
	if h, _ := hitOf(run(l2, e, siteEv("203.0.113.5", "shop.example", prose, 200, now)), "sqli-func"); !h.Weak {
		t.Fatalf("重启后应保留学到的参数: %+v", h)
	}
	if r := l2.Report().Profile; r.SiteTotal != 1 || r.Mature < 1 {
		t.Fatalf("报告: %+v", r)
	}
}
