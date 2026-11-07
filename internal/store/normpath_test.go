package store

import (
	"strings"
	"testing"
)

// 路径归一：数字 ID、UUID、哈希替换为占位符，去掉查询参数，统一小写；不需要替换时不分配。
func TestNormPath(t *testing.T) {
	cases := map[string]string{
		"":                                   "/",
		"/":                                  "/",
		"/?a=1":                              "/",
		"/API/Users/123/Profile":             "/api/users/{id}/profile",
		"/u/123":                             "/u/{id}",
		"/123":                               "/{id}",
		"/a//b/":                             "/a//b/",
		"/files/0123456789abcdef0123/x#frag": "/files/{hash}/x",
		"/o/550e8400-e29b-41d4-a716-446655440000/items/7?x=1": "/o/{uuid}/items/{id}",
		"/static/app.js":   "/static/app.js",
		"relative/42/path": "relative/{id}/path",
	}
	for in, want := range cases {
		if got := normPath(in); got != want {
			t.Errorf("normPath(%q) = %q, want %q", in, got, want)
		}
	}
	long := "/" + strings.Repeat("路", 100)
	if got := normPath(long); len(got) > 200 || !strings.HasPrefix(long, got) {
		t.Errorf("超长路径应在字符边界截断到 200 字节: %d", len(got))
	}
	if n := testing.AllocsPerRun(100, func() { normPath("/static/js/app.js?v=3") }); n != 0 {
		t.Errorf("不需要替换的路径不应分配: %v", n)
	}
}
