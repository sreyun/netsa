package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 缓存容量用 LRU 控制：超出上限只淘汰最久未使用的键，热键保留、计数可观测。
// 旧实现是「超过 1024 个键整体清空」，会让大屏刷新出现周期性卡顿尖峰。
func TestRespCacheLRU(t *testing.T) {
	rc := newRespCache()
	rc.max = 4
	calls := 0
	h := rc.wrap(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, r.URL.Query().Get("k"))
	})
	get := func(k string) string {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/api/x?k="+k, nil))
		return rec.Body.String()
	}

	for _, k := range []string{"a", "b", "c", "d"} {
		get(k)
	}
	if calls != 4 {
		t.Fatalf("首次请求应各自计算一次: %d", calls)
	}
	// 命中 a，使其成为最近使用；随后插入 e 应淘汰最久未使用的 b
	if body := get("a"); body != "a" || calls != 4 {
		t.Fatalf("a 应命中缓存: body=%q calls=%d", body, calls)
	}
	get("e")
	if calls != 5 {
		t.Fatalf("新增键应计算一次: %d", calls)
	}
	if body := get("a"); body != "a" || calls != 5 {
		t.Fatalf("热键 a 不应被淘汰: body=%q calls=%d", body, calls)
	}
	if body := get("b"); body != "b" || calls != 6 {
		t.Fatalf("冷键 b 应被淘汰后重算: body=%q calls=%d", body, calls)
	}

	entries, hits, misses := rc.stats()
	if entries > rc.max {
		t.Fatalf("条目数超过上限: %d > %d", entries, rc.max)
	}
	if hits == 0 || misses == 0 {
		t.Fatalf("命中计数缺失: hits=%d misses=%d", hits, misses)
	}
}

// 内存上限：响应体总量超过上限时从最久未使用的一端淘汰；太大的响应不缓存；过期的条目新建键时被清掉。
func TestRespCacheByteBudget(t *testing.T) {
	rc := newRespCache()
	rc.maxBytes, rc.maxEntry = 1000, 600
	size := map[string]int{}
	h := rc.wrap(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", size[r.URL.Query().Get("k")]))
	})
	get := func(k string) {
		h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/x?k="+k, nil))
	}
	size["a"], size["b"], size["c"], size["big"] = 400, 400, 400, 700
	get("a")
	get("b")
	get("c") // 1200 > 1000：淘汰最久未使用的 a
	if n, b := len(rc.items), rc.size(); n != 2 || b != 800 {
		t.Fatalf("超出总量应淘汰最旧的条目: %d 个 %d 字节", n, b)
	}
	get("big") // 超过单个上限：不缓存
	if rc.size() != 800 {
		t.Fatalf("太大的响应不应计入缓存: %d", rc.size())
	}
	// 过期的条目在新建键时清掉
	ttl := rc.wrap(time.Millisecond, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "yy") })

	for _, k := range []string{"p", "q"} {
		ttl(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/y?k="+k, nil))
	}
	time.Sleep(5 * time.Millisecond)
	get("d")
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for k := range rc.items {
		if strings.HasPrefix(k, "/api/y") {
			t.Fatalf("过期的条目应被清掉: %s", k)
		}
	}
}
