package api

import (
	"io"
	"net/http"
	"net/http/httptest"
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
