package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 处理器 panic 后，缓存条目锁必须释放：否则之后这个键的请求全部永久挂起。
func TestRespCacheReleasesLockOnPanic(t *testing.T) {
	rc := newRespCache()
	calls := 0
	h := rc.wrap(time.Minute, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			panic("统计时出现异常")
		}
		writeJSON(w, map[string]int{"n": calls})
	})
	func() {
		defer func() { recover() }() // net/http 同样只结束该请求
		h(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/overview", nil))
	}()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", "/api/overview", nil))
		done <- w
	}()
	select {
	case w := <-done:
		if w.Code != http.StatusOK || calls != 2 {
			t.Fatalf("panic 之后应重新计算: %d %d", w.Code, calls)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("panic 之后同一个键的请求被永久挂起")
	}
}
