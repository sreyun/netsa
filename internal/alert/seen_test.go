package alert

import (
	"testing"
	"time"
)

// 去重窗口按过期时间精确淘汰：窗口内重复的键判重，窗口过后重新推送，
// 且不会因为条目过多而整体清空（旧实现会短暂产生重复推送）。
func TestSeenSetWindow(t *testing.T) {
	s := newSeenSet()
	t0 := time.Now()
	if s.Seen("k", t0, time.Minute) {
		t.Fatal("首次出现不应判重")
	}
	if !s.Seen("k", t0.Add(30*time.Second), time.Minute) {
		t.Fatal("窗口内应判重")
	}
	if s.Seen("k", t0.Add(90*time.Second), time.Minute) {
		t.Fatal("窗口过后应重新推送")
	}
	if n := s.Len(); n != 1 {
		t.Fatalf("过期键应被清理，实际 %d", n)
	}
}

// 大量一次性键在窗口过后全部过期，内存随窗口回收，不依赖清空兜底。
func TestSeenSetBounded(t *testing.T) {
	s := newSeenSet()
	t0 := time.Now()
	for i := 0; i < 5000; i++ {
		s.Seen(string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676)), t0, time.Minute)
	}
	if n := s.Len(); n == 0 {
		t.Fatal("窗口内应保留去重键")
	}
	// 推进到全部过期后，任意新键都会触发队列淘汰
	s.Seen("fresh", t0.Add(2*time.Minute), time.Minute)
	if n := s.Len(); n != 1 {
		t.Fatalf("过期键应全部回收，实际 %d", n)
	}
}
