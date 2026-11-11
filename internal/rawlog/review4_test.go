package rawlog

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 检索结果按字节数约束内存：超长日志行累计超过上限时只保留最新的部分、标记为不完整，并可按位置继续翻页取得其余的日志。
func TestSearchMemoryCap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loc := time.FixedZone("CST", 8*3600)
	s, err := Open(ctx, Options{Dir: t.TempDir(), RetentionDays: 3650, Location: loc})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(5 * time.Second)
	base := time.Date(2026, 10, 20, 9, 0, 0, 0, loc)
	const total = 200
	pad := strings.Repeat("x", 10<<10)
	var evs []*model.Event
	for i := 0; i < total; i++ {
		evs = append(evs, ev(base.Add(time.Duration(i)*time.Second), "198.51.100.1", "line-"+strconv.Itoa(i)+" "+pad))
	}
	s.Write(evs, make([][]model.Hit, total))
	waitWritten(t, s, total)
	s.maintain(false)

	q := Query{From: base.Add(-time.Hour), To: base.Add(time.Hour), Limit: 5000, MaxHold: 200 << 10}
	seen := map[string]bool{}
	var last time.Time
	for pages := 1; ; pages++ {
		res, err := s.Search(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var held int
		for _, r := range res.Records {
			held += len(r.Raw)
			name, _, _ := strings.Cut(r.Raw, " ")
			if seen[name] {
				t.Fatalf("第 %d 页重复: %s", pages, name)
			}
			seen[name] = true
			if !last.IsZero() && r.Time.After(last) {
				t.Fatalf("第 %d 页时间不是倒序", pages)
			}
			last = r.Time
		}
		if int64(held) > q.MaxHold {
			t.Fatalf("第 %d 页保留 %d 字节，超过上限 %d", pages, held, q.MaxHold)
		}
		if pages == 1 && (!res.Truncated || !strings.Contains(res.Reason, "200KB") || res.Records[0].Raw[:9] != "line-199 ") {
			t.Fatalf("第一页应只保留最新的部分并说明原因: truncated=%v reason=%q first=%q", res.Truncated, res.Reason, res.Records[0].Raw[:9])
		}
		if res.Next == "" {
			break
		}
		if q.Cursor, err = ParseCursor(res.Next); err != nil {
			t.Fatal(err)
		}
		if pages > 50 {
			t.Fatal("翻页没有结束")
		}
	}
	if len(seen) != total {
		t.Fatalf("逐页应取得全部 %d 条，实际 %d 条", total, len(seen))
	}
}
