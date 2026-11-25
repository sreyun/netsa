package rawlog

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 时间范围不可用时说明具体原因，接口仍按 ErrRange 返回 400
func TestSearchRangeReasons(t *testing.T) {
	s := &Store{}
	now := time.Now()
	for _, c := range []struct {
		from, to time.Time
		want     string
	}{
		{time.Time{}, now, ErrRange.Error()},
		{now, now.Add(-time.Hour), "开始时间必须早于结束时间"},
		{now.Add(-40 * 24 * time.Hour), now, "检索的时间范围最长 31 天，请缩小范围"},
	} {
		_, err := s.Search(context.Background(), Query{From: c.from, To: c.to})
		if !errors.Is(err, ErrRange) || err.Error() != c.want {
			t.Errorf("%v ~ %v: %v", c.from, c.to, err)
		}
	}
}
