package geo

import (
	"testing"
	"time"
)

// 重新定位得到的新对象只有更新时间不同时视为内容相同；位置、来源等变化时不同。
func TestSameContent(t *testing.T) {
	a := &Info{IP: "203.0.113.5", Country: "中国", City: "上海", Sources: []SourceResult{{Source: "ip2region"}}, UpdatedAt: time.Now().Add(-time.Hour)}
	b := *a
	b.UpdatedAt = time.Now()
	if !SameContent(a, &b) {
		t.Fatal("只有更新时间不同时应视为相同")
	}
	c := b
	c.City = "杭州"
	if SameContent(a, &c) {
		t.Fatal("城市不同时应视为不同")
	}
	if SameContent(a, nil) || !SameContent(nil, nil) {
		t.Fatal("空值比较不正确")
	}
}
