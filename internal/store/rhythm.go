package store

import (
	"math"
	"time"
)

// 行为节奏：同一个攻击者换多少出口地址，作息时间与操作节奏不变（人工操作在工作时段、请求间隔几秒到几十秒；
// 自动化工具全天候、请求间隔不到一秒）。同源关联据此比对轮换出口的同一攻击者，只作为辅助线索：
// 大量扫描器的节奏本来就相似，单凭节奏不构成关联。

// Rhythm 是攻击源的活跃时段（按小时）与相邻两次请求的间隔分布。
type Rhythm struct {
	Hours [24]uint32 `json:"h"` // 各小时的事件数（按日志时区）
	Gaps  [8]uint32  `json:"g"` // 请求间隔：<1 秒、1~2、2~4、4~8、8~16、16~64 秒、1~10 分钟、更长
	N     uint32     `json:"n"`
	last  int64      // 上一次事件的时间（纳秒，不持久化）
}

// rhythmMin 是参与比对的最少事件数：事件太少时分布没有代表性。
const rhythmMin = 50

func (r *Rhythm) observe(t time.Time, loc *time.Location) {
	if r.N < math.MaxUint32 {
		r.N++
	}
	r.Hours[t.In(loc).Hour()]++
	ns := t.UnixNano()
	if r.last != 0 {
		d := ns - r.last
		if d < 0 {
			d = -d
		}
		r.Gaps[gapBucket(time.Duration(d))]++
	}
	r.last = ns
}

func gapBucket(d time.Duration) int {
	switch {
	case d < time.Second:
		return 0
	case d < 2*time.Second:
		return 1
	case d < 4*time.Second:
		return 2
	case d < 8*time.Second:
		return 3
	case d < 16*time.Second:
		return 4
	case d < 64*time.Second:
		return 5
	case d < 10*time.Minute:
		return 6
	}
	return 7
}

// similar 判断两个攻击源的行为节奏是否相似：活跃时段与请求间隔分布的余弦相似度都达到阈值。
// 全天候活跃（24 小时都有）的自动化工具之间不比较时段：彼此都很“相似”，说明不了是同一个人。
func (r *Rhythm) similar(o *Rhythm) (hours, gaps float64, ok bool) {
	if r == nil || o == nil || r.N < rhythmMin || o.N < rhythmMin || r.allDay() && o.allDay() {
		return 0, 0, false
	}
	hours, gaps = cosine(r.Hours[:], o.Hours[:]), cosine(r.Gaps[:], o.Gaps[:])
	return hours, gaps, hours >= 0.9 && gaps >= 0.9
}

// allDay 判断是否全天大部分时段都在活动（20 个小时以上有事件）。
func (r *Rhythm) allDay() bool {
	n := 0
	for _, v := range r.Hours {
		if v > 0 {
			n++
		}
	}
	return n >= 20
}

func cosine(a, b []uint32) float64 {
	var dot, na, nb float64
	for i := range a {
		x, y := float64(a[i]), float64(b[i])
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / math.Sqrt(na*nb)
}

// location 返回按天汇总与行为节奏使用的时区（调用方持锁）。
func (s *Store) location() *time.Location {
	if s.loc != nil {
		return s.loc
	}
	return time.Local
}
