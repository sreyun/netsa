package store

import "sort"

// topK 从任意多个元素中选出按 before 排在前 k 位的元素：有界堆（根为已选元素中排名最后的），O(n log k)，
// 只保存 k 个元素。用于“全部数据里取一页 / 前若干个”的查询（攻击源列表、攻击面的入口与服务），
// 不必先复制并排序全部数据（2 万个入口时原先要复制 2 万份并整体排序，全程持有读锁、阻塞日志入库）。
// k <= 0 表示不限数量（全部保留，最后整体排序）。
type topK[T any] struct {
	k      int
	before func(a, b T) bool // a 排在 b 之前
	h      []T
}

func newTopK[T any](k int, before func(a, b T) bool) *topK[T] {
	n := 256
	if k > 0 {
		n = min(k, 1024)
	}
	return &topK[T]{k: k, before: before, h: make([]T, 0, n)}
}

// worse 判断 h[i] 排在 h[j] 之后。
func (t *topK[T]) worse(i, j int) bool { return t.before(t.h[j], t.h[i]) }

func (t *topK[T]) down(i int) {
	for n := len(t.h); ; {
		w, l := i, 2*i+1
		if l < n && t.worse(l, w) {
			w = l
		}
		if r := l + 1; r < n && t.worse(r, w) {
			w = r
		}
		if w == i {
			return
		}
		t.h[i], t.h[w] = t.h[w], t.h[i]
		i = w
	}
}

// add 加入一个候选元素。
func (t *topK[T]) add(x T) {
	switch {
	case t.k <= 0 || len(t.h) < t.k:
		t.h = append(t.h, x)
		if len(t.h) == t.k {
			for i := t.k/2 - 1; i >= 0; i-- {
				t.down(i)
			}
		}
	case t.before(x, t.h[0]):
		t.h[0] = x
		t.down(0)
	}
}

// sorted 返回选出的元素（按 before 排序）。
func (t *topK[T]) sorted() []T {
	sort.Slice(t.h, func(i, j int) bool { return t.before(t.h[i], t.h[j]) })
	return t.h
}
