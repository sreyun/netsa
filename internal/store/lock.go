package store

import (
	"sync"
	"sync/atomic"
	"time"
)

// timedRWMutex 是状态库的读写锁，额外记录写锁的等待与持有时间。
//
// 日志入库每一批都要拿写锁；查询在读锁内做全量计算时，入库就在这里排队，写者等待期间新的读请求也被挡住，
// 表现为页面与入库一起卡顿。等待时间直接反映这种争用，是状态库分区（演进路线 N1）效果的度量依据。
// 每次 Unlock 递增写代数：保存快照时与上次保存的代数比较，没有写入过就不必重写整个快照。
type timedRWMutex struct {
	sync.RWMutex
	held time.Time // 拿到写锁的时间（只在持有写锁时读写）
	gen  atomic.Uint64

	count     atomic.Int64 // 写锁次数
	waitTotal atomic.Int64 // 累计等待（纳秒）
	// 最近两个统计周期内的最大值（纳秒）：Maintain 每个周期轮换一次，指标反映的是最近的状况而不是启动以来的峰值
	waitCur, waitPrev atomic.Int64
	holdCur, holdPrev atomic.Int64
}

func atomicMax(a *atomic.Int64, v int64) {
	for {
		old := a.Load()
		if v <= old || a.CompareAndSwap(old, v) {
			return
		}
	}
}

// Lock 拿写锁并记录等待时间。
func (m *timedRWMutex) Lock() {
	t0 := time.Now()
	m.RWMutex.Lock()
	now := time.Now()
	w := int64(now.Sub(t0))
	m.count.Add(1)
	m.waitTotal.Add(w)
	atomicMax(&m.waitCur, w)
	m.held = now
}

// Unlock 释放写锁并记录持有时间。
func (m *timedRWMutex) Unlock() {
	atomicMax(&m.holdCur, int64(time.Since(m.held)))
	m.gen.Add(1)
	m.RWMutex.Unlock()
}

// unlockClean 释放写锁但不递增写代数：调用方确认这次持锁没有修改任何会保存到快照的数据。
func (m *timedRWMutex) unlockClean() {
	atomicMax(&m.holdCur, int64(time.Since(m.held)))
	m.RWMutex.Unlock()
}

// rotate 开始新的统计周期（调用方不需要持锁）。
func (m *timedRWMutex) rotate() {
	m.waitPrev.Store(m.waitCur.Swap(0))
	m.holdPrev.Store(m.holdCur.Swap(0))
}

// LockStats 是状态库写锁的统计。
type LockStats struct {
	Count     int64         // 写锁次数
	WaitTotal time.Duration // 累计等待
	WaitMax   time.Duration // 最近两个统计周期内单次等待的最大值
	HoldMax   time.Duration // 最近两个统计周期内单次持有的最大值
}

// LockStats 返回写锁的统计（不持锁）。
func (s *Store) LockStats() LockStats {
	m := &s.mu
	return LockStats{Count: m.count.Load(), WaitTotal: time.Duration(m.waitTotal.Load()),
		WaitMax: time.Duration(max(m.waitCur.Load(), m.waitPrev.Load())), HoldMax: time.Duration(max(m.holdCur.Load(), m.holdPrev.Load()))}
}
