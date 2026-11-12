package store

import (
	"os"
	"sync/atomic"
	"time"
)

// 增量快照：满规模时（20 万个攻击源画像）完整快照编码一次要十几秒 CPU，其中画像占八成以上，
// 而每分钟真正有变化的画像通常只有几百到几千个。因此完整快照每 15 分钟保存一次（改动的画像超过三成时提前），
// 其余时候只写增量快照（快照文件名加 .delta）：除画像以外的部分照常完整写入（规模有上限），
// 画像只写上次完整保存之后改动过的，并列出期间淘汰的。恢复时先读增量快照，它记下的标识与完整快照一致时，
// 完整快照只取画像（其余部分只扫描、不建对象），叠加增量快照中的画像与淘汰记录；不一致时按完整快照恢复。
//
// 增量快照是相对完整快照累积的，不是一串链式的增量：只依赖一份完整快照，任何一次写入失败都不影响已有的文件。
// 处置记录预写日志只在完整快照之后整理，增量快照丢失或被旧版本忽略时，分析员的处置结论仍能从日志恢复。

const (
	fullEvery     = 15 * time.Minute // 完整快照的最长间隔
	deltaMaxRatio = 0.3              // 改动与淘汰的画像超过全部画像的这个比例时直接保存完整快照
)

func deltaPath(path string) string { return path + ".delta" }

// markDirty 记下画像在上次完整保存之后有改动（调用方持写锁）。第一次保存或载入快照之前不记录：
// 没有配置快照时不必记，否则改动记录会一直增长，淘汰的画像也无法释放。
func (s *Store) markDirty(p *IPProfile) {
	if s.trackDirty && !p.dirty {
		p.dirty = true
		s.dirtyList = append(s.dirtyList, p)
	}
}

// deltaDue 判断这次可以只保存增量快照（调用方持 saveMu）。
func (s *Store) deltaDue(path string) bool {
	// 系统时钟回拨时 age 为负，同样保存完整快照，否则可能很久都不再完整保存
	if age := time.Since(s.baseAt); s.baseID == "" || s.basePath != path || age < 0 || age >= fullEvery {
		return false
	}
	if _, err := os.Stat(path); err != nil { // 完整快照被删除或移走
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return float64(len(s.dirtyList)+len(s.removedIPs)) <= deltaMaxRatio*float64(len(s.ips))
}

// takeDirty 在完整保存开始前取走改动记录：此后的改动进入下一份增量快照。保存期间改动的画像可能同时出现在
// 完整快照与下一份增量快照中，恢复时以增量快照为准。只改动记录本身，不算快照数据的写入。
func (s *Store) takeDirty() ([]*IPProfile, map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.unlockClean()
	list, removed := s.dirtyList, s.removedIPs
	for _, p := range list {
		p.dirty = false
	}
	s.dirtyList, s.removedIPs = nil, map[string]struct{}{}
	s.trackDirty = true
	return list, removed
}

// restoreDirty 在完整保存失败后放回改动记录（磁盘上仍是上一份完整快照）。
func (s *Store) restoreDirty(list []*IPProfile, removed map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.unlockClean()
	for _, p := range list {
		if s.ips[p.IP] == p { // 期间被淘汰的已记在淘汰名单里；不放回，否则保存一直失败时它们无法释放
			s.markDirty(p)
		}
	}
	for ip := range removed {
		s.removedIPs[ip] = struct{}{}
	}
}

// saveTimes 记录最近一次完整 / 增量保存的耗时与完整快照的时间（纳秒），供指标读取。
type saveTimes struct{ full, delta, fullAt atomic.Int64 }

// SaveStats 是快照保存的运行指标。
type SaveStats struct {
	Full, Delta time.Duration // 最近一次完整 / 增量保存的耗时
	FullAt      time.Time     // 磁盘上完整快照的保存时间（还没有时为零）
	Dirty       int           // 完整快照之后改动过的画像数（下一份增量快照的规模）
}

// SaveStats 返回快照保存的运行指标。
func (s *Store) SaveStats() SaveStats {
	st := SaveStats{Full: time.Duration(s.saveStat.full.Load()), Delta: time.Duration(s.saveStat.delta.Load())}
	if t := s.saveStat.fullAt.Load(); t > 0 {
		st.FullAt = time.Unix(0, t)
	}
	s.mu.RLock()
	st.Dirty = len(s.dirtyList)
	s.mu.RUnlock()
	return st
}
