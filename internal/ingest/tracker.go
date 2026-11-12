package ingest

import (
	"sync"

	"netsa/internal/model"
)

// 读取断点什么时候生效。
//
// 断点只能越过已经处理完的日志：送入处理队列的批次在退出时可能被丢弃，断点要是越过了它们，这些日志就永远丢失了。
// 每个文件数据源按送出顺序记下每一批之后的读取位置（offsetTracker）；处理流水线报告一批处理完时（Manager.BatchDone），
// 断点前移到「从头开始连续处理完」的最后一批之后。几个处理协程完成的先后不同，前面一批还没处理完时，后面已处理完的批次
// 先等着；没有送出或退出时被丢弃的批次一直不算处理完，断点停在它们之前，下次启动重新读取。读到文件末尾时没有新批次，
// 也记下当前位置（跳过的、无法解析的行同样算读过）。

// offsetTracker 跟踪一个文件数据源送出的批次与对应的读取位置（并发安全：读取协程送出，处理流水线报告处理完）。
type offsetTracker struct {
	mu    sync.Mutex
	path  string
	cps   *Checkpoints
	seq   uint64
	queue []trackEntry // 按送出顺序排列、还没生效的位置
}

type trackEntry struct {
	seq  uint64
	cp   checkpoint
	ok   bool // 有可用的断点（已读到文件开头用于识别的内容）
	done bool
}

// sent 登记送出的一批及其之后的读取位置，返回序号。
func (t *offsetTracker) sent(cp checkpoint, ok bool) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	t.queue = append(t.queue, trackEntry{seq: t.seq, cp: cp, ok: ok})
	return t.seq
}

// idle 记下没有新批次时的读取位置（读到末尾）：前面的批次都处理完就生效。
func (t *offsetTracker) idle(cp checkpoint, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := len(t.queue); n > 0 && t.queue[n-1].done { // 连续空闲只保留最新的位置
		t.queue[n-1].cp, t.queue[n-1].ok = cp, ok
	} else {
		t.seq++
		t.queue = append(t.queue, trackEntry{seq: t.seq, cp: cp, ok: ok, done: true})
	}
	t.advanceLocked()
}

// finish 报告一批处理完。
func (t *offsetTracker) finish(seq uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.queue { // 处理完的通常就在队首附近
		if t.queue[i].seq == seq {
			t.queue[i].done = true
			break
		}
	}
	t.advanceLocked()
}

// advanceLocked 让队首连续处理完的位置生效（写入断点的顺序与送出顺序一致，断点不会倒退）。
func (t *offsetTracker) advanceLocked() {
	n := 0
	var last *checkpoint
	for n < len(t.queue) && t.queue[n].done {
		if t.queue[n].ok {
			last = &t.queue[n].cp
		}
		n++
	}
	if n == 0 {
		return
	}
	if last != nil {
		t.cps.set(t.path, *last)
	}
	t.queue = append(t.queue[:0], t.queue[n:]...)
}

// batchRef 是送出、还没处理完的一批：所属的跟踪器与序号。
type batchRef struct {
	t   *offsetTracker
	seq uint64
}

// trackBatch 登记送出的一批（以第一条事件标识）。只登记记录读取断点的文件数据源：syslog、离线读取的文件
// 没有断点；netsa corpus 等直接读取 Out、不报告处理完的用法也不会因登记而一直占着已读过的事件。
func (m *Manager) trackBatch(s *source, first *model.Event) {
	if s.track == nil {
		return
	}
	cp, ok := s.pos()
	ref := batchRef{t: s.track, seq: s.track.sent(cp, ok)}
	m.tmu.Lock()
	if m.batches == nil {
		m.batches = map[*model.Event]batchRef{}
	}
	m.batches[first] = ref
	m.tmu.Unlock()
}

// untrackBatch 取消登记没有送出的一批：它不算处理完，断点停在它之前。
func (m *Manager) untrackBatch(first *model.Event) {
	m.tmu.Lock()
	delete(m.batches, first)
	m.tmu.Unlock()
}

// BatchDone 由处理流水线在一批事件处理完之后调用（pipeline.Pipeline.BatchDone，参数是这一批的第一条事件）。
// 不认识的批次（不是本管理器送出的、重复报告的）忽略。
func (m *Manager) BatchDone(first *model.Event) {
	m.tmu.Lock()
	ref, ok := m.batches[first]
	delete(m.batches, first)
	m.tmu.Unlock()
	if ok {
		ref.t.finish(ref.seq)
	}
}

// InFlight 返回文件数据源已送入处理队列、还没有处理完的批数。
func (m *Manager) InFlight() int {
	m.tmu.Lock()
	defer m.tmu.Unlock()
	return len(m.batches)
}
