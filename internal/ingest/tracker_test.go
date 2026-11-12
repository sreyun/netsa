package ingest

import (
	"context"
	"testing"

	"netsa/internal/model"
)

func trackedOffset(c *Checkpoints, path string) int64 {
	cp, ok := c.get(path)
	if !ok {
		return -1
	}
	return cp.Offset
}

// 断点只越过从头开始连续处理完的批次：后面的批次先处理完时等前面的；没有送出（或退出时丢弃）的批次之后一直不前移；
// 读到末尾时的位置在前面的批次处理完后生效，连续空闲只保留最新的位置；写入顺序与送出顺序一致，断点不倒退。
func TestOffsetTracker(t *testing.T) {
	c := &Checkpoints{m: map[string]checkpoint{}}
	tr := &offsetTracker{path: "/a", cps: c}
	cp := func(off int64) checkpoint { return checkpoint{Offset: off, PrefixLen: 1, Prefix: "p"} }

	tr.idle(cp(10), true)
	if trackedOffset(c, "/a") != 10 {
		t.Fatal("没有在处理中的批次时，末尾位置应立即生效")
	}
	s1 := tr.sent(cp(100), true)
	s2 := tr.sent(cp(200), true)
	s3 := tr.sent(cp(300), true)
	tr.idle(cp(310), true) // 读到末尾（之后几行被跳过）
	tr.idle(cp(320), true) // 连续空闲：只保留最新的
	if len(tr.queue) != 4 {
		t.Fatalf("连续空闲应合并为一个位置: %d", len(tr.queue))
	}
	tr.finish(s2) // 第二批先处理完
	if trackedOffset(c, "/a") != 10 {
		t.Fatal("第一批还没处理完，断点不能越过它")
	}
	tr.finish(s1)
	if got := trackedOffset(c, "/a"); got != 200 {
		t.Fatalf("前两批处理完，断点应到 200: %d", got)
	}
	tr.finish(s3)
	if got := trackedOffset(c, "/a"); got != 320 || len(tr.queue) != 0 {
		t.Fatalf("全部处理完，断点应到最新的末尾位置: %d，剩余 %d", got, len(tr.queue))
	}
	tr.finish(s3) // 重复报告：忽略
	if trackedOffset(c, "/a") != 320 {
		t.Fatal("重复报告不应改变断点")
	}

	// 还没读到文件开头用于识别的内容：位置不可用，弹出但不写入断点
	s4 := tr.sent(checkpoint{}, false)
	tr.finish(s4)
	if trackedOffset(c, "/a") != 320 || len(tr.queue) != 0 {
		t.Fatal("不可用的位置不应写入断点")
	}

	// 没有送出（退出时）或被丢弃的批次：之后的位置都不生效
	tr.sent(cp(400), true) // 永远不会报告处理完
	s6 := tr.sent(cp(500), true)
	tr.finish(s6)
	tr.idle(cp(600), true)
	if got := trackedOffset(c, "/a"); got != 320 {
		t.Fatalf("丢弃的批次之后断点不应前移: %d", got)
	}
}

// 管理器按批次的第一条事件找到所属的数据源；没有断点的数据源（syslog、离线读取）不登记；没有送出的批次取消登记。
func TestBatchTracking(t *testing.T) {
	c := &Checkpoints{m: map[string]checkpoint{}}
	m := NewManager(4)
	m.Checkpoints = c
	file := &source{track: &offsetTracker{path: "/f", cps: c}}
	pos := int64(0)
	file.pos = func() (checkpoint, bool) { return checkpoint{Offset: pos, PrefixLen: 1, Prefix: "p"}, true }
	syslog := &source{}

	a, b, x := &model.Event{}, &model.Event{}, &model.Event{}
	pos = 50
	m.trackBatch(file, a)
	pos = 90
	m.trackBatch(file, b)
	m.trackBatch(syslog, x)
	if m.InFlight() != 2 {
		t.Fatalf("应有 2 批文件日志在处理中（syslog 不登记）: %d", m.InFlight())
	}
	m.BatchDone(x)
	m.BatchDone(b)
	if trackedOffset(c, "/f") != -1 {
		t.Fatal("第一批没处理完，断点不应生效")
	}
	m.BatchDone(a)
	if got := trackedOffset(c, "/f"); got != 90 || m.InFlight() != 0 {
		t.Fatalf("处理完后断点应到 90: %d，处理中 %d", got, m.InFlight())
	}
	m.BatchDone(&model.Event{}) // 不认识的批次忽略
	// 没有送出：取消登记，断点停在它之前
	y, z := &model.Event{}, &model.Event{}
	pos = 120
	m.trackBatch(file, y)
	m.untrackBatch(y)
	pos = 150
	m.trackBatch(file, z)
	m.BatchDone(z)
	if got := trackedOffset(c, "/f"); got != 90 {
		t.Fatalf("没有送出的批次之后断点不应前移: %d", got)
	}
}

// 离线读取（netsa corpus 直接读取 Out、不报告处理完）不登记批次：读过的事件不会被一直占着。
func TestReadFileNotTracked(t *testing.T) {
	path := t.TempDir() + "/a.log"
	appendFile(t, path, 0, 600)
	m := NewManager(16)
	m.Checkpoints = &Checkpoints{m: map[string]checkpoint{}}
	if err := m.ReadFile(context.Background(), path, "auto", "", ""); err != nil {
		t.Fatal(err)
	}
	collect(t, m.Out, 600)
	m.Wait()
	if m.InFlight() != 0 || len(m.batches) != 0 {
		t.Fatalf("离线读取不应登记批次: %d", m.InFlight())
	}
}
