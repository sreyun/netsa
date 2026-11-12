package ingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// collectDone 像处理流水线一样取出事件并报告每批处理完（BatchDone），读取断点据此生效。
func collectDone(t *testing.T, m *Manager, n int) []*model.Event {
	t.Helper()
	var out []*model.Event
	timeout := time.After(10 * time.Second)
	for len(out) < n {
		select {
		case batch := <-m.Out:
			out = append(out, batch...)
			m.BatchDone(batch[0])
		case <-timeout:
			t.Fatalf("只收到 %d/%d 条事件", len(out), n)
		}
	}
	return out
}

// readCheckpoints 读取断点文件（测试中检查保存的位置）。
func readCheckpoints(t *testing.T, path string) map[string]checkpoint {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]checkpoint{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// renameRetry 重命名文件（Windows：上一轮的跟踪协程退出后才释放文件）。
func renameRetry(t *testing.T, from, to string) {
	t.Helper()
	var err error
	for i := 0; i < 50; i++ {
		if err = os.Rename(from, to); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(err)
}

// 读取断点：重启后从上次读到的位置继续，停机期间写入的日志不丢、已读过的不重复；停机期间文件被轮转时从头读取新文件；
// 没有断点时保持原来的规则（从末尾开始）。
func TestCheckpointResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	ckpt := filepath.Join(dir, CheckpointFile)
	appendFile(t, path, 0, 5)

	run := func(want int) []*model.Event {
		t.Helper()
		cps, err := LoadCheckpoints(ckpt)
		if err != nil {
			t.Fatal(err)
		}
		m := NewManager(100)
		m.Checkpoints = cps
		ctx, cancel := context.WithCancel(context.Background())
		if err := m.StartSource(ctx, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{path}}); err != nil {
			t.Fatal(err)
		}
		var evs []*model.Event
		if want > 0 {
			evs = collectDone(t, m, want)
		}
		time.Sleep(600 * time.Millisecond) // 读到末尾、记下断点
		select {
		case b := <-m.Out:
			t.Fatalf("不应再有事件: %d 条，第一条 %s", len(b), b[0].URI)
		default:
		}
		cancel()
		if err := cps.Save(); err != nil {
			t.Fatal(err)
		}
		return evs
	}
	// 第一次启动：没有断点，从末尾开始（已有的 5 行不读）；之后写入的 2 行读取
	cps, _ := LoadCheckpoints(ckpt)
	m := NewManager(100)
	m.Checkpoints = cps
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.StartSource(ctx, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{path}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	appendFile(t, path, 5, 7)
	if evs := collectDone(t, m, 2); evs[0].URI != "/p5" {
		t.Fatalf("没有断点时应从末尾开始: %s", evs[0].URI)
	}
	time.Sleep(600 * time.Millisecond)
	cancel()
	if err := cps.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ckpt); err != nil {
		t.Fatalf("应写入断点文件: %v", err)
	}
	// 停机期间写入 3 行：重启后从断点继续，正好读到这 3 行
	appendFile(t, path, 7, 10)
	if evs := run(3); evs[0].URI != "/p7" || evs[2].URI != "/p9" {
		t.Fatalf("应从断点继续: %s .. %s", evs[0].URI, evs[2].URI)
	}
	// 没有新内容：重启后不重复读取
	run(0)
	// 停机期间被轮转：新文件的内容都是停机之后写的，从头读取
	renameRetry(t, path, path+".1")
	appendFile(t, path, 100, 102)
	if evs := run(2); evs[0].URI != "/p100" {
		t.Fatalf("轮转后应从头读取新文件: %s", evs[0].URI)
	}
}

// 断点只在送入队列的日志处理完之后生效：日志还在队列里（退出时可能被丢弃）时断点不前移，
// 下次启动重新读取这些日志，而不是越过它们。
func TestCheckpointWaitsForProcessing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	ckpt := filepath.Join(dir, CheckpointFile)
	appendFile(t, path, 0, 3)
	cps, _ := LoadCheckpoints(ckpt)
	m := NewManager(100)
	m.Checkpoints = cps
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.StartSource(ctx, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{path}, FromBeginning: true}); err != nil {
		t.Fatal(err)
	}
	// 取出但不报告处理完：相当于还在处理流水线中
	evs := collect(t, m.Out, 3)
	if len(evs) != 3 {
		t.Fatalf("应是一批 3 条: %d", len(evs))
	}
	time.Sleep(600 * time.Millisecond)
	if err := cps.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readCheckpoints(t, ckpt); len(got) != 0 {
		t.Fatalf("日志还没处理完时断点不应生效: %+v", got)
	}
	if n := m.InFlight(); n != 1 {
		t.Fatalf("应有 1 批在处理中: %d", n)
	}
	m.BatchDone(evs[0]) // 处理完
	if err := cps.Save(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if got := readCheckpoints(t, ckpt)[path]; got.Offset != st.Size() {
		t.Fatalf("处理完后断点应到文件末尾: %d / %d", got.Offset, st.Size())
	}
	cancel()
}

// 文件末尾还没写完的半行不计入断点：重启时从这一行的开头读，补全后的整行照常解析，而不是从半行中间开始读成残行。
func TestCheckpointPartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	ckpt := filepath.Join(dir, CheckpointFile)
	appendFile(t, path, 0, 2)
	full, _ := os.Stat(path)
	half := line(2)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(half[:20]) // 写到一半
	f.Close()

	cps, _ := LoadCheckpoints(ckpt)
	m := NewManager(100)
	m.Checkpoints = cps
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.StartSource(ctx, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{path}, FromBeginning: true}); err != nil {
		t.Fatal(err)
	}
	collectDone(t, m, 2)
	time.Sleep(700 * time.Millisecond)
	cancel()
	if err := cps.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readCheckpoints(t, ckpt)[path]; got.Offset != full.Size() {
		t.Fatalf("断点应停在半行之前: %d，应为 %d", got.Offset, full.Size())
	}
	// 停机期间这一行写完：重启后读到完整的一行
	time.Sleep(200 * time.Millisecond) // 等跟踪协程退出、释放文件
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(half[20:])
	f.Close()
	cps2, _ := LoadCheckpoints(ckpt)
	m2 := NewManager(100)
	m2.Checkpoints = cps2
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := m2.StartSource(ctx2, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{path}}); err != nil {
		t.Fatal(err)
	}
	if evs := collectDone(t, m2, 1); evs[0].URI != "/p2" {
		t.Fatalf("应读到补全后的整行: %q", evs[0].URI)
	}
	time.Sleep(300 * time.Millisecond)
	if st := m2.Stats(); len(st) != 1 || st[0].Failed != 0 {
		t.Fatalf("不应有无法解析的残行: %+v", st)
	}
}

// 断点判断：同一个文件从断点继续；文件变短或开头变了从头读取；需要补读的内容过多时只读最新的部分；
// 从主机同步来的断点只在同一个文件时使用，文件不同按没有断点处理。
func TestResumeAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	appendFile(t, path, 0, 20)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	prefix, n := filePrefix(f, prefixLen)
	if pos, why, ok := resumeAt(f, fi.Size(), checkpoint{Offset: 100, PrefixLen: n, Prefix: prefix}); !ok || pos != 100 || why == "" {
		t.Fatalf("同一文件应从断点继续: %d %s", pos, why)
	}
	if pos, _, ok := resumeAt(f, fi.Size(), checkpoint{Offset: fi.Size() + 10, PrefixLen: n, Prefix: prefix}); !ok || pos != 0 {
		t.Fatalf("文件变短应从头读取: %d", pos)
	}
	if pos, _, ok := resumeAt(f, fi.Size(), checkpoint{Offset: 100, PrefixLen: n, Prefix: "other"}); !ok || pos != 0 {
		t.Fatalf("开头不同应从头读取: %d", pos)
	}
	if pos, why, ok := resumeAt(f, maxCatchup+500, checkpoint{Offset: 10, PrefixLen: n, Prefix: prefix}); !ok || pos != 500 || why == "" {
		t.Fatalf("补读过多时只读最新部分: %d", pos)
	}
	if _, why, ok := resumeAt(f, fi.Size(), checkpoint{}); ok || why != "" {
		t.Fatal("空断点不可用")
	}
	// 从主机同步来的断点
	if pos, _, ok := resumeAt(f, fi.Size(), checkpoint{Offset: 100, PrefixLen: n, Prefix: prefix, Foreign: true}); !ok || pos != 100 {
		t.Fatalf("同一个文件（共用存储）应从主机的断点继续: %d", pos)
	}
	if _, why, ok := resumeAt(f, fi.Size(), checkpoint{Offset: 100, PrefixLen: n, Prefix: "other", Foreign: true}); ok || why == "" {
		t.Fatal("本机文件与主机上的不同时应按没有断点处理（并说明原因）")
	}
	if _, _, ok := resumeAt(f, fi.Size(), checkpoint{Offset: fi.Size() + 10, PrefixLen: n, Prefix: prefix, Foreign: true}); ok {
		t.Fatal("本机文件比主机断点短时应按没有断点处理")
	}
}

// 温备机同步来的断点：标记为来自主机；本机读的是另一个文件时接管后从末尾开始，而不是把整个文件当作新内容从头读。
func TestForeignCheckpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	ckpt := filepath.Join(dir, CheckpointFile)
	appendFile(t, path, 0, 5)
	if err := MarkForeign(ckpt); err != nil {
		t.Fatalf("没有断点文件时应什么也不做: %v", err)
	}
	// 主机上的断点：同一路径，但文件内容不同
	data, _ := json.Marshal(map[string]checkpoint{path: {Offset: 3, PrefixLen: 10, Prefix: "primary-file", Updated: time.Now()}})
	if err := os.WriteFile(ckpt, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkForeign(ckpt); err != nil {
		t.Fatal(err)
	}
	if got := readCheckpoints(t, ckpt)[path]; !got.Foreign || got.Offset != 3 {
		t.Fatalf("应标记为来自主机: %+v", got)
	}
	cps, _ := LoadCheckpoints(ckpt)
	m := NewManager(100)
	m.Checkpoints = cps
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.StartSource(ctx, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{path}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	select {
	case b := <-m.Out:
		t.Fatalf("文件与主机上的不同：不应从头读取已有内容（读到 %s）", b[0].URI)
	default:
	}
	appendFile(t, path, 5, 6)
	if evs := collectDone(t, m, 1); evs[0].URI != "/p5" {
		t.Fatalf("应从末尾开始读新写入的日志: %s", evs[0].URI)
	}
	time.Sleep(600 * time.Millisecond)
	cancel()
	if err := cps.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readCheckpoints(t, ckpt)[path]; got.Foreign || got.PrefixLen == 0 {
		t.Fatalf("本机读过之后断点应换成本机的: %+v", got)
	}
	// 损坏的断点文件：删除
	if err := os.WriteFile(ckpt, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MarkForeign(ckpt); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ckpt); !os.IsNotExist(err) {
		t.Fatal("损坏的断点文件应删除")
	}
}

// 保存失败时保留待保存标记，下次保存重试；没有变化但很久未刷新的断点刷新更新时间（仍在跟踪的文件不会因 30 天未更新被丢弃）。
func TestCheckpointSaveRetryAndRefresh(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Checkpoints{path: filepath.Join(blocker, "sub", CheckpointFile), m: map[string]checkpoint{}}
	c.set("/a.log", checkpoint{Offset: 10, PrefixLen: 4, Prefix: "p"})
	if err := c.Save(); err == nil {
		t.Fatal("父路径是文件时保存应失败")
	}
	c.path = filepath.Join(dir, CheckpointFile)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readCheckpoints(t, c.path)["/a.log"]; got.Offset != 10 {
		t.Fatalf("上次保存失败后应重试写入: %+v", got)
	}
	if _, err := os.Stat(c.path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("不应留下临时文件")
	}
	// 没有变化：不重写；更新时间超过一天：刷新
	c.set("/a.log", checkpoint{Offset: 10, PrefixLen: 4, Prefix: "p"})
	if c.dirty {
		t.Fatal("位置没有变化时不应标记待保存")
	}
	c.mu.Lock()
	old := c.m["/a.log"]
	old.Updated = time.Now().Add(-25 * time.Hour)
	c.m["/a.log"] = old
	c.mu.Unlock()
	c.set("/a.log", checkpoint{Offset: 10, PrefixLen: 4, Prefix: "p"})
	if !c.dirty || time.Since(c.m["/a.log"].Updated) > time.Minute {
		t.Fatal("超过一天未刷新的断点应刷新更新时间")
	}
}
