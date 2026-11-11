package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// 读取断点：重启后从上次读到的位置继续，停机期间写入的日志不丢、已读过的不重复；停机期间文件被轮转时从头读取新文件；
// 没有断点时保持原来的规则（从末尾开始）。
func TestCheckpointResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	ckpt := filepath.Join(dir, "ingest-offsets.json")
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
			evs = collect(t, m.Out, want)
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
	if evs := collect(t, m.Out, 2); evs[0].URI != "/p5" {
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
	var rerr error
	for i := 0; i < 50; i++ { // Windows：上一轮的跟踪协程退出后才释放文件
		if rerr = os.Rename(path, path+".1"); rerr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rerr != nil {
		t.Fatal(rerr)
	}
	appendFile(t, path, 100, 102)
	if evs := run(2); evs[0].URI != "/p100" {
		t.Fatalf("轮转后应从头读取新文件: %s", evs[0].URI)
	}
}

// 断点判断：同一个文件从断点继续；文件变短或开头变了从头读取；需要补读的内容过多时只读最新的部分。
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
	if pos, why := resumeAt(f, fi.Size(), checkpoint{Offset: 100, PrefixLen: n, Prefix: prefix}); pos != 100 || why == "" {
		t.Fatalf("同一文件应从断点继续: %d %s", pos, why)
	}
	if pos, _ := resumeAt(f, fi.Size(), checkpoint{Offset: fi.Size() + 10, PrefixLen: n, Prefix: prefix}); pos != 0 {
		t.Fatalf("文件变短应从头读取: %d", pos)
	}
	if pos, _ := resumeAt(f, fi.Size(), checkpoint{Offset: 100, PrefixLen: n, Prefix: "other"}); pos != 0 {
		t.Fatalf("开头不同应从头读取: %d", pos)
	}
	if pos, why := resumeAt(f, maxCatchup+500, checkpoint{Offset: 10, PrefixLen: n, Prefix: prefix}); pos != 500 || why == "" {
		t.Fatalf("补读过多时只读最新部分: %d", pos)
	}
	if _, why := resumeAt(f, fi.Size(), checkpoint{}); why != "" {
		t.Fatal("空断点不可用")
	}
}
