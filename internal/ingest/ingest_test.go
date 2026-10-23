package ingest

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

func line(i int) string {
	return fmt.Sprintf(`198.51.100.%d - - [22/Oct/2026:10:15:01 +0800] "GET /p%d HTTP/1.1" 200 5 "-" "ua"`+"\n", i%250+1, i)
}

func collect(t *testing.T, ch <-chan []*model.Event, n int) []*model.Event {
	t.Helper()
	var out []*model.Event
	timeout := time.After(10 * time.Second)
	for len(out) < n {
		select {
		case batch := <-ch:
			out = append(out, batch...)
		case <-timeout:
			t.Fatalf("只收到 %d/%d 条事件", len(out), n)
		}
	}
	return out
}

func appendFile(t *testing.T, path string, from, to int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for i := from; i < to; i++ {
		f.WriteString(line(i))
	}
	f.Close()
}

func TestTailAppendTruncateRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	appendFile(t, path, 0, 3)

	m := NewManager(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.StartSource(ctx, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{path}, FromBeginning: true}); err != nil {
		t.Fatal(err)
	}
	collect(t, m.Out, 3)

	// 追加，包含一条分两次写入的半行
	appendFile(t, path, 3, 5)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	l := line(5)
	f.WriteString(l[:20])
	f.Close()
	time.Sleep(700 * time.Millisecond)
	f, _ = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	f.WriteString(l[20:])
	f.Close()
	evs := collect(t, m.Out, 3)
	if evs[2].URI != "/p5" {
		t.Fatalf("半行拼接错误: %q", evs[2].URI)
	}

	// copytruncate
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	appendFile(t, path, 10, 11)
	if ev := collect(t, m.Out, 1)[0]; ev.URI != "/p10" {
		t.Fatalf("截断后读取错误: %q", ev.URI)
	}

	// 重命名轮转（Windows 上被打开的文件无法重命名，跳过该步骤）
	if err := os.Rename(path, path+".1"); err == nil {
		appendFile(t, path, 20, 22)
		evs = collect(t, m.Out, 2)
		if evs[0].URI != "/p20" {
			t.Fatalf("轮转后读取错误: %q", evs[0].URI)
		}
	}
	st := m.Stats()[0]
	if st.Detected != "nginx" || st.Failed != 0 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestSyslogUDP(t *testing.T) {
	m := NewManager(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.StartSyslog(ctx, config.SyslogConfig{Enabled: true, UDP: "127.0.0.1:15514"}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", "127.0.0.1:15514")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, `<4>Oct 22 10:15:01 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22 SYN`)
	fmt.Fprint(conn, `<189>date=2026-10-22 time=10:15:02 srcip=198.51.100.10 dstip=10.0.0.2 dstport=3389 proto=6 action="deny"`)
	evs := collect(t, m.Out, 2)
	if evs[0].Format != "netfilter" || evs[0].DstPort != 22 || evs[1].Format != "kv_firewall" || evs[1].DstPort != 3389 {
		t.Fatalf("%+v %+v", evs[0], evs[1])
	}
}

func TestLineReaderLongLines(t *testing.T) {
	long := strings.Repeat("A", MaxLineBytes*2)
	lr := newLineReader(strings.NewReader("short\n" + long + "\nnext\ntail-without-newline"))
	var lines []string
	for {
		l, _, ok, _ := lr.next()
		if !ok {
			break
		}
		lines = append(lines, l)
	}
	if last, ok := lr.flush(); ok {
		lines = append(lines, last)
	}
	if len(lines) != 4 || lines[0] != "short" || len(lines[1]) != MaxLineBytes || lines[2] != "next" || lines[3] != "tail-without-newline" {
		t.Fatalf("超长行处理错误: n=%d len1=%d", len(lines), len(lines[1]))
	}
}

// 启动时尚不存在、之后才创建的文件应从头读取。
func TestTailFileCreatedLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "late.log")
	m := NewManager(10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.StartSource(ctx, config.SourceConfig{Name: "late", Type: "nginx", Paths: []string{path}, FromBeginning: false}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	appendFile(t, path, 0, 2)
	if evs := collect(t, m.Out, 2); evs[0].URI != "/p0" {
		t.Fatalf("应从头读取新文件: %q", evs[0].URI)
	}
}
