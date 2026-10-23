package ingest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/parser"
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

	// 重命名轮转（Windows 上被打开的文件无法重命名，跳过该步骤）。
	// 模拟 nginx：轮转后、收到重新打开日志的信号前，仍向旧文件写入，这部分内容不能丢失。
	if err := os.Rename(path, path+".1"); err == nil {
		time.Sleep(1500 * time.Millisecond) // 等待轮询发现轮转
		appendFile(t, path+".1", 15, 17)    // 写入旧文件
		appendFile(t, path, 20, 22)         // 新文件
		evs = collect(t, m.Out, 4)
		got := map[string]bool{}
		for _, ev := range evs {
			got[ev.URI] = true
		}
		for _, want := range []string{"/p15", "/p16", "/p20", "/p21"} {
			if !got[want] {
				t.Fatalf("轮转后缺少 %s: %v", want, got)
			}
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

// 通配符同时匹配当前日志与轮转后的旧文件（access.log*）时，旧文件不能被当作新文件从头重复读取。
func TestRotatedFileNotReread(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	appendFile(t, path, 0, 2)
	m := NewManager(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.StartSource(ctx, config.SourceConfig{Name: "t", Type: "auto", Paths: []string{filepath.Join(dir, "access.log*")}, FromBeginning: true}); err != nil {
		t.Fatal(err)
	}
	collect(t, m.Out, 2)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Skip("当前平台无法重命名已打开的文件")
	}
	appendFile(t, path, 2, 3)
	collect(t, m.Out, 1)
	time.Sleep(11 * time.Second) // 等待通配符重新扫描（每 10 秒）
	select {
	case batch := <-m.Out:
		t.Fatalf("轮转后的旧文件被重复读取: %d 条", len(batch))
	case <-time.After(500 * time.Millisecond):
	}
}

// syslog TCP：octet-counting（消息间无换行）、换行分隔与二者混用都能正确切分，超长消息截断而不中断连接。
func TestSyslogTCPFraming(t *testing.T) {
	ufw := func(port int) string {
		return fmt.Sprintf("<4>Oct 22 10:15:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=%d", port)
	}
	var payload strings.Builder
	for _, p := range []int{21, 22} { // octet-counting，连续发送不带换行
		m := ufw(p)
		fmt.Fprintf(&payload, "%d %s", len(m), m)
	}
	payload.WriteString(ufw(23) + "\n")                                       // 换行分隔
	payload.WriteString("<4>" + strings.Repeat("x", MaxLineBytes+100) + "\n") // 超长行
	m := ufw(25)
	fmt.Fprintf(&payload, "%d %s\n", len(m), m) // octet-counting 后跟换行

	fr := &frameReader{r: bufio.NewReader(strings.NewReader(payload.String()))}
	var got []string
	for {
		msg, err := fr.next()
		if msg != "" {
			got = append(got, msg)
		}
		if err != nil {
			break
		}
	}
	if len(got) != 5 {
		t.Fatalf("应切分出 5 条消息，实际 %d", len(got))
	}
	for i, port := range map[int]int{0: 21, 1: 22, 2: 23, 4: 25} {
		if !strings.HasSuffix(got[i], fmt.Sprintf("DPT=%d", port)) {
			t.Errorf("第 %d 条错误: %.80s", i, got[i])
		}
	}
	if len(got[3]) != MaxLineBytes {
		t.Errorf("超长消息应截断为 %d 字节，实际 %d", MaxLineBytes, len(got[3]))
	}
}

// 时区偏差自动校正：日志按 UTC 记录却按 UTC+8 解析时整体慢 8 小时，连续观测一致后自动校正；恢复正常后撤销。
func TestTimeFix(t *testing.T) {
	f := &timeFix{name: "t"}
	now := time.Now()
	ev := func(raw time.Time) *model.Event { return &model.Event{Time: raw} }
	var last *model.Event
	for i := 0; i < tzStreak; i++ {
		last = ev(now.Add(-8*time.Hour - time.Duration(i)*time.Second)) // 慢 8 小时，带少量写入延迟
		f.apply(last, now)
	}
	if f.current() != 8*time.Hour || now.Sub(last.Time) > time.Minute {
		t.Fatalf("应校正 +8 小时: offset=%v 校正后偏差=%v", f.current(), now.Sub(last.Time))
	}
	// 日志恢复正确时间后撤销校正
	for i := 0; i < tzStreak; i++ {
		f.apply(ev(now.Add(-time.Duration(i)*time.Second)), now)
	}
	if f.current() != 0 {
		t.Fatalf("应撤销校正: %v", f.current())
	}
	// 回放的历史日志延迟不固定，不能触发校正
	g := &timeFix{name: "h"}
	for i := 0; i < 200; i++ {
		g.apply(ev(now.Add(-time.Duration(i)*7*time.Minute)), now)
	}
	if g.current() != 0 {
		t.Fatalf("历史日志不应触发校正: %v", g.current())
	}
	if describeOffset(8*time.Hour) != "+8 小时" || describeOffset(-330*time.Minute) != "-5 小时 30 分钟" {
		t.Fatal("describeOffset")
	}
}

// 端到端：syslog 发送端按 UTC 记录、timezone 为 Asia/Shanghai 时，校正后事件时间与实际时间一致。
func TestSyslogTimeCorrection(t *testing.T) {
	sh, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	old := parser.Location
	parser.Location = sh
	defer func() { parser.Location = old }()

	m := NewManager(1000)
	m.AutoTime = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := "127.0.0.1:15515"
	if err := m.StartSyslog(ctx, config.SyslogConfig{Enabled: true, UDP: addr}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	n := tzStreak + 5
	for i := 0; i < n; i++ {
		ts := time.Now().UTC().Format("Jan _2 15:04:05") // 设备按 UTC 记录，不带时区
		fmt.Fprintf(conn, "<4>%s fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=%d", ts, 1000+i)
		time.Sleep(2 * time.Millisecond)
	}
	evs := collect(t, m.Out, n)
	lastEv := evs[len(evs)-1]
	if d := time.Since(lastEv.Time); d < -time.Minute || d > time.Minute {
		t.Fatalf("校正后时间仍偏差 %v", d)
	}
	if first := evs[0]; time.Since(first.Time) < 7*time.Hour {
		t.Fatalf("前几条（校正生效前）应保持原始解析结果: %v", time.Since(first.Time))
	}
	if st := m.Stats()[0]; !strings.Contains(st.TimeOffset, "+8 小时") {
		t.Fatalf("数据源状态应显示校正: %+v", st)
	}
}
