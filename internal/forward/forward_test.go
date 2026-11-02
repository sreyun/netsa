package forward

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

func sample() *model.Alert {
	return &model.Alert{ID: 7, Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), SrcIP: "203.0.113.9", RuleID: "sqli|union", Name: "注入|攻击", Category: "SQL注入",
		Severity: model.SevCritical, Phase: "exploit", Result: "success", Proven: true, Target: "a.example.com /x?a=1", Method: "GET", Status: 200,
		Evidence: "evil\nCEF:0|forged|log=1\\", UA: "ua\r\nInjected: 1", IncidentID: 3}
}

// 日志内容由攻击者控制：不能用换行或分隔符伪造出额外的日志。
func TestFormatEscapesInjection(t *testing.T) {
	for _, f := range []string{"cef", "json", "rfc5424"} {
		line := string(Format(f, sample(), "host", "1.7.0"))
		if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 || strings.Contains(line, "\r") {
			t.Errorf("%s 必须只有一行: %q", f, line)
		}
	}
	c := string(Format("cef", sample(), "host", "1.7.0"))
	for _, want := range []string{"<34>1 2026-01-02T03:04:05Z host netsa - 7 - CEF:0|netsa|netsa|1.7.0|sqli\\|union|注入\\|攻击|10|", "src=203.0.113.9", `request=a.example.com /x?a\=1`,
		`msg=evil\nCEF:0|forged|log\=1\\`, "cn1=200", "cn2=3", "cs2=true"} {
		if !strings.Contains(c, want) {
			t.Errorf("CEF 缺少 %q: %s", want, c)
		}
	}
	var got map[string]any
	if err := json.Unmarshal(Format("json", sample(), "h", "v"), &got); err != nil || got["severity"] != "critical" || got["src_ip"] != "203.0.113.9" || got["proven"] != true {
		t.Errorf("JSON: %v %v", got, err)
	}
}

func TestFormatTruncates(t *testing.T) {
	a := sample()
	a.Evidence = strings.Repeat("攻", 20000)
	for _, f := range []string{"cef", "json", "rfc5424"} {
		if b := Format(f, a, "h", "v"); len(b) > maxMessage || !strings.HasSuffix(string(b), "\n") {
			t.Errorf("%s: %d", f, len(b))
		}
	}
}

func TestNilSafe(t *testing.T) {
	f, err := New(nil, "v")
	if f != nil || err != nil {
		t.Fatal("没有配置应返回 nil")
	}
	f.Start(context.Background())
	f.Send(sample())
	if f.Stats() != nil {
		t.Fatal("nil 没有状态")
	}
}

// TCP：按等级过滤、发送、对端重启后自动重连。
func TestTCPDeliveryAndReconnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	f, err := New([]config.ForwardConfig{{Name: "s", Address: addr, Protocol: "tcp", Format: "json", MinLevel: "high"}}, "v")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	lines := make(chan string, 16)
	accept := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					lines <- sc.Text()
				}
				c.Close()
			}()
		}
	}
	go accept(ln)
	low := sample()
	low.Severity, low.ID = model.SevLow, 1
	f.Send(low)
	high := sample()
	high.Severity, high.ID = model.SevHigh, 2
	f.Send(high)
	select {
	case l := <-lines:
		if !strings.Contains(l, `"id":2`) {
			t.Fatalf("低于最低等级的不应转发: %s", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("没有收到消息")
	}
	if s := f.Stats()[0]; s.Sent != 1 || !s.Connected {
		t.Fatalf("状态: %+v", s)
	}
}

func TestUDPDelivery(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	f, err := New([]config.ForwardConfig{{Address: pc.LocalAddr().String(), Protocol: "udp"}}, "v")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Start(ctx)
	f.Send(sample())
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 9000)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "CEF:0|netsa") {
		t.Fatalf("UDP: %q %v", buf[:n], err)
	}
}

// 目标不可用时不阻塞检测：队列满后丢弃并计数。
func TestQueueFullDropsWithoutBlocking(t *testing.T) {
	f, err := New([]config.ForwardConfig{{Address: "127.0.0.1:1", Protocol: "tcp"}}, "v")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < queueSize+50; i++ {
			f.Send(sample())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Send 不应阻塞")
	}
	if s := f.Stats()[0]; s.Dropped != 50 {
		t.Fatalf("应丢弃 50 条: %+v", s)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New([]config.ForwardConfig{{Address: "a:1", MinLevel: "bad"}}, "v"); err == nil {
		t.Error("等级无效应报错")
	}
	if _, err := New([]config.ForwardConfig{{Address: "a:1", CAFile: "/no/such"}}, "v"); err == nil {
		t.Error("CA 文件不存在应报错")
	}
}
