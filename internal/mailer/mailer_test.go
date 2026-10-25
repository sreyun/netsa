package mailer

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeSMTP 是一个最小的 SMTP 服务器，记录收到的邮件。
func fakeSMTP(t *testing.T) (string, chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { c.Write([]byte(s + "\r\n")) }
		say("220 fake ESMTP")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250-fake\r\n250 8BITMIME")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				data.WriteString(cmd + "\n")
				say("250 ok")
			case cmd == "DATA":
				say("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				say("250 queued")
			case cmd == "QUIT":
				say("221 bye")
				got <- data.String()
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestSend(t *testing.T) {
	addr, got := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	cfg := Config{Host: host, Port: p, From: "netsa <soc@example.com>", TLS: "none"}
	html := "<h1>安全周报</h1><p>本周共 12 条告警</p>"
	if err := Send(cfg, []string{"a@example.com", "张三 <b@example.com>"}, "netsa 安全周报 2026-10-19 ~ 10-25", html,
		[]Attachment{{Name: "netsa-周报.html", ContentType: "text/html; charset=UTF-8", Data: []byte(html)}}); err != nil {
		t.Fatal(err)
	}
	var msg string
	select {
	case msg = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("未收到邮件")
	}
	if !strings.Contains(msg, "MAIL FROM:<SOC@EXAMPLE.COM>") || !strings.Contains(msg, "RCPT TO:<B@EXAMPLE.COM>") || !strings.Contains(msg, "Subject: =?UTF-8?b?") ||
		!strings.Contains(msg, base64.StdEncoding.EncodeToString([]byte(html))[:40]) || !strings.Contains(msg, "filename*=UTF-8''netsa-%E5%91%A8") {
		t.Fatalf("邮件内容: %s", msg)
	}
}

func TestHeaderInjection(t *testing.T) {
	if _, err := Build("soc@example.com", []string{"a@example.com"}, "主题\r\nBcc: x@evil.com", "x", nil, time.Now()); err != ErrHeader {
		t.Fatalf("主题注入: %v", err)
	}
	if _, err := ParseAddresses([]string{"a@example.com\r\nBcc: x@evil.com"}); err != ErrHeader {
		t.Fatalf("收件人注入: %v", err)
	}
	if _, err := ParseAddresses([]string{"not-an-address"}); err == nil {
		t.Fatal("无效地址")
	}
	if err := Send(Config{Host: "127.0.0.1", Port: 1, From: "a@example.com", TLS: "none"}, []string{"b@example.com"}, "x", "x", nil); err == nil {
		t.Fatal("连接失败应报错")
	}
	if (Config{Port: 465}).Mode() != "ssl" || (Config{Port: 587}).Mode() != "starttls" {
		t.Fatal("加密方式")
	}
}
