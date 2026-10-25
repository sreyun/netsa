// Package mailer 通过 SMTP 发送 HTML 邮件（周报、月报、合规报告），支持 SSL（465）与 STARTTLS（587），
// 报告同时作为 HTML 附件，便于归档或在浏览器中打印为 PDF。
package mailer

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config 是 SMTP 配置。
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // ssl / starttls / none；为空时 465 端口为 ssl，其余为 starttls
	Insecure bool   // 跳过服务器证书校验（仅用于内网自签名证书的邮件服务器）
}

// Mode 返回生效的加密方式。
func (c Config) Mode() string {
	if c.TLS != "" {
		return c.TLS
	}
	if c.Port == 465 {
		return "ssl"
	}
	return "starttls"
}

// Enabled 判断是否已配置。
func (c Config) Enabled() bool { return c.Host != "" && c.From != "" }

// Attachment 是邮件附件。
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// ErrHeader 表示收件人或主题中包含换行等非法字符（防止邮件头注入）。
var ErrHeader = errors.New("邮件地址或主题包含非法字符")

func clean(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", ErrHeader
	}
	return strings.TrimSpace(s), nil
}

// ParseAddresses 校验收件人地址。
func ParseAddresses(list []string) ([]string, error) {
	var out []string
	for _, a := range list {
		a, err := clean(a)
		if err != nil {
			return nil, err
		}
		if a == "" {
			continue
		}
		addr, err := mail.ParseAddress(a)
		if err != nil {
			return nil, fmt.Errorf("收件人地址无效: %q", a)
		}
		out = append(out, addr.Address)
	}
	if len(out) == 0 {
		return nil, errors.New("没有有效的收件人")
	}
	return out, nil
}

func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteString("\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

// Build 生成 MIME 邮件（HTML 正文 + 附件）。
func Build(from string, to []string, subject, html string, atts []Attachment, now time.Time) ([]byte, error) {
	from, err := clean(from)
	if err != nil {
		return nil, err
	}
	if subject, err = clean(subject); err != nil {
		return nil, err
	}
	fa, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("发件人地址无效: %q", from)
	}
	rb := make([]byte, 12)
	rand.Read(rb)
	boundary := "netsa-" + hex.EncodeToString(rb)
	domain := "netsa"
	if i := strings.LastIndexByte(fa.Address, '@'); i >= 0 {
		domain = fa.Address[i+1:]
	}
	var b bytes.Buffer
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", fa.String())
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", mime.BEncoding.Encode("UTF-8", subject))
	hdr("Date", now.Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(rb)+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	b.WriteString("\r\n--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(wrap76(base64.StdEncoding.EncodeToString([]byte(html))))
	for _, a := range atts {
		name, err := clean(a.Name)
		if err != nil {
			return nil, err
		}
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		b.WriteString("\r\n--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + ct + `; name="` + mime.BEncoding.Encode("UTF-8", name) + `"` + "\r\n")
		b.WriteString("Content-Disposition: attachment; filename*=UTF-8''" + url.PathEscape(name) + "\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(wrap76(base64.StdEncoding.EncodeToString(a.Data)))
	}
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return b.Bytes(), nil
}

// Send 发送邮件。整个会话最长 60 秒。
func Send(c Config, to []string, subject, html string, atts []Attachment) error {
	if !c.Enabled() {
		return errors.New("未配置邮件服务器（report.smtp.host / from）")
	}
	to, err := ParseAddresses(to)
	if err != nil {
		return err
	}
	msg, err := Build(c.From, to, subject, html, atts, time.Now())
	if err != nil {
		return err
	}
	port := c.Port
	if port == 0 {
		port = map[string]int{"ssl": 465, "none": 25}[c.Mode()]
		if port == 0 {
			port = 587
		}
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	tc := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.Insecure}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if c.Mode() == "ssl" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tc)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("连接邮件服务器 %s 失败: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("邮件服务器握手失败: %w", err)
	}
	defer cl.Close()
	if err := cl.Hello("netsa"); err != nil {
		return err
	}
	if c.Mode() == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("邮件服务器不支持 STARTTLS（可将 report.smtp.tls 设为 ssl，或在内网中设为 none）")
		}
		if err := cl.StartTLS(tc); err != nil {
			return fmt.Errorf("STARTTLS 失败: %w", err)
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("邮件服务器认证失败: %w", err)
		}
	}
	fa, _ := mail.ParseAddress(c.From)
	if err := cl.Mail(fa.Address); err != nil {
		return fmt.Errorf("发件人被拒绝: %w", err)
	}
	for _, r := range to {
		if err := cl.Rcpt(r); err != nil {
			return fmt.Errorf("收件人 %s 被拒绝: %w", r, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("邮件发送失败: %w", err)
	}
	return cl.Quit()
}
