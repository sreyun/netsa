// Package forward 把告警转发到外部 SIEM（syslog：CEF / JSON / RFC 5424）。
//
// 转发不能影响检测：每个目标有独立的有界队列和协程，目标不可用时自动重连，队列满时丢弃并计数。
// 告警内容大多来自攻击者控制的日志，所有格式都做了转义，防止换行或分隔符伪造出额外的日志。
package forward

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

const (
	queueSize    = 10000
	maxMessage   = 8192 // UDP 不能分片太多，单条消息的上限；超过时截断证据
	writeTimeout = 5 * time.Second
	dialTimeout  = 5 * time.Second
	maxBackoff   = time.Minute
)

// Stat 是一个转发目标的状态。
type Stat struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	Protocol  string    `json:"protocol"`
	Format    string    `json:"format"`
	Sent      int64     `json:"sent"`
	Dropped   int64     `json:"dropped"`
	Failed    int64     `json:"failed"`
	Queued    int       `json:"queued"`
	Connected bool      `json:"connected"`
	LastError string    `json:"last_error,omitempty"`
	LastSent  time.Time `json:"last_sent,omitzero"`
}

type target struct {
	cfg      config.ForwardConfig
	min      model.Severity
	tlsConf  *tls.Config
	queue    chan []byte
	host     string
	version  string
	sent     atomic.Int64
	dropped  atomic.Int64
	failed   atomic.Int64
	conn     atomic.Bool
	lastErr  atomic.Pointer[string]
	lastSent atomic.Int64
}

// Forwarder 管理所有转发目标。
type Forwarder struct{ targets []*target }

// New 按配置创建转发器；没有配置时返回 nil（方法对 nil 安全）。
func New(cfgs []config.ForwardConfig, version string) (*Forwarder, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}
	host, _ := os.Hostname()
	host = sanitizeToken(host)
	f := &Forwarder{}
	for _, c := range cfgs {
		if c.Protocol == "" {
			c.Protocol = "tls"
		}
		if c.Format == "" {
			c.Format = "cef"
		}
		if c.Name == "" {
			c.Name = c.Address
		}
		min := model.SevLow
		if c.MinLevel != "" {
			s, ok := model.TryParseSeverity(c.MinLevel)
			if !ok {
				return nil, fmt.Errorf("forward %s: min_level %q 无法识别", c.Name, c.MinLevel)
			}
			min = s
		}
		t := &target{cfg: c, min: min, queue: make(chan []byte, queueSize), host: host, version: version}
		if c.Protocol == "tls" {
			hostname, _, _ := net.SplitHostPort(c.Address)
			t.tlsConf = &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}
			if c.CAFile != "" {
				pem, err := os.ReadFile(c.CAFile)
				if err != nil {
					return nil, fmt.Errorf("forward %s: %w", c.Name, err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("forward %s: CA 证书无效", c.Name)
				}
				t.tlsConf.RootCAs = pool
			}
		}
		f.targets = append(f.targets, t)
	}
	return f, nil
}

// Start 启动转发协程。
func (f *Forwarder) Start(ctx context.Context) {
	if f == nil {
		return
	}
	for _, t := range f.targets {
		go t.run(ctx)
	}
}

// Send 把告警放入各目标的队列，不阻塞。
func (f *Forwarder) Send(a *model.Alert) {
	if f == nil || a == nil {
		return
	}
	for _, t := range f.targets {
		if a.Severity < t.min {
			continue
		}
		msg := Format(t.cfg.Format, a, t.host, t.version)
		select {
		case t.queue <- msg:
		default:
			t.dropped.Add(1)
		}
	}
}

// Stats 返回各目标的状态。
func (f *Forwarder) Stats() []Stat {
	if f == nil {
		return nil
	}
	out := make([]Stat, 0, len(f.targets))
	for _, t := range f.targets {
		s := Stat{Name: t.cfg.Name, Address: t.cfg.Address, Protocol: t.cfg.Protocol, Format: t.cfg.Format, Sent: t.sent.Load(), Dropped: t.dropped.Load(),
			Failed: t.failed.Load(), Queued: len(t.queue), Connected: t.conn.Load()}
		if e := t.lastErr.Load(); e != nil {
			s.LastError = *e
		}
		if n := t.lastSent.Load(); n > 0 {
			s.LastSent = time.Unix(n, 0)
		}
		out = append(out, s)
	}
	return out
}

func (t *target) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	switch t.cfg.Protocol {
	case "udp":
		return d.DialContext(ctx, "udp", t.cfg.Address)
	case "tcp":
		return d.DialContext(ctx, "tcp", t.cfg.Address)
	}
	td := tls.Dialer{NetDialer: &d, Config: t.tlsConf}
	return td.DialContext(ctx, "tcp", t.cfg.Address)
}

func (t *target) run(ctx context.Context) {
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	backoff := time.Second
	var pending []byte
	for {
		if pending == nil {
			select {
			case <-ctx.Done():
				return
			case pending = <-t.queue:
			}
		}
		if conn == nil {
			c, err := t.dial(ctx)
			if err != nil {
				t.fail(err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, maxBackoff)
				continue
			}
			conn, backoff = c, time.Second
			t.conn.Store(true)
			log.Printf("[forward] 已连接 %s（%s %s）", t.cfg.Name, t.cfg.Protocol, t.cfg.Address)
		}
		conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := conn.Write(pending); err != nil {
			// 连接断开时这条消息保留，重连后重发；TCP 下对端可能收到重复消息，SIEM 可按事件编号去重
			t.fail(err)
			conn.Close()
			conn = nil
			t.conn.Store(false)
			continue
		}
		pending = nil
		t.sent.Add(1)
		t.lastSent.Store(time.Now().Unix())
	}
}

func (t *target) fail(err error) {
	t.failed.Add(1)
	msg := err.Error()
	if prev := t.lastErr.Swap(&msg); prev == nil || *prev != msg {
		log.Printf("[forward] 转发到 %s 失败: %v", t.cfg.Name, err)
	}
}

// ErrFormat 表示格式名称无效。
var ErrFormat = errors.New("未知的转发格式")

// Format 把告警编码为一行消息（以换行结尾）。
func Format(format string, a *model.Alert, host, version string) []byte {
	var line string
	switch format {
	case "json":
		line = jsonBody(a)
	case "rfc5424":
		line = syslogHeader(a, host) + jsonBody(a)
	default:
		line = syslogHeader(a, host) + cef(a, version)
	}
	if len(line) > maxMessage-1 {
		line = clipUTF8(line, maxMessage-1)
	}
	return []byte(line + "\n")
}

// severityRFC 把等级映射为 syslog 严重性：严重 2、高危 3、中危 4、低危 5、信息 6。
func severityRFC(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 2
	case model.SevHigh:
		return 3
	case model.SevMedium:
		return 4
	case model.SevLow:
		return 5
	}
	return 6
}

func syslogHeader(a *model.Alert, host string) string {
	if host == "" {
		host = "-"
	}
	// facility 4（security/auth）
	return "<" + strconv.Itoa(4*8+severityRFC(a.Severity)) + ">1 " + a.Time.UTC().Format(time.RFC3339) + " " + host + " netsa - " + strconv.FormatUint(a.ID, 10) + " - "
}

type jsonAlert struct {
	ID         uint64    `json:"id"`
	Time       time.Time `json:"time"`
	SrcIP      string    `json:"src_ip"`
	Location   string    `json:"location,omitempty"`
	RuleID     string    `json:"rule_id"`
	Name       string    `json:"name"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	Phase      string    `json:"phase,omitempty"`
	Result     string    `json:"result,omitempty"`
	Proven     bool      `json:"proven,omitempty"`
	Target     string    `json:"target,omitempty"`
	Method     string    `json:"method,omitempty"`
	Status     int       `json:"status,omitempty"`
	Evidence   string    `json:"evidence,omitempty"`
	UA         string    `json:"ua,omitempty"`
	Source     string    `json:"source,omitempty"`
	IncidentID uint64    `json:"incident_id,omitempty"`
	Asset      string    `json:"asset,omitempty"`
	Vuln       string    `json:"vuln,omitempty"`
}

func jsonBody(a *model.Alert) string {
	b, err := json.Marshal(jsonAlert{ID: a.ID, Time: a.Time, SrcIP: a.SrcIP, Location: a.Location, RuleID: a.RuleID, Name: a.Name, Category: a.Category,
		Severity: a.Severity.String(), Phase: a.Phase, Result: a.Result, Proven: a.Proven, Target: a.Target, Method: a.Method, Status: a.Status,
		Evidence: a.Evidence, UA: a.UA, Source: a.Source, IncidentID: a.IncidentID, Asset: a.Asset, Vuln: a.Vuln})
	if err != nil {
		return `{"error":"encode"}`
	}
	return string(b)
}

// cefSeverity 把等级映射为 CEF 的 0~10。
func cefSeverity(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 10
	case model.SevHigh:
		return 8
	case model.SevMedium:
		return 5
	case model.SevLow:
		return 3
	}
	return 1
}

var (
	cefHeader = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ")
	cefValue  = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r", `\r`, "\n", `\n`)
)

func cef(a *model.Alert, version string) string {
	var b strings.Builder
	b.WriteString("CEF:0|netsa|netsa|")
	b.WriteString(cefHeader.Replace(version))
	b.WriteByte('|')
	b.WriteString(cefHeader.Replace(a.RuleID))
	b.WriteByte('|')
	b.WriteString(cefHeader.Replace(a.Name))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(cefSeverity(a.Severity)))
	b.WriteByte('|')
	ext := func(k, v string) {
		if v != "" {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(cefValue.Replace(v))
			b.WriteByte(' ')
		}
	}
	ext("rt", strconv.FormatInt(a.Time.UnixMilli(), 10))
	ext("src", a.SrcIP)
	ext("request", a.Target)
	ext("requestMethod", a.Method)
	ext("requestClientApplication", a.UA)
	ext("cat", a.Category)
	ext("outcome", a.Result)
	if a.Status != 0 {
		ext("cn1", strconv.Itoa(a.Status))
		ext("cn1Label", "httpStatus")
	}
	if a.IncidentID != 0 {
		ext("cn2", strconv.FormatUint(a.IncidentID, 10))
		ext("cn2Label", "incidentId")
	}
	ext("cs1", a.Phase)
	if a.Phase != "" {
		ext("cs1Label", "phase")
	}
	if a.Proven {
		ext("cs2", "true")
		ext("cs2Label", "proven")
	}
	ext("cs3", a.Asset)
	if a.Asset != "" {
		ext("cs3Label", "asset")
	}
	ext("cs4", a.Vuln)
	if a.Vuln != "" {
		ext("cs4Label", "vuln")
	}
	ext("msg", a.Evidence)
	return strings.TrimRight(b.String(), " ")
}

func sanitizeToken(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 32 || r >= 127 {
			return -1
		}
		return r
	}, s)
}

func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
