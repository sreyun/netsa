package ingest

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/parser"
)

// syslogSource 为每个发送端各自维护一个自动识别解析器，避免多种设备日志互相干扰格式锁定。
type syslogSource struct {
	*source
	mu      sync.RWMutex
	parsers map[string]*parser.Auto
	fixes   map[string]*timeFix // 每个发送端独立校正时区偏差（不同设备的时钟 / 时区可能不同）
	auto    bool
	events  chan *model.Event
}

func (ss *syslogSource) parserFor(remote string) *parser.Auto {
	ss.mu.RLock()
	p := ss.parsers[remote]
	ss.mu.RUnlock()
	if p != nil {
		return p
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if p = ss.parsers[remote]; p == nil {
		if len(ss.parsers) > 4096 {
			ss.parsers = map[string]*parser.Auto{}
			ss.fixes = map[string]*timeFix{}
		}
		p, _ = parser.NewAuto("auto", "")
		ss.parsers[remote] = p
		ss.fixes[remote] = &timeFix{name: ss.name + " 发送端 " + remote}
	}
	return p
}

// offsets 汇总各发送端的时区校正情况，例如 "198.51.100.9 +8 小时"。
func (ss *syslogSource) offsets() string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	var out []string
	for remote, f := range ss.fixes {
		if d := describeOffset(f.current()); d != "" {
			out = append(out, remote+" "+d)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "；")
}

// detected 汇总各发送端识别出的格式，例如 "netfilter, kv_firewall"。
func (ss *syslogSource) detected() string {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	seen := map[string]bool{}
	for _, p := range ss.parsers {
		if d := p.Detected(); d != "" {
			seen[d] = true
		}
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// StartSyslog 启动 UDP / TCP syslog 接收（RFC3164 / RFC5424 / RFC6587 octet-counting）。
func (m *Manager) StartSyslog(ctx context.Context, cfg config.SyslogConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.UDP != "" {
		pc, err := net.ListenPacket("udp", cfg.UDP)
		if err != nil {
			return err
		}
		// 增大内核接收缓冲区，吸收设备日志的突发流量，减少丢包（受系统 rmem_max 限制）
		if uc, ok := pc.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(16 << 20)
		}
		ss := m.newSyslogSource(ctx, "syslog-udp", cfg.UDP)
		go func() {
			<-ctx.Done()
			pc.Close()
		}()
		for i := 0; i < 4; i++ {
			go func() {
				buf := make([]byte, 64*1024)
				for {
					n, addr, err := pc.ReadFrom(buf)
					if err != nil {
						if ctx.Err() != nil {
							return
						}
						log.Printf("[syslog] UDP 读取失败: %v", err)
						time.Sleep(100 * time.Millisecond)
						continue
					}
					host, _, _ := net.SplitHostPort(addr.String())
					for _, line := range strings.Split(string(buf[:n]), "\n") {
						if line = strings.TrimSpace(line); line != "" {
							ss.handleLine(ctx, host, line)
						}
					}
				}
			}()
		}
		log.Printf("[syslog] UDP 监听 %s", cfg.UDP)
	}
	if cfg.TCP != "" {
		ln, err := net.Listen("tcp", cfg.TCP)
		if err != nil {
			return err
		}
		ss := m.newSyslogSource(ctx, "syslog-tcp", cfg.TCP)
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		go func() {
			slots := make(chan struct{}, maxTCPConns)
			for {
				conn, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					time.Sleep(50 * time.Millisecond) // 文件句柄耗尽等临时错误，避免空转
					continue
				}
				select {
				case slots <- struct{}{}:
				default:
					conn.Close() // 连接数已达上限，拒绝新连接，防止异常客户端耗尽资源
					continue
				}
				go func(c net.Conn) {
					defer func() { c.Close(); <-slots }()
					stop := context.AfterFunc(ctx, func() { c.Close() })
					defer stop()
					host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
					fr := &frameReader{r: bufio.NewReaderSize(&idleConn{c}, 64*1024)}
					for {
						msg, err := fr.next()
						if msg != "" {
							ss.handleLine(ctx, host, msg)
						}
						if err != nil {
							return
						}
					}
				}(conn)
			}
		}()
		log.Printf("[syslog] TCP 监听 %s", cfg.TCP)
	}
	return nil
}

func (m *Manager) newSyslogSource(ctx context.Context, name, addr string) *syslogSource {
	s, _ := m.add(name, addr, "auto", "", "")
	s.setStatus("listening", "")
	ss := &syslogSource{source: s, parsers: map[string]*parser.Auto{}, fixes: map[string]*timeFix{}, auto: m.AutoTime, events: make(chan *model.Event, 8192)}
	s.detectFn, s.offsetFn = ss.detected, ss.offsets
	go ss.batcher(ctx, m)
	return ss
}

// batcher 汇聚各接收协程解析出的事件，满一批或每 100ms 投递一次。
func (ss *syslogSource) batcher(ctx context.Context, m *Manager) {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ss.events:
			ss.batch = append(ss.batch, ev)
			if len(ss.batch) >= BatchSize {
				m.flush(ctx, ss.source)
			}
		case <-t.C:
			m.flush(ctx, ss.source)
		}
	}
}

func (ss *syslogSource) handleLine(ctx context.Context, remote, line string) {
	if ev := ss.parseLineWith(ss.parserFor(remote), line); ev != nil {
		if ss.auto {
			ss.mu.RLock()
			f := ss.fixes[remote]
			ss.mu.RUnlock()
			if f != nil {
				f.apply(ev, time.Now()) // syslog 均为实时推送
			}
		}
		ss.touch(ev)
		select {
		case ss.events <- ev:
		case <-ctx.Done():
		}
	}
}

const (
	maxTCPConns    = 1024             // syslog TCP 最大并发连接数
	tcpIdleTimeout = 15 * time.Minute // 连接空闲超过该时间即关闭，回收半开连接
)

// idleConn 在每次读取前刷新读超时，空闲连接到期后读取返回错误、连接被关闭。
type idleConn struct{ net.Conn }

func (c *idleConn) Read(p []byte) (int, error) {
	c.Conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
	return c.Conn.Read(p)
}

// frameReader 解析 syslog TCP 消息帧（RFC 6587）：
// octet-counting 形如 "123 <134>..."，按长度读取，消息之间可以没有换行；
// non-transparent-framing 以换行分隔。两种方式可在同一连接中混用。超长消息截断而不中断连接。
type frameReader struct {
	r   *bufio.Reader
	buf []byte
}

func (fr *frameReader) next() (string, error) {
	if n, ok := fr.octetLen(); ok {
		keep := min(n, MaxLineBytes)
		if cap(fr.buf) < keep {
			fr.buf = make([]byte, keep)
		}
		b := fr.buf[:keep]
		if _, err := io.ReadFull(fr.r, b); err != nil {
			return "", err
		}
		if n > keep {
			if _, err := fr.r.Discard(n - keep); err != nil {
				return "", err
			}
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	var line []byte
	for {
		chunk, err := fr.r.ReadSlice('\n')
		if room := MaxLineBytes - len(line); room > 0 {
			line = append(line, chunk[:min(len(chunk), room)]...)
		}
		switch {
		case err == nil:
			return strings.TrimSpace(string(line)), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return strings.TrimSpace(string(line)), err
		}
	}
}

// octetLen 识别 octet-counting 帧头：1~7 位数字 + 空格 + "<"（PRI 开始）。
func (fr *frameReader) octetLen() (int, bool) {
	head, _ := fr.r.Peek(9)
	n := 0
	for i, c := range head {
		switch {
		case c >= '0' && c <= '9' && i < 7:
			n = n*10 + int(c-'0')
		case c == ' ' && i > 0 && i+1 < len(head) && head[i+1] == '<' && n > 0:
			fr.r.Discard(i + 1)
			return n, true
		default:
			return 0, false
		}
	}
	return 0, false
}
