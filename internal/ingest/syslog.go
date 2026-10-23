package ingest

import (
	"bufio"
	"context"
	"log"
	"net"
	"regexp"
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
		}
		p, _ = parser.NewAuto("auto", "")
		ss.parsers[remote] = p
	}
	return p
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

var reOctetCount = regexp.MustCompile(`^\d+ <`)

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
			for {
				conn, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				go func(c net.Conn) {
					defer c.Close()
					go func() {
						<-ctx.Done()
						c.Close()
					}()
					host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
					sc := bufio.NewScanner(c)
					sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
					for sc.Scan() {
						line := sc.Text()
						if reOctetCount.MatchString(line) {
							line = line[strings.IndexByte(line, ' ')+1:]
						}
						ss.handleLine(ctx, host, line)
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
	ss := &syslogSource{source: s, parsers: map[string]*parser.Auto{}, events: make(chan *model.Event, 8192)}
	s.detectFn = ss.detected
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
		select {
		case ss.events <- ev:
		case <-ctx.Done():
		}
	}
}
