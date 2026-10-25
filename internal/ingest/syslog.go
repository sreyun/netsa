package ingest

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// syslogSource 是一个 syslog 监听（UDP / TCP / TLS）。发送端画像（格式识别、时区校正、统计、访问控制）由 Senders 统一维护，
// 同一设备经不同协议发送时共用一份画像。
type syslogSource struct {
	*source
	senders *Senders
	proto   int
	auto    bool
	events  chan *model.Event
}

// offsets 汇总经该监听发送日志的各发送端的时区校正情况，例如 "198.51.100.9 +8 小时"。
func (ss *syslogSource) offsets() string {
	var out []string
	for _, st := range ss.senders.byProto(ss.proto) {
		if d := describeOffset(st.fix.current()); d != "" {
			out = append(out, st.ip+" "+d)
		}
	}
	sort.Strings(out)
	if n := len(out); n > 20 {
		out = append(out[:20], fmt.Sprintf("等 %d 个发送端", n))
	}
	return strings.Join(out, "；")
}

// detected 汇总各发送端识别出的格式，例如 "netfilter, kv_firewall"。
func (ss *syslogSource) detected() string {
	seen := map[string]bool{}
	for _, st := range ss.senders.byProto(ss.proto) {
		if d := st.detected(); d != "" {
			seen[d] = true
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// byProto 返回经指定协议发送过日志的发送端。
func (s *Senders) byProto(proto int) []*senderStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*senderStat, 0, len(s.stats))
	for _, st := range s.stats {
		if st.protos.Load()&uint32(proto) != 0 && st.lines.Load() > 0 {
			out = append(out, st)
		}
	}
	return out
}

// StartSyslog 启动 UDP / TCP / TLS syslog 接收（RFC 3164 / RFC 5424 / RFC 6587 octet-counting / RFC 5425）。
// 发送端访问控制（白名单、阻止）在收到数据报或建立连接时即判定，被拒绝的 TCP / TLS 连接立即关闭，不读取内容。
func (m *Manager) StartSyslog(ctx context.Context, cfg config.SyslogConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if m.Senders == nil {
		var err error
		if m.Senders, err = NewSenders(cfg, "", 0); err != nil {
			return err
		}
	}
	if cfg.UDP != "" {
		pc, err := net.ListenPacket("udp", cfg.UDP)
		if err != nil {
			return err
		}
		uc := pc.(*net.UDPConn)
		// 增大内核接收缓冲区，吸收设备日志的突发流量，减少丢包（受系统 rmem_max 限制）
		_ = uc.SetReadBuffer(16 << 20)
		ss := m.newSyslogSource(ctx, "syslog-udp", cfg.UDP, ProtoUDP)
		go func() {
			<-ctx.Done()
			uc.Close()
		}()
		for i := 0; i < 4; i++ {
			go func() {
				buf := make([]byte, 64*1024)
				for {
					n, ap, err := uc.ReadFromUDPAddrPort(buf)
					if err != nil {
						if ctx.Err() != nil {
							return
						}
						log.Printf("[syslog] UDP 读取失败: %v", err)
						time.Sleep(100 * time.Millisecond)
						continue
					}
					st, ok := ss.senders.admit(ap.Addr(), ProtoUDP, ss.name)
					if !ok {
						continue // 未授权的发送端：丢弃，不解析
					}
					st.bytes.Add(int64(n))
					sec := time.Now().Unix()
					for _, line := range strings.Split(string(buf[:n]), "\n") {
						if line = strings.TrimSpace(line); line != "" {
							ss.handleLine(ctx, st, line, sec)
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
		m.serveStream(ctx, ln, m.newSyslogSource(ctx, "syslog-tcp", cfg.TCP, ProtoTCP))
		log.Printf("[syslog] TCP 监听 %s", cfg.TCP)
	}
	if cfg.TLS != "" {
		tc, err := syslogTLSConfig(cfg)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", cfg.TLS)
		if err != nil {
			return err
		}
		m.serveStream(ctx, tls.NewListener(ln, tc), m.newSyslogSource(ctx, "syslog-tls", cfg.TLS, ProtoTLS))
		mode := "单向认证"
		if cfg.TLSClientCA != "" {
			mode = "双向认证，校验客户端证书"
		}
		log.Printf("[syslog] TLS 监听 %s（%s）", cfg.TLS, mode)
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Senders.Tick()
			}
		}
	}()
	return nil
}

func syslogTLSConfig(cfg config.SyslogConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("加载 syslog TLS 证书失败: %w", err)
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.TLSClientCA != "" {
		pem, err := os.ReadFile(cfg.TLSClientCA)
		if err != nil {
			return nil, fmt.Errorf("读取 syslog.tls_client_ca 失败: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("syslog.tls_client_ca 中没有有效的 PEM 证书")
		}
		tc.ClientCAs, tc.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

// serveStream 接收 TCP / TLS 连接：连接数有上限，未授权的发送端在握手前即被关闭；连接期间规则变化（如被阻止）后断开。
func (m *Manager) serveStream(ctx context.Context, ln net.Listener, ss *syslogSource) {
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
			var addr netip.Addr
			if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				addr = ta.AddrPort().Addr()
			}
			st, ok := ss.senders.admit(addr, ss.proto, ss.name)
			if !ok {
				conn.Close()
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
				if tc, ok := c.(*tls.Conn); ok {
					c.SetDeadline(time.Now().Add(10 * time.Second)) // 握手超时，防止慢速握手占用连接
					if err := tc.Handshake(); err != nil {
						st.rejected.Add(1)
						return
					}
					c.SetDeadline(time.Time{})
					if pc := tc.ConnectionState().PeerCertificates; len(pc) > 0 {
						st.mu.Lock()
						st.cert = cleanText(pc[0].Subject.String(), 120)
						st.mu.Unlock()
					}
				}
				fr := &frameReader{r: bufio.NewReaderSize(&idleConn{c}, 64*1024)}
				for {
					msg, err := fr.next()
					if msg != "" {
						if !ss.senders.permitted(st) {
							st.rejected.Add(1)
							return
						}
						st.bytes.Add(int64(len(msg)))
						ss.handleLine(ctx, st, msg, time.Now().Unix())
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
}

func (m *Manager) newSyslogSource(ctx context.Context, name, addr string, proto int) *syslogSource {
	s, _ := m.add(name, addr, "auto", "", "")
	s.group, s.silence = "syslog", -1 // UDP / TCP / TLS 监听合并判断断流：任一协议有日志即视为正常（单台设备的断流由发送端阈值判断）
	s.setStatus("listening", "")
	ss := &syslogSource{source: s, senders: m.Senders, proto: proto, auto: m.AutoTime, events: make(chan *model.Event, 8192)}
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

// handleLine 解析发送端的一条日志：超过单发送端速率上限的日志直接丢弃（计入限速丢弃数）。
func (ss *syslogSource) handleLine(ctx context.Context, st *senderStat, line string, sec int64) {
	if !st.take(ss.senders.rateLimit, sec) {
		return
	}
	n := st.lines.Add(1)
	if n == 1 || n%1024 == 0 || n%64 == 0 && st.noHostname() {
		if h := syslogHostname(line); h != "" {
			st.mu.Lock()
			st.hostname = h
			st.mu.Unlock()
		}
	}
	ev, status := ss.parseLineStatus(st.parser(), line)
	switch status {
	case lineFailed:
		if st.failed.Add(1)%64 == 1 {
			st.mu.Lock()
			st.sample = truncateLine(line)
			st.mu.Unlock()
		}
		return
	case lineSkipped:
		return
	}
	st.parsed.Add(1)
	ev.Source = st.label(ss.name, ss.proto)
	if ev.SubjectHost { // 没有远程来源的主机事件（如日志被清除）：主体为发送日志的设备
		ev.SrcIP = st.ip
	}
	if ss.auto {
		st.fix.apply(ev, time.Now()) // syslog 均为实时推送
	}
	if ns := ev.Time.UnixNano(); ns > st.lastEvent.Load() {
		st.lastEvent.Store(ns)
	}
	ss.touch(ev)
	select {
	case ss.events <- ev:
	case <-ctx.Done():
	}
}

func (st *senderStat) noHostname() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.hostname == ""
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
