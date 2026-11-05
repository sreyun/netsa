package ingest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
	"netsa/internal/flow"
	"netsa/internal/model"
)

// 流量采集（P3-1）：NetFlow v5 / v9 与 IPFIX 共用一个 UDP 端口，sFlow v5 单独一个端口。流记录按（源、目的、目的端口、
// 协议）在窗口内合并后转为会话事件（字节数、包数已按采样率还原），与防火墙会话日志一样参与扫描、外传、
// 带宽型 DDoS 与外连情报检测。

type flowExporter struct {
	prefix netip.Prefix
	name   string
	rate   uint32
}

type flowStats struct {
	mu      sync.Mutex
	formats map[string]int64      // 识别出的格式 → 记录数
	devices map[netip.Addr]string // 设备地址 → 名称
}

func (fs *flowStats) note(format string, dev netip.Addr, name string, n int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.formats[format] += int64(n)
	if _, ok := fs.devices[dev]; !ok && len(fs.devices) < 1000 {
		fs.devices[dev] = name
	}
}

func (fs *flowStats) detected() string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	var parts []string
	for f := range fs.formats {
		parts = append(parts, f)
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("%s（%d 台设备）", strings.Join(parts, "、"), len(fs.devices))
}

// StartFlow 启动流量采集；监听地址都为空时不启用。
func (m *Manager) StartFlow(ctx context.Context, cfg config.FlowConfig) error {
	if cfg.NetFlow == "" && cfg.SFlow == "" {
		return nil
	}
	var exps []flowExporter
	for _, e := range cfg.Exporters {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			a, aerr := netip.ParseAddr(e.CIDR)
			if aerr != nil {
				return fmt.Errorf("flow.exporters: 无效的地址 %q", e.CIDR)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		exps = append(exps, flowExporter{p.Masked(), e.Name, uint32(max(e.Sampling, 0))})
	}
	lookup := func(a netip.Addr) (string, uint32) {
		for _, e := range exps {
			if e.prefix.Contains(a) {
				return e.name, e.rate
			}
		}
		return "", uint32(max(cfg.Sampling, 0))
	}
	window := cfg.Window
	if window <= 0 {
		window = 10 * time.Second
	}
	start := func(name, addr string, sflow bool) error {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		uc := pc.(*net.UDPConn)
		_ = uc.SetReadBuffer(32 << 20)
		s, _ := m.add(name, addr, "auto", "", "")
		s.group, s.silence = name, -1
		s.setStatus("listening", "")
		st := &flowStats{formats: map[string]int64{}, devices: map[netip.Addr]string{}}
		s.detectFn, s.offsetFn = st.detected, func() string { return "" }
		dec := flow.NewDecoder()
		dec.Default = func(a netip.Addr) uint32 { _, r := lookup(a); return r }
		go func() {
			<-ctx.Done()
			uc.Close()
		}()
		go m.serveFlow(ctx, uc, s, st, dec, sflow, window, lookup)
		log.Printf("[flow] %s 监听 %s", name, addr)
		return nil
	}
	if cfg.NetFlow != "" {
		if err := start("netflow", cfg.NetFlow, false); err != nil {
			return err
		}
	}
	if cfg.SFlow != "" {
		if err := start("sflow", cfg.SFlow, true); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) serveFlow(ctx context.Context, uc *net.UDPConn, s *source, st *flowStats, dec *flow.Decoder, sflow bool, window time.Duration,
	lookup func(netip.Addr) (string, uint32)) {
	agg := &flow.Aggregator{Window: window}
	formats := map[aggFmt]string{}
	buf := make([]byte, 65535)
	emit := func(now time.Time) {
		for _, r := range agg.Flush(now) {
			ev := flowEvent(r, formats[aggFmt{r.Src, r.Dst}], s.name)
			s.parsed.Add(1)
			s.touch(ev)
			s.batch = append(s.batch, ev)
			if len(s.batch) >= BatchSize {
				m.flush(ctx, s)
			}
		}
		clear(formats)
		m.flush(ctx, s)
	}
	for {
		_ = uc.SetReadDeadline(time.Now().Add(time.Second))
		n, ap, err := uc.ReadFromUDPAddrPort(buf)
		now := time.Now()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				log.Printf("[flow] %s 读取失败: %v", s.name, err)
				time.Sleep(100 * time.Millisecond)
			}
			if agg.Due(now) {
				emit(now)
			}
			continue
		}
		s.lines.Add(1)
		dev := ap.Addr().Unmap()
		var recs []flow.Record
		var format string
		if sflow {
			var agent netip.Addr
			recs, agent, err = flow.DecodeSFlow(buf[:n], now)
			format = "sflow"
			if agent.IsValid() && !agent.IsUnspecified() {
				dev = agent
			}
		} else {
			recs, format, err = dec.Decode(dev, buf[:n], now)
		}
		if err != nil && len(recs) == 0 {
			s.failed.Add(1)
			s.mu.Lock()
			s.sample = fmt.Sprintf("来自 %s 的 %d 字节数据包：%v", dev, n, err)
			s.mu.Unlock()
			if agg.Due(now) { // 持续收到无法解析的数据包时窗口照常输出
				emit(now)
			}
			continue
		}
		name, _ := lookup(dev)
		if name == "" {
			name = dev.String()
		}
		st.note(format, dev, name, len(recs))
		full := false
		for _, r := range recs {
			if !r.Src.IsValid() || !r.Dst.IsValid() {
				continue
			}
			if r.End.IsZero() || r.End.After(now.Add(time.Hour)) {
				r.End = now
			}
			formats[aggFmt{r.Src, r.Dst}] = format
			full = agg.Add(r, now) || full
		}
		if full || agg.Due(now) {
			emit(now)
		}
	}
}

type aggFmt struct{ src, dst netip.Addr }

// flowEvent 把合并后的流记录转为会话事件。
func flowEvent(r flow.Record, format, source string) *model.Event {
	ev := &model.Event{Kind: model.KindFirewall, Format: format, Source: source, Time: r.End, SrcIP: r.Src.String(), DstIP: r.Dst.String(),
		SrcPort: int(r.SrcPort), DstPort: int(r.DstPort), Proto: protoName(r.Proto), Action: model.ActionAllow,
		SentBytes: int64(min(r.Bytes, 1<<62)), Packets: int64(min(r.Packets, 1<<62)), Sampling: int(r.Sampling)}
	if r.Denied {
		ev.Action = model.ActionDeny
	}
	if r.Proto == 6 && r.Flags != 0 {
		var f []string
		for i, n := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG"} {
			if r.Flags&(1<<i) != 0 {
				f = append(f, n)
			}
		}
		ev.Flags = strings.Join(f, ",")
	}
	ev.Response = responseFlow(r)
	if format == "" {
		ev.Format = "flow"
	}
	return ev
}

// servicePorts 是 1024 以上的常见服务端口（数据库、远程桌面、Web 备用端口、反射放大协议）。
var servicePorts = map[uint16]bool{1194: true, 1433: true, 1521: true, 1900: true, 2049: true, 3283: true, 3306: true, 3389: true, 3702: true, 5353: true,
	5432: true, 5900: true, 6379: true, 8000: true, 8080: true, 8443: true, 8888: true, 9200: true, 10001: true, 11211: true, 27017: true, 37810: true}

// responseFlow 判断单向流量记录是否为服务端发回客户端的方向：源端口是服务端口（小于 1024 或常见服务端口），
// 目的端口是更大的临时端口。合并了多个源端口的记录（客户端发出的请求方向）不算。
func responseFlow(r flow.Record) bool {
	if r.Proto != 6 && r.Proto != 17 {
		return false
	}
	sp, dp := r.SrcPort, r.DstPort
	if sp == 0 || dp < 1024 || sp >= dp {
		return false
	}
	return sp < 1024 || servicePorts[sp]
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	}
	return fmt.Sprint(p)
}
