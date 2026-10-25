package parser

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/model"
)

// WebParsers 返回内置的 Web 访问日志解析器（顺序即识别优先级）。
func WebParsers() []Parser { return []Parser{Nginx{}, NginxJSON{}, DefaultW3C()} }

// FirewallParsers 返回内置的防火墙/安全设备日志解析器，顺序即识别优先级。
func FirewallParsers() []Parser {
	return []Parser{Netfilter{}, PFSense{}, WindowsFirewall{}, CiscoASA{}, PaloAlto{}, SnortFast{}, JSONFirewall{}, KVFirewall{}}
}

// AllParsers 返回全部内置解析器。
func AllParsers() []Parser {
	return append(append(WebParsers(), HostParsers()...), FirewallParsers()...)
}

// Skippable 判断是否为空行或注释行（例如 W3C / Windows 防火墙日志头）。
func Skippable(line string) bool {
	t := strings.TrimSpace(line)
	return t == "" || t[0] == '#'
}

type parserBox struct{ p Parser }

// Auto 是带格式自动识别的解析器：先在全部候选解析器中试探，某一格式连续命中后锁定，
// 锁定的格式持续失败时再重新识别。锁定后的热路径无锁，可被多个 goroutine 并发调用。
type Auto struct {
	locked atomic.Pointer[parserBox]
	mu     sync.Mutex
	cands  []Parser
	hits   map[string]int
	miss   int
}

// NewAuto 根据数据源类型构造解析器。typ 取值 auto / nginx / web / firewall / dns / auth 或具体解析器名；
// logFormat 非空时优先使用自定义 nginx log_format。
func NewAuto(typ, logFormat string) (*Auto, error) {
	var cands []Parser
	if logFormat != "" {
		lf, err := CompileLogFormat(logFormat)
		if err != nil {
			return nil, err
		}
		cands = append(cands, lf)
	}
	switch strings.ToLower(typ) {
	case "", "auto":
		cands = append(cands, AllParsers()...)
	case "nginx", "web", "apache", "iis":
		cands = append(cands, WebParsers()...)
	case "firewall", "fw", "ids", "ips":
		cands = append(cands, FirewallParsers()...)
	case "dns":
		cands = append(cands, BindDNS{}, Dnsmasq{}, CoreDNS{}, WindowsDNS{}, ZeekDNS{}, JSONDNS{})
	case "auth", "host", "secure", "vpn":
		cands = append(cands, LinuxAuth{}, WindowsSecurity{}, VPNAuth{})
	default:
		found := false
		for _, p := range AllParsers() {
			if p.Name() == typ {
				cands = append(cands, p)
				found = true
			}
		}
		if !found && logFormat == "" {
			return nil, fmt.Errorf("未知的日志类型 %q", typ)
		}
	}
	return &Auto{cands: cands, hits: map[string]int{}}, nil
}

// Detected 返回当前识别出的格式名。
func (a *Auto) Detected() string {
	if b := a.locked.Load(); b != nil {
		return b.p.Name()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	best, n := "", 0
	for k, v := range a.hits {
		if v > n {
			best, n = k, v
		}
	}
	return best
}

// Directive 处理日志中的指令行。目前支持 W3C 扩展日志（IIS）的 "#Fields:"：
// 按声明的字段顺序重建 IIS 解析器，兼容管理员自定义的记录字段。
func (a *Auto) Directive(line string) {
	w, ok := NewW3C(line)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, p := range a.cands {
		if _, isW3C := p.(*W3C); isW3C {
			a.cands[i] = w
		}
	}
	if b := a.locked.Load(); b != nil {
		if _, isW3C := b.p.(*W3C); isW3C {
			a.locked.Store(&parserBox{w})
		}
	}
}

func (a *Auto) Parse(line string) (*model.Event, bool) {
	line = strings.TrimRight(line, "\r\n")
	msg, hdr, sys := StripSyslog(line)

	locked := a.locked.Load()
	if locked != nil {
		if ev, ok := parseWith(locked.p, line, msg, hdr, sys); ok {
			return ev, true
		}
	}
	a.mu.Lock()
	cands := a.cands
	a.mu.Unlock()
	for _, p := range cands {
		if locked != nil && p == locked.p {
			continue
		}
		ev, ok := parseWith(p, line, msg, hdr, sys)
		if !ok {
			continue
		}
		a.mu.Lock()
		a.hits[p.Name()]++
		if locked != nil {
			a.miss++
		}
		if locked == nil && a.hits[p.Name()] >= 3 || a.miss > 20 {
			a.locked.Store(&parserBox{p})
			a.miss = 0
		}
		a.mu.Unlock()
		return ev, true
	}
	return nil, false
}

func parseWith(p Parser, line, msg string, hdr SyslogHeader, sys bool) (*model.Event, bool) {
	var ev *model.Event
	ok := false
	if sys {
		ev, ok = p.Parse(msg)
	}
	if !ok {
		if ev, ok = p.Parse(line); !ok {
			return nil, false
		}
	}
	if ev.SrcIP == "" && ev.SubjectHost {
		ev.SrcIP = "127.0.0.1" // 本机事件；经 syslog 接收时由采集层替换为发送端地址
	}
	// 统一规范化地址：IPv4 映射地址、方括号、区域标识，保证同一来源只对应一个画像
	src, valid := NormIP(ev.SrcIP)
	if !valid {
		return nil, false
	}
	ev.SrcIP = src
	if ev.DstIP != "" {
		ev.DstIP, _ = NormIP(ev.DstIP)
	}
	if ev.PeerIP != "" {
		ev.PeerIP, _ = NormIP(ev.PeerIP)
	}
	if ev.Time.IsZero() {
		ev.Time = hdr.Time
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.Host == "" && (ev.Kind == model.KindFirewall || ev.Kind == model.KindAuth) && hdr.Host != "" {
		ev.Host = hdr.Host
	}
	ev.Raw = line
	return ev, true
}
