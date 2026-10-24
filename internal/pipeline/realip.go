package pipeline

import (
	"net"
	"net/netip"
	"strings"

	"netsa/internal/config"
	"netsa/internal/model"
)

// 内置的可信代理网段（CDN 回源地址），来源：https://www.cloudflare.com/ips/
var trustedPresets = map[string][]string{
	"cloudflare": {
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	},
}

// PresetNames 返回内置可信代理预设名称。
func PresetNames() []string {
	var out []string
	for k := range trustedPresets {
		out = append(out, k)
	}
	return out
}

// RealIP 根据可信代理列表从客户端地址头中还原真实来源。只有直连对端属于可信代理时才信任这些头部，
// 并且对 X-Forwarded-For / Forwarded 链从右向左跳过可信代理，取第一个不可信地址，防止攻击者在左侧伪造。
type RealIP struct {
	headers []string
	trusted []netip.Prefix
	cdnOnly bool
}

// NewRealIP 根据配置创建还原器。
func NewRealIP(cfg config.RealIPConfig) *RealIP {
	r := &RealIP{cdnOnly: cfg.CDNOnly}
	for _, h := range cfg.Headers {
		r.headers = append(r.headers, strings.ToLower(strings.ReplaceAll(strings.TrimSpace(h), "-", "_")))
	}
	if len(r.headers) == 0 {
		switch strings.ToLower(cfg.Header) {
		case "none":
		case "x_real_ip":
			r.headers = []string{"x_real_ip"}
		default:
			r.headers = []string{"x_forwarded_for"}
		}
	}
	nets := append([]string(nil), cfg.TrustedProxies...)
	for _, p := range cfg.TrustedPresets {
		nets = append(nets, trustedPresets[strings.ToLower(p)]...)
	}
	for _, t := range nets {
		if p, err := netip.ParsePrefix(t); err == nil {
			r.trusted = append(r.trusted, p.Masked())
		} else if a, err := netip.ParseAddr(t); err == nil {
			r.trusted = append(r.trusted, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return r
}

func (r *RealIP) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseHop 解析转发链中的单个地址，兼容端口、方括号、引号以及 RFC 7239 的 for= 写法；
// "unknown"、"_hidden" 等混淆标识返回 false。
func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '='); i >= 0 && strings.EqualFold(strings.TrimSpace(s[:i]), "for") {
		s = strings.TrimSpace(s[i+1:])
	}
	s = strings.Trim(s, `"'`)
	if s == "" || s[0] == '_' || strings.EqualFold(s, "unknown") {
		return netip.Addr{}, false
	}
	if s[0] == '[' { // [IPv6]:port
		if j := strings.IndexByte(s, ']'); j > 0 {
			s = s[1:j]
		}
	} else if strings.Count(s, ":") == 1 { // IPv4:port
		s = s[:strings.IndexByte(s, ':')]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// splitForwarded 从 RFC 7239 Forwarded 头中提取 for= 地址链：for=192.0.2.43, for="[2001:db8::1]";proto=https
func splitForwarded(v string) []string {
	var out []string
	for _, elem := range strings.Split(v, ",") {
		for _, pair := range strings.Split(elem, ";") {
			if k, _, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && strings.EqualFold(strings.TrimSpace(k), "for") {
				out = append(out, pair)
			}
		}
	}
	return out
}

// fromChain 从右向左跳过可信代理，返回第一个不可信地址；全部可信时返回最左侧地址。
func (r *RealIP) fromChain(hops []string) (netip.Addr, bool) {
	var leftmost netip.Addr
	found := false
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHop(hops[i])
		if !ok {
			continue
		}
		if !r.isTrusted(a) {
			return a, true
		}
		leftmost, found = a, true
	}
	return leftmost, found
}

// Apply 改写事件来源 IP；发现伪造头部或绕过 CDN 直连时返回一条命中。
func (r *RealIP) Apply(ev *model.Event) *model.Hit {
	if ev.Kind != model.KindWeb || ev.PeerIP != "" || len(r.headers) == 0 {
		return nil
	}
	peer, err := netip.ParseAddr(ev.SrcIP)
	if err != nil {
		return nil
	}
	if !r.isTrusted(peer) {
		switch {
		case containsLoopback(ev.XFF) || containsLoopback(ev.XRealIP):
			return &model.Hit{RuleID: "spoof-xff", Name: "伪造来源地址头(绕过IP限制)", Category: "IP伪造",
				Severity: model.SevLow, Phase: model.PhaseRecon, Evidence: "X-Forwarded-For: " + ev.XFF + " X-Real-IP: " + ev.XRealIP}
		case r.cdnOnly && !peer.IsPrivate() && !peer.IsLoopback():
			return &model.Hit{RuleID: "cdn-bypass", Name: "绕过CDN直连源站", Category: "CDN绕过",
				Severity: model.SevMedium, Phase: model.PhaseRecon, Evidence: "直连地址 " + ev.SrcIP + " 不属于可信 CDN/代理网段，源站地址可能已暴露"}
		}
		return nil
	}
	var client netip.Addr
	ok := false
	for _, h := range r.headers {
		switch h {
		case "x_forwarded_for":
			client, ok = r.fromChain(strings.Split(ev.XFF, ","))
		case "forwarded":
			client, ok = r.fromChain(splitForwarded(ev.ClientHeaders["forwarded"]))
		case "x_real_ip":
			client, ok = parseHop(ev.XRealIP)
		default:
			client, ok = parseHop(ev.ClientHeaders[h])
		}
		if ok {
			break
		}
	}
	if ok && client != peer {
		ev.PeerIP, ev.SrcIP = ev.SrcIP, client.String()
	}
	return nil
}

func containsLoopback(v string) bool {
	if v == "" {
		return false
	}
	for _, p := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(p), "localhost") {
			return true
		}
		if a, ok := parseHop(p); ok && a.IsLoopback() {
			return true
		}
	}
	return false
}

// ClientIP 返回 HTTP 请求的真实客户端地址（用于登录失败锁定与审计）：
// 对端为可信代理（如本机或内网的 nginx 反向代理）时按 X-Forwarded-For 从右向左解析。
func (r *RealIP) ClientIP(remoteAddr, xff string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if xff != "" && r != nil && r.isTrusted(peer) {
		if a, ok := r.fromChain(strings.Split(xff, ",")); ok {
			return a.String()
		}
	}
	return peer.String()
}
