package pipeline

import (
	"hash/fnv"
	"log"
	"math/bits"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/geo"
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

	// 反向代理自动识别（见 learnPeer）
	auto   bool
	peers  sync.Map // netip.Addr → *peerStat
	npeers atomic.Int64
}

// 反向代理自动识别的阈值：携带 X-Forwarded-For 的请求数与其中不同公网客户端数（按 64 位哈希位图近似计数）。
const (
	proxyMinRequests = 20
	proxyMinClients  = 8
	maxPeerStats     = 4096
)

type peerStat struct {
	xff      atomic.Int64
	clients  atomic.Uint64 // 客户端地址哈希的位图，置位数近似为不同客户端数
	proxy    atomic.Bool
	internal bool // 内网 / 本机地址：识别后自动信任；公网地址只提示
	first    time.Time
	sample   atomic.Pointer[string] // 最近一个客户端地址（展示用）
}

// ProxyPeer 是自动识别出的反向代理 / 负载均衡 / CDN 节点。
type ProxyPeer struct {
	IP       string    `json:"ip"`
	Trusted  bool      `json:"trusted"`  // 已自动信任（内网 / 本机地址）；false 表示公网节点，需人工确认后加入 trusted_proxies
	Clients  int       `json:"clients"`  // 近似的不同客户端数（上限 64）
	Requests int64     `json:"requests"` // 携带 X-Forwarded-For 的请求数
	Sample   string    `json:"sample,omitempty"`
	First    time.Time `json:"first_seen"`
}

// learnPeer 统计未配置为可信代理的直连对端：持续携带 X-Forwarded-For、且其中出现大量不同的公网客户端时判定为反向代理。
// 返回是否按可信代理处理（只有内网 / 本机地址会被自动信任）。
func (r *RealIP) learnPeer(peer netip.Addr, ev *model.Event) bool {
	v, ok := r.peers.Load(peer)
	if !ok {
		if ev.XFF == "" || r.npeers.Load() >= maxPeerStats {
			return false
		}
		var loaded bool
		v, loaded = r.peers.LoadOrStore(peer, &peerStat{internal: peer.IsLoopback() || geo.IsInternal(peer), first: ev.Time})
		if !loaded {
			r.npeers.Add(1)
		}
	}
	st := v.(*peerStat)
	if st.proxy.Load() {
		if ev.XFF != "" {
			st.xff.Add(1) // 继续计数，界面展示的请求数随实际流量增长
		}
		return st.internal
	}
	if ev.XFF == "" {
		return false
	}
	client, ok := r.fromChain(strings.Split(ev.XFF, ","))
	if !ok || client == peer || !geo.IsPublic(client) {
		return false
	}
	n := st.xff.Add(1)
	h := fnv.New64a()
	h.Write(client.AsSlice())
	st.clients.Or(1 << (h.Sum64() & 63))
	s := client.String()
	st.sample.Store(&s)
	if n >= proxyMinRequests && bits.OnesCount64(st.clients.Load()) >= proxyMinClients && st.proxy.CompareAndSwap(false, true) {
		if st.internal {
			log.Printf("[real_ip] 自动识别反向代理 %s（携带 X-Forwarded-For，含多个公网客户端），已按可信代理还原真实客户端地址", peer)
		} else {
			log.Printf("[real_ip] 公网地址 %s 疑似未配置的 CDN / 代理节点（携带 X-Forwarded-For，含多个公网客户端），确认后请加入 real_ip.trusted_proxies", peer)
		}
		return st.internal
	}
	return false
}

// Proxies 返回自动识别出的反向代理（内网，已自动信任）与疑似未配置的 CDN / 代理节点（公网，需人工确认）。
func (r *RealIP) Proxies() []ProxyPeer {
	out := []ProxyPeer{}
	if r == nil {
		return out
	}
	r.peers.Range(func(k, v any) bool {
		st := v.(*peerStat)
		if st.proxy.Load() {
			p := ProxyPeer{IP: k.(netip.Addr).String(), Trusted: st.internal, Clients: bits.OnesCount64(st.clients.Load()),
				Requests: st.xff.Load(), First: st.first}
			if s := st.sample.Load(); s != nil {
				p.Sample = *s
			}
			out = append(out, p)
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out
}

// NewRealIP 根据配置创建还原器。
func NewRealIP(cfg config.RealIPConfig) *RealIP {
	r := &RealIP{cdnOnly: cfg.CDNOnly, auto: cfg.AutoOn()}
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
	if !r.isTrusted(peer) && !(r.auto && r.learnPeer(peer, ev)) {
		switch {
		case containsLoopback(ev.XFF) || containsLoopback(ev.XRealIP):
			// 头部内容完全由攻击者控制：转义控制字符并截断，避免超长 / 带换行的证据进入告警、推送与归档
			return &model.Hit{RuleID: "spoof-xff", Name: "伪造来源地址头(绕过IP限制)", Category: "IP伪造",
				Severity: model.SevLow, Phase: model.PhaseRecon,
				Evidence: "X-Forwarded-For: " + detect.Printable(ev.XFF, 200) + " X-Real-IP: " + detect.Printable(ev.XRealIP, 100)}
		case r.cdnOnly && !geo.IsInternal(peer) && !peer.IsLoopback():
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
