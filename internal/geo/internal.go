// 本文件维护「内网 / 保留网段」集合：这些地址不可能属于境外公网，绝不能交给定位库或在线接口查询。
//
// 典型问题：企业把 172.168.100.0/24、172.168.200.0/24 这类**已被分配为公网**的地址段用在内网
// （RFC1918 的私有段是 172.16.0.0/12，只覆盖 172.16 ~ 172.31），定位库会按其公网注册信息返回
// 「美国」等境外归属地，导致内网攻击源被画到境外地图上、封禁列表也导出错误的国内/境外判断。
//
// 处理方式：内置 RFC1918 / CGNAT / 回环 / 链路本地 / 保留与文档段，并允许通过配置 geo.intranet
// 以及启动时自动探测本机网卡网段来补充；命中后统一按「内网」或「保留地址」呈现，不再查询定位库。
package geo

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
)

// 内置的内网网段（RFC1918、CGNAT、回环、链路本地、IPv6 ULA）。
var builtinInternal = []string{
	"10.0.0.0/8",
	"100.64.0.0/10", // RFC 6598 运营商级 NAT
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",  // IPv6 唯一本地地址
	"fe80::/10", // IPv6 链路本地
}

// 内置的保留网段：不可能出现在真实日志里的地址（本网络、保留段、组播）。
// 文档 / 基准测试段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）不在此列：
// 它们常被用作演示与测试的「公网」样例地址，按普通公网地址处理。
var builtinReserved = []string{
	"0.0.0.0/8",   // 本网络
	"240.0.0.0/4", // 保留（含广播地址）
	"::/128",      // 未指定
	"ff00::/8",    // 组播
}

// 地址类别。
const (
	addrPublic   = iota // 可路由的公网地址
	addrInternal        // 内网地址（RFC1918、CGNAT、ULA、回环、链路本地、配置的内网段）
	addrReserved        // 保留 / 文档 / 基准测试地址，不属于任何真实地理位置
)

type netSet struct {
	builtinInternal []netip.Prefix
	builtinReserved []netip.Prefix
	// extra 是配置与自动探测补充的内网段（优先级最高，便于覆盖内置判定）
	extra []netip.Prefix
}

var internalSet atomic.Pointer[netSet]

func init() {
	s := &netSet{}
	for _, c := range builtinInternal {
		s.builtinInternal = append(s.builtinInternal, netip.MustParsePrefix(c))
	}
	for _, c := range builtinReserved {
		s.builtinReserved = append(s.builtinReserved, netip.MustParsePrefix(c))
	}
	internalSet.Store(s)
}

// parseNets 解析 IP / CIDR 列表，忽略空项与非法项。
func parseNets(list []string) (ok []netip.Prefix, bad []string) {
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			ok = append(ok, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			a = a.Unmap()
			ok = append(ok, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		bad = append(bad, s)
	}
	return ok, bad
}

func (s *netSet) classify(a netip.Addr) int {
	if !a.IsValid() {
		return addrPublic
	}
	a = a.Unmap().WithZone("")
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return addrInternal
	}
	for _, p := range s.extra {
		if p.Contains(a) {
			return addrInternal
		}
	}
	for _, p := range s.builtinInternal {
		if p.Contains(a) {
			return addrInternal
		}
	}
	for _, p := range s.builtinReserved {
		if p.Contains(a) {
			return addrReserved
		}
	}
	return addrPublic
}

// SetInternalNetworks 用配置内的网段替换「补充内网段」，返回生效的网段列表与无法解析的项。
// 内置的 RFC1918 / 保留段始终生效。
func SetInternalNetworks(list []string) (effective []string, invalid []string) {
	nets, bad := parseNets(list)
	s := internalSet.Load()
	next := &netSet{builtinInternal: s.builtinInternal, builtinReserved: s.builtinReserved, extra: nets}
	internalSet.Store(next)
	for _, p := range nets {
		effective = append(effective, p.String())
	}
	return effective, bad
}

// InternalNetworks 返回当前生效的全部内网 / 保留网段（内置 + 配置 + 自动探测）。
func InternalNetworks() []string {
	s := internalSet.Load()
	out := make([]string, 0, len(s.builtinInternal)+len(s.builtinReserved)+len(s.extra))
	for _, p := range s.extra {
		out = append(out, p.String())
	}
	for _, p := range s.builtinInternal {
		out = append(out, p.String())
	}
	for _, p := range s.builtinReserved {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out
}

// ExtraInternalNetworks 只返回配置与自动探测补充的网段（用于界面提示）。
func ExtraInternalNetworks() []string {
	s := internalSet.Load()
	out := make([]string, 0, len(s.extra))
	for _, p := range s.extra {
		out = append(out, p.String())
	}
	return out
}

// IsPrivate 判断字符串形式的 IP 是否为内网地址（RFC1918、CGNAT、回环、链路本地、IPv6 ULA、
// 以及配置与自动探测补充的内网段）。保留 / 文档 / 基准测试地址不属于内网，但同样不可路由，
// 由 IsNonPublic 判断。
func IsPrivate(ip string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	return IsInternal(a)
}

// IsNonPublic 判断地址是否为内网或保留地址。
func IsNonPublic(a netip.Addr) bool {
	return internalSet.Load().classify(a) != addrPublic
}

// IsInternal 判断地址是否为内网地址（不含保留 / 文档段）。
func IsInternal(a netip.Addr) bool {
	return internalSet.Load().classify(a.Unmap().WithZone("")) == addrInternal
}

// IsPublic 判断地址是否为可路由的公网地址。
func IsPublic(a netip.Addr) bool {
	return internalSet.Load().classify(a.Unmap().WithZone("")) == addrPublic
}

// addrOf 解析字符串地址，失败时返回无效地址（classify 会按公网处理）。
func addrOf(ip string) netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

// DetectLocalNetworks 返回本机网卡所在网段，用于自动识别内网（例如 netsa 部署在 172.168.100.0/24
// 的内网主机上时，该网段会被自动视为内网，不必手工配置）。回环与 IPv6 链路本地不计入。
func DetectLocalNetworks() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ipn *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ipn = v
			case *net.IPAddr:
				ipn = &net.IPNet{IP: v.IP, Mask: net.CIDRMask(32, 32)}
			default:
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if ones <= 0 || bits != ip.BitLen() || ones >= bits {
				continue // 单主机地址无法代表网段
			}
			p := netip.PrefixFrom(ip, ones).Masked()
			if seen[p.String()] {
				continue
			}
			seen[p.String()] = true
			out = append(out, p.String())
		}
	}
	sort.Strings(out)
	return out
}
