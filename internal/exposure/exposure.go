// Package exposure 维护「对外发布的服务清单」（公网 IP:端口 → 内网 IP:端口 的 DNAT 映射），
// 用于判断防火墙日志中的端口探测是否真的打到了对外开放的服务。
//
// 背景：互联网背景扫描会持续探测 1433 / 6379 / 3389 等端口，防火墙按默认策略记录并放行，
// 若该端口并没有做 DNAT 映射，探测不可能到达任何服务。把这类日志逐条记成高危告警，
// 会让真实的风险信号被噪音淹没。开启本功能后，未发布端口上的探测类命中只打标签、不产生告警。
package exposure

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"netsa/internal/config"
)

// Manager 是只读的映射表（配置加载后不再变化，读取无锁）。
type Manager struct {
	enabled bool
	// exact 为 "ip|port|proto" 精确映射
	exact map[string]struct{}
	// hosts 为该地址的全部端口都已发布
	hosts map[string]struct{}
	// ports 为「不分公网地址，该端口已发布」
	ports map[int]struct{}
	// allowed 为兜底端口白名单（allowed_ports）
	allowed map[int]struct{}

	list []config.ExposureService
	hits atomic.Int64 // 因未发布端口被降级的探测次数

	// 候选映射统计（见 candidates.go）：只生成建议，不影响检测行为
	suggest config.ExposureSuggest
	candMu  sync.Mutex
	cands   map[string]*candidate

	// 按会话证据判断探测是否到达服务（见 reach.go），与 enabled 无关
	reach     bool
	unreached atomic.Int64
	polMu     sync.Mutex
	policies  map[string]*policyStat
	// 有会话证据的对外服务（自动识别，等同于已登记的映射）
	learnMu sync.RWMutex
	learned map[string]*learnedSvc
	// 防火墙自身在内置管理 / VPN 端口之外对外提供服务的端口（exposure.device_ports）
	devicePorts map[int]bool
}

func key(ip string, port int, proto string) string {
	return ip + "|" + strconv.Itoa(port) + "|" + proto
}

func normIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "any") || s == "0.0.0.0" || s == "::" {
		return ""
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

func normProto(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "any", "*":
		return "any"
	case "tcp", "udp":
		return strings.ToLower(strings.TrimSpace(s))
	}
	return "any"
}

// Load 根据配置创建映射表。未启用时返回的 Manager 仍然可用（Enforcing 为 false）。
func Load(cfg config.ExposureConfig) (*Manager, error) {
	m := &Manager{
		enabled: cfg.Enabled,
		exact:   map[string]struct{}{},
		hosts:   map[string]struct{}{},
		ports:   map[int]struct{}{},
		allowed: map[int]struct{}{},
		suggest: cfg.Suggest, cands: map[string]*candidate{},
		reach: cfg.ReachOn(), policies: map[string]*policyStat{}, learned: map[string]*learnedSvc{},
	}
	for _, p := range cfg.DevicePorts {
		if p > 0 && p <= 65535 {
			if m.devicePorts == nil {
				m.devicePorts = map[int]bool{}
			}
			m.devicePorts[p] = true
		}
	}
	for _, p := range cfg.AllowedPorts {
		if p > 0 && p <= 65535 {
			m.allowed[p] = struct{}{}
		}
	}
	for _, s := range cfg.Services {
		ip, port, proto := normIP(s.PublicIP), s.PublicPort, normProto(s.Proto)
		if ip == "" && port == 0 {
			return nil, fmt.Errorf("exposure.services %q 需要至少指定 public_ip 或 public_port", s.Name)
		}
		if ip == "" {
			m.ports[port] = struct{}{} // 任意公网地址的该端口已发布
		} else if port == 0 {
			m.hosts[ip] = struct{}{} // 该地址的全部端口已发布
		} else {
			m.exact[key(ip, port, proto)] = struct{}{}
		}
		m.list = append(m.list, s)
	}
	return m, nil
}

// Enforcing 返回是否启用「未发布端口过滤」。未启用时调用方应保持原有检测行为。
func (m *Manager) Enforcing() bool { return m != nil && m.enabled }

// Count 返回配置的映射条数。
func (m *Manager) Count() int {
	if m == nil {
		return 0
	}
	return len(m.list)
}

// List 返回配置的映射（用于界面展示）。
func (m *Manager) List() []config.ExposureService {
	if m == nil {
		return nil
	}
	out := make([]config.ExposureService, len(m.list))
	copy(out, m.list)
	return out
}

// Lookup 判断某个公网目标端口是否已对外发布；第二个返回值表示是否命中（true 为已发布）。
// 目标为内网地址、端口未知时一律视为已发布（由调用方先行判断内网目标）。
func (m *Manager) Lookup(dstIP string, port int, proto string) (*config.ExposureService, bool) {
	if m == nil || !m.enabled {
		return nil, true // 未启用：不做判断，保持原有检测行为
	}
	ip := normIP(dstIP)
	if ip == "" || port <= 0 || port > 65535 {
		return nil, true
	}
	return m.match(ip, port, normProto(proto))
}

// match 判断已配置的映射是否覆盖该端口（不看 enabled，供候选建议去重）。
func (m *Manager) match(ip string, port int, proto string) (*config.ExposureService, bool) {
	if _, ok := m.exact[key(ip, port, proto)]; ok {
		return m.find(ip, port, proto), true
	}
	if proto != "any" {
		if _, ok := m.exact[key(ip, port, "any")]; ok { // 映射声明为 any 协议
			return m.find(ip, port, "any"), true
		}
	}
	if _, ok := m.hosts[ip]; ok {
		return nil, true
	}
	if _, ok := m.ports[port]; ok {
		return nil, true
	}
	if _, ok := m.allowed[port]; ok {
		return nil, true
	}
	if m.isLearned(ip, port, proto) {
		return nil, true
	}
	return nil, false
}

// Configured 判断该端口是否已经在清单中，不受 enabled 影响。
func (m *Manager) Configured(dstIP string, port int, proto string) bool {
	if m == nil {
		return false
	}
	ip := normIP(dstIP)
	if ip == "" || port <= 0 || port > 65535 {
		return false
	}
	_, ok := m.match(ip, port, normProto(proto))
	return ok
}

func (m *Manager) find(ip string, port int, proto string) *config.ExposureService {
	for i := range m.list {
		if normIP(m.list[i].PublicIP) == ip && (m.list[i].PublicPort == 0 || m.list[i].PublicPort == port) &&
			(m.list[i].PublicPort == 0 || normProto(m.list[i].Proto) == proto || normProto(m.list[i].Proto) == "any") {
			return &m.list[i]
		}
	}
	return nil
}

// Published 实现 store.PortPublished：目标端口是否已对外发布。未启用时一律视为已发布。
func (m *Manager) Published(dstIP string, port int, proto string) bool {
	_, ok := m.Lookup(dstIP, port, proto)
	return ok
}

// Muted 返回被降级的探测次数（进程内累计）。
func (m *Manager) Muted() int64 {
	if m == nil {
		return 0
	}
	return m.hits.Load()
}

// AddMuted 由流水线在降级一次探测时调用。
func (m *Manager) AddMuted() {
	if m != nil {
		m.hits.Add(1)
	}
}
