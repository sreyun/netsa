package exposure

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

// 到达性判断：防火墙「放行」不等于探测到达了服务。
//
// 互联网扫描打到没有做 DNAT 映射的公网端口时，防火墙常按某条宽泛的策略记录为放行，例如华为：
//
//	POLICYPERMIT ... source-zone=untrust, destination-zone=untrust, rule-name=允许本地上外网
//
// 目的安全域仍是外网域，说明报文没有被转发到任何内部安全域，探测不可能到达服务。
// 防火墙日志自身记录的会话证据（安全域、DNAT 后地址、应答包数）比主动连接探测更可靠：
// 主动探测受回流 NAT、按来源放行的策略影响，结果与攻击者看到的不一致，误判「不通」会让真实攻击不再告警。

// Verdict 是根据会话证据对一次入站访问是否到达服务的判断（与 model.Reach 相同，事件上保存判断结果）。
type Verdict = model.Reach

const (
	ReachUnknown = model.ReachUnknown // 日志没有可用的证据
	ReachNo      = model.ReachNo      // 证据表明没有到达任何服务
	ReachDevice  = model.ReachDevice  // 目标是防火墙自身（local 安全域）
	ReachYes     = model.ReachYes     // 证据表明到达了内部服务
)

// externalZone 判断安全域名称是否为外网域（华为 / H3C untrust、思科 outside、FortiGate 接口角色 wan 等）。
func externalZone(z string) bool {
	for _, p := range [...]string{"untrust", "outside", "wan", "internet", "external", "isp"} {
		if strings.HasPrefix(z, p) {
			return true
		}
	}
	return false
}

// Reach 根据防火墙日志记录的会话证据判断一次放行的入站访问是否到达了服务，并给出理由。
func Reach(ev *model.Event) (Verdict, string) {
	if ev.Reply == model.ReplyNone {
		return ReachNo, "会话结束时目标没有任何应答（应答方向 0 个包），未建立通信"
	}
	if ev.NatDstIP != "" && ev.NatDstIP != ev.DstIP && geo.IsPrivate(ev.NatDstIP) {
		return ReachYes, "经 DNAT 转发至 " + ev.NatDstIP
	}
	src, dst := strings.ToLower(ev.SrcZone), strings.ToLower(ev.DstZone)
	switch {
	case dst == "local":
		return ReachDevice, "目标为防火墙自身（local 安全域）"
	case dst != "" && dst == src:
		// 外部来源从某安全域进入、又被转发回同一安全域：没有进入任何内部安全域
		return ReachNo, "源 / 目的安全域相同（" + ev.SrcZone + " → " + ev.DstZone + "），报文未转发到任何内部安全域，该端口没有对外服务"
	case externalZone(dst):
		return ReachNo, "目的安全域为外网域 " + ev.DstZone + "，报文未转发到任何内部安全域，该端口没有对外服务"
	}
	if ev.Reply == model.ReplyYes {
		return ReachYes, "目标有应答"
	}
	if dst != "" {
		return ReachYes, "已转发至 " + ev.DstZone + " 安全域"
	}
	return ReachUnknown, ""
}

// ReachCheck 返回是否按会话证据判断探测是否到达服务。
func (m *Manager) ReachCheck() bool { return m == nil || m.reach }

// ---------------- 自动识别的对外服务 ----------------

const maxLearned = 5000

type learnedSvc struct {
	ip     string
	port   int
	proto  string
	reason string
	hits   int64
	first  time.Time
	last   time.Time
}

// LearnedService 是根据会话证据自动识别的对外服务（等同于在 exposure.services 中登记）。
type LearnedService struct {
	PublicIP   string    `json:"public_ip"`
	PublicPort int       `json:"public_port"`
	Proto      string    `json:"proto"`
	Service    string    `json:"service,omitempty"`
	Reason     string    `json:"reason"` // 例如「经 DNAT 转发至 10.0.0.21」
	Hits       int64     `json:"hits"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Learn 记录有会话证据（DNAT 到内网、转发到内部安全域、目标有应答）表明真实对外开放的公网端口。
// 之后该端口上没有会话证据的日志（例如只输出策略日志的设备、或开启 enabled 后的清单判断）也按已发布处理。
func (m *Manager) Learn(ev *model.Event, why string) {
	if m == nil || ev.DstPort <= 0 || ev.DstPort > 65535 {
		return
	}
	ip := normIP(ev.DstIP)
	if ip == "" || geo.IsPrivate(ip) {
		return
	}
	proto := normProto(ev.Proto)
	k := key(ip, ev.DstPort, proto)
	m.learnMu.Lock()
	defer m.learnMu.Unlock()
	if l := m.learned[k]; l != nil {
		l.hits++
		if ev.Time.After(l.last) {
			l.last = ev.Time
		}
		return
	}
	if len(m.learned) >= maxLearned {
		return
	}
	m.learned[k] = &learnedSvc{ip: ip, port: ev.DstPort, proto: proto, reason: why, hits: 1, first: ev.Time, last: ev.Time}
}

func (m *Manager) isLearned(ip string, port int, proto string) bool {
	m.learnMu.RLock()
	defer m.learnMu.RUnlock()
	if len(m.learned) == 0 {
		return false
	}
	if _, ok := m.learned[key(ip, port, proto)]; ok {
		return true
	}
	if proto == "any" { // 查询不区分协议时，任一协议已识别即可
		_, tcp := m.learned[key(ip, port, "tcp")]
		_, udp := m.learned[key(ip, port, "udp")]
		return tcp || udp
	}
	_, ok := m.learned[key(ip, port, "any")]
	return ok
}

// Learned 返回自动识别的对外服务（按访问次数降序）。
func (m *Manager) Learned() []LearnedService {
	if m == nil {
		return nil
	}
	m.learnMu.RLock()
	out := make([]LearnedService, 0, len(m.learned))
	for _, l := range m.learned {
		out = append(out, LearnedService{PublicIP: l.ip, PublicPort: l.port, Proto: l.proto, Service: portService(l.port), Reason: l.reason,
			Hits: l.hits, FirstSeen: l.first, LastSeen: l.last})
	}
	m.learnMu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		if out[i].PublicIP != out[j].PublicIP {
			return out[i].PublicIP < out[j].PublicIP
		}
		return out[i].PublicPort < out[j].PublicPort
	})
	return out
}

// LearnedCount 返回自动识别的对外服务数量。
func (m *Manager) LearnedCount() int {
	if m == nil {
		return 0
	}
	m.learnMu.RLock()
	defer m.learnMu.RUnlock()
	return len(m.learned)
}

// ---------------- 可疑放行策略 ----------------

const (
	maxPolicies      = 200
	maxPolicySources = 64
)

type policyStat struct {
	policy, srcZone, dstZone string
	permits                  int64
	sources                  map[string]struct{}
	ports                    map[int]int64
	example                  string
	last                     time.Time
}

// PolicyNote 是一条放行了「未到达任何服务」的外部流量的安全策略：例如出站策略的源安全域配置过宽，
// 外部来源打到未映射端口的报文也被它放行。建议收紧策略的源安全域 / 源地址。
type PolicyNote struct {
	Policy   string    `json:"policy"`
	SrcZone  string    `json:"src_zone"`
	DstZone  string    `json:"dst_zone"`
	Permits  int64     `json:"permits"` // 放行次数
	Sources  int       `json:"sources"` // 不同外部来源数（最多统计 64 个）
	TopPorts []string  `json:"top_ports"`
	Example  string    `json:"example"` // 例如 195.184.76.97 → 43.242.97.35:23
	LastSeen time.Time `json:"last_seen"`
}

// AddUnreached 由流水线在因会话证据把一次探测降级为仅打标签时调用。
func (m *Manager) AddUnreached() {
	if m != nil {
		m.unreached.Add(1)
	}
}

// RecordUnreached 按安全策略汇总被放行但没有到达服务的外部访问。
func (m *Manager) RecordUnreached(ev *model.Event) {
	if m == nil || ev.Policy == "" && ev.SrcZone == "" && ev.DstZone == "" {
		return
	}
	k := ev.Policy + "|" + ev.SrcZone + "|" + ev.DstZone
	m.polMu.Lock()
	defer m.polMu.Unlock()
	p := m.policies[k]
	if p == nil {
		if len(m.policies) >= maxPolicies {
			return
		}
		p = &policyStat{policy: ev.Policy, srcZone: ev.SrcZone, dstZone: ev.DstZone, sources: map[string]struct{}{}, ports: map[int]int64{}}
		m.policies[k] = p
	}
	p.permits++
	if len(p.sources) < maxPolicySources {
		p.sources[ev.SrcIP] = struct{}{}
	}
	if _, ok := p.ports[ev.DstPort]; ok || len(p.ports) < 100 {
		p.ports[ev.DstPort]++
	}
	if ev.Time.After(p.last) || p.example == "" {
		p.last = ev.Time
		p.example = ev.SrcIP + " → " + ev.DstIP + ":" + strconv.Itoa(ev.DstPort)
	}
}

// Unreached 返回因会话证据表明未到达服务而只打标签的探测次数（进程内累计）。
func (m *Manager) Unreached() int64 {
	if m == nil {
		return 0
	}
	return m.unreached.Load()
}

// Policies 返回放行了未到达服务的外部流量的安全策略（按放行次数降序）。
func (m *Manager) Policies() []PolicyNote {
	if m == nil {
		return nil
	}
	m.polMu.Lock()
	out := make([]PolicyNote, 0, len(m.policies))
	for _, p := range m.policies {
		ports := make([]int, 0, len(p.ports))
		for port := range p.ports {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool {
			if p.ports[ports[i]] != p.ports[ports[j]] {
				return p.ports[ports[i]] > p.ports[ports[j]]
			}
			return ports[i] < ports[j]
		})
		if len(ports) > 8 {
			ports = ports[:8]
		}
		top := make([]string, len(ports))
		for i, port := range ports {
			top[i] = strconv.Itoa(port) + " × " + strconv.FormatInt(p.ports[port], 10)
		}
		out = append(out, PolicyNote{Policy: p.policy, SrcZone: p.srcZone, DstZone: p.dstZone, Permits: p.permits,
			Sources: len(p.sources), TopPorts: top, Example: p.example, LastSeen: p.last})
	}
	m.polMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Permits != out[j].Permits {
			return out[i].Permits > out[j].Permits
		}
		return out[i].Policy < out[j].Policy
	})
	return out
}
