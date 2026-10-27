package exposure

import (
	"fmt"
	"sort"
	"time"

	"netsa/internal/geo"
)

// 候选映射：从防火墙日志里「外部来源访问公网地址端口且被放行」的连接反推可能已发布的服务。
//
// 为什么需要：exposure.services 目前完全依赖手工维护，配置漂移（新上线了服务、换了公网 IP）
// 会让「未发布端口过滤」静默失效——该过滤的端口没过滤，或者该放行的端口被降级。
// 这里用两条与端口是否真的开放强相关的信号生成候选：
//   - 放行次数：真实服务会持续收到连接，关闭的端口只有零星探测；
//   - 不同来源数：真实服务面向很多客户端，扫描器往往集中在少数地址。
//
// 候选只用于「提示」，不会自动生效：误判为已发布会让真实攻击不再告警，必须由人确认。
const (
	maxCandidates = 2000 // 候选条目上限（按公网 IP:端口 维度，正常环境远小于此值）
	maxSources    = 64   // 每个候选记录的不同来源上限
	maxSuggest    = 50   // 一次返回的建议条数上限
)

type candidate struct {
	publicIP string
	port     int
	proto    string
	allows   int64
	sources  map[string]struct{}
	first    time.Time
	last     time.Time
}

// Candidate 是一条建议登记为「对外发布服务」的映射。
type Candidate struct {
	PublicIP   string    `json:"public_ip"`
	PublicPort int       `json:"public_port"`
	Proto      string    `json:"proto"`
	Service    string    `json:"service,omitempty"` // 按端口推断的服务名
	Allows     int64     `json:"allows"`            // 累计放行次数
	Sources    int       `json:"sources"`           // 不同外部来源数
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	// YAML 是可直接粘贴到 exposure.services 的片段（内网地址需按实际 DNAT 填写）。
	YAML string `json:"yaml"`
}

// limits 返回候选建议的阈值（配置缺省时回落到 20 次 / 3 个来源）。
func (m *Manager) limits() (int, int) {
	allows, sources := m.suggest.MinAllows, m.suggest.MinSources
	if allows <= 0 {
		allows = 20
	}
	if sources <= 0 {
		sources = 3
	}
	return allows, sources
}

// Observe 记录一次对公网地址端口的访问，用于生成候选映射。
//
// 只统计「外部来源 → 公网地址」且被放行的连接：内网来源是东西向流量，
// 出站连接的目标是外部服务，两者都不能证明本地端口对外发布；被拦截的连接同理。
func (m *Manager) Observe(dstIP string, port int, proto, srcIP string, allowed bool, at time.Time) {
	if m == nil || !m.suggest.On() || !allowed || port <= 0 || port > 65535 {
		return
	}
	ip := normIP(dstIP)
	if ip == "" || geo.IsPrivate(ip) || geo.IsPrivate(srcIP) {
		return
	}
	proto = normProto(proto)
	if m.Configured(ip, port, proto) {
		return // 已登记，无需再提示
	}

	k := key(ip, port, proto)
	m.candMu.Lock()
	defer m.candMu.Unlock()
	c := m.cands[k]
	if c == nil {
		if len(m.cands) >= maxCandidates {
			return
		}
		c = &candidate{publicIP: ip, port: port, proto: proto, sources: map[string]struct{}{}, first: at, last: at}
		m.cands[k] = c
	}
	c.allows++
	if len(c.sources) < maxSources {
		c.sources[srcIP] = struct{}{}
	}
	if at.Before(c.first) {
		c.first = at
	}
	if at.After(c.last) {
		c.last = at
	}
}

// Candidates 返回达到阈值的候选映射（按放行次数降序），最多 maxSuggest 条。
func (m *Manager) Candidates() []Candidate {
	if m == nil {
		return nil
	}
	minAllows, minSources := m.limits()
	m.candMu.Lock()
	out := make([]Candidate, 0, len(m.cands))
	for _, c := range m.cands {
		if c.allows < int64(minAllows) || len(c.sources) < minSources {
			continue
		}
		out = append(out, Candidate{
			PublicIP: c.publicIP, PublicPort: c.port, Proto: c.proto,
			Service: portService(c.port), Allows: c.allows, Sources: len(c.sources),
			FirstSeen: c.first, LastSeen: c.last,
		})
	}
	m.candMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Allows != out[j].Allows {
			return out[i].Allows > out[j].Allows
		}
		if out[i].PublicIP != out[j].PublicIP {
			return out[i].PublicIP < out[j].PublicIP
		}
		return out[i].PublicPort < out[j].PublicPort
	})
	if len(out) > maxSuggest {
		out = out[:maxSuggest]
	}
	for i := range out {
		out[i].YAML = out[i].yaml()
	}
	return out
}

// CandidateCount 返回达到阈值的候选数量（界面与启动提示用）。
func (m *Manager) CandidateCount() int {
	if m == nil {
		return 0
	}
	minAllows, minSources := m.limits()
	m.candMu.Lock()
	defer m.candMu.Unlock()
	n := 0
	for _, c := range m.cands {
		if c.allows >= int64(minAllows) && len(c.sources) >= minSources {
			n++
		}
	}
	return n
}

// yaml 生成可直接粘贴到配置文件的服务条目。内网地址无法从日志推导（需要 NAT 表），
// 以注释形式留出占位，避免生成一份「看起来完整但填错」的配置。
func (c Candidate) yaml() string {
	name := c.Service
	if name == "" {
		name = fmt.Sprintf("端口 %d", c.PublicPort)
	}
	return fmt.Sprintf("  # 候选：放行 %d 次、%d 个来源，最后 %s\n"+
		"  - public_ip: %s\n    public_port: %d\n    proto: %s\n"+
		"    # private_ip: <内网地址>   # 按实际 DNAT 填写\n    # private_port: %d\n    name: %s（候选）",
		c.Allows, c.Sources, c.LastSeen.Format("2006-01-02 15:04"), c.PublicIP, c.PublicPort, c.Proto, c.PublicPort, name)
}

// portService 返回常见端口的服务名，仅用于建议中的可读名称。
func portService(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 465:
		return "SMTPS"
	case 587:
		return "SMTP 提交"
	case 993:
		return "IMAPS"
	case 1433:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5900:
		return "VNC"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP（备用端口）"
	case 8443:
		return "HTTPS（备用端口）"
	case 9200:
		return "Elasticsearch"
	case 27017:
		return "MongoDB"
	}
	return ""
}
