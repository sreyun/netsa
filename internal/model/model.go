// Package model 定义贯穿整个处理流水线的公共数据结构。
package model

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Severity 威胁等级。
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}
var sevLabels = []string{"信息", "低危", "中危", "高危", "严重"}

func (s Severity) String() string {
	if s < SevInfo || s > SevCritical {
		return "info"
	}
	return sevNames[s]
}

// Label 返回中文等级名称。
func (s Severity) Label() string {
	if s < SevInfo || s > SevCritical {
		return sevLabels[0]
	}
	return sevLabels[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = ParseSeverity(str)
	return nil
}

// ParseSeverity 解析英文或中文等级名，未知值视为 info。
func ParseSeverity(s string) Severity {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range sevNames {
		if s == n || s == sevLabels[i] {
			return Severity(i)
		}
	}
	return SevInfo
}

// Bump 将等级提升 n 级（不超过 critical）。
func (s Severity) Bump(n int) Severity {
	s += Severity(n)
	if s > SevCritical {
		return SevCritical
	}
	return s
}

// Kind 日志大类。
type Kind string

const (
	KindWeb      Kind = "web"
	KindFirewall Kind = "firewall"
)

// 防火墙动作归一化取值。
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ActionLog   = "log"
)

// 攻击阶段（简化的攻击链模型）。
const (
	PhaseRecon       = "recon"       // 侦察扫描
	PhaseExploit     = "exploit"     // 漏洞利用
	PhaseCredential  = "credential"  // 凭证攻击 / 暴力破解
	PhasePersistence = "persistence" // 后门控制
	PhaseImpact      = "impact"      // 拒绝服务 / 资源消耗
)

// 攻击结果研判。
const (
	ResultBlocked = "blocked" // 已被拦截（WAF / 防火墙）
	ResultFailed  = "failed"  // 目标不存在或请求失败
	ResultError   = "error"   // 后端异常，载荷可能已到达应用
	ResultSuccess = "success" // 疑似成功
	ResultPassed  = "passed"  // 未被拦截，但该类攻击无法从响应码判断是否成功（如 XSS、扫描器请求）
	ResultAllowed = "allowed" // 防火墙放行
	ResultUnknown = "unknown"
)

// Event 是解析后的统一日志事件，Web 与防火墙日志共用。
type Event struct {
	Time    time.Time
	Kind    Kind
	Source  string // 数据源名称
	Format  string // 识别出的日志格式
	SrcIP   string // 真实来源 IP（已按可信代理还原）
	SrcPort int
	DstIP   string
	DstPort int
	Proto   string
	Action  string
	Iface   string
	Flags   string // TCP 标志位
	// Outbound 表示出站流量（本机/内网主动发起），不作为攻击来源统计。
	Outbound bool

	// 安全设备（IPS/IDS/WAF/下一代防火墙）自身识别出的威胁，例如 Suricata 签名、FortiGate IPS 攻击名。
	Threat         string // 威胁/签名名称
	ThreatCategory string // 设备给出的分类
	ThreatSeverity string // 设备给出的等级（原始文本或数字）

	Host      string
	Method    string
	URI       string
	HTTPProto string
	Status    int
	Bytes     int64
	Referer   string
	UA        string
	XFF       string
	XRealIP   string
	// ClientHeaders 保存其他携带客户端地址的请求头（键为 cf_connecting_ip / true_client_ip / forwarded 等），
	// 仅在日志格式记录了这些头时填充。
	ClientHeaders map[string]string
	PeerIP        string // 直连对端（代理）IP，仅在经由代理还原时设置
	ReqTime       float64

	Raw string
}

// Target 返回事件的攻击目标描述。
func (e *Event) Target() string {
	if e.Kind == KindWeb {
		h := e.Host
		if h == "" {
			h = "-"
		}
		return h + " " + e.URI
	}
	dst := e.DstIP
	if dst == "" {
		dst = "*"
	}
	if e.DstPort > 0 {
		return dst + ":" + strconv.Itoa(e.DstPort) + "/" + e.Proto
	}
	return dst + "/" + e.Proto
}

// Hit 是一次检测命中。
type Hit struct {
	RuleID   string
	Name     string
	Category string
	Severity Severity
	Phase    string
	Evidence string
	Result   string
	// TagOnly 表示只给 IP 打标签，不生成告警（例如脚本类 UA）。
	TagOnly bool
}

// Alert 是对外展示的告警记录。
type Alert struct {
	ID       uint64    `json:"id"`
	Time     time.Time `json:"time"`
	Kind     Kind      `json:"kind"`
	SrcIP    string    `json:"src_ip"`
	Location string    `json:"location"`
	RuleID   string    `json:"rule_id"`
	Name     string    `json:"name"`
	Category string    `json:"category"`
	Severity Severity  `json:"severity"`
	Phase    string    `json:"phase"`
	Result   string    `json:"result"`
	Target   string    `json:"target"`
	Method   string    `json:"method,omitempty"`
	Status   int       `json:"status,omitempty"`
	Evidence string    `json:"evidence"`
	UA       string    `json:"ua,omitempty"`
	Source   string    `json:"source"`
	Lat      float64   `json:"lat,omitempty"`
	Lon      float64   `json:"lon,omitempty"`
}
