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
//
// 用于「展示类」输入（查询参数、设备上报文本），容错优先。配置文件里的规则等级应使用
// TryParseSeverity，避免拼写错误被静默降为 info。
func ParseSeverity(s string) Severity {
	if v, ok := TryParseSeverity(s); ok {
		return v
	}
	return SevInfo
}

// TryParseSeverity 严格解析等级名，无法识别时返回 false。
func TryParseSeverity(s string) (Severity, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range sevNames {
		if s == n || s == sevLabels[i] {
			return Severity(i), true
		}
	}
	return SevInfo, false
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
	KindDNS      Kind = "dns"  // DNS 查询日志（主体为发起查询的内网主机）
	KindAuth     Kind = "auth" // 主机 / VPN 认证日志（SSH、RDP、Windows 登录、VPN 登录等）
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
	PhaseCollection  = "collection"  // 数据窃取（接口遍历、批量爬取）
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

// Reply 是防火墙会话日志记录的应答情况。只有会话结束时输出的日志才有收发包计数，会话建立时的日志与策略匹配日志没有。
type Reply uint8

const (
	ReplyUnknown Reply = iota // 日志未记录收发包计数
	ReplyNone                 // 会话结束时目标方向没有任何应答（0 个包）
	ReplyYes                  // 目标有应答
)

// Reach 是根据防火墙会话证据（安全域、DNAT 后地址、应答包数）对一次放行的外部访问是否到达服务的判断，由流水线填写。
type Reach uint8

const (
	ReachUnknown Reach = iota // 日志没有可用的证据
	ReachNo                   // 证据表明没有到达任何服务
	ReachDevice               // 目标是防火墙自身（local 安全域）
	ReachYes                  // 证据表明到达了内部服务
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
	// 防火墙记录的会话信息（日志中有时填充）：源 / 目的安全域、命中的安全策略、DNAT 后的目的地址、应答情况。
	// 用于判断一次探测是否真的到达了服务（见 exposure.Reach）。
	SrcZone  string
	DstZone  string
	Policy   string
	NatDstIP string
	Reply    Reply
	Reach    Reach // 流水线按上述证据判断的到达情况（攻击面、安全评估据此判断服务是否真实对外开放）

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
	// 认证日志：User 为登录账号，Service 为认证服务（SSH / RDP / VPN …），EventID 为 Windows 安全事件 ID；
	// Action 为 allow（成功）/ deny（失败）。SubjectHost 表示 SrcIP 是上报日志的主机本身（没有远程来源的主机事件，如日志被清除）。
	User        string
	Service     string
	EventID     int
	SubjectHost bool
	// DNS 日志：Host 为查询的域名，QType 为查询类型，RCode 为响应码（NOERROR / NXDOMAIN …）
	QType string
	RCode string

	// Asset 为攻击目标对应的资产（登记了资产台账时由流水线填写，仅攻击事件）
	Asset   *AssetRef
	ReqTime float64

	Raw string
}

// Target 返回事件的攻击目标描述。
func (e *Event) Target() string {
	switch e.Kind {
	case KindDNS:
		t := "DNS " + e.Host
		if e.QType != "" {
			t += " " + e.QType
		}
		return t
	case KindAuth:
		t := e.Service
		if t == "" {
			t = "登录"
		}
		if e.User != "" {
			t += " 账号 " + e.User
		}
		if e.Host != "" {
			t += " @" + e.Host
		} else if e.DstIP != "" {
			t += " @" + e.DstIP
		}
		return t
	}
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
	// Vuln 为关联到的目标资产上未修复的漏洞（CVE / 名称）
	Vuln string
}

// AssetRef 是事件目标资产的摘要。
type AssetRef struct {
	Name  string
	Level string // core / important / normal
	Owner string
}

// Alert 是对外展示的告警记录。
type Alert struct {
	ID         uint64    `json:"id"`
	Time       time.Time `json:"time"`
	Kind       Kind      `json:"kind"`
	SrcIP      string    `json:"src_ip"`
	Location   string    `json:"location"`
	RuleID     string    `json:"rule_id"`
	Name       string    `json:"name"`
	Category   string    `json:"category"`
	Severity   Severity  `json:"severity"`
	Phase      string    `json:"phase"`
	Result     string    `json:"result"`
	Target     string    `json:"target"`
	Method     string    `json:"method,omitempty"`
	Status     int       `json:"status,omitempty"`
	Evidence   string    `json:"evidence"`
	UA         string    `json:"ua,omitempty"`
	Source     string    `json:"source"`
	Lat        float64   `json:"lat,omitempty"`
	Lon        float64   `json:"lon,omitempty"`
	IncidentID uint64    `json:"incident_id,omitempty"` // 所属安全事件
	Asset      string    `json:"asset,omitempty"`       // 目标资产名称
	AssetLevel string    `json:"asset_level,omitempty"` // 目标资产重要性：core / important / normal
	Owner      string    `json:"owner,omitempty"`       // 资产负责人
	Vuln       string    `json:"vuln,omitempty"`        // 关联的未修复漏洞
}
