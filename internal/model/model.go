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
	// KindProcess 是主机的进程、文件、注册表、进程访问事件与 EDR / HIDS 告警（Sysmon、Windows 4688、auditd、Wazuh），
	// 主体为上报日志的主机：DstIP 为主机地址（日志记录了时），Host 为主机名
	KindProcess Kind = "process"
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
	// NoSource 表示设备只记录了被攻击的目的地址，没有来源（防火墙攻击防范的多源洪泛日志，来源多为伪造地址）：
	// 不建立来源画像，只计入攻击统计、资产攻击链路，并与多源 DDoS 检测相互印证
	NoSource bool
	// Replay 表示事后补发命中的事件副本：原事件已经计入事件量（服务器被判定失陷时补记它此前发起的横向连接），
	// 只记录命中，不再计入事件量与画像的访问统计
	Replay bool
	// DNS 日志：Host 为查询的域名，QType 为查询类型，RCode 为响应码（NOERROR / NXDOMAIN …）
	QType string
	RCode string

	// Asset 为攻击目标对应的资产（登记了资产台账时由流水线填写，仅攻击事件）
	Asset   *AssetRef
	ReqTime float64
	// Web 日志的增强字段（nginx 的 log_format 增加 $request_length $upstream_status $upstream_response_time
	// $ssl_protocol $ssl_cipher 后才有）：请求长度（含请求头与请求体）；后端应用的响应码（0 为日志没有记录，
	// -1 为请求没有转发到后端，由 nginx 自己响应：静态文件、return、限流、缓存）；后端耗时；TLS 协议与加密套件
	ReqLength    int64
	Upstream     int
	UpstreamTime float64
	TLSProto     string
	TLSCipher    string
	// TLSFinger 是客户端的 TLS 指纹（流量日志的 JA3 / JA4；只有 Web 日志时为“协议/加密套件”）
	TLSFinger string
	// SentBytes / RecvBytes 是防火墙、流量日志记录的会话字节数：发起方发送 / 接收（0 为没有记录）；Packets 为包数
	SentBytes int64
	RecvBytes int64
	Packets   int64
	// Duration 是会话 / 流的持续时间（秒，0 为没有记录）：长连接结束时一次性报告的字节数按时长折算到统计窗口
	Duration float64
	// SrcHost 是认证日志记录的来源主机名（Windows 4624 的 WorkstationName），用于串起横向登录链
	SrcHost string
	// PayloadAddrs 是利用载荷中写明的公网地址（反弹 Shell、下载执行、JNDI 的回连地址），由流水线的联动检测提取。
	// 资产攻击链路据此把之后连接这些地址的服务器与被攻击的站点串起来
	PayloadAddrs []string

	// Body 是日志记录的请求体（Zeek 的 post_body、nginx 的 $request_body；截断到 4 KB），与查询参数一样参与规则匹配
	Body string
	// Aux 表示同一连接的辅助记录（Zeek ssl.log、files.log）：连接本身已由会话日志（conn.log）记录，
	// 只用于情报匹配、TLS 指纹、文件证据与关联，不计入事件量、连接统计与行为检测
	Aux bool
	// SNI 是 TLS 握手中的服务器名称（Zeek ssl.log 的 server_name）
	SNI string
	// File 是传输的文件（Zeek files.log），Proc 是进程事件的详情（KindProcess）
	File *FileInfo
	Proc *ProcInfo
	// Bps / Pps 是抗 D 服务、流量设备报告的攻击峰值（比特每秒、包每秒）
	Bps int64
	Pps int64
	// Sampling 是流量日志（NetFlow / sFlow）的采样率，SentBytes / Packets 已按采样率还原
	Sampling int
	// Response 表示单向流量记录中服务端发回客户端的方向（源端口为服务端口、目的端口为临时端口）：
	// 不是新的连接，只计入带宽统计，不参与扫描、回连、外连情报与外传检测
	Response bool

	Raw string
}

// FileInfo 是流量日志记录的一次文件传输。
type FileInfo struct {
	Name   string
	Mime   string
	Size   int64
	MD5    string
	SHA1   string
	SHA256 string
	Proto  string // 传输协议：HTTP / FTP / SMB / SMTP …
}

// ProcInfo 是一次主机进程事件。
type ProcInfo struct {
	Op          string // process（进程创建）/ network（网络连接）/ file（文件创建）/ registry（注册表）/ access（进程访问）/ alert（EDR 告警）
	Image       string // 进程路径
	CommandLine string
	Parent      string // 父进程路径
	ParentCmd   string
	User        string
	PID         int
	Target      string // 文件路径、注册表键、被访问的进程（lsass.exe）
	Access      string // 进程访问权限（Sysmon 10 的 GrantedAccess）
	Rule        string // EDR / HIDS 告警的规则编号
	Level       int    // EDR / HIDS 告警的等级（Wazuh 0~15）
	Mitre       []string
}

// Target 返回事件的攻击目标描述。其中来自日志的内容（账号、域名、进程、URI）里的控制字符与非法字节转义为 \xHH，
// 页面、告警推送与导出中不会出现乱码。
func (e *Event) Target() string { return Printable(e.target(), 0) }

func (e *Event) target() string {
	switch e.Kind {
	case KindProcess:
		t := e.Host
		if t == "" {
			t = e.DstIP
		}
		if e.Proc != nil {
			switch {
			case e.Proc.Target != "" && e.Proc.Op != "process":
				t += " " + e.Proc.Target
			case e.Proc.Image != "":
				t += " " + e.Proc.Image
			}
		}
		return t
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
	if e.File != nil && e.File.Name != "" {
		return e.SrcIP + " ← " + e.DstIP + " 文件 " + e.File.Name
	}
	if e.Kind == KindWeb {
		return webTarget(e.Host, e.Method, e.URI)
	}
	dst := e.DstIP
	if dst == "" {
		dst = "*"
	}
	// ICMP 没有端口：部分设备把类型 / 代码（如回显请求 8×256=2048）写在端口字段里，按端口显示会成为“2048/icmp”
	if e.DstPort > 0 && !strings.HasPrefix(e.Proto, "icmp") {
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
	// Learned 是自学习对本次命中的调整：-1 按分析员的误报结论下调一级，+1 来源曾被确认为攻击、升级一级。
	// 等级裁决据此放宽分类底线（下调的命中最多低于底线一级），见 risk.Finalize
	Learned int8
	// Proven 表示响应码之外还有第二份证据证明攻击成功（目标确有该漏洞、响应明显大于接口基线、脚本交互等）。
	// 只凭 2xx 判定的“疑似成功”最高到高危，有第二份证据才升为严重，见 risk.Finalize
	Proven bool
	// Disproven 表示复核确认响应只是兜底页面（单页应用、统一错误页），分类底线放宽一级
	Disproven bool
	// Weak 表示特征只出现在自由文本里，没有可执行的内容（如搜索“<script> 标签的用法”）：不按分类底线抬升，最高低危
	Weak bool
	// Syntax 是语法分析（libinjection）对 SQL 注入、XSS 命中的复核：1 构成注入，-1 不构成注入，0 未复核
	Syntax int8
	// Param 是命中所在的查询参数名（只记录 SQL 注入、XSS、命令执行这类可能出现在普通文字里的命中）
	Param string
	// Inapplicable 表示站点没有运行攻击针对的产品、请求也没有成功（被动识别站点产品，见 learn/site.go）：最高低危
	Inapplicable bool
	// SelfRef 表示远程文件包含的参数地址全部指向请求的 Host（如 pdf.js 预览本站的文件）。Host 头由客户端提供，
	// 由状态库确认它是已登记的资产、或有正常访问的真实站点后才丢弃这条命中，否则照常告警
	SelfRef bool
	// Feeds 是产生这条命中的威胁情报源（情报命中才有），事件按情报源累计，自学习据此统计每个情报源的准确率
	Feeds []string
}

// AssetRef 是事件目标资产的摘要。
type AssetRef struct {
	Name  string
	Level string // core / important / normal
	Owner string
	// Group 表示资产按网段或通配域名登记、事件只是落在其范围内（一个网段内有多台主机、多个站点）：
	// 资产攻击链路仍按主机地址或站点区分，不把整个网段合并成一个资产
	Group bool
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
	// Learned 是自学习对等级的调整（+1：来源被确认为攻击后升级一级；-1：按误报结论下调一级）；
	// Retracted 是自学习纠错后撤销这条告警（或其中的升级）的原因：观察规则已停用、自动确认的来源被撤销
	Learned    int8   `json:"learned,omitempty"`
	Retracted  string `json:"retracted,omitempty"`
	Asset      string `json:"asset,omitempty"`       // 目标资产名称
	AssetLevel string `json:"asset_level,omitempty"` // 目标资产重要性：core / important / normal
	Owner      string `json:"owner,omitempty"`       // 资产负责人
	Vuln       string `json:"vuln,omitempty"`        // 关联的未修复漏洞
	Proven     bool   `json:"proven,omitempty"`      // 有响应码之外的第二份成功证据
}
