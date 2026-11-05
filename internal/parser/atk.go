package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"netsa/internal/model"
)

// 防火墙自身的攻击防范判定：华为 USG / HiSecEngine 的 ANTIATTACK（攻击防范）、ANTIDDOS 日志，H3C SecPath 的 ATK 日志，
// 深信服 AF 的 DOS / IPS / WAF 等安全日志。设备已经判定为攻击，解析为设备威胁（Threat），由检测引擎按名称归类
// （洪泛 → 洪水攻击，扫描 → 端口扫描 / 主机探测，Land / Smurf / Teardrop 等畸形报文 → 洪水攻击，IP 欺骗 → IP伪造）。
//
// 与通用的 key=value 解析不同：
//   - 取值里有空格（AttackType=Syn flood attack），按分隔符（华为“, ”、H3C“;”、深信服“, ”与中文逗号）切分后再取键值；
//   - H3C 的洪泛类日志只记录被攻击的目的地址（来源是大量伪造地址），解析为 NoSource 的设备威胁：不建立来源画像，
//     只计入攻击统计、资产攻击链路，并与按会话日志判断的多源 DDoS 相互印证；
//   - 攻击类型取日志字段，没有时由 H3C 的日志助记符（ATK_IP4_TCP_SYNFLOOD）还原；
//   - 次数（TotalPackets、AtkTimes）写进设备威胁的分类说明，便于核对攻击规模。

// AttackDefense 解析防火墙攻击防范日志。
type AttackDefense struct{}

func (AttackDefense) Name() string { return "atk_defense" }

var (
	// 信息中心格式的日志头：%%01ANTIATTACK/4/ANTIATTACK(l)[0]:、%%10ATK/3/ATK_IP4_TCP_SYNFLOOD:、%%10IPS/4/IPS_IPV4_INTERZONE:
	reATKHeader = regexp.MustCompile(`%%\d{2}(ANTI-?ATTACK|ATK|ANTI-?DDOS|DDOS|ATTACK|SECE|IPS|AV|ANTIVIRUS)/(\d)/([A-Za-z0-9_\-]+)(?:\([a-z]\))?(?:\[\d+\])?:\s*`)
)

// 攻击防范日志的键名（小写、去掉下划线与连字符、去掉 H3C 的字段编号）。
var (
	atkSrc     = []string{"srcip", "srcipaddr", "sourceip", "srcaddr", "attackerip", "srcipv4", "源ip", "源地址", "攻击者ip", "攻击源ip"}
	atkDst     = []string{"dstip", "dstipaddr", "destinationip", "dstaddr", "destip", "targetip", "dstipv4", "目的ip", "目的地址", "目标ip", "受害者ip", "被攻击ip"}
	atkSPort   = []string{"srcport", "sourceport", "源端口"}
	atkDPort   = []string{"dstport", "destinationport", "destport", "目的端口", "目标端口"}
	atkProto   = []string{"protocol", "proto", "协议"}
	atkAct     = []string{"action", "动作", "处理动作", "系统动作", "处置动作", "执行动作"}
	atkName    = []string{"attacktype", "attackname", "atktype", "signname", "threatname", "attack", "攻击类型", "攻击名称", "威胁名称", "漏洞名称", "规则名称", "事件名称"}
	atkCat     = []string{"category", "threattype", "日志类型", "威胁类型", "攻击分类"}
	atkSev     = []string{"severity", "level", "严重级别", "威胁等级", "危险等级", "风险等级", "等级"}
	atkCount   = []string{"totalpackets", "atktimes", "packets", "packetcount", "攻击次数", "包数"}
	atkBegin   = []string{"begintimec", "begintime", "starttime", "开始时间", "时间"}
	atkSrcZone = []string{"srczone", "srczonename", "sourcezone", "源区域"}
	atkDstZone = []string{"dstzone", "dstzonename", "destinationzone", "目的区域"}
)

// h3cMnemonic 把 H3C ATK 日志的助记符还原为攻击类型（按顺序匹配）。
var h3cMnemonic = []struct{ key, name string }{
	{"SYNACKFLOOD", "SYN-ACK Flood"}, {"SYN_ACK_FLOOD", "SYN-ACK Flood"}, {"SYNFLOOD", "SYN Flood"}, {"SYN_FLOOD", "SYN Flood"},
	{"ACKFLOOD", "ACK Flood"}, {"FINFLOOD", "FIN Flood"}, {"RSTFLOOD", "RST Flood"}, {"UDPFLOOD", "UDP Flood"}, {"UDP_FLOOD", "UDP Flood"},
	{"ICMPV6FLOOD", "ICMPv6 Flood"}, {"ICMPFLOOD", "ICMP Flood"}, {"ICMP_FLOOD", "ICMP Flood"}, {"DNSFLOOD", "DNS Flood"},
	{"HTTPFLOOD", "HTTP Flood"}, {"HTTPSFLOOD", "HTTPS Flood"}, {"SIPFLOOD", "SIP Flood"}, {"FLOOD", "Flood"},
	{"PORTSCAN", "Port scan"}, {"IPSWEEP", "IP sweep"}, {"LAND", "Land attack"}, {"SMURF", "Smurf attack"},
	{"TEARDROP", "Teardrop attack"}, {"TEAR_DROP", "Teardrop attack"}, {"PINGOFDEATH", "Ping of death"}, {"PING_OF_DEATH", "Ping of death"},
	{"WINNUKE", "WinNuke attack"}, {"FRAGGLE", "Fraggle attack"}, {"LARGE_ICMP", "Large ICMP packet"}, {"TRACEROUTE", "Traceroute"},
	{"IP_OPTION", "IP option attack"}, {"FRAGMENT", "IP fragment attack"}, {"TCP_NULLFLAG", "TCP null flag attack"},
	{"TCP_ALLFLAGS", "TCP all flags attack"}, {"TCP_SYNFIN", "TCP SYN-FIN attack"}, {"TCP_INVALIDFLAGS", "TCP invalid flags attack"},
	{"TCP_FINONLY", "TCP FIN only attack"}, {"ICMP_REDIRECT", "ICMP redirect"}, {"ICMP_UNREACHABLE", "ICMP unreachable"},
	{"IPSPOOF", "IP spoofing attack"}, {"IP_SPOOF", "IP spoofing attack"},
}

// atkKey 归一化键名：去掉 H3C 的字段编号（SrcIPAddr(1003)），小写，去掉下划线、连字符、点与空格。
func atkKey(k string) string {
	k = strings.TrimSpace(k)
	if i := strings.IndexByte(k, '('); i > 0 && strings.HasSuffix(k, ")") {
		k = k[:i]
	}
	return strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(k))
}

// atkPairs 按分隔符切分后取键值：华为“, ”、H3C“;”、深信服“, ”与中文逗号；键值之间为 = 或（中英文）冒号。
func atkPairs(body string, colon bool) map[string]string {
	kv := make(map[string]string, 24)
	body = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(body), "."))
	for _, f := range strings.FieldsFunc(strings.ReplaceAll(body, "，", ";"), func(r rune) bool { return r == ';' }) {
		for _, p := range splitCommaSpace(f) {
			k, v, ok := cutKV(p, colon)
			if !ok {
				continue
			}
			k = atkKey(k)
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			if _, dup := kv[k]; !dup && k != "" {
				kv[k] = v
			}
		}
	}
	return kv
}

// splitCommaSpace 按“, ”切分（H3C 的 Action=logging,drop 中不带空格的逗号保留）。
func splitCommaSpace(s string) []string {
	var out []string
	for {
		i := strings.Index(s, ", ")
		if i < 0 {
			return append(out, s)
		}
		out = append(out, s[:i])
		s = s[i+2:]
	}
}

// cutKV 在第一个 = 处（深信服日志在第一个冒号处）拆分键值。冒号格式的取值里可能还有冒号（时间、IPv6），只按第一个拆。
func cutKV(p string, colon bool) (string, string, bool) {
	if colon {
		i := strings.IndexAny(p, ":：")
		j := strings.IndexByte(p, '=')
		if i >= 0 && (j < 0 || i < j) {
			sz := 1
			if strings.HasPrefix(p[i:], "：") {
				sz = len("：")
			}
			return p[:i], p[i+sz:], true
		}
	}
	return strings.Cut(p, "=")
}

func (AttackDefense) Parse(line string) (*model.Event, bool) {
	var kv map[string]string
	format, level, mnemonic := "", -1, ""
	switch {
	case strings.Contains(line, "%%"):
		m := reATKHeader.FindStringSubmatchIndex(line)
		if m == nil {
			return nil, false
		}
		mod := strings.ToUpper(line[m[2]:m[3]])
		level, _ = strconv.Atoi(line[m[4]:m[5]])
		mnemonic = strings.ToUpper(line[m[6]:m[7]])
		if mod == "SECE" && !strings.Contains(mnemonic, "ATTACK") {
			return nil, false // 华为交换机的安全模块还有 ARP、DHCP 等日志，只取攻击类
		}
		// H3C 的字段带编号（SrcIPAddr(1003)=），华为没有
		vendor := "huawei"
		if mod == "ATK" || strings.Contains(line[m[1]:], ")=") {
			vendor = "h3c"
		}
		format = vendor + "_atk"
		switch mod {
		case "IPS":
			format = vendor + "_ips"
		case "AV", "ANTIVIRUS":
			format = vendor + "_av"
		}
		kv = atkPairs(line[m[1]:], false)
	case strings.Contains(line, "日志类型:") || strings.Contains(line, "日志类型："):
		i := strings.Index(line, "日志类型")
		kv = atkPairs(line[i:], true)
		format = "sangfor"
		if !sangforAttack(kv["日志类型"]) {
			return nil, false
		}
	default:
		return nil, false
	}
	src, dst := pick(kv, atkSrc...), pick(kv, atkDst...)
	if src != "" && !isIP(src) || dst != "" && !isIP(dst) || src == "" && dst == "" {
		return nil, false
	}
	name := pick(kv, atkName...)
	if name == "" && mnemonic != "" {
		name = mnemonicName(mnemonic)
	}
	if name == "" {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: format, SrcIP: src, DstIP: dst,
		Threat: name, SrcZone: pick(kv, atkSrcZone...), DstZone: pick(kv, atkDstZone...)}
	ev.SrcPort, _ = strconv.Atoi(pick(kv, atkSPort...))
	ev.DstPort, _ = strconv.Atoi(pick(kv, atkDPort...))
	proto := pick(kv, atkProto...)
	if proto == "" { // H3C 的助记符里写着协议：ATK_IP4_TCP_SYNFLOOD、ATK_IP4_UDPFLOOD、ATK_IP4_ICMP_FLOOD
		switch {
		case containsAny(mnemonic, "TCP", "SYN", "ACKFLOOD", "FINFLOOD", "RSTFLOOD", "HTTP"):
			proto = "tcp"
		case containsAny(mnemonic, "UDP", "DNS", "SIP", "FRAGGLE"):
			proto = "udp"
		case containsAny(mnemonic, "ICMP", "SMURF", "PINGOFDEATH", "PING_OF_DEATH"):
			proto = "icmp"
		}
	}
	ev.Proto = normProto(proto)
	if src == "" {
		ev.NoSource = true // 多源洪泛：设备只记录被攻击的目的地址
	}
	ev.Action = atkAction(pick(kv, atkAct...))
	ev.ThreatCategory = pick(kv, atkCat...)
	if ev.ThreatCategory == "" {
		ev.ThreatCategory = map[string]string{"huawei_atk": "攻击防范", "h3c_atk": "攻击防范", "huawei_ips": "入侵防御", "h3c_ips": "入侵防御", "huawei_av": "病毒防护", "h3c_av": "病毒防护"}[format]
	}
	if n := pick(kv, atkCount...); n != "" {
		ev.ThreatCategory += "，" + n + " 次"
	}
	ev.ThreatSeverity = pick(kv, atkSev...)
	if ev.ThreatSeverity == "" {
		ev.ThreatSeverity = atkSeverity(name, level)
	}
	ev.Time = atkTime(pick(kv, atkBegin...))
	return ev, true
}

// sangforAttack 判断深信服日志类型是否为攻击类（DOS、IPS、WAF、僵尸网络、漏洞攻击等），流量审计、上网行为日志不是。
func sangforAttack(t string) bool {
	for _, k := range []string{"DOS", "DDOS", "IPS", "WAF", "攻击", "防护", "僵尸", "漏洞", "病毒", "入侵", "暴力破解", "扫描"} {
		if strings.Contains(strings.ToUpper(t), k) {
			return true
		}
	}
	return false
}

func mnemonicName(m string) string {
	m = strings.TrimPrefix(m, "ATK_")
	for _, x := range h3cMnemonic {
		if strings.Contains(m, x.key) {
			return x.name
		}
	}
	for _, p := range []string{"IP4_", "IP6_", "IPV4_", "IPV6_"} {
		m = strings.TrimPrefix(m, p)
	}
	for _, s := range []string{"_RAW_SZ", "_RAW", "_SZ"} {
		m = strings.TrimSuffix(m, s)
	}
	return strings.ToLower(strings.ReplaceAll(m, "_", " "))
}

// atkAction 归一化动作：设备丢弃 / 阻断为拦截；只记录（logging、alert、记录）为放行。
func atkAction(s string) string {
	l := strings.ToLower(s)
	switch {
	case containsAny(l, "drop", "discard", "deny", "block", "reset", "reject", "丢弃", "拒绝", "阻断", "拦截", "已阻断"):
		return model.ActionDeny
	case containsAny(l, "log", "alert", "permit", "pass", "allow", "记录", "允许", "放行", "告警"):
		return model.ActionAllow
	}
	return model.ActionLog
}

// atkSeverity 是日志没有等级字段时的默认等级：扫描与探测为低危（互联网上的常态），畸形报文为中危，
// 洪泛按设备的日志级别（0~3 为错误及以上）判断。设备拦截后由等级裁决按结果调整。
func atkSeverity(name string, level int) string {
	l := strings.ToLower(name)
	switch {
	case containsAny(l, "scan", "sweep", "traceroute", "扫描"):
		return "low"
	case containsAny(l, "flood", "洪水", "泛洪", "洪泛", "ddos", "dos"):
		if level >= 0 && level <= 3 {
			return "high"
		}
		return "medium"
	}
	return "medium"
}

// atkTime 解析攻击开始时间：H3C 的 20261105101450、华为的 2026/11/05 10:14:50 等。解析不了时由调用方使用 syslog 头的时间。
func atkTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if len(s) == 14 && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		loc := Location
		if loc == nil {
			loc = time.Local
		}
		if t, err := time.ParseInLocation("20060102150405", s, loc); err == nil {
			return t
		}
	}
	return ParseTime(s)
}
