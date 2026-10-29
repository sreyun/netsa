package parser

import (
	"regexp"
	"strconv"
	"strings"

	"netsa/internal/model"
)

// ---------------- Palo Alto Networks PAN-OS（CSV：TRAFFIC / THREAT） ----------------

// PaloAlto 解析 PAN-OS 的 TRAFFIC 与 THREAT 日志。字段位置依据 PAN-OS 官方 syslog 字段说明：
// 7 源地址、8 目的地址、24 源端口、25 目的端口、29 协议、30 动作；THREAT 另有 32 威胁名、33 分类、34 严重等级。
type PaloAlto struct{}

func (PaloAlto) Name() string { return "paloalto" }

var paActions = map[string]bool{"allow": true, "deny": true, "drop": true, "drop-icmp": true, "reset-client": true,
	"reset-server": true, "reset-both": true, "block-url": true, "alert": true, "block": true, "sinkhole": true}

func (PaloAlto) Parse(line string) (*model.Event, bool) {
	if !strings.Contains(line, ",TRAFFIC,") && !strings.Contains(line, ",THREAT,") {
		return nil, false
	}
	// 字段 0 为保留字段（未使用），即使前面残留 syslog 头也不影响后续字段位置
	f := strings.Split(strings.TrimSpace(line), ",")
	if len(f) < 31 || (f[3] != "TRAFFIC" && f[3] != "THREAT") || !isIP(f[7]) || !paActions[f[30]] {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: "paloalto", SrcIP: f[7], DstIP: f[8], Proto: normProto(f[29]),
		Action: normAction(f[30]), Iface: f[18], Time: ParseTime(f[6])}
	ev.SrcPort, _ = strconv.Atoi(f[24])
	ev.DstPort, _ = strconv.Atoi(f[25])
	// 会话信息：10 NAT 目的地址、11 规则名、16 / 17 源 / 目的安全域；流量日志 45 为应答方向包数（只采信会话结束的 end 日志）
	if isIP(f[10]) && f[10] != "0.0.0.0" {
		ev.NatDstIP = f[10]
	}
	ev.Policy, ev.SrcZone, ev.DstZone = f[11], f[16], f[17]
	if f[3] == "TRAFFIC" && f[4] == "end" && len(f) > 45 {
		if n, err := strconv.ParseInt(f[45], 10, 64); err == nil {
			ev.Reply = model.ReplyYes
			if n == 0 {
				ev.Reply = model.ReplyNone
			}
		}
	}
	if f[3] == "THREAT" && len(f) > 34 {
		switch f[4] { // 子类型：url / file / data 为内容过滤，不视为攻击
		case "url", "file", "data":
		default:
			ev.Threat = strings.Trim(f[32], `"`)
			ev.ThreatCategory = f[4]
			if f[33] != "" && f[33] != "any" {
				ev.ThreatCategory = f[4] + "/" + f[33]
			}
			ev.ThreatSeverity = f[34]
		}
	}
	return ev, true
}

// ---------------- Snort / Suricata fast alert ----------------

var reSnort = regexp.MustCompile(`^(?:(\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+)?(?:\[\*\*\]\s+)?\[\d+:\d+:\d+\]\s+(.*?)\s+(?:\[\*\*\]\s*)?(?:\[Classification:\s*([^\]]*)\]\s*)?(?:\[Priority:\s*(\d+)\]\s*)?\{(\w+)\}\s+(\S+?)(?::(\d+))?\s+->\s+(\S+?)(?::(\d+))?\s*$`)

// SnortFast 解析 Snort/Suricata 的 fast 告警格式（含 syslog 输出）。
type SnortFast struct{}

func (SnortFast) Name() string { return "snort" }

func (SnortFast) Parse(line string) (*model.Event, bool) {
	if !strings.Contains(line, "] ") || !strings.Contains(line, "->") {
		return nil, false
	}
	m := reSnort.FindStringSubmatch(line)
	if m == nil || !isIP(m[6]) {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: "snort", Time: ParseTime(m[1]), Threat: m[2], ThreatCategory: m[3],
		ThreatSeverity: priorityWord(m[4]), Proto: normProto(m[5]), SrcIP: m[6], DstIP: m[8], Action: model.ActionLog}
	ev.SrcPort, _ = strconv.Atoi(m[7])
	ev.DstPort, _ = strconv.Atoi(m[9])
	return ev, true
}

// priorityWord 将 Snort/Suricata 的数字优先级（1 最高）转换为等级文本。
func priorityWord(p string) string {
	switch p {
	case "1":
		return "high"
	case "2":
		return "medium"
	case "3":
		return "low"
	case "":
		return ""
	}
	return "info"
}

// ---------------- 键值对 / JSON 设备日志中的威胁字段 ----------------

var (
	kvThreat    = []string{"attack", "attackname", "threatname", "threat", "signature", "signame", "virusname", "virus", "sigdesc"}
	kvThreatCat = []string{"category", "threattype", "attacktype", "attackcategory", "threatcategory", "subtype"}
	kvThreatSev = []string{"severity", "crlevel", "threatlevel", "threatseverity", "risk", "priority"}
)

// fillThreat 从键值对中提取安全设备识别出的威胁（IPS 攻击名、IDS 签名、病毒名等）。
func fillThreat(ev *model.Event, kv map[string]string) {
	ev.Threat = pick(kv, kvThreat...)
	if ev.Threat == "" {
		return
	}
	ev.ThreatCategory = pick(kv, kvThreatCat...)
	ev.ThreatSeverity = pick(kv, kvThreatSev...)
	// Suricata EVE：alert.severity 为数字，1 表示最高
	if ev.Format == "json_firewall" && kv["eventtype"] == "alert" {
		ev.Format = "suricata"
		ev.ThreatSeverity = priorityWord(ev.ThreatSeverity)
	}
}
