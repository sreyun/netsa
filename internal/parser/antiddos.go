package parser

import (
	"fmt"
	"strconv"
	"strings"

	"netsa/internal/model"
)

// CloudDDoS 解析云厂商抗 D 服务（阿里云 DDoS 防护、腾讯云大禹、华为云 AAD 等）与运营商清洗中心推送的攻击事件
// （JSON，经日志服务投递、Webhook 落盘或 syslog 转发）。各厂商的字段名不同，这里按常见的键名识别：
// 被攻击的地址（ip / vip / target_ip / attacked_ip …）、攻击类型、峰值带宽（bps / max_bps / mbps / gbps …）、
// 峰值包速率（pps / max_pps / kpps …）与状态（开始、清洗中、黑洞、结束）。攻击流量的来源不记录（多为伪造或反射），
// 按目的地址告警（NoSource），与按流量日志判断的带宽型 DDoS 相互印证。攻击结束的事件只计为跳过。
// 字段按公开文档整理，接入现场数据后请对照真实日志核对。
type CloudDDoS struct{}

func (CloudDDoS) Name() string { return "cloud_ddos" }

var (
	ddosTargetKeys = []string{"attacked_ip", "target_ip", "victim_ip", "instance_ip", "protected_ip", "dst_ip", "dest_ip", "dstip", "vip", "eip", "ip", "target"}
	ddosTypeKeys   = []string{"attack_type", "attacktype", "attack_types", "attacktypes", "attack_name", "event_name", "type"}
	ddosStatusKeys = []string{"status", "state", "event_status", "attack_status", "event_type", "eventtype", "action", "event"}
)

func (CloudDDoS) prefilter(line string) bool {
	if !strings.HasPrefix(strings.TrimSpace(line), "{") {
		return false
	}
	l := strings.ToLower(line)
	return (strings.Contains(l, "ddos") || strings.Contains(l, "attack")) &&
		(strings.Contains(l, "bps") || strings.Contains(l, "pps"))
}

func (c CloudDDoS) Parse(line string) (*model.Event, bool) {
	ev, end, ok := c.parse(line)
	if !ok || end {
		return nil, false
	}
	return ev, true
}

// Skip 把攻击结束的事件计为跳过。
func (c CloudDDoS) Skip(line string) bool {
	_, end, ok := c.parse(line)
	return ok && end
}

func (c CloudDDoS) parse(line string) (*model.Event, bool, bool) {
	line = strings.TrimSpace(line)
	if !c.prefilter(line) {
		return nil, false, false
	}
	m, ok := unmarshalLog(line)
	if !ok {
		return nil, false, false
	}
	kv := flattenLower(m)
	dst := ""
	for _, k := range ddosTargetKeys {
		if v := strings.TrimSpace(kv[k]); isIP(v) {
			dst = v
			break
		}
	}
	bps, pps := ddosRate(kv, "bps"), ddosRate(kv, "pps")
	if dst == "" || bps <= 0 && pps <= 0 {
		return nil, false, false
	}
	status := strings.ToLower(pick(kv, ddosStatusKeys...))
	end := false
	for _, w := range []string{"end", "stop", "finish", "recover", "结束", "解封", "恢复"} {
		if strings.Contains(status, w) && !strings.Contains(status, "blackhole") {
			end = true
		}
	}
	typ := pick(kv, ddosTypeKeys...)
	if typ == "" || strings.EqualFold(typ, "ddos") {
		typ = "DDoS 攻击"
	}
	desc := fmt.Sprintf("%s，峰值 %s", Printable(typ, 60), rateText(bps, pps))
	ev := &model.Event{Kind: model.KindFirewall, Format: "cloud_ddos", DstIP: dst, NoSource: true, Bps: bps, Pps: pps,
		Proto: strings.ToLower(pick(kv, "protocol", "proto")), Action: model.ActionLog}
	ev.DstPort, _ = strconv.Atoi(pick(kv, "dst_port", "port", "dport"))
	sev := "high"
	switch {
	case strings.Contains(status, "blackhole") || strings.Contains(status, "黑洞") || strings.Contains(status, "封堵"):
		desc += "，已触发黑洞（该地址暂时无法访问）"
		sev, ev.Action = "critical", model.ActionDeny
	case strings.Contains(status, "clean") || strings.Contains(status, "scrub") || strings.Contains(status, "清洗") || strings.Contains(status, "mitigat"):
		desc += "，正在清洗"
		ev.Action = model.ActionDeny
	}
	vendor := pick(kv, "vendor", "product", "source", "service")
	ev.Threat, ev.ThreatCategory, ev.ThreatSeverity = desc, "DDoS", sev
	if vendor != "" {
		ev.ThreatCategory = "DDoS（" + Printable(vendor, 30) + "）"
	}
	ev.Time = ParseTime(pick(kv, "start_time", "starttime", "begin_time", "attack_time", "time", "timestamp", "@timestamp", "event_time"))
	return ev, end, true
}

// ddosRate 读取峰值速率：按单位后缀（bps / kbps / mbps / gbps）换算为每秒的比特数或包数。
func ddosRate(kv map[string]string, unit string) int64 {
	for _, pfx := range []string{"max_", "peak_", "in_", "attack_", "inbound_", "max", "peak", "in", ""} {
		for _, mul := range []struct {
			p string
			f float64
		}{{"g", 1e9}, {"m", 1e6}, {"k", 1e3}, {"", 1}} {
			if v, ok := kv[pfx+mul.p+unit]; ok {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > 0 {
					return int64(f * mul.f)
				}
			}
		}
	}
	return 0
}

func rateText(bps, pps int64) string {
	var parts []string
	if bps > 0 {
		switch {
		case bps >= 1e9:
			parts = append(parts, fmt.Sprintf("%.2f Gbps", float64(bps)/1e9))
		default:
			parts = append(parts, fmt.Sprintf("%.1f Mbps", float64(bps)/1e6))
		}
	}
	if pps > 0 {
		switch {
		case pps >= 1e6:
			parts = append(parts, fmt.Sprintf("%.2f Mpps", float64(pps)/1e6))
		default:
			parts = append(parts, fmt.Sprintf("%.1f Kpps", float64(pps)/1e3))
		}
	}
	return strings.Join(parts, " / ")
}

// OpenCanary 解析 OpenCanary 蜜罐的 JSON 日志：每一条都是攻击者与蜜罐的交互（连接、登录尝试、端口扫描），
// 由诱饵模块按蜜罐命中处理。logtype 1000~1999 为蜜罐自身的运行日志，跳过。
type OpenCanary struct{}

func (OpenCanary) Name() string { return "opencanary" }

var canaryTypes = map[int]string{2000: "FTP 登录", 3000: "HTTP 访问", 3001: "HTTP 登录", 4000: "SSH 连接", 4002: "SSH 登录", 5000: "SMB 文件访问",
	5001: "端口扫描", 6001: "Telnet 登录", 7001: "HTTP 代理登录", 8001: "MySQL 登录", 9001: "MSSQL 登录", 17001: "Redis 命令"}

func (OpenCanary) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"logtype"`) || !strings.Contains(line, `"src_host"`) {
		return nil, false
	}
	m, ok := unmarshalLog(line)
	if !ok {
		return nil, false
	}
	kv := flattenLower(m)
	lt, _ := strconv.Atoi(kv["logtype"])
	src := kv["src_host"]
	if lt < 2000 || !isIP(src) {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: "opencanary", SrcIP: src, DstIP: kv["dst_host"], Proto: "tcp", Action: model.ActionAllow,
		User: pick(kv, "logdata.username", "logdata.user")}
	ev.SrcPort, _ = strconv.Atoi(kv["src_port"])
	ev.DstPort, _ = strconv.Atoi(kv["dst_port"])
	ev.Service = canaryTypes[lt]
	if ev.Service == "" {
		ev.Service = "logtype " + kv["logtype"]
	}
	if !isIP(ev.DstIP) {
		ev.DstIP = ""
	}
	ev.Time = ParseTime(pick(kv, "utc_time", "local_time_adjusted", "local_time"))
	return ev, true
}
