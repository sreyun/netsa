package parser

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"netsa/internal/model"
)

// normAction 将各厂商的动作字段归一化为 allow / deny / log。
func normAction(s string) string {
	s = strings.ToLower(strings.Trim(s, `"' `))
	switch {
	case s == "":
		return model.ActionLog
	case containsAny(s, "deny", "drop", "block", "reject", "discard", "denied", "refuse", "prohibit", "fail"):
		return model.ActionDeny
	case containsAny(s, "accept", "allow", "permit", "pass", "close", "timeout", "server-rst", "client-rst", "start", "built"):
		return model.ActionAllow
	}
	return model.ActionLog
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func normProto(s string) string {
	s = strings.ToLower(strings.Trim(s, `"' `))
	switch s {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	case "58", "ipv6-icmp", "icmpv6":
		return "icmp6"
	case "":
		return "ip"
	}
	return s
}

// ---------------- Linux netfilter (iptables / UFW / firewalld / nftables) ----------------

var (
	reKernelTS = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s*`)
	// IN= 必须是独立字段，避免误匹配前缀或主机名中的 "LOGIN=" 等文本
	reNFIn = regexp.MustCompile(`(?:^|[\s\]:])IN=`)
)

// Netfilter 解析内核 LOG 目标输出：IN=eth0 OUT= SRC=... DST=... PROTO=TCP SPT=... DPT=...
// 通过 --log-prefix 判断动作，例如 "[UFW BLOCK]"、"FINAL_REJECT"、"IPTABLES-DROP"。
type Netfilter struct{}

func (Netfilter) Name() string { return "netfilter" }

func (Netfilter) Parse(line string) (*model.Event, bool) {
	if !strings.Contains(line, " SRC=") || !strings.Contains(line, " DST=") {
		return nil, false
	}
	loc := reNFIn.FindStringIndex(line)
	if loc == nil {
		return nil, false
	}
	i := loc[1] - len("IN=")
	prefix := line[:i]
	if j := strings.LastIndex(prefix, "kernel:"); j >= 0 {
		prefix = prefix[j+7:]
	}
	prefix = reKernelTS.ReplaceAllString(strings.TrimSpace(prefix), "")

	ev := &model.Event{Kind: model.KindFirewall, Format: "netfilter", Action: normAction(prefix)}
	var flags []string
	var out string
	for _, tok := range strings.Fields(line[i:]) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			switch tok {
			case "SYN", "ACK", "FIN", "RST", "PSH", "URG":
				flags = append(flags, tok)
			}
			continue
		}
		switch k {
		case "IN":
			ev.Iface = v
		case "OUT":
			out = v
		case "SRC":
			ev.SrcIP = v
		case "DST":
			ev.DstIP = v
		case "PROTO":
			ev.Proto = normProto(v)
		case "SPT":
			ev.SrcPort, _ = strconv.Atoi(v)
		case "DPT":
			ev.DstPort, _ = strconv.Atoi(v)
		}
	}
	if !isIP(ev.SrcIP) {
		return nil, false
	}
	ev.Flags = strings.Join(flags, ",")
	ev.Outbound = ev.Iface == "" && out != ""
	return ev, true
}

// ---------------- pfSense / OPNsense filterlog ----------------

// PFSense 解析 filterlog 的 CSV 格式。
type PFSense struct{}

func (PFSense) Name() string { return "pfsense" }

func (PFSense) Parse(line string) (*model.Event, bool) {
	if i := strings.Index(line, "filterlog"); i >= 0 {
		if j := strings.Index(line[i:], ": "); j >= 0 {
			line = line[i+j+2:]
		}
	}
	f := strings.Split(strings.TrimSpace(line), ",")
	if len(f) < 20 {
		return nil, false
	}
	act := f[6]
	if act != "pass" && act != "block" && act != "reject" && act != "match" {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: "pfsense", Iface: f[4], Action: normAction(act), Outbound: f[7] == "out"}
	var proto string
	var base int
	switch f[8] {
	case "4":
		proto, base = f[16], 18
	case "6":
		proto, base = f[12], 15
	default:
		return nil, false
	}
	if len(f) <= base+1 || !isIP(f[base]) {
		return nil, false
	}
	ev.Proto = normProto(proto)
	ev.SrcIP, ev.DstIP = f[base], f[base+1]
	if (ev.Proto == "tcp" || ev.Proto == "udp") && len(f) > base+3 {
		ev.SrcPort, _ = strconv.Atoi(f[base+2])
		ev.DstPort, _ = strconv.Atoi(f[base+3])
		if ev.Proto == "tcp" && len(f) > base+5 {
			ev.Flags = f[base+5]
		}
	}
	return ev, true
}

// ---------------- Windows 防火墙 pfirewall.log ----------------

var reWinFW = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (ALLOW|DROP|ALLOW-SOURCE-ROUTE|DROP-SOURCE-ROUTE) (\S+) (\S+) (\S+) (\S+) (\S+)(?: (\S+) (\S+))?(?: .* (SEND|RECEIVE|FORWARD|-))?`)

// WindowsFirewall 解析 Windows Defender 防火墙日志。
type WindowsFirewall struct{}

func (WindowsFirewall) Name() string { return "windows_firewall" }

func (WindowsFirewall) Parse(line string) (*model.Event, bool) {
	m := reWinFW.FindStringSubmatch(line)
	if m == nil || !isIP(m[4]) {
		return nil, false
	}
	ev := &model.Event{
		Time:     ParseTime(m[1]),
		Kind:     model.KindFirewall,
		Format:   "windows_firewall",
		Action:   normAction(m[2]),
		Proto:    normProto(m[3]),
		SrcIP:    m[4],
		DstIP:    m[5],
		Outbound: m[10] == "SEND",
	}
	ev.SrcPort, _ = strconv.Atoi(m[6])
	ev.DstPort, _ = strconv.Atoi(m[7])
	if m[9] != "" && m[9] != "-" {
		ev.Flags = m[9]
	}
	return ev, true
}

// ---------------- Cisco ASA / FTD ----------------

var (
	reProtoWord = regexp.MustCompile(`(?i)\b(tcp|udp|icmp)\b`)
	reASA       = regexp.MustCompile(`%(?:ASA|FTD)-\d-(\d{6}):\s*(.*)$`)
	reASAAddr   = regexp.MustCompile(`(?i)(deny|denied|built inbound|teardown)\s+(tcp|udp|icmp)?.*?(?:src|from|for)\s+(?:\S+?:)?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)/?(\d+)?.*?(?:dst|to)\s+(?:\S+?:)?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)/?(\d+)?`)
)

// CiscoASA 解析 ASA 常见的拒绝/建立连接消息（106001/106006/106015/106023/302013 等）。
type CiscoASA struct{}

func (CiscoASA) Name() string { return "cisco_asa" }

func (CiscoASA) Parse(line string) (*model.Event, bool) {
	m := reASA.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	a := reASAAddr.FindStringSubmatch(m[2])
	if a == nil || !isIP(a[3]) {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: "cisco_asa", Action: normAction(a[1]), Proto: normProto(a[2]), SrcIP: a[3], DstIP: a[5]}
	if ev.Proto == "ip" {
		ev.Proto = normProto(reProtoWord.FindString(m[2]))
	}
	ev.SrcPort, _ = strconv.Atoi(a[4])
	ev.DstPort, _ = strconv.Atoi(a[6])
	return ev, true
}

// ---------------- 通用 key=value（FortiGate / 华为 USG / H3C / 深信服 / 山石 等） ----------------

// kvKey 统一键名：忽略大小写、下划线、连字符与点。
var kvKey = strings.NewReplacer("_", "", "-", "", ".", "")

var (
	kvSrc   = []string{"srcip", "src", "sourceip", "sip", "srcaddr", "sourceaddress", "srcipaddr", "clientip", "source", "srcaddress", "attackerip"}
	kvDst   = []string{"dstip", "dst", "destinationip", "dip", "dstaddr", "destip", "destinationaddress", "dstipaddr", "destination", "dstaddress", "targetip"}
	kvSPort = []string{"srcport", "sport", "spt", "sourceport", "srcportnum"}
	kvDPort = []string{"dstport", "dport", "dpt", "destinationport", "destport", "dstportnum"}
	kvProto = []string{"proto", "protocol", "ipprotocol", "transport"}
	kvAct   = []string{"action", "act", "policyaction", "disposition", "result", "policy_action", "fwaction"}
	kvTime  = []string{"devtime", "eventtime", "timestamp", "logtime", "time", "rt"}
)

// KVFirewall 解析键值对风格的防火墙日志，键名大小写与下划线不敏感。
type KVFirewall struct{}

func (KVFirewall) Name() string { return "kv_firewall" }

func (KVFirewall) Parse(line string) (*model.Event, bool) {
	if strings.Count(line, "=") < 3 {
		return nil, false
	}
	kv := make(map[string]string, 32)
	kvPairs(line, func(key, val string) {
		k := strings.ToLower(kvKey.Replace(key))
		if _, ok := kv[k]; !ok {
			kv[k] = val
		}
	})
	return kvEvent(kv, "kv_firewall", line)
}

func kvEvent(kv map[string]string, format, line string) (*model.Event, bool) {
	src := pick(kv, kvSrc...)
	if !isIP(src) {
		return nil, false
	}
	dst := pick(kv, kvDst...)
	dport := pick(kv, kvDPort...)
	if dst == "" && dport == "" {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: format, SrcIP: src, DstIP: dst}
	ev.SrcPort, _ = strconv.Atoi(pick(kv, kvSPort...))
	ev.DstPort, _ = strconv.Atoi(dport)
	ev.Proto = normProto(pick(kv, kvProto...))
	act := pick(kv, kvAct...)
	if act == "" {
		// 华为等设备把动作写在日志类型中，如 POLICYDENY / POLICYPERMIT
		up := strings.ToUpper(line)
		switch {
		case containsAny(up, "DENY", "DROP", "BLOCK", "REJECT"):
			act = "deny"
		case containsAny(up, "PERMIT", "ACCEPT", "ALLOW"):
			act = "allow"
		}
	}
	ev.Action = normAction(act)
	if d, t := kv["date"], kv["time"]; d != "" && t != "" {
		ev.Time = ParseTime(d + " " + t)
	} else {
		ev.Time = ParseTime(pick(kv, kvTime...))
	}
	fillThreat(ev, kv)
	return ev, true
}

// JSONFirewall 解析 JSON 格式的防火墙 / 安全设备日志。
type JSONFirewall struct{}

func (JSONFirewall) Name() string { return "json_firewall" }

func (JSONFirewall) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil, false
	}
	raw := flattenLower(m)
	kv := make(map[string]string, len(raw))
	for k, v := range raw {
		kv[kvKey.Replace(k)] = v
	}
	if _, isWeb := kv["request"]; isWeb {
		return nil, false
	}
	return kvEvent(kv, "json_firewall", line)
}

func isKeyStart(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }
func isKeyChar(c byte) bool  { return isKeyStart(c) || c >= '0' && c <= '9' || c == '.' || c == '-' }

// kvPairs 单次扫描解析 key=value、key="value"、key='value'（键值间允许一个空格，值以空白、逗号或分号结束），
// 兼容 H3C 的 Key(1003)=Value 写法。
func kvPairs(line string, fn func(key, val string)) {
	n := len(line)
	for i := 0; i < n; {
		if !isKeyStart(line[i]) || i > 0 && isKeyChar(line[i-1]) {
			i++
			continue
		}
		ks := i
		for i < n && isKeyChar(line[i]) {
			i++
		}
		key := line[ks:i]
		j := i
		if j < n && line[j] == '(' { // H3C：SrcIPAddr(1003)=
			k := j + 1
			for k < n && line[k] >= '0' && line[k] <= '9' {
				k++
			}
			if k > j+1 && k < n && line[k] == ')' {
				j = k + 1
			}
		}
		if j < n && line[j] == ' ' {
			j++
		}
		if j >= n || line[j] != '=' {
			continue
		}
		j++
		if j < n && line[j] == ' ' {
			j++
		}
		if j < n && (line[j] == '"' || line[j] == '\'') {
			q := line[j]
			k := j + 1
			for k < n && line[k] != q {
				if line[k] == '\\' && q == '"' {
					k++
				}
				k++
			}
			fn(key, line[j+1:min(k, n)])
			i = k + 1
			continue
		}
		k := j
		for k < n && line[k] != ' ' && line[k] != '\t' && line[k] != ',' && line[k] != ';' {
			k++
		}
		fn(key, line[j:k])
		i = k
	}
}
