package parser

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

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
	reASA       = regexp.MustCompile(`%(?:ASA|FTD)-\d-(\d{6}):\s*`)
	reASAAddr   = regexp.MustCompile(`(?i)(deny|denied|built inbound|teardown)\s+(tcp|udp|icmp)?.*?(?:src|from|for)\s+(?:\S+?:)?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)/?(\d+)?.*?(?:dst|to)\s+(?:\S+?:)?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)/?(\d+)?`)
)

// CiscoASA 解析 ASA 常见的拒绝/建立连接消息（106001/106006/106015/106023/302013 等）。
type CiscoASA struct{}

func (CiscoASA) Name() string { return "cisco_asa" }

func (CiscoASA) Parse(line string) (*model.Event, bool) {
	// 先按字面量定位消息头：其他格式的日志（尤其是带大量 %XX 编码的 Web 请求）不必进入正则匹配
	i := strings.Index(line, "%ASA-")
	if j := strings.Index(line, "%FTD-"); j >= 0 && (i < 0 || j < i) {
		i = j
	}
	if i < 0 {
		return nil, false
	}
	m, msg := headMatch(reASA, line[i:])
	if m == nil || strings.IndexByte(msg, '\n') >= 0 {
		return nil, false
	}
	a := reASAAddr.FindStringSubmatch(msg)
	if a == nil || !isIP(a[3]) {
		return nil, false
	}
	ev := &model.Event{Kind: model.KindFirewall, Format: "cisco_asa", Action: normAction(a[1]), Proto: normProto(a[2]), SrcIP: a[3], DstIP: a[5]}
	if ev.Proto == "ip" {
		ev.Proto = normProto(reProtoWord.FindString(msg))
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

	// 会话信息：华为 source-zone / destination-zone / rule-name、H3C SrcZoneName / DstZoneName、
	// FortiGate srcintfrole / dstintfrole / policyname、ECS observer.ingress.zone / observer.egress.zone / rule.name 等
	kvSrcZone = []string{"sourcezone", "srczone", "srczonename", "sourcezonename", "fromzone", "observeringresszone", "srcintfrole"}
	kvDstZone = []string{"destinationzone", "dstzone", "dstzonename", "destinationzonename", "destzone", "tozone", "observeregresszone", "dstintfrole"}
	kvPolicy  = []string{"rulename", "policyname", "securitypolicy", "policy", "policyid"}
	kvNatDst  = []string{"destinationnatip", "dstnatip", "natdstipaddr", "natdstip", "destnatip", "natdestinationip", "xlatedst", "postnatdestinationip"}
	// 应答方向（目标 → 发起方）的包数 / 字节数：华为会话日志 RcvPkts / RcvBytes、FortiGate rcvdpkt / rcvdbyte、ECS destination.packets
	kvRcvPkts  = []string{"rcvpkts", "rcvdpkt", "receivedpkts", "recvpkts", "rcvpackets", "packetsreceived", "destinationpackets"}
	kvRcvBytes = []string{"rcvbytes", "rcvdbyte", "receivedbytes", "recvbytes", "bytesreceived", "destinationbytes"}
	// 发起方发送的字节数 / 包数：华为 SendBytes / SendPkts、FortiGate sentbyte / sentpkt、ECS source.bytes、Palo Alto bytes_sent
	kvSentBytes = []string{"sendbytes", "sentbyte", "sentbytes", "bytessent", "sourcebytes", "sendbyte", "origbytes", "txbytes"}
	kvSentPkts  = []string{"sendpkts", "sentpkt", "sentpkts", "pktssent", "sourcepackets", "origpkts", "txpkts"}
)

// fillSession 提取防火墙记录的会话信息，用于判断探测是否真的到达了服务。
// 收发包计数只采信会话结束时的日志：会话建立时（FortiGate action=start）计数恒为 0，不代表目标没有应答。
func fillSession(ev *model.Event, kv map[string]string, act string) {
	zone := func(keys []string) string {
		z := strings.Trim(pick(kv, keys...), `"' `)
		if strings.EqualFold(z, "undefined") || z == "-" {
			return ""
		}
		return z
	}
	ev.SrcZone, ev.DstZone = zone(kvSrcZone), zone(kvDstZone)
	ev.Policy = strings.TrimRight(strings.Trim(pick(kv, kvPolicy...), "\"' \x00"), ".") // 华为日志以句号结尾（直接发送的 syslog 末尾还带 NUL）
	if ev.Policy == "-" || ev.Policy == "---" {
		ev.Policy = ""
	}
	nat := pick(kv, kvNatDst...)
	if nat == "" && strings.Contains(strings.ToLower(kv["trandisp"]), "dnat") {
		nat = kv["tranip"] // FortiGate 虚拟 IP（DNAT）
	}
	if isIP(nat) && nat != "0.0.0.0" {
		ev.NatDstIP = nat
	}
	// 会话字节数（数据外传按内网主机统计外发字节）：会话建立时的日志计数恒为 0，同样不采信
	if !strings.EqualFold(strings.Trim(act, `"' `), "start") {
		ev.SentBytes = atoi64(pick(kv, kvSentBytes...))
		ev.RecvBytes = atoi64(pick(kv, kvRcvBytes...))
		ev.Packets = atoi64(pick(kv, kvSentPkts...)) + atoi64(pick(kv, kvRcvPkts...))
		if d := atoi64(pick(kv, "duration", "elapsed", "elapsed_time", "session_duration", "elapsedtime")); d > 0 {
			ev.Duration = float64(d) // FortiGate duration、Palo Alto elapsed（秒）
		}
	}
	if strings.EqualFold(strings.Trim(act, `"' `), "start") {
		return
	}
	for _, keys := range [][]string{kvRcvPkts, kvRcvBytes} {
		if v := pick(kv, keys...); v != "" {
			if n, err := strconv.ParseInt(strings.Trim(v, `"`), 10, 64); err == nil {
				ev.Reply = model.ReplyYes
				if n == 0 {
					ev.Reply = model.ReplyNone
				}
				return
			}
		}
	}
}

// KVFirewall 解析键值对风格的防火墙日志，键名大小写与下划线不敏感。
type KVFirewall struct{}

func (KVFirewall) Name() string { return "kv_firewall" }

var (
	// 华为 / H3C 信息中心格式的日志头：%%01SHELL/6/DISPLAY_CMDRECORD(s)、%%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION
	reInfoCenter = regexp.MustCompile(`%%\d{2}[A-Z][A-Z0-9_\-]*/\d/[A-Z0-9_\-]+`)
	// 华为设备的告警（trap）以日志形式发出时没有 %% 前缀，消息以 OID 开头：
	// USG6630E CONFIG/4/CONFIGCHANGE:OID 1.3.6.1.4.1.2011.6.122.83.1.2.1 配置发生变更。( 登录用户=**, ...)
	reTrapHeader = regexp.MustCompile(`(^|\s)[A-Z][A-Z0-9_\-]*/\d/[A-Z0-9_\-]+(\([a-z]\))?(\[\d+\])?:\s*OID \d+(\.\d+)+`)
	reKVAddrKey  = regexp.MustCompile(`(?i)(src|source|dst|dest|destination)[ _\-]?(ip|addr|address)`)
	// 中文日志的地址字段（源IP地址=、目的地址=）
	reKVAddrKeyCN = regexp.MustCompile(`(源|目的)\s*(IP|地址|ip)`)
)

// Skip 识别华为、H3C 设备的运维日志（命令记录、配置变更、接口状态、CPU 告警等，含无 %% 前缀的告警日志）：
// 格式正确，但没有源 / 目的地址，不是流量或安全事件，计为跳过而不是解析失败。
// 带地址字段（英文或中文）却解析失败的行仍计为失败，便于发现日志格式变化。
func (KVFirewall) Skip(line string) bool {
	header := strings.Contains(line, "%%") && reInfoCenter.MatchString(line) ||
		strings.Contains(line, "OID ") && reTrapHeader.MatchString(line)
	return header && !reKVAddrKey.MatchString(line) && !reKVAddrKeyCN.MatchString(line)
}

func (KVFirewall) Parse(line string) (*model.Event, bool) {
	if strings.Count(line, "=") < 3 {
		return nil, false
	}
	// 华为、H3C 的攻击防范、入侵防御日志取值里有空格，由 AttackDefense 解析；这里按普通会话日志解析会丢掉攻击类型
	if strings.Contains(line, "%%") && reATKHeader.MatchString(line) {
		return nil, false
	}
	kv := kvMapPool.Get().(map[string]string)
	defer func() {
		clear(kv)
		kvMapPool.Put(kv)
	}()
	kvPairs(line, func(key, val string) {
		k := normKVKey(key)
		if _, ok := kv[k]; !ok {
			kv[k] = val
		}
	})
	return kvEvent(kv, "kv_firewall", line) // kvEvent 只在调用期间读取 kv，事件里保存的是取值（日志行的子串）
}

// 防火墙会话日志是数量最多的日志（生产环境 95% 以上），每行几十个键值对：
//   - 键值表复用（sync.Pool），不再每行新建一个 map；
//   - 键名的归一结果（转小写、去掉 _ - .）按原始写法缓存：同一种设备每行都是同样几十个键（华为的 SourceIP、
//     DestinationPort…），不必每个键都重新分配一次字符串。缓存条数有上限，键名异常多时不再增加。
var kvMapPool = sync.Pool{New: func() any { return make(map[string]string, 48) }}

var (
	kvKeyCache  sync.Map // 原始键名 → 归一键名
	kvKeyCached atomic.Int32
)

const maxKVKeyCache = 4096

func normKVKey(key string) string {
	if v, ok := kvKeyCache.Load(key); ok {
		return v.(string)
	}
	k := strings.ToLower(kvKey.Replace(key))
	if kvKeyCached.Load() < maxKVKeyCache && len(key) <= 64 {
		if _, loaded := kvKeyCache.LoadOrStore(strings.Clone(key), k); !loaded { // 键名是日志行的子串，复制后再缓存，不连带保留整行
			kvKeyCached.Add(1)
		}
	}
	return k
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
		case containsAny(up, "PERMIT", "ACCEPT", "ALLOW"), strings.Contains(up, "SESSION_TEARDOWN"): // 会话日志只记录已放行建立的会话
			act = "allow"
		}
	}
	ev.Action = normAction(act)
	fillSession(ev, kv, act)
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
	m, ok := unmarshalLog(line)
	if !ok {
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
		// 华为 time=2026/10/29 08:49:59：日期与时间之间有空格，按一个值处理
		if isDate(line[j:k]) && k+9 <= n && line[k] == ' ' && isClock(line[k+1:k+9]) {
			k += 9
		}
		fn(key, line[j:k])
		i = k
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isDate 判断是否为 2026/10/29 或 2026-10-29 形式的日期。
func isDate(s string) bool {
	return len(s) == 10 && (s[4] == '/' || s[4] == '-') && s[7] == s[4] &&
		isDigit(s[0]) && isDigit(s[1]) && isDigit(s[2]) && isDigit(s[3]) && isDigit(s[5]) && isDigit(s[6]) && isDigit(s[8]) && isDigit(s[9])
}

// isClock 判断是否为 08:49:59 形式的时间。
func isClock(s string) bool {
	return len(s) == 8 && s[2] == ':' && s[5] == ':' &&
		isDigit(s[0]) && isDigit(s[1]) && isDigit(s[3]) && isDigit(s[4]) && isDigit(s[6]) && isDigit(s[7])
}

func atoi64(s string) int64 {
	n, err := strconv.ParseInt(strings.Trim(s, `"' `), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
