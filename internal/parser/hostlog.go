package parser

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netsa/internal/model"
)

// HostParsers 返回主机 / VPN 认证日志与 DNS 日志解析器。这些格式特征明确，排在防火墙解析器之前，
// 避免通用的键值对 / JSON 防火墙解析器把认证与 DNS 日志当作流量日志。
func HostParsers() []Parser {
	return []Parser{LinuxAuth{}, WindowsSecurity{}, VPNAuth{}, BindDNS{}, Dnsmasq{}, CoreDNS{}, WindowsDNS{}, ZeekDNS{}, JSONDNS{}}
}

func authEvent(format, service, src, user string, ok bool) *model.Event {
	ev := &model.Event{Kind: model.KindAuth, Format: format, Service: service, SrcIP: src, User: strings.Trim(user, `"'[]<>`)}
	ev.Action = model.ActionDeny
	if ok {
		ev.Action = model.ActionAllow
	}
	if src == "" || src == "-" || !isIP(src) {
		ev.SrcIP, ev.SubjectHost = "", true // 没有远程来源（本地操作）：主体为上报日志的主机
	}
	return ev
}

// ---------------- Linux auth.log / secure ----------------

var (
	reSSHFail    = regexp.MustCompile(`^(?:error: )?(?:Failed|Invalid) (?:password|publickey|keyboard-interactive/pam|none|user)(?: for)? (?:invalid user )?(\S*) from (\S+)(?: port (\d+))?`)
	reSSHAccept  = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	reSSHMaxAuth = regexp.MustCompile(`^(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	rePamFail    = regexp.MustCompile(`pam_unix\(([\w-]+):auth\): authentication failure;.*?rhost=(\S*)(?:\s+user=(\S+))?`)
	reUserAdd    = regexp.MustCompile(`^new user: name=([^,\s]+)`)
	reGroupAdd   = regexp.MustCompile(`^(?:add '([^']+)' to (?:shadow )?group '([^']+)'|user (\S+) added to group (\S+))`)
)

// LinuxAuth 解析 Linux 认证日志：sshd 登录成功 / 失败、PAM 认证失败、新建账号、加入特权组。
type LinuxAuth struct{}

func (LinuxAuth) Name() string { return "linux_auth" }

func (LinuxAuth) Parse(line string) (*model.Event, bool) {
	if len(line) < 12 {
		return nil, false
	}
	switch c := line[0]; {
	case c == 'F' || c == 'I' || c == 'A' || c == 'e' || c == 'm':
		if m := reSSHFail.FindStringSubmatch(line); m != nil {
			return authEvent("linux_auth", "SSH", m[2], m[1], false), true
		}
		if m := reSSHAccept.FindStringSubmatch(line); m != nil {
			ev := authEvent("linux_auth", "SSH", m[3], m[2], true)
			ev.Flags = m[1] // 认证方式：password / publickey …
			return ev, true
		}
		if m := reSSHMaxAuth.FindStringSubmatch(line); m != nil {
			return authEvent("linux_auth", "SSH", m[2], m[1], false), true
		}
	case c == 'n':
		if m := reUserAdd.FindStringSubmatch(line); m != nil {
			ev := authEvent("linux_auth", "useradd", "", m[1], true)
			ev.EventID = 4720 // 与 Windows“新建账号”统一
			return ev, true
		}
	}
	if strings.Contains(line, "pam_unix(") {
		if m := rePamFail.FindStringSubmatch(line); m != nil && m[2] != "" {
			svc := strings.ToUpper(m[1])
			if svc == "SSHD" {
				svc = "SSH"
			}
			return authEvent("linux_auth", svc, m[2], m[3], false), true
		}
	}
	if c := line[0]; c != 'a' && c != 'u' {
		return nil, false
	}
	if m := reGroupAdd.FindStringSubmatch(line); m != nil {
		user, group := m[1], m[2]
		if user == "" {
			user, group = m[3], m[4]
		}
		ev := authEvent("linux_auth", "usermod", "", user, true)
		ev.EventID, ev.URI = 4732, group // 加入组：URI 记录组名
		return ev, true
	}
	return nil, false
}

// ---------------- Windows 安全事件 ----------------

// winEvents 是关注的 Windows 安全事件 ID。
var winEvents = map[int]bool{4624: true, 4625: true, 4740: true, 4720: true, 4722: true, 4724: true, 4728: true, 4732: true, 4756: true,
	1102: true, 104: true, 4697: true, 7045: true, 4698: true, 4771: true, 4776: true}

var (
	reWinID     = regexp.MustCompile(`(?i)(?:EventID|Event ID|事件 ID|事件ID)["\s:=]+(\d{3,4})\b`)
	reWinIP     = regexp.MustCompile(`(?i)(?:Source Network Address|源网络地址|IpAddress|Client Address|客户端地址)["\s:=]+(?:::ffff:)?([0-9a-fA-F.:]+)`)
	reWinUser   = regexp.MustCompile(`(?i)(?:TargetUserName|Account Name|帐户名称|账户名称|帐户名|账户名)["\s:=]+([^\s"\\,;]+)`)
	reWinLogon  = regexp.MustCompile(`(?i)(?:LogonType|Logon Type|登录类型)["\s:=]+(\d+)`)
	reWinHost   = regexp.MustCompile(`(?i)(?:Computer|Hostname|计算机)["\s:=]+([A-Za-z0-9._-]+)`)
	reWinGroup  = regexp.MustCompile(`(?i)(?:TargetUserName|Group Name|组名)["\s:=]+([^\t"\\,;]+?)(?:\s{2,}|["\t,;]|$)`)
	reWinMember = regexp.MustCompile(`(?i)(?:MemberName|Member Name|Security ID)["\s:=]+(?:CN=)?([^,"\s\\]+)`)
)

// WindowsSecurity 解析 Windows 安全事件：NXLog / Winlogbeat 的 JSON，以及 Snare 等转发的事件文本（中英文）。
// 关注登录成功 / 失败、账号锁定、新建账号、加入组、日志被清除、服务 / 计划任务创建。
type WindowsSecurity struct{}

func (WindowsSecurity) Name() string { return "windows_security" }

func logonService(t string) string {
	switch t {
	case "10":
		return "RDP"
	case "3":
		return "网络登录"
	case "2", "11":
		return "本地登录"
	case "8":
		return "明文网络登录"
	}
	return "Windows 登录"
}

func (WindowsSecurity) Parse(line string) (*model.Event, bool) {
	var id int
	kv := map[string]string{}
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		if !strings.Contains(line, "vent") { // EventID / event_id / EventId
			return nil, false
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			return nil, false
		}
		kv = flattenLower(m)
		id, _ = strconv.Atoi(pick(kv, "eventid", "event_id", "eventcode"))
	} else {
		// 预筛：事件 ID 字段或 Snare 标识，避免对每一行执行正则（自动识别时所有格式的日志都会经过这里）
		if !strings.Contains(line, "MSWinEventLog") && !strings.Contains(line, "vent") && !strings.Contains(line, "事件") {
			return nil, false
		}
		m := reWinID.FindStringSubmatch(line)
		if m == nil {
			// Snare：MSWinEventLog \t 1 \t Security \t 序号 \t 时间 \t 事件ID \t …
			if !strings.Contains(line, "MSWinEventLog") {
				return nil, false
			}
			f := strings.Split(line, "\t")
			if len(f) < 6 {
				return nil, false
			}
			m = []string{"", strings.TrimSpace(f[5])}
		}
		id, _ = strconv.Atoi(m[1])
		find := func(re *regexp.Regexp) string {
			if m := re.FindStringSubmatch(line); m != nil {
				return m[1]
			}
			return ""
		}
		kv["ipaddress"], kv["targetusername"], kv["logontype"], kv["computer"] = find(reWinIP), find(reWinUser), find(reWinLogon), find(reWinHost)
		if id == 4728 || id == 4732 || id == 4756 {
			kv["group"], kv["membername"] = find(reWinGroup), find(reWinMember)
		}
	}
	if !winEvents[id] {
		return nil, false
	}
	ip := pick(kv, "ipaddress", "sourcenetworkaddress", "ip_address", "clientaddress", "workstationip")
	ip = strings.TrimPrefix(ip, "::ffff:")
	user := pick(kv, "targetusername", "target_user_name", "username", "user")
	if dom := pick(kv, "targetdomainname"); dom != "" && user != "" && !strings.Contains(user, `\`) && dom != "-" {
		user = dom + `\` + user
	}
	svc := "Windows"
	ok := true
	switch id {
	case 4624, 4625:
		svc, ok = logonService(pick(kv, "logontype", "logon_type")), id == 4624
	case 4771, 4776:
		svc, ok = "域认证", false
		if code := pick(kv, "status", "failurecode", "errorcode"); code == "0x0" || code == "0" {
			ok = true
		}
	case 4740:
		svc, ok = "账号锁定", false
	}
	if ip == "127.0.0.1" || ip == "::1" {
		ip = ""
	}
	ev := authEvent("windows_security", svc, ip, user, ok)
	ev.EventID = id
	ev.Host = pick(kv, "computer", "computer_name", "computername", "hostname")
	if id == 4728 || id == 4732 || id == 4756 {
		ev.URI = pick(kv, "group", "targetusername")
		ev.User = pick(kv, "membername", "member_name", "subjectusername")
	}
	if id == 7045 || id == 4697 {
		ev.URI = pick(kv, "servicename", "service_name", "imagepath", "servicefilename")
	}
	if id == 4698 {
		ev.URI = pick(kv, "taskname", "task_name")
	}
	if strings.HasSuffix(ev.User, "$") && (id == 4624 || id == 4625) {
		return nil, false // 计算机账号的网络登录（域内大量正常流量）
	}
	ev.Time = ParseTime(pick(kv, "eventtime", "timecreated", "@timestamp", "timestamp", "event_time"))
	return ev, true
}

// ---------------- VPN / 设备管理 / 数据库登录 ----------------

var (
	reASAAuth   = regexp.MustCompile(`%ASA-\d-(113015|113004|113005|716039|722051|611102|605004|605005)\b.*`)
	reASAUserIP = regexp.MustCompile(`(?:user = (\S+)|User <([^>]*)>|user '([^']*)').*?(?:user IP = |IP <|from )([0-9a-fA-F.:]+)`)
	reOVPNFail  = regexp.MustCompile(`(?:^|\s)([0-9a-fA-F.:]+):\d+ (?:TLS Auth Error: Auth Username/Password verification failed|.*AUTH_FAILED)`)
	reOVPNOK    = regexp.MustCompile(`(?:^|\s)([0-9a-fA-F.:]+):\d+ \[([^\]]+)\] Peer Connection Initiated`)
	reMSSQL     = regexp.MustCompile(`Login (failed|succeeded) for user '([^']*)'.*\[CLIENT: ([0-9a-fA-F.:]+)\]`)
)

// VPNAuth 解析 VPN 与设备管理登录：FortiGate（SSL VPN、管理登录）、Cisco ASA（AAA、AnyConnect、SSH 管理）、OpenVPN，
// 以及 SQL Server 登录日志。
type VPNAuth struct{}

func (VPNAuth) Name() string { return "vpn_auth" }

func (VPNAuth) Parse(line string) (*model.Event, bool) {
	switch {
	case strings.Contains(line, "subtype=") && strings.Contains(line, "action="):
		kv := map[string]string{}
		kvPairs(line, func(k, v string) {
			k = strings.ToLower(k)
			if _, ok := kv[k]; !ok {
				kv[k] = v
			}
		})
		sub, act := kv["subtype"], strings.ToLower(kv["action"])
		var svc string
		switch {
		case sub == "vpn" && (strings.Contains(act, "login") || strings.Contains(act, "auth") || act == "tunnel-up"):
			svc = "SSL VPN"
		case sub == "system" && act == "login":
			svc = "设备管理登录"
		default:
			return nil, false
		}
		src := pick(kv, "remip", "srcip", "ip")
		fail := strings.Contains(act, "fail") || kv["status"] == "failed" || strings.Contains(kv["reason"], "fail") || strings.Contains(kv["reason"], "denied")
		ev := authEvent("vpn_auth", svc, src, kv["user"], !fail)
		if ev.SubjectHost {
			return nil, false
		}
		ev.Host = kv["devname"]
		if d, t := kv["date"], kv["time"]; d != "" && t != "" {
			ev.Time = ParseTime(d + " " + t)
		}
		return ev, true
	case strings.Contains(line, "%ASA-"):
		m := reASAAuth.FindStringSubmatch(line)
		if m == nil {
			return nil, false
		}
		u := reASAUserIP.FindStringSubmatch(line)
		if u == nil {
			return nil, false
		}
		user := u[1] + u[2] + u[3]
		ok := m[1] == "113004" || m[1] == "722051" || m[1] == "605005"
		if m[1] == "716039" || m[1] == "113015" || m[1] == "113005" || m[1] == "605004" || m[1] == "611102" {
			ok = false
		}
		svc := "Cisco VPN"
		if m[1] == "605004" || m[1] == "605005" || m[1] == "611102" {
			svc = "设备管理登录"
		}
		return authEvent("vpn_auth", svc, u[4], user, ok), true
	case strings.Contains(line, "Login failed for user") || strings.Contains(line, "Login succeeded for user"):
		m := reMSSQL.FindStringSubmatch(line)
		if m == nil {
			return nil, false
		}
		return authEvent("vpn_auth", "MSSQL", m[3], m[2], m[1] == "succeeded"), true
	}
	if !strings.Contains(line, "AUTH_FAILED") && !strings.Contains(line, "TLS Auth Error") && !strings.Contains(line, "Peer Connection Initiated") {
		return nil, false
	}
	if m := reOVPNFail.FindStringSubmatch(line); m != nil && isIP(m[1]) {
		return authEvent("vpn_auth", "OpenVPN", m[1], "", false), true
	}
	if m := reOVPNOK.FindStringSubmatch(line); m != nil && isIP(m[1]) {
		return authEvent("vpn_auth", "OpenVPN", m[1], m[2], true), true
	}
	return nil, false
}

// ---------------- DNS ----------------

func dnsEvent(format, client, server, name, qtype, rcode string) (*model.Event, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || !isIP(client) {
		return nil, false
	}
	return &model.Event{Kind: model.KindDNS, Format: format, SrcIP: client, DstIP: server, Host: name, QType: strings.ToUpper(qtype), RCode: strings.ToUpper(rcode), Proto: "dns"}, true
}

var reBind = regexp.MustCompile(`client (?:@0x[0-9a-f]+ )?([0-9a-fA-F.:]+)#\d+(?: \([^)]*\))?: (?:view \S+: )?query: (\S+) \S+ (\S+) [-+]\S*(?: \(([0-9a-fA-F.:]+)\))?`)

// BindDNS 解析 BIND 查询日志（querylog）。
type BindDNS struct{}

func (BindDNS) Name() string { return "bind_query" }

func (BindDNS) Parse(line string) (*model.Event, bool) {
	i := strings.Index(line, "query: ")
	if i < 0 || !strings.Contains(line, "client ") {
		return nil, false
	}
	m := reBind.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	ev, ok := dnsEvent("bind_query", m[1], m[4], m[2], m[3], "")
	if ok && len(line) > 24 && line[2] == '-' && line[6] == '-' { // 25-Oct-2026 10:00:00.123
		if t, err := time.ParseInLocation("02-Jan-2006 15:04:05.000", line[:24], locOrLocal()); err == nil {
			ev.Time = t
		}
	}
	return ev, ok
}

func locOrLocal() *time.Location {
	if Location != nil {
		return Location
	}
	return time.Local
}

var reDnsmasq = regexp.MustCompile(`^query\[(\w+)\] (\S+) from ([0-9a-fA-F.:]+)`)

// Dnsmasq 解析 dnsmasq 的查询日志（log-queries）。
type Dnsmasq struct{}

func (Dnsmasq) Name() string { return "dnsmasq" }

func (Dnsmasq) Parse(line string) (*model.Event, bool) {
	if !strings.HasPrefix(line, "query[") {
		return nil, false
	}
	m := reDnsmasq.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	return dnsEvent("dnsmasq", m[3], "", m[2], m[1], "")
}

var reCoreDNS = regexp.MustCompile(`^\[\w+\] \[?([0-9a-fA-F.:]+?)\]?:\d+ - \d+ "(\w+) IN (\S+) \w+ \d+ \w+ \d+" (\w+) `)

// CoreDNS 解析 CoreDNS 的 log 插件输出。
type CoreDNS struct{}

func (CoreDNS) Name() string { return "coredns" }

func (CoreDNS) Parse(line string) (*model.Event, bool) {
	if !strings.HasPrefix(line, "[") || !strings.Contains(line, " IN ") {
		return nil, false
	}
	m := reCoreDNS.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	return dnsEvent("coredns", m[1], "", m[3], m[2], m[4])
}

var reWinDNS = regexp.MustCompile(`PACKET\s+\S+\s+(?:UDP|TCP)\s+(Rcv|Snd)\s+([0-9a-fA-F.:]+)\s+\S+\s+(R)?\s*Q\s+\[[0-9a-fA-F]+\s+[A-Z ]*?\s*(\w+)\]\s+(\w+)\s+(\S+)`)
var reWinDNSLabel = regexp.MustCompile(`\(\d+\)`)

// WindowsDNS 解析 Windows DNS 服务器调试日志（只取收到的查询与发出的响应）。
type WindowsDNS struct{}

func (WindowsDNS) Name() string { return "windows_dns" }

func (WindowsDNS) Parse(line string) (*model.Event, bool) {
	if !strings.Contains(line, " PACKET ") {
		return nil, false
	}
	m := reWinDNS.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	name := strings.Trim(reWinDNSLabel.ReplaceAllString(m[6], "."), ".")
	rcode := ""
	if m[3] == "R" { // 响应
		rcode = m[4]
	} else if m[1] != "Rcv" {
		return nil, false // 本机向上游发出的查询
	}
	ev, ok := dnsEvent("windows_dns", m[2], "", name, m[5], rcode)
	if ok && rcode != "" {
		ev.Flags = "R" // 响应记录：与查询记录是同一次查询，不重复做单条检测
	}
	if ok {
		if i := strings.Index(line, " PACKET"); i > 0 {
			ev.Time = ParseTime(strings.TrimSpace(line[:strings.LastIndexByte(line[:i], ' ')]))
			if ev.Time.IsZero() {
				if t, err := time.ParseInLocation("1/2/2006 3:04:05 PM", strings.TrimSpace(line[:strings.LastIndexByte(line[:i], ' ')]), locOrLocal()); err == nil {
					ev.Time = t
				}
			}
		}
	}
	return ev, ok
}

// ZeekDNS 解析 Zeek（Bro）的 dns.log（制表符分隔，表头以 # 开头已被跳过）。
type ZeekDNS struct{}

func (ZeekDNS) Name() string { return "zeek_dns" }

func (ZeekDNS) Parse(line string) (*model.Event, bool) {
	if strings.Count(line, "\t") < 15 {
		return nil, false
	}
	f := strings.Split(line, "\t")
	if len(f) < 16 || !isIP(f[2]) || f[9] == "-" || f[6] != "udp" && f[6] != "tcp" {
		return nil, false
	}
	rcode := f[15]
	if rcode == "-" {
		rcode = ""
	}
	ev, ok := dnsEvent("zeek_dns", f[2], f[4], f[9], strings.Trim(f[13], "-"), rcode)
	if ok {
		ev.Time = ParseTime(f[0])
	}
	return ev, ok
}

// JSONDNS 解析 JSON 格式的 DNS 日志：Suricata eve（event_type=dns）、Packetbeat、各类 DNS 网关。
type JSONDNS struct{}

func (JSONDNS) Name() string { return "json_dns" }

func (JSONDNS) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, "dns") {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal([]byte(line), &m) != nil {
		return nil, false
	}
	kv := flattenLower(m)
	if et := kv["event_type"]; et != "" && et != "dns" {
		return nil, false
	}
	if kv["event_type"] == "dns" && kv["type"] == "answer" {
		return nil, false // Suricata 的应答记录与查询重复
	}
	name := pick(kv, "rrname", "query", "qname", "question.name", "domain")
	if name == "" {
		return nil, false
	}
	ev, ok := dnsEvent("json_dns", pick(kv, "src_ip", "client_ip", "client", "srcip", "source_ip"), pick(kv, "dest_ip", "server", "dstip"), name,
		pick(kv, "rrtype", "qtype", "query_type", "type"), pick(kv, "rcode", "response_code"))
	if ok {
		ev.Time = ParseTime(pick(kv, "timestamp", "@timestamp", "time"))
	}
	return ev, ok
}
