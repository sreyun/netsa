package parser

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"netsa/internal/model"
)

// 主机进程日志（EDR / HIDS）：
//   - Sysmon（经 Winlogbeat、NXLog、Elastic Agent 输出的 JSON）：1 进程创建、3 网络连接、10 进程访问、11 文件创建、
//     12 / 13 / 14 注册表；Windows 安全日志 4688（进程创建，需开启“在进程创建事件中包含命令行”）；
//     Elastic Defend / ECS 的 process 事件；
//   - Linux auditd：EXECVE 记录（与同一事件的 SYSCALL 记录合并出进程路径与账号）；
//   - Wazuh / OSSEC 告警（alerts.json）：按告警等级与 MITRE 编号归类。
// 事件的主体是上报日志的主机（SubjectHost）：SrcIP 为日志中记录的本机地址（Winlogbeat 的 host.ip、Wazuh 的 agent.ip），
// 没有记录时经 syslog 接收的取发送端地址。

// ProcessParsers 返回主机进程日志解析器。
func ProcessParsers() []Parser { return []Parser{SysmonJSON{}, WazuhAlert{}, NewAuditd()} }

func procEvent(format, hostIP, host string, p *model.ProcInfo) *model.Event {
	ev := &model.Event{Kind: model.KindProcess, Format: format, Host: strings.ToLower(host), Proc: p, SubjectHost: true, Action: model.ActionAllow}
	if isIP(hostIP) {
		ev.SrcIP, ev.DstIP = hostIP, hostIP
	}
	return ev
}

// SysmonJSON 解析 JSON 格式的 Sysmon、Windows 4688 与 ECS 进程事件。
type SysmonJSON struct{}

func (SysmonJSON) Name() string { return "sysmon" }

func (SysmonJSON) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, "Image") && !strings.Contains(line, `"image"`) &&
		!strings.Contains(line, "NewProcessName") && !strings.Contains(line, `"process"`) && !strings.Contains(line, "process.executable") {
		return nil, false
	}
	m, ok := unmarshalLog(line)
	if !ok {
		return nil, false
	}
	kv := flattenLower(m)
	id, _ := strconv.Atoi(pick(kv, "winlog.event_id", "eventid", "event_id", "event.code"))
	channel := strings.ToLower(pick(kv, "winlog.channel", "channel", "sourcename", "winlog.provider_name", "providername", "event.provider"))
	sysmon := strings.Contains(channel, "sysmon")
	ecs := pick(kv, "event.category") == "process" || pick(kv, "process.executable") != ""
	p := &model.ProcInfo{User: pick(kv, "user", "subjectusername", "user.name", "username")}
	if d := pick(kv, "subjectdomainname"); d != "" && p.User != "" && !strings.Contains(p.User, `\`) && d != "-" {
		p.User = d + `\` + p.User
	}
	format := "sysmon"
	switch {
	case sysmon && id == 1, !sysmon && id == 4688:
		p.Op = "process"
		p.Image = pick(kv, "image", "newprocessname", "new_process_name")
		p.CommandLine = pick(kv, "commandline", "processcommandline", "command_line")
		p.Parent = pick(kv, "parentimage", "parentprocessname", "parent_process_name")
		p.ParentCmd = pick(kv, "parentcommandline")
		p.PID = atoiHex(pick(kv, "processid", "newprocessid"))
		if id == 4688 {
			format = "windows_4688"
		}
	case sysmon && id == 3:
		p.Op, p.Image = "network", pick(kv, "image")
		if ip := pick(kv, "destinationip"); ip != "" {
			p.Target = ip + ":" + pick(kv, "destinationport")
		}
	case sysmon && id == 10:
		p.Op, p.Image, p.Target, p.Access = "access", pick(kv, "sourceimage"), pick(kv, "targetimage"), strings.ToLower(pick(kv, "grantedaccess"))
		p.User = pick(kv, "sourceuser", "user")
	case sysmon && id == 11:
		p.Op, p.Image, p.Target = "file", pick(kv, "image"), pick(kv, "targetfilename")
	case sysmon && (id == 12 || id == 13 || id == 14):
		p.Op, p.Image, p.Target = "registry", pick(kv, "image"), pick(kv, "targetobject")
		if d := pick(kv, "details"); d != "" {
			p.CommandLine = d // 写入的值（Run 键指向的程序）
		}
	case ecs:
		format = "ecs_process"
		p.Op = "process"
		p.Image = pick(kv, "process.executable", "process.name")
		p.CommandLine = pick(kv, "process.command_line", "process.args")
		p.Parent = pick(kv, "process.parent.executable", "process.parent.name")
		p.ParentCmd = pick(kv, "process.parent.command_line")
		p.PID = atoi(pick(kv, "process.pid"))
		if t := pick(kv, "event.type"); t != "" && t != "start" && t != "info" {
			return nil, false // 只取进程启动（结束事件与启动重复）
		}
	default:
		return nil, false
	}
	if p.Image == "" && p.CommandLine == "" && p.Target == "" {
		return nil, false
	}
	ev := procEvent(format, pick(kv, "host.ip", "hostip", "agent.ip", "ipaddress"),
		pick(kv, "winlog.computer_name", "computer", "computer_name", "computername", "hostname", "host.name", "host.hostname"), p)
	ev.EventID = id
	ev.Time = ParseTime(pick(kv, "utctime", "@timestamp", "eventtime", "timecreated", "timestamp", "event_time"))
	return ev, true
}

// atoiHex 解析十进制或 0x 开头的十六进制（4688 的进程编号）。
func atoiHex(s string) int {
	if h, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		n, _ := strconv.ParseInt(h, 16, 64)
		return int(n)
	}
	return atoi(s)
}

// WazuhAlert 解析 Wazuh / OSSEC 的告警（alerts.json）。
type WazuhAlert struct{}

func (WazuhAlert) Name() string { return "wazuh" }

func (WazuhAlert) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"rule"`) || !strings.Contains(line, `"agent"`) {
		return nil, false
	}
	m, ok := unmarshalLog(line)
	if !ok {
		return nil, false
	}
	kv := flattenLower(m)
	level, err := strconv.Atoi(kv["rule.level"])
	desc := kv["rule.description"]
	if err != nil || desc == "" {
		return nil, false
	}
	p := &model.ProcInfo{Op: "alert", Rule: kv["rule.id"], Level: level, User: pick(kv, "data.dstuser", "data.srcuser", "data.win.eventdata.user")}
	if rm, ok := m["rule"].(map[string]any); ok {
		if mi, ok := rm["mitre"].(map[string]any); ok {
			if ids, ok := mi["id"].([]any); ok {
				for _, x := range ids {
					if s, ok := x.(string); ok && len(p.Mitre) < 8 {
						p.Mitre = append(p.Mitre, s)
					}
				}
			}
		}
	}
	p.Image = pick(kv, "data.win.eventdata.image", "syscheck.path", "data.audit.exe")
	p.CommandLine = pick(kv, "data.win.eventdata.commandline", "data.audit.execve.a0", "data.command")
	p.Target = pick(kv, "syscheck.path", "data.win.eventdata.targetfilename")
	agentIP := kv["agent.ip"]
	ev := procEvent("wazuh", agentIP, kv["agent.name"], p)
	ev.Threat, ev.ThreatSeverity = desc, strconv.Itoa(level)
	ev.ThreatCategory = kv["rule.groups"]
	ev.Raw = Printable(kv["full_log"], 300)
	// 网络来源的告警（SSH 暴力破解、Web 攻击）：攻击者为来源地址，主机为目标
	if src := pick(kv, "data.srcip", "data.src_ip"); isIP(src) && src != agentIP {
		ev.SrcIP, ev.SubjectHost = src, false
		if !isIP(agentIP) {
			ev.DstIP = ""
		}
	}
	ev.Time = ParseTime(pick(kv, "timestamp", "@timestamp"))
	return ev, true
}

// Printable 截断并去掉控制字符（证据展示用）。
func Printable(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Auditd 解析 Linux auditd 的 EXECVE 记录。同一事件的 SYSCALL 记录（进程路径、账号、父进程号）先于 EXECVE 输出，
// 按事件编号合并；ENRICHED 格式中的 UID="www-data" 等可读字段优先。
type Auditd struct {
	mu   sync.Mutex
	sys  map[string]auditSyscall // 事件编号 → SYSCALL 记录
	comm map[string]string       // 进程号 → 进程名（推断父进程）
}

type auditSyscall struct {
	exe, user, ppid, pid string
}

// NewAuditd 创建 auditd 解析器（每个数据源一个实例，保存 SYSCALL 记录用于合并）。
func NewAuditd() *Auditd {
	return &Auditd{sys: map[string]auditSyscall{}, comm: map[string]string{}}
}

func (*Auditd) Name() string { return "auditd" }

var (
	reAuditMsg = regexp.MustCompile(`type=(SYSCALL|EXECVE|PROCTITLE) msg=audit\((\d+\.\d+):(\d+)\):(.*)`)
	reAuditKV  = regexp.MustCompile(`(\w+)=("[^"]*"|\S+)`)
)

func (a *Auditd) Parse(line string) (*model.Event, bool) {
	i := strings.Index(line, "type=")
	if i < 0 || !strings.Contains(line, "msg=audit(") {
		return nil, false
	}
	m := reAuditMsg.FindStringSubmatch(line[i:])
	if m == nil {
		return nil, false
	}
	kv := map[string]string{}
	body := m[4]
	enriched := ""
	if j := strings.IndexByte(body, 0x1d); j >= 0 { // ENRICHED 格式：可读字段在 0x1d 之后
		body, enriched = body[:j], body[j+1:]
	}
	raw := map[string]string{} // 带引号的原值：EXECVE 参数不带引号时为十六进制
	for _, x := range reAuditKV.FindAllStringSubmatch(body, -1) {
		kv[x[1]], raw[x[1]] = strings.Trim(x[2], `"`), x[2]
	}
	for _, x := range reAuditKV.FindAllStringSubmatch(enriched, -1) {
		kv["_"+strings.ToLower(x[1])] = strings.Trim(x[2], `"`)
	}
	id := m[3]
	a.mu.Lock()
	defer a.mu.Unlock()
	switch m[1] {
	case "SYSCALL":
		if len(a.sys) > 4096 {
			clear(a.sys)
		}
		if len(a.comm) > 20000 {
			clear(a.comm)
		}
		user := kv["_uid"]
		if user == "" {
			user = kv["uid"]
		}
		a.sys[id] = auditSyscall{exe: kv["exe"], user: user, ppid: kv["ppid"], pid: kv["pid"]}
		if kv["pid"] != "" && kv["comm"] != "" {
			a.comm[kv["pid"]] = kv["comm"]
		}
		return nil, false
	case "PROCTITLE":
		return nil, false
	}
	argc := atoi(kv["argc"])
	if argc <= 0 || argc > 256 {
		return nil, false
	}
	args := make([]string, 0, argc)
	for k := 0; k < argc; k++ {
		args = append(args, auditArg(raw["a"+strconv.Itoa(k)]))
	}
	sc := a.sys[id]
	delete(a.sys, id)
	p := &model.ProcInfo{Op: "process", Image: sc.exe, CommandLine: strings.Join(args, " "), User: sc.user, PID: atoi(sc.pid)}
	if p.Image == "" {
		p.Image = args[0]
	}
	if c := a.comm[sc.ppid]; c != "" {
		p.Parent = c
	}
	host := ""
	if j := strings.Index(line, "node="); j >= 0 && (j == 0 || line[j-1] == ' ') {
		if f := strings.Fields(line[j+5:]); len(f) > 0 {
			host = f[0]
		}
	}
	ev := procEvent("auditd", "", host, p)
	ev.Time = ParseTime(m[2])
	return ev, true
}

// auditArg 还原 auditd 的参数：含空格、引号等的参数以十六进制记录。
func auditArg(v string) string {
	if strings.HasPrefix(v, `"`) {
		return strings.Trim(v, `"`)
	}
	if len(v) >= 2 && len(v)%2 == 0 && strings.Trim(v, "0123456789ABCDEFabcdef") == "" {
		if b, err := hex.DecodeString(v); err == nil {
			return strings.ReplaceAll(string(b), "\x00", " ")
		}
	}
	return v
}
