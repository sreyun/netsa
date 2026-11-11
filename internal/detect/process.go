package detect

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"netsa/internal/model"
)

// 主机进程检测（EDR / HIDS 日志，P3-3）：补齐主机侧执行、持久化与凭证窃取的证据。
//   - Web 服务进程（IIS w3wp、PHP、Tomcat / WebLogic 等 Java 应用服务器、Apache、nginx）启动命令解释器或侦察命令：
//     WebShell 或命令注入已经在服务器上执行，严重；Linux 以 www-data / nginx / apache 等 Web 账号执行同样处理；
//   - 反弹 Shell：/dev/tcp、nc -e、socat exec、脚本语言的 socket + 重定向；
//   - 编码的 PowerShell、下载执行（IEX DownloadString、curl | sh）与 LOLBin（certutil、bitsadmin、mshta、regsvr32、
//     rundll32 javascript:、wmic process call create、msiexec 远程安装包）；
//   - 凭证窃取：访问 lsass 进程内存（Sysmon 10）、procdump / comsvcs MiniDump / mimikatz、导出 SAM / NTDS；
//   - 持久化：计划任务、服务、Run 键、cron、SSH authorized_keys、加入管理员组；
//   - 痕迹清除与破坏：清除事件日志、关闭 Defender、删除卷影副本（勒索软件的前置动作）；
//   - 第三方 EDR / HIDS 告警（Wazuh）：按告警等级定级，带有的 MITRE 编号写入证据。
// 进程事件本身就是主机上已经发生的动作，结果为“成功”。

const (
	CatHostExec        = "主机命令执行" // Web 服务进程执行系统命令
	CatRevShell        = "反弹Shell"
	CatSuspCmd         = "可疑命令" // 编码的 PowerShell、下载执行、LOLBin
	CatCredTheft       = "凭证窃取"
	CatPersistence     = "持久化"
	CatEvasion         = "痕迹清除"
	CatAccountTakeover = "账号盗用" // 不可能的旅行、首次从新的国家登录、多地并发登录
)

// webServers 是 Web 服务进程（不含扩展名，小写）。
var webServers = map[string]bool{"w3wp": true, "iisexpress": true, "php-cgi": true, "php-fpm": true, "php": true, "httpd": true,
	"apache2": true, "apache": true, "nginx": true, "tomcat": true, "tomcat8": true, "tomcat9": true, "tomcat10": true, "uwsgi": true,
	"lighttpd": true, "caddy": true}

// javaServers 出现在 Java 进程命令行中时，视为 Web 应用服务器。
var javaServers = []string{"catalina", "tomcat", "weblogic", "jboss", "wildfly", "websphere", "resin", "jetty", "glassfish", "tongweb", "apusic", "bes.", "inforsuite"}

// webUsers 是 Web 服务的运行账号（auditd 没有父进程路径时据此判断）。
var webUsers = map[string]bool{"www-data": true, "apache": true, "nginx": true, "nobody": true, "tomcat": true, "httpd": true, "www": true,
	"wwwrun": true, "php-fpm": true, "iusr": true, "weblogic": true, "jboss": true}

// shellTools 是命令解释器与常见的侦察、下载工具。
var shellTools = map[string]bool{"cmd": true, "powershell": true, "pwsh": true, "bash": true, "sh": true, "dash": true, "zsh": true, "ash": true,
	"ksh": true, "whoami": true, "net": true, "net1": true, "ipconfig": true, "ifconfig": true, "systeminfo": true, "tasklist": true,
	"certutil": true, "bitsadmin": true, "wget": true, "curl": true, "nc": true, "ncat": true, "netcat": true, "python": true, "python3": true,
	"perl": true, "id": true, "uname": true, "hostname": true, "quser": true, "query": true, "nltest": true, "wmic": true, "mshta": true,
	"rundll32": true, "regsvr32": true, "cscript": true, "wscript": true, "socat": true, "telnet": true, "busybox": true}

// lsassSafe 是正常访问 lsass 内存的系统与安全软件进程。
var lsassSafe = map[string]bool{"msmpeng": true, "mssense": true, "csrss": true, "wininit": true, "services": true, "svchost": true, "lsm": true,
	"wmiprvse": true, "vmtoolsd": true, "lsass": true, "smss": true, "mrt": true, "sense": true, "sensece": true, "nissrv": true,
	"securityhealthservice": true, "taskmgr": false, "procexp": false, "procexp64": false}

// lsassRead 是读取 lsass 内存所需的访问权限（Sysmon 10 的 GrantedAccess）。
var lsassRead = map[string]bool{"0x1010": true, "0x1410": true, "0x1418": true, "0x1438": true, "0x143a": true, "0x1f0fff": true,
	"0x1fffff": true, "0x1f1fff": true, "0x1f3fff": true, "0x40": true, "0x1410a": true}

// procName 返回进程的文件名（小写、不含扩展名与版本号）：带版本号的可执行文件（php-fpm8.2、python3.11、tomcat9）
// 按不带版本的名称识别。
func procName(p string) string {
	p = strings.ToLower(strings.Trim(strings.TrimSpace(p), `"`))
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	p = strings.TrimSuffix(strings.TrimSuffix(p, ".exe"), ".com")
	// 名称本身就带数字的进程（rundll32、regsvr32、apache2、net1）按原名识别：去掉数字后 rundll32 变成 rundll，
	// 针对它们的系统工具滥用、Web 进程派生与外连规则全部失效
	if webServers[p] || shellTools[p] || suspNetProc[p] {
		return p
	}
	if t := strings.TrimRight(strings.TrimRight(p, "0123456789."), "-_"); t != "" {
		p = t
	}
	return p
}

type procRule struct {
	id, name, cat string
	sev           model.Severity
	phase         string
	tech          string
	re            *regexp.Regexp
	img           map[string]bool // 非空时只匹配这些进程
}

func pr(id, name, cat string, sev model.Severity, phase, tech, re string, imgs ...string) procRule {
	r := procRule{id: id, name: name, cat: cat, sev: sev, phase: phase, tech: tech, re: regexp.MustCompile(re)}
	if len(imgs) > 0 {
		r.img = map[string]bool{}
		for _, x := range imgs {
			r.img[x] = true
		}
	}
	return r
}

// procRules 按命令行匹配（命令行已转为小写）。
var procRules = []procRule{
	// 反弹 Shell
	pr("proc-revshell", "反弹 Shell", CatRevShell, model.SevCritical, model.PhasePersistence, "T1059.004",
		`/dev/(?:tcp|udp)/\d|\bnc(?:at|\.traditional|\.openbsd)?\b[^|;&]*\s-(?:e|c)\s|ncat\b[^|;&]*--(?:sh-)?exec|socat\b[^|;&]*exec:|mkfifo\b[^;]*\b(?:nc|ncat|telnet)\b|`+
			`python[0-9.]*\s+-c\s.*socket.*(?:subprocess|pty\.spawn|dup2)|perl\s+-e\s.*socket.*(?:exec|open)|php\s+-r\s.*fsockopen|ruby\s+-rsocket|`+
			`net\.sockets\.tcpclient.*(?:getstream|iex|invoke-expression)`),
	// 下载执行
	pr("proc-download-exec", "下载并执行脚本", CatSuspCmd, model.SevCritical, model.PhaseExploit, "T1105",
		`(?:curl|wget)\b[^|;]*https?://[^|;]*\|\s*(?:ba|da|z)?sh\b|(?:curl|wget)\b[^;&]*https?://\S+.*&&\s*(?:chmod\s+\+?[0-7x]+|(?:ba)?sh\s)`),
	pr("proc-ps-download", "PowerShell 下载执行", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1059.001",
		`(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr\s|invoke-restmethod|irm\s|start-bitstransfer)[^;]*https?://.*|(?:iex|invoke-expression)\s*\(?\s*\(?new-object\s+net\.webclient`,
		"powershell", "pwsh", "cmd"),
	// LOLBin
	pr("proc-certutil", "certutil 下载文件", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1105", `-(?:urlcache|verifyctl)\b.*https?://|-decode(?:hex)?\s`, "certutil"),
	pr("proc-bitsadmin", "bitsadmin 下载文件", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1105", `/(?:transfer|addfile)\b.*https?://`, "bitsadmin"),
	pr("proc-mshta", "mshta 执行远程脚本", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1218", `https?://|javascript:|vbscript:`, "mshta"),
	pr("proc-regsvr32", "regsvr32 加载远程脚本（Squiblydoo）", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1218", `/i:\s*https?://|scrobj\.dll`, "regsvr32"),
	pr("proc-rundll32", "rundll32 执行脚本", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1218", `javascript:|vbscript:|url\.dll,\s*(?:file|open)protocolhandler\s+https?://|comsvcs`, "rundll32"),
	pr("proc-wmic", "wmic 远程创建进程", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1047", `process\s+call\s+create|/node:`, "wmic"),
	pr("proc-msiexec", "msiexec 安装远程安装包", CatSuspCmd, model.SevHigh, model.PhaseExploit, "T1218", `https?://`, "msiexec"),
	// 凭证窃取
	pr("proc-cred-dump", "导出凭证", CatCredTheft, model.SevCritical, model.PhaseExploit, "T1003",
		`procdump[0-9]*(?:\.exe)?\s.*-ma\s.*lsass|comsvcs(?:\.dll)?[ ,]+#?(?:minidump|24)|sekurlsa::|lsadump::|kerberos::(?:golden|ptt)|privilege::debug|`+
			`\bmimikatz\b|ntdsutil\b.*\bifm\b|\\ntds\\ntds\.dit|reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)\b|\bunshadow\b|pypykatz|lazagne`),
	// 持久化
	pr("proc-schtask", "创建可疑的计划任务", CatPersistence, model.SevHigh, model.PhasePersistence, "T1053",
		`/create\b.*(?:https?://|-enc|frombase64|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|mshta|regsvr32|rundll32|certutil)`, "schtasks"),
	pr("proc-service", "创建服务", CatPersistence, model.SevMedium, model.PhasePersistence, "T1543", `\bcreate\b.*binpath\s*=|\bconfig\b.*binpath\s*=`, "sc"),
	pr("proc-runkey", "写入开机启动项（Run 键）", CatPersistence, model.SevHigh, model.PhasePersistence, "T1547.001",
		`\breg(?:\.exe)?\s+add\s.*\\currentversion\\(?:run|runonce|policies\\explorer\\run)\b|\\image file execution options\\.*debugger`),
	pr("proc-cron", "写入计划任务（cron）", CatPersistence, model.SevHigh, model.PhasePersistence, "T1053",
		`>>?\s*/etc/(?:crontab|cron\.d/)|crontab\s+-l.*\|\s*crontab\s+-|/var/spool/cron/`),
	pr("proc-sshkey", "写入 SSH 公钥（authorized_keys）", CatPersistence, model.SevHigh, model.PhasePersistence, "T1098.004", `>>?\s*\S*\.ssh/authorized_keys`),
	pr("proc-admin-group", "加入管理员组", CatPersistence, model.SevHigh, model.PhasePersistence, "T1098",
		`\bnet1?(?:\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add|usermod\s+-a?g\s*(?:sudo|wheel|root)\b`),
	pr("proc-add-user", "命令行新建账号", CatPersistence, model.SevMedium, model.PhasePersistence, "T1136", `\bnet1?(?:\.exe)?\s+user\s+\S+\s+\S+\s+/add|\buseradd\b.*-o\s+-u\s*0`),
	// 痕迹清除与破坏
	pr("proc-clear-log", "清除事件日志", CatEvasion, model.SevHigh, model.PhasePersistence, "T1070.001",
		`wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|clear-eventlog|remove-eventlog|limit-eventlog`),
	pr("proc-clear-history", "清除命令历史", CatEvasion, model.SevMedium, model.PhasePersistence, "T1070.003",
		`history\s+-c\b|rm\s+(?:-\w+\s+)*\S*\.bash_history|unset\s+histfile|histfile=/dev/null|ln\s+-sf?\s+/dev/null\s+\S*history`),
	pr("proc-disable-av", "关闭或绕过安全软件", CatEvasion, model.SevHigh, model.PhasePersistence, "T1562.001",
		`set-mppreference\s.*-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection)\s+\$?true|add-mppreference\s.*-exclusion(?:path|process)|`+
			`setenforce\s+0|systemctl\s+(?:stop|disable)\s+(?:auditd|falcon|wazuh|osquery)|sc(?:\.exe)?\s+(?:stop|delete)\s+(?:windefend|sense|wdboot)`),
	pr("proc-shadow-delete", "删除卷影副本 / 禁用恢复（勒索前置动作）", CatDestroy, model.SevCritical, model.PhaseImpact, "T1490",
		`vssadmin(?:\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|bcdedit(?:\.exe)?\s+/set\s.*recoveryenabled\s+no|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)|`+
			`delete\s+shadows\s+/all|get-wmiobject\s+win32_shadowcopy.*delete`),
}

// maxCmdLine 是参与匹配的命令行长度上限。
const maxCmdLine = 8192

// reEncodedPS 匹配 PowerShell 的编码参数（-e / -enc / -EncodedCommand 及其缩写）。
var reEncodedPS = regexp.MustCompile(`(?i)(?:^|\s)[-/]e(?:c|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedcommand)?\s+([a-z0-9+/=]{20,})`)

// inspectProcess 检测主机进程事件。
func inspectProcess(ev *model.Event) []model.Hit {
	p := ev.Proc
	if p == nil {
		return nil
	}
	if p.Op == "alert" {
		if h, ok := edrAlertHit(ev); ok {
			return []model.Hit{h}
		}
		return nil
	}
	img, parent := procName(p.Image), procName(p.Parent)
	cmdLine := p.CommandLine
	if len(cmdLine) > maxCmdLine {
		cmdLine = cmdLine[:maxCmdLine] // 只匹配前 8 KB（Windows 命令行最长 32 KB）
	}
	cmd := strings.ToLower(cmdLine)
	who := hostLabel(ev)
	hit := func(id, name, cat string, sev model.Severity, phase, tech, evidence string) model.Hit {
		return model.Hit{RuleID: id, Name: name, Category: cat, Severity: sev, Phase: phase, Result: model.ResultSuccess, Proven: true,
			Evidence: Printable(who+evidence+"（"+tech+"）", 400)}
	}
	var hits []model.Hit
	switch p.Op {
	case "access":
		if procName(p.Target) == "lsass" && lsassRead[p.Access] && !lsassSafe[img] {
			hits = append(hits, hit("proc-lsass-access", "读取 lsass 进程内存（凭证窃取）", CatCredTheft, model.SevCritical, model.PhaseExploit, "T1003.001",
				fmt.Sprintf("进程 %s 以权限 %s 访问 lsass.exe", Printable(p.Image, 160), p.Access)))
		}
		return hits
	case "file":
		t := strings.ToLower(p.Target)
		switch {
		case webServers[img] || img == "java" && isJavaServer(strings.ToLower(p.ParentCmd)):
			if webScriptFile(t) {
				hits = append(hits, hit("proc-webshell-drop", "Web 服务进程写入脚本文件（WebShell 落地）", CatWebShell, model.SevCritical, model.PhasePersistence,
					"T1505.003", fmt.Sprintf("%s 创建 %s", img, Printable(p.Target, 200))))
			}
		case strings.Contains(t, `\start menu\programs\startup\`):
			hits = append(hits, hit("proc-startup-file", "写入启动文件夹", CatPersistence, model.SevHigh, model.PhasePersistence, "T1547.001",
				fmt.Sprintf("%s 创建 %s", Printable(p.Image, 120), Printable(p.Target, 200))))
		case strings.HasSuffix(t, "/.ssh/authorized_keys") || strings.HasSuffix(t, `\.ssh\authorized_keys`):
			hits = append(hits, hit("proc-sshkey", "写入 SSH 公钥（authorized_keys）", CatPersistence, model.SevHigh, model.PhasePersistence, "T1098.004",
				fmt.Sprintf("%s 写入 %s", Printable(p.Image, 120), Printable(p.Target, 200))))
		}
		return hits
	case "registry":
		t := strings.ToLower(p.Target)
		if strings.Contains(t, `\currentversion\run`) || strings.Contains(t, `\image file execution options\`) && strings.HasSuffix(t, `\debugger`) {
			hits = append(hits, hit("proc-runkey", "写入开机启动项（Run 键）", CatPersistence, model.SevHigh, model.PhasePersistence, "T1547.001",
				fmt.Sprintf("%s 写入 %s = %s", Printable(p.Image, 120), Printable(p.Target, 160), Printable(p.CommandLine, 120))))
		}
		return hits
	case "network":
		if suspNetProc[img] {
			if ip, _, _ := strings.Cut(p.Target, ":"); ip != "" && !isPrivateIP(ip) {
				hits = append(hits, hit("proc-net-lolbin", "脚本 / 系统工具进程连接公网", CatSuspCmd, model.SevMedium, model.PhasePersistence, "T1071",
					fmt.Sprintf("%s 连接 %s", Printable(p.Image, 120), p.Target)))
			}
		}
		return hits
	}
	// 进程创建
	if shellTools[img] && (webServers[parent] || parent == "java" && isJavaServer(strings.ToLower(p.ParentCmd)) ||
		parent == "" && webUsers[strings.ToLower(baseUser(p.User))]) {
		from := parent
		if from == "" {
			from = "Web 服务账号 " + p.User
		}
		hits = append(hits, hit("proc-web-spawn", "Web 服务进程执行系统命令（WebShell / 命令注入已执行）", CatHostExec, model.SevCritical, model.PhaseExploit,
			"T1505.003", fmt.Sprintf("%s 启动 %s：%s", from, img, Printable(p.CommandLine, 240))))
	}
	if (img == "powershell" || img == "pwsh") && cmd != "" {
		if m := reEncodedPS.FindStringSubmatch(cmdLine); m != nil { // 在原始命令行上匹配：Base64 区分大小写
			dec := decodePSCommand(m[1])
			sev, name := model.SevHigh, "编码的 PowerShell 命令"
			low := strings.ToLower(dec)
			if strings.Contains(low, "downloadstring") || strings.Contains(low, "net.webclient") || strings.Contains(low, "iex") ||
				strings.Contains(low, "invoke-expression") || strings.Contains(low, "frombase64string") {
				sev, name = model.SevCritical, "编码的 PowerShell 下载执行"
			}
			ev := "执行 " + Printable(p.CommandLine, 120)
			if dec != "" {
				ev = "执行编码命令，解码后：" + Printable(dec, 200)
			}
			hits = append(hits, hit("proc-ps-encoded", name, CatSuspCmd, sev, model.PhaseExploit, "T1059.001", ev))
		}
	}
	for i := range procRules {
		r := &procRules[i]
		if r.img != nil && !r.img[img] || cmd == "" || !r.re.MatchString(cmd) {
			continue
		}
		dup := false
		for _, h := range hits {
			dup = dup || h.RuleID == r.id
		}
		if !dup {
			hits = append(hits, hit(r.id, r.name, r.cat, r.sev, r.phase, r.tech, fmt.Sprintf("%s 执行：%s", img, Printable(p.CommandLine, 240))))
		}
	}
	return hits
}

// suspNetProc 是不应主动连接公网的脚本宿主与系统工具（Office 宏、脚本、LOLBin 下载）。
var suspNetProc = map[string]bool{"mshta": true, "rundll32": true, "regsvr32": true, "certutil": true, "bitsadmin": true, "wscript": true,
	"cscript": true, "msbuild": true, "installutil": true, "winword": true, "excel": true, "powerpnt": true, "wmic": true}

func isJavaServer(cmd string) bool {
	for _, k := range javaServers {
		if strings.Contains(cmd, k) {
			return true
		}
	}
	return false
}

// webScriptFile 判断是否为可被 Web 服务执行的脚本。
func webScriptFile(p string) bool {
	for _, ext := range []string{".php", ".php5", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".asmx", ".cer", ".asa", ".war"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func hostLabel(ev *model.Event) string {
	switch {
	case ev.Host != "" && ev.SrcIP != "" && ev.SrcIP != "127.0.0.1":
		return ev.Host + "（" + ev.SrcIP + "）上 "
	case ev.Host != "":
		return ev.Host + " 上 "
	case ev.SrcIP != "":
		return ev.SrcIP + " 上 "
	}
	return ""
}

// decodePSCommand 解码 -EncodedCommand 的参数（UTF-16LE 的 Base64）。
func decodePSCommand(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
			return ""
		}
	}
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// edrAlertHit 把第三方 EDR / HIDS 的告警转为命中：Wazuh 等级 12 以上严重、10~11 高危、7~9 中危、4~6 低危，3 以下不告警。
func edrAlertHit(ev *model.Event) (model.Hit, bool) {
	p := ev.Proc
	var sev model.Severity
	switch {
	case p.Level >= 12:
		sev = model.SevCritical
	case p.Level >= 10:
		sev = model.SevHigh
	case p.Level >= 7:
		sev = model.SevMedium
	case p.Level >= 4:
		sev = model.SevLow
	default:
		return model.Hit{}, false
	}
	cat, phase := CatHostEvent, model.PhasePersistence
mitre:
	for _, id := range p.Mitre {
		switch {
		case strings.HasPrefix(id, "T1110"):
			cat, phase = CatBruteForce, model.PhaseExploit
		case strings.HasPrefix(id, "T1003"):
			cat, phase = CatCredTheft, model.PhaseExploit
		case strings.HasPrefix(id, "T1505"):
			cat = CatWebShell
		case strings.HasPrefix(id, "T1053"), strings.HasPrefix(id, "T1543"), strings.HasPrefix(id, "T1547"), strings.HasPrefix(id, "T1098"):
			cat = CatPersistence
		case strings.HasPrefix(id, "T1070"), strings.HasPrefix(id, "T1562"):
			cat = CatEvasion
		case strings.HasPrefix(id, "T1190"):
			cat, phase = CatCVE, model.PhaseExploit
		case strings.HasPrefix(id, "T1485"), strings.HasPrefix(id, "T1486"), strings.HasPrefix(id, "T1490"):
			cat, phase = CatDestroy, model.PhaseImpact
		default:
			continue
		}
		break mitre // 取第一个能归类的编号
	}
	evd := "第三方告警（" + ev.Format + " 规则 " + p.Rule + "，等级 " + strconv.Itoa(p.Level) + "）：" + ev.Threat
	if len(p.Mitre) > 0 {
		evd += "；MITRE " + strings.Join(p.Mitre, "、")
	}
	if ev.Raw != "" {
		evd += "；" + ev.Raw
	}
	res := model.ResultUnknown
	if ev.SubjectHost {
		res = model.ResultSuccess // 主机上已经发生的事件（文件被修改、进程被执行）
	}
	return model.Hit{RuleID: "edr-" + ev.Format + "-" + p.Rule, Name: ev.Threat, Category: cat, Severity: sev, Phase: phase, Result: res,
		Evidence: Printable(hostLabel(ev)+evd, 400)}, true
}
