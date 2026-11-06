package demo

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 主机认证日志（Linux auth.log）与 DNS 日志（Zeek dns.log）的模拟数据：
//   - 内网 DNS：正常解析；10.0.0.33 周期性查询大量随机域名（DGA 僵尸程序）；10.0.0.34 通过超长子域名外传数据（DNS 隧道）；
//     10.0.0.35 在遭受 Log4j 攻击后解析 DNSLog 平台域名（带外回连）；10.0.0.32 解析矿池域名。
//   - 服务器进程（Elastic Agent / ECS）：定时备份、日志轮转、部署脚本等正常活动；入侵剧本中 PHP-FPM 执行注入的命令、反弹 Shell、写入 cron。
//   - SSH：运维人员从内网用密钥登录；外部来源暴力破解 root，偶尔在多次失败后登录成功（账号失陷）。

var normalDomains = []string{"www.baidu.com", "api.weixin.qq.com", "mirrors.aliyun.com", "www.example.com", "update.microsoft.com",
	"time.windows.com", "registry.npmjs.org", "github.com", "api.github.com", "dl.google.com", "cdn.jsdelivr.net", "pypi.org",
	"oss-cn-shanghai.aliyuncs.com", "mp.weixin.qq.com", "login.microsoftonline.com", "ntp.aliyun.com", "s3.amazonaws.com"}

func (s *Sim) dnsLine(t time.Time, client, query, qtype, rcode string) string {
	codes := map[string]int{"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2}
	qt := map[string]int{"A": 1, "AAAA": 28, "TXT": 16, "MX": 15, "CNAME": 5}
	return strings.Join([]string{fmt.Sprintf("%.6f", float64(t.UnixNano())/1e9), fmt.Sprintf("C%08x", s.r.Uint32()), client, fmt.Sprint(1024 + s.r.Intn(60000)),
		"10.0.0.1", "53", "udp", fmt.Sprint(s.r.Intn(65535)), "0.001", query, "1", "C_INTERNET", fmt.Sprint(qt[qtype]), qtype,
		fmt.Sprint(codes[rcode]), rcode, "F", "F", "T", "T", "0", "-", "-", "F"}, "\t")
}

const dgaChars = "bcdfghjklmnpqrstvwxz0123456789"

func (s *Sim) dgaDomain() string {
	b := make([]byte, 12+s.r.Intn(6))
	for i := range b {
		b[i] = dgaChars[s.r.Intn(len(dgaChars))]
	}
	return string(b) + pick(s.r, []string{".com", ".net", ".info", ".top"})
}

const b32 = "abcdefghijklmnopqrstuvwxyz234567"

func (s *Sim) tunnelLabel(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = b32[s.r.Intn(len(b32))]
	}
	return string(b)
}

func authLine(t time.Time, msg string) string {
	return fmt.Sprintf("%s web01 sshd[%d]: %s", t.Format("Jan _2 15:04:05"), 2000+t.Second()*37%9000, msg)
}

// hostLogs 生成一分钟内的 DNS 与认证日志。
func (s *Sim) hostLogs(w *writer, t time.Time, intensity int) {
	s.hostProcs(w, t)
	for i := 0; i < 2*intensity; i++ {
		client := fmt.Sprintf("10.0.0.%d", 40+s.r.Intn(20))
		fmt.Fprintln(w.dns, s.dnsLine(s.sec(t), client, pick(s.r, normalDomains), pick(s.r, []string{"A", "A", "AAAA"}), "NOERROR"))
	}
	if t.Minute()%13 == 0 { // DGA 僵尸程序集中探测
		for i := 0; i < 80; i++ {
			fmt.Fprintln(w.dns, s.dnsLine(s.sec(t), "10.0.0.33", s.dgaDomain(), "A", "NXDOMAIN"))
		}
	}
	if t.Minute()%17 == 0 { // DNS 隧道外传
		for i := 0; i < 6; i++ {
			fmt.Fprintln(w.dns, s.dnsLine(s.sec(t), "10.0.0.34", s.tunnelLabel(52)+"."+s.tunnelLabel(20)+".t.exfil-demo.net", "TXT", "NOERROR"))
		}
	}
	if t.Minute()%29 == 0 {
		fmt.Fprintln(w.dns, s.dnsLine(s.sec(t), "10.0.0.35", s.tunnelLabel(6)+".x7k2p9.dnslog.cn", "A", "NOERROR"))
	}
	if t.Minute()%23 == 0 {
		fmt.Fprintln(w.dns, s.dnsLine(s.sec(t), "10.0.0.32", "pool.minexmr.com", "A", "NOERROR"))
	}
	if t.Minute()%11 == 0 {
		fmt.Fprintln(w.auth, authLine(s.sec(t), fmt.Sprintf("Accepted publickey for deploy from 10.0.0.8 port %d ssh2: ED25519 SHA256:Zk4p…", 40000+s.r.Intn(20000))))
	}
}

// sshBrute 生成一次 SSH 暴力破解；success 为真时在多次失败后登录成功。
func (s *Sim) sshBrute(w *writer, t time.Time, ip string, success bool) {
	users := []string{"root", "admin", "test", "oracle", "ubuntu", "postgres", "git"}
	for i := 0; i < 14; i++ {
		u := pick(s.r, users)
		if i%3 == 0 {
			fmt.Fprintln(w.auth, authLine(s.sec(t), fmt.Sprintf("Invalid user %s from %s port %d", u, ip, 30000+s.r.Intn(30000))))
		} else {
			fmt.Fprintln(w.auth, authLine(s.sec(t), fmt.Sprintf("Failed password for %s from %s port %d ssh2", u, ip, 30000+s.r.Intn(30000))))
		}
	}
	if success {
		fmt.Fprintln(w.auth, authLine(t.Add(59*time.Second), fmt.Sprintf("Accepted password for root from %s port %d ssh2", ip, 30000+s.r.Intn(30000))))
	}
}

// procLine 生成服务器 10.0.0.10 的进程启动事件（Elastic Agent / ECS 格式，带本机地址）。
func (s *Sim) procLine(t time.Time, exe, cmd, parent, user string) string {
	b, _ := json.Marshal(map[string]any{
		"@timestamp": t.UTC().Format(time.RFC3339Nano),
		"event":      map[string]any{"category": "process", "type": "start", "dataset": "endpoint.events.process"},
		"host":       map[string]any{"name": "web01", "ip": []string{s.server}},
		"user":       map[string]any{"name": user},
		"process":    map[string]any{"executable": exe, "command_line": cmd, "pid": 20000 + s.r.Intn(40000), "parent": map[string]any{"executable": parent}},
	})
	return string(b)
}

// hostProcs 生成服务器上正常的进程活动：定时备份、日志轮转、部署脚本（不应告警）。
func (s *Sim) hostProcs(w *writer, t time.Time) {
	switch t.Minute() {
	case 0, 30:
		fmt.Fprintln(w.proc, s.procLine(t.Add(time.Second), "/usr/bin/rsync", "rsync -a --delete /var/www/ /backup/www/", "/usr/sbin/cron", "root"))
	case 15:
		fmt.Fprintln(w.proc, s.procLine(t.Add(2*time.Second), "/usr/sbin/logrotate", "/usr/sbin/logrotate /etc/logrotate.conf", "/usr/sbin/cron", "root"))
	case 45:
		fmt.Fprintln(w.proc, s.procLine(t.Add(3*time.Second), "/usr/bin/bash", "bash /opt/deploy/healthcheck.sh", "/usr/bin/sudo", "deploy"))
	}
}
