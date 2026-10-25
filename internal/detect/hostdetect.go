package detect

import (
	"math"
	"strings"

	"netsa/internal/model"
)

// DNS 与主机认证日志的攻击类型。
const (
	CatDNSTunnel = "DNS隧道"
	CatDGA       = "DGA域名"
	CatOOB       = "带外探测回连"
	CatMining    = "挖矿"
	CatDynDNS    = "动态域名/内网穿透"
	CatHostEvent = "主机安全事件"
	CatAccount   = "账号异常"
)

// 带外探测（DNSLog）平台：内网主机解析这些域名，通常意味着盲打的 RCE / SSRF / Log4j 等漏洞已被成功触发。
var oobDomains = domainSet("dnslog.cn", "dnslog.link", "ceye.io", "burpcollaborator.net", "oastify.com", "oast.pro", "oast.live", "oast.site",
	"oast.online", "oast.fun", "oast.me", "interact.sh", "interactsh.com", "requestbin.net", "eyes.sh", "dig.pm", "dnslog.pw", "tu4.org", "xip.io")

// 矿池域名。
var miningDomains = domainSet("minexmr.com", "supportxmr.com", "nanopool.org", "c3pool.com", "hashvault.pro", "moneroocean.stream", "f2pool.com",
	"2miners.com", "herominers.com", "xmrpool.eu", "minergate.com", "ethermine.org", "crypto-pool.fr", "dwarfpool.com", "unmineable.com", "kryptex.network")

// 动态域名与内网穿透服务：恶意软件常用于 C2，也有正常使用，等级较低。
var dynDomains = domainSet("duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "serveftp.com",
	"3322.org", "f3322.net", "f3322.org", "8800.org", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "localtunnel.me",
	"oicp.net", "vicp.net", "dynu.net", "freedns.afraid.org", "changeip.com", "natappfree.cc")

func domainSet(list ...string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, d := range list {
		m[d] = true
	}
	return m
}

// domainIn 判断域名或其任一上级域名是否在集合中，返回命中的域名。按标签逐级查表，不分配内存。
func domainIn(name string, set map[string]bool) string {
	for s := name; ; {
		if set[s] {
			return s
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return ""
		}
		s = s[i+1:]
	}
}

// 常见的二级公共后缀：计算主域名时跳过（www.example.com.cn 的主域名是 example.com.cn）。
var secondLevel = map[string]bool{"com": true, "net": true, "org": true, "gov": true, "edu": true, "co": true, "ac": true, "or": true, "ne": true, "go": true}

// splitDomain 返回主域名（注册域）与其下的子域名部分（子串切片，不分配内存）。
func splitDomain(name string) (registered, sub string) {
	last := strings.LastIndexByte(name, '.')
	if last <= 0 {
		return name, ""
	}
	cut := strings.LastIndexByte(name[:last], '.')
	if cut < 0 {
		return name, ""
	}
	if len(name)-last-1 == 2 && secondLevel[name[cut+1:last]] {
		if cut = strings.LastIndexByte(name[:cut], '.'); cut < 0 {
			return name, ""
		}
	}
	return name[cut+1:], name[:cut]
}

// longestLabel 返回子域名中最长的一段。
func longestLabel(sub string) string {
	best := ""
	for sub != "" {
		l := sub
		if i := strings.IndexByte(sub, '.'); i >= 0 {
			l, sub = sub[:i], sub[i+1:]
		} else {
			sub = ""
		}
		if len(l) > len(best) {
			best = l
		}
	}
	return best
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// dgaScore 评估主域名的第一段是否像算法生成的随机字符串（0 ~ 1.05）：长度、字符熵、辅音连续、数字混排。
func dgaScore(label string) float64 {
	if len(label) < 12 || strings.Contains(label, "-") {
		return 0
	}
	vowels, digits, run, maxRun := 0, 0, 0, 0
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			run = 0
		case c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u':
			vowels++
			run = 0
		case c >= 'a' && c <= 'z':
			run++
			maxRun = max(maxRun, run)
		default:
			return 0 // 非 ASCII（国际化域名）不判断
		}
	}
	n := float64(len(label))
	score := 0.0
	if float64(vowels)/n < 0.22 {
		score += 0.25
	}
	if maxRun >= 5 {
		score += 0.2
	}
	if digits > 0 && digits < len(label) && float64(digits)/n > 0.15 {
		score += 0.15
	}
	if len(label) >= 16 {
		score += 0.1
	}
	if score < 0.3 { // 其余特征都不满足时不可能达到阈值，省去熵的计算
		return score
	}
	if entropy(label) >= 3.5 {
		score += 0.35
	}
	return score
}

// inspectDNS 对单条 DNS 查询做特征检测。主体是发起查询的内网主机：命中即为失陷迹象。
func inspectDNS(ev *model.Event) []model.Hit {
	if ev.Flags == "R" { // 同一次查询的响应记录，只用于行为统计
		return nil
	}
	name := ev.Host
	hit := func(id, title, cat string, sev model.Severity, evidence string) []model.Hit {
		return []model.Hit{{RuleID: id, Name: title, Category: cat, Severity: sev, Phase: model.PhasePersistence, Result: model.ResultAllowed,
			Evidence: ev.SrcIP + " 查询 " + Printable(name, 120) + "（" + ev.QType + "）" + evidence}}
	}
	if d := domainIn(name, oobDomains); d != "" {
		return hit("dns-oob", "解析带外探测平台域名（"+d+"，盲打漏洞可能已被触发）", CatOOB, model.SevCritical, "")
	}
	if domainIn(name, miningDomains) != "" || strings.Contains(name, "xmr") && strings.Contains(name, "pool") {
		return hit("dns-mining", "解析矿池域名（疑似挖矿木马）", CatMining, model.SevHigh, "")
	}
	reg, sub := splitDomain(name)
	// DNS 隧道：子域名中编码数据，单段很长且随机
	if longest := longestLabel(sub); len(longest) >= 40 && entropy(longest) >= 3.8 || len(sub) >= 100 {
		sev := model.SevHigh
		if ev.QType == "TXT" || ev.QType == "NULL" || ev.QType == "CNAME" || ev.QType == "MX" {
			sev = model.SevCritical
		}
		return hit("dns-tunnel", "疑似 DNS 隧道（子域名编码数据）", CatDNSTunnel, sev, "，子域名长度 "+itoa(len(sub)))
	}
	if d := domainIn(name, dynDomains); d != "" || strings.Contains(name, ".frp.") || strings.HasPrefix(name, "frp.") {
		if d == "" {
			d = "frp"
		}
		return hit("dns-dyn", "解析动态域名 / 内网穿透服务（"+d+"）", CatDynDNS, model.SevLow, "")
	}
	first := reg
	if i := strings.IndexByte(reg, '.'); i > 0 {
		first = reg[:i]
	}
	// 随机域名：不存在（NXDOMAIN）时为高危；能解析的随机域名只在特征非常明显时告警（减少 CDN、短链等正常随机域名的误报）
	if s := dgaScore(first); ev.RCode == "NXDOMAIN" && s >= 0.7 || s >= 0.9 {
		sev := model.SevMedium
		if ev.RCode == "NXDOMAIN" {
			sev = model.SevHigh
		}
		return hit("dns-dga", "疑似 DGA 随机域名", CatDGA, sev, "")
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var privilegedUsers = map[string]bool{"root": true, "administrator": true, "admin": true, "sa": true, "oracle": true, "postgres": true, "system": true}

func baseUser(u string) string {
	u = strings.ToLower(u)
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i > 0 {
		u = u[:i]
	}
	return u
}

var adminGroups = []string{"administrators", "domain admins", "enterprise admins", "schema admins", "sudo", "wheel", "admin", "root", "管理员"}

// inspectAuth 对单条认证 / 主机安全事件做特征检测（暴力破解等需要统计的行为由 Behavior 检测）。
func inspectAuth(ev *model.Event) []model.Hit {
	host := ev.Host
	if host == "" {
		host = ev.SrcIP
	}
	mk := func(id, title, cat string, sev model.Severity, phase, evidence string) []model.Hit {
		return []model.Hit{{RuleID: id, Name: title, Category: cat, Severity: sev, Phase: phase, Result: model.ResultSuccess, Evidence: Printable(evidence, 200)}}
	}
	switch ev.EventID {
	case 1102, 104:
		return mk("host-log-cleared", "安全日志被清除（疑似清理入侵痕迹）", CatHostEvent, model.SevHigh, model.PhasePersistence, host+" 的审计日志被清除，操作账号 "+ev.User)
	case 4720:
		return mk("host-user-created", "新建系统账号", CatAccount, model.SevMedium, model.PhasePersistence, host+" 新建账号 "+ev.User)
	case 4728, 4732, 4756:
		g := strings.ToLower(ev.URI)
		for _, a := range adminGroups {
			if strings.Contains(g, a) {
				return mk("host-admin-group", "账号被加入管理员组（权限提升）", CatAccount, model.SevHigh, model.PhasePersistence, host+" 将 "+ev.User+" 加入 "+ev.URI)
			}
		}
		return nil
	case 7045, 4697:
		return mk("host-service-installed", "新安装系统服务（常见持久化手段）", CatHostEvent, model.SevMedium, model.PhasePersistence, host+" 安装服务 "+ev.URI)
	case 4698:
		return mk("host-task-created", "新建计划任务（常见持久化手段）", CatHostEvent, model.SevMedium, model.PhasePersistence, host+" 创建计划任务 "+ev.URI)
	case 4740:
		return []model.Hit{{RuleID: "auth-locked", Name: "账号因多次登录失败被锁定", Category: CatBruteForce, Severity: model.SevLow, Phase: model.PhaseCredential,
			Result: model.ResultBlocked, Evidence: host + " 锁定账号 " + ev.User}}
	}
	// 来自公网的特权账号登录成功：即使是运维操作，也应通过堡垒机 / VPN 而不是直接暴露
	if ev.Action == model.ActionAllow && !ev.SubjectHost && !isPrivateIP(ev.SrcIP) && privilegedUsers[baseUser(ev.User)] {
		return []model.Hit{{RuleID: "auth-priv-external", Name: "公网 IP 直接登录特权账号", Category: CatAccount, Severity: model.SevMedium, Phase: model.PhaseCredential,
			Result: model.ResultSuccess, Evidence: Printable(ev.SrcIP+" 以 "+ev.User+" 登录 "+ev.Service+" @"+host, 200)}}
	}
	return nil
}
