package detect

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

var reLoginPath = regexp.MustCompile(`(?i)(login|logon|signin|sign-in|sign_in|/auth|wp-login\.php|xmlrpc\.php|j_security_check|j_spring_security_check|/oauth/token|/api/[^?]*token|passport|/session|admin\.php|/user/login|password)`)

// 行为检测中常被暴力破解的认证类端口。
var authPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 445: "SMB", 1433: "MSSQL",
	1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis", 27017: "MongoDB",
}

const (
	bitCC = 1 << iota
	bitScan
	bitBrute
	bit5xx
	bitPortScan
	bitSweep
	bitFwBrute
	bitFlood
	bitBruteOK
)

// 每个 IP 的窗口状态都有容量上限：只需判断是否达到阈值，不必记录全部明细，
// 避免大规模扫描时内存随“来源 IP × 端口 × 主机”增长。
type webWin struct {
	start                   time.Time
	reqs, n404, login, n401 int
	n5xx                    int
	paths                   map[string]struct{}
	loginStatus             map[int]int // 窗口内登录提交的响应码分布
	fired                   int
}

type fwWin struct {
	start  time.Time
	events int
	ports  map[int]struct{}
	sweep  map[int]map[string]struct{}
	auth   map[int]int
	fired  int
}

// Behavior 基于时间窗口识别 CC、目录扫描、暴力破解、端口扫描等行为。
// 窗口以日志自身时间为准，因此同样适用于历史日志的离线分析。
type Behavior struct {
	mu        sync.Mutex
	th        config.Thresholds
	web       map[string]*webWin
	fw        map[string]*fwWin
	lastPrune time.Time
}

func NewBehavior(th config.Thresholds) *Behavior {
	return &Behavior{th: th, web: map[string]*webWin{}, fw: map[string]*fwWin{}}
}

// Observe 处理一个事件并返回触发的行为告警。
func (b *Behavior) Observe(ev *model.Event) []model.Hit {
	if ev.Outbound {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if ev.Time.Sub(b.lastPrune) > time.Minute {
		b.prune(ev.Time)
	}
	if ev.Kind == model.KindWeb {
		return b.observeWeb(ev)
	}
	return b.observeFw(ev)
}

func (b *Behavior) observeWeb(ev *model.Event) []model.Hit {
	w := b.web[ev.SrcIP]
	if w == nil || outside(ev.Time, w.start, b.th.WebWindow) {
		w = &webWin{start: ev.Time}
		b.web[ev.SrcIP] = w
	}
	w.reqs++
	path := ev.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	switch {
	case ev.Status == 404:
		w.n404++
	case ev.Status == 401:
		w.n401++
	case ev.Status >= 500:
		w.n5xx++
	}
	// 只在出现 404 时记录路径：正常访客不分配集合，扫描器的集合达到阈值后不再增长
	if ev.Status == 404 && len(w.paths) < b.th.ScanPaths {
		if w.paths == nil {
			w.paths = map[string]struct{}{}
		}
		w.paths[path] = struct{}{}
	}
	isLogin := ev.Method == "POST" && reLoginPath.MatchString(path)
	// 判断“疑似破解成功”需要基于本次之前的响应码分布
	bruteOK := false
	if isLogin {
		bruteOK = w.fired&bitBrute != 0 && looksLikeLoginSuccess(w.loginStatus, ev.Status)
		w.login++
		if w.loginStatus == nil {
			w.loginStatus = map[int]int{}
		}
		if len(w.loginStatus) < 16 {
			w.loginStatus[ev.Status]++
		}
	}
	win := fmtDur(b.th.WebWindow)
	var hits []model.Hit
	fire := func(bit int, cond bool, mk func() model.Hit) {
		if cond && w.fired&bit == 0 {
			w.fired |= bit
			h := mk() // 证据文本只在触发时生成
			if h.Result == "" {
				h.Result = model.ResultUnknown
			}
			hits = append(hits, h)
		}
	}
	fire(bitCC, w.reqs >= b.th.CCRequests, func() model.Hit {
		return model.Hit{RuleID: "bhv-cc", Name: "CC攻击/高频请求", Category: CatCC,
			Severity: model.SevHigh, Phase: model.PhaseImpact, Evidence: fmt.Sprintf("%s内请求 %d 次", win, w.reqs)}
	})
	fire(bitScan, w.n404 >= b.th.Scan404 && len(w.paths) >= b.th.ScanPaths, func() model.Hit {
		return model.Hit{RuleID: "bhv-dirscan", Name: "目录/文件枚举扫描", Category: CatDirScan,
			Severity: model.SevMedium, Phase: model.PhaseRecon, Evidence: fmt.Sprintf("%s内 404 响应 %d 次，访问 %d 个以上不同路径", win, w.n404, len(w.paths))}
	})
	fire(bitBrute, w.login >= b.th.BruteLogin || w.n401 >= b.th.BruteLogin, func() model.Hit {
		return model.Hit{RuleID: "bhv-webbrute", Name: "Web登录暴力破解", Category: CatBruteForce,
			Severity: model.SevHigh, Phase: model.PhaseCredential, Evidence: fmt.Sprintf("%s内登录提交 %d 次，401 响应 %d 次，最近路径 %s", win, w.login, w.n401, Printable(path, 80))}
	})
	fire(bitBruteOK, bruteOK, func() model.Hit {
		return model.Hit{RuleID: "bhv-webbrute-ok", Name: "暴力破解疑似成功", Category: CatBruteForce, Severity: model.SevCritical,
			Phase: model.PhaseCredential, Result: model.ResultSuccess,
			Evidence: fmt.Sprintf("连续 %d 次登录失败后 %s 返回与失败时不同的响应码 %d", w.login-1, Printable(path, 80), ev.Status)}
	})
	fire(bit5xx, w.n5xx >= b.th.Server5xx, func() model.Hit {
		return model.Hit{RuleID: "bhv-5xx", Name: "异常请求引发大量服务端错误", Category: CatProtocol,
			Severity: model.SevMedium, Phase: model.PhaseExploit, Evidence: fmt.Sprintf("%s内 5xx 响应 %d 次", win, w.n5xx)}
	})
	return hits
}

// looksLikeLoginSuccess 判断本次登录响应是否与此前的失败响应明显不同：
// 例如持续 401 后出现 200，或持续 200（表单回显错误）后出现 302 跳转。
// 若失败时也统一返回 302（如 Spring Security 跳回 /login?error），则不会误判。
func looksLikeLoginSuccess(prev map[int]int, status int) bool {
	if status < 200 || status >= 400 || len(prev) == 0 {
		return false
	}
	total, dominant, domN := 0, 0, 0
	for s, n := range prev {
		total += n
		if n > domN {
			dominant, domN = s, n
		}
	}
	return dominant != status && prev[status]*10 <= total && domN*10 >= total*8
}

func (b *Behavior) observeFw(ev *model.Event) []model.Hit {
	w := b.fw[ev.SrcIP]
	if w == nil || outside(ev.Time, w.start, b.th.FwWindow) {
		w = &fwWin{start: ev.Time}
		b.fw[ev.SrcIP] = w
	}
	w.events++
	highScan := b.th.PortScanPorts * 5
	if ev.DstPort > 0 {
		if len(w.ports) < highScan {
			if w.ports == nil {
				w.ports = map[int]struct{}{}
			}
			w.ports[ev.DstPort] = struct{}{}
		}
		if ev.DstIP != "" {
			if w.sweep == nil {
				w.sweep = map[int]map[string]struct{}{}
			}
			s := w.sweep[ev.DstPort]
			if s == nil && len(w.sweep) < 64 {
				s = map[string]struct{}{}
				w.sweep[ev.DstPort] = s
			}
			if s != nil && len(s) < b.th.HostSweep {
				s[ev.DstIP] = struct{}{}
			}
		}
		if _, ok := authPorts[ev.DstPort]; ok {
			if w.auth == nil {
				w.auth = map[int]int{}
			}
			w.auth[ev.DstPort]++
		}
	}
	win := fmtDur(b.th.FwWindow)
	var hits []model.Hit
	fire := func(bit int, cond bool, mk func() model.Hit) {
		if cond && w.fired&bit == 0 {
			w.fired |= bit
			h := mk() // 证据文本只在触发时生成
			h.Result = fwResult(ev)
			hits = append(hits, h)
		}
	}
	nPorts := len(w.ports)
	sev := model.SevMedium
	if nPorts >= highScan {
		sev = model.SevHigh
	}
	fire(bitPortScan, nPorts >= b.th.PortScanPorts, func() model.Hit {
		return model.Hit{RuleID: "bhv-portscan", Name: "端口扫描", Category: CatPortScan,
			Severity: sev, Phase: model.PhaseRecon, Evidence: fmt.Sprintf("%s内探测 %d 个以上不同端口，最近目标 %s", win, nPorts, ev.Target())}
	})
	if s := w.sweep[ev.DstPort]; len(s) >= b.th.HostSweep {
		fire(bitSweep, true, func() model.Hit {
			return model.Hit{RuleID: "bhv-hostsweep", Name: "主机存活/横向扫描", Category: CatHostSweep,
				Severity: model.SevMedium, Phase: model.PhaseRecon, Evidence: fmt.Sprintf("%s内对 %d 台以上主机的 %d 端口发起连接", win, len(s), ev.DstPort)}
		})
	}
	if name, ok := authPorts[ev.DstPort]; ok && w.auth[ev.DstPort] >= b.th.BruteConns {
		fire(bitFwBrute, true, func() model.Hit {
			return model.Hit{RuleID: "bhv-fwbrute", Name: name + "暴力破解", Category: CatBruteForce,
				Severity: model.SevHigh, Phase: model.PhaseCredential, Evidence: fmt.Sprintf("%s内对 %s 端口发起 %d 次连接", win, name, w.auth[ev.DstPort])}
		})
	}
	fire(bitFlood, w.events >= b.th.FloodEvents, func() model.Hit {
		return model.Hit{RuleID: "bhv-flood", Name: "流量洪泛/DoS", Category: CatFlood,
			Severity: model.SevHigh, Phase: model.PhaseImpact, Evidence: fmt.Sprintf("%s内产生 %d 条防火墙事件", win, w.events)}
	})
	return hits
}

func fwResult(ev *model.Event) string {
	switch ev.Action {
	case model.ActionDeny:
		return model.ResultBlocked
	case model.ActionAllow:
		return model.ResultAllowed
	}
	return model.ResultUnknown
}

// Size 返回当前跟踪中的窗口数量（用于运行状态展示）。
func (b *Behavior) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.web) + len(b.fw)
}

func (b *Behavior) prune(now time.Time) {
	b.lastPrune = now
	for ip, w := range b.web {
		if now.Sub(w.start) > 2*b.th.WebWindow || w.start.Sub(now) > 2*b.th.WebWindow {
			delete(b.web, ip)
		}
	}
	for ip, w := range b.fw {
		if now.Sub(w.start) > 2*b.th.FwWindow || w.start.Sub(now) > 2*b.th.FwWindow {
			delete(b.fw, ip)
		}
	}
}

func fmtDur(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d分钟", int(d/time.Minute))
	}
	return fmt.Sprintf("%d秒", int(d/time.Second))
}

// outside 判断事件是否落在窗口之外；允许多数据源之间存在少量乱序。
func outside(t, start time.Time, win time.Duration) bool {
	d := t.Sub(start)
	return d > win || d < -win
}
