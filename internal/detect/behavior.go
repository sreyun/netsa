package detect

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
	"netsa/internal/geo"
	"netsa/internal/model"
)

var reLoginPath = regexp.MustCompile(`(?i)(login|logon|signin|sign-in|sign_in|/auth|wp-login\.php|xmlrpc\.php|j_security_check|j_spring_security_check|/oauth/token|/api/[^?]*token|passport|/session|admin\.php|/user/login|password)`)

// reNotLoginSubmit 是路径里带 auth / password / session 等字样、却不提交口令的辅助接口：口令强度校验（每输入一个字符调用一次）、
// 验证码与是否需要验证码的预检、登录状态 / 会话引导轮询、注销、刷新令牌、获取加密公钥。它们被频繁调用是正常的页面行为。
var reNotLoginSubmit = regexp.MustCompile(`(?i)(strength|captcha|kaptcha|hascode|needcode|codevalidate|bootstrap|/status\b|heartbeat|keepalive|logout|signout|sign-out|refresh|userinfo|public-?key|getkey|rsakey)`)

// loginSubmit 判断请求是否为提交口令的登录请求。
func loginSubmit(method, path string) bool {
	return method == "POST" && reLoginPath.MatchString(path) && !reNotLoginSubmit.MatchString(path)
}

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
	bitVulnScan
)

// 每个 IP 的窗口状态都有容量上限：只需判断是否达到阈值，不必记录全部明细，
// 避免大规模扫描时内存随“来源 IP × 端口 × 主机”增长。
type webWin struct {
	start                   time.Time
	reqs, n404, login, n401 int
	n5xx                    int
	paths                   map[string]struct{}
	loginStatus             map[int]int    // 窗口内登录提交的响应码分布
	loginPaths              map[string]int // 各登录接口的提交次数（疑似成功须出现在被反复提交的同一接口上）
	fired                   int
	scan                    scanSignals // 窗口内命中的攻击特征（判断自动化漏洞扫描）
	// 判断高频请求是不是页面资源加载：静态资源（脚本、样式、图片、字体）的成功请求数，以及请求数过半 CC 阈值后
	// 才开始记录的不同路径（有上限，正常访客不分配）
	static  int
	ccPaths map[string]struct{}
	// 请求数过半阈值后：其中长连接 / 轮询传输（SockJS xhr_send、SSE、WebSocket 降级）的请求数与请求总数
	ccLL, ccSeen int
}

// 高频请求中静态资源占七成以上、且访问了 ccPageLoadPaths 个以上不同路径时，是页面资源加载：
// App 内嵌页面（WebView 不缓存，每次打开都重新加载全部脚本）、出口 NAT 后的多个用户。CC 攻击反复请求少数几个接口，
// 绕过缓存时变的是参数而不是路径。
const ccPageLoadPaths = 20

type fwWin struct {
	start    time.Time
	events   int
	webOK    int // 被放行、目标有应答的 Web 端口连接
	ports    map[int]struct{}
	sweep    map[int]map[string]struct{}
	auth     map[int]int    // 端口 → 同一主机上的最大连接数
	authHost map[string]int // 端口/主机 → 连接数
	fired    int
}

// loginWin 是一个登录接口的全局窗口，用于发现分布式暴力破解（撞库）：每个来源只尝试少量几次，
// 按来源统计达不到阈值，但同一接口在短时间内收到大量来自不同来源的失败登录。
type loginWin struct {
	start   time.Time
	fails   int
	ips     map[string]struct{} // 失败登录的来源（有上限）
	alerted map[string]struct{} // 已告警的来源（每个来源只告警一次）
}

// enumWin 是一个来源的接口遍历窗口：同一接口按 ID 依次请求大量不同对象（越权遍历、批量爬取数据）。
// 接口以哈希为键、ID 以整数保存，统计时不分配字符串；同一接口请求达到 enumLazy 次后才开始记录 ID 集合，
// 正常访客浏览几个带 ID 的页面只占用一个计数。
type enumWin struct {
	start time.Time
	keys  map[uint64]*enumState
}

type enumState struct {
	n      int
	ids    map[uint64]struct{}
	fired  bool
	size   int64 // 首个响应的大小
	varied bool  // 不同 ID 的响应大小是否不同：完全相同说明返回的是同一个页面（单页应用兜底、统一的无权限提示），并没有拿到数据
}

const enumLazy = 20

// beacon 记录内网主机到同一外部地址与端口的连接时间，用于发现按固定间隔回连的 C2 心跳。
type beacon struct {
	times [12]int64 // 最近的连接时间（Unix 秒，环形）
	n     int
	last  int64
	fired bool
	seen  time.Time
}

// Behavior 基于时间窗口识别 CC、目录扫描、暴力破解、端口扫描等行为。
// 窗口以日志自身时间为准，因此同样适用于历史日志的离线分析。
type Behavior struct {
	mu         sync.Mutex
	th         config.Thresholds
	web        map[string]*webWin
	fw         map[string]*fwWin
	logins     map[string]*loginWin   // 登录接口 → 全局窗口
	enum       map[string]*enumWin    // 来源 → 接口遍历窗口
	beacons    map[string]*beacon     // 内网主机>外部地址:端口 → 连接时间
	beaconDst  map[string]int         // 外部地址:端口 → 已告警周期性外连的内网主机数（多台主机同规律外连多为统一部署的软件）
	auth       map[string]*authWin    // 认证来源 → 登录失败窗口
	dns        map[string]*dnsWin     // 内网主机 → DNS 查询窗口
	errs       map[string]*hostErr    // 站点 → 返回 5xx 的不同来源（区分服务故障与攻击）
	slow       map[string]*slowWin    // 来源 → 超时窗口（只为收到过超时的来源建立）
	attacked   map[string]time.Time   // 来源 → 最近一次命中攻击规则的时间
	impact     map[string]*hostImpact // 站点 → 超时统计、业务路径可用性与可疑来源
	sites      map[string]*siteWin    // 站点 → 请求量窗口与基线（分布式 CC）
	homes      map[string]*homeSize   // 站点 → 首页的响应大小（识别对不存在的路径返回首页的兜底页面）
	dsts       map[dstKey]*dstWin     // 目的地址:端口 → 事件量窗口与基线（多源 DDoS）
	devFloods  map[string]devFlood    // 目的地址 → 设备最近报告的洪泛（behavior_devflood.go）
	exfil      map[string]*exfilWin   // 内网主机 → 外发字节窗口与基线（behavior_exfil.go）
	downloads  map[string]*dlWin      // 外部来源 → 下载量窗口
	scripts    map[string]*scriptStat // 站点+脚本路径 → 访问画像（behavior_webshell.go）
	shellSites map[string]*shellSite  // 站点 → 首次出现时间与最近的上传
	// 横向移动（behavior_lateral.go）：被攻击的内网服务器、东西向连接对的首次出现时间、来源的观察期、最近的网络登录
	attackedSrv        map[string]srvMark
	ewSeen, ewSeenPrev map[uint64]int64
	ewSrcs             map[string]*ewSource
	ewPend             map[string][]ewPending
	bw                 map[string]*bwWin       // 目的地址 → 入向流量（带宽型 DDoS）
	accts              map[string]*acctProfile // 账号 → 成功登录的地点（账号盗用）
	// Geo 返回地址的定位（账号盗用检测按地点判断）；为空时不检测。在行为检测的锁内调用，必须只查本地数据
	Geo         func(ip string) *geo.Info
	pendingLate []Late // 需要以其他事件记录的命中（TakeLate 取出）
	logons      map[string]logonMark
	authSince   time.Time
	latest      time.Time // 已处理事件的最新时间（排除未来时间的异常日志），作为窗口过期的基准
	lastPrune   time.Time // 上次清理的系统时间
}

// maxWindows 是同时跟踪的行为窗口上限：大量不同来源（如伪造源地址的扫描）时不再为新来源建窗口，防止内存耗尽。
const maxWindows = 300000

// maxAuthHosts 是单个来源窗口内跟踪的「端口 + 主机」数量上限，伪造大量目标不会占用过多内存。
const maxAuthHosts = 256

func NewBehavior(th config.Thresholds) *Behavior {
	return &Behavior{th: th, web: map[string]*webWin{}, fw: map[string]*fwWin{}, logins: map[string]*loginWin{},
		enum: map[string]*enumWin{}, beacons: map[string]*beacon{}, beaconDst: map[string]int{}, auth: map[string]*authWin{}, dns: map[string]*dnsWin{}, errs: map[string]*hostErr{},
		slow: map[string]*slowWin{}, attacked: map[string]time.Time{}, impact: map[string]*hostImpact{},
		sites: map[string]*siteWin{}, dsts: map[dstKey]*dstWin{}, homes: map[string]*homeSize{},
		exfil: map[string]*exfilWin{}, downloads: map[string]*dlWin{}, scripts: map[string]*scriptStat{}, shellSites: map[string]*shellSite{},
		attackedSrv: map[string]srvMark{}, ewSrcs: map[string]*ewSource{}, ewPend: map[string][]ewPending{}, bw: map[string]*bwWin{}, accts: map[string]*acctProfile{}, logons: map[string]logonMark{}}
}

// Observe 处理一个事件并返回触发的行为告警。
func (b *Behavior) Observe(ev *model.Event) []model.Hit { return b.ObserveHits(ev, nil) }

// ObserveHits 与 Observe 相同，ruleHits 是同一事件命中的攻击规则：用于把攻击之后的写操作与业务受损关联起来。
func (b *Behavior) ObserveHits(ev *model.Event, ruleHits []model.Hit) []model.Hit {
	// 主机进程事件与同一连接的辅助记录（ssl.log、files.log）不是新的连接：不参与连接统计与行为检测
	if ev.Kind == model.KindProcess || ev.Aux {
		return nil
	}
	// 单向流量记录的应答方向：只计入入向带宽（反射放大的流量就是应答）
	if ev.Response {
		if ev.Kind == model.KindFirewall && !isPrivateIP(ev.SrcIP) {
			b.mu.Lock()
			b.observeBandwidth(ev)
			b.mu.Unlock()
		}
		return nil
	}
	// 出站流量（内网主机访问公网）不做扫描 / 洪泛 / 暴力破解判定：正常上网会连接大量不同的公网地址与端口，
	// 按入站攻击的阈值判断会产生大量误报；只检测按固定间隔回连同一地址的 C2 心跳。
	// 内网主机之间的横向扫描（目的为内网地址）仍按入站规则检测。
	if ev.Kind == model.KindAuth || ev.Kind == model.KindDNS {
		var f dnsFacts
		if ev.Kind == model.KindDNS {
			f = dnsFactsOf(ev) // 锁外计算
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		b.maybePrune(ev)
		if ev.Kind == model.KindAuth {
			hits := b.observeAuth(ev)
			hits = append(hits, b.observeTakeover(ev)...)
			if h, ok := b.observeLogonChain(ev); ok {
				hits = append(hits, h)
			}
			return hits
		}
		return b.observeDNS(ev, &f)
	}
	egress := ev.Outbound || IsEgress(ev)
	if egress && ev.Kind != model.KindFirewall {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if ev.Time.After(b.latest) && !ev.Time.After(now.Add(time.Hour)) {
		b.latest = ev.Time
	}
	// 按系统时间定期清理：若按日志时间调度，一条未来时间的异常日志会使清理长期不再执行
	if now.Sub(b.lastPrune) > 30*time.Second || len(b.web)+len(b.fw) >= maxWindows || len(b.beacons) >= 200000 {
		b.prune(b.latest)
		b.lastPrune = now
	}
	if ev.Kind == model.KindFirewall {
		b.noteDeviceFlood(ev, ruleHits)
	}
	b.noteAttackTargets(ev, ruleHits)
	if ev.SrcIP == "" { // 设备只记录了目的地址的多源洪泛：没有来源可统计，只用于印证
		return nil
	}
	if egress {
		hits := b.observeBeacon(ev)
		if h, ok := b.observeExfil(ev); ok {
			hits = append(hits, h)
		}
		return hits
	}
	if ev.Kind == model.KindWeb {
		var sig scanSignals
		for _, h := range ruleHits {
			sig.attacked = sig.attacked || h.Severity >= model.SevMedium
			sig.add(&h)
		}
		hits := b.observeWeb(ev, sig)
		if h, ok := b.observeDownload(ev); ok {
			hits = append(hits, h)
		}
		if h, ok := b.observeWebShell(ev); ok {
			hits = append(hits, h)
		}
		return hits
	}
	if ev.Kind == model.KindFirewall {
		b.observeBandwidth(ev) // 入向流量：带宽型 DDoS
	}
	if isPrivateIP(ev.SrcIP) && isPrivateIP(ev.DstIP) { // 东西向：内网主机之间的远程管理连接
		return append(b.observeEastWest(ev), b.observeFw(ev)...)
	}
	return b.observeFw(ev)
}

func (b *Behavior) observeWeb(ev *model.Event, sig scanSignals) []model.Hit {
	attacked := sig.attacked
	w := b.web[ev.SrcIP]
	if w == nil && len(b.web)+len(b.fw) >= maxWindows {
		return nil
	}
	if w == nil || outside(ev.Time, w.start, b.th.WebWindow) {
		w = &webWin{start: ev.Time}
		b.web[ev.SrcIP] = w
	}
	w.reqs++
	path := ev.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	host := ev.Host
	if host == "" {
		host = "-"
	}
	// 对不存在的路径返回首页（200）的站点（单页应用、统一兜底页），与首页大小相同的 200 等同于 404
	miss := ev.Status == 404 || b.softMiss(ev, host, path)
	switch {
	case miss:
		w.n404++
	case ev.Status == 401:
		// 只统计登录提交与 HTTP Basic 认证（日志记录了 $remote_user）的 401：App、单页应用带着过期令牌
		// 启动或轮询时，十几个业务接口（含 GET /auth/bootstrap 这类会话引导接口）会同时返回 401，那是会话过期，不是暴力破解
		if ev.User != "" || loginSubmit(ev.Method, path) {
			w.n401++
		}
	case ev.Status >= 500:
		w.n5xx++
		b.noteErr(ev)
	}
	if !miss && ev.Status < 400 && StaticAsset(path) {
		w.static++
	}
	if w.reqs*2 >= b.th.CCRequests && w.fired&bitCC == 0 {
		w.ccSeen++
		if LongLivedURI(ev.URI) {
			w.ccLL++
		}
	}
	if w.reqs*2 >= b.th.CCRequests && w.fired&bitCC == 0 && len(w.ccPaths) < ccPageLoadPaths {
		if w.ccPaths == nil {
			w.ccPaths = make(map[string]struct{}, ccPageLoadPaths)
		}
		w.ccPaths[path] = struct{}{}
	}
	// 只在出现 404（或兜底页面）时记录路径：正常访客不分配集合，扫描器的集合达到阈值后不再增长
	if miss && len(w.paths) < b.th.ScanPaths {
		if w.paths == nil {
			w.paths = map[string]struct{}{}
		}
		w.paths[path] = struct{}{}
	}
	isLogin := loginSubmit(ev.Method, path)
	// 判断“疑似破解成功”需要基于本次之前的响应码分布
	bruteOK := false
	if isLogin {
		bruteOK = w.fired&bitBrute != 0 && w.loginPaths[path] >= 3 && looksLikeLoginSuccess(w.loginStatus, ev.Status)
		if w.loginPaths == nil {
			w.loginPaths = map[string]int{}
		}
		if _, ok := w.loginPaths[path]; ok || len(w.loginPaths) < 8 {
			w.loginPaths[path]++
		}
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
		h := model.Hit{RuleID: "bhv-cc", Name: "CC攻击/高频请求", Category: CatCC,
			Severity: model.SevHigh, Phase: model.PhaseImpact, Evidence: fmt.Sprintf("%s内请求 %d 次", win, w.reqs)}
		switch {
		case isPrivateIP(ev.SrcIP):
			// 内部来源的高频请求多是没有还原真实地址的反向代理、负载均衡健康检查、监控或内部扫描器：
			// 照常提示，但只是弱证据（低危，不按分类底线抬升）
			h.Severity, h.Weak = model.SevLow, true
			h.Evidence += "；来源是内网地址，多为反向代理（未还原真实客户端地址）、监控或内部扫描器"
		case w.ccSeen > 0 && w.ccLL*10 >= w.ccSeen*7:
			h.Severity, h.Weak = model.SevLow, true
			h.Evidence += fmt.Sprintf("；其中 %d%% 是长连接 / 轮询传输（SockJS、SSE、WebSocket 降级）的消息请求，是页面的实时通道，不是 CC 攻击", w.ccLL*100/w.ccSeen)
		case w.static*10 >= w.reqs*7 && len(w.ccPaths) >= ccPageLoadPaths:
			h.Severity, h.Weak = model.SevLow, true
			h.Evidence += fmt.Sprintf("；其中静态资源（脚本、样式、图片）占 %d%%，访问了 %d 个以上不同路径，是页面资源加载"+
				"（App 内嵌页面不缓存、或出口 NAT 后的多个用户），不像反复请求少数接口的 CC 攻击", w.static*100/w.reqs, len(w.ccPaths))
		}
		return h
	})
	fire(bitScan, w.n404 >= b.th.Scan404 && len(w.paths) >= b.th.ScanPaths, func() model.Hit {
		return model.Hit{RuleID: "bhv-dirscan", Name: "目录/文件枚举扫描", Category: CatDirScan,
			Severity: model.SevMedium, Phase: model.PhaseRecon, Evidence: fmt.Sprintf("%s内 404（或与首页相同的兜底页面）响应 %d 次，访问 %d 个以上不同路径", win, w.n404, len(w.paths))}
	})
	w.scan.merge(sig)
	fire(bitVulnScan, w.scan.scanning(), func() model.Hit {
		return w.scan.hit(win, w.n404)
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
	fire(bit5xx, w.n5xx >= b.th.Server5xx && !b.outage(ev.Host), func() model.Hit {
		return model.Hit{RuleID: "bhv-5xx", Name: "异常请求引发大量服务端错误", Category: CatProtocol,
			Severity: model.SevMedium, Phase: model.PhaseExploit, Evidence: fmt.Sprintf("%s内 5xx 响应 %d 次", win, w.n5xx)}
	})
	if isLogin {
		if h, ok := b.distBrute(ev, path); ok {
			hits = append(hits, h)
		}
	}
	if ev.Status >= 200 && ev.Status < 300 && (ev.Method == "GET" || ev.Method == "POST") {
		if h, ok := b.enumerate(ev); ok {
			hits = append(hits, h)
		}
	}
	if h, ok := b.observeSite(ev, path); ok {
		hits = append(hits, h)
	}
	return append(hits, b.observeImpact(ev, path, attacked)...)
}

// distBrute 检测分布式暴力破解（撞库）：同一登录接口在窗口内收到大量来自不同来源的失败登录（401 / 403 / 429）。
// 达到阈值后，继续参与的每个来源各告警一次。
func (b *Behavior) distBrute(ev *model.Event, path string) (model.Hit, bool) {
	key := ev.Host + " " + path
	lw := b.logins[key]
	if lw == nil || outside(ev.Time, lw.start, b.th.DistWindow) {
		if lw == nil && len(b.logins) >= 5000 {
			return model.Hit{}, false
		}
		lw = &loginWin{start: ev.Time, ips: map[string]struct{}{}, alerted: map[string]struct{}{}}
		b.logins[key] = lw
	}
	if ev.Status != 401 && ev.Status != 403 && ev.Status != 429 {
		return model.Hit{}, false
	}
	lw.fails++
	if len(lw.ips) < 20000 {
		lw.ips[ev.SrcIP] = struct{}{}
	}
	if lw.fails < b.th.DistBruteLogins || len(lw.ips) < b.th.DistBruteIPs {
		return model.Hit{}, false
	}
	if _, done := lw.alerted[ev.SrcIP]; done || len(lw.alerted) >= 20000 {
		return model.Hit{}, false
	}
	lw.alerted[ev.SrcIP] = struct{}{}
	return model.Hit{RuleID: "bhv-distbrute", Name: "分布式暴力破解/撞库", Category: CatBruteForce, Severity: model.SevHigh,
		Phase: model.PhaseCredential, Result: model.ResultFailed,
		Evidence: fmt.Sprintf("%s内 %d 个来源对 %s 失败登录 %d 次（单个来源次数少，疑似僵尸网络撞库）", fmtDur(b.th.DistWindow), len(lw.ips), Printable(path, 80), lw.fails)}, true
}

// 搜索引擎爬虫按 ID 抓取页面属于正常行为，不作为接口遍历告警（可伪造的 UA 仍会被其他规则检测）
var reSearchBot = regexp.MustCompile(`(?i)googlebot|bingbot|baiduspider|yandexbot|sogou|360spider|bytespider|yisouspider|applebot|duckduckbot`)

// 涉及个人信息、订单、账户的接口被遍历时风险更高
var reSensitiveAPI = regexp.MustCompile(`(?i)user|member|account|customer|order|invoice|profile|address|phone|mobile|card|admin|employee|patient|student|contract`)

// enumParts 找出接口遍历统计用的对象 ID：路径中第一个纯数字段，或名称像 ID 的纯数字查询参数。
// 返回 ID 前后的文本（接口键为 prefix + "{id}" + suffix），不分配内存。
func enumParts(uri string) (prefix, suffix, id string, ok bool) {
	path, query := uri, ""
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		path, query = uri[:i], uri[i+1:]
	}
	for start := 0; start < len(path); {
		end := strings.IndexByte(path[start:], '/')
		if end < 0 {
			end = len(path)
		} else {
			end += start
		}
		if seg := path[start:end]; seg != "" && len(seg) <= 18 && allDigits(seg) {
			return path[:start], path[end:], seg, true
		}
		start = end + 1
	}
	for query != "" {
		kv := query
		if i := strings.IndexByte(query, '&'); i >= 0 {
			kv, query = query[:i], query[i+1:]
		} else {
			query = ""
		}
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			if k, v := kv[:eq], kv[eq+1:]; v != "" && len(v) <= 18 && allDigits(v) && isIDParam(k) {
				return path + "?" + k + "=", "", v, true // 仅在命中时拼接（查询参数形式较少见）
			}
		}
	}
	return "", "", "", false
}

// enumKey 返回接口键与对象 ID（用于测试与告警证据）。
func enumKey(uri string) (key, id string) {
	p, s, id, ok := enumParts(uri)
	if !ok {
		return "", ""
	}
	if strings.HasSuffix(p, "=") {
		return p + "{id}", id
	}
	return p + "{id}" + s, id
}

// isIDParam 判断查询参数名是否表示对象 ID（id、uid、user_id、orderNo、item_code 等）；搜索词、页码等数字参数不计入。
func isIDParam(k string) bool {
	if len(k) == 0 || len(k) > 32 {
		return false
	}
	for i := 0; i < len(k); i++ {
		if c := k[i] | 0x20; (c < 'a' || c > 'z') && k[i] != '_' {
			return false
		}
	}
	for _, suf := range [...]string{"id", "no", "num", "number", "code"} {
		if len(k) >= len(suf) && strings.EqualFold(k[len(k)-len(suf):], suf) {
			return true
		}
	}
	return false
}

// fnvStr 计算字符串的 FNV-1a 哈希（不分配内存），可分段累计。
func fnvStr(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

const fnvOffset = 14695981039346656037

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// enumerate 检测接口遍历 / 批量爬取：同一来源在窗口内对同一接口请求了大量不同的对象 ID 且返回成功。
func (b *Behavior) enumerate(ev *model.Event) (model.Hit, bool) {
	prefix, suffix, id, ok := enumParts(ev.URI)
	if !ok {
		return model.Hit{}, false
	}
	ew := b.enum[ev.SrcIP]
	if ew == nil || outside(ev.Time, ew.start, b.th.EnumWindow) {
		if ew == nil && len(b.enum) >= maxWindows/4 {
			return model.Hit{}, false
		}
		ew = &enumWin{start: ev.Time, keys: map[uint64]*enumState{}}
		b.enum[ev.SrcIP] = ew
	}
	k := fnvStr(fnvStr(fnvStr(fnvOffset, prefix), "{id}"), suffix)
	st := ew.keys[k]
	if st == nil {
		if len(ew.keys) >= 32 {
			return model.Hit{}, false
		}
		st = &enumState{}
		ew.keys[k] = st
	}
	st.n++
	if st.n == 1 {
		st.size = ev.Bytes
	} else if ev.Bytes != st.size {
		st.varied = true
	}
	if st.fired || st.n < enumLazy {
		return model.Hit{}, false
	}
	if st.ids == nil {
		st.ids = map[uint64]struct{}{}
	}
	if len(st.ids) < b.th.EnumIDs {
		n, _ := strconv.ParseUint(id, 10, 64)
		st.ids[n] = struct{}{}
	}
	// 前 enumLazy 次请求未记录 ID，阈值相应扣除
	if len(st.ids)+enumLazy-1 < b.th.EnumIDs {
		return model.Hit{}, false
	}
	st.fired = true
	if reSearchBot.MatchString(ev.UA) { // 搜索引擎爬虫只在即将告警时判断，避免每个请求都执行正则
		return model.Hit{}, false
	}
	if !st.varied && st.size > 0 { // 所有 ID 返回的响应大小完全相同：同一个兜底页面 / 无权限提示，并没有取到数据
		return model.Hit{}, false
	}
	key, _ := enumKey(ev.URI)
	set := st.ids
	sev := model.SevMedium
	if reSensitiveAPI.MatchString(key) {
		sev = model.SevHigh
	}
	return model.Hit{RuleID: "bhv-enum", Name: "接口遍历/批量爬取", Category: CatCrawl, Severity: sev, Phase: model.PhaseCollection,
		Result:   model.ResultPassed,
		Evidence: fmt.Sprintf("%s内对 %s 请求了 %d 个以上不同 ID 并成功返回（疑似越权遍历或批量爬取数据）", fmtDur(b.th.EnumWindow), Printable(key, 100), len(set)+enumLazy-1)}, true
}

// approxDur 把秒数格式化为“约 N 秒 / N.N 分钟”。
func approxDur(sec float64) string {
	if sec >= 120 {
		return fmt.Sprintf("%.1f 分钟", sec/60)
	}
	return fmt.Sprintf("%.0f 秒", sec)
}

// observeBeacon 检测内网主机按固定间隔连接同一外部地址（C2 心跳）：最近的连接间隔稳定（波动不超过 12%），
// 平均间隔在 1 分钟到 1 小时之间。DNS、NTP 等天然周期性的服务不检测。
func (b *Behavior) observeBeacon(ev *model.Event) []model.Hit {
	if ev.DstIP == "" || ev.DstPort == 53 || ev.DstPort == 123 || ev.DstPort == 853 {
		return nil
	}
	key := ev.SrcIP + ">" + ev.DstIP + ":" + strconv.Itoa(ev.DstPort)
	bc := b.beacons[key]
	if bc == nil {
		if len(b.beacons) >= 200000 {
			return nil
		}
		bc = &beacon{}
		b.beacons[key] = bc
	}
	t := ev.Time.Unix()
	if bc.n > 0 && t-bc.last < 5 { // 同一会话的多条连接日志、或乱序日志
		return nil
	}
	bc.times[bc.n%len(bc.times)] = t
	bc.n++
	bc.last, bc.seen = t, ev.Time
	if bc.fired || bc.n < b.th.BeaconConns {
		return nil
	}
	k := min(bc.n, len(bc.times))
	ts := make([]int64, 0, k)
	for i := bc.n - k; i < bc.n; i++ {
		ts = append(ts, bc.times[i%len(bc.times)])
	}
	var sum, sq float64
	for i := 1; i < len(ts); i++ {
		d := float64(ts[i] - ts[i-1])
		sum += d
		sq += d * d
	}
	cnt := float64(len(ts) - 1)
	mean := sum / cnt
	std := math.Sqrt(math.Max(0, sq/cnt-mean*mean))
	if mean < 60 || mean > 3600 || std/mean > 0.12 {
		return nil
	}
	bc.fired = true
	h := model.Hit{RuleID: "bhv-beacon", Name: "周期性外连（疑似C2心跳）", Category: CatBeacon, Severity: model.SevMedium,
		Phase: model.PhasePersistence, Result: fwResult(ev),
		Evidence: fmt.Sprintf("%s 每隔约 %s 连接 %s:%d（截至本次共 %d 次连接，间隔波动 %.0f%%；同一对地址只告警一次）", ev.SrcIP, approxDur(mean), ev.DstIP, ev.DstPort, bc.n, 100*std/mean)}
	dst := ev.DstIP + ":" + strconv.Itoa(ev.DstPort)
	peers := b.beaconDst[dst]
	if _, ok := b.beaconDst[dst]; ok || len(b.beaconDst) < 100000 {
		b.beaconDst[dst] = peers + 1
	}
	switch {
	case strings.EqualFold(ev.Proto, "icmp"):
		// 定时 ping 外部地址多是链路 / 可用性监控；ICMP 隧道不会这样等间隔地只发探测包
		h.Name, h.Severity = "周期性ICMP探测（多为链路监控）", model.SevLow
	case peers >= 2:
		h.Severity = model.SevLow
		h.Evidence += fmt.Sprintf("；已有 %d 台内网主机以同样的规律连接该地址，多为统一部署的客户端、监控或更新代理", peers)
	}
	return []model.Hit{h}
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
	if w == nil && len(b.web)+len(b.fw) >= maxWindows {
		return nil
	}
	if w == nil || outside(ev.Time, w.start, b.th.FwWindow) {
		w = &fwWin{start: ev.Time}
		b.fw[ev.SrcIP] = w
	}
	w.events++
	internal := InternalSource(ev)
	if ev.Action == model.ActionAllow && ev.Reply == model.ReplyYes && webPort(ev.DstPort) {
		w.webOK++
	}
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
		// 内部来源被策略放行的连接是业务访问（应用服务器的连接池、定时任务连数据库），连接次数不能说明暴力破解；
		// 只统计被拒绝的。外部来源的放行连接照常统计
		if _, ok := authPorts[ev.DstPort]; ok && !(internal && ev.Action == model.ActionAllow) {
			if w.auth == nil {
				w.auth, w.authHost = map[int]int{}, map[string]int{}
			}
			// 按「同一主机的同一端口」计数：暴力破解是对一个服务反复尝试；对大量主机各连几次是横向扫描，
			// 由 bhv-hostsweep 判断。累加到端口上会把互联网背景扫描误判为暴力破解
			key := strconv.Itoa(ev.DstPort) + "/" + ev.DstIP
			if _, seen := w.authHost[key]; seen || len(w.authHost) < maxAuthHosts {
				w.authHost[key]++
				w.auth[ev.DstPort] = max(w.auth[ev.DstPort], w.authHost[key])
			}
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
	// 来自互联网的扫描是常态，低一级：只有内网来源的扫描才是需要优先处理的横向移动信号
	external := !internal
	sev, sweepSev := model.SevMedium, model.SevMedium
	if nPorts >= highScan {
		sev = model.SevHigh
	}
	if external {
		sev--
		sweepSev = model.SevLow
	}
	fire(bitPortScan, nPorts >= b.th.PortScanPorts, func() model.Hit {
		return model.Hit{RuleID: "bhv-portscan", Name: "端口扫描", Category: CatPortScan,
			Severity: sev, Phase: model.PhaseRecon, Evidence: fmt.Sprintf("%s内探测 %d 个以上不同端口，最近目标 %s", win, nPorts, ev.Target())}
	})
	if s := w.sweep[ev.DstPort]; len(s) >= b.th.HostSweep {
		fire(bitSweep, true, func() model.Hit {
			return model.Hit{RuleID: "bhv-hostsweep", Name: "主机存活/横向扫描", Category: CatHostSweep,
				Severity: sweepSev, Phase: model.PhaseRecon, Evidence: fmt.Sprintf("%s内对 %d 台以上主机的 %d 端口发起连接", win, len(s), ev.DstPort)}
		})
	}
	if name, ok := authPorts[ev.DstPort]; ok && w.auth[ev.DstPort] >= b.th.BruteConns {
		fire(bitFwBrute, true, func() model.Hit {
			return model.Hit{RuleID: "bhv-fwbrute", Name: name + "暴力破解", Category: CatBruteForce,
				Severity: model.SevMedium, Phase: model.PhaseCredential, Evidence: fmt.Sprintf("%s内对同一主机的 %s 端口发起 %d 次连接（防火墙日志只能看到连接次数，看不到认证结果）", win, name, w.auth[ev.DstPort])}
		})
	}
	// 事件多但分散在大量端口 / 主机上的是高速扫描（已由端口扫描、主机扫描告警），不是洪泛：
	// 互联网扫描源（如 79.124.58.130）5 分钟内对上百个地址的随机端口各连一次，曾被判为高危的“流量洪泛/DoS”
	// 内部来源的连接多是业务本身：反向代理、负载均衡回源、监控探活、内部漏洞扫描器打出的成千上万个会话，
	// 判为“流量洪泛/DoS”会让这些主机在资产攻击链路里出现“横向 / 影响”。内部主机对外的异常流量由外发流量突增判断
	// 九成以上是被放行、服务端正常应答的 Web 连接，或打向 Web 端口、而该来源同时出现在 Web 日志中（策略匹配日志没有应答信息）：
	// 页面开着时不断重连的长连接、NAT 后面的大量用户都会这样，这些连接是不是攻击由 Web 日志的 CC 检测判断（防火墙只看得到连接数）
	if w.events >= b.th.FloodEvents && w.fired&bitFlood == 0 && (internal || b.scanLike(w) || w.webOK*10 >= w.events*9 || webPort(ev.DstPort) && b.recentWeb(ev.SrcIP, ev.Time)) {
		w.fired |= bitFlood // 扫描窗口、内部来源或正常的 Web 连接：不判为洪泛，之后的事件也不再重复判断
	}
	fire(bitFlood, w.events >= b.th.FloodEvents, func() model.Hit {
		return model.Hit{RuleID: "bhv-flood", Name: "流量洪泛/DoS", Category: CatFlood,
			Severity: model.SevHigh, Phase: model.PhaseImpact, Evidence: fmt.Sprintf("%s内产生 %d 条防火墙事件", win, w.events)}
	})
	if h, ok := b.observeDst(ev, internal); ok {
		hits = append(hits, h)
	}
	return hits
}

// scanLike 判断窗口内的连接是否分散在大量端口或主机上（扫描），而不是集中打向少数目标。
func (b *Behavior) scanLike(w *fwWin) bool {
	if len(w.ports) >= b.th.PortScanPorts {
		return true
	}
	hosts := map[string]struct{}{}
	for _, s := range w.sweep {
		if len(s) >= b.th.HostSweep {
			return true
		}
		for h := range s {
			if hosts[h] = struct{}{}; len(hosts) >= b.th.HostSweep {
				return true
			}
		}
	}
	return false
}

func fwResult(ev *model.Event) string {
	switch {
	case ev.Action == model.ActionDeny:
		return model.ResultBlocked
	case ev.Action == model.ActionAllow && ev.Reply == model.ReplyNone:
		return model.ResultFailed // 会话结束时对端没有应答：连接未建立
	case ev.Action == model.ActionAllow:
		return model.ResultAllowed
	}
	return model.ResultUnknown
}

// SweepHosts 返回来源在当前窗口内探测同一端口的不同主机数（达到 host_sweep 后不再增长）。
func (b *Behavior) SweepHosts(src string, port int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if w := b.fw[src]; w != nil {
		return len(w.sweep[port])
	}
	return 0
}

// Size 返回当前跟踪中的窗口数量（用于运行状态展示）。
func (b *Behavior) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.web) + len(b.fw)
}

func (b *Behavior) prune(now time.Time) {
	b.pruneSurge(now)
	b.pruneDevFloods(now)
	b.pruneExfil(now)
	b.pruneLateral(now)
	b.pruneBandwidth(now)
	b.pruneAccounts(now)
	for k, w := range b.logins {
		if now.Sub(w.start) > 2*b.th.DistWindow || w.start.Sub(now) > 2*b.th.DistWindow {
			delete(b.logins, k)
		}
	}
	for k, w := range b.enum {
		if now.Sub(w.start) > 2*b.th.EnumWindow || w.start.Sub(now) > 2*b.th.EnumWindow {
			delete(b.enum, k)
		}
	}
	for k, bc := range b.beacons {
		if d := now.Sub(bc.seen); d > 3*time.Hour || d < -3*time.Hour {
			delete(b.beacons, k)
		}
	}
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
	for ip, w := range b.auth {
		if outside(now, w.start, 2*b.th.FwWindow) {
			delete(b.auth, ip)
		}
	}
	for ip, w := range b.dns {
		if outside(now, w.start, 2*b.th.FwWindow) {
			delete(b.dns, ip)
		}
	}
	for h, e := range b.errs {
		if outside(now, e.start, 2*b.th.WebWindow) {
			delete(b.errs, h)
		}
	}
	b.pruneImpact(now)
}

// fmtDur 把统计窗口格式化为“5分钟”“30秒”。窗口来自配置、只有少数几个取值，结果缓存起来：
// 行为检测每条日志都要准备一次窗口文字（防火墙日志处理中曾占约 1%）。
func fmtDur(d time.Duration) string {
	if v, ok := durText.Load(d); ok {
		return v.(string)
	}
	s := fmt.Sprintf("%d秒", int(d/time.Second))
	if d%time.Minute == 0 {
		s = fmt.Sprintf("%d分钟", int(d/time.Minute))
	}
	durText.Store(d, s)
	return s
}

var durText sync.Map // time.Duration → 文字

// outside 判断事件是否落在窗口之外；允许多数据源之间存在少量乱序。
func outside(t, start time.Time, win time.Duration) bool {
	d := t.Sub(start)
	return d > win || d < -win
}

// hostErr 是一个站点在窗口内收到 5xx 响应的不同来源。
type hostErr struct {
	start time.Time
	ips   map[string]struct{}
}

// outageSources 是同一站点在窗口内收到 5xx 的不同来源数阈值：达到即视为服务故障（后端宕机、发布、过载），
// 此时某个来源收到大量 5xx 只是正常访问碰上故障，不判定为「异常请求引发服务端错误」。
const outageSources = 10

func (b *Behavior) noteErr(ev *model.Event) {
	e := b.errs[ev.Host]
	if e == nil || outside(ev.Time, e.start, b.th.WebWindow) {
		if e == nil && len(b.errs) >= 5000 {
			return
		}
		e = &hostErr{start: ev.Time, ips: map[string]struct{}{}}
		b.errs[ev.Host] = e
	}
	if len(e.ips) < outageSources {
		e.ips[ev.SrcIP] = struct{}{}
	}
}

func (b *Behavior) outage(host string) bool {
	e := b.errs[host]
	return e != nil && len(e.ips) >= outageSources
}

// webPort 判断是否为常见的 Web 服务端口。
func webPort(p int) bool {
	switch p {
	case 80, 443, 8080, 8443, 8000, 8888:
		return true
	}
	return false
}

// recentWeb 判断来源在防火墙统计窗口内是否也出现在 Web 日志中（调用方持锁）。
func (b *Behavior) recentWeb(ip string, t time.Time) bool {
	w := b.web[ip]
	return w != nil && !outside(t, w.start, b.th.FwWindow)
}
