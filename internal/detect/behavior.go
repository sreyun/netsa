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
	n     int
	ids   map[uint64]struct{}
	fired bool
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
	mu        sync.Mutex
	th        config.Thresholds
	web       map[string]*webWin
	fw        map[string]*fwWin
	logins    map[string]*loginWin // 登录接口 → 全局窗口
	enum      map[string]*enumWin  // 来源 → 接口遍历窗口
	beacons   map[string]*beacon   // 内网主机>外部地址:端口 → 连接时间
	latest    time.Time            // 已处理事件的最新时间（排除未来时间的异常日志），作为窗口过期的基准
	lastPrune time.Time            // 上次清理的系统时间
}

// maxWindows 是同时跟踪的行为窗口上限：大量不同来源（如伪造源地址的扫描）时不再为新来源建窗口，防止内存耗尽。
const maxWindows = 300000

func NewBehavior(th config.Thresholds) *Behavior {
	return &Behavior{th: th, web: map[string]*webWin{}, fw: map[string]*fwWin{}, logins: map[string]*loginWin{},
		enum: map[string]*enumWin{}, beacons: map[string]*beacon{}}
}

// Observe 处理一个事件并返回触发的行为告警。
func (b *Behavior) Observe(ev *model.Event) []model.Hit {
	// 出站流量（内网主机访问公网）不做扫描 / 洪泛 / 暴力破解判定：正常上网会连接大量不同的公网地址与端口，
	// 按入站攻击的阈值判断会产生大量误报；只检测按固定间隔回连同一地址的 C2 心跳。
	// 内网主机之间的横向扫描（目的为内网地址）仍按入站规则检测。
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
	if egress {
		return b.observeBeacon(ev)
	}
	if ev.Kind == model.KindWeb {
		return b.observeWeb(ev)
	}
	return b.observeFw(ev)
}

func (b *Behavior) observeWeb(ev *model.Event) []model.Hit {
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
	return hits
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
	return []model.Hit{{RuleID: "bhv-beacon", Name: "周期性外连（疑似C2心跳）", Category: CatBeacon, Severity: model.SevMedium,
		Phase: model.PhasePersistence, Result: fwResult(ev),
		Evidence: fmt.Sprintf("%s 每隔约 %s 连接 %s:%d（连续 %d 次，间隔波动 %.0f%%）", ev.SrcIP, approxDur(mean), ev.DstIP, ev.DstPort, bc.n, 100*std/mean)}}
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
