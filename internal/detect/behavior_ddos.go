package detect

import (
	"fmt"
	"time"

	"netsa/internal/model"
)

// 本文件检测两类多来源的资源消耗攻击，单个来源都低于 cc_requests / flood_events，按来源统计发现不了：
//
//   - 分布式 CC（bhv-distcc）：按站点汇总，一个 web_window 内的请求量比平时暴增，且大量来源反复请求同一路径。
//     正常的访问高峰（上班打卡、活动开始）访客会请求各种页面和接口，不会每个来源都集中刷同一个路径，
//     所以除了总量突增，还要求“集中刷同一路径”的来源达到 dist_cc_ips 个。
//   - 多源 DDoS（bhv-ddos）：按防火墙日志的目的地址与端口汇总，一个 fw_window 内的事件量比平时暴增，且来自大量不同来源。
//     繁忙的对外服务平时就有大量来源，因此按该目的地址自己的基线判断突增，而不是只看固定的来源数。
//
// 基线是每个窗口请求 / 事件量的指数滑动平均，突增窗口不计入：攻击持续多久都按平时的水平比较；
// 业务量缓慢上升（每分钟增长几个百分点）时基线跟得上，几分钟内暴增数倍的才算突增。

const (
	surgeFactor   = 5   // 窗口内的量达到平时的倍数
	surgeAlpha    = 0.1 // 基线的平滑系数
	surgeMature   = 10  // 基线至少积累的窗口数
	maxSurgeSites = 2000
	maxSiteSrcs   = 20000
	maxSitePaths  = 512
	maxDDoSDsts   = 5000
	maxDDoSSrcs   = 20000
	maxSurgeFlags = 500 // 一次分布式 CC 最多告警的来源数（集中刷接口的来源都是需要封禁的肉鸡）
	maxDDoSFlags  = 50  // 一次 DDoS 最多告警的来源数：伪造源地址时逐个来源告警意义不大，只告警最先达到 10 条事件的参与者
	surgeRecheck  = 256 // 达到阈值后每隔多少条重新判断一次（判断需要遍历来源）
)

// surgeBase 是按窗口统计的量与平时水平（基线）。
type surgeBase struct {
	start   time.Time
	n       int     // 当前窗口的量
	base    float64 // 平时每个窗口的量（不含突增窗口）
	windows int     // 已计入基线的窗口数
	surge   bool    // 当前窗口已判定为突增
	checked int     // 上次判断时的量
	flagged int     // 当前突增已告警的来源数
}

// roll 在事件时间超出当前窗口时结算：非突增窗口计入基线，中间没有任何请求的窗口按 0 计入。返回是否开始了新窗口。
func (s *surgeBase) roll(t time.Time, win time.Duration) bool {
	if s.start.IsZero() {
		s.start = t
		return true
	}
	d := t.Sub(s.start)
	if d >= 0 && d < win {
		return false
	}
	if d < 0 {
		if -d < win {
			return false // 窗口内的乱序日志
		}
		s.start = t // 时间倒退较多（回放历史日志）：重新开始，不计入基线
		s.n, s.surge, s.checked, s.flagged = 0, false, 0, 0
		return true
	}
	if !s.surge {
		if s.windows == 0 {
			s.base = float64(s.n)
		} else {
			s.base = surgeAlpha*float64(s.n) + (1-surgeAlpha)*s.base
		}
		s.windows++
	}
	if idle := min(int(d/win)-1, 60); idle > 0 { // 空闲的窗口
		for range idle {
			s.base *= 1 - surgeAlpha
		}
		s.windows += idle
	}
	s.start = s.start.Add(d / win * win)
	s.n, s.surge, s.checked, s.flagged = 0, false, 0, 0
	return true
}

// need 返回判定突增需要达到的量：基线成熟后取绝对阈值与平时的 surgeFactor 倍中较大的；
// 基线还不成熟（刚启动、新站点）时没有参照，只按 immature 倍的绝对阈值判断。
func (s *surgeBase) need(abs, immature int) int {
	if s.windows < surgeMature {
		return abs * immature
	}
	return max(abs, int(s.base*surgeFactor))
}

// ---------------- 分布式 CC ----------------

type ccSrc struct {
	n     int    // 窗口内的请求数
	cand  string // 请求最多的路径（多数投票，不必记录每个路径的次数）
	vote  int
	fired bool
}

// concentrated 判断来源是否在集中刷同一路径：窗口内请求达到 perIP 次，且多数投票的净票数超过 60%（即该路径占 80% 以上）。
func (c *ccSrc) concentrated(path string, perIP int) bool {
	return c.n >= perIP && c.cand == path && c.vote*5 >= c.n*3
}

type siteWin struct {
	surgeBase
	srcs  map[string]*ccSrc
	paths map[string]int
	hot   string // 突增集中的路径
	conc  int    // 判定时集中刷该路径的来源数
}

func (b *Behavior) observeSite(ev *model.Event, path string) (model.Hit, bool) {
	host := ev.Host
	if host == "" {
		host = "-"
	}
	s := b.sites[host]
	if s == nil {
		if len(b.sites) >= maxSurgeSites {
			return model.Hit{}, false
		}
		s = &siteWin{srcs: map[string]*ccSrc{}, paths: map[string]int{}}
		b.sites[host] = s
	}
	if s.roll(ev.Time, b.th.WebWindow) {
		clear(s.srcs)
		clear(s.paths)
		s.hot, s.conc = "", 0
	}
	s.n++
	src := s.srcs[ev.SrcIP]
	if src == nil && len(s.srcs) < maxSiteSrcs {
		src = &ccSrc{}
		s.srcs[ev.SrcIP] = src
	}
	if src != nil {
		src.n++
		switch {
		case src.vote == 0:
			src.cand, src.vote = path, 1
		case src.cand == path:
			src.vote++
		default:
			src.vote--
		}
	}
	if c, ok := s.paths[path]; ok || len(s.paths) < maxSitePaths {
		s.paths[path] = c + 1
	}
	if !s.surge {
		if s.n < s.need(b.th.DistCCRequests, 2) || s.n-s.checked < surgeRecheck && s.checked > 0 {
			return model.Hit{}, false
		}
		s.checked = s.n
		if !b.siteSurge(s) {
			return model.Hit{}, false
		}
		s.surge = true
	}
	if src == nil || src.fired || s.flagged >= maxSurgeFlags || !src.concentrated(s.hot, b.th.DistCCIPRequests) {
		return model.Hit{}, false
	}
	src.fired = true
	s.flagged++
	base := "平时没有足够的访问记录"
	if s.windows >= surgeMature {
		base = fmt.Sprintf("平时约 %.0f 次", s.base)
	}
	return model.Hit{RuleID: "bhv-distcc", Name: "分布式CC攻击", Category: CatCC, Severity: model.SevHigh, Phase: model.PhaseImpact,
		Result: model.ResultUnknown,
		Evidence: fmt.Sprintf("%s内站点 %s 收到 %d 次请求（%s），%d 个以上来源集中请求 %s（占 %d%%）；该来源请求 %d 次，几乎都是这个路径",
			fmtDur(b.th.WebWindow), Printable(host, 80), s.n, base, s.conc, Printable(s.hot, 80), s.paths[s.hot]*100/max(s.n, 1), src.n)}, true
}

// siteSurge 判断站点的请求量突增是否是分布式 CC：请求集中在同一路径（占一半以上），且集中刷这个路径的来源达到 dist_cc_ips 个。
func (b *Behavior) siteSurge(s *siteWin) bool {
	hot, top := "", 0
	for p, c := range s.paths {
		if c > top {
			hot, top = p, c
		}
	}
	if top*2 < s.n {
		return false // 访问分散在各种路径上：正常的访问高峰
	}
	conc := 0
	for _, c := range s.srcs {
		if c.concentrated(hot, b.th.DistCCIPRequests) {
			conc++
		}
	}
	if conc < b.th.DistCCIPs {
		return false // 少数来源刷同一路径：由单来源的 CC 检测告警
	}
	s.hot, s.conc = hot, conc
	return true
}

// ---------------- 多源 DDoS ----------------

type dstKey struct {
	ip   string
	port int
}

type dstWin struct {
	surgeBase
	srcs    map[string]int // 来源 → 窗口内的事件数（有上限）
	failed  int            // 被拒绝或没有应答的事件数（SYN 洪泛、已被设备拦截）
	nSrcs   int            // 判定时的来源数
	topSrc  int            // 判定时单个来源的最大事件数
	fired   map[string]struct{}
	trigger bool // 当前突增是否已经告警过第一条
}

// observeDst 按目的地址与端口汇总入站的防火墙事件，判断是否为多源 DDoS。
func (b *Behavior) observeDst(ev *model.Event, internal bool) (model.Hit, bool) {
	if internal || ev.DstIP == "" {
		return model.Hit{}, false
	}
	k := dstKey{ev.DstIP, ev.DstPort}
	d := b.dsts[k]
	if d == nil {
		if len(b.dsts) >= maxDDoSDsts {
			return model.Hit{}, false
		}
		d = &dstWin{srcs: map[string]int{}}
		b.dsts[k] = d
	}
	if d.roll(ev.Time, b.th.FwWindow) {
		clear(d.srcs)
		d.failed, d.nSrcs, d.topSrc, d.fired, d.trigger = 0, 0, 0, nil, false
	}
	d.n++
	if ev.Action == model.ActionDeny || ev.Reply == model.ReplyNone {
		d.failed++
	}
	cnt, tracked := d.srcs[ev.SrcIP]
	if tracked || len(d.srcs) < maxDDoSSrcs {
		cnt++
		d.srcs[ev.SrcIP] = cnt
	}
	if !d.surge {
		// 基线不成熟时没有参照：繁忙的对外服务本来就有大量来源，只在量大到明显异常（10 倍阈值）时判断
		if d.n < d.need(b.th.DDoSEvents, 10) || d.n-d.checked < surgeRecheck && d.checked > 0 {
			return model.Hit{}, false
		}
		d.checked = d.n
		top := 0
		for _, c := range d.srcs {
			top = max(top, c)
		}
		if len(d.srcs) < b.th.DDoSSources || top*2 >= d.n {
			return model.Hit{}, false // 来源不够多，或主要来自一个来源（单来源洪泛由 bhv-flood 判断）
		}
		d.surge, d.nSrcs, d.topSrc = true, len(d.srcs), top
	}
	// 第一条告警给触发判定的来源（伪造源地址时每个来源只有几条事件）；之后只告警事件较多的参与者
	if d.flagged >= maxDDoSFlags || d.trigger && cnt < 10 {
		return model.Hit{}, false
	}
	if _, ok := d.fired[ev.SrcIP]; ok {
		return model.Hit{}, false
	}
	if d.fired == nil {
		d.fired = map[string]struct{}{}
	}
	d.fired[ev.SrcIP] = struct{}{}
	d.trigger = true
	d.flagged++
	// 大部分连接被拒绝或没有应答：SYN 洪泛或已被设备拦截，资源消耗的迹象明确，判为高危；否则可能是业务量突增，中危待核实
	sev := model.SevMedium
	failPct := d.failed * 100 / max(d.n, 1)
	if failPct >= 50 {
		sev = model.SevHigh
	}
	// 防火墙攻击防范同时报告了针对该地址的洪泛：两种判定相互印证，不只是业务量突增
	corr := ""
	if df, ok := b.deviceFloodNear(ev.DstIP, ev.Time); ok {
		sev = model.SevHigh
		corr = "；防火墙攻击防范同时报告「" + df.name + "」"
	}
	base := "平时没有足够的记录"
	if d.windows >= surgeMature {
		base = fmt.Sprintf("平时约 %.0f 条", d.base)
	}
	return model.Hit{RuleID: "bhv-ddos", Name: "分布式拒绝服务(DDoS)", Category: CatFlood, Severity: sev, Phase: model.PhaseImpact,
		Result: fwResult(ev),
		Evidence: fmt.Sprintf("%s内 %s:%d 收到 %d 条连接（%s），来自 %d 个以上不同来源，其中 %d%% 被拒绝或没有应答；该来源 %d 条",
			fmtDur(b.th.FwWindow), ev.DstIP, ev.DstPort, d.n, base, d.nSrcs, failPct, cnt) + corr}, true
}

// pruneSurge 清理长时间没有流量的站点与目的地址。
func (b *Behavior) pruneSurge(now time.Time) {
	for k, s := range b.sites {
		if outside(now, s.start, 24*time.Hour) {
			delete(b.sites, k)
		}
	}
	for k, d := range b.dsts {
		if outside(now, d.start, 24*time.Hour) {
			delete(b.dsts, k)
		}
	}
}
