package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netsa/internal/model"
)

// 本文件检测两类以“业务受损”为结果的行为：
//
//   - 慢请求 / 超时攻击（bhv-timeout）：同一来源持续收到网关超时，且明显多于同一站点的其他访客。
//     只看次数会把后端整体故障误判为攻击（故障时所有访客都超时），所以要和同站其他访客比较。
//   - 疑似破坏性攻击（bhv-destroy）：一条此前正常服务多个访客的业务路径，开始对多个其他访客返回
//     404 / 410 / 5xx，且此前有可疑来源：触发了超时攻击，或在攻击之后对该路径写操作成功。
//     只有可疑来源自己收到 404（例如被 WAF 拦截）不算；没有可疑来源的路径失效多为发布或下线，也不告警。

const (
	okClients    = 3                // 路径至少对这么多不同访客返回过正常响应，才算业务路径
	failClients  = 3                // 失效后收到错误的不同访客数（其中可疑来源以外的至少 2 个）
	pathLookback = time.Hour        // 业务路径最近一次正常响应距今不超过该时间
	pendingTTL   = 2 * time.Hour    // 破坏性攻击的证据保留多久，等可疑来源再次出现时告警
	maxImpact    = 5000             // 跟踪的站点数上限
	maxHostPaths = 5000             // 每个站点跟踪的业务路径数上限
	maxSuspects  = 256              // 每个站点的可疑来源数上限
	maxSlowWins  = 100000           // 超时窗口数上限（只为收到过超时的来源建立）
	maxAttacked  = 100000           // 最近有攻击命中的来源数上限
	slowRatio    = 0.3              // 来源的超时比例至少为该值：偶尔超时的正常大客户不算
	slowVsOthers = 4                // 来源的超时比例至少是同站其他访客的该倍数
	failMemory   = 30 * time.Minute // 路径开始失效后，收集失效证据的时间
)

type slowWin struct {
	start          time.Time
	reqs, timeouts int
	paths          []string // 超时的路径样例
	fired          bool
}

type hostLoad struct {
	start          time.Time
	reqs, timeouts int
}

type suspect struct {
	at      time.Time
	why     string
	writes  []string // 攻击之后写操作成功的路径
	pending string   // 待告警的证据：该来源下一次出现时告警（告警必须落在攻击者自己的请求上）
	since   time.Time
	fired   bool
}

type pathHealth struct {
	ok       map[string]struct{}
	okLast   time.Time
	failFrom time.Time
	fail     map[string]struct{}
	status   map[int]int // 失效后的响应码分布
	fired    bool
}

type hostImpact struct {
	load     hostLoad
	paths    map[string]*pathHealth
	suspects map[string]*suspect
}

func isTimeoutResp(ev *model.Event, slow time.Duration) bool {
	return ev.Status == 504 || ev.Status == 408 || slow > 0 && ev.ReqTime >= slow.Seconds()
}

func isWrite(method string) bool {
	return method == "DELETE" || method == "PUT" || method == "PATCH" || method == "POST"
}

// observeImpact 在 observeWeb 之后调用（调用方持锁）。attacked 表示本次请求命中了中危及以上的攻击规则。
func (b *Behavior) observeImpact(ev *model.Event, path string, attacked bool) []model.Hit {
	hi := b.impact[ev.Host]
	if hi == nil {
		if len(b.impact) >= maxImpact {
			return nil
		}
		hi = &hostImpact{load: hostLoad{start: ev.Time}, paths: map[string]*pathHealth{}, suspects: map[string]*suspect{}}
		b.impact[ev.Host] = hi
	}
	if attacked && (b.attacked[ev.SrcIP] != (time.Time{}) || len(b.attacked) < maxAttacked) {
		b.attacked[ev.SrcIP] = ev.Time
	}
	var hits []model.Hit
	// 可疑来源再次出现：告警（证据在路径失效时已经准备好）
	if s := hi.suspects[ev.SrcIP]; s != nil && s.pending != "" && !s.fired {
		if outside(ev.Time, s.since, pendingTTL) {
			s.pending = ""
		} else {
			s.fired = true
			hits = append(hits, model.Hit{RuleID: "bhv-destroy", Name: "疑似破坏性攻击", Category: CatDestroy, Severity: model.SevHigh,
				Phase: model.PhaseImpact, Result: model.ResultSuccess, Evidence: s.pending})
		}
	}
	if h, ok := b.slowRequest(ev, hi, path); ok {
		hits = append(hits, h)
	}
	// 攻击之后写操作成功：记下路径，之后该路径对其他访客失效时关联到这个来源
	if isWrite(ev.Method) && ev.Status >= 200 && ev.Status < 300 {
		if at, ok := b.attacked[ev.SrcIP]; ok && !outside(ev.Time, at, 3*b.th.TimeoutWindow) {
			s := hi.suspect(ev.SrcIP, ev.Time, "攻击后对业务路径写操作成功")
			if s != nil && len(s.writes) < 8 && !contains(s.writes, path) {
				s.writes = append(s.writes, path)
			}
		}
	}
	if ev.Method == "GET" || ev.Method == "HEAD" {
		b.pathHealth(ev, hi, path)
	}
	return hits
}

// slowRequest 统计来源与站点的超时，判断是否为慢请求 / 超时攻击。
func (b *Behavior) slowRequest(ev *model.Event, hi *hostImpact, path string) (model.Hit, bool) {
	win := b.th.TimeoutWindow
	timeout := isTimeoutResp(ev, b.th.SlowRequest)
	if outside(ev.Time, hi.load.start, win) {
		hi.load = hostLoad{start: ev.Time}
	}
	hi.load.reqs++
	if timeout {
		hi.load.timeouts++
	}
	sw := b.slow[ev.SrcIP]
	if sw != nil && outside(ev.Time, sw.start, win) {
		delete(b.slow, ev.SrcIP)
		sw = nil
	}
	if sw == nil {
		if !timeout || len(b.slow) >= maxSlowWins {
			return model.Hit{}, false
		}
		sw = &slowWin{start: ev.Time}
		b.slow[ev.SrcIP] = sw
	}
	sw.reqs++
	if timeout {
		sw.timeouts++
		if len(sw.paths) < 3 && !contains(sw.paths, path) {
			sw.paths = append(sw.paths, path)
		}
	}
	if sw.fired || sw.timeouts < b.th.TimeoutRequests {
		return model.Hit{}, false
	}
	ratio := float64(sw.timeouts) / float64(sw.reqs)
	// 站点窗口与来源窗口的起点不同，相减可能为负
	oReqs, oTimeouts := max(hi.load.reqs-sw.reqs, 0), max(hi.load.timeouts-sw.timeouts, 0)
	others := 0.0
	if oReqs > 0 {
		others = float64(oTimeouts) / float64(oReqs)
	}
	if ratio < slowRatio || others*slowVsOthers > ratio {
		return model.Hit{}, false // 偶尔超时，或同站其他访客也大量超时（后端整体故障）
	}
	sw.fired = true
	hi.suspect(ev.SrcIP, ev.Time, fmt.Sprintf("%s内 %d 次请求超时", fmtDur(win), sw.timeouts))
	samples := make([]string, len(sw.paths))
	for i, p := range sw.paths {
		samples[i] = Printable(p, 60)
	}
	return model.Hit{RuleID: "bhv-timeout", Name: "慢请求/超时攻击", Category: CatCC, Severity: model.SevMedium, Phase: model.PhaseImpact,
		Result: model.ResultUnknown,
		Evidence: fmt.Sprintf("%s内 %d 次请求中 %d 次超时（504 / 408 或耗时 ≥ %s），同站其他访客超时比例 %.0f%%；超时路径如 %s",
			fmtDur(win), sw.reqs, sw.timeouts, fmtSec(b.th.SlowRequest), others*100, strings.Join(samples, "、"))}, true
}

// pathHealth 跟踪业务路径的可用性，路径对多个其他访客失效时关联到可疑来源。
func (b *Behavior) pathHealth(ev *model.Event, hi *hostImpact, path string) {
	ok := ev.Status >= 200 && ev.Status < 300 || ev.Status == 304
	failed := ev.Status == 404 || ev.Status == 410 || ev.Status >= 500
	ph := hi.paths[path]
	if ph == nil {
		// 只为返回过正常响应的路径建立状态：扫描器请求大量不存在的路径不占内存
		if !ok || len(hi.paths) >= maxHostPaths {
			return
		}
		ph = &pathHealth{ok: map[string]struct{}{}}
		hi.paths[path] = ph
	}
	if ok {
		if len(ph.ok) < okClients {
			ph.ok[ev.SrcIP] = struct{}{}
		}
		ph.okLast = ev.Time
		ph.failFrom, ph.fail, ph.status, ph.fired = time.Time{}, nil, nil, false // 恢复正常
		return
	}
	if !failed || len(ph.ok) < okClients || outside(ev.Time, ph.okLast, pathLookback) {
		return
	}
	if ph.fail == nil || outside(ev.Time, ph.failFrom, failMemory) {
		ph.failFrom, ph.fail, ph.status, ph.fired = ev.Time, map[string]struct{}{}, map[int]int{}, false
	}
	if len(ph.fail) < 16 {
		ph.fail[ev.SrcIP] = struct{}{}
	}
	if len(ph.status) < 8 || ph.status[ev.Status] > 0 {
		ph.status[ev.Status]++
	}
	if ph.fired || len(ph.fail) < failClients {
		return
	}
	others := 0
	for ip := range ph.fail {
		if hi.suspects[ip] == nil {
			others++
		}
	}
	if others < 2 {
		return // 只有可疑来源自己收到错误（多为被拦截），不说明业务受损
	}
	ph.fired = true
	for _, s := range hi.suspects {
		if s.pending != "" || s.fired || !related(s, path, ph.failFrom, b.th.TimeoutWindow) {
			continue
		}
		s.pending = fmt.Sprintf("%s之后，此前正常的 %s 对 %d 个访客返回 %s", s.why, Printable(path, 80), len(ph.fail), statusSummary(ph.status))
		s.since = ev.Time
	}
}

// related 判断可疑来源是否与路径失效相关：超时攻击发生在失效前后不久，或攻击后对该路径（或其上级）写操作成功。
func related(s *suspect, path string, failFrom time.Time, win time.Duration) bool {
	if failFrom.Sub(s.at) > 3*win || s.at.Sub(failFrom) > win {
		return false
	}
	if len(s.writes) == 0 {
		return true // 超时攻击：影响整个站点
	}
	for _, w := range s.writes {
		if path == w || strings.HasPrefix(path, strings.TrimSuffix(w, "/")+"/") {
			return true
		}
	}
	return false
}

// suspect 返回（必要时创建）站点上的可疑来源，超过上限时返回 nil。
func (hi *hostImpact) suspect(ip string, at time.Time, why string) *suspect {
	s := hi.suspects[ip]
	if s == nil {
		if len(hi.suspects) >= maxSuspects {
			return nil
		}
		s = &suspect{at: at, why: why}
		hi.suspects[ip] = s
		return s
	}
	s.at = at
	if !strings.Contains(s.why, why) {
		s.why = why + "；" + s.why
	}
	return s
}

func (b *Behavior) pruneImpact(now time.Time) {
	win := b.th.TimeoutWindow
	for ip, w := range b.slow {
		if outside(now, w.start, 2*win) {
			delete(b.slow, ip)
		}
	}
	for ip, at := range b.attacked {
		if outside(now, at, 3*win) {
			delete(b.attacked, ip)
		}
	}
	for host, hi := range b.impact {
		for p, ph := range hi.paths {
			if outside(now, ph.okLast, pathLookback) && (ph.fail == nil || outside(now, ph.failFrom, failMemory)) {
				delete(hi.paths, p)
			}
		}
		for ip, s := range hi.suspects {
			last := s.at
			if s.since.After(last) {
				last = s.since
			}
			if outside(now, last, pendingTTL) {
				delete(hi.suspects, ip)
			}
		}
		if len(hi.paths) == 0 && len(hi.suspects) == 0 && outside(now, hi.load.start, 2*win) {
			delete(b.impact, host)
		}
	}
}

func statusSummary(m map[int]int) string {
	codes := make([]int, 0, len(m))
	for c := range m {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = fmt.Sprintf("%d×%d", c, m[c])
	}
	return strings.Join(parts, " ")
}

func fmtSec(d time.Duration) string { return fmt.Sprintf("%g秒", d.Seconds()) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
