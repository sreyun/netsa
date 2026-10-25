package detect

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/model"
)

// authWin 是一个认证来源在窗口内的登录情况。
type authWin struct {
	start time.Time
	fails int
	users map[string]struct{} // 尝试过的账号（有上限）
	svc   string
	host  string
	fired int
}

const (
	firedAuthBrute = 1 << iota
	firedAuthSpray
	firedAuthOK
)

// dnsWin 是一台内网主机在窗口内的 DNS 查询情况。
type dnsWin struct {
	start    time.Time
	nx       int
	nxNames  map[uint64]struct{}
	subs     map[string]map[uint64]struct{} // 主域名 → 不同子域名（哈希）
	fired    bool
	firedTun map[string]bool
}

// 以 DNS 查询做信誉 / 黑名单检测的正常服务：会产生大量不同的子域名，不按 DNS 隧道判断。
var tunnelSkip = []string{"in-addr.arpa", "ip6.arpa", "spamhaus.org", "spamcop.net", "sorbs.net", "barracudacentral.org", "uribl.com", "surbl.org",
	"dnswl.org", "mailspike.net", "sophosxl.net", "e5.sk", "eset.com", "mcafee.com", "trendmicro.com", "senderbase.org", "akadns.net", "akamaiedge.net",
	"cloudfront.net", "amazonaws.com", "googlevideo.com", "1e100.net", "msedge.net", "trafficmanager.net", "azurefd.net", "kaspersky-labs.com"}

func (b *Behavior) maybePrune(ev *model.Event) {
	now := time.Now()
	if ev.Time.After(b.latest) && !ev.Time.After(now.Add(time.Hour)) {
		b.latest = ev.Time
	}
	if now.Sub(b.lastPrune) > 30*time.Second || len(b.auth)+len(b.dns) >= maxWindows {
		b.prune(b.latest)
		b.lastPrune = now
	}
}

func listUsers(m map[string]struct{}, n int) string {
	out := make([]string, 0, len(m))
	for u := range m {
		out = append(out, u)
	}
	sort.Strings(out)
	more := ""
	if len(out) > n {
		more = " 等 " + strconv.Itoa(len(out)) + " 个"
		out = out[:n]
	}
	return strings.Join(out, "、") + more
}

// observeAuth 统计同一来源的登录失败：达到阈值为暴力破解，尝试大量不同账号为密码喷洒，多次失败后登录成功为暴力破解成功。
func (b *Behavior) observeAuth(ev *model.Event) []model.Hit {
	if ev.SubjectHost || ev.SrcIP == "" {
		return nil
	}
	w := b.auth[ev.SrcIP]
	if w == nil || outside(ev.Time, w.start, b.th.FwWindow) {
		if w == nil && len(b.auth) >= maxWindows {
			return nil
		}
		w = &authWin{start: ev.Time, users: map[string]struct{}{}}
		b.auth[ev.SrcIP] = w
	}
	w.svc = ev.Service
	if ev.Host != "" {
		w.host = ev.Host
	}
	target := w.svc
	if w.host != "" {
		target += " @" + w.host
	}
	var hits []model.Hit
	if ev.Action == model.ActionDeny {
		w.fails++
		if u := ev.User; u != "" && len(w.users) < 50 {
			w.users[Printable(u, 40)] = struct{}{}
		}
		if w.fails >= b.th.AuthFailures && w.fired&firedAuthBrute == 0 {
			w.fired |= firedAuthBrute
			hits = append(hits, model.Hit{RuleID: "auth-brute", Name: w.svc + " 暴力破解", Category: CatBruteForce, Severity: model.SevHigh,
				Phase: model.PhaseCredential, Result: model.ResultFailed,
				Evidence: fmtDur(b.th.FwWindow) + "内对 " + target + " 登录失败 " + strconv.Itoa(w.fails) + " 次，账号 " + listUsers(w.users, 5)})
		}
		if len(w.users) >= b.th.AuthUsers && w.fired&firedAuthSpray == 0 {
			w.fired |= firedAuthSpray
			hits = append(hits, model.Hit{RuleID: "auth-spray", Name: w.svc + " 密码喷洒 / 账号枚举", Category: CatBruteForce, Severity: model.SevHigh,
				Phase: model.PhaseCredential, Result: model.ResultFailed,
				Evidence: fmtDur(b.th.FwWindow) + "内对 " + target + " 尝试 " + strconv.Itoa(len(w.users)) + " 个不同账号：" + listUsers(w.users, 8)})
		}
		return hits
	}
	if ev.Action == model.ActionAllow && w.fails >= 5 && w.fired&firedAuthOK == 0 {
		w.fired |= firedAuthOK
		return []model.Hit{{RuleID: "auth-brute-ok", Name: w.svc + " 暴力破解成功（疑似账号失陷）", Category: CatBruteForce, Severity: model.SevCritical,
			Phase: model.PhaseCredential, Result: model.ResultSuccess,
			Evidence: "在 " + strconv.Itoa(w.fails) + " 次登录失败后以 " + Printable(ev.User, 40) + " 登录 " + target + " 成功"}}
	}
	return nil
}

// observeDNS 统计内网主机的 DNS 查询：大量不存在的随机域名为 DGA 僵尸主机特征，同一主域名下大量不同子域名为 DNS 隧道特征。
func (b *Behavior) observeDNS(ev *model.Event) []model.Hit {
	w := b.dns[ev.SrcIP]
	if w == nil || outside(ev.Time, w.start, b.th.FwWindow) {
		if w == nil && len(b.dns) >= maxWindows {
			return nil
		}
		w = &dnsWin{start: ev.Time}
		b.dns[ev.SrcIP] = w
	}
	name := ev.Host
	var hits []model.Hit
	if ev.RCode == "NXDOMAIN" {
		w.nx++
		if w.nxNames == nil {
			w.nxNames = map[uint64]struct{}{}
		}
		if len(w.nxNames) < 1000 {
			w.nxNames[fnvStr(fnvOffset, name)] = struct{}{}
		}
		if !w.fired && w.nx >= b.th.DNSNXDomain && len(w.nxNames) >= b.th.DNSNXDomain/2 {
			w.fired = true
			hits = append(hits, model.Hit{RuleID: "dns-nxdomain", Name: "大量查询不存在的域名（疑似 DGA 僵尸主机）", Category: CatDGA, Severity: model.SevHigh,
				Phase: model.PhasePersistence, Result: model.ResultAllowed,
				Evidence: fmtDur(b.th.FwWindow) + "内 " + strconv.Itoa(w.nx) + " 次 NXDOMAIN，" + strconv.Itoa(len(w.nxNames)) + " 个不同域名，例如 " + Printable(name, 80)})
		}
	}
	reg, sub := splitDomain(name)
	if sub == "" || domainIn(name, tunnelSkip) != "" {
		return hits
	}
	if w.subs == nil {
		w.subs = map[string]map[uint64]struct{}{}
	}
	set := w.subs[reg]
	if set == nil {
		if len(w.subs) >= 100 {
			return hits
		}
		set = map[uint64]struct{}{}
		w.subs[reg] = set
	}
	if len(set) <= b.th.DNSSubdomains {
		set[fnvStr(fnvOffset, sub)] = struct{}{}
	}
	if len(set) >= b.th.DNSSubdomains && !w.firedTun[reg] {
		if w.firedTun == nil {
			w.firedTun = map[string]bool{}
		}
		w.firedTun[reg] = true
		hits = append(hits, model.Hit{RuleID: "dns-tunnel-volume", Name: "疑似 DNS 隧道（同一域名下大量不同子域名）", Category: CatDNSTunnel, Severity: model.SevHigh,
			Phase: model.PhaseCollection, Result: model.ResultAllowed,
			Evidence: fmtDur(b.th.FwWindow) + "内向 " + Printable(reg, 80) + " 查询 " + strconv.Itoa(len(set)) + " 个不同子域名，例如 " + Printable(name, 100)})
	}
	return hits
}
