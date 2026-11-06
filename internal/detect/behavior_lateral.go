package detect

import (
	"fmt"
	"strings"
	"time"

	"netsa/internal/model"
)

// 横向移动（P2-3）：
//   - 被攻击后发起内网连接（bhv-lateral-new）：近 24 小时遭受过利用尝试的服务器（Web 日志记录的服务器地址、
//     设备报出攻击的目的地址、被攻击来源访问过的内网服务器），之后连接其他内网主机的远程管理端口
//     （SSH、RDP、SMB、WinRM、VNC、RPC），而这条连接在攻击之前从未出现过。服务器已经回连攻击者的按高危；
//   - 东西向管理协议异常（bhv-lateral-fanout）：内网主机 1 小时内新增连接 5 台以上此前从未连接过的主机的
//     远程管理端口（PsExec、WMI、RDP 横向扩散）。运维跳板机平时就会连接很多服务器：观察满 24 小时之后才判断，
//     之前出现过的连接都视为正常；
//   - 横向登录链（auth-lateral-chain）：Windows 4624 的网络登录（类型 3）与远程桌面（类型 10）中，A 登录 H1 之后
//     1 小时内又从 H1 登录 H2，且这一跳此前从未出现过（跳板机的固定路径不告警）。连续三跳、或每一跳换了账号
//     （拿到新凭证继续扩散）按高危。
// 行为统计不持久化：重启后重新观察 24 小时。

const (
	lateralWindow   = 24 * time.Hour // 攻击之后多久内的新连接参与判断
	ewLearn         = 24 * time.Hour // 东西向连接的观察期
	ewFanoutWindow  = time.Hour
	ewFanoutHosts   = 5
	maxEWPairs      = 500000 // 东西向连接对（按哈希记录首次出现的时间，分两代轮换）
	maxAttackedSrv  = 20000
	maxEWSources    = 50000
	logonChainGap   = time.Hour
	maxLogonTargets = 20000
	ewPendWindow    = time.Hour // 尚未判定的首次管理连接保留多久：失陷判定（回连、外连远控）可能晚于这些连接到达
	ewPendPerSrc    = 8
	maxEWPendSrcs   = 2000
)

// adminPorts 是横向移动常用的远程管理端口。
var adminPorts = map[int]string{22: "SSH", 23: "Telnet", 135: "RPC", 139: "SMB", 445: "SMB", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}

type srvMark struct {
	at          time.Time
	why         string
	compromised bool
}

type ewSource struct {
	first  time.Time
	start  time.Time // 新增连接窗口
	news   map[string]struct{}
	fired  bool
	sample []string
}

// ewPending 是一条首次出现、但发起时还不知道来源已失陷的内网管理连接。
type ewPending struct {
	ev  model.Event
	svc string
}

// Late 是事后补发的命中：服务器被判定失陷时，它此前发起的首次内网管理连接（日志读取先后、批次并行处理都会让
// 这些连接先于失陷判定到达）。Ev 是原事件的副本，已计入事件量（Replay）。
type Late struct {
	Ev   *model.Event
	Hits []model.Hit
}

type logonMark struct {
	from, user string
	at         time.Time
	hops       int
	path       string // 登录链：A → H1 → H2
}

// MarkAttacked 记录内网服务器遭受了利用尝试或已经回连攻击者（compromised），之后它发起的新内网连接按横向移动判断。
// 已失陷时同时返回它在失陷前后 1 小时内已经发起、当时还没有判定的首次管理连接，由调用方补记告警。
func (b *Behavior) MarkAttacked(ip string, at time.Time, why string, compromised bool) []Late {
	if b == nil || ip == "" || !isPrivateIP(ip) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.markAttackedLocked(ip, at, why, compromised)
	if !compromised {
		return nil
	}
	m := b.attackedSrv[ip]
	var out []Late
	keep := b.ewPend[ip][:0]
	for _, p := range b.ewPend[ip] {
		if d := p.ev.Time.Sub(m.at); d >= -time.Minute && d <= lateralWindow {
			ev := p.ev
			ev.Replay = true
			out = append(out, Late{Ev: &ev, Hits: []model.Hit{lateralNewHit(&ev, p.svc, m)}})
			continue
		}
		keep = append(keep, p)
	}
	if len(keep) == 0 {
		delete(b.ewPend, ip)
	} else {
		b.ewPend[ip] = keep
	}
	return out
}

func (b *Behavior) markAttackedLocked(ip string, at time.Time, why string, compromised bool) {
	m, ok := b.attackedSrv[ip]
	if !ok && len(b.attackedSrv) >= maxAttackedSrv {
		return
	}
	if !ok || at.After(m.at) || compromised && !m.compromised {
		m.at, m.why = at, why
	}
	m.compromised = m.compromised || compromised
	b.attackedSrv[ip] = m
}

// noteAttackTargets 从攻击事件中找出被攻击的内网服务器（调用方持锁）。
func (b *Behavior) noteAttackTargets(ev *model.Event, ruleHits []model.Hit) {
	srv := ev.NatDstIP
	if srv == "" || !isPrivateIP(srv) {
		srv = ev.DstIP
	}
	if srv == "" || !isPrivateIP(srv) || InternalSource(ev) {
		return
	}
	for i := range ruleHits {
		h := &ruleHits[i]
		if !h.TagOnly && !h.Weak && !h.Inapplicable && h.Phase == model.PhaseExploit && h.Severity >= model.SevMedium {
			b.markAttackedLocked(srv, ev.Time, h.Name, false)
			return
		}
	}
	// 只有 Web 日志看得到攻击、防火墙日志看得到服务器：攻击来源随后访问的内网 Web 服务器即被攻击的那台
	if ev.Kind == model.KindFirewall && ev.Action != model.ActionDeny {
		switch ev.DstPort {
		case 80, 443, 8080, 8443, 8000, 8888:
			if t, ok := b.attacked[ev.SrcIP]; ok && ev.Time.Sub(t).Abs() <= 2*time.Hour {
				b.markAttackedLocked(srv, ev.Time, "攻击来源 "+ev.SrcIP+" 访问的服务器", false)
			}
		}
	}
}

// observeEastWest 判断内网主机之间的远程管理连接（调用方持锁）。
func (b *Behavior) observeEastWest(ev *model.Event) []model.Hit {
	svc, ok := adminPorts[ev.DstPort]
	if !ok || ev.SrcIP == ev.DstIP {
		return nil
	}
	k := ipKey(ev.SrcIP + ">" + ev.DstIP + ":" + fmt.Sprint(ev.DstPort))
	_, seen := b.ewFirstSeen(k)
	b.ewNote(k, ev.Time)
	src := b.ewSrcs[ev.SrcIP]
	if src == nil {
		if len(b.ewSrcs) >= maxEWSources {
			return nil
		}
		src = &ewSource{first: ev.Time}
		b.ewSrcs[ev.SrcIP] = src
	}
	if ev.Time.Before(src.first) {
		src.first = ev.Time
	}
	var hits []model.Hit
	// 被攻击的服务器：攻击之后第一次出现的管理连接。只是遭受过攻击的，观察满 24 小时后才判断
	// （重启后所有连接都是“第一次”，域内服务器连接域控的 SMB 也会被当成新连接）；已经回连攻击者的随时判断
	m, ok := b.attackedSrv[ev.SrcIP]
	switch {
	case seen:
	case ok && ev.Time.Sub(m.at) >= -time.Minute && ev.Time.Sub(m.at) <= lateralWindow && (m.compromised || ev.Time.Sub(src.first) >= ewLearn):
		hits = append(hits, lateralNewHit(ev, svc, m))
	case !ok || !m.compromised:
		b.notePending(ev, svc) // 之后判定失陷时补记
	}
	// 扇出：观察期之后新增的管理连接达到 5 台主机
	if seen || ev.Time.Sub(src.first) < ewLearn {
		return hits
	}
	if src.start.IsZero() || outside(ev.Time, src.start, ewFanoutWindow) {
		src.start, src.news, src.fired, src.sample = ev.Time, map[string]struct{}{}, false, nil
	}
	if _, ok := src.news[ev.DstIP]; !ok && len(src.news) < 64 {
		src.news[ev.DstIP] = struct{}{}
		if len(src.sample) < 5 {
			src.sample = append(src.sample, fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort))
		}
	}
	if !src.fired && len(src.news) >= ewFanoutHosts {
		src.fired = true
		hits = append(hits, model.Hit{RuleID: "bhv-lateral-fanout", Name: "东西向管理协议异常（新增连接多台主机）", Category: CatLateral,
			Severity: model.SevMedium, Phase: model.PhaseExploit, Result: fwResult(ev),
			Evidence: fmt.Sprintf("%s 1 小时内新增连接 %d 台此前从未连接过的主机的远程管理端口（%s）", ev.SrcIP, len(src.news), strings.Join(src.sample, "、"))})
	}
	return hits
}

// lateralNewHit 是被攻击的服务器第一次发起的内网管理连接。
func lateralNewHit(ev *model.Event, svc string, m srvMark) model.Hit {
	sev := model.SevMedium
	state := "遭受过攻击（" + m.why + "）"
	if m.compromised {
		sev, state = model.SevHigh, "已回连攻击者（"+m.why+"）"
	}
	when := ev.Time.Sub(m.at).Round(time.Second)
	rel := fmtDur(when) + "前"
	if when < 0 {
		rel = "前后"
	}
	return model.Hit{RuleID: "bhv-lateral-new", Name: "被攻击后发起内网连接（" + svc + "）", Category: CatLateral,
		Severity: sev, Phase: model.PhaseExploit, Result: fwResult(ev),
		Evidence: fmt.Sprintf("%s %s%s，之后第一次连接 %s:%d（%s），此前没有出现过这条连接", ev.SrcIP, rel, state, ev.DstIP, ev.DstPort, svc)}
}

// notePending 保留来源最近的首次管理连接（只保留判定需要的字段，调用方持锁）。
func (b *Behavior) notePending(ev *model.Event, svc string) {
	list, ok := b.ewPend[ev.SrcIP]
	if !ok && len(b.ewPend) >= maxEWPendSrcs {
		return
	}
	if len(list) >= ewPendPerSrc {
		list = append(list[:0], list[1:]...)
	}
	b.ewPend[ev.SrcIP] = append(list, ewPending{svc: svc, ev: model.Event{Kind: ev.Kind, Source: ev.Source, Time: ev.Time,
		SrcIP: ev.SrcIP, SrcPort: ev.SrcPort, DstIP: ev.DstIP, DstPort: ev.DstPort, Proto: ev.Proto, Action: ev.Action, Reply: ev.Reply, Format: ev.Format,
		SrcZone: ev.SrcZone, DstZone: ev.DstZone, Policy: ev.Policy, NatDstIP: ev.NatDstIP, Reach: ev.Reach}})
}

func (b *Behavior) ewFirstSeen(k uint64) (int64, bool) {
	if t, ok := b.ewSeen[k]; ok {
		return t, true
	}
	t, ok := b.ewSeenPrev[k]
	return t, ok
}

func (b *Behavior) ewNote(k uint64, at time.Time) {
	t := at.Unix()
	if old, ok := b.ewSeen[k]; ok {
		if t < old {
			b.ewSeen[k] = t
		}
		return
	}
	if old, ok := b.ewSeenPrev[k]; ok && old < t {
		t = old
	}
	if b.ewSeen == nil || len(b.ewSeen) >= maxEWPairs {
		b.ewSeenPrev, b.ewSeen = b.ewSeen, map[uint64]int64{}
	}
	b.ewSeen[k] = t
}

// observeLogonChain 判断 Windows 网络登录 / 远程桌面组成的横向登录链（调用方持锁）。
func (b *Behavior) observeLogonChain(ev *model.Event) (model.Hit, bool) {
	if ev.Action != model.ActionAllow || ev.Service != "网络登录" && ev.Service != "RDP" && ev.Service != "明文网络登录" {
		return model.Hit{}, false
	}
	tgt := shortHost(ev.Host)
	if tgt == "" {
		tgt = ev.DstIP
	}
	src := shortHost(ev.SrcHost)
	if tgt == "" || src == tgt || ev.SrcIP == "" && src == "" {
		return model.Hit{}, false
	}
	if b.authSince.IsZero() || ev.Time.Before(b.authSince) {
		b.authSince = ev.Time
	}
	user := strings.ToLower(ev.User)
	from := src
	if from == "" {
		from = ev.SrcIP
	}
	pk := ipKey("logon|" + from + ">" + tgt + "|" + user)
	_, seen := b.ewFirstSeen(pk)
	b.ewNote(pk, ev.Time)
	// 来源主机自己在此前 1 小时内被登录过：链条延长一跳
	var prev *logonMark
	for _, k := range []string{src, ev.SrcIP} {
		if m, ok := b.logons[k]; k != "" && ok && ev.Time.Sub(m.at) >= 0 && ev.Time.Sub(m.at) <= logonChainGap {
			prev = &m
			break
		}
	}
	cur := logonMark{from: from, user: user, at: ev.Time, hops: 1, path: from + " →(" + ev.User + ") " + tgt}
	if prev != nil {
		cur.hops = prev.hops + 1
		cur.path = prev.path + " →(" + ev.User + ") " + tgt
	}
	if _, ok := b.logons[tgt]; ok || len(b.logons) < maxLogonTargets {
		b.logons[tgt] = cur
		if ev.DstIP != "" {
			b.logons[ev.DstIP] = cur
		}
	}
	if prev == nil || seen || ev.Time.Sub(b.authSince) < ewLearn {
		return model.Hit{}, false
	}
	sev := model.SevMedium
	if cur.hops >= 3 || prev.user != user {
		sev = model.SevHigh // 连续三跳，或换了账号继续扩散（拿到了新凭证）
	}
	return model.Hit{RuleID: "auth-lateral-chain", Name: "横向登录链（" + ev.Service + "）", Category: CatLateral, Severity: sev,
		Phase: model.PhaseCredential, Result: model.ResultSuccess,
		Evidence: fmt.Sprintf("%d 跳：%s，这一跳此前从未出现过", cur.hops, Printable(cur.path, 300))}, true
}

// shortHost 返回主机名的短名（小写，去掉域名后缀）。
func shortHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || h == "-" {
		return ""
	}
	if isIPString(h) {
		return h
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

func isIPString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c == '.' || c == ':' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return strings.ContainsAny(s, ".:") && strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0
}

func ipKey(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// pruneLateral 清理过期的记录（调用方持锁）。
func (b *Behavior) pruneLateral(now time.Time) {
	for k, m := range b.attackedSrv {
		if outside(now, m.at, lateralWindow) {
			delete(b.attackedSrv, k)
		}
	}
	for k, m := range b.logons {
		if outside(now, m.at, logonChainGap) {
			delete(b.logons, k)
		}
	}
	for k, list := range b.ewPend {
		if len(list) == 0 || outside(now, list[len(list)-1].ev.Time, ewPendWindow) {
			delete(b.ewPend, k)
		}
	}
}
