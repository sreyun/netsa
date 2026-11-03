package learn

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"
)

// 从原始日志自动学习内网网段，不需要分析员的结论。
//
// 企业常把 172.168.0.0/16 这类已分配为公网的地址段用在内网（RFC1918 只到 172.31）。只看地址，这些内部主机会被定位到
// 境外、当成外部攻击源，应用服务器连数据库也会被判为暴力破解。防火墙日志里的安全域直接说明了报文从哪一侧进来：
// 同一个 /24 网段多次作为内部安全域（trust、dmz 等）的来源出现，就认定为内网。
//
// 学错的代价有限：只影响地址归属（不再查询定位、按内部来源处理放行的连接），被拒绝的访问照常告警；
// 学到的网段记入进化日志与审计链，可以在自学习页面看到依据。

const (
	netLearnEvents = 20  // 同一网段作为内部安全域来源出现的日志条数达到该值才认定
	maxLearnedNets = 256 // 自动学习的网段数上限
	maxNetPending  = 4096
)

// LearnedNet 是一个自动学习到的内网网段。
type LearnedNet struct {
	Prefix string    `json:"prefix"`
	Zone   string    `json:"zone"`   // 依据：出现的内部安全域
	Events int       `json:"events"` // 认定时累计的日志条数
	Hosts  []string  `json:"hosts"`  // 认定时见到的地址（最多 5 个）
	Time   time.Time `json:"time"`
}

type netObs struct {
	events int
	zone   string
	hosts  []string
}

// ObserveInternalZone 记录一条“公网段地址出现在内部安全域”的防火墙日志，返回本次新认定的网段（没有则为空）。
// 调用方只在来源安全域属于内部、且地址不在已知内网段时调用。
func (l *Learner) ObserveInternalZone(ip, zone string, t time.Time) string {
	if l == nil {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return "" // IPv6 的内网规划各不相同，不按固定长度推断
	}
	p, _ := a.Prefix(24)
	key := p.String()
	c, ok := l.observeNetLocked(key, ip, zone, t)
	if ok && l.OnChange != nil {
		l.OnChange(c) // 写入审计链，不持锁调用（审计回调会再次进入学习模块）
	}
	if !ok {
		return ""
	}
	return key
}

func (l *Learner) observeNetLocked(key, ip, zone string, t time.Time) (Change, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.nets[key] != nil || len(l.nets) >= maxLearnedNets {
		return Change{}, false
	}
	o := l.netPending[key]
	if o == nil {
		if len(l.netPending) >= maxNetPending {
			return Change{}, false
		}
		o = &netObs{zone: zone}
		l.netPending[key] = o
	}
	o.events++
	if len(o.hosts) < 5 && !slices.Contains(o.hosts, ip) {
		o.hosts = append(o.hosts, ip)
	}
	if o.events < netLearnEvents {
		return Change{}, false
	}
	delete(l.netPending, key)
	l.nets[key] = &LearnedNet{Prefix: key, Zone: o.zone, Events: o.events, Hosts: o.hosts, Time: t}
	c := Change{Time: time.Now(), Kind: "intranet", User: "自学习",
		Detail: fmt.Sprintf("从防火墙日志识别内网网段 %s：%d 条日志的来源安全域为 %s（如 %s），之后按内部地址处理", key, o.events, o.zone, o.hosts[0])}
	l.logLocked(c)
	return c, true
}

// LearnedNets 返回自动学习到的内网网段。
func (l *Learner) LearnedNets() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.nets))
	for k := range l.nets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (l *Learner) learnedNetsLocked() []LearnedNet {
	out := make([]LearnedNet, 0, len(l.nets))
	for _, n := range l.nets {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}
