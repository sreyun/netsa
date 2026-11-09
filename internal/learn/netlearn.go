package learn

import (
	"fmt"
	"log"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"netsa/internal/detect"
)

// 从原始日志自动学习内网网段，不需要分析员的结论。
//
// 企业常把 172.168.0.0/16 这类已分配为公网的地址段用在内网（RFC1918 只到 172.31）。只看地址，这些内部主机会被定位到
// 境外、当成外部攻击源，应用服务器连数据库也会被判为暴力破解。防火墙日志里的安全域直接说明了报文从哪一侧进来：
// 同一个 /24 网段多次作为内部安全域（trust、dmz 等）的来源出现、且来自多个不同地址，就认定为内网。
//
// 防火墙自身的 local 域不作为依据：那是防火墙自己的接口地址，外网接口就是运营商分配的公网地址，
// 同一 /24 里往往还有机房其他租户。把它学成内网，同网段的外部攻击者会被当成内部主机：不查定位与情报、不能封禁。
//
// 学到的网段影响地址归属（不再查询定位、按内部来源处理放行的连接、联动封禁跳过），被拒绝的访问照常告警；
// 学到的网段记入进化日志与审计链，可以在自学习页面看到依据。

const (
	netLearnEvents = 20  // 同一网段作为内部安全域来源出现的日志条数达到该值才认定
	netLearnHosts  = 3   // 并且至少见到这么多个不同地址：一两个地址（如防火墙的接口、NAT 地址）不足以说明整个 /24
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
// 调用方只在来源安全域属于内部、且地址不在已知内网段时调用；防火墙自身的 local 域在这里忽略。
func (l *Learner) ObserveInternalZone(ip, zone string, t time.Time) string {
	if l == nil || detect.DeviceZone(zone) {
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
	if o.events < netLearnEvents || len(o.hosts) < netLearnHosts {
		return Change{}, false
	}
	delete(l.netPending, key)
	l.nets[key] = &LearnedNet{Prefix: key, Zone: o.zone, Events: o.events, Hosts: o.hosts, Time: t}
	c := Change{Time: time.Now(), Kind: "intranet", User: "自学习",
		Detail: fmt.Sprintf("从防火墙日志识别内网网段 %s：%d 条日志、%d 个地址的来源安全域为 %s（如 %s），之后按内部地址处理",
			key, o.events, len(o.hosts), o.zone, strings.Join(o.hosts[:min(len(o.hosts), 3)], "、"))}
	l.logLocked(c)
	return c, true
}

// dropDeviceNetsLocked 撤销旧版本依据防火墙自身 local 域学到的内网网段（启动时执行，幂等）。
// 这些网段之后按公网地址处理：重新定位、可以封禁；撤销记入进化日志并计入自我纠错。
func (l *Learner) dropDeviceNetsLocked() int {
	n := 0
	for _, key := range slices.Sorted(maps.Keys(l.nets)) {
		ln := l.nets[key]
		if !detect.DeviceZone(ln.Zone) {
			continue
		}
		delete(l.nets, key)
		n++
		hosts := strings.Join(ln.Hosts[:min(len(ln.Hosts), 3)], "、")
		l.logLocked(Change{Time: time.Now(), Kind: "intranet_off", User: "自学习",
			Detail: fmt.Sprintf("撤销内网网段 %s：依据的来源安全域 %s 是防火墙自身，%s 是防火墙的接口地址，不能说明整个网段属于内网；之后按公网地址处理", key, ln.Zone, hosts)})
		log.Printf("[learn] 撤销依据防火墙自身 %s 域学到的内网网段 %s（%s 是防火墙的接口地址）", ln.Zone, key, hosts)
	}
	if n > 0 {
		l.loop.NetsOff += n
		l.dirty = true
	}
	return n
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
