package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netsa/internal/model"
)

// 带宽型 DDoS（bhv-ddos-bw，P3-1）：按目的地址统计 1 分钟内的入向字节数与包数（NetFlow / sFlow / IPFIX、Zeek conn.log、
// 带字节数的防火墙会话日志，流量已按采样率还原），达到 ddos_bps 或 ddos_pps 且为该地址平时的 10 倍以上时告警。
// 反射放大攻击的来源是被利用的反射器、SYN 洪泛的来源多为伪造地址：告警按被攻击的目的地址生成（与设备只记录
// 目的地址的洪泛日志一样），证据列出来源数、主要的源端口（反射协议）与来源。
// 设备、云抗 D 服务报告同一地址遭受洪泛时，两种判定相互印证（DDoSContext）。

const (
	bwWindow    = time.Minute
	bwFactor    = 10
	maxBWDsts   = 5000
	maxBWSrcs   = 64
	maxBWPorts  = 32
	bwRefire    = 10 * time.Minute
	bwSrcCounts = 100000 // 来源数的计数上限
)

// reflectPorts 是常见的反射放大协议（源端口）。
var reflectPorts = map[int]string{19: "Chargen", 53: "DNS", 111: "Portmap", 123: "NTP", 137: "NetBIOS", 161: "SNMP", 389: "CLDAP",
	1900: "SSDP", 3283: "ARD", 3702: "WS-Discovery", 5353: "mDNS", 10001: "Ubiquiti", 11211: "Memcached", 37810: "DVR", 1194: "OpenVPN"}

type bwWin struct {
	surgeBase
	cur      int64 // 当前固定窗口的字节数（基线）
	bytes    slideSum
	pkts     slideSum
	srcs     map[string]int64
	nsrc     int
	ports    map[string]int64 // 协议/源端口 → 字节数
	fired    time.Time
	peakBps  int64
	peakPps  int64
	lastSeen time.Time
}

// observeBandwidth 统计入向流量（调用方持锁）。返回 true 表示刚判定为带宽型 DDoS，补发的告警已放入待处理队列。
func (b *Behavior) observeBandwidth(ev *model.Event) {
	if ev.SentBytes <= 0 && ev.Packets <= 0 || ev.DstIP == "" || isPrivateIP(ev.SrcIP) {
		return
	}
	dst := ev.DstIP
	if ev.NatDstIP != "" {
		dst = ev.NatDstIP
	}
	w := b.bw[dst]
	if w == nil {
		if len(b.bw) >= maxBWDsts {
			return
		}
		w = &bwWin{srcs: map[string]int64{}, ports: map[string]int64{}}
		b.bw[dst] = w
	}
	if w.rollBytes(ev.Time, bwWindow, w.cur) {
		w.cur = 0
		if ev.Time.Sub(w.fired) > 2*bwWindow {
			clear(w.srcs)
			clear(w.ports)
			w.nsrc = 0
		}
	}
	bytes, packets := windowShare(ev.SentBytes, ev.Duration, bwWindow), windowShare(max(ev.Packets, 1), ev.Duration, bwWindow)
	w.cur = satAdd(w.cur, bytes)
	if ev.Time.After(w.lastSeen) {
		w.lastSeen = ev.Time
	}
	total, _ := w.bytes.add(ev.Time, bwWindow, bytes)
	pkts, _ := w.pkts.add(ev.Time, bwWindow, max(packets, 1))
	if _, ok := w.srcs[ev.SrcIP]; ok {
		w.srcs[ev.SrcIP] = satAdd(w.srcs[ev.SrcIP], bytes)
	} else {
		if w.nsrc < bwSrcCounts {
			w.nsrc++
		}
		if len(w.srcs) < maxBWSrcs {
			w.srcs[ev.SrcIP] = bytes
		}
	}
	pk := ev.Proto + "/" + fmt.Sprint(ev.SrcPort)
	if _, ok := w.ports[pk]; ok || len(w.ports) < maxBWPorts {
		w.ports[pk] = satAdd(w.ports[pk], bytes)
	}
	secs := int64(bwWindow / time.Second)
	bps, pps := total/secs*8, pkts/secs
	w.peakBps, w.peakPps = max(w.peakBps, bps), max(w.peakPps, pps)
	needBps, needPps := b.th.DDoSBps, b.th.DDoSPps
	if w.windows >= surgeMature {
		needBps = max(needBps, int64(min(w.base*bwFactor, 9e18))/secs*8) // 平时的 10 倍以上
	}
	over := needBps > 0 && bps >= needBps || needPps > 0 && pps >= needPps && bps >= needBps/20
	if !w.fired.IsZero() && ev.Time.Sub(w.fired).Abs() < bwRefire {
		w.surge = true // 攻击持续期间不计入基线、不重复告警
		return
	}
	if !over {
		return
	}
	w.surge, w.fired = true, ev.Time
	base := "平时没有足够的记录"
	if w.windows >= surgeMature {
		base = "平时约 " + fmtBps(int64(min(w.base, 9e18))/secs*8)
	}
	evidence := fmt.Sprintf("%s 1 分钟内入向流量 %s、%s，来自 %s 个来源（%s）", dst, fmtBps(bps), fmtPps(pps), countStr(w.nsrc, bwSrcCounts), base)
	if refl := topPorts(w.ports, total); refl != "" {
		evidence += "；主要协议 " + refl
	}
	if top := topSrcs(w.srcs, 3); top != "" {
		evidence += "；流量最大的来源 " + top
	}
	sev := model.SevHigh
	if d, ok := b.deviceFloodNear(dst, ev.Time); ok {
		sev = model.SevCritical
		evidence += "；设备 / 抗 D 服务同时报告该地址遭受" + d.name
	}
	if ev.Sampling > 1 {
		evidence += fmt.Sprintf("（采样率 1:%d，已按采样率还原）", ev.Sampling)
	}
	h := model.Hit{RuleID: "bhv-ddos-bw", Name: "带宽型 DDoS（入向流量突增）", Category: CatFlood, Severity: sev, Phase: model.PhaseImpact,
		Result: model.ResultUnknown, Evidence: Printable(evidence, 400)}
	tgt := &model.Event{Kind: model.KindFirewall, Format: ev.Format, Source: ev.Source, Time: ev.Time, DstIP: dst, DstPort: ev.DstPort, Proto: ev.Proto,
		NoSource: true, Replay: true, Bps: bps, Pps: pps}
	b.pendingLate = append(b.pendingLate, Late{Ev: tgt, Hits: []model.Hit{h}})
}

// bandwidthNear 返回目的地址在 t 前后的带宽型 DDoS 判定（调用方持锁）。
func (b *Behavior) bandwidthNear(dst string, t time.Time) (*bwWin, bool) {
	w := b.bw[dst]
	if w == nil || w.fired.IsZero() || t.Sub(w.fired) > devFloodWindow || w.fired.Sub(t) > devFloodWindow {
		return nil, false
	}
	return w, true
}

// TakeLate 取出行为检测产生的、需要以其他事件记录的命中（按目的地址告警的带宽型 DDoS）。
func (b *Behavior) TakeLate() []Late {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.pendingLate
	b.pendingLate = nil
	return out
}

func topPorts(m map[string]int64, total int64) string {
	type kv struct {
		k string
		n int64
	}
	var list []kv
	for k, n := range m {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n || list[i].n == list[j].n && list[i].k < list[j].k })
	var out []string
	for i := 0; i < len(list) && i < 3; i++ {
		proto, port, _ := strings.Cut(list[i].k, "/")
		label := strings.ToUpper(proto)
		var p int
		fmt.Sscan(port, &p)
		if name, ok := reflectPorts[p]; ok && proto == "udp" {
			label = fmt.Sprintf("UDP %d（%s 反射）", p, name)
		} else if p > 0 && proto == "udp" {
			label = fmt.Sprintf("UDP 源端口 %d", p)
		}
		out = append(out, fmt.Sprintf("%s %d%%", label, list[i].n*100/max(total, 1)))
	}
	return strings.Join(out, "、")
}

func topSrcs(m map[string]int64, n int) string {
	type kv struct {
		k string
		n int64
	}
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n || list[i].n == list[j].n && list[i].k < list[j].k })
	var out []string
	for i := 0; i < len(list) && i < n; i++ {
		out = append(out, list[i].k)
	}
	return strings.Join(out, "、")
}

func countStr(n, limit int) string {
	if n >= limit {
		return fmt.Sprintf("%d 以上", limit)
	}
	return fmt.Sprint(n)
}

func fmtBps(v int64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2f Gbps", float64(v)/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1f Mbps", float64(v)/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1f Kbps", float64(v)/1e3)
	}
	return fmt.Sprintf("%d bps", v)
}

func fmtPps(v int64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.2f Mpps", float64(v)/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1f Kpps", float64(v)/1e3)
	}
	return fmt.Sprintf("%d pps", v)
}

// pruneBandwidth 清理长时间没有流量的目的地址（调用方持锁）。
func (b *Behavior) pruneBandwidth(now time.Time) {
	for k, w := range b.bw {
		if outside(now, w.lastSeen, time.Hour) {
			delete(b.bw, k)
		}
	}
}
