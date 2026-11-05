package flow

import (
	"net/netip"
	"time"
)

// Aggregator 按（源、目的、目的端口、协议）在窗口内合并流量记录：核心设备每秒数万条流，逐条送入检测没有必要，
// 合并后字节数、包数累加，扫描（目的端口不同）与洪泛（同一目的）的特征都保留。
type Aggregator struct {
	Window time.Duration // 合并窗口（默认 10 秒）
	Max    int           // 窗口内最多保留的键（默认 200000），超过时提前输出
	m      map[aggKey]*Record
	start  time.Time
}

type aggKey struct {
	src, dst netip.Addr
	dport    uint16
	proto    uint8
	denied   bool
}

// Add 合并一条记录；返回 true 表示已达到键数上限，调用方应立即 Flush。
func (a *Aggregator) Add(r Record, now time.Time) bool {
	if a.m == nil {
		a.m = map[aggKey]*Record{}
		a.start = now
	}
	k := aggKey{r.Src, r.Dst, r.DstPort, r.Proto, r.Denied}
	if x := a.m[k]; x != nil {
		x.Bytes += r.Bytes
		x.Packets += r.Packets
		x.Flags |= r.Flags
		if r.End.After(x.End) {
			x.End = r.End
		}
		if x.SrcPort != r.SrcPort {
			x.SrcPort = 0 // 多个源端口
		}
		return false
	}
	c := r
	a.m[k] = &c
	max := a.Max
	if max <= 0 {
		max = 200000
	}
	return len(a.m) >= max
}

// Due 判断窗口是否已到期。
func (a *Aggregator) Due(now time.Time) bool {
	w := a.Window
	if w <= 0 {
		w = 10 * time.Second
	}
	return len(a.m) > 0 && now.Sub(a.start) >= w
}

// Flush 输出并清空窗口内的记录。
func (a *Aggregator) Flush(now time.Time) []Record {
	out := make([]Record, 0, len(a.m))
	for _, r := range a.m {
		out = append(out, *r)
	}
	clear(a.m)
	a.start = now
	return out
}

// Len 返回窗口内的键数。
func (a *Aggregator) Len() int { return len(a.m) }
