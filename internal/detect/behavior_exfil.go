package detect

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strings"
	"time"

	"netsa/internal/model"
)

// 数据窃取：
//   - 数据外传（bhv-exfil）：按内网主机统计外发字节（防火墙会话日志的发送字节数），exfil_window 内达到 exfil_bytes
//     且为该主机平时的 10 倍以上；平时没有足够记录时，按 exfil_bytes 的 4 倍判断。基线是每个窗口外发字节数的
//     指数滑动平均，突增窗口不计入。证据中列出主要的外发目的地址。
//   - 大量下载（bhv-download）：单个外部来源 download_window 内从动态接口、文件下载的响应字节数达到 download_bytes。
//     图片、音视频、样式脚本等静态资源不计入（视频站、图床的正常访问量很大）。
// 只有会话结束时输出的防火墙日志才有字节数；只记录会话建立的设备、UFW 这类逐包日志无法统计外发流量。

const (
	maxExfilHosts = 20000
	maxExfilDsts  = 32
	maxDownloads  = 50000
	exfilFactor   = 10 // 外发量达到平时的倍数
	exfilImmature = 4  // 基线不成熟时按阈值的倍数判断
)

type exfilWin struct {
	surgeBase
	bytes int64 // 固定窗口内的外发量（基线）
	slide slideSum
	dsts  map[string]int64
	fired time.Time
}

// slideSlots 是滑动窗口的分槽数。
const slideSlots = 10

// slideSum 是按时间分槽的滑动窗口累计：一次突发跨过固定窗口的边界时不会被拆成两半而漏报。
// 窗口按已记录的最新时间计算，乱序到达的较早日志只要还在窗口内照样计入。
type slideSum struct {
	at  [slideSlots]int64 // 槽的编号（时间 / 槽宽）
	sum [slideSlots]int64
	cnt [slideSlots]int32
}

// add 计入一次并返回窗口内的累计量与次数。
func (s *slideSum) add(t time.Time, win time.Duration, n int64) (int64, int) {
	w := max(int64(win)/slideSlots, 1)
	id := t.UnixNano() / w
	i := int((id%slideSlots + slideSlots) % slideSlots)
	switch {
	case s.at[i] == id:
		s.sum[i] = satAdd(s.sum[i], n)
		s.cnt[i]++
	case s.at[i] < id:
		s.at[i], s.sum[i], s.cnt[i] = id, n, 1
	} // 比槽中记录还早一个窗口以上的日志：已在窗口之外
	hi := id
	for _, a := range s.at {
		hi = max(hi, a)
	}
	var total int64
	count := 0
	for j, a := range s.at {
		if d := hi - a; d >= 0 && d < slideSlots {
			total = satAdd(total, s.sum[j])
			count += int(s.cnt[j])
		}
	}
	return total, count
}

// observeExfil 统计内网主机外发的字节数（调用方持锁）。
func (b *Behavior) observeExfil(ev *model.Event) (model.Hit, bool) {
	if ev.SentBytes <= 0 || ev.SrcIP == "" {
		return model.Hit{}, false
	}
	sent := windowShare(ev.SentBytes, ev.Duration, b.th.ExfilWindow)
	w := b.exfil[ev.SrcIP]
	if w == nil {
		if len(b.exfil) >= maxExfilHosts {
			return model.Hit{}, false
		}
		w = &exfilWin{dsts: map[string]int64{}}
		b.exfil[ev.SrcIP] = w
	}
	if w.rollBytes(ev.Time, b.th.ExfilWindow, w.bytes) {
		w.bytes = 0
		clear(w.dsts)
	}
	w.bytes = satAdd(w.bytes, sent)
	total, sessions := w.slide.add(ev.Time, b.th.ExfilWindow, sent)
	if _, ok := w.dsts[ev.DstIP]; ok || len(w.dsts) < maxExfilDsts {
		w.dsts[ev.DstIP] = satAdd(w.dsts[ev.DstIP], sent)
	}
	need := b.th.ExfilBytes * exfilImmature
	if w.windows >= surgeMature {
		need = max(b.th.ExfilBytes, int64(min(w.base*exfilFactor, 9e18)))
	}
	if !w.fired.IsZero() && ev.Time.Sub(w.fired).Abs() < b.th.ExfilWindow {
		w.surge = true // 突增延续到下一个窗口：同样不计入基线，也不重复告警
	}
	if w.surge || total < need {
		return model.Hit{}, false
	}
	w.surge, w.fired = true, ev.Time // 突增窗口不计入基线
	base := "平时没有足够的记录"
	if w.windows >= surgeMature {
		base = "平时约 " + fmtBytes(int64(min(w.base, 9e18)))
	}
	top, topBytes := "", int64(0)
	for d, n := range w.dsts {
		if n > topBytes || n == topBytes && d < top {
			top, topBytes = d, n
		}
	}
	sev := model.SevMedium
	if w.windows >= surgeMature {
		sev = model.SevHigh // 与该主机自己的基线相比暴增
	}
	return model.Hit{RuleID: "bhv-exfil", Name: "外发流量突增（疑似数据外传）", Category: CatExfil, Severity: sev, Phase: model.PhaseCollection,
		Result: fwResult(ev),
		Evidence: fmt.Sprintf("%s内 %s 向外发送 %s（%s），%d 个会话；主要目的地址 %s（%s，%d%%）", fmtDur(b.th.ExfilWindow), ev.SrcIP,
			fmtBytes(total), base, sessions, top, fmtBytes(topBytes), min(topBytes*100/max(total, 1), 100))}, true
}

// windowShare 返回一个统计窗口内的量：长连接结束时一次性报告的字节数、包数按持续时间平均折算，
// 持续时间不超过窗口（或没有记录）时全部计入。否则一个持续两小时的备份会话会在结束的那个窗口里显得像一次突发。
func windowShare(n int64, dur float64, win time.Duration) int64 {
	n = min(n, maxCount) // 日志与数据包中的计数来自外部，异常的巨大值不能让累计溢出
	if n <= 0 || dur <= win.Seconds() {
		return n
	}
	return int64(float64(n) * win.Seconds() / dur)
}

// maxCount 是单条记录计入的字节数 / 包数上限（1 PB），satAdd 是不会溢出的加法：伪造的超大计数只会让统计封顶，
// 不会因为溢出变成负数而让检测失效。
const maxCount = 1 << 50

func satAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// rollBytes 与 roll 相同，但按窗口内的字节数而不是事件数累计基线。
func (s *surgeBase) rollBytes(t time.Time, win time.Duration, bytes int64) bool {
	s.n = int(min(bytes, 1<<40))
	return s.roll(t, win)
}

type dlWin struct {
	start time.Time // 路径统计的起点（保留两个窗口）
	last  time.Time
	slide slideSum
	paths map[string]int64
	fired time.Time
}

// staticMedia 是不计入下载量的静态资源：图片、音视频、字体、样式与脚本。
var staticMedia = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".svg": true, ".ico": true,
	".bmp": true, ".avif": true, ".mp4": true, ".m4s": true, ".m3u8": true, ".ts": true, ".flv": true, ".webm": true, ".mp3": true,
	".m4a": true, ".aac": true, ".ogg": true, ".wav": true, ".css": true, ".js": true, ".woff": true, ".woff2": true, ".ttf": true, ".map": true}

// observeDownload 统计外部来源的下载量（调用方持锁）。
func (b *Behavior) observeDownload(ev *model.Event) (model.Hit, bool) {
	if ev.Bytes <= 0 || ev.Status < 200 || ev.Status >= 300 || isPrivateIP(ev.SrcIP) {
		return model.Hit{}, false
	}
	p := ev.URI
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if staticMedia[strings.ToLower(path.Ext(p))] {
		return model.Hit{}, false
	}
	w := b.downloads[ev.SrcIP]
	if w == nil {
		if len(b.downloads) >= maxDownloads {
			return model.Hit{}, false
		}
		w = &dlWin{start: ev.Time, last: ev.Time}
		b.downloads[ev.SrcIP] = w
	}
	if outside(ev.Time, w.start, 2*b.th.DownloadWindow) {
		w.start, w.paths = ev.Time, nil
	}
	if ev.Time.After(w.last) {
		w.last = ev.Time
	}
	bytes, reqs := w.slide.add(ev.Time, b.th.DownloadWindow, ev.Bytes)
	if w.paths == nil {
		w.paths = map[string]int64{}
	}
	if _, ok := w.paths[p]; ok || len(w.paths) < 64 {
		w.paths[p] += ev.Bytes
	}
	if !w.fired.IsZero() && ev.Time.Sub(w.fired).Abs() < b.th.DownloadWindow || bytes < b.th.DownloadBytes {
		return model.Hit{}, false
	}
	w.fired = ev.Time
	type kv struct {
		p string
		n int64
	}
	var top []kv
	for k, v := range w.paths {
		top = append(top, kv{k, v})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n || top[i].n == top[j].n && top[i].p < top[j].p })
	var names []string
	for i := 0; i < len(top) && i < 3; i++ {
		names = append(names, Printable(top[i].p, 80)+"（"+fmtBytes(top[i].n)+"）")
	}
	sev := model.SevMedium
	if t, ok := b.attacked[ev.SrcIP]; ok && ev.Time.Sub(t) < 24*time.Hour {
		sev = model.SevHigh // 该来源此前发起过攻击
	}
	return model.Hit{RuleID: "bhv-download", Name: "单来源下载量突增", Category: CatDownload, Severity: sev, Phase: model.PhaseCollection,
		Result:   model.ResultSuccess,
		Evidence: fmt.Sprintf("%s内下载 %s，%d 个请求；主要路径 %s", fmtDur(b.th.DownloadWindow), fmtBytes(bytes), reqs, strings.Join(names, "、"))}, true
}

// pruneExfil 清理长时间没有流量的窗口（调用方持锁）。
func (b *Behavior) pruneExfil(now time.Time) {
	for k, w := range b.exfil {
		if outside(now, w.start, 24*time.Hour) {
			delete(b.exfil, k)
		}
	}
	for k, w := range b.downloads {
		if outside(now, w.last, 2*b.th.DownloadWindow) {
			delete(b.downloads, k)
		}
	}
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
