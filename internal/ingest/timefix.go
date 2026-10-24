package ingest

import (
	"log"
	"math"
	"strconv"
	"sync"
	"time"

	"netsa/internal/model"
)

// 很多日志的时间不带时区（传统 syslog、FortiGate、Cisco ASA、华为、Palo Alto 等），只能按配置的 timezone 解析。
// 当日志产生方实际按另一时区记录时（最常见的是服务器或设备使用 UTC，而 timezone 配置为 Asia/Shanghai），
// 所有事件都会整体偏移若干小时（如慢 8 小时）。
//
// timeFix 对实时日志（已追上文件末尾后新写入的行、syslog）比较“日志时间”与“接收时间”：
// 二者之差若持续稳定在某个时区差（15 分钟的整数倍，扣除少量写入延迟）上，即判定为时区不一致并自动校正。
// 历史日志（从头读取、离线分析）不参与判断；设备时间恢复正常后校正自动撤销。
type timeFix struct {
	mu     sync.Mutex
	name   string        // 用于日志输出
	cand   time.Duration // 当前候选偏差
	streak int           // 连续观测到候选偏差的次数
	since  time.Time     // 候选偏差首次出现的接收时间
	offset time.Duration // 已生效的校正量（加到事件时间上）
}

const (
	tzQuantum   = 15 * time.Minute // 时区偏差的最小单位
	tzTolerance = 5 * time.Minute  // 允许的写入 / 传输延迟
	tzMaxOffset = 14 * time.Hour   // 时区偏差的最大值（UTC-12 ~ UTC+14）
	tzStreak    = 10               // 连续多少条一致才生效 / 撤销
)

// tzHold 为候选偏差需持续的时间：设备断网恢复后集中补发的历史日志只持续数秒，不会被误判（测试中缩短）。
var tzHold = 30 * time.Second

// apply 用接收时间 now 观测事件时间并按当前校正量调整事件时间。
func (f *timeFix) apply(ev *model.Event, now time.Time) {
	if ev.Time.IsZero() {
		return
	}
	d := now.Sub(ev.Time) // 未校正的原始偏差
	q := time.Duration(math.Round(float64(d)/float64(tzQuantum))) * tzQuantum
	f.mu.Lock()
	if r := d - q; r >= -tzTolerance && r <= tzTolerance && q >= -tzMaxOffset && q <= tzMaxOffset {
		if q == f.cand && f.streak > 0 {
			f.streak++
		} else {
			f.cand, f.streak, f.since = q, 1, now
		}
		if f.streak >= tzStreak && now.Sub(f.since) >= tzHold && f.cand != f.offset {
			old := f.offset
			f.offset = f.cand
			f.mu.Unlock()
			f.report(old)
			f.mu.Lock()
		}
	}
	off := f.offset
	f.mu.Unlock()
	if off != 0 {
		ev.Time = ev.Time.Add(off)
	}
}

func (f *timeFix) report(old time.Duration) {
	f.mu.Lock()
	off := f.offset
	f.mu.Unlock()
	switch {
	case off == 0:
		log.Printf("[ingest] %s 的日志时间已与实际时间一致，撤销此前 %s 的自动校正", f.name, fmtOffset(old))
	case off > 0:
		log.Printf("[ingest] %s 的日志时间比实际时间慢 %s，已自动校正（日志产生方的时区可能与 timezone 配置不一致，例如按 UTC 记录）", f.name, fmtOffset(off))
	default:
		log.Printf("[ingest] %s 的日志时间比实际时间快 %s，已自动校正（日志产生方的时区可能与 timezone 配置不一致）", f.name, fmtOffset(-off))
	}
}

// current 返回当前校正量。
func (f *timeFix) current() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.offset
}

// fmtOffset 把校正量格式化为“8 小时”“5 小时 30 分钟”。
func fmtOffset(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case h > 0 && m > 0:
		return strconv.Itoa(h) + " 小时 " + strconv.Itoa(m) + " 分钟"
	case h > 0:
		return strconv.Itoa(h) + " 小时"
	}
	return strconv.Itoa(m) + " 分钟"
}

// describeOffset 返回展示用的校正说明，例如 "+8 小时"；未校正返回空字符串。
func describeOffset(d time.Duration) string {
	switch {
	case d > 0:
		return "+" + fmtOffset(d)
	case d < 0:
		return "-" + fmtOffset(d)
	}
	return ""
}
