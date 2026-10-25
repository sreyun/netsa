package ingest

import (
	"strconv"
	"time"
)

// silenceState 是一个断流检测分组（配置的数据源 / syslog 监听）的状态，由每分钟一次的 CheckSilence 更新，读取日志的热路径没有额外开销。
type silenceState struct {
	prevLines  int64
	prevFailed int64
	active     time.Time // 最近一次发现新日志的时间
	seen       bool      // 启动后读到过日志：从未有过日志的数据源（如尚未投入使用的监听）不告警
	silent     bool
	parseAlert time.Time // 最近一次解析失败率告警
}

// SourceNotice 是数据源层面的通知。
type SourceNotice struct {
	Kind    string // silent 断流 / recovered 恢复 / parse_errors 解析失败率过高
	Source  string
	Detail  string
	Last    time.Time
	Silence time.Duration
}

const (
	parseAlertMinLines = 100       // 一分钟内至少读到这么多行才判断解析失败率
	parseAlertRatio    = 0.5       // 解析失败率超过该比例时告警
	parseAlertGap      = time.Hour // 同一数据源的解析失败率告警间隔
)

func liveStatus(st string) bool { return st == "tailing" || st == "waiting" || st == "listening" }

// CheckSilence 每分钟调用一次：实时数据源（跟踪中的文件、syslog 监听）超过阈值没有新日志时返回断流通知，恢复后返回恢复通知；
// 一分钟内解析失败率超过一半时返回解析异常通知（通常是日志格式被修改，检测随之失效）。默认阈值为 DefaultSilence（0 表示默认关闭）。
func (m *Manager) CheckSilence(now time.Time) []SourceNotice {
	def := m.DefaultSilence
	type agg struct {
		lines, failed int64
		silence       time.Duration
		live          bool
	}
	m.mu.Lock()
	srcs := append([]*source(nil), m.sources...)
	m.mu.Unlock()
	groups := map[string]*agg{}
	var order []string
	for _, s := range srcs {
		if s.group == "" {
			continue
		}
		g := groups[s.group]
		if g == nil {
			g = &agg{silence: def}
			if s.silence >= 0 {
				g.silence = s.silence
			}
			groups[s.group] = g
			order = append(order, s.group)
		}
		g.lines += s.lines.Load()
		g.failed += s.failed.Load()
		s.mu.Lock()
		g.live = g.live || liveStatus(s.status)
		s.mu.Unlock()
	}
	var out []SourceNotice
	m.smu.Lock()
	defer m.smu.Unlock()
	if m.silence == nil {
		m.silence = map[string]*silenceState{}
	}
	for _, name := range order {
		g := groups[name]
		st := m.silence[name]
		if st == nil {
			st = &silenceState{prevLines: g.lines, prevFailed: g.failed, active: now, seen: g.lines > 0}
			m.silence[name] = st
			continue
		}
		dl, df := g.lines-st.prevLines, g.failed-st.prevFailed
		st.prevLines, st.prevFailed = g.lines, g.failed
		if dl > 0 {
			st.active, st.seen = now, true
			if st.silent {
				st.silent = false
				out = append(out, SourceNotice{Kind: "recovered", Source: name, Detail: "已恢复读取日志", Last: now, Silence: g.silence})
			}
			if dl >= parseAlertMinLines && float64(df) > float64(dl)*parseAlertRatio && now.Sub(st.parseAlert) >= parseAlertGap {
				st.parseAlert = now
				out = append(out, SourceNotice{Kind: "parse_errors", Source: name, Last: now,
					Detail: "近 1 分钟读取 " + strconv.FormatInt(dl, 10) + " 行，其中 " + strconv.FormatInt(df, 10) + " 行无法解析（" +
						strconv.Itoa(int(float64(df)*100/float64(dl))) + "%），日志格式可能已被修改，检测可能失效"})
			}
			continue
		}
		if !g.live || !st.seen || g.silence <= 0 || st.silent || now.Sub(st.active) <= g.silence {
			continue
		}
		st.silent = true
		out = append(out, SourceNotice{Kind: "silent", Source: name, Last: st.active, Silence: g.silence,
			Detail: "已超过 " + fmtDur(g.silence) + " 没有新日志"})
	}
	return out
}

// silenceView 返回分组的断流状态（供状态页展示）。
func (m *Manager) silenceView(group string, own time.Duration) (string, bool, time.Time) {
	d := m.DefaultSilence
	if own >= 0 {
		d = own
	}
	m.smu.Lock()
	defer m.smu.Unlock()
	st := m.silence[group]
	if st == nil {
		return silenceText(d), false, time.Time{}
	}
	return silenceText(d), st.silent, st.active
}
