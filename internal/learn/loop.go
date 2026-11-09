package learn

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// 自我进化闭环：学到的东西自动生效之后，还要能发现自己学错了、撤销并修正已经产生的结果。
//
//   - 客观结论：不依赖分析员处置，从系统自己掌握的证据里得到“这个来源到底是不是攻击者”。
//     是攻击：有证据的成功利用、攻击后被攻击的主机回连、命中诱饵、与已确认攻击源同属一个攻击活动、分析员确认；
//     不是攻击：站点常客（自动确认后被撤销）、登记为授权扫描、分析员判为误报。
//   - 用客观结论评估外部模型：模型的“攻击 / 误报”判断与之比对，得到客观一致率；判为攻击的结论经核实误判较多时，
//     自动收紧按模型判断自动确认攻击源的条件（还要求来源本身的行为像攻击者），恢复正常后自动放开。
//   - 纠错回溯：撤销自动确认、停用观察规则时，通知状态库修正仍在处置的事件（见 store.Retract）。
//   - 自动处置：已经结束的低风险事件自动归档（见 store.AutoArchive），由策略控制。

const (
	maxOutcomes = 5000
	// 模型判为攻击的结论至少核实了这么多次、其中误判达到三成时，收紧按模型判断自动确认
	aiGateMinJudged = 3
	aiGateWrongPct  = 30
	// 自动归档默认天数：事件这么久没有新的活动才算结束
	defaultArchiveDays = 3
)

// Outcome 是对一个来源的客观结论。
type Outcome struct {
	IP     string    `json:"ip"`
	Attack bool      `json:"attack"`
	Reason string    `json:"reason"`
	Time   time.Time `json:"time"`
}

// LoopStats 统计自我纠错与自动处置的结果（持久化，累计）。
type LoopStats struct {
	Revoked   int             `json:"revoked"`            // 撤销的自动确认攻击源
	RulesOff  int             `json:"rules_off"`          // 停用的观察规则（被业务接口轮询自动停用、管理员停用）
	Retracted int             `json:"retracted"`          // 回溯修正的事件
	Restored  int             `json:"restored,omitempty"` // 纠错被纠正、恢复等级的事件（重新启用观察规则、被撤销的来源出现攻击证据）
	NetsOff   int             `json:"nets_off,omitempty"` // 撤销的自动识别内网网段（旧版本依据防火墙自身 local 域学到的）
	Archived  int             `json:"archived"`           // 自动归档的事件
	Migrated  bool            `json:"migrated,omitempty"` // 已从进化日志补齐旧版本的数据
	Gated     map[string]bool `json:"gated,omitempty"`
}

// LoopReport 是闭环的概览。
type LoopReport struct {
	LoopStats
	Outcomes    int  `json:"outcomes"`     // 已有客观结论的来源数
	ArchiveOn   bool `json:"archive_on"`   // 自动归档是否开启
	ArchiveDays int  `json:"archive_days"` // 多少天没有活动后归档
}

// noteOutcomeLocked 记录来源的客观结论（调用方持 l.mu）。分析员的结论另有记录，这里只记系统证据。
func (l *Learner) noteOutcomeLocked(ip string, attack bool, reason string, at time.Time) {
	if ip == "" {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	if len(l.outcomes) >= maxOutcomes && l.outcomes[ip] == nil {
		oldest, ot := "", time.Time{}
		for k, o := range l.outcomes {
			if oldest == "" || o.Time.Before(ot) {
				oldest, ot = k, o.Time
			}
		}
		delete(l.outcomes, oldest)
	}
	l.outcomes[ip] = &Outcome{IP: ip, Attack: attack, Reason: reason, Time: at}
	l.dirty = true
}

// NoteOutcome 记录系统之外的客观结论（如登记为授权扫描），并据此重新评估外部模型。ip 不是单个地址时忽略。
func (l *Learner) NoteOutcome(ip string, attack bool, reason string) {
	if l == nil {
		return
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return
	}
	now := time.Now()
	l.mu.Lock()
	l.noteOutcomeLocked(ip, attack, reason, now)
	cs := l.refreshAIStatsLocked(now)
	l.mu.Unlock()
	l.emit(cs)
}

// refreshAIStatsLocked 重新计算模型的研判表现，并在“收紧按模型判断自动确认”的状态变化时写进化日志（调用方持 l.mu）。
func (l *Learner) refreshAIStatsLocked(now time.Time) []Change {
	l.aiStats = l.aiStatsLocked()
	if l.loop.Gated == nil {
		l.loop.Gated = map[string]bool{}
	}
	var out []Change
	for i := range l.aiStats {
		st := &l.aiStats[i]
		gated := st.AtkJudged >= aiGateMinJudged && st.AtkWrong*100 >= st.AtkJudged*aiGateWrongPct
		st.Gated = gated
		if gated == l.loop.Gated[st.Model] {
			continue
		}
		var c Change
		if gated {
			l.loop.Gated[st.Model] = true
			c = Change{Time: now, Kind: "ai_gate", User: "自学习", Detail: fmt.Sprintf("收紧按模型判断自动确认攻击源：模型 %s 判为攻击的结论经核实 %d 次、其中 %d 次误判（%d%%），"+
				"之后只自动确认行为本身也像攻击者的来源（攻击命中占三成以上）", st.Model, st.AtkJudged, st.AtkWrong, st.AtkWrong*100/st.AtkJudged)}
		} else {
			delete(l.loop.Gated, st.Model)
			c = Change{Time: now, Kind: "ai_gate_off", User: "自学习", Detail: fmt.Sprintf("恢复按模型判断自动确认攻击源：模型 %s 判为攻击的结论经核实误判已低于 %d%%", st.Model, aiGateWrongPct)}
		}
		l.dirty = true
		l.logLocked(c)
		out = append(out, c)
	}
	return out
}

// aiGatedLocked 判断该模型的“判为攻击”是否已被收紧（调用方持 l.mu）。
func (l *Learner) aiGatedLocked(model string) bool { return l.loop.Gated[model] }

// RecordLoop 记录状态库完成的纠错回溯 / 自动归档（写进化日志与审计链）。
func (l *Learner) RecordLoop(kind string, n int, detail string) {
	if l == nil || n <= 0 {
		return
	}
	l.mu.Lock()
	switch kind {
	case "retract":
		l.loop.Retracted += n
	case "unretract":
		l.loop.Restored += n
	case "auto_archive":
		l.loop.Archived += n
	}
	c := Change{Time: time.Now(), Kind: kind, User: "自学习", Detail: detail}
	l.logLocked(c)
	l.dirty = true
	l.mu.Unlock()
	l.emit([]Change{c})
}

// retract 通知状态库回溯修正（异步：调用方可能在检测流水线上，不能与状态库的锁交叉）。
func (l *Learner) retract(rule, ip, why string) {
	if f := l.OnRetract; f != nil {
		l.cbq.do(func() { f(rule, ip, why) })
	}
}

// restore 通知状态库撤销纠错（异步，同 retract）。
func (l *Learner) restore(rule, ip, why string) {
	if f := l.OnRestore; f != nil {
		l.cbq.do(func() { f(rule, ip, why) })
	}
}

// callbackQueue 按调用顺序串行执行回调，不阻塞调用方。回溯与恢复各开一个协程会乱序：
// 管理员停用观察规则后随即重新启用，恢复可能先于回溯执行，规则已启用、告警却停留在已撤销的状态。
type callbackQueue struct {
	mu      sync.Mutex
	q       []func()
	running bool
}

func (c *callbackQueue) do(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.q = append(c.q, f)
	if !c.running {
		c.running = true
		go c.drain()
	}
}

func (c *callbackQueue) drain() {
	for {
		c.mu.Lock()
		if len(c.q) == 0 {
			c.running = false
			c.mu.Unlock()
			return
		}
		f := c.q[0]
		c.q[0] = nil
		c.q = c.q[1:]
		c.mu.Unlock()
		f()
	}
}

// regularOutcome 判断客观结论是否为“站点常客”（自动确认因此被撤销、告警因此回溯修正过）。
func regularOutcome(o *Outcome) bool {
	return o != nil && !o.Attack && strings.HasPrefix(o.Reason, "站点常客")
}

// ArchivePolicy 返回是否自动归档已结束的低风险事件，以及多少天没有活动后归档。
func (l *Learner) ArchivePolicy() (bool, int) {
	if l == nil {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.opt.ArchiveOff, archiveDays(l.opt.ArchiveDays)
}

func archiveDays(d int) int {
	if d <= 0 {
		return defaultArchiveDays
	}
	return d
}

// loopReportLocked 汇总闭环状态（调用方持 l.mu）。
func (l *Learner) loopReportLocked() LoopReport {
	r := LoopReport{LoopStats: l.loop, Outcomes: len(l.outcomes), ArchiveOn: !l.opt.ArchiveOff, ArchiveDays: archiveDays(l.opt.ArchiveDays)}
	r.Gated = nil
	for m, g := range l.loop.Gated {
		if g {
			if r.Gated == nil {
				r.Gated = map[string]bool{}
			}
			r.Gated[m] = true
		}
	}
	return r
}

// outcomeListLocked 返回按时间排序的客观结论（持久化用，调用方持 l.mu）。
func (l *Learner) outcomeListLocked() []Outcome {
	out := make([]Outcome, 0, len(l.outcomes))
	for _, o := range l.outcomes {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// migrateLoopLocked 从进化日志补齐旧版本的闭环数据（加载时调用一次，返回是否补齐过）：
// 1.10.6 / 1.10.7 撤销自动确认、停用观察规则时还没有客观结论与统计，补齐后模型能据此评估，页面统计完整。
func (l *Learner) migrateLoopLocked() bool {
	if l.loop.Migrated {
		return false
	}
	for _, c := range l.changes {
		switch c.Kind {
		case "revoke_auto":
			ip := c.IP
			if ip == "" {
				ip = ipAfter(c.Detail, "撤销自动确认的攻击源 ")
			}
			if ip == "" {
				continue
			}
			l.loop.Revoked++
			if l.outcomes[ip] == nil {
				l.outcomes[ip] = &Outcome{IP: ip, Reason: "站点常客：大量正常访问、攻击命中不到一成", Time: c.Time}
			}
		case "discover_auto_off", "discover_disable":
			l.loop.RulesOff++
		}
	}
	l.loop.Migrated = true
	l.dirty = true
	return true
}

// ipAfter 取出说明文字中某个前缀之后的地址。
func ipAfter(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	s = s[i+len(prefix):]
	if j := strings.IndexAny(s, "（( ：:，"); j >= 0 {
		s = s[:j]
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return ""
	}
	return s
}

// ReplayRetractions 对已停用的观察规则、已撤销的自动确认（站点常客）补做纠错回溯，对重新启用的观察规则补做恢复
// （启动时、状态库加载后调用）。状态库的回溯与恢复都是幂等的：已经修正过的事件不会再次调整。
func (l *Learner) ReplayRetractions() {
	if l == nil || l.OnRetract == nil {
		return
	}
	l.mu.Lock()
	var ips []string
	for ip, o := range l.outcomes {
		if regularOutcome(o) {
			ips = append(ips, ip)
		}
	}
	l.mu.Unlock()
	st := &l.atk
	st.mu.Lock()
	var rules, kept [][2]string
	for shape, r := range st.rules {
		switch {
		case r.Disabled:
			rules = append(rules, [2]string{r.ID, shape})
		case r.Kept: // 管理员重新启用（或确认保留）的规则：此前若被回溯撤销过，补做恢复（撤销纠错只在内存中，可能没来得及保存）
			kept = append(kept, [2]string{r.ID, shape})
		}
	}
	st.mu.Unlock()
	sort.Strings(ips)
	for _, ip := range ips {
		l.retract("", ip, "撤销了对 "+ip+" 的自动确认（站点常客）")
	}
	for _, r := range rules {
		l.retract(r[0], "", "观察规则 "+clipShape(r[1])+" 已停用")
	}
	for _, r := range kept {
		l.restore(r[0], "", "观察规则 "+clipShape(r[1])+" 已重新启用")
	}
}
