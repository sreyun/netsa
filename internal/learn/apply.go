package learn

import (
	"fmt"
	"log"
	"time"
)

// confirmedSourcesLocked 返回最近一次人工结论为「确认攻击」的来源（调用方持锁）。
//
// 只看来源的最近一次结论：同一来源后来被判为误报（如确认是授权扫描），就不再升级它的命中。
// 有效期在热路径上按事件时间判断，这里不过滤，避免离线回放历史日志时漏掉。
func (l *Learner) confirmedSourcesLocked() map[string]confirmed {
	if !l.opt.Escalate {
		return nil
	}
	type last struct {
		confirmed
		tp bool
	}
	latest := map[string]last{}
	for _, c := range l.cases {
		if c.Source == "" {
			continue
		}
		if old, ok := latest[c.Source]; ok && !c.Time.After(old.time) {
			continue
		}
		latest[c.Source] = last{confirmed{incident: c.Incident, time: c.Time}, c.Verdict == VerdictTP}
	}
	out := make(map[string]confirmed, len(latest))
	for src, v := range latest {
		if v.tp {
			out[src] = v.confirmed
		}
	}
	return out
}

// clearedSourcesLocked 返回最近一次人工结论为「误报」的来源及结论时间（调用方持锁）：
// 这之后的自动确认（证据、模型、攻击活动）不再升级该来源的命中，以人的结论为准。
func (l *Learner) clearedSourcesLocked() map[string]time.Time {
	latest := map[string]*Case{}
	for _, c := range l.cases {
		if c.Source == "" {
			continue
		}
		if old := latest[c.Source]; old == nil || c.Time.After(old.Time) {
			latest[c.Source] = c
		}
	}
	out := map[string]time.Time{}
	for src, c := range latest {
		if c.Verdict == VerdictFP {
			out[src] = c.Time
		}
	}
	return out
}

// Policy 返回当前生效的自学习策略，以及是否来自界面设置。
func (l *Learner) Policy() (Policy, bool) {
	if l == nil {
		return Policy{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.policyLocked(), l.policy != nil
}

func (l *Learner) policyLocked() Policy {
	p := Policy{Calibrate: l.opt.Calibrate, MinVerdicts: l.opt.MinVerdicts, MaxPrecision: l.opt.MaxPrecision,
		Escalate: l.opt.Escalate, EscalateDays: l.opt.EscalateDays, WindowDays: max(l.opt.WindowDays, 0)}
	if l.policy != nil {
		p.UpdatedBy, p.Updated = l.policy.UpdatedBy, l.policy.Updated
	}
	return p
}

// SetPolicy 修改自学习策略并立即生效：重新计算校准结果，变化记入进化日志（同时写入审计链）。
func (l *Learner) SetPolicy(p Policy, user string) error {
	if l == nil {
		return fmt.Errorf("未启用自学习")
	}
	if err := p.check(); err != nil {
		return err
	}
	now := time.Now()
	p.UpdatedBy, p.Updated = user, now
	l.mu.Lock()
	before := l.policyLocked()
	l.policy = &p
	l.opt.apply(p)
	c := Change{Time: now, Kind: "policy", User: user, Detail: "修改自学习策略：" + describePolicy(before) + " → " + describePolicy(p)}
	l.logLocked(c)
	changes := append([]Change{c}, l.recomputeLocked(now, user)...)
	l.mu.Unlock()
	l.emit(changes)
	if err := l.Save(); err != nil { // 策略已生效；保存失败由下一次定时保存重试
		log.Printf("[learn] 保存学习状态失败: %v", err)
	}
	return nil
}

func describePolicy(p Policy) string {
	on := func(b bool) string {
		if b {
			return "开"
		}
		return "关"
	}
	return fmt.Sprintf("自动校准%s（样本 ≥ %d、准确率 ≤ %.0f%%）、确认攻击源复现升级%s（%d 天）、学习窗口 %d 天",
		on(p.Calibrate), p.MinVerdicts, p.MaxPrecision*100, on(p.Escalate), p.EscalateDays, p.WindowDays)
}

// appliedStats 返回自动生效次数（Applied 的计数为原子变量，无需持锁）。
func (l *Learner) appliedStats() Applied {
	return Applied{Rule: l.applied.rule.Load(), Target: l.applied.target.Load(), Escalated: l.applied.escalated.Load(), Since: l.applied.since}
}

// AppliedStats 返回自学习结果自动生效的次数（监控指标使用）。
func (l *Learner) AppliedStats() Applied {
	if l == nil {
		return Applied{}
	}
	return l.appliedStats()
}
