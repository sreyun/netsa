package store

import (
	"time"

	"netsa/internal/model"
	"netsa/internal/risk"
)

// 没有来源的设备威胁：防火墙攻击防范的多源洪泛日志（H3C ATK_IP4_TCP_SYNFLOOD 等）只记录被攻击的目的地址，
// 来源是大量伪造地址。不建立来源画像、不归入以来源为单位的安全事件；计入攻击统计与资产攻击链路（影响阶段），
// 并按目的地址生成告警（同一目的地址、同一攻击类型 10 分钟内一条）。

// noSourceLabel 是这类告警的来源描述。
const noSourceLabel = "多个来源（设备未记录来源）"

const maxNoSourceKeys = 10000

// recordNoSourceLocked 记录没有来源的设备威胁（调用方持写锁，已计入总量与时间桶）。
func (s *Store) recordNoSourceLocked(ev *model.Event, hits []model.Hit, b *Bucket, day *DayStat) RecordResult {
	var res RecordResult
	var roles chainRoles
	t := ev.Time
	if now := time.Now(); t.After(now.Add(time.Hour)) || t.Year() < 2000 {
		t = now
	}
	for i := range hits {
		h := &hits[i]
		if h.TagOnly {
			continue
		}
		risk.Finalize(h)
		s.totals.Attacks++
		day.recordHit(h)
		b.Attacks++
		b.Sev[h.Severity]++
		s.sevCount[h.Severity]++
		s.categories[h.Category]++
		s.rules[h.RuleID]++
		s.ruleNames[h.RuleID] = h.Name
		s.phases[h.Phase]++
		s.results[h.Result]++
		if h.Result == model.ResultBlocked {
			s.totals.Blocked++
			b.Blocked++
		}
		if h.Result == model.ResultSuccess {
			s.totals.Success++
			b.Success++
		}
		var id uint64
		if a := s.noSourceAlertLocked(ev, h); a != nil {
			res.Alerts = append(res.Alerts, a)
			id = a.ID
		}
		if !roles.done {
			roles = s.chainRolesOf(ev)
		}
		s.chainHitLocked(ev, h, &roles, t, id, 0)
	}
	day.Alerts += int64(len(res.Alerts))
	return res
}

// noSourceAlertLocked 按目的地址与攻击类型生成告警，10 分钟内同一目的地址、同一攻击类型只生成一条。
func (s *Store) noSourceAlertLocked(ev *model.Event, h *model.Hit) *model.Alert {
	if s.noSrcSeen == nil || len(s.noSrcSeen) >= maxNoSourceKeys {
		s.noSrcSeen = map[string]time.Time{}
	}
	key := ev.DstIP + "|" + h.RuleID + "|" + h.Name
	if last, ok := s.noSrcSeen[key]; ok && ev.Time.Sub(last) < throttleWindow && last.Sub(ev.Time) < throttleWindow {
		return nil
	}
	s.noSrcSeen[key] = ev.Time
	s.nextID++
	s.totals.Alerts++
	a := &model.Alert{
		ID: s.nextID, Time: ev.Time, Kind: ev.Kind, Location: noSourceLabel, RuleID: h.RuleID, Name: h.Name,
		Category: h.Category, Severity: h.Severity, Phase: h.Phase, Result: h.Result, Target: truncate(ev.Target(), 300),
		Evidence: printable(h.Evidence), Source: ev.Source, Vuln: h.Vuln, Proven: h.Proven,
	}
	if r := ev.Asset; r != nil {
		a.Asset, a.AssetLevel, a.Owner = r.Name, r.Level, r.Owner
	}
	s.appendAlertLocked(a)
	return a
}

// appendAlertLocked 把告警放入保留的环形缓冲区（调用方持写锁）。
func (s *Store) appendAlertLocked(a *model.Alert) {
	if len(s.alerts) < s.maxAlerts {
		s.alerts = append(s.alerts, a)
	} else {
		s.alerts[s.alertHead] = a
		s.alertHead = (s.alertHead + 1) % s.maxAlerts
	}
}
