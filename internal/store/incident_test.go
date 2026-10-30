package store

import (
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/model"
)

func TestIncidentLifecycle(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	ip := "203.0.113.20"
	rec := func(at time.Time, rule string, sev model.Severity, result string) *model.Alert {
		res := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/a?" + rule, Status: 403, Time: at},
			[]model.Hit{attackHit(rule, "XSS跨站脚本", sev, result)})
		if len(res.Alerts) != 1 {
			t.Fatalf("应产生告警: %+v", res)
		}
		return res.Alerts[0]
	}
	a1 := rec(now, "r1", model.SevMedium, model.ResultBlocked)
	a2 := rec(now.Add(time.Minute), "r2", model.SevMedium, model.ResultPassed)
	if a1.IncidentID == 0 || a1.IncidentID != a2.IncidentID {
		t.Fatalf("同一来源的告警应归入同一事件: %d %d", a1.IncidentID, a2.IncidentID)
	}
	list, total, counts := s.Incidents(IncidentQuery{Status: "active"})
	if total != 1 || counts.Open != 1 || list[0].Alerts != 2 || list[0].Severity != model.SevMedium {
		t.Fatalf("事件列表: %+v %+v", list, counts)
	}
	due := list[0].Due
	if d := due.Sub(list[0].Created); d != 24*time.Hour {
		t.Fatalf("中危事件处置时限应为 24 小时: %v", d)
	}
	// 等级升高：时限缩短为高危的 4 小时
	rec(now.Add(2*time.Minute), "r3", model.SevHigh, model.ResultSuccess)
	d := s.Incident(a1.IncidentID)
	if d.Severity != model.SevHigh || d.Success != 1 || d.Due.Sub(d.Created) != 4*time.Hour || len(d.AlertList) != 3 || len(d.Rules) != 3 {
		t.Fatalf("等级升高后: %+v", d.IncidentView)
	}

	// 处置：关闭必须填写说明
	if _, err := s.UpdateIncidents([]uint64{a1.IncidentID}, "alice", IncidentUpdate{Status: IncFalsePositive}); err != ErrIncClose {
		t.Fatalf("关闭事件应要求说明: %v", err)
	}
	if _, err := s.UpdateIncidents([]uint64{a1.IncidentID}, "alice", IncidentUpdate{Status: "bogus"}); err != ErrIncStatus {
		t.Fatal("应拒绝无效状态")
	}
	// 批量处置中含不存在的事件：整体失败，已存在的事件不能被部分修改
	if _, err := s.UpdateIncidents([]uint64{a1.IncidentID, 999}, "alice", IncidentUpdate{Status: IncInvestigating, Note: "批量"}); err != ErrNoIncident {
		t.Fatalf("批量处置含不存在的事件应报错: %v", err)
	}
	if d := s.Incident(a1.IncidentID); d.Status != IncOpen || len(d.Notes) != 0 {
		t.Fatalf("批量处置失败时不应部分生效: %s %+v", d.Status, d.Notes)
	}
	if _, err := s.UpdateIncidents([]uint64{999}, "alice", IncidentUpdate{Note: "x"}); err != ErrNoIncident {
		t.Fatal("事件不存在")
	}
	bob := "bob"
	v, err := s.UpdateIncidents([]uint64{a1.IncidentID}, "alice", IncidentUpdate{Status: IncInvestigating, Assignee: &bob, Note: "开始排查"})
	if err != nil || v[0].Status != IncInvestigating || v[0].Assignee != "bob" || v[0].Notes != 1 {
		t.Fatalf("处置: %v %+v", err, v)
	}
	v, _ = s.UpdateIncidents([]uint64{a1.IncidentID}, "bob", IncidentUpdate{Status: IncFalsePositive, Note: "搜索接口误报"})
	if v[0].Status != IncFalsePositive || v[0].Closed.IsZero() {
		t.Fatalf("标记误报: %+v", v)
	}
	// 误报事件出现同等级告警：仍归入该事件，不重新打开
	a4 := rec(now.Add(3*time.Minute), "r4", model.SevHigh, model.ResultPassed)
	if a4.IncidentID != a1.IncidentID || s.Incident(a1.IncidentID).Status != IncFalsePositive {
		t.Fatal("误报事件出现同等级告警不应重新打开")
	}
	// 出现更高等级的告警：自动重新打开
	rec(now.Add(4*time.Minute), "r5", model.SevCritical, model.ResultSuccess)
	d = s.Incident(a1.IncidentID)
	if d.Status != IncOpen || !d.Closed.IsZero() || time.Until(d.Due) > time.Hour || d.Notes[len(d.Notes)-1].User != "系统" {
		t.Fatalf("更高等级的告警应重新打开事件: %+v", d.IncidentView)
	}
	// 已处置后再出现告警：新事件
	s.UpdateIncidents([]uint64{a1.IncidentID}, "bob", IncidentUpdate{Status: IncResolved, Note: "已封禁"})
	a6 := rec(now.Add(5*time.Minute), "r6", model.SevLow, model.ResultPassed)
	if a6.IncidentID == a1.IncidentID {
		t.Fatal("已处置事件之后的告警应归入新事件")
	}
	// 长时间无活动后再出现：新事件
	a7 := rec(now.Add(30*time.Hour), "r7", model.SevLow, model.ResultPassed)
	if a7.IncidentID == a6.IncidentID {
		t.Fatal("超过 24 小时无告警后应归入新事件")
	}
	_, total, counts = s.Incidents(IncidentQuery{})
	if total != 3 || counts.Resolved != 1 || counts.Open != 2 {
		t.Fatalf("计数: %d %+v", total, counts)
	}
	if l, _, _ := s.Incidents(IncidentQuery{Search: ip, Status: "closed"}); len(l) != 1 || l[0].ID != a1.IncidentID {
		t.Fatalf("搜索 / 已关闭过滤: %+v", l)
	}

	// 超时提醒只返回一次
	s.mu.Lock()
	s.incidents[a6.IncidentID].Due = time.Now().Add(-time.Minute)
	s.mu.Unlock()
	if o := s.TakeOverdue(); len(o) != 1 || o[0].ID != a6.IncidentID || !o[0].Overdue {
		t.Fatalf("超时提醒: %+v", o)
	}
	if o := s.TakeOverdue(); len(o) != 0 {
		t.Fatal("超时提醒不应重复")
	}
	if _, _, c := s.Incidents(IncidentQuery{}); c.Overdue != 1 {
		t.Fatalf("超时计数: %+v", c)
	}

	// 快照恢复
	path := filepath.Join(t.TempDir(), "s.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore()
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := s2.Incidents(IncidentQuery{}); total != 3 {
		t.Fatalf("快照恢复后事件数: %d", total)
	}
	d2 := s2.Incident(a1.IncidentID)
	if d2 == nil || d2.Status != IncResolved || d2.Assignee != "bob" || len(d2.Notes) != len(s.Incident(a1.IncidentID).Notes) {
		t.Fatalf("快照恢复后事件详情: %+v", d2)
	}
	a8 := s2.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, URI: "/z", Time: now.Add(30*time.Hour + time.Minute)},
		[]model.Hit{attackHit("r8", "SQL注入", model.SevLow, model.ResultPassed)}).Alerts[0]
	if a8.IncidentID != a7.IncidentID {
		t.Fatalf("快照恢复后应继续归入最近的事件: %d %d", a8.IncidentID, a7.IncidentID)
	}
}

func TestIncidentEviction(t *testing.T) {
	s := New(maxIncidents*2, 100, 5, time.Hour)
	now := time.Now()
	for i := 0; i <= maxIncidents; i++ {
		ip := "10." + itoa(i>>16&255) + "." + itoa(i>>8&255) + "." + itoa(i&255)
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, URI: "/x", Time: now}, []model.Hit{attackHit("r", "SQL注入", model.SevLow, model.ResultPassed)})
	}
	s.mu.RLock()
	n, keys := len(s.incidents), len(s.incByKey)
	_, last := s.incidents[s.nextInc]
	s.mu.RUnlock()
	if n != maxIncidents*9/10 || keys != n || !last {
		t.Fatalf("批量淘汰后: %d %d %v", n, keys, last)
	}
}
