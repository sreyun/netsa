package store

import (
	"testing"
	"time"

	"netsa/internal/model"
)

// TestIncidentHitVersusAlert 校验「命中次数」与「告警条数」两个口径：
// 同一 IP 同一规则在节流窗口内只生成前 N 条告警，其余命中只计数，二者必须能对上。
func TestIncidentHitVersusAlert(t *testing.T) {
	s := New(1000, 1000, 2, 24*time.Hour) // alerts_per_rule = 2
	base := time.Now().Add(-time.Minute)
	var evs []*model.Event
	var hits [][]model.Hit
	for i := 0; i < 5; i++ {
		evs = append(evs, &model.Event{
			Time: base.Add(time.Duration(i) * time.Second), Kind: model.KindFirewall,
			SrcIP: "203.0.113.9", DstIP: "43.242.97.40", DstPort: 1433, Proto: "tcp", Action: model.ActionAllow,
		})
		hits = append(hits, []model.Hit{{
			RuleID: "fw-riskport", Name: "高危服务端口探测(MSSQL)", Category: "高危服务探测",
			Severity: model.SevMedium, Phase: model.PhaseRecon, Result: model.ResultSuccess,
		}})
	}
	s.RecordBatch(evs, hits)

	list, _, _ := s.Incidents(IncidentQuery{})
	if len(list) != 1 {
		t.Fatalf("应合并为 1 个事件，实际 %d", len(list))
	}
	d := s.Incident(list[0].ID)
	if d.Alerts != 2 || d.Hits != 5 || d.Muted != 3 {
		t.Fatalf("告警/命中/节流计数不符: alerts=%d hits=%d muted=%d", d.Alerts, d.Hits, d.Muted)
	}
	if d.Hits != d.Alerts+d.Muted {
		t.Fatalf("命中应等于告警加节流: %d != %d + %d", d.Hits, d.Alerts, d.Muted)
	}
	// 疑似成功、攻击类型同样按命中口径统计，不能只统计生成了告警的那几条
	if d.Success != 5 {
		t.Fatalf("疑似成功应按命中计: %d", d.Success)
	}
	if len(d.Categories) != 1 || d.Categories[0] != "高危服务探测" {
		t.Fatalf("攻击类型缺失: %+v", d.Categories)
	}
	if len(d.Rules) != 1 || d.Rules[0].Value != 5 || d.Rules[0].Alerts != 2 {
		t.Fatalf("规则应区分命中与告警: %+v", d.Rules)
	}
	// 攻击目标按命中次数计（与命中规则口径一致）
	if len(d.Targets) != 1 || d.Targets[0].Value != 5 {
		t.Fatalf("目标计数不符: %+v", d.Targets)
	}
	if len(d.AlertList) != 2 {
		t.Fatalf("内存中应保留 2 条告警，实际 %d", len(d.AlertList))
	}
	// 列表视图同样带两个口径
	if v := list[0]; v.Alerts != 2 || v.Hits != 5 || v.Muted != 3 {
		t.Fatalf("事件列表口径不符: %+v", v)
	}

	// 画像的规则统计同样区分命中与告警
	det := s.IPDetail("203.0.113.9")
	if len(det.Rules) != 1 || det.Rules[0].Count != 5 || det.Rules[0].Alerts != 2 {
		t.Fatalf("画像规则统计不符: %+v", det.Rules)
	}
}

// TestIncidentCountsSurviveSnapshot 确认两个计数随快照持久化，恢复后仍然自洽。
func TestIncidentCountsSurviveSnapshot(t *testing.T) {
	s := New(100, 100, 1, time.Hour)
	base := time.Now().Add(-time.Minute)
	var evs []*model.Event
	var hits [][]model.Hit
	for i := 0; i < 3; i++ {
		evs = append(evs, &model.Event{Time: base.Add(time.Duration(i) * time.Second), Kind: model.KindFirewall,
			SrcIP: "203.0.113.10", DstIP: "43.242.97.40", DstPort: 1433, Proto: "tcp", Action: model.ActionAllow})
		hits = append(hits, []model.Hit{{RuleID: "fw-riskport", Name: "探测", Category: "高危服务探测",
			Severity: model.SevMedium, Phase: model.PhaseRecon, Result: model.ResultAllowed}})
	}
	s.RecordBatch(evs, hits)

	path := t.TempDir() + "/state.json.gz"
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := New(100, 100, 1, time.Hour)
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	list, _, _ := s2.Incidents(IncidentQuery{})
	if len(list) != 1 || list[0].Alerts != 1 || list[0].Hits != 3 || list[0].Muted != 2 {
		t.Fatalf("快照恢复后计数不符: %+v", list)
	}
}
