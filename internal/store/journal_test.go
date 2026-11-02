package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/model"
)

// 进程异常退出：快照里没有的处置记录也不能丢。
func TestIncidentJournalSurvivesCrash(t *testing.T) {
	dir := t.TempDir()
	snap, jr := filepath.Join(dir, "s.json.gz"), filepath.Join(dir, "s.json.gz.journal")
	s := newTestStore()
	if _, err := s.OpenIncidentJournal(jr); err != nil {
		t.Fatal(err)
	}
	rec := func(st *Store, ip string) uint64 {
		res := st.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/x", Status: 403, Time: time.Now()},
			[]model.Hit{attackHit("r", "SQL注入", model.SevHigh, model.ResultBlocked)})
		return res.Alerts[0].IncidentID
	}
	id1 := rec(s, "203.0.113.1")
	if err := s.Save(snap); err != nil {
		t.Fatal(err)
	}
	id2 := rec(s, "203.0.113.2") // 快照之后才出现的事件
	for _, id := range []uint64{id1, id2} {
		if _, err := s.UpdateIncidents([]uint64{id}, "ana", IncidentUpdate{Status: IncFalsePositive, Note: "确认是授权扫描"}); err != nil {
			t.Fatal(err)
		}
	}
	s.CloseJournal() // 模拟 kill -9：不保存快照

	// 末尾写了一半的行（写入时断电）不影响恢复
	f, _ := os.OpenFile(jr, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"incident":{"id":99,"not`)
	f.Close()

	s2 := newTestStore()
	if err := s2.Load(snap); err != nil {
		t.Fatal(err)
	}
	n, err := s2.OpenIncidentJournal(jr)
	if err != nil || n != 2 {
		t.Fatalf("应重放 2 次变更: %d %v", n, err)
	}
	for _, id := range []uint64{id1, id2} {
		d := s2.Incident(id)
		if d == nil || d.Status != IncFalsePositive || len(d.Notes) == 0 || d.Notes[len(d.Notes)-1].Text != "确认是授权扫描" {
			t.Fatalf("事件 #%d 的处置记录丢失: %+v", id, d)
		}
	}
	// 重放后新建的事件不复用编号
	if id3 := rec(s2, "203.0.113.3"); id3 <= id2 {
		t.Fatalf("事件编号重复: %d <= %d", id3, id2)
	}
	s2.CloseJournal()
}

// 全新安装：状态目录还不存在时也要能写入处置记录。
func TestIncidentJournalCreatesDir(t *testing.T) {
	s := newTestStore()
	jr := filepath.Join(t.TempDir(), "state", "sub", "s.journal")
	if _, err := s.OpenIncidentJournal(jr); err != nil {
		t.Fatal(err)
	}
	defer s.CloseJournal()
	id := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.1", Method: "GET", URI: "/x", Status: 403, Time: time.Now()},
		[]model.Hit{attackHit("r", "SQL注入", model.SevHigh, model.ResultBlocked)}).Alerts[0].IncidentID
	if _, err := s.UpdateIncidents([]uint64{id}, "ana", IncidentUpdate{Note: "x"}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(jr); err != nil || st.Size() == 0 {
		t.Fatalf("应写入日志: %v", err)
	}
}

// 快照保存成功后丢弃已包含的内容；快照里更新的事件不被旧日志覆盖。
func TestIncidentJournalCompaction(t *testing.T) {
	dir := t.TempDir()
	snap, jr := filepath.Join(dir, "s.json.gz"), filepath.Join(dir, "j")
	s := newTestStore()
	if _, err := s.OpenIncidentJournal(jr); err != nil {
		t.Fatal(err)
	}
	defer s.CloseJournal()
	id := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.1", Method: "GET", URI: "/x", Status: 403, Time: time.Now()},
		[]model.Hit{attackHit("r", "SQL注入", model.SevHigh, model.ResultBlocked)}).Alerts[0].IncidentID
	if _, err := s.UpdateIncidents([]uint64{id}, "ana", IncidentUpdate{Note: "第一次"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(jr); st.Size() == 0 {
		t.Fatal("处置后应写入日志")
	}
	if err := s.Save(snap); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(jr); st.Size() != 0 {
		t.Fatalf("保存快照后应清空日志: %d", st.Size())
	}
	// 整理之后仍能继续写入
	if _, err := s.UpdateIncidents([]uint64{id}, "ana", IncidentUpdate{Note: "第二次"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(jr); st.Size() == 0 {
		t.Fatal("整理后应能继续写入")
	}
	// 旧日志不覆盖快照里更新的事件
	s2 := newTestStore()
	if err := s2.Load(snap); err != nil {
		t.Fatal(err)
	}
	s2.incidents[id].Updated = time.Now().Add(time.Hour)
	s2.incidents[id].Status = IncResolved
	if _, err := s2.OpenIncidentJournal(jr); err != nil {
		t.Fatal(err)
	}
	s2.CloseJournal()
	if s2.Incident(id).Status != IncResolved {
		t.Fatal("旧日志不应覆盖更新的状态")
	}
}
