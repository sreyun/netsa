package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/model"
)

// 步骤满时记下腾位失败：同阶段、不更强的命中直接判定没有位置；更强的命中、步骤变化后、一小时后重新判断。
func TestChainRoomDenyCache(t *testing.T) {
	tr := &chainTrack{Key: "h", Kind: "host"}
	now := time.Now()
	for i := range chainMaxSteps {
		tr.Steps = append(tr.Steps, &chainStep{Stage: stExploit, Category: "c", Src: fmt.Sprint(i), Severity: model.SevHigh, Result: model.ResultBlocked,
			First: now, Last: now, Count: 1})
	}
	tr.reindex()
	weak := hitRank(model.SevHigh, model.ResultBlocked, false)
	if tr.makeRoom(stExploit, weak, now) {
		t.Fatal("同等强度、不陈旧的步骤不应让位")
	}
	if d := tr.deny[stExploit]; !d.ok || d.rank != weak || d.ver != tr.ver {
		t.Fatalf("应记下腾位失败: %+v", d)
	}
	// 记下之后，把一步改成陈旧：一小时内仍按记录判定没有位置（最多推迟一小时）
	tr.Steps[0].Last = now.Add(-48 * time.Hour)
	if tr.makeRoom(stExploit, weak, now.Add(time.Minute)) {
		t.Fatal("记录有效期内应直接判定没有位置")
	}
	if !tr.makeRoom(stExploit, weak, now.Add(2*time.Hour)) || len(tr.Steps) != chainMaxSteps-1 {
		t.Fatal("超过一小时后应重新判断并淘汰陈旧步骤")
	}
	// 步骤数回到上限：更强的命中不受记录影响
	tr.Steps = append(tr.Steps, &chainStep{Stage: stExploit, Category: "c", Src: "x", Severity: model.SevHigh, Result: model.ResultBlocked, First: now, Last: now, Count: 1})
	tr.reindex()
	tr.makeRoom(stExploit, weak, now.Add(3*time.Hour))
	strong := hitRank(model.SevCritical, model.ResultSuccess, true)
	if !tr.makeRoom(stExploit, strong, now.Add(3*time.Hour)) {
		t.Fatal("更强的命中应能腾位")
	}
}

// 没有写入时不重写快照；有写入、文件被删除时照常保存；没有清理掉任何东西的维护不算写入。
func TestSaveSkipsUnchanged(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Minute)
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.30", Method: "GET", URI: "/a", Status: 403, Time: now},
		[]model.Hit{attackHit("r1", "XSS跨站脚本", model.SevHigh, model.ResultBlocked)})
	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(path, old, old)
	s.Maintain() // 没有可清理的内容
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Fatal("没有写入时不应重写快照")
	}
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.31", Method: "GET", URI: "/a", Status: 403, Time: now},
		[]model.Hit{attackHit("r1", "XSS跨站脚本", model.SevHigh, model.ResultBlocked)})
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.ModTime().Equal(old) {
		t.Fatal("有写入时应保存")
	}
	os.Remove(path)
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("快照文件被删除时应重新保存")
	}
	r := newTestStore()
	if err := r.Load(path); err != nil || r.IPDetail("203.0.113.31") == nil {
		t.Fatalf("恢复: %v", err)
	}
	if ls := s.LockStats(); ls.Count == 0 {
		t.Fatal("应统计写锁次数")
	}
}

// 被攻击目标汇总有上限：大量零散目标不会让汇总无限增长，集中被攻击的目标保持准确。
func TestAggTargetsCapped(t *testing.T) {
	a := newAggregate()
	for i := range 5 {
		a.bumpTarget(fmt.Sprintf("hot%d", i), int64(1000+i))
	}
	for i := range maxAggTargets + 100 {
		a.bumpTarget(fmt.Sprintf("/p?id=%d", i), 1)
	}
	if len(a.targets) > maxAggTargets {
		t.Fatalf("汇总超过上限: %d", len(a.targets))
	}
	for i := range 5 {
		if a.targets[fmt.Sprintf("hot%d", i)] != int64(1000+i) {
			t.Fatalf("集中被攻击的目标应保留准确计数: %v", a.targets[fmt.Sprintf("hot%d", i)])
		}
	}
	a.bumpTarget("/p?id=1", -5) // 已被丢弃的目标再扣减：不会出现负数
	if v, ok := a.targets["/p?id=1"]; ok && v < 0 {
		t.Fatal("计数不应为负")
	}
}
