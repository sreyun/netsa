package store

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"netsa/internal/model"
)

func deltaEvent(ip string, at time.Time, k int) (*model.Event, []model.Hit) {
	return &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "a.example.com", Method: "GET", URI: fmt.Sprintf("/p%d?id=1'", k), Status: 403, Time: at},
		[]model.Hit{attackHit(fmt.Sprintf("r%d", k%3), "SQL注入", model.SevHigh, model.ResultBlocked)}
}

// checkList 校验画像数组与画像 map 一致。
func checkList(t *testing.T, s *Store) {
	t.Helper()
	if len(s.ipList) != len(s.ips) {
		t.Fatalf("画像数组 %d 个，map %d 个", len(s.ipList), len(s.ips))
	}
	for i, p := range s.ipList {
		if p.listIdx != i || s.ips[p.IP] != p {
			t.Fatalf("画像数组第 %d 项（%s）与 map 不一致", i, p.IP)
		}
	}
}

func readSnapJSON(t *testing.T, p string) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if b, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func profileKeys(t *testing.T, m map[string]json.RawMessage) []string {
	t.Helper()
	var ps map[string]json.RawMessage
	if err := json.Unmarshal(m["profiles"], &ps); err != nil {
		t.Fatal(err)
	}
	out := mapKeys(ps)
	sort.Strings(out)
	return out
}

// sameProfiles 比较两个状态库的全部画像（按持久化内容）。
func sameProfiles(t *testing.T, a, b *Store) {
	t.Helper()
	if len(a.ips) != len(b.ips) {
		t.Fatalf("画像数 %d ≠ %d", len(a.ips), len(b.ips))
	}
	for ip, p := range a.ips {
		q := b.ips[ip]
		if q == nil {
			t.Fatalf("缺少画像 %s", ip)
		}
		x, _ := json.Marshal(p)
		y, _ := json.Marshal(q)
		if !bytes.Equal(x, y) {
			t.Fatalf("画像 %s 不一致:\n%s\n%s", ip, x, y)
		}
	}
}

// 完整快照之后只写改动过的画像；恢复时叠加增量快照，结果与内存中一致，完整快照文件不被改写。
func TestDeltaSnapshotRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.gz")
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := 1; i <= 20; i++ {
		s.Record(deltaEvent(fmt.Sprintf("203.0.113.%d", i), now, i))
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(deltaPath(path)); err == nil {
		t.Fatal("第一次应保存完整快照")
	}
	base, _ := os.ReadFile(path)
	baseID := string(readSnapJSON(t, path)["id"])

	s.Record(deltaEvent("203.0.113.1", now.Add(time.Minute), 7)) // 已有画像的新命中
	s.Tag("203.0.113.2", "honeypot", "x")                        // 打标签
	s.Record(deltaEvent("198.51.100.200", now, 1))               // 新画像
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if cur, _ := os.ReadFile(path); !bytes.Equal(cur, base) {
		t.Fatal("增量保存不应改写完整快照")
	}
	d := readSnapJSON(t, deltaPath(path))
	if string(d["delta_base"]) != baseID {
		t.Fatalf("增量快照应记下完整快照的标识 %s，实际 %s", baseID, d["delta_base"])
	}
	if got := profileKeys(t, d); fmt.Sprint(got) != "[198.51.100.200 203.0.113.1 203.0.113.2]" {
		t.Fatalf("增量快照只应包含改动过的画像: %v", got)
	}
	for _, k := range []string{"alerts", "buckets", "surface"} {
		if _, ok := d[k]; !ok {
			t.Fatalf("增量快照应完整包含 %s", k)
		}
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, s, r)
	checkList(t, r)
	if len(r.Alerts(AlertQuery{Limit: 1000})) != len(s.Alerts(AlertQuery{Limit: 1000})) {
		t.Fatal("告警应以增量快照为准")
	}
	if _, ok := r.Profile("203.0.113.2").Tags["honeypot"]; !ok {
		t.Fatal("标签应从增量快照恢复")
	}

	// 恢复后的改动与恢复前增量快照中的改动一起写入下一份增量快照
	r.Record(deltaEvent("203.0.113.3", now.Add(2*time.Minute), 2))
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	if got := profileKeys(t, readSnapJSON(t, deltaPath(path))); fmt.Sprint(got) != "[198.51.100.200 203.0.113.1 203.0.113.2 203.0.113.3]" {
		t.Fatalf("恢复后的增量快照应累积: %v", got)
	}
	r2 := newTestStore()
	if err := r2.Load(path); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, r, r2)
}

// 淘汰的画像列在增量快照中，恢复后不会从完整快照里复活；淘汰后又出现的来源以新画像为准。
func TestDeltaSnapshotEvicted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := New(1000, 100, 5, time.Hour)
	now := time.Now().Add(-time.Hour)
	ip := func(i int) string { return fmt.Sprintf("10.9.%d.%d", i/256, i%256) }
	for i := 0; i < 1000; i++ {
		s.Record(deltaEvent(ip(i), now.Add(time.Duration(i)*time.Second), i))
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	for i := 1000; i < 1020; i++ {
		s.Record(deltaEvent(ip(i), now.Add(time.Duration(i)*time.Second), i))
	}
	s.Maintain()
	checkList(t, s)
	if len(s.removedIPs) == 0 {
		t.Fatal("应有画像被淘汰")
	}
	var gone string
	for x := range s.removedIPs {
		gone = x
		break
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	d := readSnapJSON(t, deltaPath(path))
	var removed []string
	json.Unmarshal(d["removed"], &removed)
	if len(removed) != len(s.removedIPs) {
		t.Fatalf("增量快照应列出 %d 个淘汰的画像，实际 %d", len(s.removedIPs), len(removed))
	}
	r := New(1000, 100, 5, time.Hour)
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, s, r)
	checkList(t, r)

	// 淘汰的来源再次出现：新画像写入增量快照，恢复时先删后加
	s.Record(deltaEvent(gone, now.Add(time.Hour), 1))
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r = New(1000, 100, 5, time.Hour)
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, s, r)
	if r.Profile(gone) == nil {
		t.Fatal("再次出现的来源应恢复")
	}
}

// 完整快照之后，留在磁盘上的旧增量快照（记下的是旧快照的标识）被忽略。
func TestDeltaSnapshotStaleIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.gz")
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := 1; i <= 10; i++ {
		s.Record(deltaEvent(fmt.Sprintf("203.0.113.%d", i), now, i))
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s.Record(deltaEvent("203.0.113.1", now.Add(time.Minute), 1))
	if err := s.Save(path); err != nil { // 增量
		t.Fatal(err)
	}
	stale, _ := os.ReadFile(deltaPath(path))
	s.baseAt = time.Now().Add(-fullEvery) // 到了完整保存的时间
	s.Record(deltaEvent("203.0.113.1", now.Add(2*time.Minute), 2))
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if cur, _ := os.ReadFile(deltaPath(path)); !bytes.Equal(cur, stale) {
		t.Fatal("完整保存时旧增量快照留在原处")
	}
	if len(s.dirtyList) != 0 {
		t.Fatal("完整保存后改动记录应清空")
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, s, r)
	if len(r.dirtyList) != 0 {
		t.Fatal("旧增量快照不应计入改动")
	}
	// 标识不匹配的增量快照（来自其他实例）同样忽略
	s.Record(deltaEvent("203.0.113.5", now.Add(3*time.Minute), 3))
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "state.json.gz")
	o := newTestStore()
	o.Record(deltaEvent("192.0.2.9", now, 1))
	if err := o.Save(other); err != nil {
		t.Fatal(err)
	}
	r = newTestStore()
	b, _ := os.ReadFile(deltaPath(path))
	os.WriteFile(deltaPath(other), b, 0o600)
	if err := r.Load(other); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, o, r)
}

// 完整保存失败时改动记录放回，下一份增量快照仍包含它们；损坏的增量快照备份后忽略。
func TestDeltaSnapshotFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := 1; i <= 10; i++ {
		s.Record(deltaEvent(fmt.Sprintf("203.0.113.%d", i), now, i))
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s.Record(deltaEvent("203.0.113.1", now.Add(time.Minute), 1))
	s.baseAt = time.Now().Add(-fullEvery)
	if err := os.Mkdir(path+".tmp", 0o755); err != nil { // 临时文件无法创建
		t.Fatal(err)
	}
	if err := s.Save(path); err == nil {
		t.Fatal("应保存失败")
	}
	if len(s.dirtyList) != 1 || !s.dirtyList[0].dirty {
		t.Fatalf("保存失败后改动记录应放回: %d", len(s.dirtyList))
	}
	os.Remove(path + ".tmp")
	s.baseAt = time.Now()
	if err := s.Save(path); err != nil { // 仍基于原来的完整快照写增量
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, s, r)

	os.WriteFile(deltaPath(path), []byte(`{"version":2,"delta_base":`), 0o600)
	r = newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatalf("增量快照损坏不应影响恢复: %v", err)
	}
	if r.Profile("203.0.113.1") == nil {
		t.Fatal("应恢复完整快照中的画像")
	}
	if m, _ := filepath.Glob(deltaPath(path) + ".corrupt*.bak"); len(m) == 0 {
		t.Fatal("损坏的增量快照应备份")
	}
}

// 改动较多或距上次完整保存超过 15 分钟时保存完整快照。
func TestDeltaSnapshotFullWhenMostlyDirty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := 1; i <= 10; i++ {
		s.Record(deltaEvent(fmt.Sprintf("203.0.113.%d", i), now, i))
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	id := s.baseID
	for i := 1; i <= 4; i++ {
		s.Record(deltaEvent(fmt.Sprintf("203.0.113.%d", i), now.Add(time.Minute), i))
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if s.baseID == id {
		t.Fatal("四成画像有改动时应保存完整快照")
	}
}

// 分段持锁入库与逐条入库的结果一致（跨越分段边界、同一来源重复出现）。
func TestRecordBatchChunks(t *testing.T) {
	a, b := newTestStore(), newTestStore()
	now := time.Now().Add(-time.Hour)
	var evs []*model.Event
	var hits [][]model.Hit
	for i := 0; i < 3*recordChunk+5; i++ {
		ev, h := deltaEvent(fmt.Sprintf("203.0.113.%d", i%40), now.Add(time.Duration(i)*time.Second), i)
		evs, hits = append(evs, ev), append(hits, h)
	}
	got := a.RecordBatch(evs, hits)
	for i := range evs {
		ev := *evs[i]
		want := b.Record(&ev, hits[i])
		if got[i].NewIP != want.NewIP || got[i].Level != want.Level || got[i].Score != want.Score || len(got[i].Alerts) != len(want.Alerts) {
			t.Fatalf("第 %d 条结果不一致: %+v / %+v", i, got[i], want)
		}
	}
	sameProfiles(t, a, b)
	checkList(t, a)
}

// 计数表削减到指定条数：计数更多的全部保留，门槛计数的只保留差额。
func TestTrimCounts(t *testing.T) {
	m := map[string]int64{}
	for i := 0; i < 1000; i++ {
		m[fmt.Sprint("a", i)] = 1
	}
	for i := 0; i < 300; i++ {
		m[fmt.Sprint("b", i)] = 2
	}
	m["top"] = 99
	trimCounts(m, 500)
	if len(m) != 500 || m["top"] != 99 {
		t.Fatalf("应保留 500 条且保留计数最多的: %d", len(m))
	}
	ones := 0
	for k, v := range m {
		if v == 1 {
			ones++
		} else if v == 2 && k[0] != 'b' {
			t.Fatal("计数被改动")
		}
	}
	if ones != 199 {
		t.Fatalf("门槛计数应保留差额 199 条，实际 %d", ones)
	}
	trimCounts(m, 1000) // 不超过时不变
	if len(m) != 500 {
		t.Fatal("不超过上限时不应删除")
	}
}

// 没有保存或载入过快照时不记录改动（未配置快照时改动记录不会一直增长，淘汰的画像可以释放）。
func TestDeltaNoTrackingWithoutSnapshot(t *testing.T) {
	s := New(100, 100, 5, time.Hour)
	now := time.Now().Add(-time.Hour)
	for i := 0; i < 300; i++ {
		s.Record(deltaEvent(fmt.Sprintf("10.8.%d.%d", i/256, i%256), now, i))
		if i%50 == 0 {
			s.Maintain()
		}
	}
	if err := s.Save(""); err != nil {
		t.Fatal(err)
	}
	if len(s.dirtyList) != 0 || len(s.removedIPs) != 0 {
		t.Fatalf("未配置快照时不应记录改动: %d / %d", len(s.dirtyList), len(s.removedIPs))
	}
	if err := s.Save(filepath.Join(t.TempDir(), "s.json")); err != nil {
		t.Fatal(err)
	}
	s.Record(deltaEvent("10.8.0.1", now.Add(time.Minute), 1))
	if len(s.dirtyList) != 1 {
		t.Fatalf("保存快照之后应开始记录改动: %d", len(s.dirtyList))
	}
}

// 完整快照的标识写在最前面，只读开头即可取得；增量快照与旧布局（标识不在最前面）取不到。
// 旧布局的完整快照仍能叠加标识匹配的增量快照（按画像解析后核对）。
func TestPeekSnapshotID(t *testing.T) {
	for _, name := range []string{"state.json.gz", "state.json"} {
		path := filepath.Join(t.TempDir(), name)
		s := newTestStore()
		now := time.Now().Add(-time.Hour)
		for i := 1; i <= 10; i++ {
			s.Record(deltaEvent(fmt.Sprintf("203.0.113.%d", i), now, i))
		}
		if err := s.Save(path); err != nil {
			t.Fatal(err)
		}
		if got := peekSnapshotID(path); got == "" || got != s.baseID {
			t.Fatalf("%s: 应读到完整快照的标识 %q，实际 %q", name, s.baseID, got)
		}
		s.Record(deltaEvent("203.0.113.1", now.Add(time.Minute), 1))
		if err := s.Save(path); err != nil {
			t.Fatal(err)
		}
		if got := peekSnapshotID(deltaPath(path)); got != "" {
			t.Fatalf("增量快照没有完整快照标识: %q", got)
		}
		// 改写成标识不在最前面的布局（按键名排序重新编码）
		m := readSnapJSON(t, path)
		b, _ := json.Marshal(m)
		os.WriteFile(path, b, 0o600)
		if got := peekSnapshotID(path); got != "" {
			t.Fatalf("标识不在最前面时应取不到: %q", got)
		}
		r := newTestStore()
		if err := r.Load(path); err != nil {
			t.Fatal(err)
		}
		sameProfiles(t, s, r)
		if len(r.dirtyList) != 1 {
			t.Fatalf("旧布局的完整快照也应叠加匹配的增量快照: %d", len(r.dirtyList))
		}
	}
}

// 完整保存失败时，期间被淘汰的画像不放回改动记录（它们已在淘汰名单中）。
func TestRestoreDirtySkipsEvicted(t *testing.T) {
	s := New(1000, 100, 5, time.Hour)
	if err := s.Save(filepath.Join(t.TempDir(), "s.json")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	s.Record(deltaEvent("10.7.0.1", now, 1))
	s.Record(deltaEvent("10.7.0.2", now, 2))
	list, removed := s.takeDirty()
	s.mu.Lock()
	gone := s.ips["10.7.0.1"]
	delete(s.ips, gone.IP)
	s.listRemove(gone)
	s.removedIPs[gone.IP] = struct{}{}
	s.mu.Unlock()
	s.restoreDirty(list, removed)
	if len(s.dirtyList) != 1 || s.dirtyList[0].IP != "10.7.0.2" {
		t.Fatalf("只应放回仍在的画像: %d", len(s.dirtyList))
	}
	if _, ok := s.removedIPs["10.7.0.1"]; !ok {
		t.Fatal("淘汰记录应保留")
	}
}

// 入库、淘汰、完整 / 增量保存并发进行：停止写入后再保存一次，恢复结果与内存一致（race 检测下同样运行）。
func TestDeltaConcurrentSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.gz")
	s := New(300, 100, 5, time.Hour)
	now := time.Now().Add(-time.Hour)
	rounds := 3000
	if testing.Short() {
		rounds = 800
	}
	done := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for k := 0; k < rounds; k++ {
			ev, h := deltaEvent(fmt.Sprintf("10.6.%d.%d", k%1000/256, k%1000%256), now.Add(time.Duration(k)*time.Second), k)
			s.RecordBatch([]*model.Event{ev}, [][]model.Hit{h})
			if k%97 == 0 {
				s.Maintain()
			}
			if k%131 == 0 {
				s.Tag(ev.SrcIP, "t", "x")
			}
		}
	}()
	var savers sync.WaitGroup
	savers.Add(1)
	go func() {
		defer savers.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			if i%4 == 0 {
				s.saveMu.Lock()
				s.baseAt = time.Time{} // 强制完整保存
				s.saveMu.Unlock()
			}
			if err := s.Save(path); err != nil {
				t.Error(err)
				return
			}
			s.Overview()
			s.Attackers(AttackerQuery{Limit: 10})
		}
	}()
	writers.Wait()
	close(done)
	savers.Wait()
	s.mu.gen.Add(1)
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	checkList(t, s)
	r := New(300, 100, 5, time.Hour)
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	sameProfiles(t, s, r)
	checkList(t, r)
}

// 系统时钟回拨（完整快照的时间在未来）时保存完整快照，不会长期只写增量快照。
func TestDeltaClockBackwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := 1; i <= 10; i++ {
		s.Record(deltaEvent(fmt.Sprintf("203.0.113.%d", i), now, i))
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	id := s.baseID
	s.baseAt = time.Now().Add(24 * time.Hour)
	s.Record(deltaEvent("203.0.113.1", now.Add(time.Minute), 1))
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if s.baseID == id {
		t.Fatal("完整快照的时间在未来时应保存完整快照")
	}
}
