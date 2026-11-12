package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netsa/internal/model"
)

// 满规模测量（默认跳过）：NETSA_SCALE=200000 go test -run TestScale -v ./internal/store
// 建立指定数量的攻击源画像，测量快照保存与恢复耗时、大小，以及查询并发时日志入库等待写锁的时间。
func TestScale(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("NETSA_SCALE"))
	if n <= 0 {
		t.Skip("设置 NETSA_SCALE 后运行")
	}
	s := New(n, 20000, 5, 168*time.Hour)
	now := time.Now().Add(-time.Hour)
	cats := []string{"SQL注入", "XSS跨站脚本", "目录扫描", "命令/代码执行", "端口扫描", "敏感文件探测"}
	ip := func(i int) string { return fmt.Sprintf("%d.%d.%d.%d", 20+i>>24&63, i>>16&255, i>>8&255, i&255) }
	// span 为来源地址的个数：k 号事件来自 ip(k % span)
	batch := func(base, count, span int, at time.Time) ([]*model.Event, [][]model.Hit) {
		evs := make([]*model.Event, 0, count)
		hits := make([][]model.Hit, 0, count)
		for i := 0; i < count; i++ {
			k := base + i
			evs = append(evs, &model.Event{Kind: model.KindWeb, SrcIP: ip(k % span), Host: "site" + strconv.Itoa(k%50) + ".example.com", Method: "GET",
				URI: "/p" + strconv.Itoa(k%400) + "?id=" + strconv.Itoa(k), Status: 403, Bytes: 512, Time: at.Add(time.Duration(k%3600) * time.Second)})
			hits = append(hits, []model.Hit{{RuleID: "r" + strconv.Itoa(k%40), Name: "n", Category: cats[k%len(cats)], Severity: model.SevHigh, Phase: model.PhaseExploit,
				Result: model.ResultBlocked, Evidence: "x"}})
		}
		return evs, hits
	}
	start := time.Now()
	for base := 0; base < 3*n; base += 256 {
		evs, hits := batch(base, 256, n, now)
		s.RecordBatch(evs, hits)
	}
	// 按 7 天留存补齐分钟桶（快照头部在一次读锁内编码）
	s.mu.Lock()
	for m, t0 := int64(0), now.Unix()/60; m < 7*24*60; m++ {
		if s.buckets[t0-m] == nil {
			s.buckets[t0-m] = &Bucket{T: (t0 - m) * 60, Web: 1000 + m, Attacks: m % 97, Blocked: m % 89, Sev: [5]int64{1, 2, 3, 4, 5}}
		}
	}
	s.mu.Unlock()
	t.Logf("写入 %d 条命中、%d 个攻击源：%s", 3*n, len(s.ips), time.Since(start).Round(time.Millisecond))
	ls0 := s.LockStats()
	t.Logf("只有写入时：写锁持有最长 %s（%d 次）", ls0.HoldMax.Round(time.Microsecond), ls0.Count)
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	t.Logf("存活堆 %d MB", ms.HeapAlloc>>20)

	// 快照编码的耗时构成：画像与其余部分
	t0 := time.Now()
	for _, p := range s.profileList() {
		if _, err := json.Marshal(p); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("编码全部画像 %s", time.Since(t0).Round(time.Millisecond))

	path := filepath.Join(t.TempDir(), "state.json.gz")
	start = time.Now()
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	t.Logf("保存快照 %s，%d MB", time.Since(start).Round(time.Millisecond), fi.Size()>>20)
	start = time.Now()
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	t.Logf("没有变化时再次保存 %s", time.Since(start).Round(time.Millisecond))
	// 一分钟内常见的改动量：1% 的画像有新命中，之后只写增量快照
	for base := 0; base < n/100; base += 256 {
		evs, hits := batch(base, min(256, n/100-base), n, now.Add(time.Minute))
		s.RecordBatch(evs, hits)
	}
	start = time.Now()
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(deltaPath(path))
	t.Logf("1%% 画像改动后保存（增量）%s，%d KB，改动 %d 个", time.Since(start).Round(time.Millisecond), fi.Size()>>10, len(s.dirtyList))
	runtime.GC() // 与下面的对照同样先回收保存时留下的垃圾，否则先测的一方吃亏
	r := New(n, 20000, 5, 168*time.Hour)
	if p := os.Getenv("NETSA_SCALE_LOADPROF"); p != "" {
		f, _ := os.Create(p)
		pprof.StartCPUProfile(f)
		defer f.Close()
	}
	start = time.Now()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NETSA_SCALE_LOADPROF") != "" {
		pprof.StopCPUProfile()
	}
	t.Logf("恢复快照（完整 + 增量）%s，%d 个画像", time.Since(start).Round(time.Millisecond), len(r.ips))
	sameCount := len(r.ips) == len(s.ips)
	r = nil // 释放恢复出的副本：本机内存不大，两份状态同时存活时后面的耗时会被换页拖慢
	runtime.GC()
	if !sameCount {
		t.Fatal("恢复后的画像数应一致")
	}
	// 对照：只有完整快照时的恢复耗时（增量快照暂时移开）
	if err := os.Rename(deltaPath(path), deltaPath(path)+".off"); err != nil {
		t.Fatal(err)
	}
	r = New(n, 20000, 5, 168*time.Hour)
	start = time.Now()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	t.Logf("恢复快照（只有完整快照，对照）%s", time.Since(start).Round(time.Millisecond))
	r = nil
	runtime.GC()
	if err := os.Rename(deltaPath(path)+".off", deltaPath(path)); err != nil {
		t.Fatal(err)
	}

	queries := []struct {
		name string
		fn   func()
	}{
		{"总览", func() { s.Overview() }},
		{"地图", func() { s.MapData(model.SevInfo) }},
		{"攻击源搜索", func() { s.Attackers(AttackerQuery{Search: "site", Limit: 20}) }},
		{"攻击源列表", func() { s.Attackers(AttackerQuery{Sort: "score", Limit: 20}) }},
		{"资产链路", func() { s.ChainList(ChainQuery{Limit: 20}) }},
		{"事件搜索", func() { s.Incidents(IncidentQuery{Search: "sql"}) }},
		{"安全评估", func() { s.Assess(Visibility{ParseRate: 1}) }},
		{"指标", func() { s.Metrics() }},
	}
	for _, q := range queries {
		var worst time.Duration
		for range 3 {
			t0 := time.Now()
			q.fn()
			worst = max(worst, time.Since(t0))
		}
		t.Logf("查询 %s：%s", q.name, worst.Round(time.Microsecond))
	}
	// 逐项归因：后台只循环执行一种操作，前台向 2000 个来源写入，记录每批入库的最长耗时
	saveFull := func() {
		s.saveMu.Lock()
		s.baseAt = time.Time{} // 强制完整保存
		s.saveMu.Unlock()
		s.mu.gen.Add(1) // 写代数前进，否则没有变化时跳过
		t0, id := time.Now(), s.baseID
		if err := s.Save(path); err != nil {
			t.Error(err)
		}
		if os.Getenv("NETSA_SCALE_DEBUG") != "" {
			t.Logf("完整保存 %s，标识变化 %v", time.Since(t0), id != s.baseID)
		}
	}
	saveDelta := func() {
		s.mu.gen.Add(1) // 写代数前进，否则没有变化时跳过
		if err := s.Save(path); err != nil {
			t.Error(err)
		}
	}
	saveFull()
	ops := append([]struct {
		name string
		fn   func()
	}{{"完整保存", saveFull}, {"增量保存", saveDelta}}, queries...)
	for k, op := range ops {
		var stop atomic.Bool
		var runs atomic.Int64
		done := make(chan struct{})
		go func() {
			defer close(done)
			for !stop.Load() {
				op.fn()
				runs.Add(1)
			}
		}()
		var worst time.Duration
		t0 := time.Now()
		for base := (k + 4) * n; time.Since(t0) < time.Second || runs.Load() == 0; base += 256 {
			evs, hits := batch(base, 256, 2000, now)
			b0 := time.Now()
			s.RecordBatch(evs, hits)
			worst = max(worst, time.Since(b0))
		}
		stop.Store(true)
		<-done
		t.Logf("与%s并发：入库每批最长 %s（%s 执行 %d 次）", op.name, worst.Round(time.Microsecond), op.name, runs.Load())
	}

	// 查询并发时入库的等待：后台循环执行几种全量查询，前台持续写入并记录每批等待写锁的最长时间
	var stop atomic.Bool
	var wg sync.WaitGroup
	fns := []func(){func() { _ = s.Save(path) }}
	for _, q := range queries {
		fns = append(fns, q.fn)
	}
	for _, q := range fns {
		wg.Add(1)
		go func(q func()) {
			defer wg.Done()
			for !stop.Load() {
				q()
			}
		}(q)
	}
	var worst, total time.Duration
	batches := 0
	deadline := time.Now().Add(5 * time.Second)
	for base := 20 * n; time.Now().Before(deadline); base += 256 {
		evs, hits := batch(base, 256, n, now)
		t0 := time.Now()
		s.RecordBatch(evs, hits)
		d := time.Since(t0)
		total += d
		worst = max(worst, d)
		batches++
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("查询并发时入库 %d 批：平均 %s，最长 %s", batches, (total / time.Duration(max(batches, 1))).Round(time.Microsecond), worst.Round(time.Microsecond))
	ls := s.LockStats()
	t.Logf("写锁：等待最长 %s，持有最长 %s，累计等待 %s，共 %d 次（超过 5ms %d 次、50ms %d 次）", ls.WaitMax.Round(time.Microsecond), ls.HoldMax.Round(time.Microsecond),
		ls.WaitTotal.Round(time.Millisecond), ls.Count, ls.WaitOver5, ls.WaitOver50)
}
