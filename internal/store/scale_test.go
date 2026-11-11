package store

import (
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
	batch := func(base, count int, at time.Time) ([]*model.Event, [][]model.Hit) {
		evs := make([]*model.Event, 0, count)
		hits := make([][]model.Hit, 0, count)
		for i := 0; i < count; i++ {
			k := base + i
			evs = append(evs, &model.Event{Kind: model.KindWeb, SrcIP: ip(k % n), Host: "site" + strconv.Itoa(k%50) + ".example.com", Method: "GET",
				URI: "/p" + strconv.Itoa(k%400) + "?id=" + strconv.Itoa(k), Status: 403, Bytes: 512, Time: at.Add(time.Duration(k%3600) * time.Second)})
			hits = append(hits, []model.Hit{{RuleID: "r" + strconv.Itoa(k%40), Name: "n", Category: cats[k%len(cats)], Severity: model.SevHigh, Phase: model.PhaseExploit,
				Result: model.ResultBlocked, Evidence: "x"}})
		}
		return evs, hits
	}
	start := time.Now()
	for base := 0; base < 3*n; base += 256 {
		evs, hits := batch(base, 256, now)
		s.RecordBatch(evs, hits)
	}
	t.Logf("写入 %d 条命中、%d 个攻击源：%s", 3*n, len(s.ips), time.Since(start).Round(time.Millisecond))
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	t.Logf("存活堆 %d MB", ms.HeapAlloc>>20)

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
	t.Logf("恢复快照 %s，%d 个画像", time.Since(start).Round(time.Millisecond), len(r.ips))

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
	for base := 3 * n; time.Now().Before(deadline); base += 256 {
		evs, hits := batch(base, 256, now)
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
	t.Logf("写锁：等待最长 %s，持有最长 %s，累计等待 %s，共 %d 次", ls.WaitMax.Round(time.Microsecond), ls.HoldMax.Round(time.Microsecond),
		ls.WaitTotal.Round(time.Millisecond), ls.Count)
}
