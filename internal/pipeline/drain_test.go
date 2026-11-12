package pipeline

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/store"
)

func drainBatches(n int) chan []*model.Event {
	in := make(chan []*model.Event, n)
	for i := 0; i < n; i++ {
		in <- []*model.Event{{Kind: model.KindWeb, SrcIP: fmt.Sprintf("198.51.100.%d", i%250+1), Method: "GET", URI: "/x?id=1' or '1'='1",
			Status: 200, Time: time.Now()}}
	}
	return in
}

// 退出时处理完队列中已有的日志：每批都入库并报告处理完（文件数据源的读取断点据此生效）；
// Drain 为 0 时立即停止（离线分析按 Ctrl+C），没处理的批次不报告处理完。
func TestRunDrainsQueueOnShutdown(t *testing.T) {
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	const n = 200
	var done atomic.Int64
	p := &Pipeline{Engine: eng, Store: store.New(1000, 1000, 5, time.Hour), Drain: 5 * time.Second, BatchDone: func(*model.Event) { done.Add(1) }}
	in := drainBatches(n)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 已经在退出
	select {
	case <-p.Run(ctx, in, 4):
	case <-time.After(10 * time.Second):
		t.Fatal("队列排空后应结束")
	}
	if done.Load() != n || len(in) != 0 {
		t.Fatalf("退出时应处理完队列中的 %d 批: 处理 %d 批，剩余 %d 批", n, done.Load(), len(in))
	}
	if got := p.Store.Overview().Totals.Events; got != n {
		t.Fatalf("应全部入库: %d", got)
	}

	// 不排空：立即停止，报告处理完的批数与实际处理的一致（不会把没处理的算作处理完）
	var done2 atomic.Int64
	p2 := &Pipeline{Engine: eng, Store: store.New(1000, 1000, 5, time.Hour), BatchDone: func(*model.Event) { done2.Add(1) }}
	in2 := drainBatches(n)
	select {
	case <-p2.Run(ctx, in2, 4):
	case <-time.After(10 * time.Second):
		t.Fatal("应立即结束")
	}
	if done2.Load() >= n || int64(n-len(in2)) < done2.Load() {
		t.Fatalf("不排空时不应处理完全部批次: 报告 %d 批，取走 %d 批", done2.Load(), n-len(in2))
	}
	if got := p2.Store.Overview().Totals.Events; got != done2.Load() {
		t.Fatalf("报告处理完的批数应与入库一致: %d / %d", done2.Load(), got)
	}
}

// 排空有时限：超过 Drain 后停止，不会因为队列一直有数据而无法退出。
func TestRunDrainDeadline(t *testing.T) {
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	in := make(chan []*model.Event, 4)
	stop := make(chan struct{})
	defer close(stop)
	go func() { // 持续送入日志的数据源
		for {
			select {
			case in <- []*model.Event{{Kind: model.KindWeb, SrcIP: "198.51.100.7", Method: "GET", URI: "/", Status: 200, Time: time.Now()}}:
			case <-stop:
				return
			}
		}
	}()
	p := &Pipeline{Engine: eng, Store: store.New(1000, 1000, 5, time.Hour), Drain: 300 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := p.Run(ctx, in, 2)
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("超过排空时限后应结束")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("排空时间过长: %s", d)
	}
}
