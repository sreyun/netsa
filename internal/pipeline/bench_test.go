package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/demo"
	"netsa/internal/detect"
	"netsa/internal/ingest"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/store"
)

var benchLines = []string{
	`203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET /products/1024?ref=home HTTP/1.1" 200 5123 "https://www.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36" "-"`,
	`203.0.113.6 - - [22/Oct/2026:10:15:01 +0800] "GET /static/js/app.min.js HTTP/1.1" 200 88123 "https://www.example.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X)" "-"`,
	`198.51.100.7 - - [22/Oct/2026:10:15:01 +0800] "GET /news?id=-1%20union%20select%201,group_concat(table_name),3%20from%20information_schema.tables-- HTTP/1.1" 200 1200 "-" "sqlmap/1.7" "-"`,
	`Oct 22 10:15:01 web01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=198.51.100.23 DST=10.0.0.10 LEN=40 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 SYN URGP=0`,
}

func BenchmarkParseAuto(b *testing.B) {
	p, _ := parser.NewAuto("auto", "")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.Parse(benchLines[i%len(benchLines)])
	}
}

func BenchmarkInspectWeb(b *testing.B) {
	e, _ := detect.NewEngine("", 1)
	p, _ := parser.NewAuto("nginx", "")
	evs := []*model.Event{}
	for _, l := range benchLines[:3] {
		ev, _ := p.Parse(l)
		evs = append(evs, ev)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Inspect(evs[i%len(evs)])
	}
}

// BenchmarkEndToEnd 读取演示日志，经解析、检测、行为分析、入库全流程，报告每秒事件数。
func BenchmarkEndToEnd(b *testing.B) {
	dir := b.TempDir()
	if err := demo.Generate(dir, 2, 6, 1); err != nil {
		b.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	var lines int64
	for _, f := range files {
		st, _ := os.Stat(f)
		lines += st.Size()
	}
	cfg := config.Default()
	eng, _ := detect.NewEngine("", 1)
	b.ResetTimer()
	var events int64
	start := time.Now()
	for i := 0; i < b.N; i++ {
		st := store.New(200000, 20000, 5, time.Hour)
		p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(cfg.Detect.Thresholds), Store: st,
			RealIP: NewRealIP(cfg.RealIP)}
		m := ingest.NewManager(4096)
		ctx := context.Background()
		done := p.Run(ctx, m.Out, 0)
		for _, f := range files {
			m.ReadFile(ctx, f, "auto", "", "")
		}
		go func() { m.Wait(); m.Close() }()
		<-done
		events += p.Processed()
	}
	b.ReportMetric(float64(events)/time.Since(start).Seconds(), "events/s")
	_ = lines
}

func benchInspect(b *testing.B, line string) {
	e, _ := detect.NewEngine("", 1)
	p, _ := parser.NewAuto("nginx", "")
	ev, _ := p.Parse(line)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Inspect(ev)
	}
}

func BenchmarkInspectBenign(b *testing.B) { benchInspect(b, benchLines[0]) }
func BenchmarkInspectAttack(b *testing.B) { benchInspect(b, benchLines[2]) }
