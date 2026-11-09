package pipeline

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/store"
)

// 华为防火墙会话日志（生产环境 95% 以上的日志是这一类）：解析 → 检测 → 行为分析 → 入库的整条链路。
// 来源分布模拟互联网背景流量：大量不同的外部地址访问少数几个对外服务，偶尔有扫描。
func BenchmarkHuaweiSessions(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	lines := make([]string, 4096)
	ports := []int{443, 80, 22, 3389, 8080, 3306, 445, 23}
	for i := range lines {
		src := fmt.Sprintf("%d.%d.%d.%d", 1+rng.Intn(220), rng.Intn(256), rng.Intn(256), 1+rng.Intn(254))
		dport := ports[rng.Intn(len(ports))]
		zone, act := "untrust", "SESSION_TEARDOWN"
		if rng.Intn(4) == 0 {
			act = "POLICYDENY"
		}
		lines[i] = fmt.Sprintf(`<190>Nov  9 2026 01:47:%02d USG6630E %%%%01SECLOG/6/%s(l):IPVer=4,Protocol=tcp,SourceIP=%s,DestinationIP=10.34.44.%d,SourcePort=%d,DestinationPort=%d,SourceNatIP=%s,SourceNatPort=%d,BeginTime=1794186439,EndTime=1794186440,SendPkts=%d,SendBytes=%d,RcvPkts=%d,RcvBytes=%d,SourceVpnID=0,DestinationVpnID=0,SourceZone=%s,DestinationZone=dmz,PolicyName=web-in,CloseReason=tcp-fin.`,
			i%60, act, src, 50+rng.Intn(10), 1024+rng.Intn(60000), dport, src, 1024+rng.Intn(60000), 1+rng.Intn(9), 60+rng.Intn(4000), rng.Intn(9), rng.Intn(9000), zone)
	}
	ap, _ := parser.NewAuto("auto", "")
	cfg := config.Default()
	eng, _ := detect.NewEngine("", 1)
	st := store.New(200000, 20000, 5, time.Hour)
	p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(cfg.Detect.Thresholds), Store: st, RealIP: NewRealIP(cfg.RealIP)}
	p.SetEngine(eng)
	const batch = 256
	evs := make([]*model.Event, 0, batch)
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		ev, ok := ap.Parse(lines[i%len(lines)])
		if !ok {
			b.Fatal("应能解析")
		}
		ev.Time = start.Add(time.Duration(i) * time.Millisecond)
		evs = append(evs, ev)
		if len(evs) == batch || i == b.N-1 {
			items := make([]item, len(evs))
			for k, e := range evs {
				items[k] = p.inspect(e)
			}
			p.aggregate(items)
			evs = evs[:0]
		}
	}
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "events/s")
}
