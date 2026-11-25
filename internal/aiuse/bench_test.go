package aiuse

import (
	"strconv"
	"testing"
	"time"

	"netsa/internal/model"
)

// 热路径：绝大多数事件与 AI 无关，统计不能拖慢流水线（不分配内存、不加锁）
func BenchmarkObserveUnrelated(b *testing.B) {
	m, _ := New(Options{Location: time.Local})
	web := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", Host: "www.example.com", URI: "/Products/List?id=3", Status: 200, Time: time.Now()}
	fw := &model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.5", DstIP: "198.51.100.7", SrcPort: 50000, DstPort: 443, SentBytes: 900, RecvBytes: 4000, Time: time.Now()}
	dns := &model.Event{Kind: model.KindDNS, SrcIP: "10.0.0.5", Host: "www.baidu.com", RCode: "NOERROR", Time: time.Now()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Observe(web)
		m.Observe(fw)
		m.Observe(dns)
	}
}

// 满规模（30 万条记录）时汇总一次的耗时：期间持锁，流水线的统计要等它结束
func BenchmarkReportFull(b *testing.B) {
	m, _ := New(Options{Location: time.Local})
	now := time.Now()
	svcs := []string{"chatgpt", "deepseek", "kimi", "claude", "doubao", "openai-api"}
	for i := 0; len(m.cells) < defaultMaxRecords; i++ {
		d := m.dayOf(now) - day(i%60)
		ip := "10." + strconv.Itoa(i/65536%256) + "." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256)
		m.cells[cellKey{d: d, svc: svcs[i%len(svcs)], ip: ip}] = &cell{queries: 3, conns: 2, up: 1000, first: now.Unix(), last: now.Unix()}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Report(Query{From: now.AddDate(0, 0, -29), To: now})
	}
}

// 满规模时持锁复制一次范围内记录的耗时（流水线的统计只需要等这么久）
func BenchmarkReportLockHold(b *testing.B) {
	m, _ := New(Options{Location: time.Local})
	now := time.Now()
	for i := 0; len(m.cells) < defaultMaxRecords; i++ {
		ip := "10." + strconv.Itoa(i/65536%256) + "." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256)
		m.cells[cellKey{d: m.dayOf(now) - day(i%60), svc: "chatgpt", ip: ip}] = &cell{queries: 1, first: now.Unix(), last: now.Unix()}
	}
	d0, d1 := m.dayOf(now)-29, m.dayOf(now)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.mu.Lock()
		m.rowsLocked(d0, d1, "", "")
		m.mu.Unlock()
	}
}
