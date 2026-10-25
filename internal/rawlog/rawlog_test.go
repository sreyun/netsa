package rawlog

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

func ev(t time.Time, ip, raw string) *model.Event {
	return &model.Event{Time: t, Kind: model.KindWeb, Source: "nginx", SrcIP: ip, DstIP: "10.0.0.1", Raw: raw}
}

func waitWritten(t *testing.T, s *Store, n int64) {
	t.Helper()
	for i := 0; i < 200 && s.written.Load() < n; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if s.written.Load() < n {
		t.Fatalf("写入超时: %d/%d", s.written.Load(), n)
	}
}

func TestWriteSearchVerify(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	loc := time.FixedZone("CST", 8*3600)
	s, err := Open(ctx, Options{Dir: dir, RetentionDays: 180, Location: loc})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 20, 9, 30, 0, 0, loc)
	var evs []*model.Event
	var hits [][]model.Hit
	for i := 0; i < 300; i++ {
		ip := "198.51.100." + strconv.Itoa(i%3+1)
		raw := `198.51.100.x - - "GET /page?id=` + strconv.Itoa(i) + ` HTTP/1.1" 200 12 "-" "Mozilla"`
		if i == 150 {
			raw = "GET /search?q=Union\tSelect\n1 HTTP/1.1" // 原始日志中的制表符、换行不能破坏格式
		}
		evs = append(evs, ev(base.Add(time.Duration(i)*time.Minute/2), ip, raw)) // 跨 3 个小时
		var h []model.Hit
		if i%10 == 0 {
			h = []model.Hit{{RuleID: "r", Severity: model.SevHigh}}
		}
		hits = append(hits, h)
	}
	s.Write(evs, hits)
	waitWritten(t, s, 300)
	s.maintain(false) // 刷新后即可检索（无需等待分段关闭）

	q := Query{From: base.Add(-time.Hour), To: base.Add(5 * time.Hour)}
	res, err := s.Search(ctx, q)
	if err != nil || len(res.Records) != 200 || !res.Truncated || res.Segments != 3 {
		t.Fatalf("默认最多 200 条: %v %d %+v", err, len(res.Records), res)
	}
	if !res.Records[0].Time.After(res.Records[199].Time) || res.Records[0].Raw != evs[299].Raw {
		t.Fatal("结果应按时间倒序，最新的在前")
	}
	q.IP, q.Limit = "198.51.100.2", 1000
	res, _ = s.Search(ctx, q)
	if len(res.Records) != 100 || res.Truncated {
		t.Fatalf("按 IP: %d %+v", len(res.Records), res.Reason)
	}
	q.IP = "203.0.113.99"
	if res, _ = s.Search(ctx, q); len(res.Records) != 0 || res.Scanned != 0 {
		t.Fatalf("不存在的 IP 应由布隆过滤器跳过全部分段: %+v", res)
	}
	q.IP, q.Keyword = "", "UNION"
	res, _ = s.Search(ctx, q)
	if len(res.Records) != 1 || res.Records[0].Raw != "GET /search?q=Union\tSelect 1 HTTP/1.1" {
		t.Fatalf("关键字（不区分大小写）: %+v", res.Records)
	}
	q.Keyword, q.AttacksOnly = "", true
	if res, _ = s.Search(ctx, q); len(res.Records) != 30 || !res.Records[0].Attack {
		t.Fatalf("只看攻击: %d", len(res.Records))
	}
	if _, err := s.Search(ctx, Query{From: base, To: base.Add(40 * 24 * time.Hour)}); err != ErrRange {
		t.Fatal("时间范围过大应报错")
	}

	// 再次写入已关闭的小时：追加新的 gzip 成员，检索能读到前后两部分
	s.mu.Lock()
	for _, seg := range s.segs {
		s.closeLocked(seg)
	}
	s.mu.Unlock()
	s.Write([]*model.Event{ev(base.Add(time.Minute), "198.51.100.9", "late line")}, [][]model.Hit{nil})
	waitWritten(t, s, 301)
	cancel()
	s.Close(5 * time.Second)

	ctx2 := context.Background()
	if res, _ := s.Search(ctx2, Query{From: base, To: base.Add(30 * time.Minute), IP: "198.51.100.1", Limit: 1000}); len(res.Records) != 21 { // 两端都包含
		t.Fatalf("多个 gzip 成员: %d", len(res.Records))
	}
	if res, _ := s.Search(ctx2, Query{From: base, To: base.Add(30 * time.Minute), Keyword: "late line"}); len(res.Records) != 1 {
		t.Fatal("追加写入的日志")
	}

	// 完整性校验：哈希链完整、分段一致
	v := s.Verify(ctx2)
	if !v.ChainOK || v.OK != 3 || len(v.Problems) != 0 {
		t.Fatalf("校验: %+v", v)
	}
	// 篡改分段内容
	p := filepath.Join(dir, "20261020", "10.log.gz")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0xff
	os.WriteFile(p, b, 0o640)
	// 删除留存期内的分段
	os.Remove(filepath.Join(dir, "20261020", "11.log.gz"))
	v = s.Verify(ctx2)
	if v.OK != 1 || len(v.Problems) != 2 || !strings.Contains(strings.Join(v.Problems, ";"), "篡改") || !strings.Contains(strings.Join(v.Problems, ";"), "缺失") {
		t.Fatalf("应发现篡改与缺失: %+v", v)
	}
	// 修改清单
	mp := filepath.Join(dir, "manifest.jsonl")
	m, _ := os.ReadFile(mp)
	os.WriteFile(mp, []byte(strings.Replace(string(m), `"size":`, `"size":1`, 1)), 0o640)
	if v = s.Verify(ctx2); v.ChainOK {
		t.Fatal("清单被修改后哈希链应断裂")
	}
	st := s.Status()
	if st.Written != 301 || len(st.Days) != 1 || st.Oldest != "20261020" {
		t.Fatalf("状态: %+v", st)
	}
}

func TestCleanup(t *testing.T) {
	dir := t.TempDir()
	loc := time.Local
	now := time.Now()
	for _, d := range []int{-200, -100, -2, 0} {
		day := filepath.Join(dir, now.AddDate(0, 0, d).Format("20060102"))
		os.MkdirAll(day, 0o750)
		os.WriteFile(filepath.Join(day, "01.log.gz"), make([]byte, 1000), 0o640)
	}
	s := &Store{opt: Options{Dir: dir, RetentionDays: 180, MaxBytes: 2500, Location: loc}, segs: map[string]*segment{}}
	s.cleanup()
	left, _ := os.ReadDir(dir)
	var names []string
	for _, d := range left {
		names = append(names, d.Name())
	}
	// -200 天超过留存期；剩余 3 天 3000 字节超过容量上限 2500，再删除最早的 -100 天；当天不删除
	want := []string{now.AddDate(0, 0, -2).Format("20060102"), now.Format("20060102"), "removed"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("清理后: %v，期望 %v", names, want)
	}
	if !s.removed(now.AddDate(0, 0, -100).Format("20060102") + "/01.log.gz") {
		t.Fatal("因容量清理的分段应留下标记")
	}
}

func BenchmarkWrite(b *testing.B) {
	e := ev(time.Now(), "198.51.100.1", `198.51.100.1 - - [25/Oct/2026:10:00:00 +0800] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"`)
	seg, err := openSegment(b.TempDir(), "20261025/10")
	if err != nil {
		b.Fatal(err)
	}
	defer seg.close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		seg.append(e.Time, e, false)
	}
}
