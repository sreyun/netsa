package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netsa/internal/model"
)

// 集成测试需要一个可写的 PostgreSQL（建议 ≥ 11）：
//
//	NETSA_TEST_PG_URL=postgres://user:pass@127.0.0.1:5432/db?sslmode=disable go test ./internal/archive/
//
// 每个测试在独立的 schema 中运行，结束后删除。
func testDSN(t *testing.T) string {
	dsn := os.Getenv("NETSA_TEST_PG_URL")
	if dsn == "" {
		t.Skip("未设置 NETSA_TEST_PG_URL，跳过 PostgreSQL 集成测试")
	}
	schema := fmt.Sprintf("netsa_test_%d_%d", time.Now().UnixNano()%1e9, rand.Intn(1e6))
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err == nil {
			c.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			c.Close(context.Background())
		}
	})
	return withParam(dsn, "search_path", schema)
}

func withParam(dsn, k, v string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + k + "=" + url.QueryEscape(v)
}

func openTest(t *testing.T, dsn string, retention int, batch ...int) *Archive {
	sh, _ := time.LoadLocation("Asia/Shanghai")
	bs := 50
	if len(batch) > 0 {
		bs = batch[0]
	}
	a, err := Open(context.Background(), Options{DSN: dsn, RetentionMonths: retention, BatchSize: bs, FlushInterval: 50 * time.Millisecond,
		QueueSize: 100000, Instance: "node-1", Location: sh})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("等待超时: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func partNames(t *testing.T, a *Archive) map[string]PartitionInfo {
	ps, err := a.partitions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]PartitionInfo{}
	for _, p := range ps {
		m[p.Name] = p
	}
	return m
}

func TestIntegrationArchive(t *testing.T) {
	dsn := testDSN(t)
	a := openTest(t, dsn, 6)
	defer a.Close(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	loc := a.opt.Location
	now := time.Now().In(loc)
	parts := partNames(t, a)
	for _, m := range []int{-1, 0, 1} {
		if _, ok := parts[partitionName(monthStart(now, m))]; !ok {
			t.Fatalf("缺少分区 %s: %v", partitionName(monthStart(now, m)), parts)
		}
	}
	if _, ok := parts[Table+"_default"]; !ok {
		t.Fatal("缺少默认分区")
	}

	// 默认分区中预先存在 3 个月前的数据（例如分区创建之前写入的），建分区时应迁入新分区
	old := monthStart(now, -3).Add(36 * time.Hour)
	if _, err := a.pool.Exec(ctx, "INSERT INTO "+Table+" (time, alert_id, src, rule_id, rule_name, severity) VALUES ($1, 9999, '203.0.113.99', 'legacy', '历史规则', 2)", old); err != nil {
		t.Fatal(err)
	}

	alerts := []*model.Alert{
		{ID: 1, Time: now.Add(-time.Minute), Kind: model.KindWeb, SrcIP: "10.1.2.3", Location: "内网", RuleID: "sqli-001", Name: "SQL 注入 union select", Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultBlocked, Method: "GET", Status: 403, Target: "/login?id=1 union select 1", Evidence: "union select", Source: "nginx", Lat: 31.2, Lon: 121.5},
		{ID: 2, Time: now.Add(-2 * time.Minute), Kind: model.KindWeb, SrcIP: "10.1.2.200", RuleID: "xss-001", Name: "XSS 跨站脚本", Category: "XSS", Severity: model.SevMedium, Result: model.ResultPassed, Target: "/q?<script>", Evidence: "100%_done", Source: "nginx"},
		{ID: 3, Time: now.Add(-3 * time.Minute), Kind: model.KindFirewall, SrcIP: "198.51.100.7", RuleID: "fw-deny", Name: "防火墙拒绝", Category: "端口扫描", Severity: model.SevLow, Result: model.ResultBlocked, Source: "firewall"},
		{ID: 4, Time: now.Add(-4 * time.Minute), Kind: model.KindWeb, SrcIP: "2001:db8::5", RuleID: "rce-001", Name: "远程命令执行", Category: "命令执行", Severity: model.SevCritical, Result: model.ResultSuccess, Source: "nginx"},
		// 攻击载荷中的 NUL 字节与非法 UTF-8 不能导致整批失败
		{ID: 5, Time: now.Add(-5 * time.Minute), Kind: model.KindWeb, SrcIP: "::ffff:10.1.2.4", RuleID: "sqli-001", Name: "SQL 注入 union select", Category: "SQL注入", Severity: model.SevHigh, Target: "/a\x00b", Evidence: "bad\xff\xfeutf8\x00", UA: "sqlmap\x00", Source: "nginx"},
		// 设备时钟错误产生的未来时间
		{ID: 6, Time: now.AddDate(0, 3, 0), SrcIP: "10.9.9.9", RuleID: "clock", Name: "时钟错误", Severity: model.SevLow},
		// 超过保留期（6 个月）的告警不写入
		{ID: 7, Time: now.AddDate(-1, 0, 0), SrcIP: "10.9.9.8", RuleID: "too-old", Name: "过期", Severity: model.SevLow},
		// 2 个月前与 3 个月前：写入时自动建分区；3 个月前的分区需迁入默认分区中的旧数据
		{ID: 8, Time: monthStart(now, -2).Add(time.Hour), SrcIP: "10.1.2.5", RuleID: "sqli-001", Name: "SQL 注入 union select", Severity: model.SevHigh},
		{ID: 9, Time: old.Add(time.Hour), SrcIP: "203.0.113.99", RuleID: "legacy", Name: "历史规则", Severity: model.SevMedium},
	}
	for _, al := range alerts {
		a.Add(al)
	}
	waitFor(t, "写入 8 条告警", 10*time.Second, func() bool { w, _ := a.Counts(); return w == 8 })
	if a.expired.Load() != 1 {
		t.Fatalf("过期计数 %d", a.expired.Load())
	}
	parts = partNames(t, a)
	for _, m := range []int{-2, -3} {
		if _, ok := parts[partitionName(monthStart(now, m))]; !ok {
			t.Fatalf("写入时未自动创建分区 %s", partitionName(monthStart(now, m)))
		}
	}
	var inDefault, inOld int
	a.pool.QueryRow(ctx, "SELECT count(*) FROM "+Table+"_default").Scan(&inDefault)
	a.pool.QueryRow(ctx, "SELECT count(*) FROM "+partitionName(monthStart(now, -3))).Scan(&inOld)
	if inDefault != 0 || inOld != 2 {
		t.Fatalf("建分区时应把默认分区中的数据迁入: default=%d 分区=%d", inDefault, inOld)
	}

	week := Query{From: now.AddDate(0, 0, -7), To: now.Add(time.Minute)}
	search := func(q Query) []Row {
		t.Helper()
		if q.Limit == 0 {
			q.Limit = 100
		}
		res, err := a.Search(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return res.Items
	}
	ids := func(rows []Row) string {
		var s []string
		for _, r := range rows {
			s = append(s, fmt.Sprint(r.AlertID))
		}
		return strings.Join(s, ",")
	}
	cases := []struct {
		name string
		q    Query
		want string
	}{
		{"最近 7 天（时间倒序，含时钟错误按接收时间记录的告警）", week, "6,1,2,3,4,5"},
		{"精确 IP", Query{IP: "10.1.2.3"}, "1"},
		{"IPv4 映射地址按 IPv4 存储", Query{IP: "10.1.2.4"}, "5"},
		{"网段", Query{From: week.From, IP: "10.1.2.0/24"}, "1,2,5"},
		{"IPv6", Query{IP: "2001:db8::/32"}, "4"},
		{"规则 ID", Query{From: week.From, Rule: "sqli-001"}, "1,5"},
		{"规则名称包含", Query{Rule: "跨站"}, "2"},
		{"最低等级", Query{From: week.From, MinSeverity: model.SevHigh}, "1,4,5"},
		{"攻击类型", Query{Category: "SQL注入"}, "1,5"},
		{"研判结果", Query{Result: model.ResultSuccess}, "4"},
		{"日志大类", Query{Kind: string(model.KindFirewall)}, "3"},
		{"关键字（% 与 _ 按字面匹配）", Query{Search: "100%_"}, "2"},
		{"关键字不区分大小写（同时匹配目标、证据与规则名称）", Query{Search: "UNION SELECT"}, "1,5,8"},
		{"通配符不会匹配全部", Query{Search: "%"}, "2"},
		{"时间范围（2 个月前所在月）", Query{From: monthStart(now, -2), To: monthStart(now, -1)}, "8"},
		{"组合条件", Query{From: week.From, IP: "10.1.2.0/24", Rule: "sqli-001", MinSeverity: model.SevHigh}, "1,5"},
		{"无结果", Query{IP: "192.0.2.1"}, ""},
		{"注入尝试按字面匹配", Query{Rule: "' OR 1=1 --"}, ""},
	}
	for _, c := range cases {
		if got := ids(search(c.q)); got != c.want {
			t.Errorf("%s: 得到 %q，期望 %q", c.name, got, c.want)
		}
	}
	// 数据清洗与字段映射
	r := search(Query{IP: "10.1.2.4"})[0]
	if r.Target != "/ab" || r.Evidence != "bad�utf8" || r.UA != "sqlmap" || r.SrcIP != "::ffff:10.1.2.4" || r.Instance != "node-1" {
		t.Fatalf("数据清洗: %+v", r)
	}
	r = search(Query{IP: "10.1.2.3"})[0]
	if r.Status != 403 || r.Method != "GET" || r.Location != "内网" || r.Severity != model.SevHigh || r.Kind != "web" || !r.Time.Equal(alerts[0].Time.Truncate(time.Microsecond)) {
		t.Fatalf("字段映射: %+v", r)
	}
	// 分页
	p1, _ := a.Search(ctx, Query{From: week.From, Limit: 4})
	p2, _ := a.Search(ctx, Query{From: week.From, Limit: 4, Offset: 4})
	if len(p1.Items) != 4 || !p1.HasMore || len(p2.Items) != 2 || p2.HasMore || ids(p1.Items)+","+ids(p2.Items) != "6,1,2,3,4,5" {
		t.Fatalf("分页: %s / %s", ids(p1.Items), ids(p2.Items))
	}
	if _, err := a.Search(ctx, Query{IP: "not-ip"}); err == nil {
		t.Fatal("非法 IP 应报错")
	}

	// 统计
	st, err := a.Stats(ctx, Query{From: monthStart(now, -6)})
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 9 || st.BySeverity["high"] != 3 || st.BySeverity["critical"] != 1 || len(st.TopRules) == 0 || st.TopRules[0].Name != "sqli-001" || st.TopRules[0].Count != 3 {
		t.Fatalf("统计: %+v", st)
	}
	if st.TopIPs[0].Name != "203.0.113.99" || st.TopIPs[0].Count != 2 || len(st.Trend) < 3 || st.Bucket != "day" || st.FirstSeen.After(old) {
		t.Fatalf("统计: %+v", st)
	}
	if day := st.Trend[len(st.Trend)-1].Name; day != now.Format("2006-01-02") && day != now.Add(-5*time.Minute).Format("2006-01-02") {
		t.Fatalf("按天统计应使用配置时区: %+v", st.Trend)
	}
	// 数据跨度在 3 天以内时按小时统计趋势
	if hst, err := a.Stats(ctx, week); err != nil || hst.Total != 6 || hst.Bucket != "hour" || len(hst.Trend) == 0 || len(hst.Trend[0].Name) != len("2006-01-02 15:00") {
		t.Fatalf("按小时统计: %+v %v", hst, err)
	}
	empty, err := a.Stats(ctx, Query{IP: "192.0.2.1"})
	if err != nil || empty.Total != 0 || empty.TopIPs == nil {
		t.Fatalf("空统计: %+v %v", empty, err)
	}

	// 导出
	var exported []int64
	n, err := a.Export(ctx, Query{From: week.From, MinSeverity: model.SevMedium}, func(r Row) error { exported = append(exported, r.AlertID); return nil })
	if err != nil || n != 4 || fmt.Sprint(exported) != "[1 2 4 5]" {
		t.Fatalf("导出: %d %v %v", n, exported, err)
	}
	stop := errors.New("stop")
	if n, err := a.Export(ctx, week, func(Row) error { return stop }); !errors.Is(err, stop) || n != 0 {
		t.Fatalf("导出回调错误应中止: %d %v", n, err)
	}

	// 状态
	s := a.Status(ctx)
	if !s.Connected || s.Written != 8 || s.Expired != 1 || len(s.Partitions) < 6 || !s.Partitions[len(s.Partitions)-1].Default || strings.Contains(s.Server, "@") {
		t.Fatalf("状态: %+v", s)
	}

	// 保留期：模拟 8 个月之后的维护，只保留最近 6 个月（含当月）的分区
	future := monthStart(now, 8).Add(time.Hour)
	if err := a.dropExpired(ctx, future); err != nil {
		t.Fatal(err)
	}
	cut := a.cutoff(future)
	for name, p := range partNames(t, a) {
		if !p.Default && !p.To.After(cut) {
			t.Fatalf("过期分区 %s 未删除", name)
		}
	}
	if _, ok := partNames(t, a)[partitionName(monthStart(now, 1))]; ok {
		t.Fatal("下月分区早于新的保留期起点，应被删除")
	}
	// 删除分区后重新写入同月数据，分区会重新创建
	a.Add(&model.Alert{ID: 10, Time: now, SrcIP: "10.0.0.1", RuleID: "again", Name: "again", Severity: model.SevLow})
	waitFor(t, "删除分区后重新写入", 10*time.Second, func() bool { w, _ := a.Counts(); return w == 9 })
	if got := ids(search(Query{Rule: "again"})); got != "10" {
		t.Fatalf("重新写入: %q", got)
	}
}

// 多个 netsa 实例共用一个数据库：并发建表、建分区由咨询锁串行化，大量并发写入不丢失。
func TestIntegrationConcurrent(t *testing.T) {
	dsn := testDSN(t)
	var as []*Archive
	for i := 0; i < 3; i++ {
		as = append(as, openTest(t, dsn, 3, 1000)) // 默认批量大小
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, a := range as {
		if err := a.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
	}
	const perWorker, workers = 5000, 8
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			a := as[w%len(as)]
			for i := 0; i < perWorker; i++ {
				a.Add(&model.Alert{ID: uint64(w*perWorker + i), Time: time.Now().Add(-time.Duration(i) * time.Second), SrcIP: fmt.Sprintf("10.%d.%d.%d", w, i/256%256, i%256),
					RuleID: fmt.Sprintf("r%d", i%20), Name: "并发", Severity: model.Severity(1 + i%4), Evidence: strings.Repeat("x", 200)})
			}
		}(w)
	}
	wg.Wait()
	total := int64(perWorker * workers)
	waitFor(t, "并发写入", 60*time.Second, func() bool {
		var n int64
		for _, a := range as {
			w, _ := a.Counts()
			n += w
		}
		return n == total
	})
	t.Logf("3 个实例并发写入 %d 条用时 %s", total, time.Since(start).Round(time.Millisecond))
	var n int64
	as[0].pool.QueryRow(ctx, "SELECT count(*) FROM "+Table).Scan(&n)
	for _, a := range as {
		if _, d := a.Counts(); d != 0 {
			t.Fatalf("丢弃 %d 条", d)
		}
		a.Close(5 * time.Second)
	}
	if n != total {
		t.Fatalf("库中 %d 条，期望 %d", n, total)
	}
}

// 数据库不可用时 netsa 照常启动，告警在队列中缓冲；数据库恢复后自动连接并写入。
func TestIntegrationOutageRecovery(t *testing.T) {
	dsn := testDSN(t)
	u, err := url.Parse(dsn)
	if err != nil || u.Host == "" {
		t.Skip("NETSA_TEST_PG_URL 需为 URL 格式")
	}
	target := u.Host
	// 预留一个当前没有监听的端口，稍后在此端口启动转发到真实数据库的代理来模拟“数据库恢复”
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := l.Addr().String()
	l.Close()
	u.Host = proxyAddr
	a := openTest(t, u.String(), 6)
	defer a.Close(5 * time.Second)

	for i := 0; i < 120; i++ {
		a.Add(&model.Alert{ID: uint64(i + 1), Time: time.Now(), SrcIP: "10.0.0.1", RuleID: "r", Name: "缓冲", Severity: model.SevHigh})
	}
	time.Sleep(1500 * time.Millisecond)
	st := a.Status(context.Background())
	pw, _ := u.User.Password()
	if st.Connected || st.Written != 0 || st.LastError == "" || pw != "" && strings.Contains(st.LastError, pw) {
		t.Fatalf("数据库不可用时的状态: %+v", st)
	}
	if _, err := a.Search(context.Background(), Query{}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("数据库不可用时查询应返回 ErrNotReady: %v", err)
	}
	if _, d := a.Counts(); d != 0 {
		t.Fatalf("缓冲期间不应丢弃: %d", d)
	}

	// 数据库恢复
	l, err = net.Listen("tcp", proxyAddr)
	if err != nil {
		t.Skipf("无法在原端口启动代理: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				s, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer s.Close()
				go io.Copy(s, c)
				io.Copy(c, s)
			}()
		}
	}()
	waitFor(t, "数据库恢复后写入缓冲的告警", 20*time.Second, func() bool { w, _ := a.Counts(); return w == 120 })
	if st := a.Status(context.Background()); !st.Connected || st.Queued != 0 {
		t.Fatalf("恢复后状态: %+v", st)
	}
}

// 队列满时丢弃并计数，Add 永不阻塞；关闭时写完队列中剩余的告警。
func TestIntegrationQueueFullAndClose(t *testing.T) {
	dsn := testDSN(t)
	sh, _ := time.LoadLocation("Asia/Shanghai")
	a, err := Open(context.Background(), Options{DSN: dsn, RetentionMonths: 6, BatchSize: 10000, FlushInterval: time.Hour, QueueSize: 100, Location: sh})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 20000; i++ {
		a.Add(&model.Alert{ID: uint64(i), Time: time.Now(), SrcIP: "10.0.0.1", RuleID: "r", Name: "n", Severity: model.SevLow})
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("Add 不应阻塞: %s", time.Since(start))
	}
	_, dropped := a.Counts()
	if dropped == 0 {
		t.Fatal("队列满时应丢弃并计数")
	}
	a.Close(10 * time.Second) // 刷新间隔为 1 小时，只有关闭时的刷新会写入
	w, d := a.Counts()
	if w+d != 20000 || w == 0 {
		t.Fatalf("关闭时应写完队列: 写入 %d 丢弃 %d", w, d)
	}
	a.Add(&model.Alert{ID: 1}) // 关闭后投递不会 panic
}

// 非法 DSN 立即报错；无法连接时 Open 不阻塞。
func TestIntegrationOpenErrors(t *testing.T) {
	if _, err := Open(context.Background(), Options{DSN: "postgres://u:p@[bad"}); err == nil || strings.Contains(err.Error(), ":p@") {
		t.Fatalf("非法 DSN: %v", err)
	}
	start := time.Now()
	a, err := Open(context.Background(), Options{DSN: "postgres://u:secretpw@127.0.0.1:1/db?connect_timeout=1"})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Open 不应等待数据库连接")
	}
	time.Sleep(1200 * time.Millisecond)
	if st := a.Status(context.Background()); st.Connected || strings.Contains(st.LastError, "secretpw") || st.Server != "127.0.0.1:1/db" {
		t.Fatalf("状态: %+v", st)
	}
	a.Close(time.Second)
}

// 同一份日志被重复分析（from_beginning 重启、analyze 重复补录）时不会产生重复归档；同一秒内内容相同的真实告警全部保留。
func TestIntegrationIdempotent(t *testing.T) {
	dsn := testDSN(t)
	now := time.Now().Truncate(time.Second)
	stream := func(idBase uint64) []*model.Alert {
		var out []*model.Alert
		for i := 0; i < 50; i++ {
			out = append(out, &model.Alert{ID: idBase + uint64(i), Time: now.Add(-time.Duration(i) * time.Minute), SrcIP: "10.0.0.1", RuleID: "r", Name: "n", Severity: model.SevHigh, Target: fmt.Sprint("/p", i)})
		}
		// 同一秒内两次完全相同的攻击请求
		for j := 0; j < 2; j++ {
			out = append(out, &model.Alert{ID: idBase + 100 + uint64(j), Time: now, SrcIP: "10.0.0.9", RuleID: "brute", Name: "暴力破解", Severity: model.SevMedium, Target: "/login", Method: "POST", Status: 401})
		}
		return out
	}
	for round, base := range []uint64{0, 5000, 9000} {
		a := openTest(t, dsn, 6)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := a.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		for _, al := range stream(base) {
			a.Add(al)
		}
		a.Close(10 * time.Second)
		var n int
		c, _ := pgx.Connect(ctx, dsn)
		c.QueryRow(ctx, "SELECT count(*) FROM "+Table).Scan(&n)
		c.Close(ctx)
		cancel()
		w, _ := a.Counts()
		if n != 52 {
			t.Fatalf("第 %d 次分析后库中 %d 条，期望 52 条", round+1, n)
		}
		if round == 0 && w != 52 || round > 0 && (w != 0 || a.duplicates.Load() != 52) {
			t.Fatalf("第 %d 次分析: 写入 %d 跳过重复 %d", round+1, w, a.duplicates.Load())
		}
	}
}
