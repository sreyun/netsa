package archive

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/jackc/pgx/v5/pgconn"

	"netsa/internal/model"
)

func TestWhereBuilder(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	q := Query{From: from, To: to, IP: "10.1.2.0/24", Rule: "sqli", MinSeverity: model.SevHigh, Category: "SQL注入", Search: "100%_x"}
	sql, args, err := q.where()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"time >= $1", "time < $2", "src_ip <<= $3", "rule_id = $4", "rule_name ILIKE $5", "severity >= $6", "category = $7", "target ILIKE $8"} {
		if !strings.Contains(sql, want) {
			t.Errorf("WHERE 缺少 %q: %s", want, sql)
		}
	}
	if len(args) != 8 || args[4] != "%sqli%" || args[7] != `%100\%\_x%` || args[5] != int16(model.SevHigh) {
		t.Fatalf("参数错误: %#v", args)
	}
	// 用户输入只作为参数，不会拼接进 SQL
	q = Query{Rule: "x' OR 1=1 --", Search: "'; DROP TABLE netsa_alerts; --"}
	sql, _, _ = q.where()
	if strings.Contains(sql, "DROP") || strings.Contains(sql, "1=1") {
		t.Fatalf("存在 SQL 注入风险: %s", sql)
	}
	for _, bad := range []string{"1.2.3", "10.0.0.0/33", "abc"} {
		if _, _, err := (&Query{IP: bad}).where(); err == nil {
			t.Errorf("非法 IP %q 应报错", bad)
		}
	}
	if s, _, _ := (&Query{IP: "2001:db8::1"}).where(); !strings.Contains(s, "src_ip <<=") {
		t.Fatal("IPv6 查询")
	}
}

func TestMonthsAndPartitionNames(t *testing.T) {
	sh, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 12, 15, 10, 0, 0, 0, sh)
	if m := monthStart(now, 1); m.Year() != 2027 || m.Month() != 1 || m.Location() != sh {
		t.Fatalf("跨年: %v", m)
	}
	if m := monthStart(now, -12); m.Year() != 2025 || m.Month() != 12 {
		t.Fatalf("上年: %v", m)
	}
	if partitionName(monthStart(now, 0)) != "netsa_alerts_p202612" {
		t.Fatal(partitionName(monthStart(now, 0)))
	}
	a := &Archive{opt: Options{RetentionMonths: 6, Location: sh}}
	if c := a.cutoff(now); !c.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, sh)) {
		t.Fatalf("保留 6 个月（含本月）的起点应为 7 月 1 日: %v", c)
	}
	a.opt.RetentionMonths = -1
	if !a.cutoff(now).IsZero() {
		t.Fatal("负数表示永久保留")
	}
}

func TestCleanAndRow(t *testing.T) {
	if got := clean("a\x00b\xffc"); got != "ab�c" {
		t.Fatalf("clean: %q", got)
	}
	sh, _ := time.LoadLocation("Asia/Shanghai")
	a := &Archive{opt: Options{RetentionMonths: 6, Location: sh, Instance: "n1"}}
	now := time.Now()
	cut := a.cutoff(now)
	// 未来时间按接收时间记录
	r, ok := a.row(item{al: &model.Alert{ID: 1, Time: now.AddDate(1, 0, 0), SrcIP: "::ffff:198.51.100.7", RuleID: "x", Name: "x", Evidence: "e\x00"}}, now, cut)
	if !ok || !r[0].(time.Time).Equal(now) || r[3] == nil || r[16] != "e" {
		t.Fatalf("row: %#v", r)
	}
	// 早于保留期的告警不写入
	if _, ok := a.row(item{al: &model.Alert{Time: now.AddDate(-1, 0, 0), SrcIP: "1.1.1.1"}}, now, cut); ok {
		t.Fatal("过期告警应跳过")
	}
	// 来源不是合法 IP 时 src_ip 为空，原始字符串仍保留
	r, _ = a.row(item{al: &model.Alert{Time: now, SrcIP: "unknown", RuleID: "x", Name: "x"}}, now, cut)
	if r[3] != nil || r[4] != "unknown" {
		t.Fatalf("非法来源: %#v", r[3:5])
	}
}

func TestScrubAndRetry(t *testing.T) {
	err := scrub(errors.New(`failed to connect to postgres://netsa:S3cret!@db:5432/netsa: password=S3cret! host=db`))
	if strings.Contains(err.Error(), "S3cret") {
		t.Fatalf("错误信息泄露口令: %v", err)
	}
	if !retryable(partitionError{fmt.Errorf("x: %w", &pgconn.PgError{Code: "23514"})}) {
		t.Fatal("建分区失败应重试")
	}
	if retryable(&pgconn.PgError{Code: "22021"}) || retryable(&pgconn.PgError{Code: "23505"}) || !retryable(&pgconn.PgError{Code: "57P01"}) || !retryable(errors.New("connection refused")) {
		t.Fatal("重试分类错误")
	}
}

// 告警指纹：重复分析同一份日志得到相同指纹（与告警编号无关），同一运行中内容相同的告警指纹不同。
func TestFingerprint(t *testing.T) {
	now := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	stream := func(idBase uint64) []*model.Alert {
		return []*model.Alert{
			{ID: idBase + 1, Time: now, SrcIP: "10.0.0.1", RuleID: "brute", Target: "a.com /login", Method: "POST", Status: 401},
			{ID: idBase + 2, Time: now, SrcIP: "10.0.0.1", RuleID: "brute", Target: "a.com /login", Method: "POST", Status: 401}, // 同一秒内的重复尝试
			{ID: idBase + 3, Time: now, SrcIP: "10.0.0.2", RuleID: "brute", Target: "a.com /login", Method: "POST", Status: 401},
		}
	}
	run := func(idBase uint64) []int64 {
		a := &Archive{occur: map[uint64]uint32{}}
		var fps []int64
		for _, al := range stream(idBase) {
			fps = append(fps, a.fingerprint(al))
		}
		return fps
	}
	first, second := run(0), run(1000)
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("重复分析应得到相同指纹: %v %v", first, second)
	}
	if first[0] == first[1] || first[0] == first[2] || first[1] == first[2] {
		t.Fatalf("同一运行中的不同告警指纹应不同: %v", first)
	}
}
