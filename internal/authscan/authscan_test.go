package authscan

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netsa/internal/model"
)

func atk(cat string) model.Hit {
	return model.Hit{RuleID: "r", Name: "r", Category: cat, Severity: model.SevHigh, Phase: model.PhaseExploit}
}

func TestAddValidate(t *testing.T) {
	m, _ := Load("")
	now := time.Now()
	for _, c := range []struct {
		e    Entry
		want string
	}{
		{Entry{IP: "bogus", End: now.Add(time.Hour), Note: "x"}, "无效"},
		{Entry{IP: "10.0.0.0/8", End: now.Add(time.Hour), Note: "x"}, "范围过大"},
		{Entry{IP: "2001:db8::/32", End: now.Add(time.Hour), Note: "x"}, "范围过大"},
		{Entry{IP: "1.2.3.4", End: now.Add(time.Hour)}, "说明"},
		{Entry{IP: "1.2.3.4", Note: "x"}, "结束时间"},
		{Entry{IP: "1.2.3.4", Start: now.Add(2 * time.Hour), End: now.Add(time.Hour), Note: "x"}, "晚于开始"},
		{Entry{IP: "1.2.3.4", Start: now.Add(-3 * time.Hour), End: now.Add(-time.Hour), Note: "x"}, "已过"},
		{Entry{IP: "1.2.3.4", Start: now.Add(-48 * time.Hour), End: now.Add(time.Hour), Note: "x"}, "回溯"},
		{Entry{IP: "1.2.3.4", End: now.Add(100 * 24 * time.Hour), Note: "x"}, "90 天"},
		{Entry{IP: "1.2.3.4", End: now.Add(time.Hour), Note: strings.Repeat("长", 201)}, "过长"},
	} {
		if _, err := m.Add(c.e); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: 应报错 %q，实际 %v", c.e, c.want, err)
		}
	}
	e, err := m.Add(Entry{IP: " 198.51.100.0/24 ", End: now.Add(time.Hour), Note: "某测评机构等保测评，工单 #123"})
	if err != nil || e.IP != "198.51.100.0/24" || e.Status != StatusActive || e.Start.IsZero() {
		t.Fatalf("合法登记: %+v %v", e, err)
	}
	if e, _ := m.Add(Entry{IP: "::ffff:203.0.113.9", End: now.Add(time.Hour), Note: "x"}); e.IP != "203.0.113.9" {
		t.Fatalf("IPv4 映射地址应归一: %s", e.IP)
	}
}

// 登记的时间窗内匹配，窗外（未开始、已结束）不匹配；按日志时间判断，补录的历史日志同样适用。
func TestMatchWindow(t *testing.T) {
	m, _ := Load("")
	now := time.Now()
	clock := now
	m.now = func() time.Time { return clock }
	e, err := m.Add(Entry{IP: "198.51.100.0/24", Start: now.Add(time.Hour), End: now.Add(3 * time.Hour), Note: "渗透测试"})
	if err != nil || e.Status != StatusPending {
		t.Fatalf("未开始的登记: %+v %v", e, err)
	}
	if m.Active() != 0 {
		t.Fatal("未开始的登记不计入生效数")
	}
	for _, c := range []struct {
		ip        string
		clock, at time.Duration // 当前时间、日志时间（相对 now）
		want      bool
	}{
		{"198.51.100.7", 30 * time.Minute, 30 * time.Minute, false}, // 未开始
		{"198.51.100.7", 2 * time.Hour, 2 * time.Hour, true},
		{"::ffff:198.51.100.7", 2 * time.Hour, 2 * time.Hour, true},
		{"198.51.101.7", 2 * time.Hour, 2 * time.Hour, false},              // 不在网段内
		{"198.51.100.7", 3 * time.Hour, 3 * time.Hour, false},              // 恰好结束
		{"bogus", 2 * time.Hour, 2 * time.Hour, false},                     // 地址无效
		{"198.51.100.7", 0, 48 * time.Hour, false},                         // 日志时间远在未来（设备时钟错误）：按当前时间判断，尚未开始
		{"198.51.100.7", 5 * time.Hour, 2 * time.Hour, true},               // 积压的日志：按日志时间，在时间窗内
		{"198.51.100.7", 5 * time.Hour, 4 * time.Hour, false},              // 积压的日志：时间窗之后的扫描照常检测
		{"198.51.100.7", 30*time.Hour + 3*time.Hour, 2 * time.Hour, false}, // 结束一天以后不再按日志时间补放行
		{"198.51.100.7", 2*time.Hour + time.Minute, 2*time.Hour + time.Minute, true},
	} {
		clock = now.Add(c.clock)
		m.Flush() // 定期维护：清理已结束一天的登记
		if got := m.Match(c.ip, now.Add(c.at)) != nil; got != c.want {
			t.Errorf("%s 当前 %v 日志 %v: %v，应为 %v", c.ip, c.clock, c.at, got, c.want)
		}
	}
	clock = now.Add(2 * time.Hour)
	m.Flush()
	if m.Active() != 1 || m.Match("198.51.100.7", time.Time{}) == nil {
		t.Fatal("到了开始时间应自动生效")
	}
	clock = now.Add(4 * time.Hour)
	m.Flush()
	if m.Active() != 0 || m.Match("198.51.100.7", time.Time{}) != nil {
		t.Fatal("过了结束时间应自动恢复检测")
	}
	if l := m.List(); len(l) != 1 || l[0].Status != StatusEnded {
		t.Fatalf("结束的登记保留记录: %+v", l)
	}
}

// 期间的命中按登记汇总；提前结束后恢复检测，统计保留并持久化。
func TestRecordFinishPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authscans.json")
	m, _ := Load(path)
	now := time.Now()
	e, _ := m.Add(Entry{IP: "203.0.113.5", End: now.Add(time.Hour), Note: "漏洞扫描", Creator: "alice"})
	ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.5", Host: "www.example.com", URI: "/?id=1'", Time: now}
	hit := m.Match(ev.SrcIP, ev.Time)
	if hit == nil {
		t.Fatal("应匹配")
	}
	m.Record(hit, ev, []model.Hit{atk("SQL注入"), atk("XSS跨站脚本"), {Category: "工具", TagOnly: true}})
	m.Record(hit, &model.Event{Kind: model.KindFirewall, SrcIP: "203.0.113.5", DstIP: "10.0.0.10", DstPort: 22, Time: now}, nil)
	if _, err := m.Finish(e.ID); err != nil {
		t.Fatal(err)
	}
	// 结束之前匹配到的对象上的计数仍记到登记上
	m.Record(hit, ev, []model.Hit{atk("SQL注入")})
	if m.Match(ev.SrcIP, time.Now()) != nil {
		t.Fatal("提前结束后应恢复检测")
	}
	if _, err := m.Finish(e.ID); err == nil {
		t.Fatal("已结束的登记不能再次结束")
	}
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Flush() // 保存最后一次计数
	m.Flush()
	r, _ = Load(path)
	l := r.List()
	if len(l) != 1 {
		t.Fatalf("登记应持久化: %+v", l)
	}
	x := l[0]
	if x.Status != StatusEnded || !x.Ended || x.Events != 3 || x.Hits != 3 || x.Categories["SQL注入"] != 2 || x.Targets["www.example.com"] != 3 || x.Creator != "alice" {
		t.Fatalf("期间的统计: %+v", x)
	}
	if r.Total() != 3 {
		t.Fatalf("累计放行命中: %d", r.Total())
	}
	if _, err := r.Delete(x.ID); err != nil || len(r.List()) != 0 {
		t.Fatalf("删除: %v", err)
	}
}

// 没有登记时匹配不做任何解析；并发匹配、记录与修改不冲突（配合 -race）。
func TestConcurrent(t *testing.T) {
	var nilM *Manager
	if nilM.Match("1.2.3.4", time.Now()) != nil || nilM.Active() != 0 || len(nilM.List()) != 0 {
		t.Fatal("未启用时不匹配")
	}
	m, _ := Load("")
	e, _ := m.Add(Entry{IP: "203.0.113.0/24", End: time.Now().Add(time.Hour), Note: "x"})
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				ev := &model.Event{SrcIP: "203.0.113.9", Time: time.Now(), DstIP: "10.0.0.1"}
				if x := m.Match(ev.SrcIP, ev.Time); x != nil {
					m.Record(x, ev, []model.Hit{atk("端口扫描")})
				}
				if g == 0 && i == 250 {
					m.Finish(e.ID)
				}
				if g == 1 && i%100 == 0 {
					m.List()
					m.Flush()
				}
			}
		}()
	}
	wg.Wait()
	if l := m.List(); l[0].Hits == 0 || l[0].Status != StatusEnded {
		t.Fatalf("%+v", l[0])
	}
}

func BenchmarkMatchNone(b *testing.B) {
	m, _ := Load("")
	for i := 0; i < b.N; i++ {
		m.Match("203.0.113.9", time.Time{})
	}
}

func BenchmarkMatchActive(b *testing.B) {
	m, _ := Load("")
	for i := range 20 {
		m.Add(Entry{IP: "198.51." + string(rune('0'+i%10)) + ".0/24", End: time.Now().Add(time.Hour), Note: "x"})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match("203.0.113.9", time.Time{})
	}
}

// 立即开始的登记向前覆盖 1 分钟：日志时间比登记时刻略早（设备时钟误差、只精确到秒的日志）的扫描同样放行，
// 更早的不放行。用固定时钟验证，与平台的时钟精度无关（Linux 的纳秒时钟上曾经匹配不上）。
func TestImmediateStartSlack(t *testing.T) {
	m, _ := Load("")
	clock := time.Date(2026, 11, 5, 10, 0, 0, 500_000_000, time.UTC)
	m.now = func() time.Time { return clock }
	if _, err := m.Add(Entry{IP: "203.0.113.5", End: clock.Add(time.Hour), Note: "渗透测试"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		at   time.Time
		want bool
	}{{clock.Truncate(time.Second), true}, {clock.Add(-30 * time.Second), true}, {clock.Add(-2 * time.Minute), false}, {clock.Add(30 * time.Minute), true}} {
		if got := m.Match("203.0.113.5", c.at) != nil; got != c.want {
			t.Errorf("%s: %v", c.at.Format(time.RFC3339Nano), got)
		}
	}
}
