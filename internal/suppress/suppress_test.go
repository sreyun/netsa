package suppress

import (
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/model"
)

func hit(rule, cat string) model.Hit {
	return model.Hit{RuleID: rule, Name: rule, Category: cat, Severity: model.SevHigh}
}

func TestFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppressions.json")
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ev := &model.Event{Kind: model.KindWeb, SrcIP: "10.8.1.5", Host: "a.com", URI: "/api/Search?q=select", Method: "GET"}
	hits := []model.Hit{hit("sqli-union", "SQL注入"), hit("xss-script", "XSS跨站脚本"), {RuleID: "ua", TagOnly: true, Category: "SQL注入"}}
	if got := m.Filter(ev, hits); len(got) != 3 {
		t.Fatal("没有规则时原样返回")
	}
	// 规则 + 目标：搜索接口上的 SQL 注入规则误报
	if _, err := m.Add(Rule{RuleID: "sqli-union", Target: "/api/search", Reason: "搜索词包含 SQL 关键字"}, 0); err != nil {
		t.Fatal(err)
	}
	got := m.Filter(ev, hits)
	if len(got) != 2 || got[0].RuleID != "xss-script" || !got[1].TagOnly {
		t.Fatalf("应只抑制搜索接口上的 SQL 注入命中: %+v", got)
	}
	if len(hits) != 3 || hits[0].RuleID != "sqli-union" {
		t.Fatal("不能修改调用方的切片")
	}
	if got := m.Filter(&model.Event{Kind: model.KindWeb, SrcIP: "10.8.1.5", URI: "/login?id=1 union select"}, hits[:1]); len(got) != 1 {
		t.Fatal("其他接口不受影响")
	}
	// 网段 + 攻击类型：内部扫描器
	m.Add(Rule{IP: "10.8.0.0/16", Category: "XSS跨站脚本", Reason: "内部安全扫描"}, 7)
	if got := m.Filter(ev, hits); len(got) != 1 || !got[0].TagOnly {
		t.Fatalf("网段 + 攻击类型: %+v", got)
	}
	if got := m.Filter(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", URI: "/x"}, hits[1:2]); len(got) != 1 {
		t.Fatal("网段外不受影响")
	}
	if m.Total() != 3 {
		t.Fatalf("抑制计数: %d", m.Total())
	}
	// 过期规则不再生效
	now := time.Now()
	m.now = func() time.Time { return now.Add(8 * 24 * time.Hour) }
	if got := m.Filter(ev, hits[1:2]); len(got) != 1 {
		t.Fatal("过期规则不应生效")
	}
	m.now = time.Now
	// 校验
	for _, bad := range []Rule{{}, {Category: "SQL注入"}, {IP: "not-ip"}, {IP: "0.0.0.0/0"}} {
		if _, err := m.Add(bad, 0); err == nil {
			t.Errorf("应拒绝: %+v", bad)
		}
	}
	// 持久化
	m.Flush()
	m2, err := Load(path)
	if err != nil || m2.Count() != 2 || m2.Total() != 3 {
		t.Fatalf("重启后: %v %d %d", err, m2.Count(), m2.Total())
	}
	list := m2.List()
	if _, err := m2.Delete(list[0].ID); err != nil || m2.Count() != 1 {
		t.Fatal("删除")
	}
}

func BenchmarkFilterNoMatch(b *testing.B) {
	m, _ := Load("")
	for i := 0; i < 200; i++ {
		m.Add(Rule{RuleID: "r" + string(rune('a'+i%26)), IP: "10.0.0.1", Reason: "x"}, 0)
	}
	ev := &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", URI: "/x"}
	hits := []model.Hit{hit("sqli-union", "SQL注入")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Filter(ev, hits)
	}
}

// 过期规则不占用名额，过期 30 天后自动清理并落盘。
func TestExpiredPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppressions.json")
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.now = func() time.Time { return now }
	for i := 0; i < maxRules; i++ {
		if _, err := m.Add(Rule{RuleID: "r", Target: "/t" + string(rune('a'+i%26)), Reason: "x"}, 1); err != nil {
			t.Fatalf("第 %d 条: %v", i, err)
		}
	}
	if _, err := m.Add(Rule{RuleID: "r", Target: "/x", Reason: "x"}, 1); err == nil {
		t.Fatal("生效中的规则达到上限时应拒绝")
	}
	// 2 天后全部过期：不再占用名额，但仍保留在列表中供核对
	now = now.Add(48 * time.Hour)
	if _, err := m.Add(Rule{RuleID: "r", Target: "/new", Reason: "x"}, 0); err != nil {
		t.Fatalf("过期规则不应占用名额: %v", err)
	}
	if m.Count() != maxRules+1 {
		t.Fatalf("过期规则应暂时保留: %d", m.Count())
	}
	ev := &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", URI: "/ta"}
	if got := m.Filter(ev, []model.Hit{hit("r", "SQL注入")}); len(got) != 1 {
		t.Fatal("过期规则不应再抑制")
	}
	// 过期满 30 天：定期保存时清理
	now = now.Add(31 * 24 * time.Hour)
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if m.Count() != 1 {
		t.Fatalf("应清理过期已久的规则: %d", m.Count())
	}
	m2, err := Load(path)
	if err != nil || m2.Count() != 1 {
		t.Fatalf("清理结果应落盘: %v %d", err, m2.Count())
	}
}
