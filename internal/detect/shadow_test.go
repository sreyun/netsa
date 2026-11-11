package detect

import (
	"strings"
	"testing"

	"netsa/internal/model"
)

// 影子运行：规则照常匹配，命中只计入统计并保留最近的样本，不产生告警；没有统计实例时影子规则只是不生效。
func TestShadowRule(t *testing.T) {
	rules := []Rule{
		{ID: "c-shadow", Name: "影子规则", Category: "自定义规则", Severity: "high", Target: "uri", Pattern: `/legacy/export`, Shadow: true},
		{ID: "c-live", Name: "正式规则", Category: "自定义规则", Severity: "high", Target: "uri", Pattern: `/legacy/import`},
	}
	e, err := NewEngineWith("", rules, 1)
	if err != nil {
		t.Fatal(err)
	}
	st := NewShadowStats()
	e.SetShadow(st)
	ev := func(uri string) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.example.com", Method: "GET", URI: uri, Status: 200, UA: "Mozilla/5.0"}
	}
	for i := 0; i < 7; i++ {
		for _, h := range e.Inspect(ev("/legacy/export?n=" + strings.Repeat("x", i))) {
			if h.RuleID == "c-shadow" {
				t.Fatal("影子规则不应产生命中")
			}
		}
	}
	found := false
	for _, h := range e.Inspect(ev("/legacy/import")) {
		found = found || h.RuleID == "c-live"
	}
	if !found {
		t.Fatal("正式规则应照常命中")
	}
	snap := st.Snapshot()
	s := snap["c-shadow"]
	if s.Hits != 7 || len(s.Samples) != maxShadowSamples || !strings.Contains(s.Samples[0], "xxxxxx") || s.First.IsZero() || len(snap) != 1 {
		t.Fatalf("影子统计: %+v", snap)
	}
	st.Keep(nil)
	if len(st.Snapshot()) != 0 {
		t.Fatal("不再影子运行的规则不保留统计")
	}
	// 没有统计实例：影子规则同样不产生命中
	e2, _ := NewEngineWith("", rules, 1)
	for _, h := range e2.Inspect(ev("/legacy/export")) {
		if h.RuleID == "c-shadow" {
			t.Fatal("影子规则不应产生命中")
		}
	}
}
