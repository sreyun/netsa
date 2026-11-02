package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"netsa/internal/detect"
	"netsa/internal/learn"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 自学习结果在流水线中自动生效：
//   - 反复误报的「规则 + 目标」真正降级（分类底线为高危的注入类规则同样有效，最多低于底线一级）；
//   - 响应证明利用成功时仍升为严重（成功证据优先于学习结果）；
//   - 分析员确认过的攻击来源再次出现时升级一级（不超过高危）。
func TestLearnAppliedEndToEnd(t *testing.T) {
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	l, err := learn.Load(learn.Options{Calibrate: true, Escalate: true})
	if err != nil {
		t.Fatal(err)
	}
	for i, src := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		l.Feedback(learn.Case{Incident: uint64(i + 1), Source: src, Rules: map[string]int{"sqli-union": 1},
			Targets: []string{"shop.example.com /api/search?q=" + src}, Verdict: learn.VerdictFP, User: "ana"})
	}
	l.Feedback(learn.Case{Incident: 9, Source: "203.0.113.77", Rules: map[string]int{"sqli-union": 1},
		Targets: []string{"shop.example.com /api/order"}, Verdict: learn.VerdictTP, User: "ana"})

	st := store.New(1000, 1000, 5, time.Hour)
	got := map[string]*model.Alert{}
	p := &Pipeline{Engine: eng, Store: st, Learn: l, OnAlert: func(a *model.Alert) { got[a.SrcIP+" "+a.Target] = a }}
	in := make(chan []*model.Event, 10)
	done := p.Run(context.Background(), in, 1)
	now := time.Now()
	web := func(src, uri string, status int) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: src, Host: "shop.example.com", Method: "GET", URI: uri, Status: status, Bytes: 500, Time: now,
			UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"}
	}
	in <- []*model.Event{
		web("198.51.100.50", "/api/search?q=1%20union%20select%201,2", 403), // 反复误报的接口：下调
		web("198.51.100.51", "/api/order?id=1%20union%20select%201,2", 403), // 其他接口：不受影响
		web("198.51.100.52", "/api/search?q=1%20union%20select%20pwd", 200), // 成功利用：仍为严重
		web("203.0.113.77", "/.git/config", 404),                            // 已确认的攻击来源复现：升级
	}
	close(in)
	<-done

	find := func(src string) *model.Alert {
		for k, a := range got {
			if strings.HasPrefix(k, src+" ") {
				return a
			}
		}
		t.Fatalf("%s 未产生告警: %v", src, got)
		return nil
	}
	if a := find("198.51.100.50"); a.Severity != model.SevMedium || !strings.Contains(a.Evidence, "自学习校准") {
		t.Fatalf("反复误报的接口应真正降为中危: %s %s", a.Severity, a.Evidence)
	}
	if a := find("198.51.100.51"); a.Severity != model.SevHigh {
		t.Fatalf("其他接口不受影响: %s", a.Severity)
	}
	if a := find("198.51.100.52"); a.Severity != model.SevCritical {
		t.Fatalf("成功利用应仍为严重: %s %s", a.Severity, a.Result)
	}
	if a := find("203.0.113.77"); a.Severity != model.SevHigh || !strings.Contains(a.Evidence, "曾被分析员确认为攻击") {
		t.Fatalf("已确认的攻击来源复现应升级一级: %s %s", a.Severity, a.Evidence)
	}
	if ap := l.Report().Applied; ap.Target < 1 || ap.Escalated < 1 {
		t.Fatalf("应统计自动生效次数: %+v", ap)
	}
}
