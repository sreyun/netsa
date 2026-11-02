package pipeline

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
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
		web("198.51.100.52", "/api/search?q=1%20union%20select%20pwd", 200), // 只有 200：校准仍然生效，不算成功证据
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
	if a := find("198.51.100.52"); a.Severity != model.SevMedium {
		t.Fatalf("只有响应码不应越过校准: %s %s", a.Severity, a.Result)
	}
	if a := find("203.0.113.77"); a.Severity != model.SevHigh || !strings.Contains(a.Evidence, "曾被分析员确认为攻击") {
		t.Fatalf("已确认的攻击来源复现应升级一级: %s %s", a.Severity, a.Evidence)
	}
	if ap := l.Report().Applied; ap.Target < 1 || ap.Escalated < 1 {
		t.Fatalf("应统计自动生效次数: %+v", ap)
	}
}

// 用户反馈的场景：一个外部来源在几分钟内对防火墙的大量公网地址各连接 2~3 次（5432、3306）。
// 这是互联网背景扫描，不是暴力破解，事件不应是高危；同样次数集中到一台主机才算暴力破解。
func TestBackgroundScanNotHigh(t *testing.T) {
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	run := func(evs []*model.Event) (*store.Store, []*model.Alert) {
		st := store.New(10000, 10000, 100, time.Hour)
		var alerts []*model.Alert
		p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(cfg.Detect.Thresholds), Store: st, OnAlert: func(a *model.Alert) { alerts = append(alerts, a) }}
		in := make(chan []*model.Event, 1)
		done := p.Run(context.Background(), in, 1)
		in <- evs
		close(in)
		<-done
		return st, alerts
	}
	now := time.Now()
	fw := func(src, dst string, port int, at time.Duration) *model.Event {
		return &model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Action: model.ActionAllow, Time: now.Add(at)}
	}
	// 40 个公网地址，每个地址 5432 与 3306 各连 2 次：单端口 80 次连接，超过 brute_conns，但每台只有 2 次
	const src = "160.250.205.248"
	var scan []*model.Event
	for round := 0; round < 2; round++ {
		for i := 1; i <= 40; i++ {
			dst := "43.242.97." + strconv.Itoa(i)
			at := time.Duration(round*40+i) * time.Second
			scan = append(scan, fw(src, dst, 5432, at), fw(src, dst, 3306, at))
		}
	}
	st, alerts := run(scan)
	for _, a := range alerts {
		if a.RuleID == "bhv-fwbrute" {
			t.Fatalf("横向扫描不应判为暴力破解: %+v", a)
		}
	}
	list, _, _ := st.Incidents(store.IncidentQuery{})
	if len(list) != 1 || list[0].Severity >= model.SevHigh {
		t.Fatalf("互联网背景扫描的事件不应是高危: %+v", list)
	}
	last := alerts[len(alerts)-1]
	if last.Severity != model.SevLow {
		t.Fatalf("判定批量扫描后应按低危: %+v", last)
	}
	d := st.Incident(list[0].ID)
	for _, r := range d.Rules {
		if strings.Contains(r.Name, "MySQL") || strings.Contains(r.Name, "PostgreSQL") {
			t.Fatalf("按规则汇总时不应显示具体端口: %s", r.Name)
		}
	}

	// 同样的连接次数集中到一台主机：才是暴力破解。只看到连接次数按中危，到达服务的证据才升高危
	var brute, reached []*model.Event
	for i := 0; i < 35; i++ {
		brute = append(brute, fw("198.51.100.9", "43.242.97.200", 5432, time.Duration(i)*time.Second))
		e := fw("198.51.100.10", "43.242.97.201", 5432, time.Duration(i)*time.Second)
		e.NatDstIP = "10.0.0.21"
		reached = append(reached, e)
	}
	find := func(alerts []*model.Alert) *model.Alert {
		for _, a := range alerts {
			if a.RuleID == "bhv-fwbrute" {
				return a
			}
		}
		t.Fatal("反复连接同一服务应判为暴力破解")
		return nil
	}
	_, a1 := run(brute)
	if a := find(a1); a.Severity != model.SevMedium {
		t.Fatalf("没有到达证据的暴力破解按中危: %s", a.Severity)
	}
	_, a2 := run(reached)
	if a := find(a2); a.Severity != model.SevHigh {
		t.Fatalf("到达服务的暴力破解按高危: %s %s", a.Severity, a.Evidence)
	}
	// 内网来源的扫描是横向移动信号，不降级
	var lateral []*model.Event
	for i := 1; i <= 25; i++ {
		e := fw("10.0.0.9", "10.0.1."+strconv.Itoa(i), 5432, time.Duration(i)*time.Second)
		e.Action = model.ActionDeny
		lateral = append(lateral, e)
	}
	_, a3 := run(lateral)
	sweep := false
	for _, a := range a3 {
		sweep = sweep || (a.RuleID == "bhv-hostsweep" && a.Severity == model.SevMedium)
	}
	if !sweep {
		t.Fatalf("内网横向扫描应保持中危: %+v", a3)
	}
}
