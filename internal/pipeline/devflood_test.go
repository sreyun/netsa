package pipeline

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/store"
)

// 防火墙攻击防范的验收：
//   - 没有来源的洪泛日志（H3C 只记录目的地址）不建立来源画像，按目的地址告警，计入资产攻击链路的影响阶段；
//   - 设备先报告洪泛、之后按会话日志判断出多源 DDoS：DDoS 告警升为高危并注明设备的判定；
//   - 按会话日志已经在突增、之后设备报告洪泛：设备告警注明会话日志的突增情况。
func TestDeviceFloodCorroboration(t *testing.T) {
	th := config.Default().Detect.Thresholds
	th.DDoSEvents, th.DDoSSources = 50, 20 // 基线不成熟时需要 10 倍：500 条、20 个以上来源
	eng, _ := detect.NewEngine("", 1)
	st := store.New(10000, 10000, 100, 24*time.Hour)
	p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(th), Store: st}
	now := time.Now().Truncate(time.Second)
	device := func(dst string, at time.Time) *model.Event {
		line := fmt.Sprintf(`%%%%10ATK/3/ATK_IP4_TCP_SYNFLOOD: RcvIfName(1023)=GE1/0/2;DstIPAddr(1007)=%s;UpperLimit(1049)=1000;Action(1053)=logging,drop;BeginTime_c(1011)=%s.`,
			dst, at.In(parser.Location).Format("20060102150405"))
		ev, ok := parser.AttackDefense{}.Parse(line)
		if !ok {
			t.Fatalf("解析失败: %s", line)
		}
		ev.Source = "h3c"
		return ev
	}
	surge := func(dst string, at time.Time) []*model.Event {
		var evs []*model.Event
		for i := range 600 {
			evs = append(evs, &model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("198.18.%d.%d", i%40, 1+i%200), DstIP: dst, DstPort: 80,
				Proto: "tcp", Action: model.ActionAllow, Time: at.Add(time.Duration(i) * 100 * time.Millisecond)})
		}
		return evs
	}
	var evs []*model.Event
	evs = append(evs, device("10.0.0.10", now))                       // 设备先报告
	evs = append(evs, surge("10.0.0.10", now.Add(10*time.Second))...) // 之后会话日志突增
	evs = append(evs, surge("10.0.0.11", now)...)                     // 会话日志先突增
	evs = append(evs, device("10.0.0.11", now.Add(70*time.Second)))   // 之后设备报告
	evs = append(evs, device("10.0.0.10", now.Add(2*time.Minute)))    // 同一目的地址 10 分钟内的重复报告不再告警
	in := make(chan []*model.Event, 1)
	done := p.Run(context.Background(), in, 1)
	in <- evs
	close(in)
	<-done

	if st.Profile("") != nil {
		t.Fatal("没有来源的设备威胁不应建立画像")
	}
	var dev10, dev11, ddos10 []*model.Alert
	for _, a := range st.Alerts(store.AlertQuery{Limit: 10000}) {
		switch {
		case a.SrcIP == "" && strings.HasPrefix(a.Target, "10.0.0.10"):
			dev10 = append(dev10, a)
		case a.SrcIP == "" && strings.HasPrefix(a.Target, "10.0.0.11"):
			dev11 = append(dev11, a)
		case a.RuleID == "bhv-ddos" && strings.HasPrefix(a.Target, "10.0.0.10"):
			ddos10 = append(ddos10, a)
		}
	}
	if len(dev10) != 1 || dev10[0].Category != detect.CatFlood || dev10[0].Location == "" || dev10[0].IncidentID != 0 || dev10[0].Target != "10.0.0.10/tcp" {
		for _, a := range dev10 {
			t.Logf("%+v", *a)
		}
		t.Fatalf("没有来源的洪泛告警（重复报告应节流）: %d 条", len(dev10))
	}
	if len(ddos10) == 0 || ddos10[0].Severity < model.SevHigh || !strings.Contains(ddos10[0].Evidence, "防火墙攻击防范同时报告「SYN Flood」") {
		t.Fatalf("设备先报告洪泛时，DDoS 告警应升为高危并注明: %+v", ddos10)
	}
	if len(dev11) != 1 || dev11[0].Severity < model.SevHigh || !strings.Contains(dev11[0].Evidence, "按会话日志同时检测到") {
		t.Fatalf("会话日志先突增时，设备告警应注明: %+v", dev11)
	}
	c := st.AssetChain("10.0.0.10")
	if c == nil || !strings.Contains(strings.Join(c.Reached, ","), "impact") {
		t.Fatalf("资产链路应有影响阶段: %+v", c)
	}
	found := false
	for _, v := range c.Steps {
		if v.Src == "" && v.SrcLabel != "" && v.Stage == "impact" {
			found = true
		}
	}
	if !found {
		t.Fatalf("链路中应有设备报告的洪泛（来源注明未记录）: %+v", c.Steps)
	}
}
