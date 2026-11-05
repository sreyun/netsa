package pipeline

import (
	"context"
	"fmt"
	"testing"
	"time"

	"netsa/internal/authscan"
	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 授权扫描的验收：登记期间的扫描不产生告警、不计入攻击统计与评分，只计入登记的统计；登记之外的来源与
// 时间窗之外的扫描照常检测（过期后自动恢复）。
func TestAuthorizedScan(t *testing.T) {
	as, _ := authscan.Load("")
	now := time.Now()
	if _, err := as.Add(authscan.Entry{IP: "198.51.100.0/24", Start: now.Add(-time.Hour), End: now.Add(time.Hour), Note: "等保测评漏洞扫描"}); err != nil {
		t.Fatal(err)
	}
	eng, _ := detect.NewEngine("", 1)
	st := store.New(1000, 1000, 100, 24*time.Hour)
	p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(config.Default().Detect.Thresholds), Store: st, AuthScan: as}
	scan := func(src string, at time.Time) []*model.Event {
		var evs []*model.Event
		for i, uri := range []string{"/?id=1%27%20union%20select%201,2,3--", "/../../etc/passwd", "/.env", "/wp-login.php"} {
			evs = append(evs, &model.Event{Kind: model.KindWeb, SrcIP: src, Host: "www.example.com", Method: "GET", URI: uri, Status: 404, Time: at.Add(time.Duration(i) * time.Second)})
		}
		for port := 20; port < 60; port++ { // 端口扫描
			evs = append(evs, &model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: "10.0.0.10", DstPort: port, Proto: "tcp", Action: model.ActionDeny, Time: at})
		}
		return evs
	}
	var evs []*model.Event
	evs = append(evs, scan("198.51.100.20", now)...)                   // 登记的扫描源，时间窗内
	evs = append(evs, scan("198.51.100.21", now.Add(-3*time.Hour))...) // 登记的网段，但在时间窗之前
	evs = append(evs, scan("203.0.113.9", now)...)                     // 未登记的来源
	in := make(chan []*model.Event, 1)
	done := p.Run(context.Background(), in, 1)
	in <- evs
	close(in)
	<-done

	attackers := map[string]bool{}
	for _, a := range st.Alerts(store.AlertQuery{Limit: 1000}) {
		attackers[a.SrcIP] = true
	}
	if attackers["198.51.100.20"] {
		t.Fatal("登记期间的扫描不应产生告警")
	}
	if !attackers["198.51.100.21"] || !attackers["203.0.113.9"] {
		t.Fatalf("时间窗之外、未登记的来源应照常告警: %v", attackers)
	}
	if p := st.Profile("198.51.100.20"); p != nil && (p.Attacks > 0 || p.Score > 0) {
		t.Fatalf("登记期间的扫描不计入攻击统计与评分: attacks=%d score=%.1f", p.Attacks, p.Score)
	}
	if c := st.AssetChain("www.example.com"); c != nil {
		for _, v := range c.Steps {
			if v.Src == "198.51.100.20" {
				t.Fatalf("登记期间的扫描不计入资产攻击链路: %+v", v)
			}
		}
	}
	l := as.List()
	if len(l) != 1 || l[0].Events != 44 || l[0].Hits == 0 || l[0].Categories["SQL注入"] == 0 {
		t.Fatalf("期间的流量与命中应计入登记: %+v", l[0])
	}
	t.Logf("登记期间：%d 个事件、%d 次命中，攻击类型 %v", l[0].Events, l[0].Hits, fmt.Sprint(l[0].Categories))
}
