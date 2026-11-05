package store

import (
	"fmt"
	"testing"
	"time"

	"netsa/internal/model"
)

// 情报类别决定情报命中的分类与等级，命中的情报源记入事件（自学习据此统计情报源的准确率）。
func TestIntelKinds(t *testing.T) {
	s := newTestStore()
	kinds := map[string]string{"远控情报": "c2", "投递情报": "malware", "钓鱼情报": "phishing", "矿池情报": "mining", "扫描源情报": "attacker"}
	lists := map[string][]string{"198.51.100.1": {"远控情报"}, "198.51.100.2": {"投递情报"}, "198.51.100.3": {"钓鱼情报"},
		"198.51.100.4": {"矿池情报"}, "198.51.100.5": {"扫描源情报"}, "198.51.100.6": {"扫描源情报", "远控情报"}, "203.0.113.9": {"扫描源情报"}}
	s.IntelMatch = func(ip string) []string { return lists[ip] }
	s.IntelKind = func(name string) string { return kinds[name] }
	n := 0
	out := func(dst string) *model.Alert {
		t.Helper()
		n++ // 每个目的地址换一台主机：同一主机同一规则的告警会被节流
		r := s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("10.0.0.%d", 30+n), DstIP: dst, DstPort: 443, Proto: "tcp",
			Action: model.ActionAllow, Reply: model.ReplyYes, Outbound: true, Time: time.Now()}, nil)
		if len(r.Alerts) != 1 {
			t.Fatalf("%s: %+v", dst, r)
		}
		return r.Alerts[0]
	}
	for dst, want := range map[string]struct {
		cat string
		sev model.Severity
	}{
		"198.51.100.1": {CatC2, model.SevCritical},
		"198.51.100.2": {CatMalDomain, model.SevHigh},
		"198.51.100.3": {CatPhishing, model.SevMedium},
		"198.51.100.4": {CatMining, model.SevHigh},
		"198.51.100.5": {"威胁情报", model.SevMedium},
		"198.51.100.6": {CatC2, model.SevCritical}, // 同时命中多个情报：按最严重的类别
	} {
		if a := out(dst); a.Category != want.cat || a.Severity != want.sev {
			t.Errorf("%s: %s %s，期望 %s %s", dst, a.Category, a.Severity, want.cat, want.sev)
		}
	}
	// 被拦截的外连攻击来源地址：低危，不被分类底线抬回
	r0 := s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.99", DstIP: "198.51.100.5", DstPort: 443, Proto: "tcp",
		Action: model.ActionDeny, Outbound: true, Time: time.Now()}, nil)
	if len(r0.Alerts) != 1 || r0.Alerts[0].Severity != model.SevLow {
		t.Fatalf("被拦截的外连攻击来源: %+v", r0.Alerts)
	}
	// 入站：扫描、暴力破解来源的名单只说明信誉，不单独构成高危
	r := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", Method: "GET", URI: "/", Status: 200, Time: time.Now()}, nil)
	if len(r.Alerts) != 1 || r.Alerts[0].Severity != model.SevMedium {
		t.Fatalf("入站扫描源情报: %+v", r.Alerts)
	}
	d := s.Incident(r.Alerts[0].IncidentID)
	if d == nil || len(d.Feeds) != 1 || d.Feeds[0] != "扫描源情报" {
		t.Fatalf("事件应记录命中的情报源: %+v", d)
	}
}

// 状态库自己生成的情报命中（外连情报地址、入站情报）经过自学习校准：情报源准确率偏低时下调。
func TestIntelHitsCalibrated(t *testing.T) {
	s := newTestStore()
	s.IntelMatch = func(ip string) []string {
		if ip == "198.51.100.1" || ip == "203.0.113.9" {
			return []string{"不准的情报"}
		}
		return nil
	}
	var seen []string
	s.Calibrate = func(ev *model.Event, hits []model.Hit) []model.Hit {
		out := append([]model.Hit(nil), hits...)
		for i := range out {
			if len(out[i].Feeds) == 1 && out[i].Feeds[0] == "不准的情报" {
				seen = append(seen, out[i].RuleID)
				out[i].Severity--
				out[i].Learned = -1
			}
		}
		return out
	}
	r := s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.31", DstIP: "198.51.100.1", DstPort: 443, Proto: "tcp",
		Action: model.ActionAllow, Reply: model.ReplyYes, Outbound: true, Time: time.Now()}, nil)
	if len(r.Alerts) != 1 || r.Alerts[0].Severity != model.SevHigh {
		t.Fatalf("外连情报命中应下调一级: %+v", r.Alerts)
	}
	r = s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", Method: "GET", URI: "/", Status: 200, Time: time.Now()}, nil)
	if len(r.Alerts) != 1 || r.Alerts[0].Severity != model.SevMedium {
		t.Fatalf("入站情报命中应下调一级: %+v", r.Alerts)
	}
	if fmt.Sprint(seen) != "[c2-egress intel]" {
		t.Fatalf("校准调用: %v", seen)
	}
}
