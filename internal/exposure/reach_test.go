package exposure

import (
	"strconv"
	"testing"

	"netsa/internal/config"
	"netsa/internal/model"
)

func TestReach(t *testing.T) {
	ev := func(src, dst, nat string, reply model.Reply) *model.Event {
		return &model.Event{Kind: model.KindFirewall, SrcIP: "195.184.76.97", DstIP: "43.242.97.35", DstPort: 23,
			SrcZone: src, DstZone: dst, NatDstIP: nat, Reply: reply, Action: model.ActionAllow}
	}
	for name, c := range map[string]struct {
		ev   *model.Event
		want Verdict
	}{
		"untrust → untrust":  {ev("untrust", "untrust", "", 0), ReachNo},
		"自定义外网域同域转发":         {ev("dianxin", "dianxin", "", 0), ReachNo},
		"转发回外网域":             {ev("isp1", "Untrust", "", 0), ReachNo},
		"FortiGate 接口角色 wan": {ev("wan", "wan", "", 0), ReachNo},
		"转发到 dmz":            {ev("untrust", "dmz", "", 0), ReachYes},
		"打到防火墙自身":            {ev("untrust", "local", "", 0), ReachDevice},
		"DNAT 到内网":           {ev("untrust", "", "10.0.0.5", 0), ReachYes},
		"DNAT 但目标无应答":        {ev("untrust", "trust", "10.0.0.5", model.ReplyNone), ReachNo},
		"有应答":                {ev("", "", "", model.ReplyYes), ReachYes},
		"没有证据":               {ev("", "", "", 0), ReachUnknown},
		"NAT 地址为公网（不视为转发到内网）": {ev("", "", "203.0.113.9", 0), ReachUnknown},
	} {
		got, why := Reach(c.ev)
		if got != c.want || got != ReachUnknown && why == "" {
			t.Errorf("%s: 得到 %d（%s），期望 %d", name, got, why, c.want)
		}
	}
}

func TestPolicyNotes(t *testing.T) {
	m, _ := Load(config.ExposureConfig{})
	for i, port := range []int{23, 23, 8291, 5432} {
		m.RecordUnreached(&model.Event{SrcIP: "195.184.76." + strconv.Itoa(i+1), DstIP: "43.242.97.35", DstPort: port,
			SrcZone: "untrust", DstZone: "untrust", Policy: "允许本地上外网"})
	}
	m.RecordUnreached(&model.Event{SrcIP: "198.51.100.1", DstIP: "43.242.97.32", DstPort: 22}) // 没有策略与安全域信息：不汇总
	list := m.Policies()
	if len(list) != 1 || list[0].Policy != "允许本地上外网" || list[0].Permits != 4 || list[0].Sources != 4 ||
		list[0].TopPorts[0] != "23 × 2" || list[0].SrcZone != "untrust" || list[0].DstZone != "untrust" {
		t.Fatalf("可疑放行策略: %+v", list)
	}
}

// 有会话证据的对外服务自动识别：之后同一端口没有证据的日志按已发布处理，候选映射中不再提示。
func TestLearnedServices(t *testing.T) {
	m, _ := Load(config.ExposureConfig{Enabled: true})
	if _, ok := m.Lookup("43.242.97.36", 443, "tcp"); ok {
		t.Fatal("未登记、未识别的端口应视为未发布")
	}
	ev := &model.Event{DstIP: "43.242.97.36", DstPort: 443, Proto: "tcp", NatDstIP: "10.0.0.21"}
	_, why := Reach(ev)
	m.Learn(ev, why)
	m.Learn(&model.Event{DstIP: "10.0.0.5", DstPort: 22, Proto: "tcp"}, "内网地址不登记")
	if _, ok := m.Lookup("43.242.97.36", 443, "tcp"); !ok {
		t.Fatal("自动识别的服务应视为已发布")
	}
	if _, ok := m.Lookup("43.242.97.36", 443, "any"); !ok {
		t.Fatal("不区分协议的查询也应命中")
	}
	if l := m.Learned(); len(l) != 1 || l[0].Reason != "经 DNAT 转发至 10.0.0.21" || l[0].Service != "HTTPS" {
		t.Fatalf("自动识别的服务: %+v", l)
	}
	for i := 0; i < 30; i++ {
		m.Observe("43.242.97.36", 443, "tcp", "198.51.100."+strconv.Itoa(i), true, ev.Time)
	}
	if c := m.Candidates(); len(c) != 0 {
		t.Fatalf("已自动识别的服务不应再作为候选: %+v", c)
	}
}
