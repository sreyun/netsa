package exposure

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

func TestReach(t *testing.T) {
	ev := func(src, dst, nat string, reply model.Reply) *model.Event {
		return &model.Event{Kind: model.KindFirewall, SrcIP: "195.184.76.97", DstIP: "43.242.97.35", DstPort: 23,
			SrcZone: src, DstZone: dst, NatDstIP: nat, Reply: reply, Action: model.ActionAllow}
	}
	// 用切片而不是以中文为键的 map：gofmt 按字符数对齐 map 的值，编辑器按显示宽度看起来是错位的，
	// 手工「对齐」后又会让 CI 的 gofmt 检查失败
	for _, c := range []struct {
		name string
		ev   *model.Event
		want Verdict
	}{
		{"untrust → untrust", ev("untrust", "untrust", "", 0), ReachNo},
		{"自定义外网域同域转发", ev("dianxin", "dianxin", "", 0), ReachNo},
		{"转发回外网域", ev("isp1", "Untrust", "", 0), ReachNo},
		{"FortiGate 接口角色 wan", ev("wan", "wan", "", 0), ReachNo},
		{"转发到 dmz", ev("untrust", "dmz", "", 0), ReachYes},
		{"打到防火墙自身的 Telnet", ev("untrust", "local", "", 0), ReachDevice},
		{"DNAT 到内网", ev("untrust", "", "10.0.0.5", 0), ReachYes},
		{"DNAT 但目标无应答", ev("untrust", "trust", "10.0.0.5", model.ReplyNone), ReachNo},
		{"有应答", ev("", "", "", model.ReplyYes), ReachYes},
		{"没有证据", ev("", "", "", 0), ReachUnknown},
		{"NAT 地址为公网（不视为转发到内网）", ev("", "", "203.0.113.9", 0), ReachUnknown},
	} {
		got, why := Reach(c.ev)
		if got != c.want || got != ReachUnknown && why == "" {
			t.Errorf("%s: 得到 %d（%s），期望 %d", c.name, got, why, c.want)
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
	m.RecordUnreached(&model.Event{SrcIP: "195.184.76.9", DstIP: "43.242.97.35", Proto: "icmp", SrcZone: "untrust", DstZone: "untrust", Policy: "允许本地上外网"})
	list := m.Policies()
	if len(list) != 1 || list[0].Policy != "允许本地上外网" || list[0].Permits != 5 || list[0].Sources != 5 ||
		list[0].TopPorts[0] != "23 × 2" || list[0].SrcZone != "untrust" || list[0].DstZone != "untrust" ||
		!slices.Contains(list[0].TopPorts, "ICMP 等无端口协议 × 1") {
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

// 自动识别的对外服务在重启后恢复；长期没有再出现会话证据的服务（可能已下线）不再恢复。
func TestLearnedPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exposure-learned.json")
	now := time.Now()
	m, _ := Load(config.ExposureConfig{Enabled: true})
	if err := m.SetPath(path, now); err != nil {
		t.Fatal(err)
	}
	m.Learn(&model.Event{Time: now, DstIP: "43.242.97.36", DstPort: 443, Proto: "tcp", NatDstIP: "10.0.0.21"}, "经 DNAT 转发至 10.0.0.21")
	m.Learn(&model.Event{Time: now.Add(-40 * 24 * time.Hour), DstIP: "43.242.97.37", DstPort: 22, Proto: "tcp"}, "目标有应答")
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("应写入文件: %v", err)
	}

	m2, _ := Load(config.ExposureConfig{Enabled: true})
	if err := m2.SetPath(path, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.Lookup("43.242.97.36", 443, "tcp"); !ok || m2.LearnedCount() != 1 {
		t.Fatalf("重启后应恢复自动识别的服务（过期的不恢复）: %+v", m2.Learned())
	}
	if l := m2.Learned()[0]; l.Reason != "经 DNAT 转发至 10.0.0.21" || l.Hits != 1 {
		t.Fatalf("恢复的内容: %+v", l)
	}
	if err := m2.Flush(); err != nil { // 没有变化时不重写
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("{broken"), 0o600)
	if err := (&Manager{learned: map[string]*learnedSvc{}}).SetPath(path, now); err == nil {
		t.Fatal("文件损坏时应返回错误")
	}
}

// 打到防火墙自身的非服务端口（互联网扫描 37215、2323、5432 等）未到达任何服务；配置追加的设备端口识别为设备服务。
func TestReachLocalPorts(t *testing.T) {
	ev := func(port int, proto string) *model.Event {
		return &model.Event{SrcIP: "79.124.58.130", DstIP: "43.242.97.51", DstPort: port, Proto: proto, SrcZone: "untrust", DstZone: "local", Action: model.ActionAllow}
	}
	m, _ := Load(config.ExposureConfig{DevicePorts: []int{6443}})
	for _, c := range []struct {
		port  int
		proto string
		want  Verdict
	}{
		{37215, "tcp", ReachNo}, {2323, "tcp", ReachNo}, {5432, "tcp", ReachNo}, {22, "tcp", ReachDevice}, {161, "udp", ReachDevice},
		{161, "tcp", ReachNo}, {500, "", ReachDevice}, {6443, "tcp", ReachDevice},
	} {
		if got, why := m.Reach(ev(c.port, c.proto)); got != c.want || why == "" {
			t.Errorf("%d/%s: %d（%s）", c.port, c.proto, got, why)
		}
	}
	if v, _ := Reach(ev(6443, "tcp")); v != ReachNo {
		t.Fatal("未配置时 6443 不是设备服务端口")
	}
	// ping 防火墙自身：由设备应答，不按「端口上没有服务」判为未到达，也不计入可疑放行策略
	if v, why := m.Reach(ev(0, "icmp")); v != ReachUnknown {
		t.Fatalf("ICMP 打到防火墙自身不应判为未到达: %d（%s）", v, why)
	}
	icmp := ev(0, "icmp")
	icmp.Reply = model.ReplyNone
	if v, _ := m.Reach(icmp); v != ReachNo {
		t.Fatal("会话结束时无应答（设备未回应 ping）仍判为未到达")
	}
	if name, sev := DeviceRisk(23, "tcp"); name != "Telnet" || sev != model.SevHigh {
		t.Fatalf("Telnet 管理服务: %s %v", name, sev)
	}
	if _, sev := DeviceRisk(4500, "udp"); sev != model.SevInfo {
		t.Fatal("VPN 端口按设计对外开放，不作为风险")
	}
}
