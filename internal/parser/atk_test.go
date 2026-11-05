package parser

import (
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 防火墙攻击防范与入侵防御日志。样例按华为 USG、H3C SecPath、深信服 AF 公开的日志字段说明构造，
// 拿到现场设备的真实日志后应补充到这里（字段名、分隔符、取值写法以真实日志为准）。
func TestAttackDefense(t *testing.T) {
	for _, c := range []struct {
		name, line               string
		format, src, dst, threat string
		dport                    int
		action, sev              string
		noSource                 bool
		catHas                   string
		at                       string // 期望的攻击开始时间（本地时区）
	}{
		{name: "华为 SYN 洪泛（有来源）",
			line:   `Nov  5 2026 10:15:01 USG6600 %%01ANTIATTACK/4/ANTIATTACK(l)[0]:VSys=public, AttackType=Syn flood attack, SrcZone=untrust, DstZone=trust, SrcIp=203.0.113.9, DstIp=10.0.0.10, SrcPort=0, DstPort=80, Protocol=TCP, BeginTime=2026/11/05 10:14:50, EndTime=2026/11/05 10:15:00, TotalPackets=152340, Action=discard.`,
			format: "huawei_atk", src: "203.0.113.9", dst: "10.0.0.10", threat: "Syn flood attack", dport: 80, action: model.ActionDeny, sev: "medium",
			catHas: "152340 次", at: "2026-11-05 10:14:50"},
		{name: "华为端口扫描",
			line:   `%%01ANTIATTACK/4/ANTIATTACK(l)[1]:VSys=public, AttackType=Port scan attack, SrcZone=untrust, SrcIp=198.51.100.7, DstIp=10.0.0.10, BeginTime=2026/11/05 10:14:50, TotalPackets=33, Action=discard.`,
			format: "huawei_atk", src: "198.51.100.7", dst: "10.0.0.10", threat: "Port scan attack", action: model.ActionDeny, sev: "low"},
		{name: "H3C SYN 洪泛（只有目的地址）",
			line:   `<188>Nov  5 10:15:01 2026 H3C-FW %%10ATK/3/ATK_IP4_TCP_SYNFLOOD: RcvIfName(1023)=GigabitEthernet1/0/2;DstIPAddr(1007)=10.0.0.10;RcvVPNInstance(1042)=;UpperLimit(1049)=1000;Action(1053)=logging,drop;BeginTime_c(1011)=20261105101450.`,
			format: "h3c_atk", dst: "10.0.0.10", threat: "SYN Flood", action: model.ActionDeny, sev: "high", noSource: true, at: "2026-11-05 10:14:50"},
		{name: "H3C 端口扫描（只记录）",
			line:   `%%10ATK/5/ATK_IP4_PORTSCAN_RAW_SZ: SrcZoneName(1025)=Untrust;SrcIPAddr(1003)=198.51.100.7;DstIPAddr(1007)=10.0.0.10;RcvVPNInstance(1042)=;Action(1053)=logging;BeginTime_c(1011)=20261105101450;EndTime_c(1012)=20261105101500;AtkTimes(1054)=33.`,
			format: "h3c_atk", src: "198.51.100.7", dst: "10.0.0.10", threat: "Port scan", action: model.ActionAllow, sev: "low", catHas: "33 次"},
		{name: "H3C Land 攻击",
			line:   `%%10ATK/3/ATK_IP4_LAND_RAW: SrcIPAddr(1003)=10.0.0.10;DstIPAddr(1007)=10.0.0.10;RcvIfName(1023)=GigabitEthernet1/0/2;Action(1053)=logging,drop.`,
			format: "h3c_atk", src: "10.0.0.10", dst: "10.0.0.10", threat: "Land attack", action: model.ActionDeny, sev: "medium"},
		{name: "H3C 入侵防御",
			line:   `%%10IPS/4/IPS_IPV4_INTERZONE: Protocol(1001)=TCP;Application(1002)=http;SrcIPAddr(1003)=198.51.100.7;SrcPort(1004)=51234;DstIPAddr(1007)=10.0.0.10;DstPort(1008)=80;SrcZoneName(1025)=Untrust;DstZoneName(1035)=Trust;AttackName(1088)=WEB_SERVER_Apache_Struts2_OGNL_Remote_Code_Execution;AttackID(1089)=12345;Category(1090)=Code Execution;Severity(1087)=CRITICAL;Action(1053)=Reset & Logging;CVE(1075)=CVE-2017-5638.`,
			format: "h3c_ips", src: "198.51.100.7", dst: "10.0.0.10", threat: "WEB_SERVER_Apache_Struts2_OGNL_Remote_Code_Execution", dport: 80, action: model.ActionDeny, sev: "CRITICAL", catHas: "Code Execution"},
		{name: "华为入侵防御（取值带引号）",
			line:   `%%01IPS/4/DETECT(l)[2]:An intrusion was detected. (SyslogId=1, VSys="public", Policy="ips", SrcIp="198.51.100.7", DstIp="10.0.0.10", SrcPort=51234, DstPort=80, SrcZone="untrust", DstZone="trust", Protocol="TCP", Application="HTTP", SignName="SQL Injection Attempt", SignId=1000, Severity=high, Category="Injection", Action=Block)`,
			format: "huawei_ips", src: "198.51.100.7", dst: "10.0.0.10", threat: "SQL Injection Attempt", dport: 80, action: model.ActionDeny, sev: "high", catHas: "Injection"},
		{name: "深信服 DOS 攻击",
			line:   `<134>Nov  5 10:15:01 localhost fwlog: 日志类型:DOS攻击日志, 源IP:203.0.113.9, 源端口:0, 目的IP:10.0.0.10, 目的端口:80, 协议:TCP, 攻击类型:SYN洪水攻击, 严重级别:高, 动作:拒绝`,
			format: "sangfor", src: "203.0.113.9", dst: "10.0.0.10", threat: "SYN洪水攻击", dport: 80, action: model.ActionDeny, sev: "高", catHas: "DOS攻击日志"},
		{name: "深信服 WAF（只记录）",
			line:   `fwlog: 日志类型:WAF应用防护日志, 用户:(null), 源IP:198.51.100.7, 源端口:51234, 目的IP:10.0.0.10, 目的端口:80, 攻击类型:SQL注入, 严重级别:中, 系统动作:被记录, URL:http://www.example.com/news.php?id=1 and 1=1`,
			format: "sangfor", src: "198.51.100.7", dst: "10.0.0.10", threat: "SQL注入", dport: 80, action: model.ActionAllow, sev: "中"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := AttackDefense{}.Parse(c.line)
			if !ok {
				t.Fatal("应能解析")
			}
			if ev.Format != c.format || ev.SrcIP != c.src || ev.DstIP != c.dst || ev.Threat != c.threat || ev.DstPort != c.dport ||
				ev.Action != c.action || ev.ThreatSeverity != c.sev || ev.NoSource != c.noSource || ev.Kind != model.KindFirewall {
				t.Fatalf("%+v", ev)
			}
			if c.catHas != "" && !strings.Contains(ev.ThreatCategory, c.catHas) {
				t.Fatalf("分类说明 %q 应包含 %q", ev.ThreatCategory, c.catHas)
			}
			if c.at != "" {
				want, _ := time.ParseInLocation("2006-01-02 15:04:05", c.at, Location)
				if !ev.Time.Equal(want) {
					t.Fatalf("时间 %v，应为 %v", ev.Time, want)
				}
			}
		})
	}
	for _, line := range []string{
		`%%01SECE/4/ARP_GW_CONFLICT(l):The gateway conflicts with 10.0.0.1, interface GigabitEthernet0/0/1.`, // 交换机的 ARP 日志
		`fwlog: 日志类型:流量审计, 源IP:10.0.0.31, 目的IP:203.0.113.1, 应用:微信`,                                           // 不是攻击日志
		`%%10ATK/3/ATK_IP4_TCP_SYNFLOOD: RcvIfName(1023)=GE1/0/2;DstIPAddr(1007)=not-an-ip;Action(1053)=drop.`,
		`%%01SHELL/6/DISPLAY_CMDRECORD(s):Record command information. (Task=VT0, Ip=10.0.0.8, User=admin, Command="display current")`,
	} {
		if ev, ok := (AttackDefense{}).Parse(line); ok {
			t.Errorf("不应解析: %s → %+v", line, ev)
		}
	}
}

// 通用的 key=value 解析不接手攻击防范日志（会截断取值、丢掉攻击类型）；自动识别时没有来源的洪泛日志同样能解析。
func TestAttackDefenseAuto(t *testing.T) {
	line := `Nov  5 2026 10:15:01 USG6600 %%01ANTIATTACK/4/ANTIATTACK(l)[0]:VSys=public, AttackType=Syn flood attack, SrcIp=203.0.113.9, DstIp=10.0.0.10, DstPort=80, Action=discard.`
	if _, ok := (KVFirewall{}).Parse(line); ok {
		t.Fatal("key=value 解析器不应接手攻击防范日志")
	}
	a, _ := NewAuto("firewall", "")
	// 先让自动识别锁定 key=value 格式（同一台设备的会话日志），攻击防范日志仍由专门的解析器处理
	for range 3 {
		if _, ok := a.Parse(`date=2026-11-05 time=10:15:01 srcip=203.0.113.9 dstip=10.0.0.10 dstport=443 proto=6 action=accept`); !ok {
			t.Fatal("会话日志")
		}
	}
	ev, ok := a.Parse(line)
	if !ok || ev.Format != "huawei_atk" || ev.Threat != "Syn flood attack" {
		t.Fatalf("%+v", ev)
	}
	ev, ok = a.Parse(`<188>Nov  5 10:15:01 2026 H3C-FW %%10ATK/3/ATK_IP4_UDPFLOOD: RcvIfName(1023)=GE1/0/2;DstIPAddr(1007)=10.0.0.10;Action(1053)=logging,drop.`)
	if !ok || !ev.NoSource || ev.SrcIP != "" || ev.DstIP != "10.0.0.10" || ev.Threat != "UDP Flood" || ev.Time.IsZero() {
		t.Fatalf("没有来源的洪泛日志: %+v", ev)
	}
}
