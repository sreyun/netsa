package parser

import (
	"strings"
	"testing"

	"netsa/internal/model"
)

func TestFirewallSessionFields(t *testing.T) {
	pa := make([]string, 50)
	for i, v := range map[int]string{3: "TRAFFIC", 4: "end", 6: "2026/10/29 08:49:59", 7: "198.51.100.40", 8: "203.0.113.10", 10: "10.0.0.5",
		11: "allow-web", 16: "untrust", 17: "dmz", 18: "ethernet1/1", 24: "51234", 25: "443", 29: "tcp", 30: "allow", 45: "0"} {
		pa[i] = v
	}
	for _, c := range []struct {
		name, line              string
		src, dst, srcZone, zone string
		policy, nat             string
		action                  string
		reply                   model.Reply
	}{
		// 华为策略匹配日志：外网探测被出站策略放行，目的安全域仍为 untrust
		{"华为 POLICYPERMIT", `<190>Oct 29 2026 00:49:59 USG6300 %%01POLICY/6/POLICYPERMIT(l):vsys=public, protocol=6, source-ip=195.184.76.97, source-port=11062, destination-ip=43.242.97.35, destination-port=23, time=2026/10/29 08:49:59, source-zone=untrust, destination-zone=untrust, application-name=, rule-name=允许本地上外网.`,
			"195.184.76.97", "43.242.97.35", "untrust", "untrust", "允许本地上外网", "", model.ActionAllow, model.ReplyUnknown},
		// 华为会话日志：会话结束时目标无应答
		{"华为 SESSION_TEARDOWN", `<190>2026-10-29 08:49:59 USG6300 %%01SECLOG/6/SESSION_TEARDOWN(l):IPVer=4,Protocol=tcp,SourceIP=195.184.76.97,DestinationIP=43.242.97.32,SourcePort=51234,DestinationPort=5432,SourceNatIP=,SourceNatPort=,BeginTime=1793235000,EndTime=1793235030,SendPkts=2,SendBytes=120,RcvPkts=0,RcvBytes=0,SourceVpnID=0,DestinationVpnID=0,SourceZone=untrust,DestinationZone=trust,PolicyName=web,CloseReason=aged-out.`,
			"195.184.76.97", "43.242.97.32", "untrust", "trust", "web", "", model.ActionAllow, model.ReplyNone},
		{"H3C 安全域", `<190>Oct 22 10:15:01 2026 H3C %%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION: SrcZoneName(1025)=Untrust;DstZoneName(1035)=Trust;SrcIPAddr(1003)=198.51.100.30;DstIPAddr(1007)=10.0.0.16;SrcPort(1004)=5000;DstPort(1008)=22;Protocol(1001)=TCP;Action(1053)=Permit;`,
			"198.51.100.30", "10.0.0.16", "Untrust", "Trust", "", "", model.ActionAllow, model.ReplyUnknown},
		{"FortiGate 无应答", `date=2026-10-29 time=08:49:59 devname="FG" type="traffic" subtype="forward" srcip=198.51.100.28 srcport=5555 srcintfrole="wan" dstip=203.0.113.14 dstport=6379 dstintfrole="undefined" proto=6 action="timeout" policyid=3 policyname="inbound" sentpkt=1 rcvdpkt=0 rcvdbyte=0`,
			"198.51.100.28", "203.0.113.14", "wan", "", "inbound", "", model.ActionAllow, model.ReplyNone},
		{"FortiGate 会话开始不采信计数", `date=2026-10-29 time=08:49:59 devname="FG" srcip=198.51.100.28 srcport=5555 dstip=203.0.113.14 dstport=6379 proto=6 action="start" policyid=3 rcvdpkt=0`,
			"198.51.100.28", "203.0.113.14", "", "", "3", "", model.ActionAllow, model.ReplyUnknown},
		{"FortiGate 虚拟 IP", `date=2026-10-29 time=08:49:59 devname="FG" srcip=198.51.100.28 srcport=5555 dstip=203.0.113.14 dstport=443 proto=6 action="close" policyid=5 trandisp="dnat" tranip=10.0.0.21 tranport=443 rcvdpkt=12`,
			"198.51.100.28", "203.0.113.14", "", "", "5", "10.0.0.21", model.ActionAllow, model.ReplyYes},
		{"Palo Alto 流量结束", strings.Join(pa, ","), "198.51.100.40", "203.0.113.10", "untrust", "dmz", "allow-web", "10.0.0.5", model.ActionAllow, model.ReplyNone},
	} {
		ev, ok := mustAuto(t, "auto", "").Parse(c.line)
		if !ok {
			t.Errorf("%s: 未能解析", c.name)
			continue
		}
		// 华为 time=2026/10/29 08:49:59 中间有空格，应取完整时间，而不是退回 syslog 头（UTC）
		if c.name == "华为 POLICYPERMIT" && ev.Time.Format("2006-01-02 15:04:05") != "2026-10-29 08:49:59" {
			t.Errorf("%s: 事件时间 %s", c.name, ev.Time)
		}
		if ev.SrcIP != c.src || ev.DstIP != c.dst || ev.SrcZone != c.srcZone || ev.DstZone != c.zone || ev.Policy != c.policy ||
			ev.NatDstIP != c.nat || ev.Action != c.action || ev.Reply != c.reply {
			t.Errorf("%s: src=%s dst=%s zone=%s→%s policy=%q nat=%s action=%s reply=%d", c.name, ev.SrcIP, ev.DstIP, ev.SrcZone, ev.DstZone,
				ev.Policy, ev.NatDstIP, ev.Action, ev.Reply)
		}
	}
}
