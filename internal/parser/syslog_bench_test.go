package parser

import (
	"strings"
	"testing"
)

// 华为防火墙会话日志（生产环境 95% 以上的日志是这一类，每条都要先剥离 syslog 头）。
const benchHuaweiSession = `<190>Nov  9 2026 01:47:19 USG6630E %%01SECLOG/6/SESSION_TEARDOWN(l):IPVer=4,Protocol=tcp,SourceIP=203.0.113.9,DestinationIP=10.34.44.59,SourcePort=51234,DestinationPort=443,SourceNatIP=203.0.113.9,SourceNatPort=51234,BeginTime=1794186439,EndTime=1794186440,SendPkts=6,SendBytes=742,RcvPkts=5,RcvBytes=4120,SourceVpnID=0,DestinationVpnID=0,SourceZone=untrust,DestinationZone=dmz,PolicyName=web-in,CloseReason=tcp-fin.`

func BenchmarkStripSyslogHuawei(b *testing.B) {
	b.SetBytes(int64(len(benchHuaweiSession)))
	for b.Loop() {
		if _, _, ok := StripSyslog(benchHuaweiSession); !ok {
			b.Fatal("应识别 syslog 头")
		}
	}
}

// 带大量 %XX 编码、但不是 ASA 日志的长行：ASA 解析器不应在其上耗费正则匹配。
func BenchmarkCiscoASANonMatching(b *testing.B) {
	line := `203.0.113.5 - - [09/Nov/2026:01:47:19 +0800] "GET /search?q=` + strings.Repeat("%27%20OR%201%3D1", 400) + ` HTTP/1.1" 200 512 "-" "curl/8"`
	b.SetBytes(int64(len(line)))
	for b.Loop() {
		CiscoASA{}.Parse(line)
	}
}
