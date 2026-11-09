package parser

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// 以下是改为只匹配报文头之前的实现，用来确认新实现对不含换行的日志结果完全一致。
var (
	refSyslog5424 = regexp.MustCompile(`^<\d{1,3}>1 (\S+) (\S+) (\S+) \S+ \S+ (?:-|(?:\[[^\]]*\])+) ?(.*)$`)
	refSyslogISO  = regexp.MustCompile(`^(?:<\d{1,3}>)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(.*)$`)
	refSyslog3164 = regexp.MustCompile(`^(?:<\d{1,3}>)?([A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\d{4}\b)?)\s+(\S+)\s+(.*)$`)
	refSyslogTag  = regexp.MustCompile(`^([A-Za-z0-9_\-./]+)(?:\[\d+\])?:\s?(.*)$`)
	refASA        = regexp.MustCompile(`%(?:ASA|FTD)-\d-(\d{6}):\s*(.*)$`)
)

func refStripSyslog(line string) (string, SyslogHeader, bool) {
	var h SyslogHeader
	if len(line) < 16 {
		return line, h, false
	}
	switch c := line[0]; {
	case c == '<', c >= 'A' && c <= 'Z':
	case c >= '0' && c <= '9' && line[4] == '-' && len(line) > 10 && line[10] == 'T':
	default:
		return line, h, false
	}
	if m := refSyslog5424.FindStringSubmatch(line); m != nil {
		h.Time, h.Host, h.Tag = ParseTime(m[1]), m[2], m[3]
		return m[4], h, true
	}
	var rest string
	if m := refSyslogISO.FindStringSubmatch(line); m != nil {
		h.Time, h.Host, rest = ParseTime(m[1]), m[2], m[3]
	} else if m := refSyslog3164.FindStringSubmatch(line); m != nil {
		h.Time, h.Host, rest = ParseTime(strings.Join(strings.Fields(m[1]), " ")), m[2], m[3]
	} else if loc := reSyslogPRI.FindStringIndex(line); loc != nil {
		return line[loc[1]:], h, true
	} else {
		return line, h, false
	}
	if strings.HasSuffix(h.Host, ":") {
		h.Tag = strings.TrimSuffix(h.Host, ":")
		h.Host = ""
		return rest, h, true
	}
	if m := refSyslogTag.FindStringSubmatch(rest); m != nil {
		h.Tag = m[1]
		rest = m[2]
	}
	return rest, h, true
}

var syslogSamples = []string{
	benchHuaweiSession,
	`<190>2026/11/5 04:22:59 USG6300 %%01SHELL/6/DISPLAY_CMDRECORD(s)[82531]:记录显示命令信息。`,
	`<188>2026/11/9 01:47:19 USG6630E CONFIG/4/CONFIGCHANGE:OID 1.3.6.1.4.1.2011.6.122.83.1.2.1 配置发生变更。`,
	`<134>1 2026-11-09T01:47:19.123Z fw01 netsa 1234 ID47 [exampleSDID@32473 iut="3" eventSource="App"] message body`,
	`<134>1 2026-11-09T01:47:19Z fw01 app - - - plain message`,
	`<134>1 2026-11-09T01:47:19Z fw01 app - - [a="1"][b="2"]trailing`,
	`2026-11-09T09:47:19+08:00 web01 nginx: 203.0.113.5 - - [09/Nov/2026:09:47:19 +0800] "GET / HTTP/1.1" 200 5`,
	`<13>2026-11-09T09:47:19.5+0800   web02   sshd[123]: Failed password for root from 203.0.113.7 port 22 ssh2`,
	`Nov  9 09:47:19 web01 sshd[4242]: Accepted publickey for deploy from 10.0.0.5 port 50022 ssh2`,
	`<86>Nov  9 2026 09:47:19 H3C %%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION: SrcZoneName(1025)=Untrust;`,
	`<86>Oct 22 10:15:01 2026 H3C %%10SHELL/5/SHELL_LOGIN: admin logged in from 10.0.0.9.`,
	`<165>Nov  9 09:47:19 asa01 : %ASA-4-106023: Deny tcp src outside:203.0.113.9/51234 dst inside:10.0.0.5/22 by access-group "out"`,
	`<189>date=2026-11-09 time=09:47:19 devname="FGT" logid="0000000013" type="traffic" srcip=203.0.113.9 dstip=10.0.0.5`,
	`Nov  9 09:47:19 host: tagless message`,
	`<0>Nov  9 09:47:19 h t`,
	`<999>Jan  1 00:00:00 h tag[1]:x`,
	`Mar 31 23:59:59.123456 2026 host kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.1`,
	"<134>Nov	9 10:00:00 host msg",
	"<134>Nov  9	2026 10:00:00 host msg",
	"<134>Nov 9 2026 10:00:00	host	msg",
	"<134>Nov 9 10:00:00 20261 host msg",
	"<134>Nov 9 10:00:00 2026",
	"<134>Nov 9 10:00:00 2026 ",
	"<134>Nov 9 10:00:00 1234 host",
	"<134>Nov 9 10:00:00.5Z host msg",
	"<134>Nov 19 2026 10:00:00.000123 fw-01:  body",
	"<12a>Nov 9 10:00:00 host msg",
	"<1>Nov 9 10:00:00 h: tagless",
	"Nov 123 10:00:00 host msg",
	"Nov 9 2026 1:00:00 host msg",
	"<190>Nov  9 2026 01:47:19 USG6630E \x00\x01 %%01SECLOG/6/SESSION_TEARDOWN(l):x=1",
	"<190>Nov  9 2026 01:47:19 USG6630E\v%%01SECLOG",
}

func TestStripSyslogMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const alphabet = " <>:[]-T01239aZz%\"=.\t/"
	lines := append([]string(nil), syslogSamples...)
	for _, s := range syslogSamples {
		for k := 0; k < 2000; k++ {
			b := []byte(s)
			for n := rng.Intn(4) + 1; n > 0; n-- {
				i := rng.Intn(len(b))
				switch rng.Intn(3) {
				case 0:
					b[i] = alphabet[rng.Intn(len(alphabet))]
				case 1:
					b = append(b[:i], b[i+1:]...)
				default:
					b = append(b[:i], append([]byte{alphabet[rng.Intn(len(alphabet))]}, b[i:]...)...)
				}
				if len(b) == 0 {
					b = []byte("x")
				}
			}
			lines = append(lines, string(b))
		}
	}
	for _, line := range lines {
		gotRest, gotH, gotOK := StripSyslog(line)
		wantRest, wantH, wantOK := refStripSyslog(line)
		if gotRest != wantRest || gotOK != wantOK || gotH.Host != wantH.Host || gotH.Tag != wantH.Tag || !gotH.Time.Equal(wantH.Time) {
			t.Fatalf("结果不一致: %q\n新: %q %+v %v\n旧: %q %+v %v", line, gotRest, gotH, gotOK, wantRest, wantH, wantOK)
		}
		// Cisco ASA：消息头定位方式改变后，提取的消息正文一致
		var want string
		if m := refASA.FindStringSubmatch(line); m != nil {
			want = m[2]
		}
		got := ""
		if ev, ok := (CiscoASA{}).Parse(line); ok {
			got = ev.SrcIP
		}
		if wantEv := refASAParse(want); got != wantEv {
			t.Fatalf("ASA 解析不一致: %q 新 %q 旧 %q", line, got, wantEv)
		}
	}
}

func refASAParse(msg string) string {
	if msg == "" {
		return ""
	}
	a := reASAAddr.FindStringSubmatch(msg)
	if a == nil || !isIP(a[3]) {
		return ""
	}
	return a[3]
}

// 任意输入下，报文头解析（含手写的 RFC3164 快速匹配）与改造前的正则实现结果一致。
func FuzzStripSyslogMatchesReference(f *testing.F) {
	for _, s := range syslogSamples {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if strings.ContainsRune(line, '\n') {
			t.Skip("含换行的报文：旧实现的 (.*)$ 不能跨行匹配，整条不识别；新实现正常剥离报文头（有意的改进）")
		}
		gotRest, gotH, gotOK := StripSyslog(line)
		wantRest, wantH, wantOK := refStripSyslog(line)
		if gotRest != wantRest || gotOK != wantOK || gotH.Host != wantH.Host || gotH.Tag != wantH.Tag || !gotH.Time.Equal(wantH.Time) {
			t.Fatalf("结果不一致: %q\n新: %q %+v %v\n旧: %q %+v %v", line, gotRest, gotH, gotOK, wantRest, wantH, wantOK)
		}
	})
}
