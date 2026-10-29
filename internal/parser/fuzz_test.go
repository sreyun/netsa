package parser

import (
	"encoding/json"
	"strings"
	"testing"
)

// 模糊测试：日志来自外部（syslog 可被任意发送端写入），解析器对任意输入都不能崩溃或死循环。
// 运行：go test ./internal/parser -run XXX -fuzz FuzzAutoParse -fuzztime 60s

var fuzzSeeds = []string{
	`203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "curl/8.0"`,
	`{"time_local":"26/Oct/2026:10:00:00 +0800","remote_addr":"198.51.100.12","request":"GET /?q=\x22><script> HTTP/1.1","status":"200"}`,
	`{"log":"203.0.113.5 - - [26/Oct/2026:10:15:01 +0800] \"GET / HTTP/1.1\" 200 1 \"-\" \"x\"\n","stream":"stdout"}`,
	`2026-10-26T10:15:01.123456789+08:00 stdout F 203.0.113.7 - - [26/Oct/2026:10:15:01 +0800] "GET /admin HTTP/1.1" 404 0 "-" "curl/8.0"`,
	`<190>Oct 29 2026 00:49:59 USG6300 %%01POLICY/6/POLICYPERMIT(l):vsys=public, protocol=6, source-ip=195.184.76.97, source-port=11062, destination-ip=43.242.97.35, destination-port=23, time=2026/10/29 08:49:59, source-zone=untrust, destination-zone=untrust, rule-name=允许本地上外网.`,
	`<190>Oct 22 10:15:01 2026 H3C %%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION: SrcZoneName(1025)=Untrust;DstZoneName(1035)=Trust;SrcIPAddr(1003)=198.51.100.30;DstIPAddr(1007)=10.0.0.16;DstPort(1008)=22;Action(1053)=Deny;`,
	`date=2026-10-29 time=08:49:59 srcip=198.51.100.28 srcport=5555 dstip=203.0.113.14 dstport=443 proto=6 action="close" trandisp="dnat" tranip=10.0.0.21 rcvdpkt=12`,
	`Oct 22 10:15:01 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=10.0.0.10 PROTO=TCP SPT=54321 DPT=22`,
	`Oct 26 10:00:00 web01 sshd[123]: Failed password for root from 203.0.113.9 port 22 ssh2`,
	`{"EventID":4625,"TargetUserName":"admin","IpAddress":"198.51.100.10","LogonType":"10"}`,
	`{"timestamp":"2026-10-25T10:00:03.000+0800","event_type":"dns","src_ip":"10.0.0.50","dns":{"type":"query","rrname":"pool.minexmr.com","rrtype":"A"}}`,
	`1,2026/10/29 08:49:59,0,TRAFFIC,end,,2026/10/29 08:49:59,198.51.100.40,203.0.113.10,0.0.0.0,10.0.0.5,allow-web`,
	`#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status`,
	`time=2026/10/29 08:49:5`, `a=b c=d e=`, `{"a":`, `\x`, `\\x22`, `<1>`, `"`,
}

func FuzzAutoParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		p, err := NewAuto("auto", "")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ { // 第二次走锁定格式 / 包装格式的路径
			if ev, ok := p.Parse(line); ok && (ev == nil || ev.Raw == "") {
				t.Fatalf("解析成功但事件不完整: %+v", ev)
			}
		}
		p.Directive(line)
		_ = p.Detected()
	})
}

func FuzzHexToJSON(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := hexToJSON(s)
		// 合法 JSON 中不会出现 \x 转义：还原必须保持原样，不能改坏正常日志
		if json.Valid([]byte(s)) && string(out) != s {
			t.Fatalf("合法 JSON 被改动:\n%q\n%q", s, out)
		}
		_, _ = unmarshalLog(s)
	})
}

func FuzzKVPairs(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		kvPairs(line, func(key, val string) {
			if key == "" || !strings.Contains(line, key) || !strings.Contains(line, val) {
				t.Fatalf("键值不是原文的子串: %q=%q", key, val)
			}
		})
	})
}

func FuzzUnwrap(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		inner, kind := unwrapLine(line)
		// JSON 字符串中的非法 UTF-8 字节会被解码为 U+FFFD（3 字节），拆包后最多膨胀 3 倍（单行另有 1MB 上限）
		if kind != wrapNone && len(inner) > 3*len(line) {
			t.Fatalf("拆包后异常膨胀: %q → %q", line, inner)
		}
		_, _, _ = StripSyslog(line)
	})
}
