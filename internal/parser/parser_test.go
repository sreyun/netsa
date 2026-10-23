package parser

import (
	"testing"

	"netsa/internal/model"
)

func mustAuto(t *testing.T, typ, format string) *Auto {
	t.Helper()
	p, err := NewAuto(typ, format)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAutoDetectFormats(t *testing.T) {
	cases := []struct {
		name, line, format string
		kind               model.Kind
		src, dst           string
		dport              int
		action             string
	}{
		{"nginx combined", `203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "curl/8.0"`,
			"nginx_combined", model.KindWeb, "203.0.113.5", "", 0, ""},
		{"nginx main with xff", `10.0.0.2 - - [22/Oct/2026:10:15:01 +0800] "POST /login HTTP/1.1" 401 12 "https://a.com/" "Mozilla/5.0" "198.51.100.7, 10.0.0.3"`,
			"nginx_main", model.KindWeb, "10.0.0.2", "", 0, ""},
		{"nginx vhost", `www.example.com:443 203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET / HTTP/2.0" 200 5 "-" "x"`,
			"nginx_combined", model.KindWeb, "203.0.113.5", "", 0, ""},
		{"nginx json", `{"time_iso8601":"2026-10-22T10:15:01+08:00","remote_addr":"203.0.113.9","request":"GET /a?b=1 HTTP/1.1","status":"404","body_bytes_sent":"10","http_user_agent":"x","host":"api.example.com"}`,
			"nginx_json", model.KindWeb, "203.0.113.9", "", 0, ""},
		{"ufw syslog", `Oct 22 10:15:01 web01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=198.51.100.23 DST=10.0.0.10 LEN=40 TOS=0x00 PREC=0x00 TTL=245 ID=54321 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0`,
			"netfilter", model.KindFirewall, "198.51.100.23", "10.0.0.10", 22, model.ActionDeny},
		{"firewalld rfc3339", `2026-10-22T10:15:01.123456+08:00 host kernel: filter_IN_public_REJECT: IN=ens3 OUT= SRC=198.51.100.24 DST=10.0.0.11 PROTO=TCP SPT=1 DPT=3389`,
			"netfilter", model.KindFirewall, "198.51.100.24", "10.0.0.11", 3389, model.ActionDeny},
		{"pfsense", `<134>Oct 22 10:15:01 filterlog[1234]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.25,10.0.0.1,51234,445,0,S,123,,64240,,mss`,
			"pfsense", model.KindFirewall, "198.51.100.25", "10.0.0.1", 445, model.ActionDeny},
		{"windows firewall", `2026-10-22 10:15:01 DROP TCP 198.51.100.26 10.0.0.12 51000 3389 52 S 1234 0 64240 - - - RECEIVE`,
			"windows_firewall", model.KindFirewall, "198.51.100.26", "10.0.0.12", 3389, model.ActionDeny},
		{"cisco asa", `<164>Oct 22 2026 10:15:01 asa01 : %ASA-4-106023: Deny tcp src outside:198.51.100.27/51234 dst inside:10.0.0.13/23 by access-group "outside_in" [0x0, 0x0]`,
			"cisco_asa", model.KindFirewall, "198.51.100.27", "10.0.0.13", 23, model.ActionDeny},
		{"fortigate", `date=2026-10-22 time=10:15:01 devname="FG" srcip=198.51.100.28 srcport=5555 dstip=10.0.0.14 dstport=6379 proto=6 action="accept" policyid=3`,
			"kv_firewall", model.KindFirewall, "198.51.100.28", "10.0.0.14", 6379, model.ActionAllow},
		{"huawei usg", `Oct 22 2026 10:15:01 USG6000 %%01SECIF/6/POLICYDENY(l)[0]:SourceIP=198.51.100.29, DestinationIP=10.0.0.15, SourcePort=4444, DestinationPort=1433, Protocol=TCP`,
			"kv_firewall", model.KindFirewall, "198.51.100.29", "10.0.0.15", 1433, model.ActionDeny},
		{"h3c", `<190>Oct 22 10:15:01 2026 H3C %%10FILTER/6/FILTER_ZONE_IPV4_EXECUTION: SrcZoneName(1025)=Untrust;DstZoneName(1035)=Trust;SrcIPAddr(1003)=198.51.100.30;DstIPAddr(1007)=10.0.0.16;SrcPort(1004)=5000;DstPort(1008)=22;Protocol(1001)=TCP;Action(1053)=Deny;`,
			"kv_firewall", model.KindFirewall, "198.51.100.30", "10.0.0.16", 22, model.ActionDeny},
		{"json firewall", `{"timestamp":"2026-10-22T10:15:01Z","src_ip":"198.51.100.31","dst_ip":"10.0.0.17","dst_port":9200,"protocol":"tcp","action":"drop"}`,
			"json_firewall", model.KindFirewall, "198.51.100.31", "10.0.0.17", 9200, model.ActionDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := mustAuto(t, "auto", "").Parse(c.line)
			if !ok {
				t.Fatalf("未能解析: %s", c.line)
			}
			if ev.Format != c.format || ev.Kind != c.kind || ev.SrcIP != c.src {
				t.Fatalf("format=%s kind=%s src=%s", ev.Format, ev.Kind, ev.SrcIP)
			}
			if c.kind == model.KindFirewall && (ev.DstIP != c.dst || ev.DstPort != c.dport || ev.Action != c.action) {
				t.Fatalf("dst=%s dport=%d action=%s", ev.DstIP, ev.DstPort, ev.Action)
			}
			if ev.Time.IsZero() || ev.Time.Year() < 2026 {
				t.Fatalf("时间解析失败: %v", ev.Time)
			}
		})
	}
}

func TestNginxFields(t *testing.T) {
	ev, ok := Nginx{}.Parse(`10.0.0.2 - bob [22/Oct/2026:10:15:01 +0800] "GET /a?x=\x22%3Cscript%3E HTTP/1.1" 200 1234 "https://ref/" "Mozilla/5.0" "198.51.100.7"`)
	if !ok {
		t.Fatal("parse failed")
	}
	if ev.Method != "GET" || ev.URI != `/a?x="%3Cscript%3E` || ev.HTTPProto != "HTTP/1.1" || ev.Status != 200 || ev.Bytes != 1234 {
		t.Fatalf("%+v", ev)
	}
	if ev.XFF != "198.51.100.7" || ev.Referer != "https://ref/" {
		t.Fatalf("xff=%q ref=%q", ev.XFF, ev.Referer)
	}
	// 非 HTTP 请求行（例如 TLS 握手发往 80 端口）
	ev, ok = Nginx{}.Parse(`203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "\x16\x03\x01\x00\xa5\x01" 400 157 "-" "-"`)
	if !ok || ev.Method != "" || ev.URI[0] != 0x16 {
		t.Fatalf("non-http: %+v", ev)
	}
}

func TestCustomLogFormat(t *testing.T) {
	format := `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" $request_time $host`
	p := mustAuto(t, "nginx", format)
	ev, ok := p.Parse(`10.1.1.1 - - [22/Oct/2026:10:15:01 +0800] "GET /x HTTP/1.1" 200 33 "-" "UA with spaces" "198.51.100.9" 0.005 shop.example.com`)
	if !ok {
		t.Fatal("custom format parse failed")
	}
	if ev.Format != "nginx_custom" || ev.Host != "shop.example.com" || ev.ReqTime != 0.005 || ev.UA != "UA with spaces" || ev.XFF != "198.51.100.9" {
		t.Fatalf("%+v", ev)
	}
}

func TestOutboundAndSkip(t *testing.T) {
	ev, ok := Netfilter{}.Parse(`kernel: [UFW BLOCK] IN= OUT=eth0 SRC=10.0.0.10 DST=198.51.100.1 PROTO=UDP SPT=1 DPT=53`)
	if !ok || !ev.Outbound {
		t.Fatalf("应识别为出站流量: %+v", ev)
	}
	if !Skippable("#Fields: date time action") || Skippable("x") {
		t.Fatal("Skippable")
	}
}

// 直接从 nginx.conf 粘贴的多行 log_format 也应能编译。
func TestLogFormatPastedFromConf(t *testing.T) {
	conf := `log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';`
	p := mustAuto(t, "nginx", conf)
	ev, ok := p.Parse(`10.0.0.2 - - [22/Oct/2026:10:15:01 +0800] "GET /a HTTP/1.1" 200 33 "-" "UA" "198.51.100.9"`)
	if !ok || ev.Format != "nginx_custom" || ev.XFF != "198.51.100.9" || ev.URI != "/a" {
		t.Fatalf("%v %+v", ok, ev)
	}
}

func TestRequestWithSpaces(t *testing.T) {
	ev, ok := Nginx{}.Parse(`203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET /a b?c=1 HTTP/1.1" 404 5 "-" "x"`)
	if !ok || ev.Method != "GET" || ev.URI != "/a b?c=1" || ev.HTTPProto != "HTTP/1.1" {
		t.Fatalf("%+v", ev)
	}
}

func TestDeviceThreatFormats(t *testing.T) {
	cases := []struct{ line, format, threat, dst string }{
		{`{"timestamp":"2026-10-22T10:15:01Z","event_type":"alert","src_ip":"198.51.100.40","src_port":5555,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature":"ET EXPLOIT Apache Log4j RCE Attempt","category":"Attempted Administrator Privilege Gain","severity":1}}`, "suricata", "ET EXPLOIT Apache Log4j RCE Attempt", "10.0.0.5"},
		{`10/22-10:15:01.123456  [**] [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 198.51.100.41:5555 -> 10.0.0.1:1433`, "snort", "ET SCAN Suspicious inbound to MSSQL port 1433", "10.0.0.1"},
		{`date=2026-10-22 time=10:15:01 type="utm" subtype="ips" srcip=198.51.100.42 dstip=10.0.0.6 dstport=443 proto=6 action="dropped" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" severity="critical"`, "kv_firewall", "Apache.Log4j.Error.Log.Remote.Code.Execution", "10.0.0.6"},
	}
	for _, c := range cases {
		ev, ok := mustAuto(t, "auto", "").Parse(c.line)
		if !ok || ev.Format != c.format || ev.Threat != c.threat || ev.DstIP != c.dst {
			t.Errorf("%s: ok=%v %+v", c.format, ok, ev)
		}
	}
}
