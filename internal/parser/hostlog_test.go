package parser

import (
	"testing"

	"netsa/internal/model"
)

func TestHostLogParsers(t *testing.T) {
	cases := []struct {
		line, format               string
		kind                       model.Kind
		src, user, service, action string
		host                       string
		eventID                    int
		subject                    bool
	}{
		{`Oct 25 10:00:01 web01 sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 51234 ssh2`, "linux_auth", model.KindAuth, "198.51.100.7", "admin", "SSH", "deny", "web01", 0, false},
		{`Oct 25 10:00:02 web01 sshd[1234]: Failed password for root from 198.51.100.7 port 51235 ssh2`, "linux_auth", model.KindAuth, "198.51.100.7", "root", "SSH", "deny", "web01", 0, false},
		{`Oct 25 10:00:03 web01 sshd[1234]: Accepted publickey for deploy from 10.0.0.8 port 40022 ssh2: ED25519 SHA256:abc`, "linux_auth", model.KindAuth, "10.0.0.8", "deploy", "SSH", "allow", "web01", 0, false},
		{`Oct 25 10:00:04 web01 sshd[99]: Invalid user oracle from 198.51.100.8 port 4242`, "linux_auth", model.KindAuth, "198.51.100.8", "oracle", "SSH", "deny", "web01", 0, false},
		{`Oct 25 10:00:05 web01 sshd[99]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.9  user=root`, "linux_auth", model.KindAuth, "198.51.100.9", "root", "SSH", "deny", "web01", 0, false},
		{`Oct 25 10:00:06 web01 useradd[300]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash`, "linux_auth", model.KindAuth, "127.0.0.1", "backdoor", "useradd", "allow", "web01", 4720, true},
		{`{"EventID":4625,"Hostname":"DC01","TargetUserName":"administrator","TargetDomainName":"CORP","IpAddress":"198.51.100.10","LogonType":"10","EventTime":"2026-10-25 10:00:07"}`, "windows_security", model.KindAuth, "198.51.100.10", `CORP\administrator`, "RDP", "deny", "DC01", 4625, false},
		{`{"winlog":{"event_id":4624,"computer_name":"FS01","event_data":{"TargetUserName":"bob","IpAddress":"::ffff:10.0.0.20","LogonType":"3"}},"@timestamp":"2026-10-25T02:00:08Z"}`, "windows_security", model.KindAuth, "10.0.0.20", "bob", "网络登录", "allow", "FS01", 4624, false},
		{`{"EventID":1102,"Hostname":"DC01","SubjectUserName":"eve"}`, "windows_security", model.KindAuth, "127.0.0.1", "", "Windows", "allow", "DC01", 1102, true},
		{`MSWinEventLog	1	Security	12	Sun Oct 25 10:00:09 2026	4625	Microsoft-Windows-Security-Auditing	N/A	Failure Audit	WS01	Logon	An account failed to log on.  Account Name: guest  Logon Type: 3  Source Network Address: 198.51.100.11`, "windows_security", model.KindAuth, "198.51.100.11", "guest", "网络登录", "deny", "", 4625, false},
		{`{"EventID":4624,"TargetUserName":"WS01$","IpAddress":"10.0.0.5","LogonType":"3"}`, "", "", "", "", "", "", "", 0, false}, // 计算机账号：忽略
		{`<190>date=2026-10-25 time=10:00:10 devname="FGT60F" logid="0101039426" type="event" subtype="vpn" level="alert" action="ssl-login-fail" tunneltype="ssl-web" remip=198.51.100.12 user="alice" reason="sslvpn_login_permission_denied"`, "vpn_auth", model.KindAuth, "198.51.100.12", "alice", "SSL VPN", "deny", "FGT60F", 0, false},
		{`<190>date=2026-10-25 time=10:00:11 devname="FGT60F" logid="0100032002" type="event" subtype="system" level="alert" user="admin" ui="https(198.51.100.13)" srcip=198.51.100.13 action="login" status="failed" reason="name_invalid"`, "vpn_auth", model.KindAuth, "198.51.100.13", "admin", "设备管理登录", "deny", "FGT60F", 0, false},
		{`%ASA-6-113015: AAA user authentication Rejected : reason = AAA failure : server = 10.0.0.2 : user = bob : user IP = 198.51.100.14`, "vpn_auth", model.KindAuth, "198.51.100.14", "bob", "Cisco VPN", "deny", "", 0, false},
		{`2026-10-25 10:00:12.34 Logon       Login failed for user 'sa'. Reason: Password did not match that for the login provided. [CLIENT: 198.51.100.15]`, "vpn_auth", model.KindAuth, "198.51.100.15", "sa", "MSSQL", "deny", "", 0, false},
		{`Sun Oct 25 10:00:13 2026 198.51.100.16:51000 TLS Auth Error: Auth Username/Password verification failed for peer`, "vpn_auth", model.KindAuth, "198.51.100.16", "", "OpenVPN", "deny", "", 0, false},
	}
	auto, _ := NewAuto("auto", "")
	for _, c := range cases {
		ev, ok := auto.Parse(c.line)
		if c.format == "" {
			if ok && ev.Kind == model.KindAuth {
				t.Errorf("应忽略: %s → %+v", c.line, ev)
			}
			continue
		}
		if !ok {
			t.Errorf("无法解析: %s", c.line)
			continue
		}
		if ev.Format != c.format || ev.Kind != c.kind || ev.SrcIP != c.src || ev.User != c.user || ev.Service != c.service || ev.Action != c.action ||
			ev.Host != c.host || ev.EventID != c.eventID || ev.SubjectHost != c.subject {
			t.Errorf("%s\n  得到 format=%s kind=%s src=%s user=%q svc=%s act=%s host=%s id=%d subject=%v", c.line, ev.Format, ev.Kind, ev.SrcIP, ev.User, ev.Service, ev.Action, ev.Host, ev.EventID, ev.SubjectHost)
		}
	}
}

func TestDNSParsers(t *testing.T) {
	cases := []struct{ line, format, client, name, qtype, rcode string }{
		{`25-Oct-2026 10:00:00.123 queries: info: client @0x7f1c2c0b4d60 10.0.0.5#53421 (www.example.com): query: www.example.com IN A +E(0)K (10.0.0.1)`, "bind_query", "10.0.0.5", "www.example.com", "A", ""},
		{`Oct 25 10:00:01 gw dnsmasq[812]: query[TXT] abcd1234.tunnel.example.net from 192.168.1.20`, "dnsmasq", "192.168.1.20", "abcd1234.tunnel.example.net", "TXT", ""},
		{`[INFO] 10.244.0.7:53421 - 4521 "AAAA IN api.example.com. udp 40 false 512" NXDOMAIN qr,rd,ra 136 0.000213s`, "coredns", "10.244.0.7", "api.example.com", "AAAA", "NXDOMAIN"},
		{`10/25/2026 10:00:02 AM 0E5C PACKET  0000020B0A1B2C30 UDP Rcv 10.0.0.30       a1b2   Q [0001   D   NOERROR] A      (7)example(3)com(0)`, "windows_dns", "10.0.0.30", "example.com", "A", ""},
		{"1761357603.123456\tCabc\t10.0.0.40\t53000\t10.0.0.1\t53\tudp\t1234\t0.001\tx7k2p9q1.evil.example\t1\tC_INTERNET\t1\tA\t3\tNXDOMAIN\tF\tF\tT\tF\t0\t-\t-\tF", "zeek_dns", "10.0.0.40", "x7k2p9q1.evil.example", "A", "NXDOMAIN"},
		{`{"timestamp":"2026-10-25T10:00:03.000+0800","event_type":"dns","src_ip":"10.0.0.50","dest_ip":"10.0.0.1","dns":{"type":"query","rrname":"pool.minexmr.com","rrtype":"A"}}`, "json_dns", "10.0.0.50", "pool.minexmr.com", "A", ""},
	}
	for _, c := range cases {
		auto, _ := NewAuto("dns", "")
		ev, ok := auto.Parse(c.line)
		if !ok {
			t.Errorf("无法解析: %s", c.line)
			continue
		}
		if ev.Kind != model.KindDNS || ev.Format != c.format || ev.SrcIP != c.client || ev.Host != c.name || ev.QType != c.qtype || ev.RCode != c.rcode || ev.Time.IsZero() {
			t.Errorf("%s\n  得到 %s %s %s %s %s %s %v", c.line, ev.Kind, ev.Format, ev.SrcIP, ev.Host, ev.QType, ev.RCode, ev.Time)
		}
	}
	// 自动识别模式下，防火墙与 Web 日志不受影响
	auto, _ := NewAuto("auto", "")
	if ev, ok := auto.Parse(`<4>Oct 22 10:15:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=22`); !ok || ev.Kind != model.KindFirewall {
		t.Fatal("防火墙日志")
	}
	if ev, ok := auto.Parse(`198.51.100.1 - - [25/Oct/2026:10:00:00 +0800] "GET /login HTTP/1.1" 200 12 "-" "curl"`); !ok || ev.Kind != model.KindWeb {
		t.Fatal("Web 日志")
	}
}
