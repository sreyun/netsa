package ingest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
)

const ufwLine = `<4>Oct 22 10:15:01 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=%d SYN`

func TestSyslogHostname(t *testing.T) {
	for line, want := range map[string]string{
		`<4>Oct 22 10:15:01 fw01 kernel: x`:                              "fw01",
		`<4>Oct  2 10:15:01 core-sw.example.com sshd[1]: x`:              "core-sw.example.com",
		`<165>1 2026-10-22T10:15:01.003Z waf01 nginx 123 ID47 - msg`:     "waf01",
		`<13>2026-10-22T10:15:01+08:00 host_a app: x`:                    "host_a",
		`<4>Oct 22 10:15:01 kernel: [UFW BLOCK] x`:                       "",
		`<189>date=2026-10-22 time=10:15:02 devname="FGT" srcip=1.2.3.4`: "",
		`plain text`:         "",
		`<165>1 - - - - - -`: "",
	} {
		if got := syslogHostname(line); got != want {
			t.Errorf("%q → %q，期望 %q", line, got, want)
		}
	}
}

func TestSenderPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "senders.json")
	cfg := config.SyslogConfig{Senders: []config.SyslogSender{{CIDR: "10.1.0.0/16", Name: "办公网", Group: "服务器"}, {CIDR: "10.1.9.9", Action: "block"}}}
	s, err := NewSenders(cfg, path, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr
	// 未开启白名单：未登记的发送端也接收，但会产生“新发送端”通知
	if _, ok := s.admit(addr("203.0.113.7"), ProtoUDP, "syslog-udp"); !ok {
		t.Fatal("未开启白名单时应接收")
	}
	if n := s.TakeNotices(); len(n) != 1 || n[0].Kind != "new" {
		t.Fatalf("新发送端通知: %+v", n)
	}
	// 阻止规则（单个 IP 优先于网段）在任何模式下都拒绝
	if _, ok := s.admit(addr("10.1.9.9"), ProtoTCP, "syslog-tcp"); ok {
		t.Fatal("阻止的发送端应被拒绝")
	}
	if n := s.TakeNotices(); len(n) != 1 || n[0].Kind != "rejected" || !strings.Contains(n[0].Detail, "阻止") {
		t.Fatalf("拒绝通知: %+v", n)
	}
	st, ok := s.admit(addr("10.1.2.3"), ProtoUDP, "syslog-udp")
	if !ok || st.label("syslog-udp", ProtoUDP) != "syslog-udp 办公网(10.1.2.3)" {
		t.Fatalf("网段登记: %v %q", ok, st.label("syslog-udp", ProtoUDP))
	}
	st.lines.Add(1)
	st.parsed.Add(1)

	// 开启白名单：白名单中有配置文件登记的允许网段，可以直接开启
	if _, err := s.SetAllowlist(true, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.admit(addr("203.0.113.7"), ProtoUDP, "syslog-udp"); ok {
		t.Fatal("开启白名单后未登记的发送端应被拒绝")
	}
	if _, ok := s.admit(addr("10.1.2.3"), ProtoUDP, "syslog-udp"); !ok {
		t.Fatal("登记的网段应接收")
	}
	// 同一发送端的拒绝通知有间隔
	s.admit(addr("203.0.113.7"), ProtoUDP, "syslog-udp")
	if n := s.TakeNotices(); len(n) != 1 || n[0].IP != "203.0.113.7" {
		t.Fatalf("拒绝通知应只有一条: %+v", n)
	}
	// 界面登记后立即生效（不需要重启）
	r, err := s.AddRule(SenderRule{CIDR: "203.0.113.7", Name: "外部 WAF", Group: "WAF", Silence: "10m"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := s.admit(addr("203.0.113.7"), ProtoUDP, "syslog-udp"); !ok || st.label("syslog-udp", ProtoUDP) != "syslog-udp 外部 WAF(203.0.113.7)" {
		t.Fatal("登记后应接收，且数据来源名称更新")
	}
	if _, err := s.AddRule(SenderRule{CIDR: "203.0.113.7"}, "admin"); err != ErrSenderDup {
		t.Fatalf("重复登记: %v", err)
	}
	for _, bad := range []SenderRule{{CIDR: "0.0.0.0/0"}, {CIDR: "x"}, {CIDR: "10.0.0.1", Action: "drop"}, {CIDR: "10.0.0.1", Silence: "5s"}} {
		if _, err := s.AddRule(bad, "admin"); err == nil {
			t.Errorf("应拒绝: %+v", bad)
		}
	}
	if _, err := s.UpdateRule("cfg-1", SenderRule{CIDR: "10.1.0.0/16"}); err != ErrSenderConfig {
		t.Fatal("配置文件中的登记只读")
	}
	if _, err := s.UpdateRule(r.ID, SenderRule{CIDR: "203.0.113.7", Name: "<b>WAF</b>\x00", Group: "WAF", Action: "block"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.admit(addr("203.0.113.7"), ProtoUDP, "syslog-udp"); ok {
		t.Fatal("修改为阻止后应立即拒绝")
	}

	rep := s.Report()
	if !rep.Allowlist || rep.Forced || rep.Totals.Senders != 3 || len(rep.Rules) != 3 || rep.Totals.Rejected != 2 {
		t.Fatalf("报告: %+v", rep.Totals)
	}
	var groups []string
	for _, g := range rep.Groups {
		groups = append(groups, g.Name)
	}
	if !strings.Contains(strings.Join(groups, ","), "服务器") || !strings.Contains(strings.Join(groups, ","), "WAF") {
		t.Fatalf("分组汇总: %v", groups)
	}

	// 持久化：登记、开关与发送端统计在重启后恢复
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	s2, err := NewSenders(cfg, path, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rep2 := s2.Report()
	if !rep2.Allowlist || len(rep2.Rules) != 3 || rep2.Totals.Lines != 1 {
		t.Fatalf("重启后: %+v", rep2.Totals)
	}
	if _, ok := s2.admit(addr("203.0.113.7"), ProtoUDP, "syslog-udp"); ok {
		t.Fatal("重启后阻止规则仍应生效")
	}
	// 关闭白名单
	if _, err := s2.SetAllowlist(false, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.admit(addr("198.51.100.1"), ProtoUDP, "syslog-udp"); !ok {
		t.Fatal("关闭白名单后应接收")
	}
}

func TestAllowlistGuards(t *testing.T) {
	s, _ := NewSenders(config.SyslogConfig{}, "", 0)
	addr := netip.MustParseAddr
	// 白名单为空时不能直接开启，避免误操作导致全部日志被拒绝
	if _, err := s.SetAllowlist(true, false, "admin"); err != ErrAllowlistOpen {
		t.Fatalf("空白名单: %v", err)
	}
	st, _ := s.admit(addr("192.0.2.10"), ProtoTCP, "syslog-tcp")
	st.lines.Add(5)
	st.parsed.Add(5)
	s.admit(addr("192.0.2.11"), ProtoTCP, "syslog-tcp") // 只连接、没有可解析的日志：不自动登记
	n, err := s.SetAllowlist(true, true, "admin")
	if err != nil || n != 1 {
		t.Fatalf("自动登记活跃发送端: %d %v", n, err)
	}
	if _, ok := s.admit(addr("192.0.2.10"), ProtoTCP, "syslog-tcp"); !ok {
		t.Fatal("自动登记的发送端应接收")
	}
	if _, ok := s.admit(addr("192.0.2.11"), ProtoTCP, "syslog-tcp"); ok {
		t.Fatal("未登记的发送端应拒绝")
	}
	// 配置文件强制开启时界面不能关闭
	f, _ := NewSenders(config.SyslogConfig{Allowlist: true, Senders: []config.SyslogSender{{CIDR: "10.0.0.0/8"}}}, "", 0)
	if _, err := f.SetAllowlist(false, false, "admin"); err != ErrAllowForced {
		t.Fatalf("强制开启: %v", err)
	}
	if !f.Report().Forced {
		t.Fatal("应标记为配置文件强制开启")
	}
}

func TestSenderRateLimitAndSilence(t *testing.T) {
	s, _ := NewSenders(config.SyslogConfig{RateLimit: 3, Senders: []config.SyslogSender{{CIDR: "10.0.0.5", Name: "fw", Silence: "5m"}}}, "", time.Hour)
	st, _ := s.admit(netip.MustParseAddr("10.0.0.5"), ProtoUDP, "syslog-udp")
	got := 0
	for i := 0; i < 10; i++ {
		if st.take(s.rateLimit, 100) {
			got++
		}
	}
	if got != 3 || st.limited.Load() != 7 || !st.take(s.rateLimit, 101) {
		t.Fatalf("限速: %d %d", got, st.limited.Load())
	}
	st.lines.Add(1)
	now := time.Now()
	s.now = func() time.Time { return now.Add(6 * time.Minute) }
	s.Tick()
	n := s.TakeNotices()
	if len(n) != 1 || n[0].Kind != "silent" || n[0].Name != "fw" || n[0].Silence != 5*time.Minute {
		t.Fatalf("断流通知: %+v", n)
	}
	if v := s.Report().Senders[0]; v.Status != "silent" || v.Silence != "5 分钟" {
		t.Fatalf("断流状态: %+v", v)
	}
	s.Tick()
	if n := s.TakeNotices(); len(n) != 0 {
		t.Fatal("断流通知不应重复")
	}
	s.admit(netip.MustParseAddr("10.0.0.5"), ProtoUDP, "syslog-udp")
	s.Tick()
	if n := s.TakeNotices(); len(n) != 1 || n[0].Kind != "recovered" {
		t.Fatalf("恢复通知: %+v", n)
	}
}

func TestSenderEvictionKeepsRegistered(t *testing.T) {
	s, _ := NewSenders(config.SyslogConfig{Senders: []config.SyslogSender{{CIDR: "10.0.0.1"}}}, "", 0)
	s.admit(netip.MustParseAddr("10.0.0.1"), ProtoUDP, "syslog-udp")
	for i := 0; i < maxSenderStats+10; i++ {
		s.admit(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), ProtoUDP, "syslog-udp")
	}
	s.mu.RLock()
	_, kept := s.stats[netip.MustParseAddr("10.0.0.1")]
	n := len(s.stats)
	s.mu.RUnlock()
	if !kept || n > maxSenderStats {
		t.Fatalf("淘汰后: kept=%v n=%d", kept, n)
	}
}

// 端到端：白名单开启后，未登记发送端的 TCP 连接被立即关闭，UDP 数据报被丢弃；登记的发送端正常接收并带上设备名称。
func TestSyslogAllowlistEndToEnd(t *testing.T) {
	m := NewManager(100)
	var err error
	m.Senders, err = NewSenders(config.SyslogConfig{Allowlist: true, Senders: []config.SyslogSender{{CIDR: "10.255.255.1", Name: "不存在的设备"}}}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.StartSyslog(ctx, config.SyslogConfig{Enabled: true, UDP: "127.0.0.1:15516", TCP: "127.0.0.1:15516"}); err != nil {
		t.Fatal(err)
	}
	u, _ := net.Dial("udp", "127.0.0.1:15516")
	defer u.Close()
	fmt.Fprintf(u, ufwLine, 22)
	c, err := net.Dial("tcp", "127.0.0.1:15516")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, ufwLine+"\n", 23)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("未授权的 TCP 连接应被关闭")
	}
	c.Close()
	select {
	case b := <-m.Out:
		t.Fatalf("未授权的发送端不应产生事件: %d", len(b))
	case <-time.After(400 * time.Millisecond):
	}
	if rep := m.Senders.Report(); rep.Totals.Dropped < 2 || rep.Senders[0].IP != "127.0.0.1" || rep.Senders[0].Status != "rejected" {
		t.Fatalf("拒绝统计: %+v %+v", rep.Totals, rep.Senders)
	}
	// 登记本机后立即接收，已建立的连接之外的新连接无需重启
	if _, err := m.Senders.AddRule(SenderRule{CIDR: "127.0.0.1", Name: "本机", Group: "测试"}, "admin"); err != nil {
		t.Fatal(err)
	}
	c2, _ := net.Dial("tcp", "127.0.0.1:15516")
	defer c2.Close()
	fmt.Fprintf(c2, ufwLine+"\n", 24)
	evs := collect(t, m.Out, 1)
	if evs[0].DstPort != 24 || evs[0].Source != "syslog-tcp 本机(127.0.0.1)" {
		t.Fatalf("登记后: %+v", evs[0])
	}
	v := m.Senders.Report().Senders
	if v[0].Hostname != "fw01" || v[0].Group != "测试" || v[0].Parsed != 1 {
		t.Fatalf("发送端画像: %+v", v[0])
	}
}

// syslog over TLS 双向认证：出示 CA 签发的客户端证书才能发送；没有证书的连接在握手阶段失败。
func TestSyslogTLSMutual(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "netsa test ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(cn string, usage x509.ExtKeyUsage, serial int64) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
		kb, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sc, sk := issue("netsa", x509.ExtKeyUsageServerAuth, 2)
	cc, ck := issue("fw01.example.com", x509.ExtKeyUsageClientAuth, 3)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	cfg := config.SyslogConfig{Enabled: true, TLS: "127.0.0.1:16514", TLSCert: write("s.crt", sc), TLSKey: write("s.key", sk), TLSClientCA: write("ca.crt", caPEM)}
	m := NewManager(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.StartSyslog(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	// 没有客户端证书：握手失败，不产生事件
	if c, err := tls.Dial("tcp", cfg.TLS, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}); err == nil {
		fmt.Fprintf(c, ufwLine+"\n", 25)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		c.Read(make([]byte, 1))
		c.Close()
	}
	select {
	case <-m.Out:
		t.Fatal("没有客户端证书不应接收日志")
	case <-time.After(300 * time.Millisecond):
	}
	pair, err := tls.X509KeyPair(cc, ck)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.Dial("tcp", cfg.TLS, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, ufwLine+"\n", 26)
	if evs := collect(t, m.Out, 1); evs[0].DstPort != 26 || evs[0].Source != "syslog-tls 127.0.0.1" {
		t.Fatalf("TLS 事件: %+v", evs[0])
	}
	v := m.Senders.Report().Senders[0]
	if !strings.Contains(v.Cert, "fw01.example.com") || strings.Join(v.Protocols, ",") != "TLS" || v.Rejected < 1 {
		t.Fatalf("TLS 发送端画像: %+v", v)
	}
	if _, err := syslogTLSConfig(config.SyslogConfig{TLSCert: cfg.TLSCert, TLSKey: cfg.TLSKey, TLSClientCA: write("bad.crt", []byte("x"))}); err == nil {
		t.Fatal("无效的客户端 CA 应报错")
	}
}
