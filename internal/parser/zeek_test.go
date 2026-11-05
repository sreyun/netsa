package parser

import (
	"strings"
	"testing"

	"netsa/internal/model"
)

// Zeek 的 TSV（带表头 / 没有表头）与 JSON 日志：conn、http、ssl、files 四类。
func TestZeekLogs(t *testing.T) {
	a, _ := NewAuto("auto", "")
	// 带表头的 conn.log：表头中的字段顺序与默认不同也按表头解析
	for _, l := range []string{
		"#separator \\x09", "#path\tconn",
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tservice",
	} {
		a.Directive(l)
	}
	ev, ok := a.Parse("1730000000.123456\tCabc\t10.0.0.10\t51514\t203.0.113.77\t443\ttcp\tSF\t943718400\t2048\t620000\t300\tssl")
	if !ok || ev.Format != "zeek_conn" || ev.Kind != model.KindFirewall || ev.SentBytes != 943718400 || ev.RecvBytes != 2048 ||
		ev.Packets != 620300 || ev.Reply != model.ReplyYes || ev.DstPort != 443 || ev.Time.Unix() != 1730000000 {
		t.Fatalf("conn（表头）: %+v", ev)
	}
	if ev, _ := a.Parse("1730000001.1\tCx\t45.33.1.2\t40000\t10.0.0.10\t3389\ttcp\tREJ\t0\t0\t1\t1\t-"); ev == nil || ev.Action != model.ActionDeny {
		t.Fatalf("REJ 为被拒绝: %+v", ev)
	}

	// 没有表头：按默认字段顺序
	b, _ := NewAuto("zeek", "")
	conn := "1730000000.5\tC1\t45.33.1.2\t40001\t10.0.0.10\t22\ttcp\t-\t-\t-\t-\tS0\tF\tT\t0\tS\t1\t44\t0\t0\t-"
	if ev, ok := b.Parse(conn); !ok || ev.Format != "zeek_conn" || ev.Reply != model.ReplyNone || ev.DstPort != 22 {
		t.Fatalf("conn（无表头）: %+v", ev)
	}
	httpLine := "1730000002.1\tC2\t45.33.1.2\t40002\t10.0.0.10\t80\t1\tPOST\twww.example.com\t/upload.php\t-\t1.1\tcurl/8.0\t-\t512\t20\t200\tOK\t-\t-\t(empty)\t-\t-\t-\tFa\t-\t-\tFb\t-\t-"
	if ev, ok := b.Parse(httpLine); !ok || ev.Kind != model.KindWeb || ev.Method != "POST" || ev.URI != "/upload.php" || ev.Status != 200 ||
		ev.ReqLength != 512 || ev.Bytes != 20 || ev.HTTPProto != "HTTP/1.1" || ev.UA != "curl/8.0" {
		t.Fatalf("http（无表头）: %+v", ev)
	}
	// 其他制表符分隔的日志不误认
	if _, ok := b.Parse("a\tb\tc\td\te\tf\tg\th\ti\tj\tk\tl\tm\tn\to\tp\tq\tr\ts\tt\tu"); ok {
		t.Fatal("随意的制表符分隔文本不应识别为 Zeek")
	}

	// JSON：ssl.log（含 ja3）、files.log、带 post_body 的 http.log
	ssl := `{"_path":"ssl","ts":1730000003.5,"uid":"C3","id.orig_h":"10.0.0.31","id.orig_p":50000,"id.resp_h":"203.0.113.9","id.resp_p":443,` +
		`"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","server_name":"Update.Example-CDN.com","established":true,"ja3":"72A589DA586844D7F0818CE684948EEA"}`
	ev, ok = a.Parse(ssl)
	if !ok || ev.Format != "zeek_ssl" || !ev.Aux || ev.TLSFinger != "ja3:72a589da586844d7f0818ce684948eea" || ev.SNI != "update.example-cdn.com" ||
		ev.TLSProto != "TLSv12" {
		t.Fatalf("ssl（JSON）: %+v", ev)
	}
	files := `{"_path":"files","ts":1730000004.0,"fuid":"F1","uid":"C4","id.orig_h":"10.0.0.10","id.orig_p":50001,"id.resp_h":"203.0.113.77","id.resp_p":80,` +
		`"source":"HTTP","mime_type":"application/x-executable","filename":"s.elf","is_orig":false,"seen_bytes":81234,"total_bytes":81234,"md5":"ABC0123456789abcdef0123456789abcd","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`
	ev, ok = a.Parse(files)
	if !ok || ev.File == nil || !ev.Aux || ev.SrcIP != "10.0.0.10" || ev.DstIP != "203.0.113.77" || ev.File.Mime != "application/x-executable" ||
		ev.File.Size != 81234 || ev.File.Proto != "HTTP" || ev.File.MD5 != "abc0123456789abcdef0123456789abcd" || !strings.Contains(ev.Target(), "s.elf") {
		t.Fatalf("files（JSON，下载方为主体）: %+v %+v", ev, ev.File)
	}
	upload := strings.Replace(files, `"is_orig":false`, `"is_orig":true`, 1)
	if ev, ok := a.Parse(upload); !ok || ev.SrcIP != "203.0.113.77" || ev.DstIP != "10.0.0.10" {
		t.Fatalf("上传的文件以接收方为主体: %+v", ev)
	}
	post := `{"_path":"http","ts":1730000005.0,"id.orig_h":"45.33.1.2","id.orig_p":1,"id.resp_h":"10.0.0.10","id.resp_p":80,"method":"POST","host":"www.example.com",` +
		`"uri":"/login","status_code":200,"request_body_len":40,"response_body_len":100,"post_body":"user=admin' or '1'='1&pass=x"}`
	if ev, ok := a.Parse(post); !ok || ev.Kind != model.KindWeb || ev.Body != "user=admin' or '1'='1&pass=x" || ev.Format != "zeek_http" {
		t.Fatalf("http（JSON，post_body）: %+v", ev)
	}
	// dns.log 的 JSON 不由 Zeek 解析器处理
	if ev, ok := a.Parse(`{"_path":"dns","ts":1730000006,"id.orig_h":"10.0.0.5","id.orig_p":1,"id.resp_h":"10.0.0.1","id.resp_p":53,"query":"a.example.com"}`); ok && ev.Kind != model.KindDNS {
		t.Fatalf("dns.log 应由 DNS 解析器处理: %+v", ev)
	}
}

// 云抗 D 服务的攻击事件：按目的地址生成没有来源的洪泛事件，单位换算；攻击结束的事件计为跳过。
func TestCloudDDoS(t *testing.T) {
	a, _ := NewAuto("auto", "")
	ev, ok := a.Parse(`{"event":"ddos_attack_start","attack_type":"UDP Flood","attacked_ip":"43.242.97.44","max_mbps":12500,"max_kpps":2100,"status":"cleaning","vendor":"阿里云 DDoS 防护","start_time":"2026-11-01 10:00:00"}`)
	if !ok || ev.Format != "cloud_ddos" || !ev.NoSource || ev.SrcIP != "" || ev.DstIP != "43.242.97.44" || ev.Bps != 12_500_000_000 || ev.Pps != 2_100_000 ||
		ev.Action != model.ActionDeny || !strings.Contains(ev.Threat, "12.50 Gbps / 2.10 Mpps") || !strings.Contains(ev.Threat, "正在清洗") {
		t.Fatalf("抗 D 攻击事件: %+v", ev)
	}
	ev, ok = a.Parse(`{"AttackType":"SYN Flood","Ip":"43.242.97.45","Bps":3000000000,"Pps":900000,"Status":"blackhole","Product":"大禹"}`)
	if !ok || ev.ThreatSeverity != "critical" || !strings.Contains(ev.Threat, "黑洞") || ev.Bps != 3e9 {
		t.Fatalf("黑洞: %+v", ev)
	}
	end := `{"event":"ddos_attack_end","attack_type":"UDP Flood","attacked_ip":"43.242.97.44","max_bps":1000000,"status":"end"}`
	if _, ok := a.Parse(end); ok || !a.Known(end) {
		t.Fatal("攻击结束的事件应计为跳过")
	}
	// 普通 JSON 日志里出现 attack 字样不误认
	if ev, ok := a.Parse(`{"msg":"attack surface report","ip":"10.0.0.1","count":3}`); ok && ev.Format == "cloud_ddos" {
		t.Fatalf("误认: %+v", ev)
	}
}
