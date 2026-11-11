package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

func ruleHits(hits []model.Hit, id string) []model.Hit {
	var out []model.Hit
	for _, h := range hits {
		if h.RuleID == id {
			out = append(out, h)
		}
	}
	return out
}

// 数据外传：与主机自己的基线相比暴增为高危；没有基线时按阈值的 4 倍判断（中危）；每个窗口只告警一次。
func TestExfil(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	egress := func(src, dst string, bytes int64, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: 443, Proto: "tcp", Action: model.ActionAllow,
			Outbound: true, SentBytes: bytes, Time: at})
	}
	// 平时每 10 分钟外发约 20 MB
	for w := range 20 {
		for i := range 4 {
			if h := ruleHits(egress("10.0.0.31", "198.51.100.8", 5<<20, t0.Add(time.Duration(w)*10*time.Minute+time.Duration(i)*time.Minute)), "bhv-exfil"); len(h) > 0 {
				t.Fatalf("平时的外发不应告警: %+v", h)
			}
		}
	}
	at := t0.Add(200 * time.Minute)
	var fired []model.Hit
	for i := range 6 { // 一个窗口内外发 1.5 GB
		fired = append(fired, ruleHits(egress("10.0.0.31", "203.0.113.50", 256<<20, at.Add(time.Duration(i)*time.Minute)), "bhv-exfil")...)
	}
	if len(fired) != 1 || fired[0].Severity != model.SevHigh || !strings.Contains(fired[0].Evidence, "203.0.113.50") || !strings.Contains(fired[0].Evidence, "平时约") {
		t.Fatalf("与基线相比暴增: %+v", fired)
	}
	// 没有基线的主机：2 GB 不告警，5 GB 告警（中危）
	var cold []model.Hit
	for i := range 20 {
		cold = append(cold, ruleHits(egress("10.0.0.32", "203.0.113.60", 256<<20, t0.Add(time.Duration(i)*20*time.Second)), "bhv-exfil")...)
	}
	if len(cold) != 1 || cold[0].Severity != model.SevMedium {
		t.Fatalf("没有基线时按阈值的 4 倍判断: %+v", cold)
	}
	if h := ruleHits(egress("10.0.0.33", "203.0.113.60", 2<<30, t0), "bhv-exfil"); len(h) != 0 {
		t.Fatalf("没有基线时 2 GB 不告警: %+v", h)
	}
	// 跨过固定窗口边界的突发（窗口从第一次外发开始计）：不会被拆成两半漏报，乱序到达的较早会话同样计入，只告警一次
	egress("10.0.0.34", "198.51.100.8", 1<<20, t0)
	var split []model.Hit
	for _, s := range []int{620, 560, 580, 600, 640, 660} { // 9m20s ~ 11m（含乱序）
		split = append(split, ruleHits(egress("10.0.0.34", "203.0.113.61", 900<<20, t0.Add(time.Duration(s)*time.Second)), "bhv-exfil")...)
	}
	if len(split) != 1 || !strings.Contains(split[0].Evidence, "4.4 GB") {
		t.Fatalf("跨窗口边界的突发: %+v", split)
	}
	if h := ruleHits(egress("10.0.0.34", "203.0.113.61", 900<<20, t0.Add(700*time.Second)), "bhv-exfil"); len(h) != 0 {
		t.Fatalf("同一次突发不重复告警: %+v", h)
	}
}

// 单来源下载量突增：动态接口与文件下载计入，图片、视频等静态资源不计入。
func TestDownloadSurge(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	web := func(src, uri string, bytes int64, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: src, Host: "a.example.com", Method: "GET", URI: uri, Status: 200, Bytes: bytes, UA: "Mozilla/5.0", Time: at})
	}
	for i := range 30 {
		if h := ruleHits(web("198.51.100.9", fmt.Sprintf("/video/%d.mp4", i), 100<<20, t0.Add(time.Duration(i)*time.Second)), "bhv-download"); len(h) > 0 {
			t.Fatalf("视频不计入: %+v", h)
		}
	}
	var fired []model.Hit
	for i := range 12 {
		fired = append(fired, ruleHits(web("198.51.100.10", fmt.Sprintf("/api/export?page=%d", i), 50<<20, t0.Add(time.Duration(i)*time.Second)), "bhv-download")...)
	}
	if len(fired) != 1 || !strings.Contains(fired[0].Evidence, "/api/export") || fired[0].Category != CatDownload {
		t.Fatalf("接口导出 600 MB: %+v", fired)
	}
}

// WebShell 行为画像：站点观察满 24 小时后新出现的脚本，只被 1 个来源以 POST 访问、响应大小各不相同；
// 同一来源此前上传过文件时有证据。被多个来源访问的正常页面、观察期内的脚本不告警。
func TestWebShellBehavior(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	req := func(src, method, uri string, bytes, reqLen int64, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: src, Host: "www.example.com", Method: method, URI: uri, Status: 200,
			Bytes: bytes, ReqLength: reqLen, UA: "Mozilla/5.0", Time: at})
	}
	req("198.51.100.1", "GET", "/index.php", 5000, 300, t0) // 站点开始观察
	// 观察期内出现的脚本：不告警
	for i := range 6 {
		if h := ruleHits(req("198.51.100.2", "POST", "/early.php", int64(100+i*37), 500, t0.Add(time.Hour+time.Duration(i)*time.Second)), "bhv-webshell"); len(h) > 0 {
			t.Fatalf("观察期内不告警: %+v", h)
		}
	}
	at := t0.Add(25 * time.Hour)
	req("203.0.113.66", "POST", "/admin/upload.php", 120, 85<<10, at) // 上传
	var fired []model.Hit
	for i := range 6 {
		fired = append(fired, ruleHits(req("203.0.113.66", "POST", "/uploads/2026/11/x7.php", int64(64+i*211), int64(200+i*13), at.Add(time.Duration(i+1)*time.Minute)), "bhv-webshell")...)
	}
	if len(fired) != 1 || !fired[0].Proven || fired[0].Result != model.ResultSuccess || !strings.Contains(fired[0].Evidence, "上传者就是访问者") ||
		!strings.Contains(fired[0].Evidence, "/admin/upload.php") {
		t.Fatalf("上传后的 WebShell 交互: %+v", fired)
	}
	// 新上线的后台页面，路径里有 upload、没有其他上传：脚本自身的第一次 POST 不算它的上传证据
	var page []model.Hit
	for i := range 6 {
		page = append(page, ruleHits(req("198.51.100.40", "POST", "/admin/upload-profile.php", int64(64+i*97), 300, at.Add(2*time.Hour+time.Duration(i)*time.Minute)), "bhv-webshell")...)
	}
	if len(page) != 1 || page[0].Proven || strings.Contains(page[0].Evidence, "向 /admin/upload-profile.php 上传") {
		t.Fatalf("新页面自身的请求不能当作上传证据: %+v", page)
	}
	// 被 3 个来源访问的新页面：正常
	for i := range 9 {
		if h := ruleHits(req(fmt.Sprintf("198.51.100.%d", 20+i%3), "POST", "/news/comment.php", int64(100+i*50), 400, at.Add(time.Duration(i)*time.Second)), "bhv-webshell"); len(h) > 0 {
			t.Fatalf("多个来源访问的页面不告警: %+v", h)
		}
	}
	// 以 GET 为主：不告警
	for i := range 8 {
		m := "GET"
		if i == 0 {
			m = "POST"
		}
		if h := ruleHits(req("198.51.100.30", m, "/report.php", int64(100+i*50), 400, at.Add(time.Duration(i)*time.Second)), "bhv-webshell"); len(h) > 0 {
			t.Fatalf("GET 为主不告警: %+v", h)
		}
	}
}

// 横向移动：被攻击的服务器事后第一次连接其他主机的远程管理端口；观察期之后的扇出；横向登录链。
func TestLateralMovement(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	fw := func(src, dst string, port int, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Action: model.ActionAllow, Time: at})
	}
	fw("10.0.0.10", "10.0.0.5", 445, t0) // 平时：服务器连接域控
	at := t0.Add(25 * time.Hour)
	// Web 日志记录了服务器地址的利用尝试
	b.ObserveHits(&model.Event{Kind: model.KindWeb, SrcIP: "45.33.10.20", DstIP: "10.0.0.10", Host: "www.example.com", Method: "GET", URI: "/x", Status: 200, Time: at},
		[]model.Hit{{RuleID: "cmd-inject", Name: "命令注入", Category: CatCmdExec, Severity: model.SevHigh, Phase: model.PhaseExploit}})
	if h := ruleHits(fw("10.0.0.10", "10.0.0.5", 445, at.Add(time.Minute)), "bhv-lateral-new"); len(h) != 0 {
		t.Fatalf("攻击之前就有的连接不告警: %+v", h)
	}
	h := ruleHits(fw("10.0.0.10", "10.0.0.21", 3389, at.Add(2*time.Minute)), "bhv-lateral-new")
	if len(h) != 1 || h[0].Severity != model.SevMedium || !strings.Contains(h[0].Evidence, "10.0.0.21:3389") {
		t.Fatalf("被攻击后第一次连接 RDP: %+v", h)
	}
	if h := ruleHits(fw("10.0.0.10", "10.0.0.21", 3389, at.Add(3*time.Minute)), "bhv-lateral-new"); len(h) != 0 {
		t.Fatalf("同一连接只告警一次: %+v", h)
	}
	// 已经回连攻击者的服务器：观察期内也判断，高危
	b.MarkAttacked("10.0.0.40", at, "回连攻击者 45.33.10.20", true)
	if h := ruleHits(fw("10.0.0.40", "10.0.0.22", 445, at.Add(time.Minute)), "bhv-lateral-new"); len(h) != 1 || h[0].Severity != model.SevHigh {
		t.Fatalf("已失陷的服务器发起新连接: %+v", h)
	}
	// 失陷判定晚于连接到达（日志读取先后、批次并行）：判定时补记此前 1 小时内的首次管理连接，已出现过的连接与判定很早之前的连接不补记
	fw("10.0.0.41", "10.0.0.5", 445, t0)
	fw("10.0.0.41", "10.0.0.5", 445, at)
	fw("10.0.0.41", "10.0.0.23", 22, at.Add(-3*time.Hour))
	fw("10.0.0.41", "10.0.0.24", 445, at.Add(2*time.Minute))
	fw("10.0.0.41", "10.0.0.25", 3389, at.Add(3*time.Minute))
	late := b.MarkAttacked("10.0.0.41", at.Add(time.Minute), "外连威胁情报地址", true)
	if len(late) != 2 || !late[0].Ev.Replay || late[0].Ev.DstIP != "10.0.0.24" || late[1].Ev.DstPort != 3389 ||
		late[0].Hits[0].RuleID != "bhv-lateral-new" || late[0].Hits[0].Severity != model.SevHigh {
		t.Fatalf("应补记失陷前后的首次管理连接: %+v", late)
	}
	if again := b.MarkAttacked("10.0.0.41", at.Add(2*time.Minute), "回连攻击者", true); len(again) != 0 {
		t.Fatalf("补记过的连接不再重复: %+v", again)
	}
	if h := ruleHits(fw("10.0.0.41", "10.0.0.26", 445, at.Add(4*time.Minute)), "bhv-lateral-new"); len(h) != 1 {
		t.Fatalf("判定之后的新连接照常告警: %+v", h)
	}
	if b.MarkAttacked("10.0.0.42", at, "x", false) != nil {
		t.Fatal("只是遭受过攻击时不补记")
	}
	// 扇出：观察期之后 1 小时内新增连接 5 台主机
	fw("10.0.0.50", "10.0.0.5", 22, t0)
	var fan []model.Hit
	for i := range 6 {
		fan = append(fan, ruleHits(fw("10.0.0.50", fmt.Sprintf("10.0.1.%d", 10+i), 5985, at.Add(time.Duration(i)*time.Minute)), "bhv-lateral-fanout")...)
	}
	if len(fan) != 1 {
		t.Fatalf("新增连接 5 台主机的 WinRM: %+v", fan)
	}
	// 观察期内的扇出不告警（跳板机刚开始被观察）
	for i := range 6 {
		if h := ruleHits(fw("10.0.0.60", fmt.Sprintf("10.0.2.%d", 10+i), 3389, t0.Add(time.Duration(i)*time.Minute)), "bhv-lateral-fanout"); len(h) != 0 {
			t.Fatalf("观察期内不判断扇出: %+v", h)
		}
	}
}

func TestLogonChain(t *testing.T) {
	b := NewBehavior(config.Default().Detect.Thresholds)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	logon := func(srcIP, srcHost, host, user, svc string, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindAuth, SrcIP: srcIP, SrcHost: srcHost, Host: host, User: user, Service: svc,
			Action: model.ActionAllow, EventID: 4624, Time: at})
	}
	// 平时的跳板机路径：运维 PC → JUMP → APP1（观察期内出现）
	logon("10.0.9.5", "OPS-PC", "JUMP.corp.local", "ops", "RDP", t0)
	logon("10.0.9.20", "JUMP", "APP1.corp.local", "ops", "网络登录", t0.Add(10*time.Minute))
	at := t0.Add(26 * time.Hour)
	logon("10.0.9.5", "OPS-PC", "JUMP.corp.local", "ops", "RDP", at)
	if h := ruleHits(logon("10.0.9.20", "JUMP", "APP1.corp.local", "ops", "网络登录", at.Add(5*time.Minute)), "auth-lateral-chain"); len(h) != 0 {
		t.Fatalf("此前出现过的跳板路径不告警: %+v", h)
	}
	// 失陷的办公 PC → FILE1（bob）→ DC1（换成 administrator）
	logon("10.0.5.7", "PC-07", "FILE1", "bob", "网络登录", at.Add(time.Hour))
	h := ruleHits(logon("10.0.5.30", "FILE1", "DC1", "administrator", "RDP", at.Add(time.Hour+20*time.Minute)), "auth-lateral-chain")
	if len(h) != 1 || h[0].Severity != model.SevHigh || !strings.Contains(h[0].Evidence, "pc-07 →(bob) file1 →(administrator) dc1") {
		t.Fatalf("换了账号的横向登录链: %+v", h)
	}
	// 超过 1 小时的两次登录不串成链
	logon("10.0.5.8", "PC-08", "FILE2", "carol", "网络登录", at.Add(3*time.Hour))
	if h := ruleHits(logon("10.0.5.31", "FILE2", "DB1", "carol", "网络登录", at.Add(5*time.Hour)), "auth-lateral-chain"); len(h) != 0 {
		t.Fatalf("间隔过久不算一条链: %+v", h)
	}
}
