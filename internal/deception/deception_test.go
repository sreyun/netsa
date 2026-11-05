package deception

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// 诱饵：路径（精确与前缀）、线索、账号、蜜罐地址各自命中；使用同一线索 / 账号的来源互相关联；正常请求不命中；
// 页面维护的诱饵与命中记录保存后重新加载不丢失。
func TestDeception(t *testing.T) {
	file := filepath.Join(t.TempDir(), "deception.json")
	cfg := config.DeceptionConfig{Paths: []string{"/backup_2026.zip", "/admin_old/*"}, Tokens: []string{"x-ops-key-7f3a9c"},
		Accounts: []string{"svc_backup"}, Hosts: []string{"10.0.9.9", "10.0.8.0/24:3389"}}
	m, err := Load(cfg, file)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	web := func(ip, uri string, status int) []model.Hit {
		return m.Match(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "www.example.com", Method: "GET", URI: uri, Status: status, Time: now})
	}
	if h := web("198.51.100.1", "/backup_2026.zip", 200); len(h) != 1 || h[0].RuleID != "decoy-path" || h[0].Category != Category ||
		!strings.Contains(h[0].Evidence, "已取得诱饵内容") {
		t.Fatalf("诱饵路径: %+v", h)
	}
	if h := web("198.51.100.2", "/Admin_Old/login.php?x=1", 404); len(h) != 1 || h[0].RuleID != "decoy-path" {
		t.Fatalf("前缀诱饵（不区分大小写）: %+v", h)
	}
	if h := web("198.51.100.1", "/backup_2026.zip", 200); len(h) != 1 || !h[0].TagOnly {
		t.Fatalf("同一来源反复访问同一诱饵只标记、不重复告警: %+v", h)
	}
	// 读过诱饵文件的人换了出口地址使用其中的接口密钥
	if h := web("203.0.113.5", "/api/ops/export?key=X-OPS-KEY-7F3A9C", 403); len(h) != 1 || h[0].RuleID != "decoy-token" || h[0].Severity != model.SevCritical {
		t.Fatalf("诱饵线索: %+v", h)
	}
	web("192.0.2.77", "/internal?token=x-ops-key-7f3a9c", 404)
	// 诱饵账号：SSH 登录与 Web 登录表单
	auth := &model.Event{Kind: model.KindAuth, SrcIP: "203.0.113.5", DstIP: "10.0.0.20", User: `CORP\svc_backup`, Service: "SSH", Action: model.ActionDeny, Time: now}
	if h := m.Match(auth); len(h) != 1 || h[0].RuleID != "decoy-account" || h[0].Severity != model.SevHigh {
		t.Fatalf("诱饵账号: %+v", h)
	}
	if h := m.Match(&model.Event{Kind: model.KindWeb, SrcIP: "192.0.2.88", Host: "oa.example.com", Method: "POST", URI: "/login", Body: "username=svc_backup&password=1", Time: now}); len(h) != 1 ||
		h[0].RuleID != "decoy-account" {
		t.Fatalf("登录表单中的诱饵账号: %+v", h)
	}
	// 蜜罐：地址任意端口、网段的指定端口；内网主机扫描蜜罐为利用阶段（横向）
	fw := func(src, dst string, port int) []model.Hit {
		return m.Match(&model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Action: model.ActionAllow, Time: now})
	}
	if h := fw("10.0.0.31", "10.0.9.9", 445); len(h) != 1 || h[0].RuleID != "decoy-host" || h[0].Phase != model.PhaseExploit || h[0].Severity != model.SevHigh {
		t.Fatalf("内网主机连接蜜罐: %+v", h)
	}
	if h := fw("45.33.1.2", "10.0.8.7", 3389); len(h) != 1 || h[0].Severity != model.SevMedium {
		t.Fatalf("外部来源连接蜜罐网段: %+v", h)
	}
	// 不命中：同一网段的其他端口、普通路径、线索的一部分、账号作为普通文字
	for _, h := range [][]model.Hit{fw("45.33.1.2", "10.0.8.7", 80), web("198.51.100.9", "/backup_2026.zip.html", 200), web("198.51.100.9", "/index?q=x-ops-key", 200),
		web("198.51.100.9", "/search?q=how+to+svc_backupfoo", 200)} {
		if len(h) != 0 {
			t.Fatalf("不应命中: %+v", h)
		}
	}
	// OpenCanary 的日志本身就是蜜罐命中
	if h := m.Match(&model.Event{Kind: model.KindFirewall, Format: "opencanary", SrcIP: "45.33.9.9", DstIP: "10.0.9.20", DstPort: 22, Service: "SSH 登录", Time: now}); len(h) != 1 ||
		!strings.Contains(h[0].Evidence, "OpenCanary SSH 登录") {
		t.Fatalf("OpenCanary: %+v", h)
	}

	links := m.Links()
	if ips := links["诱饵线索 x-ops-key-7f3a9c"]; len(ips) != 2 || ips[0] != "192.0.2.77" || ips[1] != "203.0.113.5" {
		t.Fatalf("同一线索的来源应关联: %+v", links)
	}
	if ips := links["诱饵账号 svc_backup"]; len(ips) != 2 {
		t.Fatalf("同一账号的来源应关联: %+v", links)
	}
	if _, ok := links["诱饵路径 /backup_2026.zip"]; ok {
		t.Fatal("诱饵路径会被扫描器盲扫到，不作为关联依据")
	}
	if !m.IsAttacker("203.0.113.5") || m.IsAttacker("198.51.100.9") {
		t.Fatal("命中过诱饵的来源")
	}

	// 页面维护：校验、重复、配置中的诱饵不能在页面删除
	if _, err := m.Add(KindToken, "abc", "", "admin"); err == nil {
		t.Fatal("过短的线索应拒绝")
	}
	if _, err := m.Add(KindHost, "10.0.0.0/8", "", "admin"); err == nil {
		t.Fatal("过大的蜜罐网段应拒绝")
	}
	d, err := m.Add(KindPath, "/wp-backup.sql", "放在官网根目录", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(KindPath, "/WP-BACKUP.SQL", "", "admin"); err == nil {
		t.Fatal("重复的诱饵应拒绝")
	}
	if h := web("198.51.100.3", "/wp-backup.sql", 200); len(h) != 1 || !strings.Contains(h[0].Evidence, "放在官网根目录") {
		t.Fatalf("页面登记的诱饵: %+v", h)
	}
	st := m.List()
	var cfgID string
	for _, x := range st.Decoys {
		if x.Config {
			cfgID = x.ID
		}
	}
	if _, err := m.Delete(cfgID); err == nil {
		t.Fatal("配置文件中的诱饵不能在页面删除")
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	m2, err := Load(cfg, file)
	if err != nil {
		t.Fatal(err)
	}
	st2 := m2.List()
	if len(st2.Decoys) != len(st.Decoys) || st2.Total != st.Total || len(st2.Attackers) != len(st.Attackers) || len(m2.Links()) != 2 {
		t.Fatalf("重新加载: %d/%d 诱饵 %d/%d 次 %d/%d 来源", len(st2.Decoys), len(st.Decoys), st2.Total, st.Total, len(st2.Attackers), len(st.Attackers))
	}
	if _, err := m2.Delete(d.ID); err != nil {
		t.Fatal(err)
	}
}
