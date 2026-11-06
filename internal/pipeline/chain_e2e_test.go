package pipeline

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/demo"
	"netsa/internal/detect"
	"netsa/internal/ingest"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 资产攻击链路的验收：演示日志经解析、检测、行为分析、联动与入库全流程后，官网（www.example.com）与其服务器
// 10.0.0.10 合并为同一资产，完整展示“扫描 → 漏洞利用 → 成功 → 回连 → 横向 → 窃取”。
// 各日志文件并发读取、先后不定（与生产环境一致），结果不应依赖读取顺序。
func TestDemoAssetChain(t *testing.T) {
	dir := t.TempDir()
	if err := demo.Generate(dir, 3, 2, 1); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	eng, err := detect.NewEngine("", cfg.Detect.SuccessMinBytes)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(200000, 20000, 5, 24*time.Hour)
	intel := netip.MustParsePrefix("203.0.113.0/24") // configs/demo-intel.txt
	st.IntelMatch = func(ip string) []string {
		if a, err := netip.ParseAddr(ip); err == nil && intel.Contains(a) {
			return []string{"演示威胁情报"}
		}
		return nil
	}
	p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(cfg.Detect.Thresholds), Store: st, RealIP: NewRealIP(cfg.RealIP)}
	m := ingest.NewManager(4096)
	ctx := context.Background()
	done := p.Run(ctx, m.Out, 0)
	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	for _, f := range files {
		typ, host := "auto", ""
		switch filepath.Base(f) {
		case "access.log":
			host = "www.example.com" // configs/demo.yaml 中数据源的 host
		case "auth.log":
			typ = "auth"
		case "dns.log":
			typ = "dns"
		case "process.log":
			typ = "edr"
		}
		if err := m.ReadFile(ctx, f, typ, "", host); err != nil {
			t.Fatal(err)
		}
	}
	go func() { m.Wait(); m.Close() }()
	<-done

	c := st.AssetChain("www.example.com")
	if c == nil {
		t.Fatal("官网没有攻击链路")
	}
	if !slices.Contains(c.Members, "10.0.0.10") {
		t.Fatalf("官网与回连载荷地址的服务器应合并: %v（合并依据 %+v）", c.Members, c.Links)
	}
	for _, s := range []string{"recon", "exploit", "breach", "control", "lateral", "collect"} {
		if !slices.Contains(c.Reached, s) {
			t.Fatalf("缺少 %s 阶段: %v", s, c.Reached)
		}
	}
	if c.Confidence != "high" {
		t.Fatalf("应研判为高置信失陷: %s %s", c.Confidence, c.Verdict)
	}
	var breach, control *store.ChainStepView
	for i := range c.Path {
		switch c.Path[i].Stage {
		case "breach":
			breach = &c.Path[i]
		case "control":
			control = &c.Path[i]
		}
	}
	if breach == nil || !strings.Contains(breach.Target, "/api/ping") || breach.Category != "命令/代码执行" {
		t.Fatalf("突破应为命令注入成功: %+v", breach)
	}
	if control == nil || control.Src != "10.0.0.10" || !control.Self {
		t.Fatalf("控制应为服务器自身外连: %+v", control)
	}
	// 关键路径中突破的攻击者也是侦察、利用的那一个
	for _, v := range c.Path {
		if (v.Stage == "recon" || v.Stage == "exploit") && v.Src != breach.Src {
			t.Fatalf("%s 阶段应选突破成功的攻击者 %s: %+v", v.Stage, breach.Src, v)
		}
	}
	// P2：服务器外传数据（数据外传）、失陷后第一次连接其他主机的 SMB（横向移动）
	var exfil, lateral bool
	for _, v := range c.Steps {
		switch {
		case v.Category == "数据外传" && v.Src == "10.0.0.10" && v.Stage == "collect":
			exfil = true
		case v.Category == "横向移动" && v.Src == "10.0.0.10" && v.Stage == "lateral":
			lateral = true
		}
	}
	if !exfil || !lateral {
		for _, v := range c.Steps {
			t.Logf("%s %s %s → %s %s", v.Stage, v.Category, v.Src, v.Target, v.Evidence)
		}
		t.Fatalf("链路中应有数据外传（%v）与横向移动（%v）", exfil, lateral)
	}
	// P3：服务器进程日志中 PHP-FPM 执行注入的命令（突破）、反弹 Shell（控制）、写入 cron（植入）；正常的备份、日志轮转不进入链路
	got := map[string]string{}
	for _, v := range c.Steps {
		if v.Src == "10.0.0.10" {
			got[v.Category] = v.Stage
		}
	}
	if got["主机命令执行"] != "breach" || got["反弹Shell"] != "control" || got["持久化"] != "persist" {
		t.Fatalf("链路中应有主机侧的证据: %v", got)
	}
	for _, a := range st.Alerts(store.AlertQuery{Limit: 5000}) {
		if a.Kind == model.KindProcess && (strings.Contains(a.Evidence, "rsync") || strings.Contains(a.Evidence, "logrotate") || strings.Contains(a.Evidence, "healthcheck")) {
			t.Fatalf("正常的进程活动不应告警: %+v", a)
		}
	}
	// 被横向扫描的数据库主机单独成链，来源为失陷的服务器
	db := st.AssetChain("10.0.0.21")
	if db == nil {
		t.Fatal("被横向扫描的主机没有链路")
	}
	internal := false
	for _, v := range db.Steps {
		if v.Src == "10.0.0.10" && v.Internal {
			internal = true
		}
	}
	if !internal {
		t.Fatalf("10.0.0.21 的链路中应有来自 10.0.0.10 的步骤: %+v", db.Steps)
	}
	// 失陷研判中的官网 / 服务器能展开到这条链路
	opened := false
	for _, x := range st.CompromisedAssets() {
		if ch := st.AssetChain(x.Chain); ch != nil && ch.Key == c.Key {
			opened = true
		}
	}
	if !opened {
		t.Fatal("疑似失陷资产不能展开到合并后的链路")
	}
	l := st.ChainList(store.ChainQuery{Stage: "exploit"})
	if l.Total == 0 || l.Chains[0].Confidence != "high" {
		t.Fatalf("列表首位应为高置信失陷资产: %+v", l.Chains)
	}
	t.Logf("官网链路：%s；共 %d 个资产越过侦察，记录 %d 个资产标识", c.Verdict, l.Total, l.Tracked)
}
