package rulemgr

import (
	"os"
	"path/filepath"
	"testing"

	"netsa/internal/detect"
)

// 影子运行的统计在规则变更（引擎重建）之间保留；匹配条件改变时清零；转为正式或删除后不再保留；重启后影子状态不变。
func TestShadowAcrossRebuild(t *testing.T) {
	m, _ := newManager(t)
	if _, err := m.Upsert(detect.Rule{ID: "acme", Name: "内部后门", Category: "WebShell后门", Severity: "high", Pattern: "acme-backdoor", Shadow: true}, "", "root"); err != nil {
		t.Fatal(err)
	}
	if hits(m.Engine(), "/acme-backdoor")["acme"] {
		t.Fatal("影子规则不应产生命中")
	}
	if st := m.Shadow()["acme"]; st.Hits != 1 {
		t.Fatalf("应记录影子命中: %+v", st)
	}
	// 其他规则变更：引擎重建，影子统计保留
	if _, err := m.Upsert(detect.Rule{ID: "other", Pattern: "other-marker"}, "", "root"); err != nil {
		t.Fatal(err)
	}
	hits(m.Engine(), "/acme-backdoor")
	if st := m.Shadow()["acme"]; st.Hits != 2 {
		t.Fatalf("引擎重建后统计应保留: %+v", st)
	}
	// 只改名称：统计保留；改匹配条件：清零
	if _, err := m.Upsert(detect.Rule{ID: "acme", Name: "改名", Category: "WebShell后门", Severity: "high", Pattern: "acme-backdoor", Shadow: true}, "", "root"); err != nil {
		t.Fatal(err)
	}
	if m.Shadow()["acme"].Hits != 2 {
		t.Fatal("只改名称不应清零")
	}
	if _, err := m.Upsert(detect.Rule{ID: "acme", Name: "改名", Category: "WebShell后门", Severity: "high", Pattern: "acme-shell", Shadow: true}, "", "root"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Shadow()["acme"]; ok {
		t.Fatal("匹配条件改变后应清零")
	}
	// 重启后仍是影子运行
	m2, err := New(Options{Path: m.opt.Path, MinBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if hits(m2.Engine(), "/acme-shell")["acme"] || m2.Shadow()["acme"].Hits != 1 {
		t.Fatal("重启后应保持影子运行")
	}
	// 转为正式：产生命中，影子统计删除
	if _, err := m.Upsert(detect.Rule{ID: "acme", Name: "改名", Category: "WebShell后门", Severity: "high", Pattern: "acme-shell"}, "", "root"); err != nil {
		t.Fatal(err)
	}
	if !hits(m.Engine(), "/acme-shell")["acme"] {
		t.Fatal("转为正式后应产生命中")
	}
	if len(m.Shadow()) != 0 {
		t.Fatalf("转为正式后不再保留影子统计: %v", m.Shadow())
	}
	// Sigma 导入的规则可以整体先影子运行
	res, err := ConvertSigma([]byte(`title: Test Webshell
logsource:
  category: webserver
detection:
  sel:
    cs-uri-query|contains: 'cmd=whoami'
  condition: sel
level: high
`))
	if err != nil || len(res.Rules) != 1 {
		t.Fatalf("转换: %v %+v", err, res)
	}
	res.Rules[0].Shadow = true
	if _, err := m.ImportRules(res.Rules, "sigma", "root"); err != nil {
		t.Fatal(err)
	}
	if hits(m.Engine(), "/x.php?cmd=whoami")[res.Rules[0].ID] || m.Shadow()[res.Rules[0].ID].Hits != 1 {
		t.Fatal("导入的影子规则只记录命中")
	}
}

// 影子统计跟随实际生效的规则：Sigma 重新导入、规则包升级等改了匹配条件同样清零，条件不变则保留；
// rules_file 中的影子规则不会因为托管规则变更而丢失统计。
func TestShadowSyncOnCommit(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rulesFile, []byte("rules:\n  - id: file-shadow\n    name: 文件中的影子规则\n    severity: high\n    pattern: file-shadow-marker\n    shadow: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{Path: filepath.Join(dir, "rules.json"), RulesFile: rulesFile, MinBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	hits(m.Engine(), "/file-shadow-marker")
	if m.Shadow()["file-shadow"].Hits != 1 {
		t.Fatalf("rules_file 中的影子规则应记录命中: %v", m.Shadow())
	}
	sigma := []detect.Rule{{ID: "sig-1", Name: "Sigma", Pattern: "sigma-old", Shadow: true}}
	if _, err := m.ImportRules(sigma, "sigma", "root"); err != nil {
		t.Fatal(err)
	}
	hits(m.Engine(), "/sigma-old")
	if m.Shadow()["sig-1"].Hits != 1 || m.Shadow()["file-shadow"].Hits != 1 {
		t.Fatalf("托管规则变更不应清掉 rules_file 影子规则的统计: %v", m.Shadow())
	}
	// 重新导入、条件不变：保留
	if _, err := m.ImportRules(sigma, "sigma", "root"); err != nil {
		t.Fatal(err)
	}
	if m.Shadow()["sig-1"].Hits != 1 {
		t.Fatal("条件不变的重新导入不应清零")
	}
	// 重新导入、条件改变：清零
	sigma[0].Pattern = "sigma-new"
	if _, err := m.ImportRules(sigma, "sigma", "root"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Shadow()["sig-1"]; ok {
		t.Fatal("重新导入改变了匹配条件，此前的影子统计应清零")
	}
}
