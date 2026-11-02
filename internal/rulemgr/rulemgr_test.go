package rulemgr

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"netsa/internal/detect"
	"netsa/internal/model"
)

func newManager(t *testing.T, keys ...string) (*Manager, *[]*detect.Engine) {
	t.Helper()
	var swaps []*detect.Engine
	m, err := New(Options{Path: filepath.Join(t.TempDir(), "rules.json"), MinBytes: 1, Keys: keys, OnChange: func(e *detect.Engine) { swaps = append(swaps, e) }})
	if err != nil {
		t.Fatal(err)
	}
	return m, &swaps
}

func hits(e *detect.Engine, uri string) map[string]bool {
	out := map[string]bool{}
	for _, h := range e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.1", Method: "GET", URI: uri, Status: 404, UA: "Mozilla/5.0"}) {
		out[h.RuleID] = true
	}
	return out
}

// 规则变更立刻作用于检测；错误的规则不影响正在运行的引擎。
func TestUpsertDeleteHotReload(t *testing.T) {
	m, swaps := newManager(t)
	if hits(m.Engine(), "/acme-backdoor")["acme"] {
		t.Fatal("添加前不应命中")
	}
	if _, err := m.Upsert(detect.Rule{ID: "acme", Name: "内部后门", Category: "WebShell后门", Severity: "high", Pattern: "acme-backdoor"}, "", "root"); err != nil {
		t.Fatal(err)
	}
	if len(*swaps) != 1 || !hits((*swaps)[0], "/ACME-BACKDOOR")["acme"] {
		t.Fatal("应热更新且大小写不敏感")
	}
	// 留空的字段保存为实际生效的默认值
	if it, err := m.Upsert(detect.Rule{ID: "minimal", Pattern: "minimal-marker"}, "", "root"); err != nil || it.Name != "minimal" || it.Category != "自定义规则" || it.Target != "uri" {
		t.Fatalf("默认值: %+v %v", it, err)
	}
	if err := m.Delete("minimal"); err != nil {
		t.Fatal(err)
	}
	*swaps = (*swaps)[:1]
	for name, r := range map[string]detect.Rule{
		"bad-regex":    {ID: "x", Pattern: "("},
		"bad-severity": {ID: "x", Pattern: "a", Severity: "hgih"},
		"bad-target":   {ID: "x", Pattern: "a", Target: "body"},
		"bad-id":       {ID: "a b", Pattern: "a"},
		"no-pattern":   {ID: "x"},
		"too-long":     {ID: "x", Pattern: strings.Repeat("a", maxPattern+1)},
		"builtin-id":   {ID: "sqli-union", Pattern: "a"},
	} {
		if _, err := m.Upsert(r, "", "root"); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
	if len(*swaps) != 1 {
		t.Fatalf("错误的规则不应切换引擎: %d", len(*swaps))
	}
	// 重启后保持
	m2, err := New(Options{Path: m.opt.Path, MinBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !hits(m2.Engine(), "/acme-backdoor")["acme"] {
		t.Fatal("重启后应保留")
	}
	if err := m.Delete("acme"); err != nil {
		t.Fatal(err)
	}
	if hits((*swaps)[1], "/acme-backdoor")["acme"] {
		t.Fatal("删除后不应命中")
	}
	if err := m.Delete("acme"); err == nil {
		t.Fatal("不存在的规则应报错")
	}
}

func TestRuleTest(t *testing.T) {
	r, err := Test(detect.Rule{Pattern: `union\s+select`}, "/a?x=1%20UNION%20SELECT%202")
	if err != nil || !r.Matched || r.Evidence == "" {
		t.Fatalf("应按归一化后的文本匹配: %+v %v", r, err)
	}
	if r, err := Test(detect.Rule{Pattern: "nothing"}, "/a"); err != nil || r.Matched {
		t.Fatalf("不应命中: %+v %v", r, err)
	}
	if _, err := Test(detect.Rule{Pattern: "("}, "/a"); err == nil {
		t.Fatal("错误的表达式应报错")
	}
	if r, err := Test(detect.Rule{Pattern: "sqlmap", Target: "ua"}, "sqlmap/1.8"); err != nil || !r.Matched {
		t.Fatalf("UA: %+v %v", r, err)
	}
}

func signedPack(t *testing.T, priv ed25519.PrivateKey, name string, serial int64, rules ...detect.Rule) Pack {
	t.Helper()
	p := Pack{Name: name, Serial: serial, Rules: rules}
	if err := Sign(&p, priv); err != nil {
		t.Fatal(err)
	}
	return p
}

// 规则包：只信任配置的公钥，内容不能被改动，不能回滚。
func TestRulePack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	m, swaps := newManager(t, base64.StdEncoding.EncodeToString(pub))
	rule := detect.Rule{ID: "pack-1", Name: "规则包规则", Severity: "medium", Pattern: "pack-marker"}
	if _, err := m.InstallPack(signedPack(t, other, "p", 1, rule), "root"); err == nil {
		t.Fatal("不信任的密钥应拒绝")
	}
	tampered := signedPack(t, priv, "p", 1, rule)
	tampered.Rules[0].Pattern = "evil"
	if _, err := m.InstallPack(tampered, "root"); err == nil || !strings.Contains(err.Error(), "签名") {
		t.Fatalf("被改动的规则包应拒绝: %v", err)
	}
	unsigned := Pack{Name: "p", Serial: 1, Rules: []detect.Rule{rule}, KeyID: KeyID(pub)}
	if _, err := m.InstallPack(unsigned, "root"); err == nil {
		t.Fatal("没有签名应拒绝")
	}
	if _, err := m.InstallPack(signedPack(t, priv, "p", 2, rule), "root"); err != nil {
		t.Fatal(err)
	}
	if !hits(m.Engine(), "/pack-marker")["pack-1"] {
		t.Fatal("规则包应生效")
	}
	if _, err := m.InstallPack(signedPack(t, priv, "p", 2, rule), "root"); err == nil {
		t.Fatal("相同序号应拒绝")
	}
	if _, err := m.InstallPack(signedPack(t, priv, "p", 1, rule), "root"); err == nil {
		t.Fatal("回滚应拒绝")
	}
	// 规则包里的规则不能单独修改或删除
	if _, err := m.Upsert(detect.Rule{ID: "pack-1", Pattern: "x"}, "", "root"); err == nil {
		t.Fatal("不能修改规则包里的规则")
	}
	if err := m.Delete("pack-1"); err == nil {
		t.Fatal("不能删除规则包里的规则")
	}
	// 升级替换旧规则；一条无效时整包不生效
	before := len(*swaps)
	if _, err := m.InstallPack(signedPack(t, priv, "p", 3, detect.Rule{ID: "pack-2", Pattern: "x"}, detect.Rule{ID: "pack-3", Pattern: "("}), "root"); err == nil {
		t.Fatal("有无效规则应整包拒绝")
	}
	if len(*swaps) != before || !hits(m.Engine(), "/pack-marker")["pack-1"] {
		t.Fatal("失败时应保持原样")
	}
	if _, err := m.InstallPack(signedPack(t, priv, "p", 4, detect.Rule{ID: "pack-2", Pattern: "new-marker"}), "root"); err != nil {
		t.Fatal(err)
	}
	e := m.Engine()
	if hits(e, "/pack-marker")["pack-1"] || !hits(e, "/new-marker")["pack-2"] {
		t.Fatal("升级应替换旧规则")
	}
	// 与其他来源的规则冲突
	m.Upsert(detect.Rule{ID: "mine", Pattern: "x"}, "", "root")
	if _, err := m.InstallPack(signedPack(t, priv, "q", 1, detect.Rule{ID: "mine", Pattern: "y"}), "root"); err == nil {
		t.Fatal("ID 冲突应拒绝")
	}
	if err := m.UninstallPack("p"); err != nil {
		t.Fatal(err)
	}
	if hits(m.Engine(), "/new-marker")["pack-2"] {
		t.Fatal("卸载后不应命中")
	}
	if err := m.UninstallPack("p"); err == nil {
		t.Fatal("重复卸载应报错")
	}
	if _, err := New(Options{Keys: []string{"bad"}}); err == nil {
		t.Fatal("无效公钥应报错")
	}
}

func TestConvertSigma(t *testing.T) {
	data := []byte(`
title: Exploit Attempt On Acme CVE-2026-1
id: 11112222-3333-4444-5555-666677778888
status: experimental
level: high
tags: [attack.initial_access, cve.2026-1]
logsource: {category: webserver}
detection:
  selection:
    cs-uri-query|contains:
      - '/acme/exec?'
      - 'a.b=1'
    cs-method: POST
    sc-status: 200
  condition: selection
---
title: Scanner UA
level: low
logsource: {category: webserver}
detection:
  selection:
    c-useragent|startswith: 'EvilScan'
  condition: selection
---
title: Multiple Fields
logsource: {category: webserver}
detection:
  selection:
    cs-uri-query|contains: a
    c-useragent|contains: b
  condition: selection
---
title: With Exclusion
logsource: {category: webserver}
detection:
  selection: {cs-uri-query|contains: a}
  filter: {cs-uri-query|contains: b}
  condition: selection and not filter
---
title: Not Web
logsource: {product: windows}
detection:
  selection: {EventID: 4625}
  condition: selection
---
title: All Modifier
logsource: {category: webserver}
detection:
  selection: {cs-uri-query|contains|all: [a, b]}
  condition: selection
---
title: Lookaround
logsource: {category: webserver}
detection:
  selection: {cs-uri-query|re: 'a(?=b)'}
  condition: selection
---
title: Keywords SQL Injection
logsource: {category: proxy}
detection:
  keywords: ['xp_cmdshell', 'sp_oacreate']
  condition: keywords
---
title: One Of
level: medium
logsource: {category: webserver}
detection:
  selection_a: {cs-uri-stem|endswith: '.evil'}
  selection_b: {cs-uri-stem|endswith: '.bad'}
  condition: 1 of selection_*
`)
	res, err := ConvertSigma(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 4 || len(res.Skipped) != 5 {
		t.Fatalf("应转换 4 条、跳过 5 条: %+v", res)
	}
	r := res.Rules[0]
	if r.ID != "sigma-111122223333" || r.Severity != "high" || r.Target != "uri" || r.Category != "已知漏洞利用" || len(r.Methods) != 1 || r.Methods[0] != "POST" || r.Pattern != `/acme/exec\?|a\.b=1` {
		t.Fatalf("转换: %+v", r)
	}
	if u := res.Rules[1]; u.Target != "ua" || u.Pattern != "^evilscan" || u.Severity != "low" {
		t.Fatalf("UA: %+v", u)
	}
	if k := res.Rules[2]; k.Category != "SQL注入" || k.Pattern != "xp_cmdshell|sp_oacreate" {
		t.Fatalf("关键字: %+v", k)
	}
	if o := res.Rules[3]; o.Target != "path" || !strings.Contains(o.Pattern, `\.evil$`) || !strings.Contains(o.Pattern, `\.bad$`) {
		t.Fatalf("1 of: %+v", o)
	}
	// 转换结果能被引擎接受并命中
	m, _ := newManager(t)
	if _, err := m.ImportRules(res.Rules, "sigma", "root"); err != nil {
		t.Fatal(err)
	}
	if !hits(m.Engine(), "/x?xp_cmdshell")[res.Rules[2].ID] {
		t.Fatal("导入后应生效")
	}
	if _, err := ConvertSigma([]byte("{{{")); err == nil {
		t.Fatal("无效 YAML 应报错")
	}
	if _, err := ConvertSigma(nil); err == nil {
		t.Fatal("空内容应报错")
	}
}
