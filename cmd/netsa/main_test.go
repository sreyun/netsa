package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netsa/internal/config"
	"netsa/internal/rulemgr"
)

func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "c.yaml")
	body := "storage:\n  snapshot: " + filepath.ToSlash(filepath.Join(dir, "state", "s.json.gz")) + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCmdEvalBuiltin(t *testing.T) {
	if err := cmdEval(nil); err != nil {
		t.Fatalf("内置样本应全部达标: %v", err)
	}
}

func TestCmdEvalCorpusFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.tsv")
	os.WriteFile(p, []byte("benign\tg\tapp\tGET\t200\t100\tnone\t/a\n"), 0o600)
	if err := cmdEval([]string{"-corpus", p, "-json"}); err != nil {
		t.Fatal(err)
	}
	// 不符合期望时返回错误，便于接入 CI
	os.WriteFile(p, []byte("attack\tg\tapp\tGET\t200\t100\t>=high\t/a\n"), 0o600)
	if err := cmdEval([]string{"-corpus", p, "-v"}); err == nil || !strings.Contains(err.Error(), "不符合") {
		t.Fatalf("应报告不符合: %v", err)
	}
	if err := cmdEval([]string{"-corpus", filepath.Join(t.TempDir(), "none")}); err == nil {
		t.Fatal("文件不存在应报错")
	}
}

func TestBackupRestoreCommands(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, dir)
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0o700)
	os.WriteFile(filepath.Join(state, "s.json.gz"), []byte("snapshot"), 0o600)
	os.WriteFile(filepath.Join(state, "users.json"), []byte("{}"), 0o600)
	out := filepath.Join(dir, "b", "backup.tar.gz")
	if err := cmdBackup([]string{"-c", cfg, "-o", out}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); os.PathSeparator == '/' && mode != 0o600 {
		t.Fatalf("备份有敏感内容，权限应为 0600: %o", mode)
	}
	// 目录不是空的：必须确认覆盖
	if err := cmdRestore([]string{"-c", cfg, "-i", out}); err == nil {
		t.Fatal("非空目录应要求 -force")
	}
	os.WriteFile(filepath.Join(state, "s.json.gz"), []byte("changed"), 0o600)
	if err := cmdRestore([]string{"-c", cfg, "-i", out, "-force"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "s.json.gz")); string(b) != "snapshot" {
		t.Fatalf("应恢复内容: %s", b)
	}
	if err := cmdRestore([]string{"-c", cfg}); err == nil {
		t.Fatal("没有指定备份文件应报错")
	}
}

// 规则包命令：生成密钥、签名，产物能被规则管理校验并安装。
func TestRulePackCommands(t *testing.T) {
	dir := t.TempDir()
	key, rules, pack := filepath.Join(dir, "k"), filepath.Join(dir, "r.yaml"), filepath.Join(dir, "p.json")
	if err := cmdRulePack([]string{"keygen", "-o", key}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRulePack([]string{"keygen", "-o", key}); err == nil {
		t.Fatal("不能覆盖已有的私钥")
	}
	os.WriteFile(rules, []byte("rules:\n  - id: acme\n    name: 内部规则\n    severity: medium\n    pattern: acme-marker\n"), 0o600)
	if err := cmdRulePack([]string{"sign", "-key", key, "-in", rules, "-name", "acme", "-serial", "1", "-o", pack}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(key)
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))
	m, err := rulemgr.New(rulemgr.Options{MinBytes: 1, Keys: []string{pub}})
	if err != nil {
		t.Fatal(err)
	}
	var p rulemgr.Pack
	data, _ := os.ReadFile(pack)
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if st, err := m.InstallPack(p, "root"); err != nil || st.Rules != 1 {
		t.Fatalf("安装: %+v %v", st, err)
	}
	// 有错误的规则文件不能被签发
	os.WriteFile(rules, []byte("rules:\n  - id: bad\n    pattern: \"(\"\n"), 0o600)
	if err := cmdRulePack([]string{"sign", "-key", key, "-in", rules, "-name", "a", "-serial", "2", "-o", pack}); err == nil {
		t.Fatal("错误的规则不应被签发")
	}
	if err := cmdRulePack(nil); err == nil {
		t.Fatal("缺少子命令应报错")
	}
	if err := cmdRulePack([]string{"bogus"}); err == nil {
		t.Fatal("未知子命令应报错")
	}
}

func TestStateDir(t *testing.T) {
	if _, err := stateDir(&config.Config{}); err == nil {
		t.Fatal("没有快照路径时应报错")
	}
	cfg := &config.Config{Storage: config.StorageConfig{Snapshot: "state/s.json.gz"}}
	if d, err := stateDir(cfg); err != nil || filepath.ToSlash(d) != "state" {
		t.Fatalf("%q %v", d, err)
	}
}

// 配置中的外部系统都能装配起来，错误的配置在启动时报错。
func TestBuildWithIntegrations(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Storage.Snapshot = filepath.Join(dir, "s.json.gz")
	cfg.Geo.Online.Enabled = false
	cfg.Block = config.BlockConfig{Enabled: true}
	cfg.Forward = []config.ForwardConfig{{Name: "siem", Address: "127.0.0.1:1", Protocol: "tcp"}}
	cfg.Playbooks = []config.PlaybookConfig{{Name: "p", Note: "步骤"}}
	a, err := build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.block == nil || a.forward == nil || a.playbooks == nil || a.rules == nil {
		t.Fatalf("模块未装配: %+v", a)
	}
	if a.pipe.CurrentEngine() == nil {
		t.Fatal("流水线应有引擎")
	}
	// 坏的规则文件不能被静默忽略
	os.WriteFile(filepath.Join(dir, "rules-managed.json"), []byte("{bad"), 0o600)
	if _, err := build(cfg); err == nil {
		t.Fatal("规则文件损坏应报错")
	}
}
