package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netsa/internal/model"
	"netsa/internal/risk"
)

const badSeverityRules = `rules:
  - id: t-bad
    pattern: abc
    category: 自定义规则
    severity: hgih
`

const lowSeverityRules = `rules:
  - id: t-low
    pattern: abcxyz
    category: SQL注入
    severity: low
`

// 规则文件的等级必须合法：拼写错误若被当作 info 处理，会让高危攻击静默降级。
func TestRuleSeverityValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, err := LoadRules(write("bad.yaml", badSeverityRules)); err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("拼写错误的等级应加载失败: %v", err)
	}

	// 低于分类底线的声明在加载阶段被纠正：SQL 注入不允许声明为低危
	rules, err := LoadRules(write("low.yaml", lowSeverityRules))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rules {
		if r.ID == "t-low" {
			found = true
			if r.sev != model.SevHigh {
				t.Fatalf("SQL 注入的等级应被抬到高危，实际 %s", r.sev)
			}
			// 对外暴露的等级必须是生效值，否则 /api/rules 与告警口径不一致
			if r.Severity != "high" {
				t.Fatalf("规则对外等级应为 high，实际 %q", r.Severity)
			}
		}
	}
	if !found {
		t.Fatal("自定义规则未加载")
	}

	// 内置规则的等级必须全部合法，且不低于分类底线（防止后续修改引入回归）。
	// 检查的是源码中的声明值而不是加载后的生效值：生效值已被纠正，检查它发现不了声明错误，
	// 而声明错误会让每次启动都打印一批「已提升」日志，看起来像配置故障。
	for _, r := range builtinRules {
		sev, ok := model.TryParseSeverity(r.Severity)
		if !ok {
			t.Errorf("内置规则 %s 的等级 %q 无法识别", r.ID, r.Severity)
			continue
		}
		if !r.TagOnly && sev < risk.Floor(r.Category) {
			t.Errorf("内置规则 %s 声明的等级 %s 低于分类底线 %s", r.ID, sev, risk.Floor(r.Category))
		}
		if r.TagOnly && sev > model.SevLow {
			t.Errorf("仅打标签的内置规则 %s 声明的等级 %s 高于低危", r.ID, sev)
		}
	}
	all, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		if r.ID == "ua-automation" && r.sev != model.SevInfo {
			t.Errorf("仅打标签的脚本 UA 规则应保持信息级，实际 %s", r.sev)
		}
	}
}
