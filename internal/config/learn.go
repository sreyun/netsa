package config

import "fmt"

// LearnConfig 是自学习参数，均默认开启。自学习只从分析员的研判结论与平台自身的审计记录中学习，
// 自动调整每次最多一级：按误报结论下调（最多低于攻击分类底线一级），确认攻击源复现时上调（最多到高危）；
// 会隐藏告警的误报抑制只生成建议，由人确认采纳。
type LearnConfig struct {
	// Calibrate 按研判准确率自动校准规则等级：研判样本达到 min_verdicts 且准确率不高于 max_precision 的规则下调一级。
	Calibrate    *bool   `yaml:"calibrate"`
	MinVerdicts  int     `yaml:"min_verdicts"`  // 默认 5
	MaxPrecision float64 `yaml:"max_precision"` // 默认 0.2
	// Sentinel 学习平台账号的常用登录网段与时段，异常登录、登录失败暴增、批量导出与高危配置变更时告警。
	Sentinel *bool `yaml:"sentinel"`
	// Compliance 每小时自动执行等保合规自检，测评项结果下降时告警；每天自动校验审计链完整性。
	Compliance *bool `yaml:"compliance"`
	// Escalate 被分析员确认为攻击的来源在 escalate_days 天内再次出现时，其低危 / 中危攻击命中升级一级（最多到高危）。
	Escalate     *bool `yaml:"escalate"`
	EscalateDays int   `yaml:"escalate_days"` // 默认 30
	// WindowDays 学习窗口（天）：更早的人工结论不再参与校准与建议。默认 180，负数不限
	WindowDays int `yaml:"window_days"`
}

// EscalateOn 返回是否升级已确认攻击来源的复现命中。
func (c LearnConfig) EscalateOn() bool { return onByDefault(c.Escalate) }

func onByDefault(b *bool) bool { return b == nil || *b }

// CalibrateOn 返回是否自动校准规则等级。
func (c LearnConfig) CalibrateOn() bool { return onByDefault(c.Calibrate) }

// SentinelOn 返回是否学习平台账号的行为基线。
func (c LearnConfig) SentinelOn() bool { return onByDefault(c.Sentinel) }

// ComplianceOn 返回是否持续合规自检。
func (c LearnConfig) ComplianceOn() bool { return onByDefault(c.Compliance) }

func (c LearnConfig) validate() error {
	if c.MinVerdicts < 0 || c.MinVerdicts > 1000 {
		return fmt.Errorf("learn.min_verdicts 应在 0 ~ 1000 之间")
	}
	if c.MaxPrecision < 0 || c.MaxPrecision >= 1 {
		return fmt.Errorf("learn.max_precision 应在 0 ~ 1 之间（不含 1）")
	}
	if c.EscalateDays < 0 || c.EscalateDays > 365 {
		return fmt.Errorf("learn.escalate_days 应在 0 ~ 365 之间")
	}
	if c.WindowDays > 3650 {
		return fmt.Errorf("learn.window_days 不能超过 3650")
	}
	return nil
}
