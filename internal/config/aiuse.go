package config

import "fmt"

// AIUseConfig 是 AI 使用统计：按已接入的 DNS、TLS 握手（SNI）、Web 与会话日志，统计内网终端使用了哪些 AI 服务、
// 用了多少、上传了多少数据。只做统计与展示，不产生告警，也不进入攻击检测与评分。默认开启。
//
// 内置目录收录了常见的境内外 AI 服务（对话、编程、模型接口、图像、AI 搜索等）；services 可新增服务
// （如 API 中转站、单位自建的模型网关），或按 id 覆盖内置服务的字段。页面“风险管理 → AI 使用 → 服务目录”
// 中设定的策略与登记的服务保存在状态目录，与这里合并生效（页面设定的策略优先）。
type AIUseConfig struct {
	// Enabled 为 false 时关闭统计（默认开启）
	Enabled *bool `yaml:"enabled"`
	// Services 新增服务，或按 id 覆盖内置服务（只替换填写了的字段）
	Services []AIServiceConfig `yaml:"services"`
	// Policies 是服务的使用策略（服务 id → allow / restrict / deny），按单位的 AI 使用管理制度填写；
	// 第一阶段只用于统计（如“使用了禁止类服务的终端数”），不拦截、不告警
	Policies map[string]string `yaml:"policies"`
	// Disable 停用的内置服务 id
	Disable []string `yaml:"disable"`
	// RetentionDays 按天统计的保留天数（默认 62，覆盖“上月”月报；最多 400）
	RetentionDays int `yaml:"retention_days"`
	// MaxRecords 按“天 × 终端 × 服务”统计的记录数上限（默认 300000，约占 40 MB 内存），超过时先淘汰最早一天
	MaxRecords int `yaml:"max_records"`
	// File 状态文件，默认与 storage.snapshot 同目录的 aiuse.json.gz
	File string `yaml:"file"`
}

// AIServiceConfig 是配置文件中的一个 AI 服务。
type AIServiceConfig struct {
	ID       string   `yaml:"id"`       // 与内置服务相同时覆盖内置服务；新增时可省略
	Name     string   `yaml:"name"`     // 名称
	Vendor   string   `yaml:"vendor"`   // 厂商
	Category string   `yaml:"category"` // chat / coding / api / image / audio / search / writing / agent / model / other
	Region   string   `yaml:"region"`   // domestic（境内）/ overseas（境外）
	Policy   string   `yaml:"policy"`   // allow / restrict / deny，留空为未设定
	Domains  []string `yaml:"domains"`  // 按标签匹配（example.com 含其子域名）；含一个 * 时按前后缀匹配（ark.*.volces.com）
	Note     string   `yaml:"note"`
}

// On 返回是否开启 AI 使用统计（默认开启）。
func (c AIUseConfig) On() bool { return onByDefault(c.Enabled) }

func (c *AIUseConfig) validate() error {
	if c.RetentionDays < 0 || c.RetentionDays > 400 {
		return fmt.Errorf("ai_usage.retention_days 应在 1 ~ 400 之间: %d", c.RetentionDays)
	}
	if c.MaxRecords < 0 || c.MaxRecords > 5000000 {
		return fmt.Errorf("ai_usage.max_records 应在 1 ~ 5000000 之间: %d", c.MaxRecords)
	}
	return nil
}
