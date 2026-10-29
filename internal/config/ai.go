package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// AIConfig 是可选的外部大模型（默认关闭）。使用 OpenAI 兼容的 /chat/completions 接口，
// 适配 DeepSeek、通义千问、智谱、Kimi 等云端模型，以及内网部署的 vLLM / Ollama / Xinference。
//
// 合规边界：
//   - 密钥只从环境变量读取，不写入配置文件；
//   - 发送前默认脱敏（内网地址、口令 / 令牌类参数、手机号、证件号、邮箱）；公网地址必须使用 HTTPS；
//   - 每次调用记入审计链，有每小时调用上限；
//   - 模型结论只作研判参考，不参与自学习、不自动处置。
type AIConfig struct {
	Enabled bool   `yaml:"enabled"`
	BaseURL string `yaml:"base_url"` // 例如 https://api.deepseek.com/v1、http://10.0.0.20:8000/v1
	Model   string `yaml:"model"`
	// APIKeyEnv 是保存密钥的环境变量名（默认 NETSA_AI_API_KEY）；内网模型不需要密钥时可不设置该变量
	APIKeyEnv  string        `yaml:"api_key_env"`
	Timeout    time.Duration `yaml:"timeout"`      // 单次调用超时（默认 90 秒）
	MaxPerHour int           `yaml:"max_per_hour"` // 每小时最多调用次数（默认 30）
	// Desensitize 发送前脱敏（默认开启）。关闭只适用于完全在内网部署的模型。
	Desensitize *bool `yaml:"desensitize"`
	// AutoTriage 新出现的高危及以上事件自动研判（结果写入事件处置记录，默认关闭）
	AutoTriage bool `yaml:"auto_triage"`
}

// DesensitizeOn 返回是否发送前脱敏（未配置时默认开启）。
func (c AIConfig) DesensitizeOn() bool { return onByDefault(c.Desensitize) }

// KeyEnv 返回保存密钥的环境变量名。
func (c AIConfig) KeyEnv() string {
	if strings.TrimSpace(c.APIKeyEnv) == "" {
		return "NETSA_AI_API_KEY"
	}
	return strings.TrimSpace(c.APIKeyEnv)
}

func (c AIConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Model) == "" {
		return fmt.Errorf("ai.model 不能为空")
	}
	u, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("ai.base_url 应为 http(s)://主机[:端口]/路径，例如 https://api.deepseek.com/v1")
	}
	if u.User != nil {
		return fmt.Errorf("ai.base_url 不能包含账号口令，请通过 ai.api_key_env 指定的环境变量提供密钥")
	}
	if u.Scheme == "http" && !privateHost(u.Hostname()) {
		return fmt.Errorf("ai.base_url 指向公网地址时必须使用 https（日志与告警内容不能明文传输）")
	}
	if c.Timeout < 0 || c.Timeout > 10*time.Minute {
		return fmt.Errorf("ai.timeout 应在 0 ~ 10 分钟之间")
	}
	if c.MaxPerHour < 0 || c.MaxPerHour > 10000 {
		return fmt.Errorf("ai.max_per_hour 应在 0 ~ 10000 之间")
	}
	return nil
}

// privateHost 判断模型服务是否位于内网（回环、私有地址、单标签主机名或 .local / .internal / .lan 域名）。
func privateHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	h = strings.ToLower(h)
	return h == "localhost" || !strings.Contains(h, ".") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".lan")
}
