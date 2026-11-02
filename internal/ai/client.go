package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netsa/internal/config"
)

// Settings 是外部模型的运行配置。可在 Web 管理页面（自学习 → 外部模型）修改，立即生效，
// 保存在状态目录的 ai.json（含密钥，文件权限 0600）；界面从未保存过时取配置文件 ai 段与环境变量中的密钥。
type Settings struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"`
	Model   string `json:"model"`
	// APIKey 是界面填写的密钥，只保存在服务端，任何接口都不返回
	APIKey string `json:"api_key,omitempty"`
	// KeyFromEnv 表示界面未填写密钥时使用环境变量中的密钥（兼容原有部署方式）；
	// 在界面填写或清除密钥后不再使用环境变量
	KeyFromEnv  bool      `json:"key_from_env"`
	MaxPerHour  int       `json:"max_per_hour"`
	Desensitize bool      `json:"desensitize"`
	AutoTriage  bool      `json:"auto_triage"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	Updated     time.Time `json:"updated,omitzero"`
}

func normalize(s Settings) Settings {
	s.BaseURL = strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
	s.Model = strings.TrimSpace(s.Model)
	s.APIKey = strings.TrimSpace(s.APIKey)
	if s.MaxPerHour <= 0 {
		s.MaxPerHour = 30
	}
	return s
}

// check 校验配置。未启用时也校验已填写的地址，避免保存一个之后无法启用的配置。
func (s Settings) check() error {
	if s.Enabled || s.BaseURL != "" {
		if err := config.CheckAIEndpoint(s.BaseURL); err != nil {
			return err
		}
	}
	if s.Enabled && s.Model == "" {
		return errors.New("请填写模型名称，例如 deepseek-chat、qwen-max")
	}
	if len(s.Model) > 128 || strings.ContainsAny(s.Model, "\r\n\t\"") {
		return errors.New("模型名称无效（最多 128 个字符，不能包含换行与引号）")
	}
	if len(s.APIKey) > 512 {
		return errors.New("模型密钥过长（最多 512 个字符）")
	}
	for _, r := range s.APIKey {
		if r <= ' ' || r >= 0x7f {
			return errors.New("模型密钥只能包含可见的 ASCII 字符（不能有空格、换行或中文）")
		}
	}
	if s.MaxPerHour < 1 || s.MaxPerHour > 10000 {
		return errors.New("每小时调用上限应在 1 ~ 10000 之间")
	}
	return nil
}

// Client 是模型客户端，可并发使用；配置可在运行中替换（进行中的调用使用替换前的配置）。
type Client struct {
	mu      sync.Mutex
	set     Settings
	envKey  string // 环境变量中的密钥
	keyEnv  string // 环境变量名
	path    string // 界面配置的保存位置，为空时只保存在内存中
	fromUI  bool   // 当前配置来自界面
	http    *http.Client
	calls   []time.Time // 近 1 小时的调用时间
	total   int64
	failed  int64
	lastErr string
	now     func() time.Time
}

// New 以配置文件的 ai 段创建客户端（总是返回非空客户端，未启用时调用会返回 ErrDisabled）。
// 密钥从 cfg.KeyEnv() 指定的环境变量读取（getenv 便于测试注入，可为 nil）。
func New(cfg config.AIConfig, getenv func(string) string) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	c := &Client{keyEnv: cfg.KeyEnv(), http: &http.Client{Timeout: timeout}, now: time.Now}
	if getenv != nil {
		c.envKey = strings.TrimSpace(getenv(c.keyEnv))
	}
	c.set = normalize(Settings{Enabled: cfg.Enabled, BaseURL: cfg.BaseURL, Model: cfg.Model, KeyFromEnv: true,
		MaxPerHour: cfg.MaxPerHour, Desensitize: cfg.DesensitizeOn(), AutoTriage: cfg.AutoTriage})
	return c
}

// SetPath 设置界面配置的保存位置，并加载已保存的配置（存在时优先于配置文件）。
// 返回是否加载了界面配置；已保存的配置无效时停用模型并返回错误，不影响服务启动。
func (c *Client) SetPath(path string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.path = path
	if path == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return false, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	s = normalize(s)
	c.fromUI = true
	if err := s.check(); err != nil {
		s.Enabled = false
		c.set = s
		return true, fmt.Errorf("已保存的外部模型配置无效，已停用：%w", err)
	}
	c.set = s
	return true, nil
}

func (c *Client) keyLocked() string {
	if c.set.APIKey != "" {
		return c.set.APIKey
	}
	if c.set.KeyFromEnv {
		return c.envKey
	}
	return ""
}

// Enabled 返回是否启用了外部模型。
func (c *Client) Enabled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.set.Enabled
}

// Model 返回模型名。
func (c *Client) Model() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.set.Model
}

// Desensitize 返回是否发送前脱敏。
func (c *Client) Desensitize() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.set.Desensitize
}

// AutoTriage 返回是否自动研判新出现的高危事件。
func (c *Client) AutoTriage() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.set.Enabled && c.set.AutoTriage
}

// Status 是模型接入状态（不含密钥）。
type Status struct {
	Enabled     bool   `json:"enabled"`
	Model       string `json:"model,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"` // 只含协议与主机
	KeySet      bool   `json:"key_set"`
	Desensitize bool   `json:"desensitize"`
	AutoTriage  bool   `json:"auto_triage"`
	MaxPerHour  int    `json:"max_per_hour"`
	UsedHour    int    `json:"used_hour"`
	Total       int64  `json:"total"`
	Failed      int64  `json:"failed"`
	LastError   string `json:"last_error,omitempty"`
}

// endpointOf 只保留协议与主机，不暴露路径。
func endpointOf(base string) string {
	if i := strings.Index(base, "://"); i >= 0 {
		if j := strings.IndexByte(base[i+3:], '/'); j >= 0 {
			return base[:i+3+j]
		}
	}
	return base
}

// Status 返回接入状态。
func (c *Client) Status() Status {
	if c == nil {
		return Status{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set.Enabled {
		return Status{}
	}
	return Status{Enabled: true, Model: c.set.Model, Endpoint: endpointOf(c.set.BaseURL), KeySet: c.keyLocked() != "", Desensitize: c.set.Desensitize,
		AutoTriage: c.set.AutoTriage, MaxPerHour: c.set.MaxPerHour, UsedHour: len(c.recentLocked()), Total: c.total, Failed: c.failed, LastError: c.lastErr}
}

// View 是界面展示的配置（不含密钥）。
type View struct {
	Enabled     bool      `json:"enabled"`
	BaseURL     string    `json:"base_url"`
	Model       string    `json:"model"`
	KeySet      bool      `json:"key_set"`
	KeySource   string    `json:"key_source"`         // ui：界面填写；env：环境变量；空：未设置
	KeyHint     string    `json:"key_hint,omitempty"` // 界面填写的密钥末 4 位，便于核对是否填对
	KeyEnv      string    `json:"key_env"`
	MaxPerHour  int       `json:"max_per_hour"`
	Desensitize bool      `json:"desensitize"`
	AutoTriage  bool      `json:"auto_triage"`
	FromUI      bool      `json:"from_ui"` // 配置来自界面（否则来自配置文件 ai 段）
	Persist     bool      `json:"persist"` // 界面配置会保存到文件；否则重启后恢复为配置文件中的值
	UpdatedBy   string    `json:"updated_by,omitempty"`
	Updated     time.Time `json:"updated,omitzero"`
}

// View 返回界面展示的配置。
func (c *Client) View() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.set
	v := View{Enabled: s.Enabled, BaseURL: s.BaseURL, Model: s.Model, KeyEnv: c.keyEnv, MaxPerHour: s.MaxPerHour, Desensitize: s.Desensitize,
		AutoTriage: s.AutoTriage, FromUI: c.fromUI, Persist: c.path != "", UpdatedBy: s.UpdatedBy, Updated: s.Updated}
	switch {
	case s.APIKey != "":
		v.KeySet, v.KeySource = true, "ui"
		if len(s.APIKey) >= 16 {
			v.KeyHint = s.APIKey[len(s.APIKey)-4:]
		}
	case s.KeyFromEnv && c.envKey != "":
		v.KeySet, v.KeySource = true, "env"
	}
	return v
}

// Update 是界面提交的配置。api_key 留空表示保持原值；clear_key 表示不再使用任何密钥
// （清除界面保存的密钥，也不再使用环境变量中的密钥），适用于不需要密钥的内网模型。
type Update struct {
	Enabled     bool   `json:"enabled"`
	BaseURL     string `json:"base_url"`
	Model       string `json:"model"`
	APIKey      string `json:"api_key"`
	ClearKey    bool   `json:"clear_key"`
	MaxPerHour  int    `json:"max_per_hour"`
	Desensitize bool   `json:"desensitize"`
	AutoTriage  bool   `json:"auto_triage"`
}

// ErrKeyRebind 表示模型地址的主机变更后沿用了原密钥。
var ErrKeyRebind = errors.New("模型地址的主机已变更：为防止密钥被发送到新的地址，请重新填写模型密钥（新地址不需要密钥时勾选「不使用密钥」）")

func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// mergeLocked 把界面提交的配置与当前配置合并为候选配置（调用方持锁）。
// 主机变更且沿用原密钥时拒绝：否则拿到管理会话的人只需改一下地址就能把密钥发到自己的服务器上。
func (c *Client) mergeLocked(u Update) (Settings, error) {
	s := normalize(Settings{Enabled: u.Enabled, BaseURL: u.BaseURL, Model: u.Model, APIKey: c.set.APIKey, KeyFromEnv: c.set.KeyFromEnv,
		MaxPerHour: u.MaxPerHour, Desensitize: u.Desensitize, AutoTriage: u.AutoTriage})
	newKey := strings.TrimSpace(u.APIKey)
	switch {
	case u.ClearKey:
		s.APIKey, s.KeyFromEnv = "", false
	case newKey != "":
		s.APIKey, s.KeyFromEnv = newKey, false
	case c.keyLocked() != "" && c.set.BaseURL != "" && hostOf(s.BaseURL) != hostOf(c.set.BaseURL):
		return s, ErrKeyRebind
	}
	if err := s.check(); err != nil {
		return s, err
	}
	return s, nil
}

// Apply 保存界面提交的配置并立即生效（每小时调用计数保留）。校验失败时返回错误、配置不变；
// 配置已生效但写入文件失败时返回 warning。
func (c *Client) Apply(u Update, user string) (View, string, error) {
	c.mu.Lock()
	s, err := c.mergeLocked(u)
	if err != nil {
		c.mu.Unlock()
		return View{}, "", err
	}
	s.UpdatedBy, s.Updated = user, c.now()
	c.set, c.fromUI = s, true
	c.lastErr = ""
	warn := ""
	if err := c.saveLocked(); err != nil {
		warn = "保存配置文件失败（重启后恢复为原配置）：" + err.Error()
	}
	c.mu.Unlock()
	return c.View(), warn, nil
}

func (c *Client) saveLocked() error {
	if c.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(c.set, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o750); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, c.path)
}

// TestResult 是连通性测试结果。
type TestResult struct {
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	Model     string `json:"model"`
	Reply     string `json:"reply,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Test 用界面上尚未保存的配置发送一次最小请求，检查地址、密钥与模型名称是否可用。
// 测试同样占用每小时调用额度（防止被用来刷接口），但不计入失败统计。
func (c *Client) Test(ctx context.Context, u Update) (TestResult, error) {
	c.mu.Lock()
	s, err := c.mergeLocked(u)
	if err == nil && s.Model == "" {
		err = errors.New("请填写模型名称")
	}
	if err == nil {
		err = config.CheckAIEndpoint(s.BaseURL)
	}
	key := s.APIKey
	if key == "" && s.KeyFromEnv {
		key = c.envKey
	}
	c.mu.Unlock()
	if err != nil {
		return TestResult{}, err
	}
	if err := c.take(); err != nil {
		return TestResult{}, err
	}
	start := c.now()
	text, _, err := c.do(ctx, s, key, "你是连通性测试助手。", "这是一次连通性测试，请只回复 OK。", 16)
	r := TestResult{OK: err == nil, LatencyMS: c.now().Sub(start).Milliseconds(), Model: s.Model, Reply: clip(text, 100)}
	if err != nil {
		r.Error = err.Error()
	}
	return r, nil
}

func (c *Client) recentLocked() []time.Time {
	cut := c.now().Add(-time.Hour)
	i := 0
	for i < len(c.calls) && c.calls[i].Before(cut) {
		i++
	}
	c.calls = c.calls[i:]
	return c.calls
}

// ErrRateLimited 表示已达到每小时调用上限。
var ErrRateLimited = errors.New("已达到每小时模型调用上限（可在「自学习 → 外部模型」中调整）")

// ErrDisabled 表示未启用外部模型。
var ErrDisabled = errors.New("未启用外部模型（在「自学习 → 外部模型」中配置并启用）")

// take 占用一次调用额度。
func (c *Client) take() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.recentLocked()) >= c.set.MaxPerHour {
		return ErrRateLimited
	}
	c.calls = append(c.calls, c.now())
	c.total++
	return nil
}

func (c *Client) fail(err error) error {
	c.mu.Lock()
	c.failed++
	c.lastErr = err.Error()
	c.mu.Unlock()
	return err
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Complete 发送一次对话请求并返回模型输出的文本，同时返回发送的字节数（审计用）。
func (c *Client) Complete(ctx context.Context, system, user string) (string, int, error) {
	if !c.Enabled() {
		return "", 0, ErrDisabled
	}
	c.mu.Lock()
	s, key := c.set, c.keyLocked()
	c.mu.Unlock()
	if err := c.take(); err != nil {
		return "", 0, err
	}
	text, sent, err := c.do(ctx, s, key, system, user, 2000)
	if err != nil {
		return "", sent, c.fail(err)
	}
	return text, sent, nil
}

// do 调用 OpenAI 兼容的 /chat/completions 接口。密钥只放在请求头中，错误信息中不包含密钥。
func (c *Client) do(ctx context.Context, s Settings, key, system, user string, maxTokens int) (string, int, error) {
	body, _ := json.Marshal(map[string]any{
		"model":       s.Model,
		"messages":    []chatMessage{{Role: "system", Content: system}, {Role: "user", Content: user}},
		"max_tokens":  maxTokens,
		"temperature": 0.2,
		"stream":      false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", len(body), err
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", len(body), fmt.Errorf("调用模型失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", len(body), fmt.Errorf("读取模型响应失败: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if key != "" {
			msg = strings.ReplaceAll(msg, key, "***") // 个别网关会在错误信息中回显请求头
		}
		return "", len(body), fmt.Errorf("模型接口返回 %d: %s", resp.StatusCode, clip(msg, 300))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &out); err != nil || len(out.Choices) == 0 {
		return "", len(body), errors.New("模型响应格式不符合 OpenAI 兼容接口（缺少 choices）")
	}
	return out.Choices[0].Message.Content, len(body), nil
}
