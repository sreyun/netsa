package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Enabled  bool   `json:"enabled"`
	Protocol string `json:"protocol"` // openai / anthropic
	BaseURL  string `json:"base_url"`
	Model    string `json:"model"`
	// APIKey 是界面填写的密钥，只保存在服务端，任何接口都不返回
	APIKey string `json:"api_key,omitempty"`
	// KeyFromEnv 表示界面未填写密钥时使用环境变量中的密钥（兼容原有部署方式）；
	// 在界面填写或清除密钥后不再使用环境变量
	KeyFromEnv  bool   `json:"key_from_env"`
	MaxPerHour  int    `json:"max_per_hour"`
	MaxTokens   int    `json:"max_tokens,omitempty"`  // 研判的输出长度上限，0 为自动
	TimeoutSec  int    `json:"timeout_sec,omitempty"` // 单次调用超时（秒）
	Thinking    string `json:"thinking,omitempty"`    // 思考模式：auto / off / on
	Desensitize bool   `json:"desensitize"`
	AutoTriage  bool   `json:"auto_triage"`
	// NoDowngrade 关闭「模型高置信判为误报时下调事件等级」（默认开启）
	NoDowngrade bool      `json:"no_downgrade,omitempty"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	Updated     time.Time `json:"updated,omitzero"`
}

// savedFile 是 ai.json 的内容：配置与模型适配信息。
type savedFile struct {
	Settings
	Profiles map[string]*Profile `json:"profiles,omitempty"`
}

const defaultTimeoutSec = 120

func normalize(s Settings) Settings {
	s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
	if s.Protocol == "" {
		s.Protocol = ProtoOpenAI
	}
	s.BaseURL = strings.TrimRight(strings.TrimSpace(s.BaseURL), "/")
	for _, tail := range []string{"/chat/completions", "/messages"} { // 粘贴了完整接口地址
		s.BaseURL = strings.TrimRight(strings.TrimSuffix(s.BaseURL, tail), "/")
	}
	s.Model = strings.TrimSpace(s.Model)
	s.APIKey = strings.TrimSpace(s.APIKey)
	if s.MaxPerHour <= 0 {
		s.MaxPerHour = 30
	}
	if s.TimeoutSec <= 0 {
		s.TimeoutSec = defaultTimeoutSec
	}
	if s.Thinking == "" {
		s.Thinking = "auto"
	}
	return s
}

// check 校验配置。未启用时也校验已填写的地址，避免保存一个之后无法启用的配置。
func (s Settings) check() error {
	if s.Protocol != ProtoOpenAI && s.Protocol != ProtoAnthropic {
		return errors.New("接口协议只能是 openai 或 anthropic")
	}
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
	if s.MaxTokens != 0 && (s.MaxTokens < 256 || s.MaxTokens > 128000) {
		return errors.New("输出长度上限应为 0（自动）或 256 ~ 128000")
	}
	if s.TimeoutSec < 10 || s.TimeoutSec > 1800 {
		return errors.New("调用超时应在 10 ~ 1800 秒之间")
	}
	if s.Thinking != "auto" && s.Thinking != "off" && s.Thinking != "on" {
		return errors.New("思考模式只能是 auto、off 或 on")
	}
	return nil
}

// Client 是模型客户端，可并发使用；配置可在运行中替换（进行中的调用使用替换前的配置）。
type Client struct {
	mu       sync.Mutex
	set      Settings
	profiles map[string]*Profile // 协议 + 主机 + 模型 → 自动学到的适配信息
	envKey   string              // 环境变量中的密钥
	keyEnv   string              // 环境变量名
	path     string              // 界面配置的保存位置，为空时只保存在内存中
	fromUI   bool                // 当前配置来自界面
	http     *http.Client        // 超时由每次调用的 context 控制，界面修改后立即生效
	backoff  time.Duration       // 瞬时错误重试前的等待
	calls    []time.Time         // 近 1 小时的调用时间
	total    int64
	failed   int64
	lastErr  string
	now      func() time.Time
}

// New 以配置文件的 ai 段创建客户端（总是返回非空客户端，未启用时调用会返回 ErrDisabled）。
// 密钥从 cfg.KeyEnv() 指定的环境变量读取（getenv 便于测试注入，可为 nil）。
func New(cfg config.AIConfig, getenv func(string) string) *Client {
	c := &Client{keyEnv: cfg.KeyEnv(), http: &http.Client{}, backoff: 1500 * time.Millisecond, now: time.Now, profiles: map[string]*Profile{}}
	if getenv != nil {
		c.envKey = strings.TrimSpace(getenv(c.keyEnv))
	}
	c.set = normalize(Settings{Enabled: cfg.Enabled, BaseURL: cfg.BaseURL, Model: cfg.Model, KeyFromEnv: true, TimeoutSec: int(cfg.Timeout / time.Second),
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
	var f savedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return false, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	s := normalize(f.Settings)
	c.fromUI = true
	for k, p := range f.Profiles {
		if p != nil {
			c.profiles[k] = p
		}
	}
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

// AutoDowngrade 返回模型高置信判为误报时是否下调事件等级。
func (c *Client) AutoDowngrade() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.set.NoDowngrade
}

// CallBudget 返回一次研判最长耗时：研判最多调用 3 次模型（截断重试、格式修复），每次还可能重试一次瞬时错误。
func (c *Client) CallBudget() time.Duration {
	if c == nil {
		return 3 * time.Minute
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return min(time.Duration(c.set.TimeoutSec)*3*time.Second+30*time.Second, 30*time.Minute)
}

// Status 是模型接入状态（不含密钥）。
type Status struct {
	Enabled     bool     `json:"enabled"`
	Protocol    string   `json:"protocol,omitempty"`
	Model       string   `json:"model,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"` // 只含协议与主机
	KeySet      bool     `json:"key_set"`
	Desensitize bool     `json:"desensitize"`
	AutoTriage  bool     `json:"auto_triage"`
	MaxPerHour  int      `json:"max_per_hour"`
	UsedHour    int      `json:"used_hour"`
	Total       int64    `json:"total"`
	Failed      int64    `json:"failed"`
	LastError   string   `json:"last_error,omitempty"`
	Adapt       *Profile `json:"adapt,omitempty"` // 平台对该模型的自动适配与研判统计
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
	st := Status{Enabled: true, Protocol: c.set.Protocol, Model: c.set.Model, Endpoint: endpointOf(c.set.BaseURL), KeySet: c.keyLocked() != "", Desensitize: c.set.Desensitize,
		AutoTriage: c.set.AutoTriage, MaxPerHour: c.set.MaxPerHour, UsedHour: len(c.recentLocked()), Total: c.total, Failed: c.failed, LastError: c.lastErr}
	if p := c.profiles[profileKey(c.set)]; p != nil {
		cp := *p
		st.Adapt = &cp
	}
	return st
}

// View 是界面展示的配置（不含密钥）。
type View struct {
	Enabled     bool      `json:"enabled"`
	Protocol    string    `json:"protocol"`
	BaseURL     string    `json:"base_url"`
	Model       string    `json:"model"`
	KeySet      bool      `json:"key_set"`
	KeySource   string    `json:"key_source"`         // ui：界面填写；env：环境变量；空：未设置
	KeyHint     string    `json:"key_hint,omitempty"` // 界面填写的密钥末 4 位，便于核对是否填对
	KeyEnv      string    `json:"key_env"`
	MaxPerHour  int       `json:"max_per_hour"`
	MaxTokens   int       `json:"max_tokens"`
	TimeoutSec  int       `json:"timeout_sec"`
	Thinking    string    `json:"thinking"`
	Desensitize bool      `json:"desensitize"`
	AutoTriage  bool      `json:"auto_triage"`
	NoDowngrade bool      `json:"no_downgrade"`
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
	v := View{Enabled: s.Enabled, Protocol: s.Protocol, BaseURL: s.BaseURL, Model: s.Model, KeyEnv: c.keyEnv, MaxPerHour: s.MaxPerHour, MaxTokens: s.MaxTokens,
		TimeoutSec: s.TimeoutSec, Thinking: s.Thinking, Desensitize: s.Desensitize,
		AutoTriage: s.AutoTriage, NoDowngrade: s.NoDowngrade, FromUI: c.fromUI, Persist: c.path != "", UpdatedBy: s.UpdatedBy, Updated: s.Updated}
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
	Protocol    string `json:"protocol"`
	BaseURL     string `json:"base_url"`
	Model       string `json:"model"`
	APIKey      string `json:"api_key"`
	ClearKey    bool   `json:"clear_key"`
	MaxPerHour  int    `json:"max_per_hour"`
	MaxTokens   int    `json:"max_tokens"`
	TimeoutSec  int    `json:"timeout_sec"`
	Thinking    string `json:"thinking"`
	Desensitize bool   `json:"desensitize"`
	AutoTriage  bool   `json:"auto_triage"`
	NoDowngrade bool   `json:"no_downgrade"`
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
	s := Settings{Enabled: u.Enabled, Protocol: u.Protocol, BaseURL: u.BaseURL, Model: u.Model, APIKey: c.set.APIKey, KeyFromEnv: c.set.KeyFromEnv,
		MaxPerHour: u.MaxPerHour, MaxTokens: u.MaxTokens, TimeoutSec: u.TimeoutSec, Thinking: u.Thinking, Desensitize: u.Desensitize, AutoTriage: u.AutoTriage, NoDowngrade: u.NoDowngrade}
	if s.TimeoutSec == 0 {
		s.TimeoutSec = c.set.TimeoutSec
	}
	s = normalize(s)
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
	data, err := json.MarshalIndent(savedFile{Settings: c.set, Profiles: c.profiles}, "", "  ")
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
	OK        bool     `json:"ok"`
	LatencyMS int64    `json:"latency_ms"`
	Protocol  string   `json:"protocol,omitempty"` // 实际可用的协议（与所选不同时界面会切换）
	Model     string   `json:"model"`
	Reply     string   `json:"reply,omitempty"`
	Note      string   `json:"note,omitempty"`   // 连接正常但值得注意的情况（如推理模型）
	Models    []string `json:"models,omitempty"` // 模型名称不存在时，接口提供的模型列表
	Error     string   `json:"error,omitempty"`
}

// candidateLocked 取表单对应的候选配置与实际使用的密钥（调用方持锁）。
func (c *Client) candidateLocked(u Update) (Settings, string, error) {
	s, err := c.mergeLocked(u)
	if err == nil {
		err = config.CheckAIEndpoint(s.BaseURL)
	}
	key := s.APIKey
	if key == "" && s.KeyFromEnv {
		key = c.envKey
	}
	return s, key, err
}

// Test 用界面上尚未保存的配置发送一次最小请求，检查地址、密钥与模型名称是否可用。
// 地址不存在时尝试另一种协议；模型不存在时列出接口提供的模型。
// 测试同样占用每小时调用额度（防止被用来刷接口），但不计入失败统计。
func (c *Client) Test(ctx context.Context, u Update) (TestResult, error) {
	c.mu.Lock()
	s, key, err := c.candidateLocked(u)
	if err == nil && s.Model == "" {
		err = errors.New("请填写模型名称")
	}
	c.mu.Unlock()
	if err != nil {
		return TestResult{}, err
	}
	if err := c.take(); err != nil {
		return TestResult{}, err
	}
	const system, user = "你是连通性测试助手。", "这是一次连通性测试，请只回复 OK。"
	start := c.now()
	reply, _, err := c.do(ctx, s, key, system, user, callOpts{maxTokens: 16})
	r := TestResult{OK: err == nil, Protocol: s.Protocol, Model: s.Model}
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound || errors.As(err, &ae) && ae.Status == http.StatusMethodNotAllowed {
		lower := strings.ToLower(ae.Msg)
		if strings.Contains(lower, "model") {
			r.Models, _ = c.listModels(ctx, s, key)
		} else {
			alt := s
			alt.Protocol = ProtoAnthropic
			if s.Protocol == ProtoAnthropic {
				alt.Protocol = ProtoOpenAI
			}
			if rep, _, altErr := c.do(ctx, alt, key, system, user, callOpts{maxTokens: 16}); altErr == nil {
				reply, err = rep, nil
				r.OK, r.Protocol = true, alt.Protocol
				r.Note = "该地址使用 " + alt.Protocol + " 协议，已自动切换，保存后生效。"
			}
		}
	}
	r.LatencyMS, r.Reply = c.now().Sub(start).Milliseconds(), clip(reply.Text, 100)
	if err != nil {
		r.Error = err.Error()
	} else if reply.Thinking != "" {
		r.Note += "这是带思考过程的推理模型：研判耗时较长，平台已自动请求关闭思考；如果研判提示输出被截断，请在模型服务上关闭思考模式或调高输出长度上限。"
	}
	return r, nil
}

// Models 读取表单对应接口提供的模型列表，用于在界面上选择模型名称。
func (c *Client) Models(ctx context.Context, u Update) ([]string, error) {
	u.Enabled = false // 只需要地址，模型名称还没有选
	c.mu.Lock()
	s, key, err := c.candidateLocked(u)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.listModels(ctx, s, key)
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

// chatReply 是一次模型调用的结果。
type chatReply struct {
	Text     string // 正文（已去掉混在其中的思考过程）
	Thinking string // 思考过程：独立字段 / 内容块，或正文中的 <think> 段
	Finish   string // 结束原因；length 表示被截断，refusal 表示模型拒绝回答
	Refusal  string // 拒绝回答的说明
}

// Complete 发送一次对话请求并返回模型输出的正文，同时返回发送的字节数（审计用）。
func (c *Client) Complete(ctx context.Context, system, user string) (string, int, error) {
	r, sent, err := c.complete(ctx, system, user, callOpts{maxTokens: triageMaxTokens})
	return r.Text, sent, err
}

func (c *Client) complete(ctx context.Context, system, user string, o callOpts) (chatReply, int, error) {
	if !c.Enabled() {
		return chatReply{}, 0, ErrDisabled
	}
	c.mu.Lock()
	s, key := c.set, c.keyLocked()
	c.mu.Unlock()
	if err := c.take(); err != nil {
		return chatReply{}, 0, err
	}
	r, sent, err := c.do(ctx, s, key, system, user, o)
	if err != nil {
		return chatReply{}, sent, c.fail(err)
	}
	return r, sent, nil
}
