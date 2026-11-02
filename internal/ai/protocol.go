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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 模型接口协议。vLLM 同时提供这两种接口。
const (
	ProtoOpenAI    = "openai"    // POST {base}/chat/completions
	ProtoAnthropic = "anthropic" // POST {base}/messages
)

// Profile 是平台针对一个模型（协议 + 主机 + 模型名）自动学到的适配信息：请求被拒绝时从错误信息中学习，
// 之后不再发送对方不支持的参数；同时统计研判结果，便于判断模型是否适合当前用途。
type Profile struct {
	Thinks           bool `json:"thinks,omitempty"`             // 观察到思考过程
	NoChatKwargs     bool `json:"no_chat_kwargs,omitempty"`     // 不接受 chat_template_kwargs
	NoResponseFormat bool `json:"no_response_format,omitempty"` // 不接受 response_format
	NoTemperature    bool `json:"no_temperature,omitempty"`     // 不接受 temperature
	UseMaxCompletion bool `json:"use_max_completion,omitempty"` // 要求 max_completion_tokens
	AuthBearer       bool `json:"auth_bearer,omitempty"`        // Anthropic 协议的服务要求 Authorization 头
	MaxTokensCap     int  `json:"max_tokens_cap,omitempty"`     // 服务接受的输出长度上限

	Calls     int64     `json:"calls"`             // 成功返回的请求数
	LatencyMS int64     `json:"latency_ms"`        // 累计耗时
	Parsed    int64     `json:"parsed"`            // 得到结构化结论的研判数
	Repaired  int64     `json:"repaired"`          // 其中经格式修复才得到结论的次数
	Unparsed  int64     `json:"unparsed"`          // 未得到结论的研判数
	Truncated int64     `json:"truncated"`         // 输出被截断的次数
	Refused   int64     `json:"refused"`           // 模型拒绝回答的次数
	Adapted   []string  `json:"adapted,omitempty"` // 最近的自动适配记录
	LastUsed  time.Time `json:"last_used,omitzero"`
}

const maxProfiles = 32

func profileKey(s Settings) string {
	return s.Protocol + "|" + hostOf(s.BaseURL) + "|" + s.Model
}

// profile 返回模型适配信息的副本。
func (c *Client) profile(key string) Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.profiles[key]; p != nil {
		return *p
	}
	return Profile{}
}

// updateProfile 修改模型适配信息；只有配置来自界面时才落盘（否则写出的文件会在重启后被当成界面配置）。
func (c *Client) updateProfile(key string, fn func(*Profile)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.profiles == nil {
		c.profiles = map[string]*Profile{}
	}
	p := c.profiles[key]
	if p == nil {
		if len(c.profiles) >= maxProfiles {
			oldest := ""
			for k, v := range c.profiles {
				if oldest == "" || v.LastUsed.Before(c.profiles[oldest].LastUsed) {
					oldest = k
				}
			}
			delete(c.profiles, oldest)
		}
		p = &Profile{}
		c.profiles[key] = p
	}
	fn(p)
	p.LastUsed = c.now()
	if c.fromUI {
		c.saveLocked() // 适配信息丢失只是多试一次，保存失败不影响调用
	}
}

// reasoningModel 按名称判断通常带思考过程的模型。
func reasoningModel(model string) bool {
	m := strings.ToLower(model)
	for _, k := range []string{"qwen3", "deepseek-r", "-r1", "think"} {
		if strings.Contains(m, k) {
			return true
		}
	}
	return false
}

// thinkingOff 判断是否请求关闭思考：研判只需要结论，思考过程会增加耗时并占用输出长度。
func thinkingOff(s Settings, p Profile) bool {
	switch s.Thinking {
	case "off":
		return true
	case "on":
		return false
	}
	return p.Thinks || reasoningModel(s.Model)
}

// apiBase 返回接口前缀：只填写了主机时补上 /v1。
func apiBase(base string) string {
	if u, err := url.Parse(base); err == nil && strings.Trim(u.Path, "/") == "" {
		return strings.TrimRight(base, "/") + "/v1"
	}
	return base
}

type callOpts struct {
	maxTokens int
	json      bool // 要求输出 JSON
}

// builtRequest 是发送给模型的请求及其使用的可选参数，请求被拒绝时据此判断可以去掉什么。
type builtRequest struct {
	url       string
	headers   map[string]string
	body      []byte
	maxTokens int
	optional  []string // 本次发送的可选参数
}

func buildRequest(s Settings, key, system, user string, o callOpts, p Profile) builtRequest {
	maxTokens := o.maxTokens
	if p.MaxTokensCap > 0 && maxTokens > p.MaxTokensCap {
		maxTokens = p.MaxTokensCap
	}
	off := thinkingOff(s, p)
	// Qwen3 系列关闭思考的约定写法；只在无法通过参数关闭时使用，不支持时也只是多一行文字
	if off && strings.Contains(strings.ToLower(s.Model), "qwen3") && (s.Protocol == ProtoAnthropic || p.NoChatKwargs) {
		user += "\n/no_think"
	}
	b := builtRequest{maxTokens: maxTokens, headers: map[string]string{"Content-Type": "application/json"}}
	if s.Protocol == ProtoAnthropic {
		b.url = apiBase(s.BaseURL) + "/messages"
		b.headers["anthropic-version"] = "2023-06-01"
		if key != "" {
			if p.AuthBearer {
				b.headers["Authorization"] = "Bearer " + key
			} else {
				b.headers["x-api-key"] = key
			}
		}
		// 不发送 temperature：当前的 Anthropic 模型会以 400 拒绝；也不发送 thinking：各模型取值规则不同，省略总是合法
		b.body, _ = json.Marshal(map[string]any{
			"model": s.Model, "max_tokens": maxTokens, "system": system,
			"messages": []chatMessage{{Role: "user", Content: user}},
		})
		return b
	}
	b.url = apiBase(s.BaseURL) + "/chat/completions"
	if key != "" {
		b.headers["Authorization"] = "Bearer " + key
	}
	req := map[string]any{
		"model":    s.Model,
		"messages": []chatMessage{{Role: "system", Content: system}, {Role: "user", Content: user}},
		"stream":   false,
	}
	if p.UseMaxCompletion {
		req["max_completion_tokens"] = maxTokens
	} else {
		req["max_tokens"] = maxTokens
	}
	if !p.NoTemperature {
		req["temperature"] = 0.2
		b.optional = append(b.optional, "temperature")
	}
	if o.json && !p.NoResponseFormat {
		req["response_format"] = map[string]string{"type": "json_object"}
		b.optional = append(b.optional, "response_format")
	}
	if off && !p.NoChatKwargs { // vLLM 等服务关闭思考的参数
		req["chat_template_kwargs"] = map[string]any{"enable_thinking": false}
		b.optional = append(b.optional, "chat_template_kwargs")
	}
	b.body, _ = json.Marshal(req)
	return b
}

// apiError 是模型接口返回的错误。
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("模型接口返回 %d: %s", e.Status, e.Msg) }

// send 发送请求并按协议解析响应。密钥只放在请求头中，错误信息中不包含密钥。
func (c *Client) send(ctx context.Context, proto, key string, b builtRequest) (chatReply, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(b.body))
	if err != nil {
		return chatReply{}, err
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return chatReply{}, fmt.Errorf("调用模型失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return chatReply{}, fmt.Errorf("读取模型响应失败: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if key != "" {
			msg = strings.ReplaceAll(msg, key, "***") // 个别网关会在错误信息中回显请求头
		}
		return chatReply{}, &apiError{Status: resp.StatusCode, Msg: clip(msg, 300)}
	}
	if proto == ProtoAnthropic {
		return parseAnthropic(data)
	}
	return parseOpenAI(data)
}

func parseOpenAI(data []byte) (chatReply, error) {
	var out struct {
		Choices []struct {
			Message struct {
				Content          json.RawMessage `json:"content"` // 只输出思考过程时可能为 null；个别服务为内容块数组
				ReasoningContent string          `json:"reasoning_content"`
				Reasoning        string          `json:"reasoning"`
				Refusal          string          `json:"refusal"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &out); err != nil || len(out.Choices) == 0 {
		return chatReply{}, errors.New("模型响应格式不符合 OpenAI 兼容接口（缺少 choices），请确认接口协议选择正确")
	}
	ch := out.Choices[0]
	text, thought := splitThinking(contentText(ch.Message.Content))
	if thought == "" {
		thought = strings.TrimSpace(ch.Message.ReasoningContent + ch.Message.Reasoning)
	}
	r := chatReply{Text: text, Thinking: thought, Finish: ch.FinishReason, Refusal: ch.Message.Refusal}
	if r.Finish == "content_filter" || r.Refusal != "" {
		r.Finish = "refusal"
	}
	return r, nil
}

func parseAnthropic(data []byte) (chatReply, error) {
	var out struct {
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Thinking string `json:"thinking"`
		} `json:"content"`
		StopReason  string `json:"stop_reason"`
		StopDetails *struct {
			Category    string `json:"category"`
			Explanation string `json:"explanation"`
		} `json:"stop_details"`
	}
	if err := json.Unmarshal(data, &out); err != nil || (out.Content == nil && out.StopReason == "") {
		return chatReply{}, errors.New("模型响应格式不符合 Anthropic 接口（缺少 content），请确认接口协议选择正确")
	}
	var text, thought strings.Builder
	for _, b := range out.Content {
		switch b.Type {
		case "text":
			text.WriteString(b.Text)
		case "thinking":
			thought.WriteString(b.Thinking)
		}
	}
	answer, inline := splitThinking(text.String())
	r := chatReply{Text: answer, Thinking: strings.TrimSpace(thought.String() + inline), Finish: out.StopReason}
	switch out.StopReason {
	case "max_tokens":
		r.Finish = "length"
	case "refusal":
		if d := out.StopDetails; d != nil {
			r.Refusal = strings.TrimSpace(d.Category + " " + d.Explanation)
		}
	}
	return r, nil
}

// contentText 取 content 的文本：字符串，或内容块数组中的 text。
func contentText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	json.Unmarshal(raw, &parts)
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString(p.Text)
	}
	return sb.String()
}

var (
	reCtxLimit  = regexp.MustCompile(`maximum context length is (\d+)`)
	reCtxInput  = regexp.MustCompile(`(\d+) (?:in the messages|input tokens)`)
	reOutLimit  = regexp.MustCompile(`(?:> |less than or equal to |at most |maximum (?:value|allowed)[^0-9]{0,20})(\d+)`)
	retryStatus = map[int]bool{429: true, 502: true, 503: true, 504: true}
)

// adaptToError 从请求被拒绝的错误信息中学习，返回是否值得调整后重试。
func (p *Profile) adaptToError(proto string, b builtRequest, e *apiError) string {
	if e.Status == http.StatusUnauthorized && proto == ProtoAnthropic && !p.AuthBearer && b.headers["x-api-key"] != "" {
		p.AuthBearer = true
		return "x-api-key 被拒绝，改用 Authorization 头"
	}
	if e.Status != http.StatusBadRequest && e.Status != http.StatusUnprocessableEntity {
		return ""
	}
	msg := strings.ToLower(e.Msg)
	has := func(s string) bool { return strings.Contains(msg, s) }
	sent := func(name string) bool {
		for _, o := range b.optional {
			if o == name {
				return true
			}
		}
		return false
	}
	// 先判断长度：vLLM 的长度错误里同时含有 max_completion_tokens 字样
	if has("maximum context length") || ((has("max_tokens") || has("max_completion_tokens")) && (has("too large") || has("exceed") || has("maximum") || has("less than") || has(" > "))) {
		limit := 0
		if m := reCtxLimit.FindStringSubmatch(msg); m != nil {
			total, _ := strconv.Atoi(m[1])
			input := 0
			if n := reCtxInput.FindStringSubmatch(msg); n != nil {
				input, _ = strconv.Atoi(n[1])
			}
			if input > 0 {
				limit = total - input - 32
			}
		} else if m := reOutLimit.FindStringSubmatch(msg); m != nil {
			limit, _ = strconv.Atoi(m[1])
		}
		if limit <= 0 || limit >= b.maxTokens {
			limit = b.maxTokens / 2
		}
		if limit < 256 || limit >= b.maxTokens {
			return "" // 输入本身已接近上下文上限，继续缩小输出没有意义
		}
		p.MaxTokensCap = limit
		return "输出长度上限调整为 " + strconv.Itoa(limit)
	}
	switch {
	case has("max_completion_tokens") && !p.UseMaxCompletion:
		p.UseMaxCompletion = true
		return "改用 max_completion_tokens"
	case has("temperature") && sent("temperature"):
		p.NoTemperature = true
		return "不再发送 temperature"
	case (has("response_format") || has("json_object") || has("structured") || has("guided") || has("grammar")) && sent("response_format"):
		p.NoResponseFormat = true
		return "不再发送 response_format"
	case (has("chat_template_kwargs") || has("enable_thinking")) && sent("chat_template_kwargs"):
		p.NoChatKwargs = true
		return "不再发送 chat_template_kwargs"
	}
	// 错误信息没有点名参数：去掉平台额外增加的参数再试一次
	if sent("response_format") || sent("chat_template_kwargs") {
		p.NoResponseFormat, p.NoChatKwargs = true, true
		return "不再发送 response_format 与 chat_template_kwargs"
	}
	return ""
}

// do 发送一次调用：请求参数被拒绝时自动调整并记住，瞬时错误（限流、网关错误、连接失败）重试一次。
func (c *Client) do(ctx context.Context, s Settings, key, system, user string, o callOpts) (chatReply, int, error) {
	pk := profileKey(s)
	timeout := time.Duration(s.TimeoutSec) * time.Second
	sent, transient := 0, true
	var last error
	for attempt := 0; attempt < 6; attempt++ {
		b := buildRequest(s, key, system, user, o, c.profile(pk))
		sent = len(b.body)
		cctx, cancel := context.WithTimeout(ctx, timeout)
		start := c.now()
		r, err := c.send(cctx, s.Protocol, key, b)
		expired := cctx.Err() != nil && ctx.Err() == nil
		cancel()
		if err == nil {
			c.updateProfile(pk, func(p *Profile) {
				p.Calls++
				p.LatencyMS += c.now().Sub(start).Milliseconds()
				p.Thinks = p.Thinks || r.Thinking != ""
			})
			return r, sent, nil
		}
		last = err
		if expired {
			return chatReply{}, sent, fmt.Errorf("模型在 %d 秒内没有返回结果，可在配置中调大超时时间", s.TimeoutSec)
		}
		if ctx.Err() != nil {
			return chatReply{}, sent, err
		}
		var ae *apiError
		if errors.As(err, &ae) {
			learned := ""
			c.updateProfile(pk, func(p *Profile) {
				if learned = p.adaptToError(s.Protocol, b, ae); learned != "" {
					p.Adapted = append(p.Adapted, learned)
					if len(p.Adapted) > 8 {
						p.Adapted = p.Adapted[len(p.Adapted)-8:]
					}
				}
			})
			if learned != "" {
				continue
			}
			if !retryStatus[ae.Status] {
				break
			}
		} else if strings.HasPrefix(err.Error(), "模型响应格式") {
			break
		}
		if !transient {
			break
		}
		transient = false
		select {
		case <-time.After(c.backoff):
		case <-ctx.Done():
			return chatReply{}, sent, ctx.Err()
		}
	}
	return chatReply{}, sent, last
}

// listModels 读取接口提供的模型列表（OpenAI 与 Anthropic 协议都是 GET {base}/models）。
func (c *Client) listModels(ctx context.Context, s Settings, key string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase(s.BaseURL)+"/models?limit=1000", nil)
	if err != nil {
		return nil, err
	}
	if key != "" {
		p := c.profile(profileKey(s))
		if s.Protocol == ProtoAnthropic && !p.AuthBearer {
			req.Header.Set("x-api-key", key)
		} else {
			req.Header.Set("Authorization", "Bearer "+key)
		}
	}
	if s.Protocol == ProtoAnthropic {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("读取模型列表失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("读取模型列表失败：接口返回 %d", resp.StatusCode)
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, errors.New("读取模型列表失败：响应格式不符合预期")
	}
	list := make([]string, 0, len(out.Data))
	for _, m := range out.Data {
		if m.ID != "" && len(list) < 200 {
			list = append(list, m.ID)
		}
	}
	sort.Strings(list)
	return list, nil
}
