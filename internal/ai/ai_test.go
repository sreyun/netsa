package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
)

func TestMasker(t *testing.T) {
	m := NewMasker(true)
	in := `10.0.0.5 → 203.0.113.9 GET /login?user=admin&password=P@ss123&token=abc.def Authorization: Bearer eyJhbGciOi.xx; ` +
		`10.0.0.5 again, 192.168.1.2, mail zhang.san@corp.example.com, tel 13812345678, id 110101199003077777`
	out := m.Mask(in)
	for _, leak := range []string{"10.0.0.5", "192.168.1.2", "P@ss123", "abc.def", "eyJhbGciOi", "zhang.san", "13812345678", "110101199003077777"} {
		if strings.Contains(out, leak) {
			t.Errorf("脱敏后仍包含 %q: %s", leak, out)
		}
	}
	for _, keep := range []string{"203.0.113.9", "内网主机#1 again", "内网主机#2", "password=***", "***@corp.example.com", "138****5678"} {
		if !strings.Contains(out, keep) {
			t.Errorf("脱敏结果应包含 %q: %s", keep, out)
		}
	}
	if NewMasker(false).Mask(in) != in {
		t.Fatal("关闭脱敏时应原样返回")
	}
	// 地址紧贴其他字符（URL 编码、拼接在参数名后）同样脱敏；本身合法的公网地址不能被拆出「内网后缀」
	glued := NewMasker(true).Mask("cmd=ping%2010.20.30.40&h=host_172.16.0.9 src 110.20.30.40 v2026.10.30.1")
	for _, leak := range []string{"10.20.30.40&", "172.16.0.9"} {
		if strings.Contains(glued, leak) {
			t.Errorf("紧贴其他字符的内网地址未脱敏 %q: %s", leak, glued)
		}
	}
	for _, keep := range []string{"%20内网主机#1&", "host_内网主机#2", "src 110.20.30.40", "v2026.10.30.1"} {
		if !strings.Contains(glued, keep) {
			t.Errorf("脱敏结果应包含 %q: %s", keep, glued)
		}
	}
	// 内网 IPv6（ULA、链路本地）同样脱敏，同一地址的不同写法对应同一个占位符；公网 IPv6、时间与 MAC 地址保留
	v6 := m.Mask("fd00:10::5 → 2001:4860:4860::8888 at 08:49:59 from fe80::1 mac 00:1a:2b:3c:4d:5e, again fd00:10:0:0:0:0:0:5")
	for _, keep := range []string{"内网主机#3 →", "2001:4860:4860::8888", "08:49:59", "from 内网主机#4", "00:1a:2b:3c:4d:5e", "again 内网主机#3"} {
		if !strings.Contains(v6, keep) {
			t.Errorf("IPv6 脱敏结果应包含 %q: %s", keep, v6)
		}
	}
}

func TestParseVerdict(t *testing.T) {
	v := ParseVerdict("结论如下：\n```json\n{\"verdict\":\"false_positive\",\"confidence\":150,\"summary\":\"内部扫描\",\"reasons\":[\"来源为授权扫描器\"],\"actions\":[\"加入白名单\"]}\n```")
	if v.Verdict != "false_positive" || v.Confidence != 100 || len(v.Reasons) != 1 || !strings.Contains(v.Note(), "疑似误报") {
		t.Fatalf("解析: %+v", v)
	}
	if v := ParseVerdict(`{"verdict":"hack","confidence":50}`); v.Verdict != "uncertain" {
		t.Fatalf("未知结论应归为无法判断: %+v", v)
	}
	if v := ParseVerdict("我无法判断"); v.Verdict != "uncertain" || v.Raw == "" {
		t.Fatalf("非 JSON 输出: %+v", v)
	}
}

// OpenAI 兼容接口：请求格式、密钥只在请求头中发送、调用上限、错误处理。
func TestClient(t *testing.T) {
	var got struct {
		Model    string
		Messages []chatMessage
	}
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		if strings.Contains(got.Messages[1].Content, "boom") {
			http.Error(w, `{"error":{"message":"quota exceeded"}}`, http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"attack\",\"confidence\":90,\"summary\":\"SQL 注入扫描\"}"}}]}`))
	}))
	defer srv.Close()
	c := New(config.AIConfig{Enabled: true, BaseURL: srv.URL + "/v1/", Model: "qwen-max", MaxPerHour: 2},
		func(k string) string { return map[string]string{"NETSA_AI_API_KEY": "sk-test"}[k] })
	v, sent, err := c.Triage(context.Background(), "事件摘要")
	if err != nil || v.Verdict != "attack" || v.Model != "qwen-max" || sent == 0 {
		t.Fatalf("研判: %+v %v", v, err)
	}
	if got.Model != "qwen-max" || got.Messages[0].Role != "system" || got.Messages[1].Content != "事件摘要" || auth != "Bearer sk-test" {
		t.Fatalf("请求: %+v auth=%q", got, auth)
	}
	if _, _, err := c.Triage(context.Background(), "boom"); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("接口错误应返回: %v", err)
	}
	if _, _, err := c.Triage(context.Background(), "x"); err != ErrRateLimited {
		t.Fatalf("超过每小时上限: %v", err)
	}
	st := c.Status()
	if st.UsedHour != 2 || st.Failed != 1 || !st.KeySet || st.Endpoint != srv.URL || strings.Contains(st.Endpoint, "sk-test") {
		t.Fatalf("状态: %+v", st)
	}
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, _, err := c.Triage(context.Background(), "x"); err != nil {
		t.Fatalf("1 小时后额度应恢复: %v", err)
	}
	off := New(config.AIConfig{}, nil)
	if off.Enabled() || off.Status().Enabled {
		t.Fatal("未启用时应为停用状态")
	}
	if _, _, err := off.Complete(context.Background(), "s", "u"); err != ErrDisabled {
		t.Fatalf("未启用时调用应返回 ErrDisabled: %v", err)
	}
}

// Web 管理页面配置：保存后立即生效并落盘（0600），重启后优先于配置文件；任何视图都不返回密钥。
func TestSettingsApplyPersist(t *testing.T) {
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		w.Write([]byte(`{"choices":[{"message":{"content":"OK"}}]}`))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ai.json")
	env := func(k string) string { return map[string]string{"NETSA_AI_API_KEY": "sk-from-env"}[k] }

	c := New(config.AIConfig{}, env)
	if loaded, err := c.SetPath(path); loaded || err != nil {
		t.Fatalf("文件不存在时沿用配置文件: %v %v", loaded, err)
	}
	if v := c.View(); v.Enabled || v.KeySource != "env" || !v.Persist || v.FromUI {
		t.Fatalf("初始视图: %+v", v)
	}
	// 校验：启用时必须填写模型名称；公网地址必须 https；不能带查询参数；密钥不能有空白
	for _, bad := range []Update{
		{Enabled: true, BaseURL: srv.URL + "/v1"},
		{Enabled: true, BaseURL: "http://api.example.com/v1", Model: "m"},
		{Enabled: true, BaseURL: srv.URL + "/v1?x=1", Model: "m"},
		{Enabled: true, BaseURL: srv.URL + "/v1", Model: "m", APIKey: "sk test"},
		{Enabled: true, BaseURL: srv.URL + "/v1", Model: "m", MaxPerHour: 20000},
	} {
		if _, _, err := c.Apply(bad, "admin"); err == nil {
			t.Errorf("应拒绝无效配置: %+v", bad)
		}
	}
	if c.Enabled() {
		t.Fatal("校验失败时配置不应改变")
	}
	key := "sk-web-0123456789abcdef"
	v, warn, err := c.Apply(Update{Enabled: true, BaseURL: srv.URL + "/v1/", Model: "deepseek-chat", APIKey: key, MaxPerHour: 5, Desensitize: true}, "admin")
	if err != nil || warn != "" || !v.Enabled || v.KeySource != "ui" || v.KeyHint != "cdef" || v.BaseURL != srv.URL+"/v1" || v.UpdatedBy != "admin" {
		t.Fatalf("保存: %+v %q %v", v, warn, err)
	}
	if b, _ := json.Marshal(map[string]any{"v": c.View(), "s": c.Status()}); strings.Contains(string(b), key) {
		t.Fatalf("视图中不能出现密钥: %s", b)
	}
	if _, _, err := c.Triage(context.Background(), "x"); err != nil || auths[len(auths)-1] != "Bearer "+key {
		t.Fatalf("保存后立即生效，使用界面填写的密钥: %v %v", err, auths)
	}
	if fi, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("配置文件应以 0600 保存: %v %v", fi, err)
	}

	// 重启：界面配置优先于配置文件
	c2 := New(config.AIConfig{Enabled: true, BaseURL: "https://other.example.com/v1", Model: "qwen-max"}, env)
	if loaded, err := c2.SetPath(path); !loaded || err != nil || c2.Model() != "deepseek-chat" || c2.View().KeySource != "ui" {
		t.Fatalf("重启后应加载界面配置: %v %v %+v", loaded, err, c2.View())
	}
	// 只修改其他项、密钥留空：保持原密钥
	if _, _, err := c2.Apply(Update{Enabled: true, BaseURL: srv.URL + "/v1", Model: "deepseek-reasoner", MaxPerHour: 5, Desensitize: true}, "bob"); err != nil || c2.View().KeyHint != "cdef" {
		t.Fatalf("密钥留空应保持原值: %v %+v", err, c2.View())
	}
	// 换到其他主机且沿用原密钥：拒绝，防止密钥被发到新地址
	if _, _, err := c2.Apply(Update{Enabled: true, BaseURL: "https://evil.example.com/v1", Model: "m", MaxPerHour: 5}, "bob"); err != ErrKeyRebind {
		t.Fatalf("主机变更沿用密钥应拒绝: %v", err)
	}
	if _, err := c2.Test(context.Background(), Update{Enabled: true, BaseURL: "https://evil.example.com/v1", Model: "m", MaxPerHour: 5}); err != ErrKeyRebind {
		t.Fatalf("测试连接同样不能把原密钥发到新地址: %v", err)
	}
	// 不使用密钥：清除界面密钥，也不再使用环境变量中的密钥
	if v, _, err := c2.Apply(Update{Enabled: true, BaseURL: srv.URL + "/v1", Model: "m", ClearKey: true, MaxPerHour: 5}, "bob"); err != nil || v.KeySet || v.KeySource != "" {
		t.Fatalf("清除密钥: %+v %v", v, err)
	}
	c2.Triage(context.Background(), "x")
	if a := auths[len(auths)-1]; a != "" {
		t.Fatalf("清除后不应发送任何密钥: %q", a)
	}
	// 已保存的配置被改坏：停用而不是带着无效配置运行
	os.WriteFile(path, []byte(`{"enabled":true,"base_url":"http://api.example.com/v1","model":"m"}`), 0o600)
	c3 := New(config.AIConfig{}, env)
	if loaded, err := c3.SetPath(path); !loaded || err == nil || c3.Enabled() {
		t.Fatalf("无效的已保存配置应停用: %v %v", loaded, err)
	}
}

// 测试连接：使用界面上尚未保存的配置，不改变当前配置；接口错误返回原因且不回显密钥。
func TestSettingsTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-right-key-000000" {
			http.Error(w, `{"error":"invalid api key: `+r.Header.Get("Authorization")+`"}`, http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"OK"}}]}`))
	}))
	defer srv.Close()
	c := New(config.AIConfig{}, nil)
	res, err := c.Test(context.Background(), Update{BaseURL: srv.URL + "/v1", Model: "m", APIKey: "sk-wrong-key-111111"})
	if err != nil || res.OK || !strings.Contains(res.Error, "401") || strings.Contains(res.Error, "sk-wrong-key-111111") {
		t.Fatalf("错误的密钥: %+v %v", res, err)
	}
	res, err = c.Test(context.Background(), Update{BaseURL: srv.URL + "/v1", Model: "m", APIKey: "sk-right-key-000000"})
	if err != nil || !res.OK || res.Reply != "OK" || res.Model != "m" {
		t.Fatalf("正确的配置: %+v %v", res, err)
	}
	if c.Enabled() || c.View().KeySet {
		t.Fatal("测试连接不应保存配置")
	}
	if _, err := c.Test(context.Background(), Update{BaseURL: srv.URL + "/v1"}); err == nil {
		t.Fatal("缺少模型名称时不应发出请求")
	}
}

func TestAIConfigValidate(t *testing.T) {
	for _, c := range []struct {
		cfg config.Config
		ok  bool
	}{
		{config.Config{AI: config.AIConfig{Enabled: true, BaseURL: "https://api.deepseek.com/v1", Model: "deepseek-chat"}}, true},
		{config.Config{AI: config.AIConfig{Enabled: true, BaseURL: "http://10.0.0.20:8000/v1", Model: "qwen"}}, true},
		{config.Config{AI: config.AIConfig{Enabled: true, BaseURL: "http://api.example.com/v1", Model: "x"}}, false},
		{config.Config{AI: config.AIConfig{Enabled: true, BaseURL: "https://u:p@api.example.com/v1", Model: "x"}}, false},
		{config.Config{AI: config.AIConfig{Enabled: true, BaseURL: "https://api.example.com/v1"}}, false},
	} {
		if err := c.cfg.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.cfg.AI, err)
		}
	}
}

// 推理模型与非严格 JSON 的输出：思考过程中的花括号、结束标签、草稿不影响取最终结论；字段类型的常见变体都能识别。
func TestParseVerdictReasoningOutput(t *testing.T) {
	answer := `{"verdict":"attack","confidence":90,"summary":"SQL 注入扫描"}`
	for _, c := range []struct {
		name, text, verdict string
		confidence          int
	}{
		{"思考过程含花括号", "<think>\n要输出 {\"verdict\":...} 格式，先写草稿 {\"verdict\":\"uncertain\",\"confidence\":10}\n</think>\n\n" + answer, "attack", 90},
		{"只有结束标签", "要输出 {verdict} 格式\n</think>\n" + answer, "attack", 90},
		{"思考后带代码块", "<think>想想</think>\n```json\n" + answer + "\n```", "attack", 90},
		{"正文中先照抄模板再作答", `格式：{"verdict":"attack|false_positive|uncertain","summary":"x"} 结论：` + answer, "attack", 90},
		{"结论嵌套在外层对象", `{"result":` + answer + `}`, "attack", 90},
		{"多个候选取最后一个", `{"verdict":"uncertain","confidence":1} {"verdict":"false_positive","confidence":70}`, "false_positive", 70},
		{"置信度为百分比字符串", `{"verdict":"attack","confidence":"85%"}`, "attack", 85},
		{"置信度为小数", `{"verdict":"attack","confidence":0.85}`, "attack", 85},
		{"中文结论", `{"verdict":"疑似误报","confidence":60}`, "false_positive", 60},
		{"中文否定不算攻击", `{"verdict":"非攻击","confidence":60}`, "false_positive", 60},
		{"字段名大小写不同", `{"Verdict":"ATTACK","Confidence":70}`, "attack", 70},
	} {
		v := ParseVerdict(c.text)
		if v.Unparsed || v.Verdict != c.verdict || v.Confidence != c.confidence {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
	if v := ParseVerdict(`{"verdict":"attack","reasons":"单个依据","actions":["封禁",1]}`); len(v.Reasons) != 1 || v.Reasons[0] != "单个依据" || len(v.Actions) != 2 {
		t.Errorf("依据与建议的变体: %+v", v)
	}
	for _, c := range []struct{ name, text string }{
		{"思考被截断", "<think>先看证据 {\"verdict\":\"attack\"} 还需要"},
		{"只照抄模板", `{"verdict":"attack|false_positive|uncertain","confidence":1}`},
		{"大量花括号不卡死", strings.Repeat("{", 1<<20)},
		{"空输出", ""},
	} {
		if v := ParseVerdict(c.text); !v.Unparsed || v.Verdict != "uncertain" {
			t.Errorf("%s 应未得到结论: %+v", c.name, v.Verdict)
		}
	}
}

// 推理模型：reasoning_content 独立返回、思考用完输出长度时重试一次更高的上限；仍然失败时说明原因，
// 处置记录能看出是没有结论，而不是模型判断为无法判断。
func TestTriageReasoningModel(t *testing.T) {
	var calls []map[string]any
	reply := func(n int) string { return "" }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		calls = append(calls, req)
		w.Write([]byte(reply(len(calls))))
	}))
	defer srv.Close()
	const truncated = `{"choices":[{"message":{"content":null,"reasoning_content":"先看证据"},"finish_reason":"length"}]}`
	const good = `{"choices":[{"message":{"content":"{\"verdict\":\"attack\",\"confidence\":88,\"summary\":\"注入\"}","reasoning_content":"先看证据"},"finish_reason":"stop"}]}`
	c := New(config.AIConfig{Enabled: true, BaseURL: srv.URL + "/v1", Model: "Qwen3.6-35B-A3B-FP8", MaxPerHour: 40}, nil)
	c.backoff = time.Millisecond
	tokens := func(i int) int { return int(calls[i]["max_tokens"].(float64)) }

	reply = func(int) string { return good }
	v, _, err := c.Triage(context.Background(), "事件摘要")
	if err != nil || v.Verdict != "attack" || v.Confidence != 88 || len(calls) != 1 || tokens(0) != triageMaxTokens {
		t.Fatalf("独立的思考字段不影响解析: %+v %v calls=%d", v, err, len(calls))
	}
	// vLLM：通过参数关闭思考、要求 JSON 输出，不改动提示文字
	kw, _ := calls[0]["chat_template_kwargs"].(map[string]any)
	if kw["enable_thinking"] != false || calls[0]["response_format"] == nil {
		t.Fatalf("应请求关闭思考与 JSON 输出: %+v", calls[0])
	}
	if got := calls[0]["messages"].([]any)[1].(map[string]any)["content"]; got != "事件摘要" {
		t.Fatalf("能用参数关闭思考时不应改动提示: %v", got)
	}

	// 第一次被截断，提高上限重试后得到结论
	calls = nil
	reply = func(n int) string {
		if n == 1 {
			return truncated
		}
		return good
	}
	if v, _, err = c.Triage(context.Background(), "x"); err != nil || v.Unparsed || v.Verdict != "attack" || len(calls) != 2 || tokens(1) != triageMaxTokens*2 {
		t.Fatalf("截断后应重试: %+v %v calls=%d", v, err, len(calls))
	}

	// 重试仍被截断：只重试一次，说明原因并展示思考过程
	calls = nil
	reply = func(int) string { return truncated }
	v, _, err = c.Triage(context.Background(), "x")
	if err != nil || !v.Unparsed || len(calls) != 2 || !strings.Contains(v.Summary, "长度上限") || v.Raw != "先看证据" {
		t.Fatalf("重试后仍截断: %+v %v calls=%d", v, err, len(calls))
	}
	if n := v.Note(); !strings.Contains(n, "未得到结论") || strings.Contains(n, "置信度") {
		t.Fatalf("处置记录不应写成模型判断: %s", n)
	}
	if st := c.Status(); st.Adapt == nil || !st.Adapt.Thinks || st.Adapt.Parsed != 2 || st.Adapt.Unparsed != 1 || st.Adapt.Truncated != 2 {
		t.Fatalf("应统计模型的研判表现: %+v", st.Adapt)
	}

	// 回复不是 JSON：请模型转换格式；其他模型不请求关闭思考
	calls = nil
	reply = func(n int) string {
		if n == 1 {
			return `{"choices":[{"message":{"content":"我认为这是攻击"},"finish_reason":"stop"}]}`
		}
		return good
	}
	c2 := New(config.AIConfig{Enabled: true, BaseURL: srv.URL + "/v1", Model: "deepseek-chat", MaxPerHour: 40}, nil)
	v, _, _ = c2.Triage(context.Background(), "x")
	if v.Unparsed || v.Verdict != "attack" || len(calls) != 2 || calls[0]["chat_template_kwargs"] != nil {
		t.Fatalf("应修复格式: %+v calls=%d", v, len(calls))
	}
	if got := calls[1]["messages"].([]any)[1].(map[string]any)["content"]; got != "我认为这是攻击" {
		t.Fatalf("格式修复应发送模型的回复: %v", got)
	}
	if st := c2.Status(); st.Adapt.Repaired != 1 {
		t.Fatalf("修复计数: %+v", st.Adapt)
	}

	// 修复也失败：说明原因并保留原文
	calls = nil
	reply = func(int) string {
		return `{"choices":[{"message":{"content":"我认为这是攻击"},"finish_reason":"stop"}]}`
	}
	v, _, _ = c2.Triage(context.Background(), "x")
	if !v.Unparsed || len(calls) != 2 || !strings.Contains(v.Summary, "JSON") || v.Raw != "我认为这是攻击" {
		t.Fatalf("非 JSON 回复: %+v calls=%d", v, len(calls))
	}

	// JSON 模式下返回空内容：学到后不再发送 response_format
	calls = nil
	reply = func(n int) string {
		if n == 1 {
			return `{"choices":[{"message":{"content":""},"finish_reason":"stop"}]}`
		}
		return good
	}
	c3 := New(config.AIConfig{Enabled: true, BaseURL: srv.URL + "/v1", Model: "local-model", MaxPerHour: 40}, nil)
	if v, _, _ = c3.Triage(context.Background(), "x"); v.Unparsed || len(calls) != 2 || calls[1]["response_format"] != nil {
		t.Fatalf("空内容应关闭 JSON 模式重试: %+v %v", v, calls)
	}

	// 测试连接：推理模型被 16 个 token 截断也算连通，并给出提示
	reply = func(int) string {
		return `{"choices":[{"message":{"content":"<think>好的，用户"},"finish_reason":"length"}]}`
	}
	r, err := c.Test(context.Background(), Update{BaseURL: srv.URL + "/v1", Model: "m", MaxPerHour: 40})
	if err != nil || !r.OK || r.Reply != "" || !strings.Contains(r.Note, "推理模型") {
		t.Fatalf("测试连接: %+v %v", r, err)
	}
}

// Anthropic 协议：路径、认证头、请求体、内容块与结束原因；x-api-key 被拒绝时自动改用 Authorization。
func TestAnthropicProtocol(t *testing.T) {
	var got map[string]any
	var hdr http.Header
	var path string
	bearerOnly := false
	reply := `{"content":[{"type":"thinking","thinking":"先分析"},{"type":"text","text":"{\"verdict\":\"false_positive\",\"confidence\":75,\"summary\":\"业务请求\"}"}],"stop_reason":"end_turn"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, hdr, path = nil, r.Header.Clone(), r.URL.Path
		json.NewDecoder(r.Body).Decode(&got)
		if bearerOnly && r.Header.Get("Authorization") == "" {
			http.Error(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`, http.StatusUnauthorized)
			return
		}
		w.Write([]byte(reply))
	}))
	defer srv.Close()
	c := New(config.AIConfig{}, nil)
	c.backoff = time.Millisecond
	// 只填主机：自动补 /v1
	if _, _, err := c.Apply(Update{Enabled: true, Protocol: "anthropic", BaseURL: srv.URL, Model: "anthropic-test-model", APIKey: "sk-ant-test-000000", MaxPerHour: 20}, "admin"); err != nil {
		t.Fatal(err)
	}
	v, _, err := c.Triage(context.Background(), "事件摘要")
	if err != nil || v.Verdict != "false_positive" || v.Confidence != 75 {
		t.Fatalf("研判: %+v %v", v, err)
	}
	if path != "/v1/messages" || hdr.Get("x-api-key") != "sk-ant-test-000000" || hdr.Get("anthropic-version") == "" || hdr.Get("Authorization") != "" {
		t.Fatalf("请求: %s %v", path, hdr)
	}
	if got["system"] == nil || got["temperature"] != nil || got["thinking"] != nil || got["response_format"] != nil || int(got["max_tokens"].(float64)) != anthropicMaxTokens {
		t.Fatalf("请求体: %+v", got)
	}
	if msgs := got["messages"].([]any); len(msgs) != 1 || msgs[0].(map[string]any)["role"] != "user" {
		t.Fatalf("messages 只应含用户消息: %+v", msgs)
	}
	if st := c.Status(); st.Protocol != "anthropic" || !st.Adapt.Thinks {
		t.Fatalf("状态: %+v", st)
	}

	// 网关要求 Authorization：自动改用并记住
	bearerOnly = true
	if v, _, err = c.Triage(context.Background(), "x"); err != nil || v.Verdict != "false_positive" {
		t.Fatalf("改用 Authorization: %+v %v", v, err)
	}
	if hdr.Get("Authorization") != "Bearer sk-ant-test-000000" || !c.Status().Adapt.AuthBearer {
		t.Fatalf("认证头: %v", hdr)
	}

	// 模型拒绝回答：说明原因，不重试
	reply = `{"content":[],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"内容策略"}}`
	if v, _, err = c.Triage(context.Background(), "x"); err != nil || !v.Unparsed || !strings.Contains(v.Summary, "拒绝回答") || !strings.Contains(v.Summary, "cyber") {
		t.Fatalf("拒绝回答: %+v %v", v, err)
	}
	if c.Status().Adapt.Refused != 1 {
		t.Fatalf("拒答计数: %+v", c.Status().Adapt)
	}
	// 输出被截断映射为 length
	reply = `{"content":[{"type":"text","text":"{\"verd"}],"stop_reason":"max_tokens"}`
	v, _, _ = c.Triage(context.Background(), "x")
	if !v.Unparsed || !strings.Contains(v.Summary, "长度上限") || int(got["max_tokens"].(float64)) != anthropicMaxTokens*2 {
		t.Fatalf("截断: %+v %+v", v, got)
	}
}

// 模型适配：从请求被拒绝的错误信息中学习，并记住，下一次不再出错；瞬时错误重试一次。
func TestAdaptiveRequests(t *testing.T) {
	var calls []map[string]any
	handler := func(int, map[string]any) (int, string) { return 200, "" }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		calls = append(calls, req)
		code, body := handler(len(calls), req)
		w.WriteHeader(code)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	const good = `{"choices":[{"message":{"content":"{\"verdict\":\"attack\",\"confidence\":50}"},"finish_reason":"stop"}]}`
	newClient := func() *Client {
		c := New(config.AIConfig{Enabled: true, BaseURL: srv.URL + "/v1", Model: "Qwen3.6-35B", MaxPerHour: 100}, nil)
		c.backoff = time.Millisecond
		return c
	}
	for _, tc := range []struct {
		name, errMsg string
		check        func(req map[string]any, p Profile) bool
	}{
		{"vLLM 上下文长度（新格式）", `{"message":"'max_tokens' or 'max_completion_tokens' is too large: 4096. This model's maximum context length is 4096 tokens and your request has 1000 input tokens (4096 > 4096 - 1000)."}`,
			func(req map[string]any, p Profile) bool {
				return p.MaxTokensCap == 3064 && req["max_tokens"].(float64) == 3064
			}},
		{"vLLM 上下文长度（旧格式）", `{"message":"This model's maximum context length is 4096 tokens. However, you requested 5096 tokens (1000 in the messages, 4096 in the completion)."}`,
			func(req map[string]any, p Profile) bool { return p.MaxTokensCap == 3064 }},
		{"输出上限", `{"error":{"message":"max_tokens: 4096 > 1024, which is the maximum allowed number of output tokens"}}`,
			func(req map[string]any, p Profile) bool { return p.MaxTokensCap == 1024 }},
		{"要求 max_completion_tokens", `{"error":{"message":"Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead."}}`,
			func(req map[string]any, p Profile) bool {
				return p.UseMaxCompletion && req["max_tokens"] == nil && req["max_completion_tokens"] != nil
			}},
		{"不支持 temperature", `{"error":{"message":"Unsupported value: 'temperature' does not support 0.2"}}`,
			func(req map[string]any, p Profile) bool { return p.NoTemperature && req["temperature"] == nil }},
		{"不支持 response_format", `{"error":{"message":"response_format is not supported by this model"}}`,
			func(req map[string]any, p Profile) bool {
				return p.NoResponseFormat && req["response_format"] == nil && req["chat_template_kwargs"] != nil
			}},
		{"不支持 chat_template_kwargs", `{"error":{"message":"Unrecognized request argument supplied: chat_template_kwargs"}}`,
			func(req map[string]any, p Profile) bool {
				last := req["messages"].([]any)[1].(map[string]any)["content"].(string)
				return p.NoChatKwargs && req["chat_template_kwargs"] == nil && strings.HasSuffix(last, "/no_think")
			}},
		{"未点名参数", `{"error":{"message":"invalid request"}}`,
			func(req map[string]any, p Profile) bool {
				return p.NoChatKwargs && p.NoResponseFormat && req["response_format"] == nil
			}},
	} {
		c := newClient()
		calls = nil
		handler = func(n int, _ map[string]any) (int, string) {
			if n == 1 {
				return 400, tc.errMsg
			}
			return 200, good
		}
		v, _, err := c.Triage(context.Background(), "x")
		if err != nil || v.Unparsed || len(calls) != 2 {
			t.Errorf("%s: %+v %v calls=%d", tc.name, v, err, len(calls))
			continue
		}
		p := *c.Status().Adapt
		if !tc.check(calls[1], p) {
			t.Errorf("%s: 重试请求 %+v 适配 %+v", tc.name, calls[1], p)
		}
		if len(p.Adapted) == 0 {
			t.Errorf("%s: 应记录适配", tc.name)
		}
		// 学到之后：下一次直接成功，不再多发一次失败的请求
		calls = nil
		handler = func(int, map[string]any) (int, string) { return 200, good }
		c.Triage(context.Background(), "x")
		if len(calls) != 1 || !tc.check(calls[0], *c.Status().Adapt) {
			t.Errorf("%s: 应记住适配结果: %+v", tc.name, calls)
		}
	}

	// 参数都已去掉仍被拒绝：返回错误，不无限重试
	c := newClient()
	calls = nil
	handler = func(int, map[string]any) (int, string) { return 400, `{"error":{"message":"bad model"}}` }
	if _, _, err := c.Triage(context.Background(), "x"); err == nil || len(calls) > 3 {
		t.Fatalf("持续被拒绝: %v calls=%d", err, len(calls))
	}

	// 瞬时错误重试一次；持续失败时返回错误
	c = newClient()
	calls = nil
	handler = func(n int, _ map[string]any) (int, string) {
		if n == 1 {
			return 503, "overloaded"
		}
		return 200, good
	}
	if v, _, err := c.Triage(context.Background(), "x"); err != nil || v.Unparsed || len(calls) != 2 {
		t.Fatalf("503 应重试: %+v %v calls=%d", v, err, len(calls))
	}
	calls = nil
	handler = func(int, map[string]any) (int, string) { return 503, "overloaded" }
	if _, _, err := c.Triage(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "503") || len(calls) != 2 {
		t.Fatalf("持续 503: %v calls=%d", err, len(calls))
	}

	// 超时：提示调大超时时间；界面修改的超时立即生效
	c = newClient()
	c.mu.Lock()
	c.set.TimeoutSec = 1
	c.mu.Unlock()
	blocked := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(blocked) // 先放行处理函数，再关闭服务
	c.mu.Lock()
	c.set.BaseURL = slow.URL + "/v1"
	c.mu.Unlock()
	if _, _, err := c.Triage(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("超时提示: %v", err)
	}
}

// 适配信息与界面配置一起保存，重启后不用重新学习；配置来自配置文件时不写文件（否则重启后会被当成界面配置）。
func TestProfilePersist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if req["response_format"] != nil {
			http.Error(w, `{"error":{"message":"response_format not supported"}}`, 400)
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"attack\",\"confidence\":50}"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ai.json")
	yaml := New(config.AIConfig{Enabled: true, BaseURL: srv.URL + "/v1", Model: "m"}, nil)
	yaml.SetPath(path)
	yaml.Triage(context.Background(), "x")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("配置来自配置文件时不应写出 ai.json")
	}
	c := New(config.AIConfig{}, nil)
	c.SetPath(path)
	if _, _, err := c.Apply(Update{Enabled: true, BaseURL: srv.URL + "/v1", Model: "m", MaxPerHour: 20}, "admin"); err != nil {
		t.Fatal(err)
	}
	c.Triage(context.Background(), "x")
	c2 := New(config.AIConfig{}, nil)
	if loaded, err := c2.SetPath(path); !loaded || err != nil {
		t.Fatal(err)
	}
	if st := c2.Status(); st.Adapt == nil || !st.Adapt.NoResponseFormat || st.Adapt.Parsed != 1 {
		t.Fatalf("重启后应保留适配信息: %+v", st.Adapt)
	}
}

// 连接测试：协议选错时自动切换；模型名称不存在时列出接口提供的模型；地址规范化。
func TestDetectProtocolAndModels(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/v1/messages":
			w.Write([]byte(`{"content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn"}`))
		case "/v1/models":
			w.Write([]byte(`{"data":[{"id":"qwen-b"},{"id":"qwen-a"}]}`))
		default:
			http.Error(w, `{"detail":"Not Found"}`, 404)
		}
	}))
	defer srv.Close()
	c := New(config.AIConfig{}, nil)
	r, err := c.Test(context.Background(), Update{BaseURL: srv.URL + "/v1/chat/completions", Model: "m", MaxPerHour: 20})
	if err != nil || !r.OK || r.Protocol != "anthropic" || !strings.Contains(r.Note, "自动切换") || r.Reply != "OK" {
		t.Fatalf("协议探测: %+v %v", r, err)
	}
	list, err := c.Models(context.Background(), Update{BaseURL: srv.URL, APIKey: "sk-list-000000", MaxPerHour: 20})
	if err != nil || len(list) != 2 || list[0] != "qwen-a" || auth != "Bearer sk-list-000000" {
		t.Fatalf("模型列表: %v %v auth=%q", list, err, auth)
	}
	if c.View().KeySet {
		t.Fatal("读取模型列表不应保存密钥")
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Write([]byte(`{"data":[{"id":"Qwen3.6-35B-A3B-FP8"}]}`))
			return
		}
		http.Error(w, `{"message":"The model 'wrong' does not exist."}`, 404)
	}))
	defer notFound.Close()
	r, err = c.Test(context.Background(), Update{BaseURL: notFound.URL + "/v1", Model: "wrong", MaxPerHour: 20})
	if err != nil || r.OK || len(r.Models) != 1 || r.Models[0] != "Qwen3.6-35B-A3B-FP8" || r.Protocol != "openai" {
		t.Fatalf("模型不存在: %+v %v", r, err)
	}
	if _, _, err := c.Apply(Update{Enabled: true, Protocol: "grpc", BaseURL: notFound.URL + "/v1", Model: "m", MaxPerHour: 20}, "a"); err == nil {
		t.Fatal("应拒绝未知协议")
	}
	for _, bad := range []Update{
		{Enabled: true, BaseURL: notFound.URL + "/v1", Model: "m", MaxPerHour: 20, MaxTokens: 10},
		{Enabled: true, BaseURL: notFound.URL + "/v1", Model: "m", MaxPerHour: 20, TimeoutSec: 5},
		{Enabled: true, BaseURL: notFound.URL + "/v1", Model: "m", MaxPerHour: 20, Thinking: "maybe"},
	} {
		if _, _, err := c.Apply(bad, "a"); err == nil {
			t.Errorf("应拒绝: %+v", bad)
		}
	}
}
