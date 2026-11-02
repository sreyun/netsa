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
