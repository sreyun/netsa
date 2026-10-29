package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	if New(config.AIConfig{}, nil) != nil {
		t.Fatal("未启用时应返回 nil")
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
