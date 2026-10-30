package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netsa/internal/ai"
	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 先脱敏再截断：内网地址跨过截断位置时，不能以残缺形式（脱敏规则无法识别）发给外部模型。
func TestIncidentFactsMaskBeforeClip(t *testing.T) {
	s, st := testServer(t, "", "")
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", Method: "GET", URI: "/x", Time: time.Now()},
		[]model.Hit{{RuleID: "r", Name: "SQL注入", Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultPassed,
			Evidence: strings.Repeat("a", 290) + " 10.20.30.40"}}) // 截断位置落在地址中间（第 300 个字符）
	facts := s.incidentFacts(st.Incident(1), ai.NewMasker(true))
	if strings.Contains(facts, "10.20.30") || !strings.Contains(facts, "203.0.113.9") {
		t.Fatalf("内网地址被截断后未脱敏:\n%s", facts)
	}
}

// 事件 AI 研判：发送前脱敏，结论写入处置记录；未启用时返回 404。
func TestIncidentAI(t *testing.T) {
	var sent string
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct{ Content string }
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &req)
		sent = req.Messages[len(req.Messages)-1].Content
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"attack\",\"confidence\":85,\"summary\":\"针对内网主机的 SQL 注入\",\"actions\":[\"封禁来源\"]}"}}]}`))
	}))
	defer llm.Close()

	s, st := testServer(t, "", "")
	h := s.Handler()
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", Host: "10.0.0.15", Method: "GET",
		URI: "/login?user=a&password=Secret123", Time: time.Now()},
		[]model.Hit{{RuleID: "sqli-bool", Name: "SQL注入", Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultPassed, Evidence: "password=Secret123"}})
	if rec := do(h, http.MethodPost, "/api/incidents/1/ai", "", nil); rec.Code != 404 {
		t.Fatalf("未启用时应返回 404: %d", rec.Code)
	}
	s.AI = ai.New(config.AIConfig{Enabled: true, BaseURL: llm.URL + "/v1", Model: "deepseek-chat"}, func(string) string { return "" })
	rec := do(h, http.MethodPost, "/api/incidents/1/ai", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"verdict":"attack"`) {
		t.Fatalf("研判: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(sent, "10.0.0.15") || strings.Contains(sent, "Secret123") || !strings.Contains(sent, "203.0.113.9") || !strings.Contains(sent, "内网主机#") {
		t.Fatalf("发送内容应脱敏内网地址与口令、保留攻击来源:\n%s", sent)
	}
	var d store.IncidentDetail
	decode(t, do(h, http.MethodGet, "/api/incidents/1", "", nil).Body.Bytes(), &d)
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0].Text, "AI 研判（deepseek-chat，仅供参考）：真实攻击") || !strings.HasPrefix(d.Notes[0].User, "AI") {
		t.Fatalf("处置记录: %+v", d.Notes)
	}
	if d.Status != store.IncOpen {
		t.Fatal("AI 结论不应改变事件状态")
	}
}
