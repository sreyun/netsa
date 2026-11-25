package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netsa/internal/aiuse"
	"netsa/internal/assets"
	"netsa/internal/model"
)

func aiuseCall(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAIUseAPI(t *testing.T) {
	s, _ := testServer(t, "", "")
	h0 := s.Handler()
	var off map[string]any
	json.Unmarshal(get(h0, "/api/aiuse").Body.Bytes(), &off)
	if off["enabled"] != false {
		t.Fatalf("未开启时应返回 enabled=false：%v", off)
	}
	if rec := aiuseCall(h0, http.MethodPost, "/api/aiuse/services", `{"name":"x","domains":["x.example.com"]}`); rec.Code != http.StatusNotFound {
		t.Fatalf("未开启时登记服务应返回 404：%d", rec.Code)
	}

	m, err := aiuse.New(aiuse.Options{Location: time.Local, Policies: map[string]string{"chatgpt": "deny"}})
	if err != nil {
		t.Fatal(err)
	}
	s.AIUse = m
	as, err := assets.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAsset(assets.Asset{IP: "10.1.10.0/24", Name: "研发办公区", Owner: "张工", Dept: "研发部", Importance: "normal"}); err != nil {
		t.Fatal(err)
	}
	s.Assets = as
	h := s.Handler()
	now := time.Now()
	m.Observe(&model.Event{Kind: model.KindDNS, SrcIP: "10.1.10.5", Host: "chatgpt.com", RCode: "NOERROR", Time: now})
	m.Observe(&model.Event{Kind: model.KindDNS, SrcIP: "10.1.10.6", Host: "chat.deepseek.com", RCode: "NOERROR", Time: now})
	m.Observe(&model.Event{Kind: model.KindDNS, SrcIP: "10.2.0.7", Host: "chat.deepseek.com", RCode: "NOERROR", Time: now})
	m.Observe(&model.Event{Kind: model.KindDNS, SrcIP: "10.2.0.7", Host: "api.cheap-gpt-relay.com", RCode: "NOERROR", Time: now})

	var r struct {
		Enabled bool `json:"enabled"`
		Report  struct {
			Totals   aiuse.Totals       `json:"totals"`
			Subjects []aiuse.SubjectRow `json:"subjects"`
			Cands    []aiuse.Candidate  `json:"candidates"`
		} `json:"report"`
		Depts []DeptRow `json:"depts"`
	}
	rec := get(h, "/api/aiuse?range=today")
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || !r.Enabled {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if r.Report.Totals.Subjects != 3 || r.Report.Totals.DenySubjects != 1 || len(r.Report.Cands) != 1 {
		t.Fatalf("totals = %+v candidates = %v", r.Report.Totals, r.Report.Cands)
	}
	var dev *aiuse.SubjectRow
	for i := range r.Report.Subjects {
		if r.Report.Subjects[i].IP == "10.1.10.5" {
			dev = &r.Report.Subjects[i]
		}
	}
	if dev == nil || dev.Owner != "张工" || dev.Dept != "研发部" || !dev.Deny {
		t.Fatalf("终端应按资产台账显示使用者与部门：%+v", dev)
	}
	if len(r.Depts) != 2 || r.Depts[0].Dept != "研发部" || r.Depts[0].Subjects != 2 || r.Depts[0].Deny != 1 {
		t.Fatalf("depts = %+v", r.Depts)
	}

	// 导出 CSV：带 BOM，按终端 + 服务一行
	rec = get(h, "/api/aiuse/export?range=today")
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(rec.Body.String(), "\xEF\xBB\xBF"))).ReadAll()
	if err != nil || len(rows) != 4 || rows[0][0] != "终端" || !strings.HasPrefix(rec.Body.String(), "\xEF\xBB\xBF") {
		t.Fatalf("CSV = %v %v", err, rows)
	}

	// 服务目录：设定策略、登记、删除
	if rec := aiuseCall(h, http.MethodPut, "/api/aiuse/services/deepseek", `{"policy":"restrict"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"restrict"`) {
		t.Fatalf("设定策略：%d %s", rec.Code, rec.Body.String())
	}
	if rec := aiuseCall(h, http.MethodPut, "/api/aiuse/services/deepseek", `{"policy":"block"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("无效策略应返回 400：%d", rec.Code)
	}
	if rec := aiuseCall(h, http.MethodPut, "/api/aiuse/services/nope", `{"policy":"deny"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("不存在的服务应返回 404：%d", rec.Code)
	}
	rec = aiuseCall(h, http.MethodPost, "/api/aiuse/services", `{"name":"便宜中转站","category":"api","region":"domestic","policy":"deny","domains":["cheap-gpt-relay.com, relay2.example.com"]}`)
	var svc aiuse.Service
	if json.Unmarshal(rec.Body.Bytes(), &svc); rec.Code != 200 || len(svc.Domains) != 2 || svc.Policy != "deny" {
		t.Fatalf("登记服务：%d %s", rec.Code, rec.Body.String())
	}
	if rec := aiuseCall(h, http.MethodPost, "/api/aiuse/services", `{"name":"太宽","domains":["google.com"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("过宽的域名应返回 400：%d", rec.Code)
	}
	var cat struct {
		Services []aiuse.CatalogItem `json:"services"`
	}
	json.Unmarshal(get(h, "/api/aiuse/services").Body.Bytes(), &cat)
	if len(cat.Services) < 70 || cat.Services[0].ID != svc.ID {
		t.Fatalf("目录中应有内置服务，页面登记的服务排在最前：%d", len(cat.Services))
	}
	if rec := aiuseCall(h, http.MethodDelete, "/api/aiuse/services/chatgpt", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("内置服务不能删除：%d", rec.Code)
	}
	if rec := aiuseCall(h, http.MethodDelete, "/api/aiuse/services/"+svc.ID, ""); rec.Code != 200 {
		t.Fatalf("删除页面登记的服务：%d %s", rec.Code, rec.Body.String())
	}

	// 疑似域名：忽略后不再列出
	m.Observe(&model.Event{Kind: model.KindDNS, SrcIP: "10.2.0.8", Host: "x.my-llm-box.com", RCode: "NOERROR", Time: now})
	if rec := aiuseCall(h, http.MethodPost, "/api/aiuse/candidates/my-llm-box.com/ignore", ""); rec.Code != 200 {
		t.Fatalf("忽略疑似域名：%d %s", rec.Code, rec.Body.String())
	}
	if rec := aiuseCall(h, http.MethodPost, "/api/aiuse/candidates/my-llm-box.com/drop", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("未知操作应返回 404：%d", rec.Code)
	}
	if strings.Contains(get(h, "/api/aiuse?range=today").Body.String(), "my-llm-box.com") {
		t.Fatal("忽略后仍列出")
	}

	// 周报中的 AI 使用摘要不列出终端
	rep := s.BuildPeriodReport("week", "recent")
	if rep.AIUse == nil || rep.AIUse.Subjects != 3 {
		t.Fatalf("周报摘要 = %+v", rep.AIUse)
	}
	b, _ := json.Marshal(rep.AIUse)
	if strings.Contains(string(b), "10.1.10.5") {
		t.Fatal("周报摘要不应包含终端地址")
	}
	found := false
	for _, line := range rep.Summary {
		if strings.Contains(line, "使用 AI 服务的终端 3 个") && strings.Contains(line, "禁止") {
			found = true
		}
	}
	if !found {
		t.Fatalf("周报结论中缺少 AI 使用：%v", rep.Summary)
	}
	var html strings.Builder
	if err := renderPeriodHTML(&html, rep, false); err != nil || !strings.Contains(html.String(), "附：AI 使用情况") {
		t.Fatalf("报告页缺少 AI 使用：%v", err)
	}
}
