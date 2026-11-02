package playbook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/store"
)

func newStore() *store.Store { return store.New(1000, 1000, 5, time.Hour) }

func rec(s *store.Store, ip, cat string, sev model.Severity, proven bool) *model.Alert {
	res := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Method: "GET", URI: "/x", Status: 200, Time: time.Now()},
		[]model.Hit{{RuleID: "r-" + cat, Name: "攻击\"引号", Category: cat, Severity: sev, Phase: model.PhaseExploit, Result: model.ResultSuccess, Proven: proven}})
	return res.Alerts[0]
}

func TestPlaybookActions(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"key": "SEC-42"}})
	}))
	defer srv.Close()
	t.Setenv("TEST_TICKET_TOKEN", "tok")
	s := newStore()
	var blocked []string
	e, err := New([]config.PlaybookConfig{{
		Name: "WebShell 应急", When: config.PlaybookWhen{MinLevel: "critical", Categories: []string{"WebShell后门"}, Proven: true},
		Assign: "oncall", Status: "investigating", Note: "1. 隔离主机\n2. 排查后门", Ticket: "jira", RequestBlock: true,
	}}, []config.TicketConfig{{Name: "jira", URL: srv.URL, TokenEnv: "TEST_TICKET_TOKEN", IDField: "data.key",
		Body: `{"summary":{{json .Title}},"source":{{json .Source}},"proven":{{.Proven}}}`}}, s,
		func(ip, reason string, inc uint64, user string) error {
			blocked = append(blocked, ip+"|"+user)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	// 不满足条件的事件不执行
	low := rec(s, "203.0.113.1", "WebShell后门", model.SevHigh, false)
	e.process(context.Background(), low.IncidentID)
	if d := s.Incident(low.IncidentID); d.Assignee != "" || len(d.Notes) != 0 {
		t.Fatalf("不满足条件不应执行: %+v", d.Notes)
	}
	a := rec(s, "203.0.113.2", "WebShell后门", model.SevCritical, true)
	e.process(context.Background(), a.IncidentID)
	d := s.Incident(a.IncidentID)
	if d.Assignee != "oncall" || d.Status != store.IncInvestigating {
		t.Fatalf("应指派并开始处置: %+v", d.IncidentView)
	}
	last := d.Notes[len(d.Notes)-1]
	if last.User != actor || !strings.Contains(last.Action, "WebShell 应急") || !strings.Contains(last.Text, "隔离主机") || !strings.Contains(last.Text, "SEC-42") || !strings.Contains(last.Text, "待管理员审批") {
		t.Fatalf("处置记录: %+v", last)
	}
	if len(blocked) != 1 || blocked[0] != "203.0.113.2|"+actor {
		t.Fatalf("封禁申请: %v", blocked)
	}
	mu.Lock()
	var parsed map[string]any
	err = json.Unmarshal([]byte(bodies[0]), &parsed)
	got := auth
	n := len(bodies)
	mu.Unlock()
	if err != nil || parsed["source"] != "203.0.113.2" || parsed["proven"] != true || got != "Bearer tok" {
		t.Fatalf("工单请求（模板必须转义引号）: %v %v %s", parsed, err, got)
	}
	// 同一剧本只执行一次
	e.process(context.Background(), a.IncidentID)
	mu.Lock()
	again := len(bodies)
	mu.Unlock()
	if again != n || len(blocked) != 1 {
		t.Fatalf("不应重复执行: %d %v", again, blocked)
	}
	// 已关闭的事件不执行
	c := rec(s, "203.0.113.3", "WebShell后门", model.SevCritical, true)
	s.UpdateIncidents([]uint64{c.IncidentID}, "ana", store.IncidentUpdate{Status: store.IncFalsePositive, Note: "误报"})
	e.process(context.Background(), c.IncidentID)
	mu.Lock()
	if len(bodies) != n {
		t.Fatal("已关闭的事件不应执行")
	}
	mu.Unlock()
}

// 工单系统不可用不影响其他动作；失败写入处置记录，不会反复重试。
func TestTicketFailure(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(500)
	}))
	defer srv.Close()
	s := newStore()
	e, err := New([]config.PlaybookConfig{{Name: "p", Note: "步骤", Ticket: "t"}}, []config.TicketConfig{{Name: "t", URL: srv.URL}}, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := rec(s, "203.0.113.1", "SQL注入", model.SevHigh, false)
	e.process(context.Background(), a.IncidentID)
	e.process(context.Background(), a.IncidentID)
	d := s.Incident(a.IncidentID)
	if calls != 1 || !strings.Contains(d.Notes[0].Text, "创建工单失败") || !strings.Contains(d.Notes[0].Text, "步骤") {
		t.Fatalf("calls=%d %+v", calls, d.Notes)
	}
}

func TestQueueAndValidation(t *testing.T) {
	if e, err := New(nil, nil, nil, nil); e != nil || err != nil {
		t.Fatal("没有剧本应返回 nil")
	}
	var nilEngine *Engine
	nilEngine.OnAlert(&model.Alert{IncidentID: 1})
	nilEngine.Run(context.Background())
	if _, err := New([]config.PlaybookConfig{{Name: "p", When: config.PlaybookWhen{MinLevel: "x"}}}, nil, nil, nil); err == nil {
		t.Error("等级无效应报错")
	}
	if _, err := New([]config.PlaybookConfig{{Name: "p"}}, []config.TicketConfig{{Name: "t", Body: "{{"}}, nil, nil); err == nil {
		t.Error("模板无效应报错")
	}
	s := newStore()
	e, _ := New([]config.PlaybookConfig{{Name: "p", Note: "步骤"}}, nil, s, nil)
	// 同一事件在队列中只排一次
	a := rec(s, "203.0.113.1", "SQL注入", model.SevHigh, false)
	e.OnAlert(a)
	e.OnAlert(a)
	if len(e.queue) != 1 {
		t.Fatalf("队列: %d", len(e.queue))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for len(s.Incident(a.IncidentID).Notes) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("后台应执行剧本")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if r, _ := e.Stats(); r != 1 {
		t.Fatalf("执行次数: %d", r)
	}
	e.OnAlert(&model.Alert{})
}
