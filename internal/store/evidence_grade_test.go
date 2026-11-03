package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 严重需要响应码之外的证据：基线一致、兜底页面都不算成功，响应明显变大才算第二份证据。
func TestVerifySuccessEvidence(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	normal := func(host, uri string, size int64) {
		for i := 0; i < 8; i++ {
			s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: host, Method: "GET", URI: uri, Status: 200, Bytes: size, Time: now, UA: "m"}, nil)
		}
	}
	normal("a.example.com", "/", 5000)
	normal("a.example.com", "/item", 3000)
	attack := func(ip, uri string, size int64, cat, method string) *model.Alert {
		t.Helper()
		res := s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "a.example.com", Method: method, URI: uri, Status: 200, Bytes: size, Time: now, UA: "m"},
			[]model.Hit{{RuleID: "r-" + ip, Name: "r", Category: cat, Severity: model.SevHigh, Phase: model.PhaseExploit, Result: model.ResultSuccess}})
		if len(res.Alerts) != 1 {
			t.Fatalf("%s 应产生告警", ip)
		}
		return res.Alerts[0]
	}
	for _, c := range []struct {
		name, ip, uri string
		size          int64
		cat, method   string
		sev           model.Severity
		result        string
		proven        bool
	}{
		{"与接口基线一致", "203.0.113.1", "/item?id=1", 3000, "SQL注入", "GET", model.SevHigh, model.ResultPassed, false},
		{"与站点首页大小相同：兜底页面，最高中危", "203.0.113.2", "/view?f=x", 5000, "目录穿越/文件包含", "GET", model.SevMedium, model.ResultPassed, false},
		{"没有基线", "203.0.113.3", "/other?x=1", 1892, "SQL注入", "GET", model.SevHigh, model.ResultSuccess, false},
		{"响应变小不算证据", "203.0.113.4", "/item?id=2", 300, "SQL注入", "GET", model.SevHigh, model.ResultSuccess, false},
		{"响应明显大于基线", "203.0.113.5", "/item?id=3", 30000, "SQL注入", "GET", model.SevCritical, model.ResultSuccess, true},
		{"POST 与脚本交互", "203.0.113.6", "/x.php", 1234, "WebShell后门", "POST", model.SevCritical, model.ResultSuccess, true},
		{"GET 访问可疑脚本名不算交互", "203.0.113.7", "/y.php", 1235, "WebShell后门", "GET", model.SevHigh, model.ResultSuccess, false},
	} {
		a := attack(c.ip, c.uri, c.size, c.cat, c.method)
		if a.Severity != c.sev || a.Result != c.result || a.Proven != c.proven {
			t.Errorf("%s: %s/%s proven=%v，证据 %s", c.name, a.Severity, a.Result, a.Proven, a.Evidence)
		}
	}
	// 兜底页面上的 WebShell 探测：不是真实脚本，底线放宽一级
	if a := attack("203.0.113.8", "/shell.php", 5000, "WebShell后门", "POST"); a.Severity != model.SevMedium || a.Proven || !strings.Contains(a.Evidence, "兜底页面") {
		t.Errorf("兜底页面: %s proven=%v %s", a.Severity, a.Proven, a.Evidence)
	}

	// 基线随快照保存：重启后不需要重新学习
	path := filepath.Join(t.TempDir(), "s.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore()
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	res := s2.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.9", Host: "a.example.com", Method: "GET", URI: "/item?id=4", Status: 200, Bytes: 3000, Time: now, UA: "m"},
		[]model.Hit{{RuleID: "r9", Name: "r", Category: "SQL注入", Severity: model.SevHigh, Phase: model.PhaseExploit, Result: model.ResultSuccess}})
	if len(res.Alerts) != 1 || res.Alerts[0].Result != model.ResultPassed {
		t.Fatalf("重启后基线应仍然有效: %+v", res.Alerts)
	}
}

// 没有第二份证据的 Web 攻击，即使判为疑似成功，也不算高置信失陷。
func TestCompromisedRequiresProof(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	rec := func(ip, host string, proven bool) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: host, Method: "GET", URI: "/run?c=id", Status: 200, Bytes: 100, Time: now},
			[]model.Hit{{RuleID: "cmd", Name: "cmd", Category: "命令/代码执行", Severity: model.SevHigh, Phase: model.PhaseExploit, Result: model.ResultSuccess, Proven: proven}})
	}
	rec("203.0.113.1", "a.example.com", false)
	rec("203.0.113.2", "b.example.com", true)
	got := map[string]string{}
	for _, c := range s.CompromisedAssets() {
		got[c.Asset] = c.Confidence
	}
	if got["a.example.com/run"] != "medium" || got["b.example.com/run"] != "high" {
		t.Fatalf("失陷置信度: %v", got)
	}
}

// 升级时修正旧事件：旧规则只凭 2xx 判严重；失陷迹象类和已关闭的事件不变。
func TestIncidentMigrateGrade(t *testing.T) {
	now := time.Now()
	mk := func(status string, sev model.Severity, cat string, v int) *Incident {
		return &Incident{Status: status, Severity: sev, Categories: map[string]int{cat: 1}, Created: now, GradeV: v, Notes: []IncidentNote{}}
	}
	legacy := mk(IncOpen, model.SevCritical, "SQL注入", 0)
	legacy.migrateGrade(now)
	if legacy.Severity != model.SevHigh || legacy.GradeV != gradeVersion || len(legacy.Notes) != 1 || !legacy.Due.Equal(now.Add(slaFor(model.SevHigh, ""))) {
		t.Fatalf("旧事件应回落到高危: %+v", legacy)
	}
	for name, i := range map[string]*Incident{
		"失陷迹象": mk(IncOpen, model.SevCritical, "带外探测", 0),
		"已关闭":  mk(IncFalsePositive, model.SevCritical, "SQL注入", 0),
		"新版事件": mk(IncOpen, model.SevCritical, "SQL注入", gradeVersion),
	} {
		i.migrateGrade(now)
		if i.Severity != model.SevCritical || len(i.Notes) != 0 {
			t.Errorf("%s 不应改变: %+v", name, i)
		}
	}
}
