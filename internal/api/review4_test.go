package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/rawlog"
	"netsa/internal/store"
)

func compItem(rep *ComplianceReport, control string) CompItem {
	for _, it := range rep.Items {
		if it.Control == control {
			return it
		}
	}
	return CompItem{}
}

// 等保自检：只配置了周报邮件、没有告警机器人时，报警类测评项不判为符合；经 HTTPS 反向代理访问、
// 或配置的访问地址是 https:// 时，平台访问判为已加密。
func TestComplianceNotifyAndHTTPS(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	s.Cfg.Report.SMTP.Host = "smtp.example.com"
	rep := s.BuildCompliance(nil)
	if it := compItem(rep, "8.1.3.3 入侵防范 d)"); it.Status == CompPass || it.Control == "" {
		t.Fatalf("没有告警机器人时报警项不应符合: %+v", it)
	}
	if it := compItem(rep, "8.1.4.1 身份鉴别 c)"); it.Status == CompPass {
		t.Fatalf("HTTP 访问不应判为加密: %+v", it)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/compliance/mlps", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if it := compItem(s.BuildCompliance(req), "8.1.4.1 身份鉴别 c)"); it.Status != CompPass {
		t.Fatalf("经 HTTPS 反向代理访问应判为加密: %+v", it)
	}
	s.Cfg.Alert.BaseURL = "https://sa.example.com"
	if it := compItem(s.BuildCompliance(nil), "8.1.4.1 身份鉴别 c)"); it.Status != CompPass {
		t.Fatalf("后台自检按配置的 https 访问地址判断: %+v", it)
	}
	// 配置中指定了 IDS 格式的数据源：重启后读到新行之前也算接入了威胁日志
	s.Cfg.Sources = append(s.Cfg.Sources, config.SourceConfig{Name: "ids", Type: "suricata"})
	if it := compItem(s.BuildCompliance(nil), "8.1.3.4 恶意代码和垃圾邮件防范 a)"); it.Status != CompPartial {
		t.Fatalf("配置了 IDS 数据源应为部分符合: %+v", it)
	}
}

// 周报 / 月报中的事件首次发现时间按报告的时区输出，与同页的生成时间一致。
func TestReportTimezone(t *testing.T) {
	sh := time.FixedZone("CST", 8*3600)
	first := time.Date(2026, 11, 9, 17, 15, 0, 0, time.UTC) // 北京时间 11-10 01:15
	r := &PeriodReport{Title: "安全周报", Generated: time.Date(2026, 11, 10, 1, 20, 0, 0, sh),
		Incidents: store.IncidentPeriod{Top: []store.IncidentView{{ID: 1, Title: "x", Severity: model.SevHigh, Status: store.IncOpen, FirstSeen: first}}}}
	var buf bytes.Buffer
	if err := renderPeriodHTML(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	if body := buf.String(); !strings.Contains(body, "2026-11-10 01:15") || strings.Contains(body, "2026-11-09 17:15") {
		t.Fatal("首次发现时间应换算到报告时区")
	}
}

// 取证包：同时生成的数量有限制；原始日志检索名额被占满时不阻塞，在说明中写明未包含原始日志。
func TestEvidenceLimits(t *testing.T) {
	s, st := testServer(t, "admin", "Adm1n-secret")
	rl, err := rawlog.Open(context.Background(), rawlog.Options{Dir: t.TempDir(), RetentionDays: 180})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close(5 * time.Second)
	s.RawLog = rl
	st.Record(&model.Event{Time: time.Now().Add(-time.Hour), Kind: model.KindWeb, SrcIP: "198.51.100.7", Host: "www.example.com", Method: "GET", URI: "/x", Status: 403},
		[]model.Hit{{RuleID: "cmd-inject", Name: "命令注入", Category: "命令/代码执行", Severity: model.SevHigh, Phase: model.PhaseExploit, Result: model.ResultBlocked}})
	inc := st.Alerts(store.AlertQuery{Limit: 10})[0].IncidentID
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	url := "/api/incidents/" + strconv.FormatUint(inc, 10) + "/evidence"

	for range cap(evidenceSem) {
		evidenceSem <- struct{}{}
	}
	rec := do(h, http.MethodGet, url, "", admin)
	for range cap(evidenceSem) {
		<-evidenceSem
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("同时生成的取证包达到上限应返回 429: %d", rec.Code)
	}

	old := evidenceRawWait
	evidenceRawWait = 50 * time.Millisecond
	defer func() { evidenceRawWait = old }()
	for range cap(rawSem) {
		rawSem <- struct{}{}
	}
	rec = do(h, http.MethodGet, url, "", admin)
	for range cap(rawSem) {
		<-rawSem
	}
	if rec.Code != 200 {
		t.Fatalf("导出: %d %s", rec.Code, rec.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var man evidenceManifest
	for _, f := range zr.File {
		if f.Name == "rawlog.log" {
			t.Fatal("检索名额被占满时不应包含原始日志")
		}
		if f.Name == "manifest.json" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			json.Unmarshal(b, &man)
		}
	}
	if !strings.Contains(strings.Join(man.Notes, "；"), "原始日志检索繁忙") {
		t.Fatalf("说明中应写明未包含原始日志: %v", man.Notes)
	}
}
