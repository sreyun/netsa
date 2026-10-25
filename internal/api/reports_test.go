package api

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/assets"
	"netsa/internal/audit"
	"netsa/internal/model"
)

func TestPeriodRange(t *testing.T) {
	sat := time.Date(2026, 10, 24, 15, 0, 0, 0, time.Local)
	for _, c := range []struct{ kind, rng, from, to string }{
		{"week", "recent", "2026-10-18", "2026-10-24"},
		{"week", "last", "2026-10-12", "2026-10-18"},
		{"month", "recent", "2026-09-25", "2026-10-24"},
		{"month", "last", "2026-09-01", "2026-09-30"},
	} {
		f, to := periodRange(c.kind, c.rng, sat)
		if f.Format("2006-01-02") != c.from || to.Format("2006-01-02") != c.to {
			t.Errorf("%s/%s: %s ~ %s", c.kind, c.rng, f.Format("2006-01-02"), to.Format("2006-01-02"))
		}
	}
	// 周一查看上周
	f, to := periodRange("week", "last", time.Date(2026, 10, 26, 9, 0, 0, 0, time.Local))
	if f.Format("01-02") != "10-19" || to.Format("01-02") != "10-25" {
		t.Fatalf("周一的上周: %s ~ %s", f, to)
	}
}

func smtpSink(t *testing.T) (int, chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		c.Write([]byte("220 sink\r\n"))
		var b strings.Builder
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(l)); {
			case cmd == "DATA":
				c.Write([]byte("354 go\r\n"))
				for {
					d, err := r.ReadString('\n')
					if err != nil || d == ".\r\n" {
						break
					}
					b.WriteString(d)
				}
				c.Write([]byte("250 ok\r\n"))
			case cmd == "QUIT":
				c.Write([]byte("221 bye\r\n"))
				got <- b.String()
				return
			default:
				c.Write([]byte("250 ok\r\n"))
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func TestReportsComplianceAudit(t *testing.T) {
	s, st := testServer(t, "admin", "Adm1n-secret")
	var err error
	if s.Trail, err = audit.Open(t.TempDir(), 180); err != nil {
		t.Fatal(err)
	}
	s.Assets, _ = assets.Load("")
	al, ln, _ := assets.ParseAssetsCSV([]byte("IP,名称,负责人,重要性,等保级别\n10.0.1.10,官网,张三,核心,三级\n"))
	s.Assets.ImportAssets(al, ln, false)
	now := time.Now()
	for i := 0; i < 5; i++ {
		st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113." + strconv.Itoa(i+1), URI: "/x", Status: 403, Time: now.Add(-time.Duration(i) * time.Hour)},
			[]model.Hit{{RuleID: "r1", Name: "SQL注入", Category: "SQL注入", Severity: model.SevHigh, Result: model.ResultBlocked}})
	}
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	eye := newLocalUser(t, h, admin, "eye", "viewer")

	var rep PeriodReport
	rec := do(h, http.MethodGet, "/api/reports/periodic?period=week", "", eye)
	decode(t, rec.Body.Bytes(), &rep)
	if rec.Code != 200 || rep.Totals.Attacks != 5 || rep.Totals.Attackers != 5 || len(rep.Daily) != 7 || len(rep.Summary) < 3 || rep.Categories[0].Name != "SQL注入" {
		t.Fatalf("周报: %d %+v", rec.Code, rep)
	}
	rec = do(h, http.MethodGet, "/api/reports/periodic?period=month&range=last&format=html", "", eye)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(body, "安全月报") ||
		!strings.Contains(body, `src="/print.js"`) || strings.Contains(body, "ZgotmplZ") {
		t.Fatalf("月报 HTML: %d %s", rec.Code, body[:min(len(body), 300)])
	}
	// 邮件：未配置时报错；配置后发送到本地 SMTP
	if rec := do(h, http.MethodPost, "/api/reports/email", `{"period":"week","to":["a@example.com"]}`, admin); rec.Code != 502 {
		t.Fatalf("未配置邮件服务器: %d %s", rec.Code, rec.Body.String())
	}
	port, got := smtpSink(t)
	s.Cfg.Report.SMTP.Host, s.Cfg.Report.SMTP.Port, s.Cfg.Report.SMTP.From, s.Cfg.Report.SMTP.TLS = "127.0.0.1", port, "soc@example.com", "none"
	if rec := do(h, http.MethodPost, "/api/reports/email", `{"period":"week","to":["a@example.com"]}`, eye); rec.Code != 403 {
		t.Fatalf("只读账号不能发送邮件: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/reports/email", `{"period":"week","to":["a@example.com"]}`, admin); rec.Code != 200 {
		t.Fatalf("发送报告: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case m := <-got:
		if !strings.Contains(m, "Content-Disposition: attachment") || !strings.Contains(m, "To: a@example.com") {
			t.Fatalf("邮件: %s", m[:min(len(m), 500)])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("未收到邮件")
	}

	// 等保合规报告：仅管理员
	if rec := do(h, http.MethodGet, "/api/compliance/mlps", "", eye); rec.Code != 403 {
		t.Fatalf("只读账号不能查看合规报告: %d", rec.Code)
	}
	var cr ComplianceReport
	rec = do(h, http.MethodGet, "/api/compliance/mlps", "", admin)
	decode(t, rec.Body.Bytes(), &cr)
	if rec.Code != 200 || len(cr.Items) < 20 || cr.Pass+cr.Partial+cr.Fail+cr.NA != len(cr.Items) || cr.Systems[3] != 1 || cr.Items[0].Status == CompPass {
		t.Fatalf("合规报告: %d %+v", rec.Code, cr.Layers)
	}
	var https, retention *CompItem
	for i, it := range cr.Items {
		if strings.Contains(it.Control, "身份鉴别 c)") {
			https = &cr.Items[i]
		}
		if strings.Contains(it.Control, "网络安全法") {
			retention = &cr.Items[i]
		}
	}
	if https == nil || https.Status != CompFail || https.Advice == "" || retention == nil || retention.Status == CompPass {
		t.Fatalf("HTTPS / 日志留存检查项: %+v %+v", https, retention)
	}
	if rec := do(h, http.MethodGet, "/api/compliance/mlps?format=html", "", admin); rec.Code != 200 || !strings.Contains(rec.Body.String(), "等级保护") {
		t.Fatalf("合规报告 HTML: %d", rec.Code)
	}

	// 审计链：所有操作（含登录）均记录；只读账号无权查看；可导出、校验
	if rec := do(h, http.MethodGet, "/api/audit", "", eye); rec.Code != 403 {
		t.Fatalf("只读账号不能查看审计: %d", rec.Code)
	}
	var ar struct {
		Entries []audit.Entry
	}
	decode(t, do(h, http.MethodGet, "/api/audit?limit=500", "", admin).Body.Bytes(), &ar)
	joined := ""
	for _, e := range ar.Entries {
		joined += e.Action + "|" + e.User + ";"
	}
	for _, want := range []string{"查看安全报告", "发送安全报告邮件", "生成等保合规报告", "|admin;", "创建账号"} {
		if !strings.Contains(joined, want) {
			t.Errorf("审计链缺少 %q: %s", want, joined)
		}
	}
	rec = do(h, http.MethodGet, "/api/audit/export?format=csv", "", admin)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "生成等保合规报告") {
		t.Fatalf("导出审计: %d", rec.Code)
	}
	var vr audit.VerifyResult
	decode(t, do(h, http.MethodPost, "/api/audit/verify", `{}`, admin).Body.Bytes(), &vr)
	if !vr.OK || vr.Entries < 8 {
		t.Fatalf("审计链校验: %+v", vr)
	}
	var legacy []map[string]any
	decode(t, do(h, http.MethodGet, "/api/auth/audit", "", admin).Body.Bytes(), &legacy)
	if len(legacy) < 8 || legacy[0]["hash"] == nil {
		t.Fatalf("旧接口应返回审计链记录: %d", len(legacy))
	}
}
