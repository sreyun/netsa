package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
	"netsa/internal/rawlog"
)

// 原始日志检索：只读账号无权检索；运营分析员可检索、导出；管理员可校验完整性；操作均有审计。
func TestRawlogAPI(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	rl, err := rawlog.Open(context.Background(), rawlog.Options{Dir: t.TempDir(), RetentionDays: 180})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var evs []*model.Event
	var hits [][]model.Hit
	for i := 0; i < 20; i++ {
		evs = append(evs, &model.Event{Time: now.Add(-time.Duration(i) * time.Minute), Kind: model.KindWeb, Source: "nginx", SrcIP: "198.51.100.7",
			Raw: `198.51.100.7 "GET /p` + strconv.Itoa(i) + ` HTTP/1.1" 200`})
		hits = append(hits, nil)
	}
	rl.Write(evs, hits)
	rl.Close(5 * time.Second) // 关闭后分段已完整落盘
	s.RawLog = rl
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	ana := newLocalUser(t, h, admin, "ana", "analyst")
	eye := newLocalUser(t, h, admin, "eye", "viewer")
	q := "/api/rawlog/search?ip=198.51.100.7&from=" + strconv.FormatInt(now.Add(-2*time.Hour).Unix(), 10)
	if rec := do(h, http.MethodGet, q, "", eye); rec.Code != 403 {
		t.Fatalf("只读账号不能检索原始日志: %d", rec.Code)
	}
	var res rawlog.Result
	rec := do(h, http.MethodGet, q+"&limit=5", "", ana)
	decode(t, rec.Body.Bytes(), &res)
	if rec.Code != 200 || len(res.Records) != 5 || res.Records[0].Raw != evs[0].Raw {
		t.Fatalf("检索: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(h, http.MethodGet, strings.Replace(q, "search", "export", 1), "", ana)
	if rec.Code != 200 || strings.Count(rec.Body.String(), "\n") != 20 || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("导出: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/rawlog/search?from=1&to=99999999", "", ana); rec.Code != 400 {
		t.Fatalf("时间范围过大: %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/rawlog/verify", `{}`, ana); rec.Code != 403 {
		t.Fatalf("校验需要管理员: %d", rec.Code)
	}
	var v rawlog.VerifyResult
	rec = do(h, http.MethodPost, "/api/rawlog/verify", `{}`, admin)
	decode(t, rec.Body.Bytes(), &v)
	if rec.Code != 200 || !v.ChainOK || v.OK == 0 || len(v.Problems) != 0 {
		t.Fatalf("校验: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/api/rawlog/status", "", eye); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"retention_days":180`) {
		t.Fatalf("状态: %d %s", rec.Code, rec.Body.String())
	}
	audit := do(h, http.MethodGet, "/api/auth/audit", "", admin).Body.String()
	for _, want := range []string{"检索原始日志", "导出原始日志", "校验原始日志完整性"} {
		if !strings.Contains(audit, want) {
			t.Errorf("审计中缺少 %s", want)
		}
	}
}
