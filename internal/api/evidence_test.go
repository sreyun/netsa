package api

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
	"netsa/internal/rawlog"
	"netsa/internal/store"
)

// 一键取证包：包含事件详情、时间线、来源画像、资产链路、原始日志与哈希清单；SHA256SUMS 与文件内容一致；
// 只读账号无权导出（包含原始日志）；导出写入操作审计；证据中以 = 开头的载荷不会在表格中被当作公式。
func TestIncidentEvidence(t *testing.T) {
	s, st := testServer(t, "admin", "Adm1n-secret")
	rl, err := rawlog.Open(context.Background(), rawlog.Options{Dir: t.TempDir(), RetentionDays: 180})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	var evs []*model.Event
	var hits [][]model.Hit
	for i := range 5 {
		ev := &model.Event{Time: now.Add(time.Duration(i) * time.Minute), Kind: model.KindWeb, Source: "nginx", SrcIP: "198.51.100.7", Host: "www.example.com",
			Method: "GET", URI: "/x?q==cmd|'/c calc'!A0", Status: 403, Raw: `198.51.100.7 "GET /x?q=` + strconv.Itoa(i) + ` HTTP/1.1" 403`}
		h := []model.Hit{{RuleID: "cmd-inject", Name: "命令注入", Category: "命令/代码执行", Severity: model.SevHigh, Phase: model.PhaseExploit,
			Result: model.ResultBlocked, Evidence: "=cmd|'/c calc'!A0"}}
		evs, hits = append(evs, ev), append(hits, h)
		st.Record(ev, h)
	}
	rl.Write(evs, hits)
	rl.Close(5 * time.Second)
	s.RawLog = rl
	inc := st.Alerts(store.AlertQuery{Limit: 10})[0].IncidentID
	if _, err := st.UpdateIncidents([]uint64{inc}, "ana", store.IncidentUpdate{Status: store.IncInvestigating, Note: "开始排查"}); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	ana := newLocalUser(t, h, admin, "ana", "analyst")
	eye := newLocalUser(t, h, admin, "eye", "viewer")
	url := "/api/incidents/" + strconv.FormatUint(inc, 10) + "/evidence"
	if rec := do(h, http.MethodGet, url, "", eye); rec.Code != 403 {
		t.Fatalf("只读账号不能导出取证包: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/incidents/99999/evidence", "", ana); rec.Code != 404 {
		t.Fatalf("事件不存在: %d", rec.Code)
	}
	rec := do(h, http.MethodGet, url, "", ana)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("导出: %d %s", rec.Code, rec.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = b
	}
	for _, want := range []string{"README.txt", "incident.json", "timeline.csv", "source.json", "chains.json", "rawlog.log", "manifest.json", "SHA256SUMS"} {
		if _, ok := files[want]; !ok {
			t.Errorf("取证包缺少 %s（实际 %v）", want, keys(files))
		}
	}
	if n := strings.Count(string(files["rawlog.log"]), "\n"); n != 5 {
		t.Errorf("原始日志应有 5 条: %d", n)
	}
	tl := string(files["timeline.csv"])
	if !strings.Contains(tl, "处置记录") || !strings.Contains(tl, "开始排查") || strings.Contains(tl, ",=cmd") || !strings.Contains(tl, "'=cmd") {
		t.Errorf("时间线应包含处置记录，并转义公式: %s", tl)
	}
	sc := bufio.NewScanner(bytes.NewReader(files["SHA256SUMS"]))
	n := 0
	for sc.Scan() {
		sum, name, _ := strings.Cut(sc.Text(), "  ")
		got := sha256.Sum256(files[name])
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s 的哈希不一致", name)
		}
		n++
	}
	if n != len(files)-2 { // 不含 README.txt 与 SHA256SUMS 自身
		t.Errorf("哈希清单条数 %d，文件 %d", n, len(files))
	}
	var man evidenceManifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil || man.Incident != inc || man.GeneratedBy != "ana" || man.Source != "198.51.100.7" {
		t.Fatalf("manifest: %+v %v", man, err)
	}
	if audit := do(h, http.MethodGet, "/api/auth/audit", "", admin).Body.String(); !strings.Contains(audit, "导出取证包") {
		t.Error("审计中缺少导出取证包")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
