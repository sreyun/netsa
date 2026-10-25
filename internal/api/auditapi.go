package api

import (
	"net/http"
	"strconv"
	"time"

	"netsa/internal/audit"
)

// auditQuery 解析审计检索条件：from / to、user、action（login 只看登录）、q、failed=1、limit。
func auditQuery(r *http.Request, defLimit, maxLimit int) audit.Query {
	q := r.URL.Query()
	return audit.Query{From: qtime(q.Get("from")), To: qtime(q.Get("to")), User: q.Get("user"), Action: q.Get("action"), Search: q.Get("q"),
		Failed: q.Get("failed") == "1", Limit: clamp(qint(r, "limit", defLimit), 1, maxLimit)}
}

// auditSearch 检索审计链（管理员）。
func (s *Server) auditSearch(w http.ResponseWriter, r *http.Request) {
	if s.Trail == nil {
		writeError(w, http.StatusServiceUnavailable, audit.ErrDisabled.Error())
		return
	}
	writeJSON(w, map[string]any{"entries": s.Trail.Search(auditQuery(r, 200, 5000)), "stats": s.Trail.Stats()})
}

// auditExport 导出审计记录（CSV / JSONL），导出操作本身也记入审计。
func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	if s.Trail == nil {
		writeError(w, http.StatusServiceUnavailable, audit.ErrDisabled.Error())
		return
	}
	q := auditQuery(r, 100000, 100000)
	format := r.URL.Query().Get("format")
	ext, ctype := "csv", "text/csv; charset=utf-8"
	if format == "jsonl" {
		ext, ctype = "jsonl", "application/x-ndjson"
	}
	s.audit(r, "导出审计记录", "格式 "+ext+"，最多 "+strconv.Itoa(q.Limit)+" 条", nil)
	extendDeadline(w, 2*time.Minute)
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="netsa-audit-`+time.Now().Format("20060102-150405")+`.`+ext+`"`)
	w.Header().Set("Cache-Control", "no-store")
	s.Trail.Export(w, q, format, s.now().Location())
}

// auditVerify 校验审计链的完整性。
func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	if s.Trail == nil {
		writeError(w, http.StatusServiceUnavailable, audit.ErrDisabled.Error())
		return
	}
	extendDeadline(w, 2*time.Minute)
	res := s.Trail.Verify()
	var err error
	if !res.OK {
		err = errAuditBroken
	}
	s.audit(r, "校验审计链完整性", strconv.Itoa(res.Entries)+" 条记录", err)
	writeJSON(w, res)
}

type auditErr string

func (e auditErr) Error() string { return string(e) }

const errAuditBroken = auditErr("审计链校验未通过")
