package api

import (
	"net/http"
	"strings"
	"time"

	"netsa/internal/authscan"
)

// authScans 返回授权扫描登记：生效中的在前。
func (s *Server) authScans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"entries": s.AuthScan.List(), "active": s.AuthScan.Active(), "total": s.AuthScan.Total(), "enabled": s.AuthScan != nil})
}

type authScanForm struct {
	IP    string `json:"ip"`
	Start string `json:"start"` // RFC 3339 或 2006-01-02T15:04（按平台时区）；为空表示立即开始
	End   string `json:"end"`
	Hours int    `json:"hours"` // 不填结束时间时，从开始时间起的小时数
	Note  string `json:"note"`
}

// parseFormTime 解析表单时间：带时区的 RFC 3339，或页面日期时间控件的本地时间（按平台时区）。
func (s *Server) parseFormTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, true
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	loc := time.Local // 与页面展示时间所用的时区一致（日期时间控件的值按展示时区填写）
	if s.Cfg != nil {
		if tz := s.displayTimezone(); tz != "" {
			if l, err := time.LoadLocation(tz); err == nil {
				loc = l
			}
		}
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, v, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (s *Server) authScanCreate(w http.ResponseWriter, r *http.Request) {
	if s.AuthScan == nil {
		writeError(w, http.StatusServiceUnavailable, "授权扫描登记未启用")
		return
	}
	var f authScanForm
	if !decodeForm(w, r, &f) {
		return
	}
	start, ok1 := s.parseFormTime(f.Start)
	end, ok2 := s.parseFormTime(f.End)
	if !ok1 || !ok2 {
		writeError(w, http.StatusBadRequest, "时间格式无效")
		return
	}
	if end.IsZero() && f.Hours > 0 {
		base := start
		if base.IsZero() {
			base = time.Now()
		}
		end = base.Add(time.Duration(min(f.Hours, 24*90)) * time.Hour)
	}
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	e, err := s.AuthScan.Add(authscan.Entry{IP: f.IP, Start: start, End: end, Note: f.Note, Creator: user})
	detail := "扫描源 " + strings.TrimSpace(f.IP) + "，说明：" + strings.TrimSpace(f.Note)
	if err == nil {
		detail += "，时间 " + e.Start.Format("2006-01-02 15:04") + " ~ " + e.End.Format("2006-01-02 15:04")
	}
	s.audit(r, "登记授权扫描", detail, err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, e)
}

func (s *Server) authScanEnd(w http.ResponseWriter, r *http.Request) {
	if s.AuthScan == nil {
		writeError(w, http.StatusNotFound, "登记不存在")
		return
	}
	e, err := s.AuthScan.Finish(r.PathValue("id"))
	s.audit(r, "提前结束授权扫描", "扫描源 "+e.IP+"，说明："+e.Note, err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, e)
}

func (s *Server) authScanDelete(w http.ResponseWriter, r *http.Request) {
	if s.AuthScan == nil {
		writeError(w, http.StatusNotFound, "登记不存在")
		return
	}
	e, err := s.AuthScan.Delete(r.PathValue("id"))
	s.audit(r, "删除授权扫描登记", "扫描源 "+e.IP+"，说明："+e.Note, err)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
