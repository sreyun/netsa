package api

import (
	"net/http"
	"strings"
)

// deceptionStatus 返回诱饵、命中过诱饵的来源与关联（P3-2）。
func (s *Server) deceptionStatus(w http.ResponseWriter, r *http.Request) {
	st := s.Deception.List()
	writeJSON(w, map[string]any{"decoys": st.Decoys, "attackers": st.Attackers, "links": st.Links, "total": st.Total, "enabled": s.Deception != nil})
}

type decoyForm struct {
	Kind  string `json:"kind"` // path / token / account / host
	Value string `json:"value"`
	Note  string `json:"note"`
}

func (s *Server) deceptionCreate(w http.ResponseWriter, r *http.Request) {
	if s.Deception == nil {
		writeError(w, http.StatusServiceUnavailable, "诱饵未启用")
		return
	}
	var f decoyForm
	if !decodeForm(w, r, &f) {
		return
	}
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	d, err := s.Deception.Add(strings.TrimSpace(f.Kind), f.Value, f.Note, user)
	s.audit(r, "登记诱饵", f.Kind+" "+strings.TrimSpace(f.Value)+"，说明："+strings.TrimSpace(f.Note), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, d)
}

func (s *Server) deceptionDelete(w http.ResponseWriter, r *http.Request) {
	if s.Deception == nil {
		writeError(w, http.StatusNotFound, "诱饵不存在")
		return
	}
	d, err := s.Deception.Delete(r.PathValue("id"))
	s.audit(r, "删除诱饵", d.Kind+" "+d.Value, err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
