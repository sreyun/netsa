package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"netsa/internal/auth"
	"netsa/internal/model"
	"netsa/internal/store"
	"netsa/internal/suppress"
)

// incidents 查询安全事件：status=active|closed|open|investigating|resolved|false_positive|ignored，
// severity 最低等级，assignee 负责人（me 表示当前账号），q 搜索，overdue=1 只看超时。
func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	assignee := q.Get("assignee")
	if assignee == "me" {
		assignee = ""
		if sess := sessionOf(r); sess != nil {
			assignee = sess.User
		}
	}
	list, total, counts := s.Store.Incidents(store.IncidentQuery{
		Status: q.Get("status"), MinSeverity: model.ParseSeverity(q.Get("severity")), Assignee: assignee, Search: q.Get("q"),
		Overdue: q.Get("overdue") == "1", Limit: clamp(qint(r, "limit", 100), 1, 1000), Offset: clamp(qint(r, "offset", 0), 0, 1<<30),
	})
	if list == nil {
		list = []store.IncidentView{}
	}
	writeJSON(w, map[string]any{"incidents": list, "total": total, "counts": counts})
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	d := s.Store.Incident(id)
	if d == nil {
		writeError(w, http.StatusNotFound, store.ErrNoIncident.Error())
		return
	}
	writeJSON(w, d)
}

type incidentForm struct {
	IDs      []uint64 `json:"ids"`
	Status   string   `json:"status"`
	Assignee *string  `json:"assignee"`
	Note     string   `json:"note"`
}

// incidentUpdate 处置单个事件（POST /api/incidents/{id}）或批量处置（POST /api/incidents/bulk，最多 500 个）。
func (s *Server) incidentUpdate(w http.ResponseWriter, r *http.Request) {
	var f incidentForm
	if !decodeForm(w, r, &f) {
		return
	}
	if id := r.PathValue("id"); id != "" {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusNotFound, store.ErrNoIncident.Error())
			return
		}
		f.IDs = []uint64{n}
	}
	if len(f.IDs) == 0 || len(f.IDs) > 500 {
		writeError(w, http.StatusBadRequest, "请选择 1 ~ 500 个事件")
		return
	}
	if f.Assignee != nil {
		a := strings.TrimSpace(*f.Assignee)
		if a != "" && s.Auth != nil && !s.assignable(a) {
			writeError(w, http.StatusBadRequest, "负责人必须是具有处置权限（管理员或运营分析员）的账号")
			return
		}
		f.Assignee = &a
	}
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	list, err := s.Store.UpdateIncidents(f.IDs, user, store.IncidentUpdate{Status: f.Status, Assignee: f.Assignee, Note: f.Note})
	detail := incidentIDs(f.IDs)
	if f.Status != "" {
		detail += " → " + store.IncidentStatusLabel[f.Status]
	}
	if f.Assignee != nil {
		detail += " 负责人 " + orDash(*f.Assignee)
	}
	s.audit(r, "处置安全事件", detail, err)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrNoIncident) {
			code = http.StatusNotFound
		}
		writeError(w, code, err.Error())
		return
	}
	if f.Status != "" {
		s.learnFeedback(list, user)
	}
	writeJSON(w, map[string]any{"incidents": list})
}

func incidentIDs(ids []uint64) string {
	var sb strings.Builder
	sb.WriteString("事件 ")
	for i, id := range ids {
		if i == 10 {
			sb.WriteString(" 等 " + strconv.Itoa(len(ids)) + " 个")
			break
		}
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("#" + strconv.FormatUint(id, 10))
	}
	return sb.String()
}

func orDash(s string) string {
	if s == "" {
		return "（无）"
	}
	return s
}

// assignable 判断账号能否作为事件负责人（管理员或运营分析员）。
func (s *Server) assignable(name string) bool {
	for _, u := range s.Auth.Users() {
		if u.Name == name {
			return auth.RoleAtLeast(u.Role, auth.RoleAnalyst)
		}
	}
	return false
}

// incidentAssignees 返回可指派的负责人列表。
func (s *Server) incidentAssignees(w http.ResponseWriter, r *http.Request) {
	out := []map[string]string{}
	if s.Auth != nil {
		for _, u := range s.Auth.Users() {
			if auth.RoleAtLeast(u.Role, auth.RoleAnalyst) {
				out = append(out, map[string]string{"name": u.Name, "role": u.Role})
			}
		}
	}
	writeJSON(w, out)
}

func (s *Server) suppressions(w http.ResponseWriter, r *http.Request) {
	list := []suppress.Rule{}
	if s.Suppress != nil {
		list = s.Suppress.List()
	}
	writeJSON(w, map[string]any{"rules": list, "total": s.Suppress.Total(), "enabled": s.Suppress != nil})
}

type suppressForm struct {
	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	IP       string `json:"ip"`
	Target   string `json:"target"`
	Reason   string `json:"reason"`
	Days     int    `json:"days"`
}

func (s *Server) suppressionCreate(w http.ResponseWriter, r *http.Request) {
	if s.Suppress == nil {
		writeError(w, http.StatusServiceUnavailable, "误报抑制未启用")
		return
	}
	var f suppressForm
	if !decodeForm(w, r, &f) {
		return
	}
	if strings.TrimSpace(f.Reason) == "" {
		writeError(w, http.StatusBadRequest, "请填写抑制原因（例如：内部扫描器、业务接口误报）")
		return
	}
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	rule, err := s.Suppress.Add(suppress.Rule{RuleID: f.RuleID, Category: f.Category, IP: f.IP, Target: f.Target, Reason: f.Reason, Creator: user}, f.Days)
	s.audit(r, "添加误报抑制", describeSuppress(f.RuleID, f.Category, f.IP, f.Target)+" 原因："+f.Reason, err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, rule)
}

func (s *Server) suppressionDelete(w http.ResponseWriter, r *http.Request) {
	if s.Suppress == nil {
		writeError(w, http.StatusNotFound, "抑制规则不存在")
		return
	}
	rule, err := s.Suppress.Delete(r.PathValue("id"))
	s.audit(r, "删除误报抑制", describeSuppress(rule.RuleID, rule.Category, rule.IP, rule.Target), err)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func describeSuppress(rule, cat, ip, target string) string {
	var parts []string
	for _, p := range [][2]string{{"规则", rule}, {"类型", cat}, {"来源", ip}, {"目标", target}} {
		if p[1] = strings.TrimSpace(p[1]); p[1] != "" {
			parts = append(parts, p[0]+" "+p[1])
		}
	}
	return strings.Join(parts, "，")
}

func incidentParam(v string) uint64 {
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}
