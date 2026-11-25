package api

import (
	"encoding/csv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/aiuse"
)

// AI 使用统计（风险管理 → AI 使用）：内网终端使用了哪些 AI 服务、用了多少、上传了多少数据。
// 统计是员工的上网行为：查看与导出需要运营分析员权限，导出记入审计链；服务目录只允许管理员修改。

// aiuseLabels 是页面展示用的中文名。
func aiuseLabels() map[string]any {
	return map[string]any{"category": aiuse.CategoryLabel, "region": aiuse.RegionLabel, "policy": aiuse.PolicyLabel, "endpoint": aiuse.EndpointKindLabel}
}

// aiuseQuery 解析查询范围：range=today / 7d / 30d / month，或 from、to（YYYY-MM-DD，含）。
func (s *Server) aiuseQuery(r *http.Request) aiuse.Query {
	q := r.URL.Query()
	from, to := s.AIUse.Range(q.Get("range"))
	loc := s.now().Location()
	if f, err := time.ParseInLocation("2006-01-02", q.Get("from"), loc); err == nil {
		from = f
		if t, err := time.ParseInLocation("2006-01-02", q.Get("to"), loc); err == nil && !t.Before(f) {
			to = t
		} else {
			to = f
		}
		if to.Sub(from) > 400*24*time.Hour {
			from = to.AddDate(0, 0, -400)
		}
	}
	return aiuse.Query{From: from, To: to, IP: canonIP(strings.TrimSpace(q.Get("ip"))), Service: strings.TrimSpace(q.Get("service")),
		Limit: clamp(qint(r, "limit", 500), 1, 5000)}
}

// DeptRow 是一个部门的汇总（按资产台账中办公网段、终端登记的部门）。
type DeptRow struct {
	Dept     string `json:"dept"`
	Subjects int    `json:"subjects"`
	Up       int64  `json:"up"`
	Deny     int    `json:"deny"`
	Services int    `json:"services"`
}

func (s *Server) aiuseReport(w http.ResponseWriter, r *http.Request) {
	if s.AIUse == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	q := s.aiuseQuery(r)
	rep := s.AIUse.Report(q)
	depts := map[string]*DeptRow{}
	deptSvcs := map[string]map[string]bool{}
	for i := range rep.Subjects {
		sr := &rep.Subjects[i]
		if name, owner, dept, ok := s.Assets.Holder(sr.IP); ok {
			sr.Asset, sr.Owner, sr.Dept = name, owner, dept
		}
		d := sr.Dept
		if d == "" {
			d = "未登记"
		}
		dr := depts[d]
		if dr == nil {
			dr = &DeptRow{Dept: d}
			depts[d] = dr
			deptSvcs[d] = map[string]bool{}
		}
		if sr.Queries+sr.Conns > 0 || sr.Up > 0 {
			dr.Subjects++
		}
		dr.Up += sr.Up
		if sr.Deny {
			dr.Deny++
		}
		for _, id := range sr.Services {
			deptSvcs[d][id] = true
		}
	}
	list := make([]DeptRow, 0, len(depts))
	for d, dr := range depts {
		dr.Services = len(deptSvcs[d])
		list = append(list, *dr)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Subjects != list[j].Subjects {
			return list[i].Subjects > list[j].Subjects
		}
		return list[i].Dept < list[j].Dept
	})
	writeJSON(w, map[string]any{"enabled": true, "report": rep, "depts": list, "labels": aiuseLabels(),
		"assets": s.Assets != nil && s.Assets.Summary().Assets > 0})
}

// aiuseExport 导出按“终端 + 服务”汇总的 CSV（记入审计链）。
func (s *Server) aiuseExport(w http.ResponseWriter, r *http.Request) {
	if s.AIUse == nil {
		writeError(w, http.StatusNotFound, "AI 使用统计未开启")
		return
	}
	q := s.aiuseQuery(r)
	rows := s.AIUse.Rows(q)
	desc := q.From.Format("2006-01-02") + " ~ " + q.To.Format("2006-01-02")
	if q.IP != "" {
		desc += " 终端 " + q.IP
	}
	if q.Service != "" {
		desc += " 服务 " + q.Service
	}
	s.audit(r, "导出 AI 使用统计", desc+"，共 "+strconv.Itoa(len(rows))+" 条", nil)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="netsa-aiuse-`+s.now().Format("20060102-150405")+`.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte("\xEF\xBB\xBF")) // UTF-8 BOM，便于 Excel 正确识别中文
	cw := csv.NewWriter(w)
	cw.Write([]string{"终端", "资产", "负责人", "部门", "服务", "厂商", "类别", "所在地", "策略", "DNS 查询", "连接", "被拦截", "上传字节", "下载字节", "首次", "最近"})
	for _, x := range rows {
		name, owner, dept, _ := s.Assets.Holder(x.IP)
		sv := x.Service
		cw.Write(csvSafe([]string{x.IP, name, owner, dept, sv.Name, sv.Vendor, aiuse.CategoryLabel[sv.Category], aiuse.RegionLabel[sv.Region],
			aiuse.PolicyLabel[sv.Policy], strconv.FormatInt(x.Queries, 10), strconv.FormatInt(x.Conns, 10), strconv.FormatInt(x.Denied, 10),
			strconv.FormatInt(x.Up, 10), strconv.FormatInt(x.Down, 10), x.First.Format("2006-01-02 15:04:05"), x.Last.Format("2006-01-02 15:04:05")}))
	}
	cw.Flush()
}

func (s *Server) aiuseCatalog(w http.ResponseWriter, r *http.Request) {
	if s.AIUse == nil {
		writeJSON(w, map[string]any{"enabled": false, "services": []any{}})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "services": s.AIUse.Catalog(), "labels": aiuseLabels()})
}

type aiServiceForm struct {
	Name     string   `json:"name"`
	Vendor   string   `json:"vendor"`
	Category string   `json:"category"`
	Region   string   `json:"region"`
	Policy   string   `json:"policy"`
	Domains  []string `json:"domains"`
	Note     string   `json:"note"`
}

func (s *Server) aiuseServiceCreate(w http.ResponseWriter, r *http.Request) {
	if s.AIUse == nil {
		writeError(w, http.StatusNotFound, "AI 使用统计未开启")
		return
	}
	var f aiServiceForm
	if !decodeForm(w, r, &f) {
		return
	}
	var domains []string
	for _, d := range f.Domains {
		for _, x := range strings.FieldsFunc(d, func(r rune) bool { return r == ',' || r == '，' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
			domains = append(domains, x)
		}
	}
	svc, err := s.AIUse.AddService(aiuse.Service{Name: f.Name, Vendor: f.Vendor, Category: f.Category, Region: f.Region, Policy: f.Policy, Domains: domains, Note: f.Note})
	s.audit(r, "登记 AI 服务", strings.TrimSpace(f.Name)+"："+strings.Join(domains, "、")+"，策略 "+aiuse.PolicyLabel[strings.ToLower(strings.TrimSpace(f.Policy))], err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, svc)
}

func (s *Server) aiuseServicePolicy(w http.ResponseWriter, r *http.Request) {
	if s.AIUse == nil {
		writeError(w, http.StatusNotFound, "AI 使用统计未开启")
		return
	}
	var f struct {
		Policy string `json:"policy"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	id := r.PathValue("id")
	old, _ := s.AIUse.Service(id)
	svc, err := s.AIUse.SetPolicy(id, f.Policy)
	s.audit(r, "设定 AI 服务策略", old.Name+"（"+id+"）："+aiuse.PolicyLabel[old.Policy]+" → "+aiuse.PolicyLabel[svc.Policy], err)
	if err != nil {
		code := http.StatusBadRequest
		if old.ID == "" {
			code = http.StatusNotFound
		}
		writeError(w, code, err.Error())
		return
	}
	writeJSON(w, svc)
}

func (s *Server) aiuseServiceDelete(w http.ResponseWriter, r *http.Request) {
	if s.AIUse == nil {
		writeError(w, http.StatusNotFound, "AI 使用统计未开启")
		return
	}
	id := r.PathValue("id")
	svc, err := s.AIUse.DeleteService(id)
	name := svc.Name
	if name == "" {
		name = id
	}
	s.audit(r, "删除 AI 服务", name+"（删除其使用记录）", err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) aiuseCandidate(w http.ResponseWriter, r *http.Request) {
	if s.AIUse == nil {
		writeError(w, http.StatusNotFound, "AI 使用统计未开启")
		return
	}
	domain, action := r.PathValue("domain"), r.PathValue("action")
	if action != "ignore" && action != "restore" {
		writeError(w, http.StatusNotFound, "未知操作")
		return
	}
	err := s.AIUse.IgnoreCandidate(domain, action == "ignore")
	label := "忽略疑似 AI 域名"
	if action == "restore" {
		label = "恢复疑似 AI 域名"
	}
	s.audit(r, label, domain, err)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
