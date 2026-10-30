package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsa/internal/assets"
	"netsa/internal/model"
	"netsa/internal/store"
)

func (s *Server) assetsReady(w http.ResponseWriter) bool {
	if s.Assets == nil {
		writeError(w, http.StatusServiceUnavailable, "资产管理未启用")
		return false
	}
	return true
}

func (s *Server) assetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assets.ErrNoAsset), errors.Is(err, assets.ErrNoVuln):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, assets.ErrAssetDup):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

// assetList 返回资产台账（按重要性、未修复漏洞数排序）与概况。
func (s *Server) assetList(w http.ResponseWriter, r *http.Request) {
	if !s.assetsReady(w) {
		return
	}
	q := r.URL.Query()
	list := s.Assets.Assets(q.Get("q"), q.Get("importance"))
	total := len(list)
	if limit := clamp(qint(r, "limit", 500), 1, 5000); len(list) > limit {
		list = list[:limit]
	}
	writeJSON(w, map[string]any{"assets": list, "total": total, "summary": s.Assets.Summary()})
}

// assetDetail 返回资产、资产上的漏洞与针对该资产的近期告警。
func (s *Server) assetDetail(w http.ResponseWriter, r *http.Request) {
	if !s.assetsReady(w) {
		return
	}
	a, vulns := s.Assets.AssetByID(r.PathValue("id"))
	if a == nil {
		writeError(w, http.StatusNotFound, assets.ErrNoAsset.Error())
		return
	}
	if vulns == nil {
		vulns = []assets.Vuln{}
	}
	alerts := s.Store.Alerts(store.AlertQuery{Asset: a.Name, Limit: 100})
	if alerts == nil {
		alerts = []*model.Alert{}
	}
	writeJSON(w, map[string]any{"asset": a, "vulns": vulns, "alerts": alerts})
}

type assetForm struct {
	IP         string   `json:"ip"`
	Hosts      []string `json:"hosts"`
	Name       string   `json:"name"`
	Owner      string   `json:"owner"`
	Dept       string   `json:"dept"`
	Importance string   `json:"importance"`
	MLPS       int      `json:"mlps"`
	Env        string   `json:"env"`
	Tags       []string `json:"tags"`
	Note       string   `json:"note"`
}

func (f assetForm) asset() assets.Asset {
	return assets.Asset{IP: f.IP, Hosts: f.Hosts, Name: f.Name, Owner: f.Owner, Dept: f.Dept, Importance: f.Importance, MLPS: f.MLPS, Env: f.Env, Tags: f.Tags, Note: f.Note}
}

func (s *Server) assetCreate(w http.ResponseWriter, r *http.Request) {
	var f assetForm
	if !s.assetsReady(w) || !decodeForm(w, r, &f) {
		return
	}
	a, err := s.Assets.AddAsset(f.asset())
	s.audit(r, "登记资产", f.Name+" "+f.IP, err)
	if err != nil {
		s.assetError(w, err)
		return
	}
	writeJSON(w, a)
}

func (s *Server) assetUpdate(w http.ResponseWriter, r *http.Request) {
	var f assetForm
	if !s.assetsReady(w) || !decodeForm(w, r, &f) {
		return
	}
	a, err := s.Assets.UpdateAsset(r.PathValue("id"), f.asset())
	s.audit(r, "修改资产", f.Name+" "+f.IP, err)
	if err != nil {
		s.assetError(w, err)
		return
	}
	writeJSON(w, a)
}

func (s *Server) assetDelete(w http.ResponseWriter, r *http.Request) {
	if !s.assetsReady(w) {
		return
	}
	a, err := s.Assets.DeleteAsset(r.PathValue("id"))
	s.audit(r, "删除资产", a.Name+" "+a.IP, err)
	if err != nil {
		s.assetError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// assetImport 导入资产表或漏洞扫描结果（CSV，UTF-8，最大 20MB）。
// type=assets|vulns，mode=merge（默认，按 IP 更新）| replace（资产：替换导入的资产；漏洞：本次未出现的未修复漏洞标记为已修复）。
func (s *Server) assetImport(w http.ResponseWriter, r *http.Request) {
	if !s.assetsReady(w) {
		return
	}
	q := r.URL.Query()
	typ, replace := q.Get("type"), q.Get("mode") == "replace"
	if typ != "assets" && typ != "vulns" {
		writeError(w, http.StatusBadRequest, "type 只能为 assets 或 vulns")
		return
	}
	extendDeadline(w, 5*time.Minute) // 大文件上传需要更长的读取时间
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 20<<20))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "文件过大（最大 20MB）")
		return
	}
	name := clipRunes(strings.TrimSpace(q.Get("name")), 100) // 按字符截断：按字节截断会把中文名称截成非法 UTF-8
	var res assets.ImportResult
	action := "导入资产"
	if typ == "assets" {
		list, lines, perr := assets.ParseAssetsCSV(data)
		if err = perr; err == nil {
			res, err = s.Assets.ImportAssets(list, lines, replace)
		}
	} else {
		action = "导入漏洞扫描结果"
		list, lines, perr := assets.ParseVulnsCSV(data)
		if err = perr; err == nil {
			res, err = s.Assets.ImportVulns(list, lines, replace, name)
		}
	}
	mode := "合并"
	if replace {
		mode = "替换"
	}
	s.audit(r, action, name+"（"+mode+"）新增 "+strconv.Itoa(res.Added)+"，更新 "+strconv.Itoa(res.Updated)+"，跳过 "+strconv.Itoa(res.Skipped), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, res)
}

// assetTemplate 下载导入模板。
func (s *Server) assetTemplate(w http.ResponseWriter, r *http.Request) {
	body, name := assets.AssetTemplate, "netsa-assets-template.csv"
	if r.URL.Query().Get("type") == "vulns" {
		body, name = assets.VulnTemplate, "netsa-vulns-template.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	io.WriteString(w, body)
}

// vulnList 查询漏洞：status=open|fixed|accepted、severity 最低等级、ip、q 搜索。
func (s *Server) vulnList(w http.ResponseWriter, r *http.Request) {
	if !s.assetsReady(w) {
		return
	}
	q := r.URL.Query()
	list, total := s.Assets.Vulns(assets.VulnQuery{IP: q.Get("ip"), Status: q.Get("status"), MinSeverity: model.ParseSeverity(q.Get("severity")),
		Search: q.Get("q"), Limit: clamp(qint(r, "limit", 500), 1, 5000)})
	writeJSON(w, map[string]any{"vulns": list, "total": total})
}

// vulnUpdate 修改漏洞状态（运营分析员以上）。
func (s *Server) vulnUpdate(w http.ResponseWriter, r *http.Request) {
	var f struct {
		Status string `json:"status"`
	}
	if !s.assetsReady(w) || !decodeForm(w, r, &f) {
		return
	}
	v, err := s.Assets.SetVulnStatus(r.PathValue("id"), f.Status)
	s.audit(r, "修改漏洞状态", v.IP+" "+v.Name+" → "+assets.VulnStatusLabel[f.Status], err)
	if err != nil {
		s.assetError(w, err)
		return
	}
	writeJSON(w, v)
}

func (s *Server) vulnDelete(w http.ResponseWriter, r *http.Request) {
	if !s.assetsReady(w) {
		return
	}
	v, err := s.Assets.DeleteVuln(r.PathValue("id"))
	s.audit(r, "删除漏洞", v.IP+" "+v.Name, err)
	if err != nil {
		s.assetError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
