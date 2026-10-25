package api

import (
	"net/http"
	"strings"
	"testing"

	"netsa/internal/assets"
)

// 资产与漏洞接口：CSV 导入、模板下载、权限（漏洞状态可由分析员修改，资产登记需要管理员）。
func TestAssetsAPI(t *testing.T) {
	s, _ := testServer(t, "admin", "Adm1n-secret")
	s.Assets, _ = assets.Load("")
	h := s.Handler()
	admin := login(t, h, "admin", "Adm1n-secret")
	ana := newLocalUser(t, h, admin, "ana", "analyst")
	csvBody := "IP,名称,负责人,重要性,等保级别\n10.0.1.10,官网,张三,核心,三级\n10.0.1.11,OA,李四,重要,二级\nbad,坏,,,\n"
	if rec := do(h, http.MethodPost, "/api/assets/import?type=assets", csvBody, ana, "Content-Type", "text/csv"); rec.Code != 403 {
		t.Fatalf("分析员不能导入资产: %d", rec.Code)
	}
	var res assets.ImportResult
	rec := do(h, http.MethodPost, "/api/assets/import?type=assets", csvBody, admin, "Content-Type", "text/csv")
	decode(t, rec.Body.Bytes(), &res)
	if rec.Code != 200 || res.Added != 2 || res.Skipped != 1 || !strings.Contains(res.Errors[0], "第 4 行") {
		t.Fatalf("导入资产: %d %s", rec.Code, rec.Body.String())
	}
	vulnCSV := "IP,端口,CVE,漏洞名称,风险等级\n10.0.1.10,8080,CVE-2017-12615,Tomcat PUT 上传,严重\n10.0.1.11,80,,弱口令,高危\n"
	rec = do(h, http.MethodPost, "/api/assets/import?type=vulns&name=2026Q4扫描", vulnCSV, admin, "Content-Type", "text/csv")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"added":2`) {
		t.Fatalf("导入漏洞: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodPost, "/api/assets/import?type=x", "a", admin); rec.Code != 400 {
		t.Fatalf("无效类型: %d", rec.Code)
	}
	var list struct {
		Assets  []assets.AssetView
		Summary assets.Summary
	}
	decode(t, do(h, http.MethodGet, "/api/assets", "", ana).Body.Bytes(), &list)
	if len(list.Assets) != 2 || list.Assets[0].Name != "官网" || list.Assets[0].OpenVulns != 1 || list.Summary.CoreOpenHigh != 1 || list.Summary.MLPS[3] != 1 {
		t.Fatalf("资产列表: %+v", list)
	}
	var vl struct{ Vulns []assets.VulnView }
	decode(t, do(h, http.MethodGet, "/api/vulns?status=open", "", ana).Body.Bytes(), &vl)
	if len(vl.Vulns) != 2 || vl.Vulns[0].Asset != "官网" {
		t.Fatalf("漏洞列表: %+v", vl)
	}
	if rec := do(h, http.MethodPut, "/api/vulns/"+vl.Vulns[0].ID, `{"status":"fixed"}`, ana); rec.Code != 200 {
		t.Fatalf("分析员标记漏洞已修复: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodDelete, "/api/vulns/"+vl.Vulns[0].ID, "", ana); rec.Code != 403 {
		t.Fatalf("分析员不能删除漏洞: %d", rec.Code)
	}
	var d struct {
		Asset assets.Asset
		Vulns []assets.Vuln
	}
	decode(t, do(h, http.MethodGet, "/api/assets/"+list.Assets[0].ID, "", ana).Body.Bytes(), &d)
	if d.Asset.Name != "官网" || len(d.Vulns) != 0 {
		t.Fatalf("资产详情（已修复的漏洞不计入）: %+v", d)
	}
	if rec := do(h, http.MethodPost, "/api/assets", `{"ip":"10.0.1.10","name":"重复"}`, admin); rec.Code != 409 {
		t.Fatalf("重复登记: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/assets/template?type=vulns", "", ana); rec.Code != 200 || !strings.Contains(rec.Body.String(), "漏洞名称") ||
		!strings.HasPrefix(rec.Body.String(), "\ufeff") {
		t.Fatalf("模板: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/auth/audit", "", admin); !strings.Contains(rec.Body.String(), "导入漏洞扫描结果") || !strings.Contains(rec.Body.String(), "修改漏洞状态") {
		t.Fatal("资产操作应记录审计")
	}
}
