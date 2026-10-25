package assets

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"netsa/internal/model"
)

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs("Apache路径穿越RCE(CVE-2021-41773/42013) 与 cve-2017-12615")
	if strings.Join(got, ",") != "CVE-2021-41773,CVE-2021-42013,CVE-2017-12615" {
		t.Fatalf("%v", got)
	}
}

func TestParseCSV(t *testing.T) {
	// CMDB 导出（中文列名、带 BOM、多余列）
	cmdb := "\ufeff资产名称,IP地址,负责人,所属部门,业务重要性,等保级别,域名,资产类型,其他\n" +
		"官网,10.0.1.10,张三,信息中心,核心,三级,www.example.com;example.com,Web,x\n" +
		"办公网,10.0.2.0/24,李四,行政部,一般,,,,\n" +
		",,,,,,,,\n" +
		"坏数据,999.1.1.1,,,,,,,\n"
	list, lines, err := ParseAssetsCSV([]byte(cmdb))
	if err != nil || len(list) != 3 || lines[2] != 5 {
		t.Fatalf("资产表: %v %d %v", err, len(list), lines)
	}
	if a := list[0]; a.Name != "官网" || a.Owner != "张三" || a.Importance != LevelCore || a.MLPS != 3 || len(a.Hosts) != 2 || a.Tags[0] != "Web" {
		t.Fatalf("资产字段: %+v", a)
	}
	// Nessus CSV（Host 列、Risk 列、CVSS 列）
	nessus := `"Plugin ID","CVE","CVSS v2.0 Base Score","Risk","Host","Protocol","Port","Name","Solution"` + "\n" +
		`"12345","CVE-2017-12615","9.3","Critical","10.0.1.10","tcp","8080","Apache Tomcat PUT JSP Upload","Upgrade"` + "\n" +
		`"23456","","0","None","10.0.1.10","tcp","0","Nessus Scan Information",""` + "\n" +
		`"34567","","6.8","","web01.example.com","tcp","443","SSL Weak Cipher",""` + "\n"
	vs, _, err := ParseVulnsCSV([]byte(nessus))
	if err != nil || len(vs) != 3 {
		t.Fatalf("Nessus: %v %d", err, len(vs))
	}
	if v := vs[0]; v.IP != "10.0.1.10" || v.Port != 8080 || v.Severity != model.SevCritical || v.CVE[0] != "CVE-2017-12615" {
		t.Fatalf("Nessus 字段: %+v", v)
	}
	if vs[1].Severity != model.SevInfo || vs[2].Host != "web01.example.com" || vs[2].IP != "" || vs[2].Severity != model.SevMedium {
		t.Fatalf("Nessus 信息项 / 主机名 / CVSS: %+v %+v", vs[1], vs[2])
	}
	// 中文扫描器（制表符分隔）
	cn := "IP地址\t端口\t漏洞名称\t风险等级\tCVE编号\n10.0.1.11\t80/tcp\tThinkPHP 5 远程代码执行\t高\t\n"
	if vs, _, err := ParseVulnsCSV([]byte(cn)); err != nil || len(vs) != 1 || vs[0].Port != 80 || vs[0].Severity != model.SevHigh {
		t.Fatalf("中文扫描器: %v %+v", err, vs)
	}
	if _, _, err := ParseVulnsCSV([]byte("IP地址,端口\n1.1.1.1,80\n")); err == nil {
		t.Fatal("缺少漏洞名称列应报错")
	}
	if _, _, err := ParseAssetsCSV([]byte{0xd7, 0xca, 0xb2, 0xfa, ',', 'I', 'P', '\n'}); err != ErrEncoding { // GBK 编码的“资产”
		t.Fatalf("GBK 编码应提示另存为 UTF-8: %v", err)
	}
}

func TestLookupAndCorrelate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	m, _ := Load(path)
	assets, lines, _ := ParseAssetsCSV([]byte("IP,名称,域名,负责人,重要性\n10.0.1.10,官网,www.example.com,张三,核心\n10.0.2.0/24,办公网,,,一般\n,门户,*.portal.example.com,,重要\n"))
	if res, err := m.ImportAssets(assets, lines, false); err != nil || res.Added != 3 {
		t.Fatalf("导入资产: %v %+v", err, res)
	}
	vulns := []Vuln{
		{IP: "10.0.1.10", Port: 8080, CVE: []string{"CVE-2017-12615"}, Name: "Tomcat PUT 任意文件上传", Severity: model.SevCritical},
		{IP: "10.0.1.10", Port: 80, Name: "SQL 注入漏洞（/news.php）", Severity: model.SevHigh},
		{IP: "10.0.1.10", Port: 80, Name: "跨站脚本（反射型）", Severity: model.SevLow},
	}
	if res, err := m.ImportVulns(vulns, []int{2, 3, 4}, false, "scan-1"); err != nil || res.Added != 3 {
		t.Fatalf("导入漏洞: %v %+v", err, res)
	}
	ev := &model.Event{Kind: model.KindWeb, Host: "www.example.com", SrcIP: "198.51.100.1", URI: "/x.jsp"}
	mt := m.Lookup(ev)
	if mt == nil || mt.Asset.Name != "官网" || len(mt.Vulns) != 3 {
		t.Fatalf("按域名识别资产并按资产 IP 关联漏洞: %+v", mt)
	}
	v, exact := mt.Correlate(&model.Hit{Name: "PUT上传WebShell(CVE-2017-12615等)", Category: "已知漏洞利用"})
	if v == nil || !exact {
		t.Fatal("CVE 精确关联")
	}
	if v, exact := mt.Correlate(&model.Hit{Name: "UNION注入", Category: "SQL注入"}); v == nil || exact || !strings.Contains(v.Name, "SQL") {
		t.Fatalf("同类关联: %+v", v)
	}
	if v, _ := mt.Correlate(&model.Hit{Name: "WebLogic反序列化", Category: "反序列化"}); v != nil {
		t.Fatal("无关的攻击不应关联")
	}
	if a := m.Lookup(&model.Event{Kind: model.KindFirewall, DstIP: "10.0.2.33"}); a == nil || a.Asset.Name != "办公网" {
		t.Fatal("按网段识别")
	}
	if a := m.Lookup(&model.Event{Kind: model.KindWeb, Host: "a.portal.example.com:8443"}); a == nil || a.Asset.Name != "门户" {
		t.Fatal("通配符域名")
	}
	if a := m.Lookup(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.1.10", DstIP: "203.0.113.5", Outbound: true}); a == nil || a.Asset.Name != "官网" || len(a.Vulns) != 0 {
		t.Fatal("外连事件按发起方识别资产")
	}
	if m.Lookup(&model.Event{Kind: model.KindWeb, Host: "other.com"}) != nil {
		t.Fatal("未登记的目标")
	}
	// 再次扫描（替换模式）：本次没有出现的 SQL 注入漏洞视为已修复，不再参与关联
	res, _ := m.ImportVulns(vulns[:1], []int{2}, true, "scan-2")
	if res.Updated != 1 || res.Removed != 2 {
		t.Fatalf("替换导入: %+v", res)
	}
	if v, _ := m.Lookup(ev).Correlate(&model.Hit{Name: "UNION注入", Category: "SQL注入"}); v != nil {
		t.Fatal("已修复的漏洞不应参与关联")
	}
	sum := m.Summary()
	if sum.Assets != 3 || sum.OpenVulns != 1 || sum.Fixed != 2 || sum.CoreOpenHigh != 1 || sum.ByImportance[LevelCore] != 1 {
		t.Fatalf("概况: %+v", sum)
	}
	list, _ := m.Vulns(VulnQuery{Status: VulnOpen})
	if len(list) != 1 || list[0].Asset != "官网" || list[0].Owner != "张三" {
		t.Fatalf("漏洞列表: %+v", list)
	}
	if _, err := m.SetVulnStatus(list[0].ID, VulnAccepted); err != nil {
		t.Fatal(err)
	}
	// 重启后恢复
	m2, err := Load(path)
	if err != nil || len(m2.Assets("", "")) != 3 || m2.Summary().Accepted != 1 {
		t.Fatalf("重启后: %v %+v", err, m2.Summary())
	}
	if m2.Assets("张三", "")[0].Name != "官网" {
		t.Fatal("按负责人搜索")
	}
	if _, err := m2.AddAsset(Asset{IP: "10.0.1.10"}); err != ErrAssetDup {
		t.Fatalf("重复登记: %v", err)
	}
	if _, err := m2.AddAsset(Asset{IP: "0.0.0.0/0"}); err == nil {
		t.Fatal("范围过大")
	}
}

func BenchmarkLookupMiss(b *testing.B) {
	m, _ := Load("")
	var list []Asset
	var lines []int
	for i := 0; i < 2000; i++ {
		list = append(list, Asset{IP: "10.1." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250)})
		lines = append(lines, i)
	}
	if res, _ := m.ImportAssets(list, lines, false); res.Added != 2000 {
		b.Fatalf("%+v", res)
	}
	ev := &model.Event{Kind: model.KindWeb, Host: "www.example.com", DstIP: "192.0.2.1"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Lookup(ev)
	}
}
