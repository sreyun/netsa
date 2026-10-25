package assets

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"netsa/internal/model"
)

// ParseImportance 解析业务重要性：核心 / 关键 / 高 / 一级 / core / critical；重要 / 中 / 二级 / important / medium；其余为一般。
func ParseImportance(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "core", "critical", "key", "high", "核心", "关键", "核心资产", "高", "一级", "1", "a":
		return LevelCore
	case "important", "medium", "major", "重要", "中", "二级", "2", "b":
		return LevelImportant
	}
	return LevelNormal
}

// ParseVulnStatus 解析漏洞状态。
func ParseVulnStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fixed", "closed", "resolved", "remediated", "已修复", "已处置", "已关闭", "修复":
		return VulnFixed
	case "accepted", "risk accepted", "ignored", "false positive", "风险接受", "已接受", "忽略", "误报":
		return VulnAccepted
	}
	return VulnOpen
}

// parseSeverity 解析漏洞等级：文字（严重 / 高危 / critical / high …）或 CVSS 分值。
func parseSeverity(s string) (model.Severity, bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "critical", "严重", "紧急", "超危", "极高", "危急":
		return model.SevCritical, true
	case "high", "高", "高危", "高风险":
		return model.SevHigh, true
	case "medium", "moderate", "中", "中危", "中风险":
		return model.SevMedium, true
	case "low", "低", "低危", "低风险":
		return model.SevLow, true
	case "info", "information", "informational", "none", "log", "信息", "提示", "无":
		return model.SevInfo, true
	}
	if f, err := strconv.ParseFloat(t, 64); err == nil {
		switch {
		case f >= 9:
			return model.SevCritical, true
		case f >= 7:
			return model.SevHigh, true
		case f >= 4:
			return model.SevMedium, true
		case f > 0:
			return model.SevLow, true
		}
		return model.SevInfo, true
	}
	return model.SevMedium, false
}

// 列名别名（小写，去掉空格）。
var assetCols = map[string][]string{
	"ip":         {"ip", "ip地址", "地址", "address", "ipaddress", "资产ip", "ip/网段", "cidr", "网段", "主机ip", "服务器ip"},
	"name":       {"name", "名称", "资产名称", "主机名", "hostname", "系统名称", "设备名称", "业务系统", "应用名称"},
	"owner":      {"owner", "负责人", "责任人", "管理员", "联系人", "运维负责人"},
	"dept":       {"dept", "department", "部门", "所属部门", "业务部门", "单位", "所属单位"},
	"importance": {"importance", "重要性", "重要程度", "资产等级", "业务重要性", "重要级别", "level", "criticality"},
	"mlps":       {"mlps", "等保级别", "等保等级", "安全保护等级", "定级"},
	"env":        {"env", "environment", "环境"},
	"hosts":      {"hosts", "host", "domain", "domains", "域名", "网站", "url", "访问地址"},
	"tags":       {"tags", "标签", "资产类型", "类型", "type", "category"},
	"note":       {"note", "备注", "说明", "description", "描述"},
}

var vulnCols = map[string][]string{
	"ip":       {"ip", "ip地址", "host", "主机", "目标", "资产ip", "主机ip", "address", "target"},
	"host":     {"hostname", "主机名", "域名", "fqdn", "dnsname", "netbiosname"},
	"port":     {"port", "端口"},
	"cve":      {"cve", "cve编号", "cveid", "cves", "cve号"},
	"name":     {"name", "漏洞名称", "名称", "nvtname", "pluginname", "title", "vulnerability", "漏洞", "漏洞标题"},
	"severity": {"severity", "risk", "风险等级", "危险等级", "威胁等级", "等级", "风险级别", "risklevel", "漏洞等级"},
	"cvss":     {"cvss", "cvssv3", "cvss3", "cvssbasescore", "cvss评分", "cvssv2basescore", "cvssv3basescore"},
	"product":  {"product", "软件", "组件", "服务", "应用", "service"},
	"status":   {"status", "状态", "修复状态"},
	"solution": {"solution", "修复建议", "解决方案", "解决办法", "加固建议"},
}

// ErrEncoding 表示文件不是 UTF-8 编码。
var ErrEncoding = errors.New("文件不是 UTF-8 编码：请在 Excel 中另存为“CSV UTF-8（逗号分隔）”后再导入")

func normCol(s string) string {
	s = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(s, "\ufeff")))
	return strings.NewReplacer(" ", "", "_", "", "-", "", "（", "(", "）", ")").Replace(s)
}

// readCSV 读取 CSV（自动识别逗号 / 制表符 / 分号分隔），返回列名映射与数据行。
func readCSV(data []byte, cols map[string][]string) (map[string]int, [][]string, error) {
	if !utf8.Valid(data) {
		return nil, nil, ErrEncoding
	}
	data = bytes.TrimPrefix(data, []byte("\ufeff"))
	first, _, _ := bytes.Cut(data, []byte("\n"))
	sep := ','
	if c, t, s := bytes.Count(first, []byte(",")), bytes.Count(first, []byte("\t")), bytes.Count(first, []byte(";")); t > c && t >= s {
		sep = '\t'
	} else if s > c && s > t {
		sep = ';'
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma, r.FieldsPerRecord, r.LazyQuotes, r.TrimLeadingSpace = sep, -1, true, true
	head, err := r.Read()
	if err == io.EOF {
		return nil, nil, errors.New("文件为空")
	}
	if err != nil {
		return nil, nil, err
	}
	alias := map[string]string{}
	for k, list := range cols {
		for _, a := range list {
			alias[a] = k
		}
	}
	idx := map[string]int{}
	for i, h := range head {
		if k := alias[normCol(h)]; k != "" {
			if _, dup := idx[k]; !dup {
				idx[k] = i
			}
		}
	}
	var rows [][]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, rec)
		if len(rows) > maxVulns {
			return nil, nil, errors.New("文件行数过多（超过 200000 行）")
		}
	}
	return idx, rows, nil
}

func col(rec []string, idx map[string]int, k string) string {
	if i, ok := idx[k]; ok && i < len(rec) {
		return strings.TrimSpace(rec[i])
	}
	return ""
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '，' || r == '；' || r == '|' || r == ' ' || r == '\n'
	})
	return f
}

// ParseAssetsCSV 解析资产表（CMDB 导出或模板），返回资产与对应的行号。必须包含 IP 或域名列。
func ParseAssetsCSV(data []byte) ([]Asset, []int, error) {
	idx, rows, err := readCSV(data, assetCols)
	if err != nil {
		return nil, nil, err
	}
	_, hasIP := idx["ip"]
	_, hasHost := idx["hosts"]
	if !hasIP && !hasHost {
		return nil, nil, errors.New("未找到 IP 或域名列（列名示例：IP、IP地址、域名）")
	}
	var out []Asset
	var lines []int
	for i, rec := range rows {
		ip := col(rec, idx, "ip")
		hosts := splitList(col(rec, idx, "hosts"))
		if ip == "" && len(hosts) == 0 {
			continue // 空行
		}
		mlps := 0
		if m := col(rec, idx, "mlps"); m != "" {
			for _, c := range m {
				if c >= '1' && c <= '5' {
					mlps = int(c - '0')
					break
				}
				if n := strings.IndexRune("一二三四五", c); n >= 0 {
					mlps = n/3 + 1
					break
				}
			}
		}
		out = append(out, Asset{IP: ip, Hosts: hosts, Name: col(rec, idx, "name"), Owner: col(rec, idx, "owner"), Dept: col(rec, idx, "dept"),
			Importance: ParseImportance(col(rec, idx, "importance")), MLPS: mlps, Env: col(rec, idx, "env"), Tags: splitList(col(rec, idx, "tags")),
			Note: col(rec, idx, "note")})
		lines = append(lines, i+2)
	}
	return out, lines, nil
}

// ParseVulnsCSV 解析漏洞扫描结果（Nessus、OpenVAS、绿盟等导出的 CSV 或模板）。必须包含 IP / 主机列与漏洞名称或 CVE 列。
func ParseVulnsCSV(data []byte) ([]Vuln, []int, error) {
	idx, rows, err := readCSV(data, vulnCols)
	if err != nil {
		return nil, nil, err
	}
	_, hasIP := idx["ip"]
	_, hasHost := idx["host"]
	_, hasName := idx["name"]
	_, hasCVE := idx["cve"]
	if !hasIP && !hasHost || !hasName && !hasCVE {
		return nil, nil, errors.New("未找到必要的列：需要 IP（或主机名）列，以及漏洞名称或 CVE 列")
	}
	var out []Vuln
	var lines []int
	for i, rec := range rows {
		ip, host := col(rec, idx, "ip"), col(rec, idx, "host")
		if ip == "" && host == "" {
			continue
		}
		if ip != "" && !looksIP(ip) { // 部分扫描器的 Host 列是主机名
			host, ip = ip, ""
		}
		sev, ok := parseSeverity(col(rec, idx, "severity"))
		if !ok || col(rec, idx, "severity") == "" {
			if c := col(rec, idx, "cvss"); c != "" {
				sev, _ = parseSeverity(c)
			}
		}
		port, _ := strconv.Atoi(strings.TrimSuffix(strings.Split(col(rec, idx, "port"), "/")[0], " "))
		out = append(out, Vuln{IP: ip, Host: host, Port: port, CVE: splitList(col(rec, idx, "cve")), Name: col(rec, idx, "name"), Severity: sev,
			Product: col(rec, idx, "product"), Status: ParseVulnStatus(col(rec, idx, "status")), Solution: col(rec, idx, "solution")})
		lines = append(lines, i+2)
	}
	return out, lines, nil
}

func looksIP(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.' || c == ':' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return strings.ContainsAny(s, ".:")
}

// AssetTemplate / VulnTemplate 是导入模板（UTF-8 带 BOM，Excel 可直接打开）。
const (
	AssetTemplate = "\ufeffIP,名称,域名,负责人,部门,重要性,等保级别,环境,标签,备注\n" +
		"10.0.1.10,官网 Web 服务器,www.example.com,张三,信息中心,核心,三级,生产,web;nginx,对外门户\n" +
		"10.0.2.0/24,办公网,,李四,行政部,一般,,生产,办公,\n"
	VulnTemplate = "\ufeffIP,端口,CVE,漏洞名称,风险等级,组件,状态,修复建议\n" +
		"10.0.1.10,8080,CVE-2017-12615,Apache Tomcat PUT 任意文件上传,严重,Tomcat 8.5.19,未修复,升级 Tomcat 并关闭 PUT 方法\n"
)
