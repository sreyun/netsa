package detect

import (
	_ "embed"
	"regexp"
	"slices"
	"strings"

	"netsa/internal/model"
)

// 国产 OA、中间件、CMS 与网络设备的漏洞接口签名，由 tools/vulnpaths 从 nuclei-templates（MIT 许可）生成，
// 另有少量人工补充（ID 以 netsa- 开头）。
//
// 签名只有方法、路径与查询参数名（以及 method=、action= 这类选择功能的参数值），不含载荷：
//   - 请求同时带有通用规则识别出的攻击载荷（注入、穿越、命令执行……）：生成“已知漏洞利用”命中，注明产品与 CVE / CNVD 编号；
//   - 只访问了存在漏洞的接口（上传、反序列化等载荷在请求体里，日志看不到）：生成“漏洞接口探测”命中，最高中危。
//     这类接口也可能是正常业务在用，自学习发现同一接口被多个网段的访客正常访问后降为低危（见 learn/profile.go）；
//     站点上从未出现过该产品、请求也没有成功时同样降为低危（见 learn/site.go）。

// CatVulnEndpoint 是访问存在已知漏洞的接口（日志里看不到载荷）的分类。
const CatVulnEndpoint = "漏洞接口探测"

//go:embed vulnpaths.tsv
var vulnpathsTSV string

type vulnSig struct {
	id, vendor, sev, method, path, ref, vtype string
	re                                        *regexp.Regexp // 路径含通配符时使用
	query                                     []string       // 必须出现的参数名，或 名=值
	trim                                      string         // 去掉末尾 / 的路径（精确比较用，加载时算好，匹配时不再拼接字符串）
	prefix                                    string         // 通配签名中第一个 * 之前的字面前缀（先用它快速排除，再执行正则）
}

// VulnVendor 是签名覆盖的一个产品。
type VulnVendor struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Lang string `json:"lang,omitempty"` // 开发语言或类型：java、php、aspnet、device
}

var vulnDB = loadVulnSigs(vulnpathsTSV)

type vulnIndex struct {
	byKey   map[string][]*vulnSig // 路径中的一段完整字面量 → 签名
	byID    map[string]*vulnSig
	vendors map[string]VulnVendor
	markers map[string]string // 正常访问中出现即说明使用了该产品的第一级目录
}

func loadVulnSigs(data string) *vulnIndex {
	ix := &vulnIndex{byKey: map[string][]*vulnSig{}, byID: map[string]*vulnSig{}, vendors: map[string]VulnVendor{}, markers: map[string]string{}}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		switch {
		case f[0] == "vendor" && len(f) >= 4:
			ix.vendors[f[1]] = VulnVendor{Key: f[1], Name: f[2], Lang: f[3]}
		case f[0] == "marker" && len(f) >= 3:
			ix.markers[f[1]] = f[2]
		case f[0] == "sig" && len(f) >= 9:
			s := &vulnSig{id: f[1], vendor: f[2], sev: f[3], method: f[4], path: f[5], ref: f[7], vtype: f[8]}
			if f[6] != "" {
				s.query = strings.Split(f[6], "&")
			}
			s.trim = strings.TrimSuffix(s.path, "/")
			if i := strings.IndexByte(s.trim, '*'); i >= 0 {
				s.re = regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(s.trim), `\*`, `[^?]*`) + "/?$")
				s.prefix = s.trim[:i]
			}
			key := ""
			for _, seg := range strings.Split(s.path, "/") {
				if !strings.Contains(seg, "*") && len(seg) > len(key) {
					key = seg
				}
			}
			if len(key) < 3 {
				continue
			}
			ix.byKey[key] = append(ix.byKey[key], s)
			ix.byID["vp-"+s.id] = s
		}
	}
	return ix
}

// VulnSigCount 返回内置的漏洞接口签名数。
func VulnSigCount() int { return len(vulnDB.byID) }

// VulnVendorOf 返回签名命中（RuleID 为 vp-*）针对的产品键。
func VulnVendorOf(ruleID string) string {
	if s := vulnDB.byID[ruleID]; s != nil {
		return s.vendor
	}
	return ""
}

// VulnVendorInfo 返回产品的中文名与开发语言。
func VulnVendorInfo(key string) (VulnVendor, bool) {
	v, ok := vulnDB.vendors[key]
	return v, ok
}

// VulnMarker 返回第一级目录对应的产品键（如 seeyon、defaultroot），不是产品目录时返回空串。
func VulnMarker(seg string) string { return vulnDB.markers[seg] }

// vulnPath 归一路径：合并重复的 /，去掉每一段的 ;参数（/seeyon/htmlofficeservlet;.js 这类绕过写法）。
func vulnPath(p string) string {
	if !strings.Contains(p, "//") && !strings.Contains(p, ";") {
		return p
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if !strings.Contains(p, ";") {
		return p
	}
	var b strings.Builder
	for i, seg := range strings.Split(p, "/") {
		if i > 0 {
			b.WriteByte('/')
		}
		if j := strings.IndexByte(seg, ';'); j >= 0 {
			seg = seg[:j]
		}
		b.WriteString(seg)
	}
	return b.String()
}

// matchVuln 按路径中的每一段查找签名。path 为归一化（解码、小写）后不含查询串的路径；
// 查询参数从原始 URI 拆分：归一化会还原 HTML 实体（&timestamp 里的 &times 变成 ×）、去掉跨参数的 SQL 注释，参数名会被破坏。
func matchVuln(method, path, rawURI string) *vulnSig {
	if len(vulnDB.byKey) == 0 || method == "" {
		return nil
	}
	p := vulnPath(path)
	var ps []Param
	parsed := false
	// 同一段在路径里重复出现时只查一次，每个签名对同一条路径只判断一次。否则 /attachment 重复几百次的
	// 8 KB 请求要把同一批签名对整条路径判断几百次（平方级，单条约 0.4 秒，可拖垮检测流水线）
	var seen []string
	rest := p
	for rest != "" {
		seg := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			seg, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		if len(seg) < 3 {
			continue
		}
		cands := vulnDB.byKey[seg]
		if len(cands) == 0 || slices.Contains(seen, seg) {
			continue
		}
		seen = append(seen, seg)
		for _, s := range cands {
			if !s.matchPath(p) {
				continue
			}
			if len(s.query) > 0 && !parsed {
				ps, parsed = splitParams(rawURI, false), true
			}
			if s.matchQuery(ps) {
				return s
			}
		}
	}
	return nil
}

// matchPath 不比较请求方法：扫描器常用 GET 确认 POST 接口是否存在（如 htmlofficeservlet），同样是在探测漏洞接口。
func (s *vulnSig) matchPath(p string) bool {
	if s.re != nil {
		return strings.HasPrefix(p, s.prefix) && s.re.MatchString(p)
	}
	return strings.TrimSuffix(p, "/") == s.trim
}

// matchQuery 判断签名要求的参数都出现了（need 为 名 或 名=值，值不区分大小写）。
func (s *vulnSig) matchQuery(ps []Param) bool {
	for _, need := range s.query {
		name, value, withValue := strings.Cut(need, "=")
		found := false
		for _, p := range ps {
			if strings.TrimSpace(p.Name) == name && (!withValue || strings.EqualFold(strings.TrimSpace(p.Value), value)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// 说明请求带着攻击载荷的分类。已知漏洞利用规则不算：原有的 cve-* 规则多数也只看路径。
var payloadCategory = map[string]bool{CatSQLi: true, CatXSS: true, CatTraversal: true, CatCmdExec: true, CatExpr: true,
	CatSSRF: true, CatXXE: true, CatDeser: true, CatWebShell: true}

// vulnHit 根据请求是否同时带有攻击载荷，生成“已知漏洞利用”或“漏洞接口探测”命中。
func vulnHit(s *vulnSig, ev *model.Event, path, result string, hits []model.Hit) model.Hit {
	v := vulnDB.vendors[s.vendor]
	if v.Name == "" {
		v.Name = s.vendor
	}
	kind := s.vtype
	if kind != "漏洞" {
		kind += "漏洞"
	}
	ref := ""
	if s.ref != "" {
		ref = "（" + s.ref + "）"
	}
	var payload []string
	for _, h := range hits {
		if !h.TagOnly && !h.Weak && h.Phase == model.PhaseExploit && payloadCategory[h.Category] && len(payload) < 3 {
			payload = append(payload, h.Name)
		}
	}
	h := model.Hit{RuleID: "vp-" + s.id, Phase: model.PhaseExploit, Result: result}
	if len(payload) > 0 {
		h.Name, h.Category = v.Name+" "+kind+"利用"+ref, CatCVE
		h.Severity = model.SevHigh
		if s.sev == "medium" {
			h.Severity = model.SevMedium
		}
		h.Evidence = ev.Method + " " + Printable(path, 160) + " 是" + v.Name + "存在" + kind + "的接口" + ref + "，请求中带有攻击载荷（" + strings.Join(payload, "、") + "）"
		return h
	}
	h.Name, h.Category = v.Name+" "+kind+"接口访问"+ref, CatVulnEndpoint
	h.Severity = model.SevMedium
	if s.sev == "medium" {
		h.Severity = model.SevLow
	}
	if h.Result == model.ResultSuccess {
		h.Result = model.ResultPassed // 看不到载荷，2xx 不能说明利用成功
	}
	h.Evidence = ev.Method + " " + Printable(path, 160) + " 是" + v.Name + "存在" + kind + "的接口" + ref + "；载荷在请求体中时日志里看不到，只能看到接口被访问"
	return h
}
