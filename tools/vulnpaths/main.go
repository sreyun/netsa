// vulnpaths 从 nuclei-templates（MIT 许可，https://github.com/projectdiscovery/nuclei-templates）中
// 提取国产 OA、中间件、CMS 与网络设备的漏洞请求，生成检测引擎使用的漏洞接口签名
// internal/detect/vulnpaths.tsv。
//
//	go run ./tools/vulnpaths -src /path/to/nuclei-templates > internal/detect/vulnpaths.tsv
//
// 只取请求的方法、路径与查询参数名（以及 method=、action= 这类选择功能的参数值），不取载荷：
// 日志看不到请求体，载荷本身由通用规则识别；签名用来认出“打的是哪个产品的哪个漏洞”。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// vendor 是一个国产产品：nuclei 的标签、产品键（与站点产品识别一致）、中文名、隐含的开发语言或类型。
type vendor struct {
	key, name, lang string
}

var vendors = map[string]vendor{}

func init() {
	add := func(key, name, lang string, tags ...string) {
		for _, t := range tags {
			vendors[t] = vendor{key, name, lang}
		}
	}
	add("seeyon", "致远OA", "java", "seeyon", "zhiyuan")
	add("weaver", "泛微OA", "java", "weaver", "ecology", "e-cology")
	add("eoffice", "泛微E-Office", "php", "e-office", "eoffice")
	add("yonyou", "用友", "java", "yonyou", "ufida", "ksoa", "grp-u8", "u8")
	add("chanjet", "畅捷通T+", "aspnet", "chanjet", "tplus")
	add("tongda", "通达OA", "php", "tongda")
	add("landray", "蓝凌OA", "java", "landray")
	add("fanruan", "帆软报表", "java", "finereport", "fanruan")
	add("kingdee", "金蝶", "java", "kingdee")
	add("wanhu", "万户OA", "java", "wanhu", "ezoffice")
	add("jinher", "金和OA", "", "jinher", "jinhe")
	add("hjsoft", "宏景HCM", "java", "hjsoft")
	add("hongfan", "红帆OA", "aspnet", "hongfan")
	add("smartbi", "Smartbi", "java", "smartbi")
	add("ruoyi", "若依", "java", "ruoyi")
	add("jeecg", "JeecgBoot", "java", "jeecg", "jeeplus")
	add("nacos", "Nacos", "java", "nacos")
	add("xxljob", "XXL-JOB", "java", "xxljob", "xxl-job")
	add("thinkphp", "ThinkPHP", "php", "thinkphp")
	add("thinkcmf", "ThinkCMF", "php", "thinkcmf")
	add("dedecms", "织梦CMS", "php", "dedecms")
	add("74cms", "骑士人才系统", "php", "74cms")
	add("metinfo", "米拓CMS", "php", "metinfo")
	add("eyoucms", "易优CMS", "php", "eyoucms")
	add("seacms", "海洋CMS", "php", "seacms")
	add("phpcms", "PHPCMS", "php", "phpcms")
	add("ecshop", "ECShop", "php", "ecshop")
	add("zentao", "禅道", "php", "zentao")
	add("ueditor", "UEditor编辑器", "", "ueditor")
	add("kindeditor", "KindEditor编辑器", "", "kindeditor")
	add("esafenet", "亿赛通", "java", "esafenet")
	add("sangfor", "深信服", "device", "sangfor")
	add("topsec", "天融信", "device", "topsec")
	add("qax", "奇安信", "device", "qax", "qianxin", "tianqing")
	add("nsfocus", "绿盟", "device", "nsfocus")
	add("leadsec", "网御星云", "device", "leadsec")
	add("panabit", "Panabit", "device", "panabit")
	add("feiyuxing", "飞鱼星", "device", "feiyuxing")
	add("ruijie", "锐捷", "device", "ruijie")
	add("h3c", "H3C", "device", "h3c")
	add("hikvision", "海康威视", "device", "hikvision")
	add("dahua", "大华", "device", "dahua")
	add("huawei", "华为", "device", "huawei")
	add("zte", "中兴", "device", "zte")
	add("tenda", "腾达路由器", "device", "tenda")
	add("totolink", "TOTOLINK路由器", "device", "totolink")
	add("wavlink", "WAVLINK路由器", "device", "wavlink")
}

// 只取这些目录：登录弱口令、产品识别、面板发现不是攻击。
var dirs = []string{"cves", "cnvd", "vulnerabilities", "exposures", "misconfiguration", "iot"}

// 漏洞类型的中文名，按标签顺序取第一个匹配的。
var vtypes = []struct{ tag, name string }{
	{"rce", "远程代码执行"}, {"deserialization", "反序列化"}, {"sqli", "SQL注入"}, {"fileupload", "任意文件上传"},
	{"file-upload", "任意文件上传"}, {"upload", "任意文件上传"}, {"lfi", "任意文件读取"}, {"fileread", "任意文件读取"},
	{"file-read", "任意文件读取"}, {"traversal", "任意文件读取"}, {"ssrf", "SSRF"}, {"xxe", "XXE"},
	{"auth-bypass", "权限绕过"}, {"unauth", "未授权访问"}, {"disclosure", "信息泄露"}, {"exposure", "信息泄露"},
	{"info-leak", "信息泄露"}, {"xss", "XSS"},
}

type template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string `yaml:"name"`
		Severity       string `yaml:"severity"`
		Tags           string `yaml:"tags"`
		Classification struct {
			CVE any `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
	HTTP     []request `yaml:"http"`
	Requests []request `yaml:"requests"`
}

type request struct {
	Method string   `yaml:"method"`
	Path   []string `yaml:"path"`
	Raw    []string `yaml:"raw"`
}

// sig 是一条漏洞接口签名。
type sig struct {
	id, vendor, sev, method, path, query, ref, vtype string
}

var reVar = regexp.MustCompile(`\{\{[^}]*\}\}`)

// 选择功能的参数：取值决定调用的是哪个功能，作为签名的一部分；其他参数只要求出现。
var selector = map[string]bool{"method": true, "action": true, "act": true, "op": true, "operation": true, "m": true, "a": true,
	"c": true, "mod": true, "module": true, "func": true, "function": true, "service": true, "s": true, "r": true, "do": true}

var reToken = regexp.MustCompile(`^[a-z0-9_.\-/]{1,48}$`)

// 太常见、不足以说明访问了漏洞接口的路径。
var genericPaths = map[string]bool{"/": true, "/index.php": true, "/index.jsp": true, "/index.html": true, "/login": true,
	"/login.php": true, "/login.jsp": true, "/admin": true, "/admin/": true, "/api": true, "/*": true, "/*.jsp": true,
	"/*.php": true, "/*.txt": true, "/*.html": true, "/*/*": true, "/index.do": true, "/main.do": true,
	// 其他系统也常用的接口名：不能说明打的是这个产品
	"/download.do": true, "/client.do": true, "/api/system/deviceinfo": true, "/index/download/index": true,
	"/search.php": true, "/officeserver": true}

func main() {
	src := flag.String("src", "", "nuclei-templates 目录")
	samples := flag.String("samples", "", "同时把每条签名对应的原始请求（变量填上随机值）写到这个文件，用于验证检测")
	flag.Parse()
	var sampleOut *os.File
	if *samples != "" {
		f, err := os.Create(*samples)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		sampleOut = f
	}
	if *src == "" {
		fmt.Fprintln(os.Stderr, "需要 -src")
		os.Exit(2)
	}
	commit := ""
	if out, err := exec.Command("git", "-C", *src, "rev-parse", "--short=12", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(out))
	}
	seen := map[string]bool{}
	var sigs []sig
	segs := map[string]map[string]int{} // 路径第一段 → 产品 → 模板数
	skipped := map[string]int{}
	for _, d := range dirs {
		root := filepath.Join(*src, "http", d)
		filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasSuffix(p, ".yaml") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			var t template
			if yaml.Unmarshal(b, &t) != nil || t.ID == "" {
				skipped["parse"]++
				return nil
			}
			v, ok := vendorOf(t.Info.Tags, p)
			if !ok {
				return nil
			}
			sev := map[string]string{"critical": "high", "high": "high", "medium": "medium"}[strings.ToLower(t.Info.Severity)]
			if sev == "" {
				skipped["severity"]++
				return nil
			}
			ref := refOf(&t)
			vt := vtypeOf(t.Info.Tags)
			n := 0
			for _, r := range append(t.HTTP, t.Requests...) {
				for _, req := range requestsOf(r) {
					method, path, query, ok := normalize(req.method, req.target)
					if !ok {
						skipped["generic"]++
						continue
					}
					k := method + " " + path + "?" + query
					if seen[k] {
						continue
					}
					seen[k] = true
					n++
					id := strings.ToLower(t.ID)
					if n > 1 {
						id += fmt.Sprintf("-%d", n)
					}
					sigs = append(sigs, sig{id: id, vendor: v.key, sev: sev, method: method, path: path, query: query, ref: ref, vtype: vt})
					if sampleOut != nil {
						target := req.target
						for _, p := range []string{"{{BaseURL}}", "{{RootURL}}", "{{Hostname}}"} {
							target = strings.TrimPrefix(target, p)
						}
						fmt.Fprintf(sampleOut, "%s\t%s\t%s\n", id, req.method, reVar.ReplaceAllString(target, "x7k2q9"))
					}
					if s := firstSeg(path); s != "" {
						if segs[s] == nil {
							segs[s] = map[string]int{}
						}
						segs[s][v.key]++
					}
				}
			}
			return nil
		})
	}
	// 补充签名：nuclei-templates 中没有、但在国内广泛被利用的接口（原 cve-middleware 规则中的部分路径）
	for _, s := range extras {
		k := s.method + " " + s.path + "?" + s.query
		if !seen[k] {
			seen[k] = true
			sigs = append(sigs, s)
		}
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].id < sigs[j].id })
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "# 由 tools/vulnpaths 从 nuclei-templates（MIT 许可，Copyright (c) 2025 ProjectDiscovery, Inc.）生成，提交 %s；不要手工修改。\n", commit)
	fmt.Fprintln(w, "# vendor<TAB>产品键<TAB>中文名<TAB>开发语言或类型")
	keys := make([]string, 0, len(vendors))
	byKey := map[string]vendor{}
	for _, v := range vendors {
		if _, ok := byKey[v.key]; !ok {
			keys = append(keys, v.key)
		}
		byKey[v.key] = v
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := byKey[k]
		fmt.Fprintf(w, "vendor\t%s\t%s\t%s\n", v.key, v.name, v.lang)
	}
	// 产品目录：只有一个产品使用、出现在至少 2 个模板中的第一级目录，可以在正常访问中识别该产品
	fmt.Fprintln(w, "# marker<TAB>路径第一段<TAB>产品键")
	var markers []string
	for s, m := range segs {
		if len(m) != 1 || commonSeg[s] || len(s) < 5 {
			continue // ajax、page、sys 这类短目录名太常见，会把站点误认成某个产品
		}
		for k, c := range m {
			if c >= 2 {
				markers = append(markers, fmt.Sprintf("marker\t%s\t%s", s, k))
			}
		}
	}
	sort.Strings(markers)
	for _, m := range markers {
		fmt.Fprintln(w, m)
	}
	fmt.Fprintln(w, "# sig<TAB>ID<TAB>产品键<TAB>等级<TAB>方法<TAB>路径（* 为任意）<TAB>必需的查询参数（& 分隔）<TAB>编号<TAB>漏洞类型")
	for _, s := range sigs {
		fmt.Fprintf(w, "sig\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.id, s.vendor, s.sev, s.method, s.path, s.query, s.ref, s.vtype)
	}
	fmt.Fprintf(os.Stderr, "签名 %d 条，产品目录 %d 个，跳过 %v\n", len(sigs), len(markers), skipped)
}

// extras 是人工维护的补充签名。
var extras = []sig{
	{id: "netsa-tongda-im-upload", vendor: "tongda", sev: "high", method: "POST", path: "/ispirit/im/upload.php", vtype: "任意文件上传"},
	{id: "netsa-weaver-workflowcenter-upload", vendor: "weaver", sev: "high", method: "POST", path: "/mobile/browser/workflowcenteruploadfile*", vtype: "任意文件上传"},
}

// 太常见的第一级目录，不能说明是某个产品。
var commonSeg = map[string]bool{"api": true, "admin": true, "servlet": true, "web": true, "system": true, "user": true,
	"login": true, "manager": true, "console": true, "common": true, "js": true, "static": true, "upload": true,
	"uploads": true, "include": true, "includes": true, "plugins": true, "plugin": true, "services": true, "service": true,
	"ws": true, "rest": true, "mobile": true, "general": true, "module": true, "modules": true, "app": true, "portal": true,
	"cgi-bin": true, "data": true, "public": true, "home": true, "index": true, "member": true, "*": true, "action": true,
	"interface": true, "inc": true, "lib": true, "config": true, "goform": true, "boaform": true, "web-inf": true,
	"isapi": true, "sdk": true, "tmp": true, "temp": true, "help": true, "m": true, "wap": true, "h5": true,
	"admin-api": true, "upgrade": true, "webservice": true, "webservices": true, "share": true,
	"report": true, "reports": true, "download": true, "files": true, "file": true, "resource": true, "resources": true,
	"attachment": true, "attachments": true, "install": true, "center": true, "portal-api": true, "manage": true,
}

func firstSeg(path string) string {
	s := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	} else {
		return "" // 根目录下的文件不是目录
	}
	if strings.ContainsAny(s, "*.?") {
		return ""
	}
	return s
}

// vendorOf 按模板所在目录（http/vulnerabilities/<厂商>/）判断厂商，再看标签：
// 标签里常同时出现母公司与产品（畅捷通 T+ 的模板也带 yonyou）。
func vendorOf(tags, path string) (vendor, bool) {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if v, ok := vendors[strings.ToLower(part)]; ok {
			return v, true
		}
	}
	for _, t := range strings.Split(tags, ",") {
		if v, ok := vendors[strings.ToLower(strings.TrimSpace(t))]; ok {
			return v, true
		}
	}
	return vendor{}, false
}

func refOf(t *template) string {
	switch c := t.Info.Classification.CVE.(type) {
	case string:
		if c != "" {
			return strings.ToUpper(c)
		}
	case []any:
		if len(c) > 0 {
			return strings.ToUpper(fmt.Sprint(c[0]))
		}
	}
	id := strings.ToUpper(t.ID)
	if strings.HasPrefix(id, "CVE-") || strings.HasPrefix(id, "CNVD-") {
		return id
	}
	return ""
}

func vtypeOf(tags string) string {
	set := map[string]bool{}
	for _, t := range strings.Split(tags, ",") {
		set[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for _, v := range vtypes {
		if set[v.tag] {
			return v.name
		}
	}
	return "漏洞"
}

type rawReq struct{ method, target string }

func requestsOf(r request) []rawReq {
	var out []rawReq
	for _, p := range r.Path {
		m := r.Method
		if m == "" {
			m = "GET"
		}
		out = append(out, rawReq{m, p})
	}
	for _, raw := range r.Raw {
		line, _, _ := strings.Cut(strings.TrimLeft(raw, " \t\r\n"), "\n")
		f := strings.Fields(line)
		if len(f) >= 2 {
			out = append(out, rawReq{f[0], f[1]})
		}
	}
	return out
}

// normalize 把模板中的请求目标转成签名：去掉 {{BaseURL}} 等前缀，变量换成 *，按检测引擎的方式解码、转小写。
// 查询参数只保留参数名，选择功能的参数保留取值。
func normalize(method, target string) (string, string, string, bool) {
	method = strings.ToUpper(method)
	if method != "GET" && method != "POST" && method != "PUT" && method != "HEAD" {
		return "", "", "", false
	}
	if method == "HEAD" {
		method = "GET"
	}
	for _, p := range []string{"{{BaseURL}}", "{{RootURL}}", "{{Hostname}}", "{{baseurl}}", "{{rooturl}}"} {
		target = strings.TrimPrefix(target, p)
	}
	if target == "" || target[0] != '/' {
		return "", "", "", false
	}
	path, query, _ := strings.Cut(target, "?")
	path = reVar.ReplaceAllString(path, "*")
	if p, err := url.PathUnescape(path); err == nil {
		path = p
	}
	path = strings.ToLower(path)
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	// 与检测引擎一致：去掉每一段的 ;参数（/files;.js、/netsecconfigajax;service 这类绕过写法）
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if j := strings.IndexByte(s, ';'); j >= 0 {
			segs[i] = s[:j]
		}
	}
	path = strings.Join(segs, "/")
	if strings.ContainsAny(path, " \t\"'<>{}|\\^`[]") || strings.Contains(path, "..") || strings.Contains(path, "%") {
		return "", "", "", false // 路径里带着载荷：交给通用规则
	}
	if genericPaths[path] || literalLen(path) < 8 || !hasLiteralSeg(path) {
		return "", "", "", false
	}
	last := path[strings.LastIndexByte(path, '/')+1:]
	if strings.Contains(last, "*") && (method == "GET" || staticExt(last)) {
		return "", "", "", false // 上传之后验证文件是否落地的请求（/upload/*.jpg），与正常的文件访问分不开
	}
	var parts []string
	for _, kv := range strings.Split(query, "&") {
		k, v, _ := strings.Cut(kv, "=")
		k = strings.ToLower(decode(k))
		if k == "" || strings.Contains(k, "{{") || !reToken.MatchString(k) {
			continue
		}
		v = strings.ToLower(decode(v))
		if selector[k] && reToken.MatchString(v) && !strings.Contains(v, "{{") {
			parts = append(parts, k+"="+v)
		} else {
			parts = append(parts, k)
		}
	}
	sort.Strings(parts)
	q := strings.Join(parts, "&")
	if loginPath(path) && !strings.Contains(q, "=") {
		return "", "", "", false // 登录接口：注入载荷在请求体里，只凭路径会把正常登录当成攻击
	}
	if method == "GET" && q == "" && pageLoad(last) {
		return "", "", "", false // 多步模板里先确认产品的首页请求（/seeyon/main.do、/xxl-job-admin/），正常访问都会打到
	}
	return method, path, q, true
}

// pageLoad 判断是否为目录或首页：index.*、main.*、default.*、home.*。
func pageLoad(last string) bool {
	if last == "" {
		return true
	}
	for _, p := range []string{"index.", "main.", "default.", "home."} {
		if strings.HasPrefix(last, p) {
			return true
		}
	}
	return false
}

func loginPath(p string) bool {
	for _, w := range []string{"login", "logon", "signin", "sign-in", "auth"} {
		if strings.Contains(p, w) {
			return true
		}
	}
	return false
}

func staticExt(name string) bool {
	for _, e := range []string{".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".txt", ".html", ".htm", ".ico", ".svg"} {
		if strings.HasSuffix(name, e) {
			return true
		}
	}
	return false
}

// hasLiteralSeg 判断路径中至少有一段完整的字面量（检测时按这一段查找签名）。
func hasLiteralSeg(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if len(s) >= 3 && !strings.Contains(s, "*") {
			return true
		}
	}
	return false
}

func decode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

// literalLen 是路径中去掉通配符与分隔符后的字符数。
func literalLen(p string) int {
	n := 0
	for _, c := range p {
		if c != '*' && c != '/' && c != '.' {
			n++
		}
	}
	return n
}
