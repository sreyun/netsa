package learn

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"netsa/internal/detect"
	"netsa/internal/model"
)

// 被动识别站点产品：从正常访客的成功请求（2xx / 304）中识别每个站点使用的产品与开发语言，
// 例如 /wp-content/ 说明是 WordPress，.php 说明有 PHP，.do / .action 说明是 Java 应用。
//
// 用途：针对某个产品的漏洞探测（ThinkPHP、WebLogic、Exchange……）、按脚本后缀访问的 WebShell 与敏感文件探测，
// 在站点上从未出现过该产品的访问痕迹、请求本身也没有成功（404、被拦截、出错）时，攻击不可能得手，最高按低危处置。
// 只在站点有足够多的正常访问、来自足够多的网段时判断；某个产品至少被几个不同网段的正常访客访问过才算“出现过”。
// 判断错的代价是一条没有成功的探测按低危显示，不会漏掉成功的攻击：成功的请求不做这个判断。

const (
	maxSites     = 2000
	siteMinReqs  = 300 // 站点参与判断所需的最少正常访问
	siteMinNets  = 20  // 以及最少的来源网段
	techMinNets  = 3   // 产品至少被这么多网段的正常访客访问过才算出现过
	maxSiteNets  = 32
	maxTechNets  = 8
	maxTechPaths = 3 // 只看路径的前几段：产品通常挂在站点根目录或第二级目录下
)

// siteStat 是一个站点的正常访问统计。
type siteStat struct {
	Reqs  uint32               `json:"reqs"`
	Nets  []uint32             `json:"nets,omitempty"`
	Tech  map[string]*techSeen `json:"tech,omitempty"`
	First time.Time            `json:"first"`
	Last  time.Time            `json:"last"`
}

// techSeen 是站点上一个产品 / 开发语言 / 前端框架的访问痕迹。
type techSeen struct {
	Nets    []uint32  `json:"nets"`
	Hits    uint32    `json:"hits"`
	Sample  string    `json:"sample"`            // 示例路径
	Version string    `json:"version,omitempty"` // 文件名里带的版本号（jquery-1.8.3.min.js）
	First   time.Time `json:"first"`
}

func (s *siteStat) mature() bool { return s.Reqs >= siteMinReqs && len(s.Nets) >= siteMinNets }

func (s *siteStat) has(tech string) bool {
	t := s.Tech[tech]
	return t != nil && len(t.Nets) >= techMinNets
}

func (s *siteStat) hasAny(techs []string) bool {
	for _, t := range techs {
		if s.has(t) {
			return true
		}
	}
	return false
}

func (s *siteStat) clone() siteStat {
	c := *s
	c.Nets = append([]uint32(nil), s.Nets...)
	c.Tech = make(map[string]*techSeen, len(s.Tech))
	for k, t := range s.Tech {
		x := *t
		x.Nets = append([]uint32(nil), t.Nets...)
		c.Tech[k] = &x
	}
	return c
}

// formatTech 是日志格式本身说明的网关产品：APISIX、Nginx Proxy Manager 的默认访问日志与 nginx 不同，
// 能识别出这种格式，就说明站点经由该网关对外提供服务。
var formatTech = map[string]string{"apisix": "apisix", "nginx_proxy_manager": "npm"}

// observeSiteLocked 记录一次正常的成功访问（调用方持 st.mu），返回是否识别出新的产品。format 为日志格式。
func (st *profileState) observeSiteLocked(host, lp, format string, nh uint32, at time.Time) bool {
	if st.sites == nil {
		st.sites = map[string]*siteStat{}
	}
	s := st.sites[host]
	if s == nil {
		if len(st.sites) >= maxSites {
			// 随意填写 Host 头的请求也会建立站点：清掉访问很少的，仍然满了就不再记录新站点
			for k, x := range st.sites {
				if x.Reqs < 10 {
					delete(st.sites, k)
				}
			}
			if len(st.sites) >= maxSites {
				return false
			}
		}
		s = &siteStat{First: at}
		st.sites[host] = s
	}
	s.Reqs++
	addNet(&s.Nets, nh, maxSiteNets)
	if at.After(s.Last) {
		s.Last = at
	}
	found := false
	keys := techOf(lp)
	if k := formatTech[format]; k != "" && !slices.Contains(keys, k) {
		keys = append(keys, k)
		for _, x := range techImplies[k] {
			if !slices.Contains(keys, x) {
				keys = append(keys, x)
			}
		}
	}
	for _, k := range keys {
		if s.Tech == nil {
			s.Tech = map[string]*techSeen{}
		}
		t := s.Tech[k]
		if t == nil {
			t = &techSeen{Sample: clipShape(lp), First: at}
			s.Tech[k] = t
		}
		if t.Version == "" {
			if v := libVersion(k, lp); v != "" {
				t.Version, t.Sample = v, clipShape(lp)
			}
		}
		was := len(t.Nets) >= techMinNets
		t.Hits++
		addNet(&t.Nets, nh, maxTechNets)
		found = found || !was && len(t.Nets) >= techMinNets
	}
	return found
}

// 产品 / 开发语言的名称。
var techNames = map[string]string{
	"php": "PHP", "java": "Java", "asp": "ASP", "aspnet": "ASP.NET", "cgi": "CGI",
	"wordpress": "WordPress", "thinkphp": "ThinkPHP", "laravel": "Laravel", "phpmyadmin": "phpMyAdmin", "zabbix": "Zabbix",
	"spring": "Spring Boot", "struts": "Struts2", "weblogic": "WebLogic", "jboss": "JBoss", "confluence": "Confluence",
	"jira": "Jira", "jenkins": "Jenkins", "nacos": "Nacos", "druid": "Druid", "swagger": "Swagger", "geoserver": "GeoServer",
	"solr": "Solr", "nexus": "Nexus", "exchange": "Exchange", "f5": "F5 BIG-IP", "citrix": "Citrix", "vmware": "VMware vCenter",
	"seeyon": "致远 OA", "weaver": "泛微 OA", "yonyou": "用友", "tongda": "通达 OA", "landray": "蓝凌 OA", "fanruan": "帆软报表",
	"kingdee": "金蝶", "jeecg": "JeecgBoot", "grafana": "Grafana", "kibana": "Kibana", "minio": "MinIO",
	"nextjs": "Next.js", "nuxt": "Nuxt", "device": "网络设备 / IoT 管理页面", "hikvision": "海康威视",
	"docker": "Docker API", "k8s": "Kubernetes API",
	"node": "Node.js", "socketio": "Socket.IO", "sveltekit": "SvelteKit", "vue": "Vue", "react": "React", "angular": "Angular",
	"angularjs": "AngularJS", "jquery": "jQuery", "bootstrap": "Bootstrap", "layui": "layui", "element": "Element",
	"iview": "iView", "umi": "UmiJS",
	"apisix": "Apache APISIX", "nginxui": "Nginx UI", "npm": "Nginx Proxy Manager", "kong": "Kong", "openresty": "OpenResty",
}

// 路径中出现即说明使用了该产品的目录名。
var segTech = map[string]string{
	"wp-content": "wordpress", "wp-includes": "wordpress", "wp-json": "wordpress", "wp-admin": "wordpress",
	"actuator": "spring", "jenkins": "jenkins", "nacos": "nacos", "druid": "druid", "swagger-ui": "swagger",
	"swagger-resources": "swagger", "geoserver": "geoserver", "solr": "solr", "nexus": "nexus", "confluence": "confluence",
	"jira": "jira", "phpmyadmin": "phpmyadmin", "zabbix": "zabbix", "grafana": "grafana", "kibana": "kibana", "minio": "minio",
	"_next": "nextjs", "_nuxt": "nuxt", "owa": "exchange", "ecp": "exchange", "ews": "exchange", "autodiscover": "exchange",
	"tmui": "f5", "citrix": "citrix", "websso": "vmware", "vsphere-client": "vmware",
	"seeyon": "seeyon", "weaver": "weaver", "wui": "weaver", "yyoa": "yonyou", "uapws": "yonyou", "ispirit": "tongda",
	"ekp": "landray", "webreport": "fanruan", "k3cloud": "kingdee", "jeecg-boot": "jeecg",
	"jmx-console": "jboss", "web-console": "jboss", "cgi-bin": "cgi", "goform": "device", "boaform": "device", "isapi": "hikvision",
	// Node.js 后端只有这类路径能看出来：Socket.IO 的连接地址、Next.js / Nuxt / SvelteKit 的资源目录、
	// 对外暴露的 webpack 开发服务器（sockjs-node、__webpack_hmr）。纯接口的 Node 服务从日志里看不出来
	"socket.io": "socketio", "sockjs-node": "node", "__webpack_hmr": "node", "iview": "iview", "layui": "layui", "element-ui": "element",
	// nginx 系网关与管理面板：APISIX 的 Admin API / 指标、Nginx UI 的日志与 MCP 接口、Nginx Proxy Manager 的代理站点接口、Kong Manager 的配置脚本
	"apisix": "apisix", "nginx_log": "nginxui", "mcp_message": "nginxui", "proxy-hosts": "npm", "redirection-hosts": "npm", "dead-hosts": "npm",
	"kconfig.js": "kong",
}

// 文件后缀对应的开发语言。
var extTech = map[string][]string{
	".php": {"php"}, ".php5": {"php"}, ".phtml": {"php"},
	".jsp": {"java"}, ".jspx": {"java"}, ".do": {"java"}, ".jsf": {"java"}, ".faces": {"java"}, ".jspa": {"java"}, ".action": {"java", "struts"},
	".asp": {"asp"}, ".asa": {"asp"}, ".cer": {"asp"},
	".aspx": {"aspnet"}, ".ashx": {"aspnet"}, ".asmx": {"aspnet"}, ".axd": {"aspnet"}, ".svc": {"aspnet"},
	".cgi": {"cgi"}, ".pl": {"cgi"},
}

// 产品隐含的开发语言与框架：出现了 WordPress 也就出现了 PHP，Next.js 运行在 Node.js 上、前端是 React。
var techImplies = map[string][]string{
	"wordpress": {"php"}, "thinkphp": {"php"}, "laravel": {"php"}, "phpmyadmin": {"php"}, "zabbix": {"php"},
	"spring": {"java"}, "struts": {"java"}, "weblogic": {"java"}, "jboss": {"java"}, "confluence": {"java"}, "jira": {"java"},
	"jenkins": {"java"}, "nacos": {"java"}, "druid": {"java"}, "swagger": {"java"}, "geoserver": {"java"}, "solr": {"java"},
	"nexus": {"java"}, "seeyon": {"java"}, "weaver": {"java"}, "yonyou": {"java"}, "landray": {"java"}, "fanruan": {"java"},
	"kingdee": {"java"}, "jeecg": {"java"}, "exchange": {"aspnet"},
	"nextjs": {"react", "node"}, "nuxt": {"vue", "node"}, "sveltekit": {"node"}, "socketio": {"node"},
	"element": {"vue"}, "iview": {"vue"}, "umi": {"react"},
	"apisix": {"openresty"}, "kong": {"openresty"}, "npm": {"openresty"},
}

// techOf 返回请求路径（小写）中出现的产品、开发语言与前端框架。
func techOf(lp string) []string {
	var out []string
	var add func(k string)
	add = func(k string) {
		if k == "" || slices.Contains(out, k) {
			return
		}
		out = append(out, k)
		for _, x := range techImplies[k] {
			add(x)
		}
		if v, ok := detect.VulnVendorInfo(k); ok && v.Lang != "" && techImplies[k] == nil {
			add(v.Lang) // 漏洞签名覆盖的国产产品：致远 OA 隐含 Java、通达 OA 隐含 PHP
		}
	}
	last := lp[strings.LastIndexByte(lp, '/')+1:]
	if i := strings.IndexByte(last, ';'); i >= 0 { // ;jsessionid=
		if strings.HasPrefix(last[i:], ";jsessionid=") {
			add("java")
		}
		last = last[:i]
	}
	if dot := strings.LastIndexByte(last, '.'); dot >= 0 {
		for _, k := range extTech[last[dot:]] {
			add(k)
		}
	}
	rest := strings.TrimPrefix(lp, "/")
	for i := 0; i < maxTechPaths && rest != ""; i++ {
		seg := rest
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			seg, rest = rest[:j], rest[j+1:]
		} else {
			rest = ""
		}
		if k, ok := segTech[seg]; ok {
			add(k)
		} else if i == 0 {
			add(detect.VulnMarker(seg)) // 漏洞签名中只有这个产品使用的第一级目录（/defaultroot/、/cdgserver3/……）
		}
	}
	if strings.Contains(lp, "/_app/immutable/") {
		add("sveltekit")
	}
	if strings.HasSuffix(last, ".js") || strings.HasSuffix(last, ".mjs") || strings.HasSuffix(last, ".css") {
		for _, k := range frontendOf(last, lp) {
			add(k)
		}
	}
	return out
}

// frontendOf 按脚本、样式的文件名识别前端框架与常用库：打包产物有固定的命名，直接引用的库文件名就是库名。
func frontendOf(last, lp string) []string {
	var out []string
	switch {
	case strings.Contains(last, ".vue_vue_type") || strings.HasPrefix(last, "_plugin-vue") || strings.HasPrefix(last, "chunk-vendors") ||
		libFile(last, "vue") || libFile(last, "vuex") || libFile(last, "vue-router"):
		out = append(out, "vue") // Vite 编译的单文件组件、vue-cli 的公共包、直接引用的 vue.min.js
	case libFile(last, "react") || libFile(last, "react-dom") || strings.Contains(lp, "/static/js/") && strings.HasSuffix(last, ".chunk.js"):
		out = append(out, "react") // create-react-app 的 /static/js/*.chunk.js
	case strings.HasPrefix(last, "umi.") && strings.HasSuffix(last, ".js"):
		out = append(out, "umi")
	case strings.HasPrefix(last, "polyfills-es20") || strings.HasPrefix(last, "main-es20") || angularHashed(last):
		out = append(out, "angular")
	case libFile(last, "angular"):
		out = append(out, "angularjs") // angular.min.js 是 1.x，已停止维护
	}
	for _, x := range [...]struct{ name, key string }{{"jquery", "jquery"}, {"bootstrap", "bootstrap"}, {"layui", "layui"},
		{"element-ui", "element"}, {"element-plus", "element"}, {"iview", "iview"}, {"view-design", "iview"}} {
		if libFile(last, x.name) {
			out = append(out, x.key)
		}
	}
	return out
}

// libFile 判断文件名是否以库名开头、后面紧跟 . - @ _（vue.min.js、jquery-1.8.3.min.js；reactive.js 不算 react）。
func libFile(last, name string) bool {
	if !strings.HasPrefix(last, name) {
		return false
	}
	if len(last) == len(name) {
		return true
	}
	c := last[len(name)]
	return c == '.' || c == '-' || c == '@' || c == '_'
}

// angularHashed 判断是否为 Angular CLI 的打包产物 polyfills.<16 位以上十六进制>.js。
func angularHashed(last string) bool {
	h, ok := strings.CutPrefix(last, "polyfills.")
	if !ok || !strings.HasSuffix(h, ".js") {
		return false
	}
	h = strings.TrimSuffix(h, ".js")
	return len(h) >= 16 && isHexish(h)
}

// 记录版本号的库：文件名或上一级目录里常带版本（jquery-1.8.3.min.js、/jquery/1.8.3/jquery.min.js）。
var versioned = map[string]string{"jquery": "jquery", "bootstrap": "bootstrap", "vue": "vue", "react": "react", "angularjs": "angular", "layui": "layui"}

// libVersion 从路径中取出库的版本号，没有时返回空串。
func libVersion(tech, lp string) string {
	name, ok := versioned[tech]
	if !ok {
		return ""
	}
	dir, last := "", lp
	if i := strings.LastIndexByte(lp, '/'); i >= 0 {
		dir, last = lp[:i], lp[i+1:]
	}
	if !strings.HasPrefix(last, name) {
		return ""
	}
	if rest := last[len(name):]; rest != "" && (rest[0] == '-' || rest[0] == '@') {
		if v := leadingVersion(strings.TrimPrefix(rest[1:], "v")); v != "" {
			return v
		}
	}
	return leadingVersion(dir[strings.LastIndexByte(dir, '/')+1:]) // CDN 的 /库名/版本/文件 目录结构
}

var reLeadingVersion = regexp.MustCompile(`^\d{1,3}\.\d{1,3}(\.\d{1,4})?`)

// leadingVersion 返回开头形如 1.8 或 1.8.3 的版本号。
func leadingVersion(s string) string { return reLeadingVersion.FindString(s) }

// 只针对特定产品的漏洞利用规则，及满足其中任意一个即可能存在漏洞的产品 / 开发语言。
var ruleTech = map[string][]string{
	"cve-thinkphp": {"php"}, "cve-phpunit": {"php"}, "cve-laravel": {"php"},
	"cve-weblogic": {"weblogic", "java"}, "cve-jboss": {"jboss", "java"}, "cve-spring-gw": {"spring", "java"},
	"cve-confluence": {"confluence"}, "cve-exchange": {"exchange", "aspnet"},
	"cve-f5": {"f5"}, "cve-citrix": {"citrix"}, "cve-vmware": {"vmware"},
	"cve-gpon": {"device", "cgi"}, "cve-hikvision": {"hikvision", "device"}, "cve-iot": {"device", "cgi"},
	"cve-container": {"docker", "k8s"},
}

// requiredTech 返回命中的攻击要得手、站点必须运行的产品 / 开发语言（任意一个）；不针对特定产品时返回 nil。
// 没有登记的已知漏洞利用、WebShell 与敏感文件探测按请求文件的后缀判断（访问 .php 的 WebShell 需要站点有 PHP）。
func requiredTech(h *model.Hit, lp string) []string {
	if t, ok := ruleTech[h.RuleID]; ok {
		return t
	}
	if v := detect.VulnVendorOf(h.RuleID); v != "" {
		return []string{v} // 国产 OA、中间件的漏洞接口签名
	}
	switch h.Category {
	case detect.CatCVE, detect.CatWebShell, detect.CatSensitive:
	default:
		return nil
	}
	last := lp[strings.LastIndexByte(lp, '/')+1:]
	if i := strings.IndexByte(last, ';'); i >= 0 {
		last = last[:i]
	}
	dot := strings.LastIndexByte(last, '.')
	if dot < 0 {
		return nil
	}
	switch ts := extTech[last[dot:]]; {
	case len(ts) == 0:
		return nil
	case ts[0] == "asp" || ts[0] == "aspnet":
		return []string{"asp", "aspnet"} // IIS 上两者常在同一站点
	default:
		return ts[:1]
	}
}

func techText(techs []string) string {
	names := make([]string, 0, len(techs))
	for _, t := range techs {
		if n := techNames[t]; n != "" {
			names = append(names, n)
		} else if v, ok := detect.VulnVendorInfo(t); ok {
			names = append(names, v.Name)
		} else {
			names = append(names, t)
		}
	}
	return strings.Join(names, " / ")
}

// SiteReport 是一个站点的产品识别结果。
type SiteReport struct {
	Host     string        `json:"host"`
	Reqs     uint32        `json:"reqs"`   // 正常的成功访问次数
	Nets     int           `json:"nets"`   // 来源网段数（最多统计 32 个）
	Mature   bool          `json:"mature"` // 访问量已足够，参与产品适用性判断
	Products []SiteProduct `json:"products"`
	Last     time.Time     `json:"last"`
}

// SiteProduct 是站点上识别出的一个产品或开发语言。
type SiteProduct struct {
	Key     string    `json:"key"`
	Name    string    `json:"name"`
	Sample  string    `json:"sample"`
	Version string    `json:"version,omitempty"`
	Hits    uint32    `json:"hits"`
	Nets    int       `json:"nets"`
	First   time.Time `json:"first"`
}

func (s *siteStat) report(host string) SiteReport {
	r := SiteReport{Host: host, Reqs: s.Reqs, Nets: len(s.Nets), Mature: s.mature(), Products: []SiteProduct{}, Last: s.Last}
	for k, t := range s.Tech {
		if len(t.Nets) < techMinNets {
			continue
		}
		r.Products = append(r.Products, SiteProduct{Key: k, Name: techText([]string{k}), Sample: t.Sample, Version: t.Version, Hits: t.Hits, Nets: len(t.Nets), First: t.First})
	}
	sort.Slice(r.Products, func(i, j int) bool { return r.Products[i].Hits > r.Products[j].Hits })
	return r
}
