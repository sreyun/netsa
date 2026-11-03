package learn

import (
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

// techSeen 是站点上一个产品 / 开发语言的访问痕迹。
type techSeen struct {
	Nets   []uint32  `json:"nets"`
	Hits   uint32    `json:"hits"`
	Sample string    `json:"sample"` // 示例路径
	First  time.Time `json:"first"`
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

// observeSiteLocked 记录一次正常的成功访问（调用方持 st.mu），返回是否识别出新的产品。
func (st *profileState) observeSiteLocked(host, lp string, nh uint32, at time.Time) bool {
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
	for _, k := range techOf(lp) {
		if s.Tech == nil {
			s.Tech = map[string]*techSeen{}
		}
		t := s.Tech[k]
		if t == nil {
			t = &techSeen{Sample: clipShape(lp), First: at}
			s.Tech[k] = t
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
}

// 文件后缀对应的开发语言。
var extTech = map[string][]string{
	".php": {"php"}, ".php5": {"php"}, ".phtml": {"php"},
	".jsp": {"java"}, ".jspx": {"java"}, ".do": {"java"}, ".jsf": {"java"}, ".faces": {"java"}, ".jspa": {"java"}, ".action": {"java", "struts"},
	".asp": {"asp"}, ".asa": {"asp"}, ".cer": {"asp"},
	".aspx": {"aspnet"}, ".ashx": {"aspnet"}, ".asmx": {"aspnet"}, ".axd": {"aspnet"}, ".svc": {"aspnet"},
	".cgi": {"cgi"}, ".pl": {"cgi"},
}

// 产品隐含的开发语言：出现了 WordPress 也就出现了 PHP。
var techImplies = map[string]string{
	"wordpress": "php", "thinkphp": "php", "laravel": "php", "phpmyadmin": "php", "zabbix": "php",
	"spring": "java", "struts": "java", "weblogic": "java", "jboss": "java", "confluence": "java", "jira": "java",
	"jenkins": "java", "nacos": "java", "druid": "java", "swagger": "java", "geoserver": "java", "solr": "java",
	"nexus": "java", "seeyon": "java", "weaver": "java", "yonyou": "java", "landray": "java", "fanruan": "java",
	"kingdee": "java", "jeecg": "java", "exchange": "aspnet",
}

// techOf 返回请求路径（小写）中出现的产品与开发语言。
func techOf(lp string) []string {
	var out []string
	add := func(k string) {
		for k != "" && !slices.Contains(out, k) {
			out = append(out, k)
			k = techImplies[k]
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
		}
	}
	return out
}

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
	Key    string    `json:"key"`
	Name   string    `json:"name"`
	Sample string    `json:"sample"`
	Hits   uint32    `json:"hits"`
	Nets   int       `json:"nets"`
	First  time.Time `json:"first"`
}

func (s *siteStat) report(host string) SiteReport {
	r := SiteReport{Host: host, Reqs: s.Reqs, Nets: len(s.Nets), Mature: s.mature(), Products: []SiteProduct{}, Last: s.Last}
	for k, t := range s.Tech {
		if len(t.Nets) < techMinNets {
			continue
		}
		r.Products = append(r.Products, SiteProduct{Key: k, Name: techText([]string{k}), Sample: t.Sample, Hits: t.Hits, Nets: len(t.Nets), First: t.First})
	}
	sort.Slice(r.Products, func(i, j int) bool { return r.Products[i].Hits > r.Products[j].Hits })
	return r
}
