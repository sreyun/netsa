package store

import (
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"netsa/internal/exposure"
	"netsa/internal/geo"
	"netsa/internal/model"
)

// Endpoint 是一个真实存在（返回 2xx/3xx）的 Web 资产入口。
type Endpoint struct {
	Host       string              `json:"host"`
	Path       string              `json:"path"`
	Methods    map[string]int      `json:"methods"`
	Hits       int64               `json:"hits"`
	Attacks    int64               `json:"attacks"`
	Attackers  int                 `json:"attackers"`
	Status     map[int]int         `json:"status"`
	Sensitive  string              `json:"sensitive,omitempty"`
	Severity   model.Severity      `json:"severity"`
	Tech       []string            `json:"tech,omitempty"`
	FirstSeen  time.Time           `json:"first_seen"`
	LastSeen   time.Time           `json:"last_seen"`
	atk        map[string]struct{} // 攻击者集合（有上限）
	sens       *sensitiveRule      // 敏感资源分类缓存
	classified bool
	// 正常（非攻击）2xx 响应大小的均值与方差（Welford 算法），用于复核攻击请求的“疑似成功”研判
	normN          int64
	normMean, norm float64
}

// observeNormal 记录一次正常响应的大小。
func (ep *Endpoint) observeNormal(bytes int64) {
	ep.normN++
	x := float64(bytes)
	d := x - ep.normMean
	ep.normMean += d / float64(ep.normN)
	ep.norm += d * (x - ep.normMean)
}

// baselineMatches 判断攻击请求的响应是否就是该接口的正常页面：要求接口的正常响应大小稳定
// （至少 5 个样本、变异系数不超过 10%），且本次响应与均值相差不超过 5% 或 2 个标准差。
// 响应大小本身波动较大的接口无法据此判断，保留原研判，宁可多报也不漏掉真实的攻击成功。
func (ep *Endpoint) baselineMatches(bytes int64) bool {
	if ep == nil || ep.normN < 5 || bytes <= 0 || ep.normMean <= 0 {
		return false
	}
	std := math.Sqrt(ep.norm / float64(ep.normN-1))
	if std/ep.normMean > 0.1 {
		return false
	}
	return math.Abs(float64(bytes)-ep.normMean) <= math.Max(0.05*ep.normMean, 2*std)
}

// Service 是从防火墙日志中观测到的网络服务（目的 IP:端口）。
type Service struct {
	DstIP    string              `json:"dst_ip"`
	Port     int                 `json:"port"`
	Proto    string              `json:"proto"`
	Name     string              `json:"name"`
	Risk     model.Severity      `json:"risk"`
	Allowed  int64               `json:"allowed"`
	Denied   int64               `json:"denied"`
	Sources  int                 `json:"sources"`
	Exposed  bool                `json:"exposed"` // 存在来自公网的放行流量
	LastSeen time.Time           `json:"last_seen"`
	src      map[string]struct{} // 来源集合（有上限）
}

// Finding 是攻击面风险发现。
type Finding struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Category    string         `json:"category"`
	Severity    model.Severity `json:"severity"`
	Asset       string         `json:"asset"`
	Evidence    string         `json:"evidence"`
	Remediation string         `json:"remediation"`
	IPs         []string       `json:"ips,omitempty"` // 相关地址：攻击来源，或失陷主机外连的地址（最多 8 个）
	Count       int64          `json:"count"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
}

type surface struct {
	Endpoints map[string]*Endpoint `json:"endpoints"`
	Services  map[string]*Service  `json:"services"`
	Findings  map[string]*Finding  `json:"findings"`
	Tech      map[string]int       `json:"tech"`
	Ports     map[int]int64        `json:"ports"` // 被探测的目的端口
	// 漏洞利用类攻击的结果统计，用于评估 WAF 防护有效性
	ExploitBlocked int64 `json:"exploit_blocked"`
	ExploitPassed  int64 `json:"exploit_passed"`
	// soft 记录各站点敏感路径 / WebShell 探测返回 200 时的响应大小 → 路径（有上限），用于识别兜底页（不持久化，运行中重新学习）
	soft map[string]map[int64]map[string]struct{}
}

const (
	maxSoftHosts = 2000
	maxSoftSizes = 64
	softSamePath = 3 // 不同探测路径返回完全相同大小的次数达到该值即判定为兜底页
)

// catchAll 判断一个 200 响应是否其实是站点的兜底页面：单页应用把所有路径都返回 index.html、统一错误页返回 200 时，
// 扫描器探测 /.env、/.git/config、webshell 路径都会得到 200，但拿到的只是首页。判断依据（自动学习，无需配置）：
//   - 响应大小与该站点首页的正常响应一致；
//   - 或已有 3 个以上不同的探测路径返回了完全相同的大小（真实存在的不同敏感文件几乎不可能大小完全一致）。
func (sf *surface) catchAll(host, path string, bytes int64) bool {
	if bytes <= 0 {
		return false
	}
	path = resourceKey(path)
	if path != "/" {
		if ep := sf.Endpoints[host+" /"]; ep != nil && ep.baselineMatches(bytes) {
			return true
		}
	}
	if sf.soft == nil {
		sf.soft = map[string]map[int64]map[string]struct{}{}
	}
	sizes := sf.soft[host]
	if sizes == nil {
		if len(sf.soft) >= maxSoftHosts {
			return false
		}
		sizes = map[int64]map[string]struct{}{}
		sf.soft[host] = sizes
	}
	paths := sizes[bytes]
	if paths == nil {
		if len(sizes) >= maxSoftSizes {
			return false
		}
		paths = map[string]struct{}{}
		sizes[bytes] = paths
	}
	if len(paths) < softSamePath {
		paths[path] = struct{}{}
	}
	return len(paths) >= softSamePath
}

// resourceKey 把指向同一资源的路径变体归一：百分号编码、重复斜杠、/./ 与 ../、末尾斜杠、;参数（Tomcat / Spring）。
// 攻击者绕过 WAF 时常用 //.env、/./.env、/.env;.css、/%2e%65nv 等变体反复读取同一个真实文件，
// 这些响应的大小当然相同，不能算作「不同探测路径返回相同大小」而误判为兜底页面、把真实泄露改判为未取到内容。
func resourceKey(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		p = strings.ToLower(u)
	}
	if strings.IndexByte(p, ';') >= 0 {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			segs[i], _, _ = strings.Cut(s, ";")
		}
		p = strings.Join(segs, "/")
	}
	return path.Clean("/" + p)
}

func newSurface() *surface {
	return &surface{
		Endpoints: map[string]*Endpoint{}, Services: map[string]*Service{}, Findings: map[string]*Finding{},
		Tech: map[string]int{}, Ports: map[int]int64{},
	}
}

const (
	maxEndpoints = 20000
	maxServices  = 20000
	maxSetSize   = 2000
)

type sensitiveRule struct {
	re          *regexp.Regexp
	title       string
	sev         model.Severity
	remediation string
}

var sensitiveRules = []sensitiveRule{
	{regexp.MustCompile(`/\.(git|svn|hg|bzr)(/|$)|/\.ds_store$`), "源代码仓库泄露", model.SevCritical,
		"删除 Web 目录中的版本库目录；nginx 中添加 location ~ /\\.(git|svn|hg) { deny all; }"},
	{regexp.MustCompile(`/\.env(\.\w+)?$|/\.aws/credentials$|/id_[rd]sa$|/\.htpasswd$|/\.git-credentials$|/credentials(\.json|\.xml)?$|/\.kube/config$`), "密钥/凭证文件可公开访问", model.SevCritical,
		"立即删除该文件并轮换其中涉及的全部密钥、口令与令牌"},
	{regexp.MustCompile(`/[^/]*(backup|bak|db|database|dump|site|www|wwwroot|web|htdocs|admin|sql|config|old)[^/]*\.(zip|rar|tar|tar\.gz|tgz|7z|sql|sql\.gz|bak|dump|mdb|sqlite)$|\.(sql|sql\.gz|bak)$`), "备份/数据库文件可下载", model.SevCritical,
		"删除 Web 目录下的备份文件，备份应存放在不可通过 HTTP 访问的位置"},
	{regexp.MustCompile(`/web-inf/|/meta-inf/|/web\.config$|/wp-config\.php\.\w+$|/application(-\w+)?\.(properties|ya?ml)$|/config\.(php|inc|json|ya?ml|xml)\.(bak|old|swp)$|/\.user\.ini$`), "配置文件泄露", model.SevHigh,
		"禁止访问配置文件，检查是否泄露数据库连接串等敏感信息"},
	{regexp.MustCompile(`/(phpinfo|php_info|info|test)\.php$|/server-(status|info)$|/nginx_status$|/actuator/(env|heapdump|threaddump|configprops|mappings|beans|trace|httptrace|logfile|jolokia|gateway/routes)|/heapdump$|/_profiler|/debug/pprof|/elmah\.axd$|/trace\.axd$|/druid/(index|sql|websession)\.html$`), "调试/监控接口暴露", model.SevHigh,
		"关闭生产环境调试接口，或在反向代理上限制为内网/白名单访问"},
	// 通用后台入口：路径本身即可判定为管理面（需要 2xx/3xx 才会进入本分类，见 observeWeb）。
	// 与下面按产品名匹配的规则互补——「/admin/login」「/manage」「/dashboard」这类通用路径
	// 同样属于对外暴露的运维入口，此前只能靠特征规则按低危背景扫描处理，会漏掉真正的暴露面。
	{regexp.MustCompile(`^/(admin|manage|management|backend|dashboard|sysadmin|admincp|adminpanel)(/|$)`), "管理后台/运维入口对外暴露", model.SevMedium,
		"管理后台应仅允许 VPN 或白名单访问，并启用强口令与多因素认证"},
	{regexp.MustCompile(`/(phpmyadmin|pma|adminer[^/]*\.php|manager/html|host-manager|jmx-console|web-console|jenkins|kibana|grafana|nacos|xxl-job-admin|solr|swagger-ui(\.html)?|v2/api-docs|v3/api-docs|wp-login\.php|wp-admin|administrator|console)(/|$)`), "管理后台/运维入口对外暴露", model.SevMedium,
		"管理后台应仅允许 VPN 或白名单访问，并启用强口令与多因素认证"},
	{regexp.MustCompile(`/(logs?|storage/logs)/[^/]*\.(log|txt)$|/[^/]*(error|access|debug|laravel)[^/]*\.log$|/nohup\.out$`), "日志文件可公开访问", model.SevMedium,
		"禁止通过 Web 访问日志目录，日志中可能包含会话、口令或内部路径"},
}

func classifySensitive(path string) *sensitiveRule {
	p := strings.ToLower(path)
	for i := range sensitiveRules {
		if sensitiveRules[i].re.MatchString(p) {
			return &sensitiveRules[i]
		}
	}
	return nil
}

var techRules = []struct {
	re   *regexp.Regexp
	tech string
}{
	{regexp.MustCompile(`\.php\d?$`), "PHP"},
	{regexp.MustCompile(`\.(jsp|jspx|do)$`), "Java"},
	{regexp.MustCompile(`\.action$`), "Struts2"},
	{regexp.MustCompile(`\.(aspx|ashx|asmx|axd)$`), "ASP.NET"},
	{regexp.MustCompile(`\.asp$`), "ASP"},
	{regexp.MustCompile(`\.(cgi|pl)$`), "CGI"},
	{regexp.MustCompile(`^/wp-(content|includes|admin|login)`), "WordPress"},
	{regexp.MustCompile(`^/actuator`), "Spring Boot"},
	{regexp.MustCompile(`^/druid/`), "Druid"},
	{regexp.MustCompile(`^/nacos`), "Nacos"},
	{regexp.MustCompile(`^/graphql`), "GraphQL"},
	{regexp.MustCompile(`^/(swagger|v2/api-docs|v3/api-docs)`), "Swagger"},
	{regexp.MustCompile(`^/phpmyadmin`), "phpMyAdmin"},
	{regexp.MustCompile(`^/jenkins`), "Jenkins"},
	{regexp.MustCompile(`^/seeyon`), "致远OA"},
	{regexp.MustCompile(`^/(weaver|wui|ecology)`), "泛微OA"},
	{regexp.MustCompile(`^/(ispirit|general)/`), "通达OA"},
	{regexp.MustCompile(`^/api/`), "REST API"},
}

// normPath 去掉查询串并将 ID 类路径段（纯数字、UUID、16 位以上十六进制）泛化，避免资产数量爆炸。
// 单次扫描实现，位于单线程聚合路径上，避免正则开销。
func normPath(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	if uri == "" {
		return "/"
	}
	segs := strings.Split(strings.ToLower(uri), "/")
	for i, s := range segs {
		switch {
		case s == "":
		case isDigits(s):
			segs[i] = "{id}"
		case isUUID(s):
			segs[i] = "{uuid}"
		case len(s) >= 16 && isHex(s):
			segs[i] = "{hash}"
		}
	}
	p := strings.Join(segs, "/")
	if len(p) > 200 {
		p = p[:200]
	}
	return p
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	return isHex(s[:8]) && isHex(s[9:13]) && isHex(s[14:18]) && isHex(s[19:23]) && isHex(s[24:])
}

// 端口 → 服务名与对公网开放时的风险等级。
var services = map[int]struct {
	name string
	risk model.Severity
}{
	21: {"FTP", model.SevHigh}, 22: {"SSH", model.SevMedium}, 23: {"Telnet", model.SevCritical}, 25: {"SMTP", model.SevLow},
	53: {"DNS", model.SevLow}, 80: {"HTTP", model.SevInfo}, 110: {"POP3", model.SevLow}, 111: {"RPCbind", model.SevHigh},
	135: {"MSRPC", model.SevHigh}, 137: {"NetBIOS", model.SevHigh}, 139: {"NetBIOS", model.SevHigh}, 143: {"IMAP", model.SevLow},
	161: {"SNMP", model.SevHigh}, 389: {"LDAP", model.SevHigh}, 443: {"HTTPS", model.SevInfo}, 445: {"SMB", model.SevCritical},
	465: {"SMTPS", model.SevLow}, 587: {"SMTP", model.SevLow}, 873: {"Rsync", model.SevHigh}, 993: {"IMAPS", model.SevLow},
	995: {"POP3S", model.SevLow}, 1080: {"SOCKS", model.SevHigh}, 1099: {"Java RMI", model.SevHigh}, 1433: {"MSSQL", model.SevHigh},
	1521: {"Oracle", model.SevHigh}, 2049: {"NFS", model.SevHigh}, 2375: {"Docker API", model.SevCritical}, 2376: {"Docker TLS", model.SevHigh},
	2379: {"etcd", model.SevCritical}, 3306: {"MySQL", model.SevHigh}, 3389: {"RDP", model.SevHigh}, 4848: {"GlassFish", model.SevHigh},
	5432: {"PostgreSQL", model.SevHigh}, 5601: {"Kibana", model.SevHigh}, 5672: {"RabbitMQ", model.SevMedium}, 5900: {"VNC", model.SevHigh},
	5984: {"CouchDB", model.SevHigh}, 5985: {"WinRM", model.SevHigh}, 6379: {"Redis", model.SevCritical}, 6443: {"K8s API", model.SevHigh},
	7001: {"WebLogic", model.SevHigh}, 8080: {"HTTP-Alt", model.SevLow}, 8443: {"HTTPS-Alt", model.SevLow}, 8848: {"Nacos", model.SevHigh},
	8888: {"HTTP-Alt", model.SevLow}, 9000: {"PHP-FPM/Portainer", model.SevMedium}, 9090: {"Prometheus", model.SevMedium},
	9200: {"Elasticsearch", model.SevCritical}, 9300: {"Elasticsearch", model.SevHigh}, 10250: {"Kubelet", model.SevCritical},
	11211: {"Memcached", model.SevCritical}, 15672: {"RabbitMQ Web", model.SevMedium}, 27017: {"MongoDB", model.SevCritical},
	50070: {"Hadoop", model.SevHigh},
}

func serviceInfo(port int) (string, model.Severity) {
	if s, ok := services[port]; ok {
		return s.name, s.risk
	}
	return "port-" + strconv.Itoa(port), model.SevInfo
}

// observeWeb 更新 Web 资产与风险发现（调用方持锁）。
func (sf *surface) observeWeb(ev *model.Event, hits []model.Hit, attacked bool) {
	host := ev.Host
	if host == "" {
		host = "-"
	}
	path := normPath(ev.URI)
	exists := ev.Status >= 200 && ev.Status < 400
	key := host + " " + path
	ep := sf.Endpoints[key]
	// 敏感资源分类只在可能产生影响时计算（新登记入口、或 2xx/3xx 响应可能暴露敏感资源），
	// 并缓存在入口上；扫描器大量的 404 请求不再逐条执行分类正则。
	var sens *sensitiveRule
	if exists {
		if ep != nil && ep.classified {
			sens = ep.sens
		} else {
			sens = classifySensitive(path)
			if ep != nil {
				ep.sens, ep.classified = sens, true
			}
		}
	}
	// 敏感路径返回的 200 其实是兜底页面（单页应用、统一错误页）：资源并不存在，不登记、不报暴露
	fake := sens != nil && ev.Status == 200 && ep == nil && sf.catchAll(host, path, ev.Bytes)
	if fake {
		sens = nil
	}
	// 攻击请求只在命中敏感资源时才登记为新入口：对所有路径都返回 200 的站点（SPA 兜底路由），
	// 扫描器的随机路径不会污染资产清单；已有入口上的攻击仍会被统计。
	if ep == nil && exists && !fake && (!attacked || sens != nil) && len(sf.Endpoints) < maxEndpoints {
		ep = &Endpoint{Host: host, Path: path, Methods: map[string]int{}, Status: map[int]int{}, FirstSeen: ev.Time,
			atk: map[string]struct{}{}, sens: sens, classified: true}
		for _, t := range techRules {
			if t.re.MatchString(path) {
				ep.Tech = append(ep.Tech, t.tech)
				sf.Tech[t.tech]++
			}
		}
		if sens != nil {
			ep.Sensitive, ep.Severity = sens.title, sens.sev
		}
		sf.Endpoints[key] = ep
	}
	if ep != nil {
		ep.Hits++
		if ev.Method != "" && len(ep.Methods) < 20 {
			ep.Methods[ev.Method]++
		}
		ep.Status[ev.Status]++
		if ev.Time.After(ep.LastSeen) {
			ep.LastSeen = ev.Time
		}
		if !attacked && ev.Status >= 200 && ev.Status < 300 && ev.Bytes > 0 {
			ep.observeNormal(ev.Bytes)
		}
		if attacked {
			ep.Attacks++
			if len(ep.atk) < maxSetSize {
				ep.atk[ev.SrcIP] = struct{}{}
				ep.Attackers = max(ep.Attackers, len(ep.atk))
			}
		}
	}

	asset := host + path
	if host == "-" {
		asset = path
	}
	// 敏感资源被成功访问（兜底页面返回的 200 已在上面排除；已登记的入口再次核对首页基线）
	if ev.Status == 200 && ev.Bytes > 0 && sens != nil && !sf.catchAll(host, path, ev.Bytes) {
		sf.finding("sens:"+key, sens.title, "敏感资源暴露", sens.sev, asset,
			ev.SrcIP+" 访问返回 200，响应 "+strconv.FormatInt(ev.Bytes, 10)+" 字节", sens.remediation, ev.SrcIP, ev.Time)
	}
	for _, h := range hits {
		if h.TagOnly || h.Phase == model.PhaseRecon {
			continue
		}
		switch h.Result {
		case model.ResultBlocked:
			sf.ExploitBlocked++
		case model.ResultSuccess, model.ResultPassed, model.ResultError:
			sf.ExploitPassed++
		}
		if h.Result == model.ResultSuccess && h.Severity >= model.SevHigh {
			rem := successRemediation[h.Category]
			if rem == "" {
				rem = "核查该接口是否存在对应漏洞，排查服务器是否已被入侵，并在 WAF 中加入拦截规则"
			}
			sf.finding("succ:"+h.Category+":"+key, "疑似攻击成功: "+h.Category, "攻击成功研判", h.Severity, asset,
				ev.SrcIP+" "+ev.Method+" 返回 "+strconv.Itoa(ev.Status)+"，"+h.Name+": "+h.Evidence, rem, ev.SrcIP, ev.Time)
		}
	}
}

// observeFw 更新网络服务暴露面（调用方持锁）。published 表示目标端口确实做过对外映射：
// 未映射的端口即使被默认策略放行，也不存在可访问的服务，不能据此判定「对公网开放」。
func (sf *surface) observeFw(ev *model.Event, published bool) {
	if ev.DstPort <= 0 {
		return
	}
	// 内网主机访问公网（出站流量）不是本方对外提供的服务，不计入暴露面
	if ev.DstIP != "" && geo.IsPrivate(ev.SrcIP) && !geo.IsPrivate(ev.DstIP) {
		return
	}
	sf.Ports[ev.DstPort]++
	key := ev.DstIP + ":" + strconv.Itoa(ev.DstPort) + "/" + ev.Proto
	sv := sf.Services[key]
	if sv == nil {
		// 只有被放行、且端口确实对外发布（DNAT 映射）的连接才能证明服务真实存在；
		// 被拒绝的探测、以及未映射端口上的放行日志只计入“被探测端口”统计。
		if ev.Action != model.ActionAllow || !published || len(sf.Services) >= maxServices {
			return
		}
		name, risk := serviceInfo(ev.DstPort)
		sv = &Service{DstIP: ev.DstIP, Port: ev.DstPort, Proto: ev.Proto, Name: name, Risk: risk, src: map[string]struct{}{}}
		sf.Services[key] = sv
	}
	switch ev.Action {
	case model.ActionAllow:
		sv.Allowed++
		if published && !geo.IsPrivate(ev.SrcIP) {
			sv.Exposed = true
			if ev.Reach == model.ReachDevice {
				// 防火墙自身的服务：管理服务对公网放行是可直接处置的风险；VPN / 路由协议本就面向外部，不作为风险
				if name, sev := exposure.DeviceRisk(ev.DstPort, ev.Proto); sev > model.SevInfo {
					by := ""
					if ev.Policy != "" {
						by = "按策略「" + ev.Policy + "」"
					}
					sf.finding("dev:"+key, "防火墙管理服务对公网放行: "+name, "服务暴露", sev, key,
						"防火墙"+by+"放行了来自公网 "+ev.SrcIP+" 到设备自身（local 安全域）的连接",
						"在防火墙上把管理服务限制为内网或运维堡垒机地址访问（华为：local 安全域策略与接口 service-manage），"+
							"关闭 Telnet / HTTP / SNMP v1、v2c 等明文管理协议，改用 SSH / HTTPS / SNMPv3", ev.SrcIP, ev.Time)
				}
			} else if sv.Risk >= model.SevMedium {
				sf.finding("svc:"+key, "高危服务对公网开放: "+sv.Name, "服务暴露", sv.Risk, key,
					"防火墙放行了来自公网 "+ev.SrcIP+" 的连接", "通过安全组/防火墙将该端口限制为内网或白名单访问，必要时修改默认端口并启用认证", ev.SrcIP, ev.Time)
			}
		}
	case model.ActionDeny:
		sv.Denied++
	}
	if len(sv.src) < maxSetSize {
		sv.src[ev.SrcIP] = struct{}{}
		sv.Sources = max(sv.Sources, len(sv.src))
	}
	if ev.Time.After(sv.LastSeen) {
		sv.LastSeen = ev.Time
	}
}

func (sf *surface) finding(id, title, cat string, sev model.Severity, asset, evidence, remediation, ip string, t time.Time) {
	f := sf.Findings[id]
	if f == nil {
		if len(sf.Findings) >= 5000 {
			return
		}
		f = &Finding{ID: id, Title: title, Category: cat, Severity: sev, Asset: asset, Evidence: evidence, Remediation: remediation, FirstSeen: t}
		sf.Findings[id] = f
	}
	f.Count++
	if sev > f.Severity { // 同一发现后续出现更严重的情况（如外连被放行）时升级
		f.Severity, f.Evidence = sev, evidence
	}
	if ip != "" && len(f.IPs) < 8 && !slices.Contains(f.IPs, ip) {
		f.IPs = append(f.IPs, ip)
	}
	if t.After(f.LastSeen) {
		f.LastSeen = t
	}
}

var successRemediation = map[string]string{
	"暴力破解":       "立即核查该账号的登录记录，重置口令并启用登录失败锁定与多因素认证",
	"WebShell后门": "立即排查并删除可疑脚本文件，检查上传功能与服务器是否已被控制",
	"SQL注入":      "使用参数化查询修复注入点，核查数据库是否有异常访问与数据外泄",
	"命令/代码执行":    "立即修复漏洞并排查服务器是否存在异常进程、计划任务与外连",
}
