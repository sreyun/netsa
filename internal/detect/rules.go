package detect

import (
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"strings"

	"gopkg.in/yaml.v3"

	"netsa/internal/model"
)

// 攻击分类。
const (
	CatSQLi        = "SQL注入"
	CatXSS         = "XSS跨站脚本"
	CatTraversal   = "目录穿越/文件包含"
	CatCmdExec     = "命令/代码执行"
	CatExpr        = "表达式注入"
	CatSSRF        = "SSRF"
	CatXXE         = "XXE"
	CatDeser       = "反序列化"
	CatWebShell    = "WebShell后门"
	CatCVE         = "已知漏洞利用"
	CatSensitive   = "敏感文件探测"
	CatAdminProbe  = "管理后台探测"
	CatScanner     = "扫描器"
	CatMapping     = "网络空间测绘"
	CatAutomation  = "自动化工具"
	CatProtocol    = "协议异常"
	CatCC          = "CC攻击"
	CatDirScan     = "目录扫描"
	CatBruteForce  = "暴力破解"
	CatPortScan    = "端口扫描"
	CatHostSweep   = "主机探测"
	CatFlood       = "洪水攻击"
	CatIoT         = "IoT僵尸网络"
	CatRiskService = "高危服务探测"
	CatIntel       = "威胁情报"
	CatSpoof       = "IP伪造"
	CatCrawl       = "数据爬取/越权遍历"
	CatBeacon      = "可疑外连"
)

// Rule 是一条特征规则。Pattern 匹配的是归一化（解码+小写）后的文本。
type Rule struct {
	ID         string   `yaml:"id" json:"id"`
	Name       string   `yaml:"name" json:"name"`
	Category   string   `yaml:"category" json:"category"`
	Severity   string   `yaml:"severity" json:"severity"`
	Phase      string   `yaml:"phase" json:"phase"`
	Target     string   `yaml:"target" json:"target"` // uri | path | ua | referer | any
	Pattern    string   `yaml:"pattern" json:"pattern"`
	OnlyFailed bool     `yaml:"only_failed" json:"only_failed,omitempty"` // 仅在请求失败(4xx)时命中，用于识别盲目探测
	TagOnly    bool     `yaml:"tag_only" json:"tag_only,omitempty"`
	Methods    []string `yaml:"methods" json:"methods,omitempty"` // 限定 HTTP 方法，为空表示不限

	sev     model.Severity
	re      *regexp.Regexp
	need    [][]string // 预过滤必要条件（合取范式），为空表示每次都执行正则
	needIDs [][]int32  // need 中字面量对应的自动机编号
	builtin bool
}

func (r *Rule) compile() error {
	if r.ID == "" || r.Pattern == "" {
		return fmt.Errorf("规则缺少 id 或 pattern: %+v", *r)
	}
	// 被检测文本已统一小写：内置规则均以小写书写，不使用 (?i) 以启用字面量前缀加速；
	// 自定义规则可能含大写字母，保留忽略大小写。
	pattern, flags := r.Pattern, syntax.Perl
	if !r.builtin {
		pattern, flags = "(?i)"+r.Pattern, syntax.Perl|syntax.FoldCase
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("规则 %s 正则错误: %w", r.ID, err)
	}
	r.re = re
	r.need = buildPrefilter(r.Pattern, flags)
	r.sev = model.ParseSeverity(r.Severity)
	if r.Name == "" {
		r.Name = r.ID
	}
	if r.Category == "" {
		r.Category = "自定义规则"
	}
	switch r.Target {
	case "":
		r.Target = "uri"
	case "uri", "path", "ua", "referer", "any":
	default:
		return fmt.Errorf("规则 %s 的 target 只能是 uri/path/ua/referer/any", r.ID)
	}
	if r.Phase == "" {
		r.Phase = model.PhaseExploit
	}
	for i, m := range r.Methods {
		r.Methods[i] = strings.ToUpper(m)
	}
	return nil
}

func (r *Rule) methodOK(method string) bool {
	if len(r.Methods) == 0 {
		return true
	}
	for _, m := range r.Methods {
		if m == method {
			return true
		}
	}
	return false
}

func rule(id, name, cat, sev, phase, target, pattern string) Rule {
	return Rule{ID: id, Name: name, Category: cat, Severity: sev, Phase: phase, Target: target, Pattern: pattern}
}

const (
	ex  = model.PhaseExploit
	rec = model.PhaseRecon
	per = model.PhasePersistence
)

var builtinRules = []Rule{
	// ---------------- SQL 注入 ----------------
	rule("sqli-union", "UNION联合查询注入", CatSQLi, "high", ex, "uri", `\bunion\s+(all\s+|distinct\s+)?\(?\s*select\b`),
	rule("sqli-bool", "布尔盲注", CatSQLi, "high", ex, "uri", `['"\)]\s*(and|or|xor|&&|\|\|)\s*['"\(]?\s*\w+\s*['"\)]?\s*(=|<|>|\blike\b|\brlike\b|\bregexp\b)\s*['"\(]?\s*\w+`),
	rule("sqli-bool-num", "数字型布尔注入", CatSQLi, "medium", ex, "uri", `[=\s]\d+\s+(and|or|xor)\s+\d+\s*(=|<|>)\s*\d+`),
	rule("sqli-time", "时间盲注", CatSQLi, "high", ex, "uri", `\b(sleep|pg_sleep)\s*\(\s*\d|\bbenchmark\s*\(\s*\d|waitfor\s+delay\s+['"]|dbms_pipe\.receive_message|dbms_lock\.sleep`),
	rule("sqli-error", "报错注入", CatSQLi, "high", ex, "uri", `\b(extractvalue|updatexml|geometrycollection|multipoint|polygon|linestring|exp)\s*\(.*(select|concat|0x7e|~)|floor\s*\(\s*rand\s*\(`),
	rule("sqli-schema", "数据库元数据探测", CatSQLi, "high", ex, "uri", `\b(information_schema|mysql\.(user|db)|pg_(catalog|shadow|user)|sqlite_master|sys\.(objects|tables|databases)|sysobjects|syscolumns|all_tables|user_tables|msysobjects)\b`),
	rule("sqli-danger", "危险数据库操作(写文件/执行命令)", CatSQLi, "critical", ex, "uri", `\b(xp_cmdshell|sp_oacreate|sp_configure)\b|load_file\s*\(|into\s+(out|dump)file\b|\blo_import\b|copy\s+\S+\s+from\s+program\b`),
	rule("sqli-stacked", "堆叠查询注入", CatSQLi, "high", ex, "uri", `['"\d\)]\s*;\s*(drop|alter|create|truncate|insert|update|delete|exec|execute|declare|shutdown)\b`),
	rule("sqli-func", "SQL函数注入特征", CatSQLi, "medium", ex, "uri", `\b(concat(_ws)?|group_concat|char|chr|substr(ing)?|ascii|ord|hex|unhex|mid|version|database|schema|current_user)\s*\(.*\bselect\b|@@(version|datadir|hostname|basedir)\b|\bselect\b.+\bfrom\b.+\bwhere\b`),
	rule("sqli-comment", "SQL注释截断", CatSQLi, "medium", ex, "uri", `['"\)]\s*(--|#)(\s|$|-|\+)`),

	// ---------------- XSS ----------------
	rule("xss-script", "Script标签注入", CatXSS, "high", ex, "uri", `<\s*/?\s*script\b`),
	rule("xss-event", "事件处理器注入", CatXSS, "high", ex, "uri", `<[^>]*\s+on[a-z]{3,20}\s*=|['"]\s*on(error|load|mouseover|focus|click|toggle|animationstart|pointerover|mouseenter)\s*=`),
	rule("xss-proto", "伪协议注入", CatXSS, "medium", ex, "uri", `(javascript|vbscript|livescript)\s*:|data\s*:\s*text/html`),
	rule("xss-tag", "危险HTML标签注入", CatXSS, "medium", ex, "uri", `<\s*(iframe|frame|svg|object|embed|applet|base|meta|form|isindex|math|details|marquee)\b`),
	rule("xss-dom", "DOM/JS执行特征", CatXSS, "medium", ex, "uri", `document\.(cookie|domain|write|location)|window\.location|\b(alert|prompt|confirm)\s*(\(|`+"`"+`)|string\.fromcharcode|expression\s*\(|\bsrcdoc\s*=`),

	// ---------------- 目录穿越 / 文件包含 ----------------
	rule("trav-dotdot", "目录穿越", CatTraversal, "medium", ex, "uri", `\.\.[/\\]`),
	rule("lfi-sensitive", "读取系统敏感文件", CatTraversal, "high", ex, "uri", `/etc/(passwd|shadow|group|hosts|issue|crontab|sudoers|ssh/)|/proc/(self|\d+)/(environ|cmdline|fd|maps|status)|c:[/\\]+windows|\\windows\\|win\.ini|boot\.ini|system32[/\\]|/var/log/(auth|secure|apache|nginx|httpd)|/root/\.|/home/[^/]+/\.ssh`),
	rule("lfi-wrapper", "伪协议文件包含", CatTraversal, "high", ex, "uri", `\b(php|zip|phar|expect|glob|compress\.zlib|ogg|rar|ssh2)://|\bdata://|\bfile://`),
	rule("rfi", "远程文件包含", CatTraversal, "medium", ex, "uri", `[?&](file|page|path|include|inc|template|tpl|dir|document|folder|root|lang|module)=\s*(https?|ftps?)://`),
	rule("null-byte", "空字节截断", CatTraversal, "medium", ex, "uri", `\x00`),

	// ---------------- 命令 / 代码执行 ----------------
	rule("cmd-inject", "系统命令注入", CatCmdExec, "high", ex, "uri", `(;|\|\|?|&&|\$\(|`+"`"+`)\s*(id|whoami|uname|cat|ls|dir|wget|curl|tftp|nc|ncat|netcat|bash|sh|zsh|ping|nslookup|dig|echo|chmod|chown|rm|python[23]?|perl|php|ruby|powershell|cmd|certutil|bitsadmin|telnet|busybox|ifconfig|ipconfig|net|systeminfo|tasklist|ps|hostname|sleep)(\s|$|[;|&)<>]|`+"`"+`)`),
	rule("cmd-download", "下载执行恶意载荷", CatCmdExec, "critical", ex, "uri", `\b(wget|curl|tftp|lwp-download)\b.{0,40}(https?|ftp)://|\b(wget|curl)\s+-[a-z]*\s|\bchmod\s+\+?[0-7x]{1,4}\s|/tmp/[a-z0-9._-]+\s*;\s*(sh|\./)|\bbusybox\s+(wget|tftp)`),
	rule("cmd-shell", "反弹Shell/命令解释器调用", CatCmdExec, "critical", ex, "uri", `/bin/(ba|z|da|c|tc)?sh\b|\bcmd(\.exe)?\s*/c\b|powershell(\.exe)?\s+-|/dev/(tcp|udp)/|\bnc(\.exe)?\s+-[a-z]*e\b|\bbash\s+-i\b|\bsh\s+-c\b|\bmkfifo\b|\bpython[23]?\s+-c\b`),
	rule("cmd-ifs", "IFS空格绕过", CatCmdExec, "high", ex, "uri", `\$\{ifs\}|\$ifs\$9|\$\{ifs%`),
	rule("code-php", "PHP代码执行", CatCmdExec, "high", ex, "uri", `\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func(_array)?|create_function|file_put_contents|fwrite|fputs|base64_decode|gzinflate|str_rot13|phpinfo)\s*\(`),
	rule("code-java", "Java代码执行", CatCmdExec, "critical", ex, "uri", `java\.lang\.(runtime|processbuilder|system|class)\b|getruntime\s*\(|processbuilder|javax\.script|\bnashorn\b|\bnew\s+java\.`),

	// ---------------- 表达式注入 ----------------
	rule("log4shell", "Log4j JNDI注入(Log4Shell)", CatExpr, "critical", ex, "any", `\$\{\s*(jndi|j\$\{|\$\{(lower|upper|::-|env|sys|date|base64|main|java|k8s|docker|spring|web|bundle|ctx|marker|sd|map)[^}]*\})`),
	rule("ognl", "OGNL表达式注入(Struts2/Confluence)", CatExpr, "critical", ex, "uri", `(%\{|\$\{)\s*\(?\s*#|#_memberaccess|@ognl|ognlcontext|ognlutil|xwork\.methodaccessor|#context\[|denymethodexecution|allowstaticmethodaccess|redirect(action)?:\s*\$\{|action:\s*\$\{|\$\{[^}]*@java\.|\$\{[^}]*(getruntime|new\s+java|freemarker\.template)`),
	rule("spel", "SpEL注入/Spring4Shell", CatExpr, "critical", ex, "uri", `\bt\s*\(\s*java\.|#\{\s*t\s*\(|class\.module\.classloader|class\.classloader|\.getclass\s*\(\s*\)\.forname`),
	rule("ssti", "服务端模板注入(SSTI)", CatExpr, "high", ex, "uri", `\{\{.*(__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|config\.items|self\.__|request\.application|lipsum|cycler|joiner|popen)|\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*\s*\d+|#\{\s*\d+\s*\*\s*\d+\s*\}`),

	// ---------------- SSRF / XXE / 反序列化 ----------------
	rule("ssrf-metadata", "云元数据访问(SSRF)", CatSSRF, "high", ex, "uri", `169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.tencentyun\.com|/latest/meta-data|/computemetadata/`),
	rule("ssrf-proto", "危险协议SSRF", CatSSRF, "high", ex, "uri", `\b(gopher|dict|ldaps?|tftp|jar|netdoc|sftp)://`),
	rule("ssrf-internal", "内网地址SSRF探测", CatSSRF, "medium", ex, "uri", `[?&][^=&]*=\s*(https?://)?(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1?\]|0x7f|2130706433|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?([/?#&]|$)`),
	rule("xxe", "XML外部实体注入", CatXXE, "high", ex, "uri", `<!entity|<!doctype[^>]*\[|\bsystem\s+['"](file|http|ftp|php|expect|jar)|xmlns:xi=|<xi:include`),
	rule("deser-fastjson", "Fastjson反序列化", CatDeser, "critical", ex, "uri", `"?@type"?\s*:\s*"(com\.sun|org\.apache|java\.|com\.alibaba|br\.com|org\.springframework|ch\.qos|com\.mchange|org\.hibernate)`),
	rule("deser-generic", "反序列化载荷", CatDeser, "high", ex, "uri", `\bro0ab|aced0005|\bysoserial\b|com\.sun\.rowset\.jdbcrowsetimpl|org\.apache\.commons\.collections|templatesimpl|\$\$bcel\$\$|o:\d+:"[a-z_\\]+":\d+:\{`),

	// ---------------- WebShell ----------------
	rule("webshell-name", "WebShell文件访问", CatWebShell, "high", per, "path", `/[^/]*(shell|cmd|c99|r57|wso|b374k|alfa|indoxploit|chopper|caidao|xiaoma|dama|silic|behinder|godzilla|antsword|webshell|backdoor|sh3ll|phpspy|jspspy|aspxspy|xise)[^/]*\.(php\d?|phtml|jsp|jspx|asp|aspx|ashx|asmx|cer|asa|cfm)$`),
	rule("webshell-param", "WebShell命令参数", CatWebShell, "high", per, "uri", `\.(php\d?|phtml|jsp|jspx|asp|aspx|ashx|cer|asa)\?(.*&)?(cmd|exec|execute|command|shell|z0|z9|caidao|ant)=`),
	rule("webshell-upload", "上传目录脚本执行", CatWebShell, "high", per, "path", `/(uploads?|uploadfiles?|attachments?|avatars?|tmp|temp)/.*\.(php\d?|phtml|pht|jsp|jspx|asp|aspx|ashx|asa|cer|cgi|pl)(;.*)?$`),
	// 静态资源目录中的脚本：GET 常见于缩略图/验证码等合法脚本，只有 POST 交互才视为 WebShell 特征
	{ID: "webshell-static", Name: "静态目录脚本POST交互", Category: CatWebShell, Severity: "high", Phase: per, Target: "path", Methods: []string{"POST"},
		Pattern: `/(images?|img|files?|static|media|pics?|photos?|css|js)/.*\.(php\d?|phtml|pht|jsp|jspx|asp|aspx|ashx|asa|cer)(;.*)?$`},
	rule("parse-vuln", "Web服务器解析漏洞利用", CatWebShell, "high", ex, "path", `\.(jpg|jpeg|png|gif|txt|ico)/[^/]*\.php$|\.(php|asp|aspx|jsp);[^/]*\.(jpg|png|gif|txt)$`),

	// ---------------- 已知漏洞利用 ----------------
	rule("cve-thinkphp", "ThinkPHP远程代码执行", CatCVE, "critical", ex, "uri", `invokefunction|think\\+(app|request|container|module|view)\b|call_user_func_array&vars|_method=__construct`),
	rule("cve-weblogic", "WebLogic漏洞利用", CatCVE, "critical", ex, "uri", `/(wls-wsat|_async|bea_wls_internal|bea_wls_deployment_internal|uddiexplorer|ws_utc)/|/console/(css|images)/.*\.\./|console\.portal\?.*(handle|_nfpb)=`),
	rule("cve-apache-trav", "Apache路径穿越RCE(CVE-2021-41773/42013)", CatCVE, "critical", ex, "uri", `/(cgi-bin|icons)/.*\.\./`),
	rule("cve-phpunit", "PHPUnit远程代码执行(CVE-2017-9841)", CatCVE, "critical", ex, "uri", `eval-stdin\.php`),
	rule("cve-laravel", "Laravel Ignition RCE(CVE-2021-3129)", CatCVE, "critical", ex, "uri", `_ignition/execute-solution`),
	rule("cve-spring-gw", "Spring Cloud Gateway RCE(CVE-2022-22947)", CatCVE, "critical", ex, "uri", `/actuator/gateway/(routes|refresh)`),
	rule("cve-f5", "F5 BIG-IP漏洞利用", CatCVE, "critical", ex, "uri", `/mgmt/tm/util/bash|/tmui/login\.jsp/\.\.;|/mgmt/shared/authn/login`),
	rule("cve-citrix", "Citrix ADC路径穿越", CatCVE, "critical", ex, "uri", `/vpns?/(\.\./)?(cfg|portal/scripts)/|/vpn/\.\./vpns/`),
	rule("cve-exchange", "Exchange ProxyShell/ProxyLogon", CatCVE, "critical", ex, "uri", `/autodiscover/autodiscover\.json\?@|/autodiscover\.json.*powershell|/ecp/[^?]*x\.js|/owa/auth/x\.js|/mapi/nspi/\?&email=autodiscover|/ecp/default\.flt`),
	rule("cve-gpon", "GPON路由器RCE", CatCVE, "critical", ex, "uri", `/gponform/diag_form|/diag_form\?images/`),
	rule("cve-hikvision", "海康威视命令注入(CVE-2021-36260)", CatCVE, "critical", ex, "uri", `/sdk/weblanguage|/onvif-http/snapshot\?auth=`),
	rule("cve-vmware", "VMware vCenter/Workspace漏洞利用", CatCVE, "critical", ex, "uri", `/ui/vropspluginui/rest/services/(uploadova|getstatus)|/analytics/telemetry/ph/api/hyper/send|/catalog-portal/ui/oauth/verify`),
	rule("cve-confluence", "Confluence漏洞利用", CatCVE, "critical", ex, "uri", `/pages/createpage-entervariables\.action|/doenterpagevariables\.action|/template/aui/text-inline\.vm|/setup/setupadministrator\.action|/server-info\.action\?bootstrapstatusprovider`),
	rule("cve-jboss", "JBoss反序列化/未授权", CatCVE, "critical", ex, "uri", `/invoker/(jmxinvokerservlet|ejbinvokerservlet|readonly)|/jmx-console/htmladaptor|/web-console/invoker|/jbossmq-httpil`),
	rule("cve-iot", "IoT/路由器设备漏洞利用", CatCVE, "high", ex, "uri", `/setup\.cgi\?next_file=|/boaform/admin/formlogin|/hnap1/?$|/shell\?cd|/cgi-bin/luci/;stok=|/goform/(setsyspwd|formsyscmd|set_lansetting|syscmd)|/apply\.cgi|/tmunblock\.cgi|/picsdesc\.xml|/ctrlt/devicecfg|/cgi-bin/(mainfunction|supervisor|jarrewrite|kerbynet|nas_sharing|vitogate)\.cgi|/dnslookup\.cgi|/currentsetting\.htm|/device\.rsp`),
	rule("cve-middleware", "中间件/OA系统漏洞利用", CatCVE, "high", ex, "uri", `^/(jenkins/|manage/)?script(text)?(\?|$)|/securityrealm/user/admin|/descriptorbyname/|/cli\?remoting=false|/solr/admin/(cores|info|collections)|/solr/[^/]+/(config|dataimport)|wt=velocity|/nacos/v1/(auth/users|cs/ops/derby|core/cluster/nodes)|serveridentity|/manager/(html|text)/(upload|deploy)|/actuator/jolokia|/jolokia/(exec|read|list)|/seeyon/(htmlofficeservlet|thirdpartycontroller|webmail\.do)|/weaver/bsh\.servlet\.bshservlet|/mobile/browser/workflowcenteruploadfile|/ispirit/(im/upload|interface)|/general/login_code\.php|/yyoa/|/defaultroot/|/axis2/axis2-admin|/xxl-job-admin/jobinfo|/wp-admin/admin-ajax\.php\?action=(revslider_show_image|duplicator_download)`),
	rule("cve-container", "容器/K8s API未授权访问", CatCVE, "high", ex, "path", `^/(v1\.\d+/)?(containers/(json|create)|images/json|exec/[^/]+/start)$|^/api/v1/(pods|namespaces|secrets)|^/apis/apps/v1`),
	rule("cve-shellshock", "Shellshock(CVE-2014-6271)", CatCVE, "critical", ex, "any", `\(\)\s*\{\s*:?\s*;?\s*\}\s*;`),

	// ---------------- 敏感文件 / 信息泄露探测 ----------------
	rule("sens-vcs", "源码仓库泄露探测(.git/.svn)", CatSensitive, "medium", rec, "path", `/\.(git|svn|hg|bzr|cvs)(/|$)|/\.ds_store$|/cvs/(entries|root)$|/\.gitlab-ci\.yml$`),
	rule("sens-secret", "密钥/凭证文件探测", CatSensitive, "high", rec, "path", `/\.(env(\.\w+)?|aws/credentials|npmrc|pypirc|dockercfg|docker/config\.json|kube/config|ssh/(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys)|bash_history|zsh_history|mysql_history|git-credentials|netrc|htpasswd|vscode/sftp\.json)$|/(id_rsa|id_dsa)(\.pub)?$|/credentials(\.json|\.xml)?$|/secrets?\.(json|ya?ml)$`),
	rule("sens-backup", "备份文件探测", CatSensitive, "medium", rec, "path", `/[^/]*(backup|bak|db|database|dump|site|www|wwwroot|web|htdocs|html|public_html|admin|sql|config|old)[^/]*\.(zip|rar|tar|tar\.gz|tgz|7z|bz2|sql|sql\.gz|bak|old|swp|dump|sqlite|mdb)$|\.(sql|bak|swp)$`),
	rule("sens-config", "配置文件探测", CatSensitive, "medium", rec, "path", `/(web\.config|wp-config\.php(\.\w+)?|configuration\.php\.\w+|config\.(php|inc|json|ya?ml|xml|ini)(\.bak|\.old|~)|settings\.py|application(-\w+)?\.(properties|ya?ml)|database\.yml|appsettings\.json|parameters\.yml|composer\.(json|lock)|\.htaccess|\.user\.ini)$|/web-inf/|/meta-inf/`),
	rule("sens-debug", "调试/信息泄露接口探测", CatSensitive, "medium", rec, "path", `/(phpinfo|php_info|info|test|pi)\.php$|/server-(status|info)$|/nginx_status$|/_profiler|/elmah\.axd$|/trace\.axd$|/__debug__|/debug/(vars|pprof)|/actuator/(env|heapdump|threaddump|configprops|mappings|beans|trace|httptrace|logfile|loggers|sessions|shutdown|restart)$|/heapdump$|/druid/(index|websession|sql)\.html$`),
	rule("sens-log", "日志文件探测", CatSensitive, "medium", rec, "path", `/(logs?|storage/logs)/[^/]*\.(log|txt)$|/(error|access|debug|laravel)[^/]*\.log$|/nohup\.out$`),
	{ID: "admin-probe", Name: "管理后台/敏感入口探测", Category: CatAdminProbe, Severity: "low", Phase: rec, Target: "path", OnlyFailed: true,
		Pattern: `/(wp-login\.php|wp-admin|administrator|phpmyadmin|pma|myadmin|mysqladmin|dbadmin|adminer(-[\d.]+)?\.php|admin\.php|admin/login|manager/html|console/login|webadmin|login\.action|zabbix|cacti|nagios|kibana|jenkins|axis2|jmx-console|web-console|hudson|nacos|xxl-job-admin|actuator|swagger-ui(\.html)?|v2/api-docs|webui|cpanel|webmail|owa|ecp|remote/login|\+cscoe\+|dana-na|global-protect|sslvpn)(/|$)`},

	// ---------------- 工具指纹 ----------------
	rule("ua-scanner", "漏洞扫描器", CatScanner, "medium", rec, "ua", `sqlmap|nikto|nessus|openvas|acunetix|\bwvs\b|netsparker|appscan|w3af|nuclei|\bxray\b|goby|burp|dirbuster|dirsearch|gobuster|\bffuf\b|feroxbuster|wfuzz|wpscan|joomscan|droopescan|whatweb|masscan|zgrab|nmap|hydra|medusa|fscan|afrog|pocsuite|vulmap|jaeles|arachni|skipfish|commix|jorgee|zmeu|morfeus|havij|pangolin|webinspect|qualys|metasploit|naabu|katana|yakit|bbscan|w9scan|sqlninja|nimbostratus|webfuzz|vulnscan|hello,? ?world|l9explore|l9tcpid|tsunami|cansina`),
	rule("ua-mapping", "网络空间测绘引擎", CatMapping, "low", rec, "ua", `censys|shodan|zoomeye|fofa|\bquake\b|360netlab|internet-measurement|netcraft|leakix|onyphe|criminalip|binaryedge|expanse|paloaltonetworks|stretchoid|researchscan|project sonar|shadowserver|securitytrails|natlas|modat|odin\.io|alphastrike|netsystemsresearch|bitsightbot|internetcensus|ipip\.net`),
	{ID: "ua-automation", Name: "脚本/自动化客户端", Category: CatAutomation, Severity: "info", Phase: rec, Target: "ua", TagOnly: true,
		Pattern: `^(python-requests|python-urllib|python-httpx|python/|aiohttp|go-http-client|curl/|wget/|libwww-perl|java/|okhttp|apache-httpclient|scrapy|axios|node-fetch|undici|ruby|php/|guzzlehttp|winhttp|powershell|mozilla/4\.0$|mozilla/5\.0$)`},
}

// RulesFile 是自定义规则文件结构。
type RulesFile struct {
	Disable []string `yaml:"disable"`
	Rules   []Rule   `yaml:"rules"`
}

// LoadRules 返回编译好的内置规则，并合并自定义规则文件（可为空）。
func LoadRules(path string) ([]*Rule, error) {
	var custom RulesFile
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取规则文件失败: %w", err)
		}
		if err := yaml.Unmarshal(b, &custom); err != nil {
			return nil, fmt.Errorf("解析规则文件失败: %w", err)
		}
	}
	disabled := map[string]bool{}
	for _, id := range custom.Disable {
		disabled[id] = true
	}
	var out []*Rule
	index := map[string]int{}
	for li, list := range [][]Rule{builtinRules, custom.Rules} {
		for i := range list {
			r := list[i]
			r.Methods = append([]string(nil), r.Methods...)
			r.builtin = li == 0
			if disabled[r.ID] {
				continue
			}
			if err := r.compile(); err != nil {
				return nil, err
			}
			// 自定义规则与内置规则 ID 相同时覆盖内置规则，便于调整阈值或误报
			if j, ok := index[r.ID]; ok {
				out[j] = &r
				continue
			}
			index[r.ID] = len(out)
			out = append(out, &r)
		}
	}
	return out, nil
}
