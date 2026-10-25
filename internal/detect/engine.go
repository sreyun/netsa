package detect

import (
	"net/netip"
	"strings"
	"sync"

	"netsa/internal/model"
)

// 规则作用的文本段。
const (
	segURI = iota
	segPath
	segUA
	segRef
	segAny
	segCount
)

func segOf(target string) int {
	switch target {
	case "path":
		return segPath
	case "ua":
		return segUA
	case "referer":
		return segRef
	case "any":
		return segAny
	}
	return segURI
}

// Engine 是无状态的特征检测引擎，可被多个 goroutine 并发调用。
type Engine struct {
	rules    []*Rule
	minBytes int64
	ac       *acMatcher // 全部预过滤字面量的多模式匹配自动机
	words    int        // 每个文本段位图的字数
	bitsPool sync.Pool
}

func NewEngine(rulesFile string, successMinBytes int64) (*Engine, error) {
	rules, err := LoadRules(rulesFile)
	if err != nil {
		return nil, err
	}
	e := &Engine{rules: rules, minBytes: successMinBytes}
	// 收集所有规则的预过滤字面量并编号，构建 Aho-Corasick 自动机
	ids := map[string]int32{}
	var lits []string
	for _, r := range rules {
		r.needIDs = nil
		for _, clause := range r.need {
			var ci []int32
			for _, s := range clause {
				id, ok := ids[s]
				if !ok {
					id = int32(len(lits))
					ids[s] = id
					lits = append(lits, s)
				}
				ci = append(ci, id)
			}
			r.needIDs = append(r.needIDs, ci)
		}
	}
	if len(lits) > 0 {
		e.ac = newACMatcher(lits)
		e.words = (len(lits) + 63) / 64
		e.bitsPool.New = func() any { b := make(bitset, segCount*e.words); return &b }
	}
	return e, nil
}

// Rules 返回已加载的规则列表。
func (e *Engine) Rules() []*Rule { return e.rules }

// Inspect 对单个事件执行特征检测。
func (e *Engine) Inspect(ev *model.Event) []model.Hit {
	if ev.Outbound {
		return nil
	}
	switch ev.Kind {
	case model.KindFirewall:
		return inspectFirewall(ev)
	case model.KindDNS:
		return inspectDNS(ev)
	case model.KindAuth:
		return inspectAuth(ev)
	}
	return e.inspectWeb(ev)
}

// 能由响应判断是否成功的分类：命中且返回 2xx 时研判为“疑似成功”并升级风险。
// SSRF、XXE、表达式注入（Log4j / OGNL / SpEL / SSTI）、反序列化多为盲打或带外利用，页面正常返回 200 是常态，
// 无法据此判断成功，研判为“未拦截”，避免把正常响应误判为失陷。
var bumpOnSuccess = map[string]bool{
	CatSQLi: true, CatTraversal: true, CatCmdExec: true, CatWebShell: true, CatCVE: true, CatSensitive: true,
}

// scanSegments 一次扫描 "uri\nua\nreferer"，按出现位置把命中的字面量记入各文本段的位图。
func (e *Engine) scanSegments(all string, uriLen, pathLen, uaLen int, segs *[segCount]bitset) {
	uaStart, refStart := uriLen+1, uriLen+uaLen+2
	m := e.ac
	node := int32(0)
	for i := 0; i < len(all); i++ {
		c := m.alpha[all[i]]
		if c == 0 {
			node = 0
			continue
		}
		node = m.next[int(node)*m.width+int(c)]
		end := i + 1
		for _, id := range m.out[node] {
			start := end - m.lens[id]
			segs[segAny].set(id)
			switch {
			case end <= uriLen:
				segs[segURI].set(id)
				if end <= pathLen {
					segs[segPath].set(id)
				}
			case start >= uaStart && end < refStart:
				segs[segUA].set(id)
			case start >= refStart:
				segs[segRef].set(id)
			}
		}
	}
}

func clausesPass(clauses [][]int32, bits bitset) bool {
	for _, clause := range clauses {
		ok := false
		for _, id := range clause {
			if bits.has(id) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (e *Engine) inspectWeb(ev *model.Event) []model.Hit {
	uri := Normalize(ev.URI)
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	ua := strings.ToLower(ev.UA)
	ref := Normalize(ev.Referer)
	all := uri + "\n" + ua + "\n" + ref
	result := WebResult(ev, e.minBytes)

	var segs [segCount]bitset
	if e.ac != nil {
		bp := e.bitsPool.Get().(*bitset)
		buf := *bp
		buf.clear()
		for i := range segs {
			segs[i] = buf[i*e.words : (i+1)*e.words]
		}
		e.scanSegments(all, len(uri), len(path), len(ua), &segs)
		defer e.bitsPool.Put(bp)
	}

	var hits []model.Hit
	for _, r := range e.rules {
		seg := segOf(r.Target)
		text := [segCount]string{uri, path, ua, ref, all}[seg]
		if text == "" || !r.methodOK(ev.Method) {
			continue
		}
		if r.needIDs != nil && e.ac != nil && !clausesPass(r.needIDs, segs[seg]) {
			continue
		}
		if r.OnlyFailed && result != model.ResultFailed && result != model.ResultBlocked {
			continue
		}
		loc := r.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		h := model.Hit{
			RuleID: r.ID, Name: r.Name, Category: r.Category, Severity: r.sev, Phase: r.Phase,
			Evidence: excerpt(text, loc[0], loc[1]), Result: result, TagOnly: r.TagOnly,
		}
		if result == model.ResultSuccess {
			if bumpOnSuccess[r.Category] {
				h.Severity = h.Severity.Bump(1)
			} else {
				h.Result = model.ResultPassed
			}
		}
		hits = append(hits, h)
	}
	return append(hits, specialWebChecks(ev, uri, result)...)
}

// excerpt 截取命中位置附近的上下文作为证据。
func excerpt(s string, start, end int) string {
	const ctx = 40
	a, b := start-ctx, end+ctx
	prefix, suffix := "…", "…"
	if a <= 0 {
		a, prefix = 0, ""
	}
	if b >= len(s) {
		b, suffix = len(s), ""
	}
	return prefix + Printable(s[a:b], 300) + suffix
}

// specialWebChecks 是无法用单条正则表达的协议层检测。
func specialWebChecks(ev *model.Event, uri, result string) []model.Hit {
	var hits []model.Hit
	add := func(id, name, cat string, sev model.Severity, phase, evidence string) {
		r := result
		if r == model.ResultSuccess && !bumpOnSuccess[cat] {
			r = model.ResultPassed
		}
		hits = append(hits, model.Hit{RuleID: id, Name: name, Category: cat, Severity: sev, Phase: phase, Evidence: evidence, Result: r})
	}
	raw := ev.URI
	switch {
	case ev.Method == "" && raw != "":
		name := "非HTTP协议探测"
		switch {
		case strings.HasPrefix(raw, "\x16\x03"):
			name = "TLS握手发往HTTP端口"
		case strings.Contains(raw, "mstshash") || strings.HasPrefix(raw, "\x03\x00"):
			name = "RDP协议探测"
		case strings.HasPrefix(raw, "SSH-"):
			name = "SSH协议探测"
		}
		add("proto-nonhttp", name, CatProtocol, model.SevLow, model.PhaseRecon, Printable(raw, 80))
	case ev.Method == "CONNECT":
		add("proto-connect", "代理隧道探测(CONNECT)", CatProtocol, model.SevMedium, model.PhaseRecon, ev.Method+" "+Printable(raw, 120))
	case strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://"):
		add("proto-proxy", "开放代理探测", CatProtocol, model.SevMedium, model.PhaseRecon, Printable(raw, 120))
	case ev.Method == "PUT" && (hasScriptExt(uri) || strings.HasSuffix(uri, ".jsp/") || strings.Contains(uri, ".jsp::$data")):
		add("cve-put-upload", "PUT上传WebShell(CVE-2017-12615等)", CatCVE, model.SevCritical, model.PhaseExploit, ev.Method+" "+Printable(raw, 120))
	case ev.Method == "TRACE" || ev.Method == "TRACK":
		add("proto-trace", "HTTP TRACE方法探测", CatProtocol, model.SevLow, model.PhaseRecon, ev.Method+" "+Printable(raw, 80))
	case ev.Method == "PROPFIND" || ev.Method == "MKCOL" || ev.Method == "MOVE" || ev.Method == "COPY" || ev.Method == "SEARCH":
		add("proto-webdav", "WebDAV方法探测", CatProtocol, model.SevLow, model.PhaseRecon, ev.Method+" "+Printable(raw, 80))
	}
	if len(raw) > 4096 {
		add("proto-longurl", "超长URL(溢出/Fuzz)", CatProtocol, model.SevLow, model.PhaseRecon, Printable(raw, 120))
	}
	if ev.UA == "" && ev.Method != "" {
		hits = append(hits, model.Hit{RuleID: "ua-empty", Name: "空User-Agent", Category: CatAutomation, Severity: model.SevInfo, Phase: model.PhaseRecon, TagOnly: true})
	}
	return hits
}

func hasScriptExt(uri string) bool {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	for _, ext := range []string{".jsp", ".jspx", ".php", ".asp", ".aspx", ".war"} {
		if strings.HasSuffix(uri, ext) {
			return true
		}
	}
	return false
}

// WebResult 根据响应码与响应大小研判攻击结果。
func WebResult(ev *model.Event, minBytes int64) string {
	s := ev.Status
	switch {
	case s == 0:
		return model.ResultUnknown
	case s == 403 || s == 406 || s == 418 || s == 429 || s == 444 || s == 451 || s == 495 || s == 496:
		return model.ResultBlocked
	case s == 499:
		// 客户端主动断开，时间盲注等场景常见，无法判定
		return model.ResultUnknown
	case s >= 500:
		return model.ResultError
	case s >= 300:
		return model.ResultFailed
	case s == 201 || s == 204:
		// 201 Created / 204 No Content 本身没有响应体（PUT 上传、POST 创建成功），不能按响应大小判为失败
		return model.ResultSuccess
	case s >= 200:
		if minBytes > 0 && ev.Bytes < minBytes {
			return model.ResultFailed
		}
		return model.ResultSuccess
	}
	return model.ResultUnknown
}

// 端口分类。
var (
	iotPorts = map[int]string{
		23: "Telnet", 2323: "Telnet", 5555: "ADB", 37215: "华为HG532", 52869: "Realtek UPnP", 7547: "TR-069",
		8291: "MikroTik Winbox", 60001: "IoT", 9530: "IoT", 81: "IoT Web", 49152: "UPnP",
	}
	riskPorts = map[int]string{
		6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API",
		2379: "etcd", 10250: "Kubelet", 3306: "MySQL", 1433: "MSSQL", 1521: "Oracle", 5432: "PostgreSQL",
		5984: "CouchDB", 50070: "Hadoop", 8848: "Nacos", 445: "SMB", 135: "MSRPC", 139: "NetBIOS",
		5900: "VNC", 5985: "WinRM", 873: "Rsync", 2049: "NFS", 161: "SNMP", 1099: "Java RMI", 7001: "WebLogic",
	}
)

func inspectFirewall(ev *model.Event) []model.Hit {
	var hits []model.Hit
	if ev.Threat != "" {
		hits = append(hits, deviceThreatHit(ev))
	}
	if ev.DstPort <= 0 {
		return hits
	}
	if len(hits) > 0 {
		// 设备已给出明确的威胁判定时，不再叠加基于端口的推测性告警
		return hits
	}
	result := model.ResultUnknown
	switch ev.Action {
	case model.ActionDeny:
		result = model.ResultBlocked
	case model.ActionAllow:
		result = model.ResultAllowed
	}
	// 内网主机之间被放行的业务访问（如应用服务器连接数据库）属于正常东西向流量，不作为探测告警；
	// 内网发起且被拒绝的访问仍然告警，用于发现横向移动。
	if result == model.ResultAllowed && isPrivateIP(ev.SrcIP) {
		return nil
	}
	sev := model.SevLow
	if result == model.ResultAllowed {
		sev = model.SevMedium
	}
	if name, ok := iotPorts[ev.DstPort]; ok {
		return []model.Hit{{RuleID: "fw-iot", Name: "IoT僵尸网络端口探测(" + name + ")", Category: CatIoT, Severity: sev,
			Phase: model.PhaseRecon, Evidence: ev.Target(), Result: result}}
	}
	if name, ok := riskPorts[ev.DstPort]; ok {
		return []model.Hit{{RuleID: "fw-riskport", Name: "高危服务端口探测(" + name + ")", Category: CatRiskService, Severity: sev,
			Phase: model.PhaseRecon, Evidence: ev.Target(), Result: result}}
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsEgress 判断防火墙事件是否为内网主机访问公网的出站连接（部分设备日志不标注方向，按地址判断）。
func IsEgress(ev *model.Event) bool {
	return ev.Kind == model.KindFirewall && ev.DstIP != "" && isPrivateIP(ev.SrcIP) && !isPrivateIP(ev.DstIP)
}

func isPrivateIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}

// 安全设备威胁名称关键字 → 本系统攻击分类与攻击阶段（按顺序匹配，越具体越靠前）。
// 关键字按“词”匹配避免误判（如 windows 不应匹配 dos）：以 * 结尾表示词前缀，含空格或符号的为短语子串。
var threatMap = []struct {
	keys  []string
	cat   string
	phase string
}{
	{[]string{"log4j", "log4shell", "jndi", "ognl", "spel", "struts*", "ssti", "template injection"}, CatExpr, model.PhaseExploit},
	{[]string{"sqli", "sql injection", "sql-injection", "sql_injection", "union select"}, CatSQLi, model.PhaseExploit},
	{[]string{"xss", "cross-site", "cross site scripting"}, CatXSS, model.PhaseExploit},
	{[]string{"traversal", "lfi", "rfi", "file inclusion", "file disclosure"}, CatTraversal, model.PhaseExploit},
	{[]string{"rce", "command injection", "cmd injection", "os command", "remote code execution", "code execution", "code.execution", "shellshock"}, CatCmdExec, model.PhaseExploit},
	{[]string{"webshell", "backdoor", "trojan*", "malware", "botnet", "c2", "cnc", "c&c", "command and control", "coinminer", "miner", "mining", "ransomware", "virus", "worm", "mirai", "gafgyt"}, "恶意软件/远控", model.PhasePersistence},
	{[]string{"deserializ*", "fastjson", "jackson", "ysoserial"}, CatDeser, model.PhaseExploit},
	{[]string{"brute*", "bruteforce", "password guess", "dictionary attack", "credential stuffing"}, CatBruteForce, model.PhaseCredential},
	{[]string{"scan*", "probe", "sweep", "recon*", "nmap", "masscan", "zmap"}, CatPortScan, model.PhaseRecon},
	{[]string{"dos", "ddos", "flood*", "amplification"}, CatFlood, model.PhaseImpact},
	{[]string{"cve-", "exploit*", "overflow", "vulnerab*"}, CatCVE, model.PhaseExploit},
}

// matchThreat 判断威胁文本是否命中关键字列表。
func matchThreat(text string, tokens map[string]bool, keys []string) bool {
	for _, k := range keys {
		switch {
		case strings.HasSuffix(k, "*"):
			stem := strings.TrimSuffix(k, "*")
			for t := range tokens {
				if strings.HasPrefix(t, stem) {
					return true
				}
			}
		case strings.ContainsAny(k, " -_.&"):
			if strings.Contains(text, k) {
				return true
			}
		default:
			if tokens[k] {
				return true
			}
		}
	}
	return false
}

func threatTokens(text string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.FieldsFunc(text, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') }) {
		out[t] = true
	}
	return out
}

// threatSeverity 将设备给出的等级文本映射为本系统等级，无法识别时默认高危（设备已明确判定为威胁）。
func threatSeverity(s string) model.Severity {
	s = strings.ToLower(strings.TrimSpace(s))
	tokens := threatTokens(s)
	switch {
	case s == "":
		return model.SevHigh
	case tokens["critical"] || tokens["crit"] || tokens["emergency"] || tokens["emerg"] || tokens["alert"] || strings.Contains(s, "严重"):
		return model.SevCritical
	case tokens["high"] || tokens["major"] || tokens["error"] || strings.Contains(s, "高"):
		return model.SevHigh
	case tokens["medium"] || tokens["moderate"] || tokens["warning"] || tokens["warn"] || strings.Contains(s, "中"):
		return model.SevMedium
	case tokens["low"] || tokens["minor"] || tokens["notice"] || strings.Contains(s, "低"):
		return model.SevLow
	case tokens["info"] || tokens["informational"] || strings.Contains(s, "信息"):
		return model.SevInfo
	}
	return model.SevHigh
}

// deviceThreatHit 把 IPS/IDS/下一代防火墙识别出的威胁转换为命中，分类依据威胁名称与设备分类推断。
func deviceThreatHit(ev *model.Event) model.Hit {
	name := strings.TrimSpace(ev.Threat)
	text := strings.ToLower(name + " " + ev.ThreatCategory)
	tokens := threatTokens(text)
	cat, phase := "设备威胁告警", model.PhaseExploit
	for _, m := range threatMap {
		if matchThreat(text, tokens, m.keys) {
			cat, phase = m.cat, m.phase
			break
		}
	}
	result := model.ResultUnknown
	switch ev.Action {
	case model.ActionDeny:
		result = model.ResultBlocked
	case model.ActionAllow:
		result = model.ResultPassed
	}
	evidence := Printable(name, 160)
	if ev.ThreatCategory != "" {
		evidence += "（" + Printable(ev.ThreatCategory, 60) + "）"
	}
	return model.Hit{RuleID: "dev-" + ev.Format, Name: "设备告警: " + Printable(name, 80), Category: cat,
		Severity: threatSeverity(ev.ThreatSeverity), Phase: phase, Evidence: evidence + " → " + ev.Target(), Result: result}
}
