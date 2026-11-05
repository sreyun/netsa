package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"netsa/internal/geo"
	"netsa/internal/model"
	"netsa/internal/risk"
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
	rules     []*Rule
	minBytes  int64
	ac        *acMatcher // 全部预过滤字面量的多模式匹配自动机
	words     int        // 每个文本段位图的字数
	bitsPool  sync.Pool
	uaRules   []int    // 针对 UA 的规则在 rules 中的下标（结果按 UA 缓存，见 uacache.go）
	uaSlot    []int    // rules 下标 → uaRules 中的位置，非 UA 规则为 -1
	uac       *uaCache // UA 规则的匹配结果缓存
	decRules  []int    // 对编码载荷的解码结果生效的规则（decode.go）
	decLits   bitset   // 这些规则用到的全部预过滤字面量：解码结果中一个都没有时不必逐条匹配
	decAlways bool
}

func NewEngine(rulesFile string, successMinBytes int64) (*Engine, error) {
	return NewEngineWith(rulesFile, nil, successMinBytes)
}

// NewEngineWith 在内置规则和规则文件之外，加上页面维护的规则。这些规则不能覆盖已有规则：
// 覆盖内置规则请用规则文件，它是可以审查的配置。
func NewEngineWith(rulesFile string, extra []Rule, successMinBytes int64) (*Engine, error) {
	rules, err := LoadRules(rulesFile)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(rules)+len(extra))
	for _, r := range rules {
		seen[r.ID] = true
	}
	for i := range extra {
		r := extra[i]
		if seen[r.ID] {
			return nil, fmt.Errorf("规则 ID %s 已存在", r.ID)
		}
		seen[r.ID] = true
		r.Methods = append([]string(nil), r.Methods...)
		if err := r.compile(); err != nil {
			return nil, err
		}
		rules = append(rules, &r)
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
	e.uaSlot = make([]int, len(rules))
	for i, r := range rules {
		e.uaSlot[i] = -1
		if segOf(r.Target) == segUA {
			e.uaSlot[i] = len(e.uaRules)
			e.uaRules = append(e.uaRules, i)
		}
		if seg := segOf(r.Target); seg != segUA && seg != segRef && !r.TagOnly && decodedCats[r.Category] {
			e.decRules = append(e.decRules, i) // 对编码载荷的解码结果生效的规则
		}
	}
	if e.ac != nil {
		e.decLits = make(bitset, e.words)
		for _, i := range e.decRules {
			if rules[i].needIDs == nil {
				e.decAlways = true // 没有预过滤字面量的规则（规则文件、页面维护的规则）：解码结果都要逐条匹配
			}
			for _, clause := range rules[i].needIDs {
				for _, id := range clause {
					e.decLits.set(id)
				}
			}
		}
	}
	e.uac = newUACache()
	return e, nil
}

// TestRule 用样本试运行一条规则：样本按检测时相同的方式归一化。返回是否命中和证据。
func TestRule(r Rule, sample string) (bool, string, error) {
	r.Methods = append([]string(nil), r.Methods...)
	if err := r.compile(); err != nil {
		return false, "", err
	}
	text := Normalize(sample)
	switch segOf(r.Target) {
	case segPath:
		text, _, _ = strings.Cut(text, "?")
	case segUA:
		text = strings.ToLower(sample)
	}
	loc := r.re.FindStringIndex(text)
	if loc == nil {
		return false, "", nil
	}
	return true, excerpt(text, loc[0], loc[1]), nil
}

// Rules 返回已加载的规则列表。
func (e *Engine) Rules() []*Rule { return e.rules }

// Inspect 对单个事件执行特征检测。
//
// 所有分支的命中都会经过 risk.Finalize 统一裁决等级：特征规则、设备告警、防火墙端口探测
// 各自声明的等级只作为「建议值」，最终是否够严重由分类底线与响应结果共同决定。
func (e *Engine) Inspect(ev *model.Event) []model.Hit {
	if ev.Outbound {
		return nil
	}
	var hits []model.Hit
	switch ev.Kind {
	case model.KindFirewall:
		hits = inspectFirewall(ev)
	case model.KindDNS:
		hits = inspectDNS(ev)
	case model.KindAuth:
		hits = inspectAuth(ev)
	default:
		hits = e.inspectWeb(ev)
	}
	for i := range hits {
		before := hits[i].Severity
		risk.Finalize(&hits[i])
		// 只在等级被下调时写入说明：上调（分类底线）是常态，写进证据会让页面变得嘈杂
		if hits[i].Severity < before && hits[i].Result != model.ResultPassed && hits[i].Result != model.ResultSuccess {
			if d := risk.Describe(&hits[i], before); d != "" {
				hits[i].Evidence = Printable(hits[i].Evidence+"（"+d+"）", 400)
			}
		}
	}
	return hits
}

// 能由响应判断是否成功的分类由 risk.SuccessEscalates 统一定义：
// SSRF、XXE、表达式注入（Log4j / OGNL / SpEL / SSTI）、反序列化多为盲打或带外利用，
// 页面正常返回 200 是常态，无法据此判断成功，一律标注为「未拦截」，避免误判为失陷；
// 敏感文件探测只能证明资源可访问，同样不作为成功证据。

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
	if ev.Threat != "" {
		// WAF（ModSecurity、naxsi、Lua WAF）与 nginx 限流的判定：同一请求在访问日志中另有记录并按规则检测，这里只采信设备的判定
		return []model.Hit{deviceThreatHit(ev)}
	}
	if nonHTTPRequest(ev) {
		// 二进制协议探测：只判断协议异常，不按 URI 规则匹配（其中的 \x00 曾被判为高危的“空字节截断”）
		return specialWebChecks(ev, Normalize(ev.URI), WebResult(ev, e.minBytes))
	}
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

	var uaLocs []int32 // UA 规则的命中位置（按 UA 缓存）
	if ua != "" && len(e.uaRules) > 0 {
		uaLocs = e.uaLocs(ua, &segs)
	}
	var hits []model.Hit
	var review []reviewRef // 需要语法分析复核的命中（URI 上可能出现在普通文字里的分类）
	for i, r := range e.rules {
		seg := segOf(r.Target)
		text := [segCount]string{uri, path, ua, ref, all}[seg]
		if text == "" || !r.methodOK(ev.Method) {
			continue
		}
		// 先判断与本次请求相关的廉价条件，再做预过滤与正则
		if r.OnlyFailed && result != model.ResultFailed && result != model.ResultBlocked {
			continue
		}
		var start, end int
		if s := e.uaSlot[i]; s >= 0 {
			if uaLocs[2*s] < 0 {
				continue
			}
			start, end = int(uaLocs[2*s]), int(uaLocs[2*s+1])
		} else {
			if r.needIDs != nil && e.ac != nil && !clausesPass(r.needIDs, segs[seg]) {
				continue
			}
			loc := r.re.FindStringIndex(text)
			if loc == nil {
				continue
			}
			start, end = loc[0], loc[1]
		}
		if r.ID == "trav-dotdot" && !strings.Contains(uri[len(path):], "..") && harmlessDotDot(ev.URI) {
			continue
		}
		if r.ID == "rfi" && sameSiteURL(text[end:], ev.Host) {
			continue
		}
		h := model.Hit{
			RuleID: r.ID, Name: r.Name, Category: r.Category, Severity: r.sev, Phase: r.Phase,
			Evidence: excerpt(text, start, end), Result: result, TagOnly: r.TagOnly,
		}
		if result == model.ResultSuccess && !risk.ResponseProvable(r.Category) {
			h.Result = model.ResultPassed
		}
		if seg == segURI && !r.TagOnly && proseCategory[r.Category] {
			review = append(review, reviewRef{hit: len(hits), start: start, end: end})
			if inertProse(uri, start, end) {
				h.Weak = true
				if h.Result == model.ResultSuccess {
					h.Result = model.ResultPassed
				}
			}
		}
		hits = append(hits, h)
	}
	hits = reviewSyntax(ev, uri, result, hits, review)
	// 编码载荷：Base64 / Hex 编码的片段、路径中用 + 代替空格的注入，解码后再匹配
	if enc := e.decodedHits(ev, result, hits); len(enc) > 0 {
		hits = append(hits, enc...)
	}
	if s := matchVuln(ev.Method, path, ev.URI); s != nil { // 国产 OA、中间件的已知漏洞接口
		hits = append(hits, vulnHit(s, ev, path, result, hits))
	}
	return append(hits, specialWebChecks(ev, uri, result)...)
}

// harmlessDotDot 判断路径中的 ../ 是否只是普通的相对路径：字面写在路径里（没有编码）、解析后没有越出
// 站点根目录。如 /assets/../assets/app.js，来自页面里的相对引用，不是目录穿越。查询串里的 ../ 由调用方排除。
// 解析后指向敏感文件的情况由 lfi-sensitive 等规则单独判断。
func harmlessDotDot(uri string) bool {
	path, _, _ := strings.Cut(uri, "?")
	if strings.ContainsAny(path, `%\;`) {
		return false
	}
	depth := 0
	for _, seg := range strings.Split(path, "/") {
		switch seg {
		case "", ".":
		case "..":
			if depth--; depth < 0 {
				return false
			}
		default:
			if strings.HasSuffix(seg, "..") {
				// /static../：nginx 的 location 不以 / 结尾而 alias 以 / 结尾时，这样的路径会跳出 alias 目录（off-by-slash）
				return false
			}
			depth++
		}
	}
	return true
}

// sameSiteURL 判断参数中 "scheme://" 之后的地址是否指向本站（与请求的站点名相同或同一主域名）：
// pdf.js 的 viewer.html?file=https://本站/group1/M00/…pdf、登录后的回跳地址引用的是自己的资源，不是包含远程文件。
// 只比较主机名；http://本站@evil.com/、本站.evil.com 这类写法的主机名不同，照常告警。
func sameSiteURL(rest, host string) bool {
	if host == "" {
		return false
	}
	h := rest
	if i := strings.IndexAny(h, "/?#&\\:; "); i >= 0 {
		h = h[:i]
	}
	if h == "" || !strings.Contains(h, ".") {
		return false
	}
	host = strings.ToLower(host)
	if h == host {
		return true
	}
	a, _ := splitDomain(h)
	b, _ := splitDomain(host)
	return a == b && strings.Contains(a, ".")
}

// archiveExts 是源码包、备份常用的文件后缀。
var archiveExts = []string{".tar.gz", ".tar.xz", ".tar.bz2", ".zip", ".rar", ".tar", ".tgz", ".7z", ".jar", ".war", ".xz", ".lz",
	".zst", ".bz2", ".gz", ".z", ".sql", ".bak"}

// siteArchive 判断请求是否在下载以站点名命名的源码包或备份（/app.zip、/example.com.tar.gz、/www.example.com.rar）：
// 目录扫描工具会按目标域名生成这类文件名，固定的正则写不出来。返回请求的路径，不是时返回空。
func siteArchive(host, uri string) string {
	path, _, _ := strings.Cut(uri, "?")
	if host == "" || len(path) < 4 || strings.IndexByte(path[1:], '/') >= 0 || isIPHost(host) {
		return ""
	}
	name := strings.ToLower(path[1:])
	for _, ext := range archiveExts {
		base, ok := strings.CutSuffix(name, ext)
		if !ok || base == "" {
			continue
		}
		h := strings.ToLower(host)
		reg, _ := splitDomain(h)
		label, _, _ := strings.Cut(h, ".")
		regLabel, _, _ := strings.Cut(reg, ".")
		switch base {
		case h, strings.TrimPrefix(h, "www."), reg, label, regLabel:
			return path
		}
		return ""
	}
	return ""
}

// randomScript 判断请求的最后一段是否是随机串命名的服务端脚本（16~40 位字母数字混合，大小写或数字都较多），
// 返回文件名。正常应用的脚本名是有意义的单词；构建工具生成的哈希文件名是 .js / .css，不是服务端脚本。
func randomScript(uri string) string {
	path, _, _ := strings.Cut(uri, "?")
	name := path[strings.LastIndexByte(path, '/')+1:]
	if i := strings.IndexByte(name, ';'); i >= 0 {
		name = name[:i]
	}
	dot := strings.LastIndexByte(name, '.')
	if dot < 16 || dot > 40 {
		return ""
	}
	switch strings.ToLower(name[dot+1:]) {
	case "php", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "ashx", "cer":
	default:
		return ""
	}
	var upper, lower, digit int
	for _, c := range name[:dot] {
		switch {
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= '0' && c <= '9':
			digit++
		default:
			return "" // 有下划线、连字符的多是有意义的名字（user_profile_edit.php）
		}
	}
	// 随机串：大写、小写、数字三类都有，且至少两类各占 4 个以上
	if upper == 0 || lower == 0 || digit == 0 || (min(upper, lower) < 4 && min(upper, digit) < 4 && min(lower, digit) < 4) {
		return ""
	}
	return name
}

// needlessEscapes 统计路径中把字母、数字编码为 %XX 的次数（查询串不计：部分客户端会整体编码参数）。
func needlessEscapes(uri string) int {
	path, _, _ := strings.Cut(uri, "?")
	n := 0
	for i := 0; i+2 < len(path); i++ {
		if path[i] != '%' {
			continue
		}
		v, ok1 := unhexByte(path[i+1])
		w, ok2 := unhexByte(path[i+2])
		if !ok1 || !ok2 {
			continue
		}
		c := v<<4 | w
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			n++
		}
		i += 2
	}
	return n
}

func unhexByte(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// isIPHost 判断站点名是否是 IP 地址（没有域名可用来生成文件名）。
func isIPHost(h string) bool {
	h = strings.Trim(h, "[]")
	return strings.Count(h, ":") > 1 || strings.Trim(h, "0123456789.") == ""
}

// nonHTTPRequest 判断请求行是否根本不是 HTTP：TLS 握手、Oracle TNS、RDP 等二进制协议发往 HTTP 端口时，
// nginx 记录的“请求行”是一串二进制，里面的 \x00 与符号不是 Web 攻击载荷。
func nonHTTPRequest(ev *model.Event) bool {
	return ev.Method == "" && ev.URI != "" && ev.URI[0] != '/'
}

// maxLuaArgs 是 OpenResty ngx.req.get_uri_args 默认最多读取的参数个数：之后的参数 Lua WAF 看不到（CVE-2018-9230）。
const maxLuaArgs = 100

// proseCategory 是特征可能出现在普通文字中的分类（文章标题、搜索词），其余分类的特征本身就不是自然语言。
var proseCategory = map[string]bool{CatXSS: true, CatCmdExec: true, CatSQLi: true}

// inertToken 是只被提到、不会执行的写法：不带属性的标签、没有参数的函数名。phpinfo() 没有参数也能执行，不在其中。
var inertToken = regexp.MustCompile(`</?\s*(script|iframe|frame|svg|object|embed|form|meta|base|applet|math|details|marquee)\s*>|\b(eval|assert|system|exec|shell_exec|passthru|popen|alert|prompt|confirm|` + phpFuncsIO + `|` + phpFuncsCB + `)\s*\(\s*\)`)

// inertProse 判断命中位置所在的参数值是否只是普通文字：去掉只被提到的写法后，剩下的至少有两个词，
// 且没有任何代码或注入需要的符号。如“how to use <script> tag”；而 <script>alert(1)</script>、
// system('id') 都留有符号，不受影响。
func inertProse(uri string, start, end int) bool {
	q := strings.IndexByte(uri, '?')
	if q < 0 || start <= q {
		return false
	}
	from := q + 1 + strings.LastIndexByte(uri[q+1:start], '&') + 1
	to := len(uri)
	if i := strings.IndexByte(uri[end:], '&'); i >= 0 {
		to = end + i
	}
	eq := strings.IndexByte(uri[from:to], '=')
	if eq < 0 || from+eq >= start {
		return false
	}
	value := uri[from+eq+1 : to]
	// 只被提到的写法里没有这些符号，含有时去掉之后仍然含有，不必跑正则（攻击载荷大多如此）
	if strings.ContainsAny(value, "'\"`;{}[]$|&=\\%*#@") || !strings.Contains(value, ">") && !emptyParens(value) {
		return false
	}
	rest := inertToken.ReplaceAllString(value, " ")
	if rest == value || strings.ContainsAny(rest, "<>'\"`;(){}[]$|&=\\/%*#@") {
		return false
	}
	return len(strings.FieldsFunc(rest, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })) >= 2
}

// emptyParens 判断文本中是否有空括号 ()（中间可以有空白）：只被提到的函数名都带空括号。
func emptyParens(s string) bool {
	for i := strings.IndexByte(s, '('); i >= 0; {
		j := i + 1
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if j < len(s) && s[j] == ')' {
			return true
		}
		k := strings.IndexByte(s[j:], '(')
		if k < 0 {
			break
		}
		i = j + k
	}
	return false
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
		if r == model.ResultSuccess && !risk.ResponseProvable(cat) {
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
		case strings.Contains(raw, "(DESCRIPTION=") || strings.Contains(raw, "(CONNECT_DATA="):
			name = "Oracle TNS协议探测"
		}
		add("proto-nonhttp", name, CatProtocol, model.SevLow, model.PhaseRecon, Printable(raw, 80))
	case ev.Method == "CONNECT":
		add("proto-connect", "代理隧道探测(CONNECT)", CatProtocol, model.SevMedium, model.PhaseRecon, ev.Method+" "+Printable(raw, 120))
	case strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://"):
		add("proto-proxy", "开放代理探测", CatProtocol, model.SevMedium, model.PhaseRecon, Printable(raw, 120))
	case ev.Method == "PUT" && (hasScriptExt(uri) || strings.HasSuffix(uri, ".jsp/") || strings.Contains(uri, ".jsp::$data")):
		add("cve-put-upload", "PUT上传WebShell(CVE-2017-12615等)", CatCVE, model.SevCritical, model.PhaseExploit, ev.Method+" "+Printable(raw, 120))
		// 201 / 204 表示服务器确实创建了这个脚本文件，响应码本身就是证据
		hits[len(hits)-1].Proven = ev.Status == 201 || ev.Status == 204
	case ev.Method == "TRACE" || ev.Method == "TRACK":
		add("proto-trace", "HTTP TRACE方法探测", CatProtocol, model.SevLow, model.PhaseRecon, ev.Method+" "+Printable(raw, 80))
	case ev.Method == "PROPFIND" || ev.Method == "MKCOL" || ev.Method == "MOVE" || ev.Method == "COPY" || ev.Method == "SEARCH":
		add("proto-webdav", "WebDAV方法探测", CatProtocol, model.SevLow, model.PhaseRecon, ev.Method+" "+Printable(raw, 80))
	}
	if p := siteArchive(ev.Host, raw); p != "" {
		add("sens-sitearchive", "站点源码包探测", CatSensitive, model.SevMedium, model.PhaseRecon, Printable(p, 120))
	}
	if name := randomScript(raw); name != "" {
		// 上传漏洞利用后访问刚上传的脚本：工具生成的文件名是随机串（S1WpC8G9WjvkbIPWhWWM.jsp）
		add("webshell-random", "随机文件名脚本访问（疑似上传的WebShell）", CatWebShell, model.SevMedium, model.PhaseExploit, Printable(raw, 120))
	}
	if n := needlessEscapes(raw); n >= 2 {
		// 正常客户端不会把字母、数字编码成 %XX；%77eb%75i 这类写法是在躲避基于路径的检测
		add("proto-escape", "非必要的百分号编码（绕过检测）", CatProtocol, model.SevMedium, model.PhaseExploit,
			fmt.Sprintf("路径中 %d 处把字母或数字编码为 %%XX：%s", n, Printable(raw, 100)))
	}
	if len(raw) > 4096 {
		add("proto-longurl", "超长URL(溢出/Fuzz)", CatProtocol, model.SevLow, model.PhaseRecon, Printable(raw, 120))
	}
	if q := strings.IndexByte(raw, '?'); q >= 0 && len(raw)-q > 2*maxLuaArgs && strings.Count(raw[q:], "&") >= maxLuaArgs {
		// 用超过 100 个参数把载荷挤到 Lua WAF（基于 ngx.req.get_uri_args 的 OpenResty WAF）读取范围之外
		add("proto-manyargs", "超多参数绕过WAF(CVE-2018-9230)", CatProtocol, model.SevMedium, model.PhaseExploit,
			strconv.Itoa(strings.Count(raw[q:], "&")+1)+" 个参数："+Printable(raw[max(q, len(raw)-120):], 120))
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

// Result 用引擎配置的最小响应字节数研判攻击结果（与特征检测使用同一口径）。
func (e *Engine) Result(ev *model.Event) string { return WebResult(ev, e.minBytes) }

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
	if result == model.ResultAllowed && InternalSource(ev) {
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

// IsEgress 判断防火墙事件是否为内网主机访问公网的出站连接（部分设备日志不标注方向，按地址与安全域判断）。
func IsEgress(ev *model.Event) bool {
	return ev.Kind == model.KindFirewall && ev.DstIP != "" && InternalSource(ev) && !isPrivateIP(ev.DstIP) && zoneSide(ev.DstZone) <= 0
}

// isPrivateIP 统一使用 geo 包的网段集合（内置 RFC1918 / 保留段 + 配置的内网段 + 本机自动探测的网段），
// 避免各模块各自维护一套判定导致 172.168.100.0/24 这类内网误用段被当成公网。
func isPrivateIP(ip string) bool { return geo.IsPrivate(ip) }

// InternalSource 判断事件来源是否在内部：私有或配置的内网地址，或防火墙标明报文来自内部安全域。
//
// 企业把 172.168.0.0/16 这类公网段用在内网、又没有配置 geo.intranet 时，只看地址会把内部主机当成外部攻击源，
// 应用服务器连数据库也会被判为暴力破解；防火墙日志里的安全域（trust、dmz 等）直接说明了报文从哪一侧进来。
func InternalSource(ev *model.Event) bool {
	return isPrivateIP(ev.SrcIP) || ev.Kind == model.KindFirewall && zoneSide(ev.SrcZone) > 0
}

// InternalZone 判断安全域名称是否表示内部一侧（trust、dmz、inside 等）。
func InternalZone(zone string) bool { return zoneSide(zone) > 0 }

// zoneSide 按安全域名称判断属于内部（1）、外部（-1）还是无法判断（0）。
// 覆盖华为 / H3C / 山石（trust、untrust、dmz、local）、思科 / ASA（inside、outside）与常见的自定义命名。
func zoneSide(zone string) int {
	z := strings.ToLower(strings.TrimSpace(zone))
	if z == "" {
		return 0
	}
	for _, p := range []string{"untrust", "outside", "wan", "external", "internet", "public", "isp", "外网", "互联网"} {
		if strings.HasPrefix(z, p) {
			return -1
		}
	}
	for _, p := range []string{"trust", "inside", "internal", "intranet", "lan", "dmz", "local", "server", "office", "manage", "内网", "办公", "服务器"} {
		if strings.HasPrefix(z, p) {
			return 1
		}
	}
	return 0
}

// 安全设备威胁名称关键字 → 本系统攻击分类与攻击阶段（按顺序匹配，越具体越靠前）。
// 关键字按“词”匹配避免误判（如 windows 不应匹配 dos）：以 * 结尾表示词前缀，含空格或符号的为短语子串。
var threatMap = []struct {
	keys  []string
	cat   string
	phase string
}{
	{[]string{"log4j", "log4shell", "jndi", "ognl", "spel", "struts*", "ssti", "template injection", "表达式注入", "模板注入"}, CatExpr, model.PhaseExploit},
	{[]string{"sqli", "sql injection", "sql-injection", "sql_injection", "union select", "sql注入"}, CatSQLi, model.PhaseExploit},
	{[]string{"xss", "cross-site", "cross site scripting", "跨站"}, CatXSS, model.PhaseExploit},
	{[]string{"traversal", "lfi", "rfi", "file inclusion", "file disclosure", "目录遍历", "目录穿越", "路径遍历", "文件包含", "任意文件读取"}, CatTraversal, model.PhaseExploit},
	{[]string{"rce", "command injection", "cmd injection", "os command", "remote code execution", "code execution", "code.execution", "shellshock", "命令注入", "命令执行", "代码执行", "远程执行"}, CatCmdExec, model.PhaseExploit},
	{[]string{"webshell", "backdoor", "trojan*", "malware", "botnet", "c2", "cnc", "c&c", "command and control", "coinminer", "miner", "mining", "ransomware", "virus", "worm", "mirai", "gafgyt", "后门", "木马", "僵尸网络", "挖矿", "病毒", "蠕虫", "勒索", "远控"}, "恶意软件/远控", model.PhasePersistence},
	{[]string{"deserializ*", "fastjson", "jackson", "ysoserial", "反序列化"}, CatDeser, model.PhaseExploit},
	{[]string{"brute*", "bruteforce", "password guess", "dictionary attack", "credential stuffing", "暴力破解", "口令猜测", "弱口令"}, CatBruteForce, model.PhaseCredential},
	// 防火墙攻击防范（华为 ANTIATTACK、H3C ATK）的单包攻击：地址扫描、IP 欺骗、TCP 标志位与 IP 选项异常、畸形报文拒绝服务
	{[]string{"ip sweep", "ipsweep", "ping sweep", "地址扫描", "主机扫描", "ip扫描"}, CatHostSweep, model.PhaseRecon},
	{[]string{"spoof*", "ip欺骗", "地址欺骗"}, CatSpoof, model.PhaseRecon},
	{[]string{"null flag", "all flags", "syn-fin", "fin only", "invalid flags", "traceroute", "tracert", "ip option", "icmp redirect", "icmp unreachable", "large icmp", "畸形报文", "异常报文"}, CatProtocol, model.PhaseRecon},
	{[]string{"land", "smurf", "teardrop", "ping of death", "pingofdeath", "winnuke", "fraggle", "ip fragment", "死亡之ping"}, CatFlood, model.PhaseImpact},
	{[]string{"scan*", "probe", "sweep", "recon*", "nmap", "masscan", "zmap", "端口扫描", "扫描", "探测"}, CatPortScan, model.PhaseRecon},
	{[]string{"rate limit", "cc attack", "cc_attack", "deny_cc", "cc攻击"}, CatCC, model.PhaseImpact},
	{[]string{"dos", "ddos", "flood*", "amplification", "洪水", "泛洪", "洪泛", "拒绝服务"}, CatFlood, model.PhaseImpact},
	{[]string{"cve-", "exploit*", "overflow", "vulnerab*", "漏洞利用", "漏洞攻击", "溢出"}, CatCVE, model.PhaseExploit},
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
		case strings.ContainsAny(k, " -_.&") || !isASCII(k): // 短语与中文关键字（中文不按词切分）按子串匹配
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

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
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
	proven := result == model.ResultPassed
	if ev.Kind == model.KindWeb {
		if cat == CatPortScan {
			cat, phase = CatScanner, model.PhaseRecon // WAF 识别出的扫描器请求
		}
		// WAF 只告警未拦截（DetectionOnly、学习模式）时按响应码判断结果；WAF 看不到攻击是否生效，不作为第二份证据
		if ev.Action != model.ActionDeny && ev.Status > 0 {
			if result = WebResult(ev, 0); result == model.ResultSuccess {
				result = model.ResultPassed
			}
		}
		proven = false
	}
	evidence := Printable(name, 160)
	if ev.ThreatCategory != "" {
		evidence += "（" + Printable(ev.ThreatCategory, 60) + "）"
	}
	// 设备看到了完整的流量内容，放行时它给出的等级就是响应码之外的独立判断
	return model.Hit{RuleID: "dev-" + ev.Format, Name: "设备告警: " + Printable(name, 80), Category: cat,
		Severity: threatSeverity(ev.ThreatSeverity), Phase: phase, Evidence: evidence + " → " + ev.Target(), Result: result, Proven: proven}
}
