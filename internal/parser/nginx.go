package parser

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"netsa/internal/model"
)

// Parser 将一行日志解析为统一事件。实现必须是并发安全的。
type Parser interface {
	Name() string
	Parse(line string) (*model.Event, bool)
}

// ---------------- combined / main / vhost ----------------

const qstr = `((?:[^"\\]|\\.)*)`

var (
	reNginxCombined = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "` + qstr + `" (\d{3}) (\d+|-)(?: "` + qstr + `" "` + qstr + `")?(?: "` + qstr + `")?(.*)$`)
	reNginxVhost    = regexp.MustCompile(`^([A-Za-z0-9.\-_]+)(?::\d+)? (\S+) \S+ (\S+) \[([^\]]+)\] "` + qstr + `" (\d{3}) (\d+|-)(?: "` + qstr + `" "` + qstr + `")?(?: "` + qstr + `")?(.*)$`)
)

// Nginx 解析 nginx/Apache 的 combined、main（带 XFF）以及 vhost_combined 格式。
type Nginx struct{}

func (Nginx) Name() string { return "nginx" }

func (Nginx) Parse(line string) (*model.Event, bool) {
	if len(line) < 20 {
		return nil, false
	}
	var ip, user, tm, req, status, bytes, ref, ua, xff, host, tail string
	if f, ok := fastCombined(line); ok && isIP(f.ip) {
		ip, user, tm, req, status, bytes, ref, ua, xff, tail = f.ip, f.user, f.tm, f.req, f.status, f.bytes, f.ref, f.ua, f.xff, f.tail
	} else if !strings.Contains(line, `] "`) {
		// 两个正则都要求时间字段后紧跟请求（`] "`）：防火墙、syslog 等其他格式的日志不必进入正则匹配
		return nil, false
	} else if m := reNginxCombined.FindStringSubmatch(line); m != nil && isIP(m[1]) {
		ip, user, tm, req, status, bytes, ref, ua, xff, tail = m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10]
	} else if m := reNginxVhost.FindStringSubmatch(line); m != nil && isIP(m[2]) && !isIP(m[1]) {
		host, ip, user, tm, req, status, bytes, ref, ua, xff, tail = m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11]
	} else {
		return nil, false
	}
	ev := &model.Event{
		Time:    parseNginxTime(tm),
		Kind:    model.KindWeb,
		Format:  "nginx_combined",
		SrcIP:   ip,
		Host:    host,
		Referer: dash(unescapeNginx(ref)),
		UA:      dash(unescapeNginx(ua)),
		XFF:     dash(xff),
		User:    dash(user),
	}
	if ev.XFF != "" {
		ev.Format = "nginx_main"
	}
	ev.Status, _ = strconv.Atoi(status)
	ev.Bytes, _ = strconv.ParseInt(bytes, 10, 64)
	setRequest(ev, unescapeNginx(req))
	parseTail(ev, tail)
	return ev, true
}

// parseTail 读取 combined 格式之后常见的附加字段：请求耗时（$request_time，形如 0.005）与站点名（$host）。
// 也支持 rt=0.005、host=example.com 这样的键值写法。
//
// 通过 syslog 转发时，nginx 的 syslog 标签（如 mg-prd-nginx）在 IP 之前，会被当作 vhost_combined 的站点名；
// 这时行尾真正的域名更可信：开头的“站点名”不像域名（没有点）而行尾有域名，就以行尾为准。
func parseTail(ev *model.Event, tail string) {
	tail = strings.TrimSpace(tail)
	if tail == "" {
		return
	}
	reqTime, host := -1.0, ""
	var extra map[string]string // key=value 形式的增强字段（rl=、us=、ssl= 等）
	for i, tok := range strings.Fields(tail) {
		if i >= 12 {
			break
		}
		tok = strings.Trim(tok, `"`)
		if k, v, ok := strings.Cut(tok, "="); ok {
			if extra == nil {
				extra = map[string]string{}
			}
			extra[strings.ToLower(k)] = strings.Trim(v, `"`)
			switch strings.ToLower(k) {
			case "rt", "request_time", "req_time":
				if f, err := strconv.ParseFloat(v, 64); err == nil && reqTime < 0 {
					reqTime = f
				}
			case "host", "http_host", "server_name", "vhost":
				if host == "" && looksLikeHost(v) {
					host = v
				}
			}
			continue
		}
		if reqTime < 0 && strings.Contains(tok, ".") {
			if f, err := strconv.ParseFloat(tok, 64); err == nil && f >= 0 {
				reqTime = f // 第一个小数是 $request_time；其后的 $upstream_response_time 不覆盖
				continue
			}
		}
		if host == "" && looksLikeHost(tok) {
			host = tok
		}
	}
	if reqTime >= 0 {
		ev.ReqTime = reqTime
	}
	if extra != nil {
		fillEnhanced(ev, extra)
	}
	if host != "" && (ev.Host == "" || !strings.Contains(ev.Host, ".")) {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ev.Host = strings.ToLower(host)
	}
}

// looksLikeHost 判断字段像不像域名（至少含一个点和字母，只含域名字符，可带端口）。IP 不算：行尾的 IP 多是上游地址。
func looksLikeHost(s string) bool {
	if len(s) < 4 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	letter := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letter = true
		case c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':' || c == '_':
		default:
			return false
		}
	}
	return letter && s[0] != '.' && s[0] != '-'
}

// setRequest 拆分请求行 "GET /path HTTP/1.1"；非标准请求行原样保存到 URI。
func setRequest(ev *model.Event, req string) {
	if req == "-" || req == "" {
		return
	}
	method, rest, ok := strings.Cut(req, " ")
	if ok && isMethod(method) {
		ev.Method = method
		// URI 中可能含有未编码的空格，协议版本取最后一段
		if i := strings.LastIndex(rest, " HTTP/"); i >= 0 {
			rest, ev.HTTPProto = rest[:i], rest[i+1:]
		}
		ev.URI = rest
		return
	}
	ev.URI = req
}

// unescapeNginx 还原 nginx 日志中的 \xHH 转义。
func unescapeNginx(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// ---------------- JSON 格式 ----------------

// NginxJSON 解析 log_format escape=json 输出的 JSON 访问日志（同样适用于大多数 JSON 网关日志）。
type NginxJSON struct{}

func (NginxJSON) Name() string { return "nginx_json" }

func (NginxJSON) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return nil, false
	}
	m, ok := unmarshalLog(line)
	if !ok {
		return nil, false
	}
	kv := flattenLower(m)
	// 兼容 nginx escape=json、Caddy（request.remote_ip / headers.User-Agent）、Traefik（ClientHost / RequestPath）
	// 与 Elastic ECS（source.ip / url.original / user_agent.original，按完整路径优先取，避免同名的最后一级键混淆）等
	// 也兼容 APISIX / Kong 日志插件（request.uri、response.status、client_ip、毫秒时间戳）、
	// ModSecurity JSON 审计日志（v3 的 transaction.response.http_code，v2 的 request.request_line），
	// 以及 OpenResty Lua WAF（unixhot/waf：attack_method、req_url，只记录拦截，没有状态码）
	status := pick(kv, "status", "http.response.status_code", "response", "response_code", "status_code", "downstreamstatus", "http_code")
	req := pick(kv, "request", "request_line")
	if _, err := strconv.ParseFloat(req, 64); err == nil {
		req = "" // 嵌套字段的末级同名键（如 Kong 的 latencies.request 耗时），不是请求行
	}
	uri := pick(kv, "request_uri", "url.original", "uri", "url.path", "path", "url", "requestpath", "req_url")
	method := pick(kv, "request_method", "http.request.method", "method", "requestmethod")
	wafAttack := kv["attack_method"]
	if wafAttack != "" && status == "" {
		status = "403"
	}
	if status == "" || (req == "" && uri == "" && method == "") {
		return nil, false
	}
	ip := pick(kv, "remote_addr", "source.ip", "client.ip", "source.address", "client.address", "client_ip", "clientip", "remote_ip", "clienthost",
		"clientaddr", "ip", "client", "real_ip", "realip", "remote_address")
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h // Traefik ClientAddr 形如 1.2.3.4:5678
	}
	if !isIP(ip) {
		return nil, false
	}
	ev := &model.Event{
		Time: ParseTime(pick(kv, "time_iso8601", "time_local", "@timestamp", "timestamp", "time", "msec", "ts", "startutc", "startlocal",
			"start_time", "started_at", "time_stamp", "local_time", "unix_time")),
		Kind:    model.KindWeb,
		Format:  "nginx_json",
		SrcIP:   ip,
		Host:    pick(kv, "host", "http_host", "url.domain", "server_name", "domain", "requesthost"),
		Referer: dash(pick(kv, "http_referer", "http.request.referrer", "referer", "referrer", "request_referer")),
		UA:      dash(pick(kv, "http_user_agent", "user_agent.original", "user_agent", "user-agent", "agent", "ua", "request_user-agent")),
		XFF:     dash(pick(kv, "http_x_forwarded_for", "x_forwarded_for", "x-forwarded-for", "xff", "request_x-forwarded-for")),
		XRealIP: dash(pick(kv, "http_x_real_ip", "x_real_ip")),
		User:    dash(pick(kv, "remote_user")),
		DstIP:   pick(kv, "server_addr", "destination.ip"),
	}
	ev.Status, _ = strconv.Atoi(status)
	ev.Bytes, _ = strconv.ParseInt(pick(kv, "body_bytes_sent", "http.response.body.bytes", "bytes_sent", "size", "bytes", "downstreamcontentsize"), 10, 64)
	ev.ReqTime = reqTimeOf(kv, pick(kv, "request_time", "duration"))
	ev.DstPort, _ = strconv.Atoi(pick(kv, "server_port"))
	fillEnhanced(ev, kv)
	if req != "" {
		setRequest(ev, req)
	}
	if method != "" {
		ev.Method = method
	}
	if uri != "" && (ev.URI == "" || req == "") {
		ev.URI = uri
		if args := pick(kv, "args", "query_string", "url.query"); args != "" && !strings.Contains(uri, "?") {
			ev.URI += "?" + args
		}
	}
	if p := pick(kv, "server_protocol", "protocol"); p != "" && ev.HTTPProto == "" {
		ev.HTTPProto = p
	} else if v := kv["http.version"]; v != "" && ev.HTTPProto == "" {
		ev.HTTPProto = "HTTP/" + v // ECS 只记录版本号
	}
	fillClientHeaders(ev, kv)
	if rp := pick(kv, "realip_remote_addr"); isIP(rp) && rp != ip {
		ev.PeerIP = rp
	}
	if _, ok := m["transaction"]; ok {
		modsecAudit(ev, m)
	} else if wafAttack != "" {
		ev.Format = "lua_waf"
		ev.Threat = "Lua WAF 拦截（" + wafAttack + "）"
		ev.ThreatCategory = strings.ReplaceAll(strings.ToLower(wafAttack), "_", " ") + " " + kv["rule_tag"]
		ev.ThreatSeverity = "medium"
		ev.Action = model.ActionDeny
	}
	return ev, true
}

// reqTimeOf 读取请求耗时（秒）。没有 $request_time 时换算 Tengine 的 $request_time_msec / $request_time_usec，
// 以及 APISIX（latency）与 Kong（latencies.request）日志插件的毫秒耗时。
func reqTimeOf(kv map[string]string, sec string) float64 {
	if f, err := strconv.ParseFloat(sec, 64); err == nil {
		return f
	}
	for _, u := range []struct {
		key string
		div float64
	}{{"request_time_msec", 1e3}, {"request_time_usec", 1e6}, {"latency", 1e3}, {"latencies.request", 1e3}} {
		if f, err := strconv.ParseFloat(kv[u.key], 64); err == nil {
			return f / u.div
		}
	}
	return 0
}

func pick(kv map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := kv[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

// ---------------- 自定义 log_format ----------------

// LogFormat 根据 nginx 的 log_format 定义编译出的解析器。
type LogFormat struct {
	re    *regexp.Regexp
	names []string
}

var (
	reVar       = regexp.MustCompile(`\$\{?([a-zA-Z_][a-zA-Z0-9_]*)\}?`)
	reFmtHeader = regexp.MustCompile(`^\s*log_format\s+\S+\s+(?:escape=\S+\s+)?`)
	reQuoted    = regexp.MustCompile(`'((?:[^'\\]|\\.)*)'`)
)

// normalizeLogFormat 兼容直接从 nginx.conf 复制的多行写法：
// log_format main '$remote_addr - ...'
//
//	'"$http_user_agent" ...';
func normalizeLogFormat(format string) string {
	format = strings.TrimSpace(reFmtHeader.ReplaceAllString(format, ""))
	format = strings.TrimSpace(strings.TrimSuffix(format, ";"))
	if !strings.HasPrefix(format, "'") {
		return format
	}
	var b strings.Builder
	for _, m := range reQuoted.FindAllStringSubmatch(format, -1) {
		b.WriteString(m[1])
	}
	return b.String()
}

// CompileLogFormat 将 nginx log_format 字符串（例如
// `$remote_addr - $remote_user [$time_local] "$request" $status ...`）编译为正则解析器。
func CompileLogFormat(format string) (*LogFormat, error) {
	format = normalizeLogFormat(format)
	locs := reVar.FindAllStringSubmatchIndex(format, -1)
	if len(locs) == 0 {
		return nil, fmt.Errorf("log_format 中没有变量")
	}
	var b strings.Builder
	b.WriteString("^")
	seen := map[string]int{}
	var names []string
	prev := 0
	for i, loc := range locs {
		b.WriteString(regexp.QuoteMeta(format[prev:loc[0]]))
		name := format[loc[2]:loc[3]]
		var next string
		if i+1 < len(locs) {
			next = format[loc[1]:locs[i+1][0]]
		} else {
			next = format[loc[1]:]
		}
		group := name
		if n := seen[name]; n > 0 {
			group = fmt.Sprintf("%s__%d", name, n)
		}
		seen[name]++
		names = append(names, name)
		b.WriteString("(?P<" + group + ">" + varPattern(name, next, i == len(locs)-1) + ")")
		prev = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(format[prev:]))
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("编译 log_format 失败: %w", err)
	}
	return &LogFormat{re: re, names: names}, nil
}

func varPattern(name, next string, last bool) string {
	if next == "" {
		if last {
			return ".*"
		}
		return `\S*?`
	}
	switch name {
	case "time_local":
		return `[^\]]*?`
	case "request", "http_user_agent", "http_referer":
		if next[0] == '"' {
			return `(?:[^"\\]|\\.)*`
		}
		return ".*?"
	}
	switch next[0] {
	case '"':
		return `(?:[^"\\]|\\.)*`
	case ']':
		return `[^\]]*`
	case '\'':
		return `[^']*`
	case ' ':
		return `\S*`
	case '|', '\t', ',', ';':
		return `[^` + regexp.QuoteMeta(next[:1]) + `]*`
	}
	return ".*?"
}

func (*LogFormat) Name() string { return "nginx_custom" }

func (f *LogFormat) Parse(line string) (*model.Event, bool) {
	m := f.re.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	kv := make(map[string]string, len(f.names))
	for i, name := range f.names {
		if _, ok := kv[name]; !ok {
			v := unescapeNginx(m[i+1])
			if name != "upstream_status" { // “-”表示请求没有转发到后端，需要保留
				v = dash(v)
			}
			kv[name] = v
		}
	}
	ip := pick(kv, "remote_addr", "http_x_real_ip", "realip_remote_addr")
	if !isIP(ip) {
		return nil, false
	}
	ev := &model.Event{
		Time:    ParseTime(pick(kv, "time_local", "time_iso8601", "msec", "unix_time")), // $unix_time 为 Tengine 变量
		Kind:    model.KindWeb,
		Format:  "nginx_custom",
		SrcIP:   ip,
		Host:    pick(kv, "host", "http_host", "server_name"),
		Referer: kv["http_referer"],
		UA:      kv["http_user_agent"],
		XFF:     kv["http_x_forwarded_for"],
		XRealIP: kv["http_x_real_ip"],
		User:    kv["remote_user"],
		DstIP:   kv["server_addr"],
	}
	ev.Status, _ = strconv.Atoi(kv["status"])
	ev.Bytes, _ = strconv.ParseInt(pick(kv, "body_bytes_sent", "bytes_sent"), 10, 64)
	ev.ReqTime = reqTimeOf(kv, kv["request_time"])
	ev.DstPort, _ = strconv.Atoi(kv["server_port"])
	fillEnhanced(ev, kv)
	ev.SrcPort, _ = strconv.Atoi(kv["remote_port"])
	if r := kv["request"]; r != "" {
		setRequest(ev, r)
	} else {
		ev.Method = kv["request_method"]
		ev.URI = pick(kv, "request_uri", "uri")
		if a := pick(kv, "args", "query_string"); a != "" && !strings.Contains(ev.URI, "?") {
			ev.URI += "?" + a
		}
		ev.HTTPProto = kv["server_protocol"]
	}
	fillClientHeaders(ev, kv)
	if rp := kv["realip_remote_addr"]; isIP(rp) && rp != ip {
		ev.PeerIP = rp
	}
	return ev, true
}

// isMethod 判断是否为合法的 HTTP 方法名（大写字母、下划线或连字符，2~16 个字符）。
func isMethod(s string) bool {
	if len(s) < 2 || len(s) > 16 || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !(c >= 'A' && c <= 'Z' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// NormIP 规范化 IP 文本：去掉方括号与 IPv6 区域标识，IPv4 映射地址（::ffff:1.2.3.4）还原为 IPv4，
// 使同一来源在 IPv4/IPv6 双栈监听下不会被识别为两个不同的攻击者。无法解析时返回 false。
func NormIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && s[0] == '[' {
		if i := strings.IndexByte(s, ']'); i > 0 {
			s = s[1:i]
		}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s, false
	}
	return a.Unmap().WithZone("").String(), true
}

// clientHeaderVars 是日志中可能记录的客户端地址头（nginx 变量名 → 规范键名）。
var clientHeaderVars = map[string]string{
	"http_cf_connecting_ip": "cf_connecting_ip", "cf_connecting_ip": "cf_connecting_ip", "cf-connecting-ip": "cf_connecting_ip",
	"http_true_client_ip": "true_client_ip", "true_client_ip": "true_client_ip", "true-client-ip": "true_client_ip",
	"http_ali_cdn_real_ip": "ali_cdn_real_ip", "ali_cdn_real_ip": "ali_cdn_real_ip", "ali-cdn-real-ip": "ali_cdn_real_ip",
	"http_x_client_ip": "x_client_ip", "x_client_ip": "x_client_ip", "x-client-ip": "x_client_ip",
	"http_forwarded": "forwarded", "forwarded": "forwarded",
}

// fillClientHeaders 把日志中记录的客户端地址头放入事件，供真实 IP 还原按优先级选用。
func fillClientHeaders(ev *model.Event, kv map[string]string) {
	for k, norm := range clientHeaderVars {
		if v := dash(kv[k]); v != "" {
			if ev.ClientHeaders == nil {
				ev.ClientHeaders = map[string]string{}
			}
			ev.ClientHeaders[norm] = v
		}
	}
}
