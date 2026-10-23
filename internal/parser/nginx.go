package parser

import (
	"encoding/json"
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
	var ip, tm, req, status, bytes, ref, ua, xff, host string
	if f, ok := fastCombined(line); ok && isIP(f.ip) {
		ip, tm, req, status, bytes, ref, ua, xff = f.ip, f.tm, f.req, f.status, f.bytes, f.ref, f.ua, f.xff
	} else if m := reNginxCombined.FindStringSubmatch(line); m != nil && isIP(m[1]) {
		ip, tm, req, status, bytes, ref, ua, xff = m[1], m[3], m[4], m[5], m[6], m[7], m[8], m[9]
	} else if m := reNginxVhost.FindStringSubmatch(line); m != nil && isIP(m[2]) && !isIP(m[1]) {
		host, ip, tm, req, status, bytes, ref, ua, xff = m[1], m[2], m[4], m[5], m[6], m[7], m[8], m[9], m[10]
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
	}
	if ev.XFF != "" {
		ev.Format = "nginx_main"
	}
	ev.Status, _ = strconv.Atoi(status)
	ev.Bytes, _ = strconv.ParseInt(bytes, 10, 64)
	setRequest(ev, unescapeNginx(req))
	return ev, true
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
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil, false
	}
	kv := flattenLower(m)
	// 兼容 nginx escape=json、Caddy（request.remote_ip / headers.User-Agent）与 Traefik（ClientHost / RequestPath）等
	status := pick(kv, "status", "response", "response_code", "status_code", "downstreamstatus")
	req := pick(kv, "request")
	uri := pick(kv, "request_uri", "uri", "path", "url", "requestpath")
	method := pick(kv, "request_method", "method", "requestmethod")
	if status == "" || (req == "" && uri == "" && method == "") {
		return nil, false
	}
	ip := pick(kv, "remote_addr", "client_ip", "clientip", "remote_ip", "clienthost", "clientaddr", "ip", "client", "real_ip", "realip")
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h // Traefik ClientAddr 形如 1.2.3.4:5678
	}
	if !isIP(ip) {
		return nil, false
	}
	ev := &model.Event{
		Time:    ParseTime(pick(kv, "time_iso8601", "time_local", "@timestamp", "timestamp", "time", "msec", "ts", "startutc", "startlocal")),
		Kind:    model.KindWeb,
		Format:  "nginx_json",
		SrcIP:   ip,
		Host:    pick(kv, "host", "http_host", "server_name", "domain", "requesthost"),
		Referer: dash(pick(kv, "http_referer", "referer", "referrer", "request_referer")),
		UA:      dash(pick(kv, "http_user_agent", "user_agent", "user-agent", "agent", "ua", "request_user-agent")),
		XFF:     dash(pick(kv, "http_x_forwarded_for", "x_forwarded_for", "x-forwarded-for", "xff", "request_x-forwarded-for")),
		XRealIP: dash(pick(kv, "http_x_real_ip", "x_real_ip")),
		DstIP:   pick(kv, "server_addr"),
	}
	ev.Status, _ = strconv.Atoi(status)
	ev.Bytes, _ = strconv.ParseInt(pick(kv, "body_bytes_sent", "bytes_sent", "size", "bytes", "downstreamcontentsize"), 10, 64)
	ev.ReqTime, _ = strconv.ParseFloat(pick(kv, "request_time", "duration"), 64)
	ev.DstPort, _ = strconv.Atoi(pick(kv, "server_port"))
	if req != "" {
		setRequest(ev, req)
	}
	if method != "" {
		ev.Method = method
	}
	if uri != "" && (ev.URI == "" || req == "") {
		ev.URI = uri
		if args := pick(kv, "args", "query_string"); args != "" && !strings.Contains(uri, "?") {
			ev.URI += "?" + args
		}
	}
	if p := pick(kv, "server_protocol", "protocol"); p != "" && ev.HTTPProto == "" {
		ev.HTTPProto = p
	}
	fillClientHeaders(ev, kv)
	if rp := pick(kv, "realip_remote_addr"); isIP(rp) && rp != ip {
		ev.PeerIP = rp
	}
	return ev, true
}

// flattenLower 将 JSON 对象展开为小写键的字符串映射（嵌套对象使用最后一级键）。
func flattenLower(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	var walk func(map[string]any)
	walk = func(m map[string]any) {
		for k, v := range m {
			k = strings.ToLower(k)
			switch x := v.(type) {
			case string:
				out[k] = x
			case float64:
				out[k] = strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				out[k] = strconv.FormatBool(x)
			case map[string]any:
				walk(x)
			case []any:
				// Caddy 的请求头为字符串数组，取第一个值
				if len(x) > 0 {
					if s, ok := x[0].(string); ok {
						out[k] = s
					}
				}
			}
		}
	}
	walk(m)
	return out
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
			kv[name] = dash(unescapeNginx(m[i+1]))
		}
	}
	ip := pick(kv, "remote_addr", "http_x_real_ip", "realip_remote_addr")
	if !isIP(ip) {
		return nil, false
	}
	ev := &model.Event{
		Time:    ParseTime(pick(kv, "time_local", "time_iso8601", "msec")),
		Kind:    model.KindWeb,
		Format:  "nginx_custom",
		SrcIP:   ip,
		Host:    pick(kv, "host", "http_host", "server_name"),
		Referer: kv["http_referer"],
		UA:      kv["http_user_agent"],
		XFF:     kv["http_x_forwarded_for"],
		XRealIP: kv["http_x_real_ip"],
		DstIP:   kv["server_addr"],
	}
	ev.Status, _ = strconv.Atoi(kv["status"])
	ev.Bytes, _ = strconv.ParseInt(pick(kv, "body_bytes_sent", "bytes_sent"), 10, 64)
	ev.ReqTime, _ = strconv.ParseFloat(kv["request_time"], 64)
	ev.DstPort, _ = strconv.Atoi(kv["server_port"])
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
