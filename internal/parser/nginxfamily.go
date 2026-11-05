package parser

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"netsa/internal/model"
)

// nginx 系产品（Tengine、OpenResty 及基于 OpenResty 的 APISIX、Kong、Nginx Proxy Manager）的日志。
// Tengine、OpenResty、Kong 的访问日志与 nginx 相同，由 Nginx / LogFormat 解析；这里是默认格式不同的产品，
// 以及这些产品共用的错误日志（ModSecurity、naxsi 的拦截记录与限流拒绝）。

// ---------------- Apache APISIX 默认访问日志 ----------------

// APISIX 解析 Apache APISIX 默认的访问日志：$http_host 在请求行之前，$request_time 紧跟字节数，
// 行尾是上游地址、上游状态码、上游耗时与上游 URL：
//
//	$remote_addr - $remote_user [$time_local] $http_host "$request" $status $body_bytes_sent $request_time "$http_referer" "$http_user_agent" $upstream_addr $upstream_status $upstream_response_time "$upstream_scheme://$upstream_host$upstream_uri"
type APISIX struct{}

func (APISIX) Name() string { return "apisix" }

func (APISIX) Parse(line string) (*model.Event, bool) {
	// 来源、ident、用户（逐段切开而不是 SplitN：其他格式的行也会经过这里，不能为它们分配内存）
	ip, rest, ok := strings.Cut(line, " ")
	if !ok {
		return nil, false
	}
	for range 2 {
		if _, rest, ok = strings.Cut(rest, " "); !ok {
			return nil, false
		}
	}
	if len(rest) < 2 || rest[0] != '[' || !isIP(ip) {
		return nil, false
	}
	j := strings.IndexByte(rest, ']')
	if j < 0 || len(rest) < j+3 || rest[j+1] != ' ' {
		return nil, false
	}
	tm := rest[1:j]
	host, rest, ok := strings.Cut(rest[j+2:], " ")
	if !ok || host == "" || host[0] == '"' {
		return nil, false
	}
	req, rest, ok := quoted(rest)
	if !ok || !strings.HasPrefix(rest, " ") {
		return nil, false
	}
	n := strings.SplitN(rest[1:], " ", 4) // 状态码、字节数、请求耗时、其余
	if len(n) < 4 || len(n[0]) != 3 || n[0][0] < '1' || n[0][0] > '5' {
		return nil, false
	}
	status, err := strconv.Atoi(n[0])
	if err != nil {
		return nil, false
	}
	reqTime, err := strconv.ParseFloat(n[2], 64)
	if err != nil {
		return nil, false
	}
	ref, rest, ok := quoted(n[3])
	if !ok || !strings.HasPrefix(rest, " ") {
		return nil, false
	}
	ua, _, ok := quoted(rest[1:])
	if !ok {
		return nil, false
	}
	ev := &model.Event{
		Time:    parseNginxTime(tm),
		Kind:    model.KindWeb,
		Format:  "apisix",
		SrcIP:   ip,
		Status:  status,
		ReqTime: reqTime,
		Host:    hostOnly(dash(host)),
		Referer: dash(unescapeNginx(ref)),
		UA:      dash(unescapeNginx(ua)),
	}
	ev.Bytes, _ = strconv.ParseInt(n[1], 10, 64)
	setRequest(ev, unescapeNginx(req))
	return ev, true
}

// hostOnly 去掉站点名中的端口并转为小写。
func hostOnly(h string) string {
	if h == "" {
		return ""
	}
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.ToLower(h)
}

// ---------------- Nginx Proxy Manager ----------------

// NginxProxyManager 解析 Nginx Proxy Manager（基于 OpenResty）代理站点的 proxy 格式与默认站点的 standard 格式：
//
//	[$time_local] $upstream_cache_status $upstream_status $status - $request_method $scheme $host "$request_uri" [Client $remote_addr] [Length $body_bytes_sent] [Gzip $gzip_ratio] [Sent-to $server] "$http_user_agent" "$http_referer"
//	[$time_local] $status - $request_method $scheme $host "$request_uri" [Client $remote_addr] [Length $body_bytes_sent] [Gzip $gzip_ratio] "$http_user_agent" "$http_referer"
type NginxProxyManager struct{}

func (NginxProxyManager) Name() string { return "nginx_proxy_manager" }

func (NginxProxyManager) Parse(line string) (*model.Event, bool) {
	if len(line) < 40 || line[0] != '[' || !strings.Contains(line, " [Client ") {
		return nil, false
	}
	j := strings.IndexByte(line, ']')
	if j < 0 {
		return nil, false
	}
	tm := line[1:j]
	// [缓存状态 上游状态码] 状态码 -：缓存状态、上游状态码也可能是 "-"，分隔符是紧跟在状态码之后的 "-"
	tail, status := strings.TrimPrefix(line[j+1:], " "), 0
	for k := 0; ; k++ {
		tok, r, ok := strings.Cut(tail, " ")
		if !ok || k > 5 {
			return nil, false
		}
		tail = r
		if tok == "-" && status > 0 {
			break
		}
		if n, err := strconv.Atoi(tok); err == nil && n >= 100 && n <= 599 {
			status = n
		} else {
			status = 0
		}
	}
	f := strings.SplitN(tail, " ", 4) // 方法、协议、站点名、"URI" 及其余
	if len(f) < 4 || f[0] != "-" && !isMethod(f[0]) {
		return nil, false
	}
	uri, rest, ok := quoted(f[3])
	if !ok {
		return nil, false
	}
	ev := &model.Event{
		Time:   parseNginxTime(tm),
		Kind:   model.KindWeb,
		Format: "nginx_proxy_manager",
		Method: dash(f[0]),
		URI:    dash(unescapeNginx(uri)),
		Host:   hostOnly(dash(f[2])),
		Status: status,
	}
	for { // [Client …] [Length …] [Gzip …] [Sent-to …]
		rest = strings.TrimPrefix(rest, " ")
		if !strings.HasPrefix(rest, "[") {
			break
		}
		k := strings.IndexByte(rest, ']')
		if k < 0 {
			return nil, false
		}
		key, val, _ := strings.Cut(rest[1:k], " ")
		switch key {
		case "Client":
			ev.SrcIP = val
		case "Length":
			ev.Bytes, _ = strconv.ParseInt(val, 10, 64)
		}
		rest = rest[k+1:]
	}
	if !isIP(ev.SrcIP) {
		return nil, false
	}
	if ua, r, ok := quoted(rest); ok {
		ev.UA = dash(unescapeNginx(ua))
		if ref, _, ok := quoted(strings.TrimPrefix(r, " ")); ok {
			ev.Referer = dash(unescapeNginx(ref))
		}
	}
	return ev, true
}

// ---------------- nginx / Tengine / OpenResty 错误日志 ----------------

// NginxError 解析 nginx 系产品的错误日志：
//
//	2026/11/05 10:00:00 [error] 1234#0: *5678 <消息>, client: 1.2.3.4, server: example.com, request: "GET / HTTP/1.1", host: "example.com"
//
// 只有安全相关的行产生事件：ModSecurity 与 naxsi 的拦截或告警、limit_req / limit_conn 的限流拒绝。
// 其余错误（文件不存在、上游超时等）由 Skip 识别为已知格式，计为跳过而不是解析失败。
// 同一请求的访问日志另有一条记录，这里的事件只携带 WAF 的判定（见 detect 对 Threat 的处理），不重复匹配规则。
type NginxError struct{}

func (NginxError) Name() string { return "nginx_error" }

// nginxErrorLine 拆出错误日志的时间、级别与消息；不是错误日志格式时返回 false。
func nginxErrorLine(line string) (tm, level, msg string, ok bool) {
	if len(line) < 32 || line[4] != '/' || line[7] != '/' || line[10] != ' ' || line[13] != ':' || line[16] != ':' ||
		line[19] != ' ' || line[20] != '[' || line[0] < '0' || line[0] > '9' {
		return "", "", "", false
	}
	j := strings.IndexByte(line[21:], ']')
	if j <= 0 || j > 8 {
		return "", "", "", false
	}
	level = line[21 : 21+j]
	rest := line[21+j+1:]
	// " 1234#0: " 进程号#线程号，之后可能有 "*连接号 "
	if !strings.HasPrefix(rest, " ") {
		return "", "", "", false
	}
	pid, rest, ok := strings.Cut(rest[1:], ": ")
	if !ok || !strings.Contains(pid, "#") {
		return "", "", "", false
	}
	if strings.HasPrefix(rest, "*") {
		if k := strings.IndexByte(rest, ' '); k > 0 {
			rest = rest[k+1:]
		}
	}
	return line[:19], level, rest, true
}

// Skip 识别格式正确但与安全无关的错误日志行。
func (NginxError) Skip(line string) bool {
	_, _, _, ok := nginxErrorLine(line)
	return ok
}

func (NginxError) Parse(line string) (*model.Event, bool) {
	tm, _, msg, ok := nginxErrorLine(line)
	if !ok {
		return nil, false
	}
	i := strings.LastIndex(msg, ", client: ")
	if i < 0 {
		return nil, false
	}
	body, trailer := msg[:i], errorTrailer(msg[i+2:])
	ev := &model.Event{Time: ParseTime(tm), Kind: model.KindWeb, Format: "nginx_error", SrcIP: trailer["client"]}
	switch {
	case strings.Contains(body, "ModSecurity: "):
		if !modsecErrorLine(ev, body[strings.Index(body, "ModSecurity: ")+len("ModSecurity: "):]) {
			return nil, false
		}
	case strings.Contains(body, "NAXSI_FMT: "):
		if !naxsiLine(ev, body[strings.Index(body, "NAXSI_FMT: ")+len("NAXSI_FMT: "):]) {
			return nil, false
		}
	case strings.HasPrefix(body, "limiting requests"), strings.HasPrefix(body, "limiting connections"):
		limitLine(ev, body)
	default:
		return nil, false
	}
	if !isIP(ev.SrcIP) {
		return nil, false
	}
	ev.Host = hostOnly(pick(trailer, "host", "server"))
	if r := trailer["request"]; r != "" {
		setRequest(ev, unescapeNginx(r))
	}
	if ev.Referer == "" {
		ev.Referer = trailer["referrer"]
	}
	return ev, true
}

// errorTrailer 解析错误日志行尾的 "client: 1.2.3.4, server: x, request: "…", host: "…"" 字段。
func errorTrailer(s string) map[string]string {
	kv := make(map[string]string, 6)
	for s != "" {
		k, rest, ok := strings.Cut(s, ": ")
		if !ok || k == "" || len(k) > 16 || strings.ContainsAny(k, " ,\"") {
			break
		}
		var v string
		if strings.HasPrefix(rest, `"`) {
			if v, rest, ok = quoted(rest); !ok {
				break
			}
		} else if v, rest, ok = strings.Cut(rest, ", "); !ok {
			v, rest = rest, ""
		} else {
			rest = ", " + rest
		}
		kv[k] = v
		s = strings.TrimPrefix(rest, ", ")
	}
	return kv
}

var reModsecField = regexp.MustCompile(`\[(\w+) "((?:[^"\\]|\\.)*)"\]`)

// modsecRecord 是 ModSecurity 一条规则命中的要素。
type modsecRecord struct {
	msg, id, sev string
	tags         []string
	denied       bool
}

// parseModsecText 解析 ModSecurity 文本格式的命中记录（错误日志与 v2 JSON 审计日志的 messages）：
// "Access denied with code 403 (phase 2). Matched … [id "942100"] [msg "SQL Injection …"] [severity "2"] [tag "attack-sqli"] …"
func parseModsecText(s string) modsecRecord {
	r := modsecRecord{denied: strings.HasPrefix(s, "Access denied")}
	for _, m := range reModsecField.FindAllStringSubmatch(s, -1) {
		switch m[1] {
		case "id":
			r.id = m[2]
		case "msg":
			r.msg = m[2]
		case "severity":
			r.sev = m[2]
		case "tag":
			r.tags = append(r.tags, m[2])
		}
	}
	return r
}

// anomaly 判断是否为 CRS 的异常评分汇总或关联规则（949xxx、959xxx、98xxxx）：这类记录不说明攻击类型。
func (r modsecRecord) anomaly() bool {
	return strings.Contains(r.msg, "Anomaly Score") || strings.HasPrefix(r.id, "949") || strings.HasPrefix(r.id, "959") ||
		strings.HasPrefix(r.id, "98")
}

// attackTags 返回 CRS 的攻击类型标签（attack-sqli、attack-rce……）。
func (r modsecRecord) attackTags() []string {
	var out []string
	for _, t := range r.tags {
		if strings.HasPrefix(t, "attack-") && t != "attack-generic" {
			out = append(out, t)
		}
	}
	return out
}

// apply 把命中记录写入事件。
func (r modsecRecord) apply(ev *model.Event) {
	ev.Threat = r.msg
	if ev.Threat == "" {
		ev.Threat = "ModSecurity 规则 " + r.id
	}
	cat := "ModSecurity"
	if r.id != "" {
		cat += " " + r.id
	}
	if t := r.attackTags(); len(t) > 0 {
		cat += " " + strings.Join(t, " ")
	}
	ev.ThreatCategory = cat
	ev.ThreatSeverity = modsecSeverity(r.sev)
	ev.Action = model.ActionLog
	if r.denied {
		ev.Action = model.ActionDeny
	}
}

// modsecSeverity 把 ModSecurity 的规则等级（0~7 或 EMERGENCY…DEBUG）换成通用等级词。
// CRS 几乎所有攻击规则都标为 CRITICAL，这只是规则本身的等级，不代表攻击成功，按高危处理。
func modsecSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "0", "1", "2", "3", "EMERGENCY", "ALERT", "CRITICAL", "ERROR":
		return "high"
	case "4", "WARNING":
		return "medium"
	case "5", "NOTICE":
		return "low"
	case "6", "7", "INFO", "DEBUG":
		return "info"
	}
	return "high"
}

// modsecErrorLine 处理错误日志中的一条 ModSecurity 记录。阻断模式下一个请求会先逐条记录命中的规则（Warning），
// 最后记录异常评分超限的拦截（Access denied）；只记录评分汇总的告警（未拦截）不说明攻击类型，跳过。
func modsecErrorLine(ev *model.Event, s string) bool {
	if !strings.HasPrefix(s, "Access denied") && !strings.HasPrefix(s, "Warning") {
		return false // 审计日志写入失败等运行错误
	}
	r := parseModsecText(s)
	if r.anomaly() && !r.denied {
		return false
	}
	r.apply(ev)
	if r.denied {
		if i := strings.Index(s, "with code "); i >= 0 {
			ev.Status, _ = strconv.Atoi(strings.TrimSpace(s[i+10 : min(len(s), i+13)]))
		}
	}
	return true
}

// naxsi 的评分类型对应的攻击类型关键字（供设备威胁分类）。
var naxsiScores = map[string]string{
	"$SQL": "sql injection", "$XSS": "xss", "$RFI": "rfi", "$TRAVERSAL": "traversal", "$EVADE": "evasion",
	"$UPLOAD": "upload", "$UWA": "scanner", "$ATTACK": "exploit",
}

// naxsiLine 处理 naxsi 的 NAXSI_FMT 记录：ip=…&server=…&uri=…&config=block&cscore0=$SQL&score0=8&zone0=ARGS&id0=1000&var_name0=id
func naxsiLine(ev *model.Event, s string) bool {
	kv := map[string]string{}
	for _, p := range strings.Split(s, "&") {
		if k, v, ok := strings.Cut(p, "="); ok {
			kv[k] = v
		}
	}
	var kinds, ids []string
	for i := 0; i < 16; i++ {
		n := strconv.Itoa(i)
		if c, ok := kv["cscore"+n]; ok {
			k := naxsiScores[strings.ToUpper(c)]
			if k == "" {
				k = strings.ToLower(strings.TrimPrefix(c, "$"))
			}
			kinds = append(kinds, k)
		}
		if id, ok := kv["id"+n]; ok {
			ids = append(ids, id)
		}
		if _, ok := kv["zone"+n]; !ok && i > 0 {
			break
		}
	}
	if len(kinds) == 0 && len(ids) == 0 {
		return false
	}
	ev.Threat = "naxsi 规则 " + strings.Join(ids, ",")
	ev.ThreatCategory = "naxsi " + strings.Join(kinds, " ")
	ev.ThreatSeverity = "high"
	ev.Action = model.ActionLog
	cfg := strings.ToLower(kv["config"])
	if kv["block"] == "1" || strings.Contains(cfg, "block") || strings.Contains(cfg, "drop") {
		ev.Action = model.ActionDeny
		ev.Status = 403
	}
	if ev.SrcIP == "" {
		ev.SrcIP = kv["ip"]
	}
	return true
}

// limitLine 处理 limit_req / limit_conn 拒绝请求的记录：
// limiting requests, excess: 20.500 by zone "one"；limiting connections by zone "addr"。dry run 只记录不拒绝。
func limitLine(ev *model.Event, s string) {
	zone := ""
	if i := strings.Index(s, `zone "`); i >= 0 {
		zone, _, _ = strings.Cut(s[i+6:], `"`)
	}
	mod := "limit_req"
	if strings.HasPrefix(s, "limiting connections") {
		mod = "limit_conn"
	}
	ev.Threat = "nginx 限流拒绝（" + mod + " " + zone + "）"
	ev.ThreatCategory = "rate limit"
	ev.ThreatSeverity = "low"
	ev.Action = model.ActionDeny
	ev.Status = 503
	if strings.Contains(s, "dry run") {
		ev.Action = model.ActionLog
		ev.Status = 0
	}
}

// ---------------- ModSecurity JSON 审计日志 ----------------

// modsecAudit 从 ModSecurity JSON 审计日志（SecAuditLogFormat JSON）中取出 WAF 的判定，事件的请求字段已由 NginxJSON 填好。
// v3（libmodsecurity，nginx 连接器）：{"transaction":{"client_ip":…,"request":{…},"response":{"http_code":403},"messages":[{"message":…,"details":{"ruleId":…,"severity":"2","tags":[…]}}]}}
// v2：{"transaction":{"remote_address":…},"request":{"request_line":…},"response":{"status":403},"audit_data":{"messages":["Access denied …"],"action":{"intercepted":true}}}
func modsecAudit(ev *model.Event, m map[string]any) bool {
	tx, ok := m["transaction"].(map[string]any)
	if !ok {
		return false
	}
	var recs []modsecRecord
	denied := false
	if msgs, ok := tx["messages"].([]any); ok { // v3
		for _, x := range msgs {
			mm, ok := x.(map[string]any)
			if !ok {
				continue
			}
			r := modsecRecord{}
			r.msg, _ = mm["message"].(string)
			if d, ok := mm["details"].(map[string]any); ok {
				r.id, _ = d["ruleId"].(string)
				r.sev, _ = d["severity"].(string)
				if tags, ok := d["tags"].([]any); ok {
					for _, t := range tags {
						if s, ok := t.(string); ok {
							r.tags = append(r.tags, s)
						}
					}
				}
			}
			recs = append(recs, r)
		}
		engine := ""
		if p, ok := tx["producer"].(map[string]any); ok {
			engine, _ = p["secrules_engine"].(string)
		}
		denied = !strings.EqualFold(engine, "DetectionOnly") && (ev.Status == 403 || ev.Status == 406)
	} else if ad, ok := m["audit_data"].(map[string]any); ok { // v2
		if msgs, ok := ad["messages"].([]any); ok {
			for _, x := range msgs {
				if s, ok := x.(string); ok {
					recs = append(recs, parseModsecText(s))
				}
			}
		}
		if a, ok := ad["action"].(map[string]any); ok {
			denied, _ = a["intercepted"].(bool)
		}
	} else {
		return false
	}
	if len(recs) == 0 {
		return true // 只因响应码被记录（SecAuditLogRelevantStatus），按普通访问处理
	}
	best := recs[0]
	for _, r := range recs { // 优先取说明攻击类型的规则，评分汇总放到最后
		if !r.anomaly() && (best.anomaly() || len(best.attackTags()) == 0 && len(r.attackTags()) > 0) {
			best = r
		}
	}
	best.denied = denied
	best.apply(ev)
	ev.Format = "modsecurity"
	return true
}
