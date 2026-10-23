package parser

import (
	"strconv"
	"strings"
	"time"

	"netsa/internal/model"
)

// W3C 解析 W3C 扩展日志格式（IIS 默认格式）。字段顺序由日志中的 "#Fields:" 指令决定，
// 缺少指令时按 IIS 默认字段解析。按规范 date/time 为 UTC。
type W3C struct {
	fields []string
	idx    map[string]int
}

const iisDefaultFields = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken"

var defaultW3C, _ = NewW3C(iisDefaultFields)

// DefaultW3C 返回按 IIS 默认字段配置的解析器。
func DefaultW3C() *W3C { return defaultW3C }

// NewW3C 根据 "#Fields:" 指令创建解析器；字段中必须包含客户端地址与请求路径。
func NewW3C(directive string) (*W3C, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(directive), "#Fields:")
	if !ok {
		return nil, false
	}
	w := &W3C{fields: strings.Fields(rest), idx: map[string]int{}}
	for i, f := range w.fields {
		w.idx[strings.ToLower(f)] = i
	}
	_, hasIP := w.idx["c-ip"]
	_, hasURI := w.idx["cs-uri-stem"]
	if !hasIP || !hasURI {
		return nil, false
	}
	return w, true
}

func (*W3C) Name() string { return "iis_w3c" }

func (w *W3C) Parse(line string) (*model.Event, bool) {
	if len(line) == 0 || line[0] == '#' {
		return nil, false
	}
	cols := strings.Fields(line)
	if len(cols) != len(w.fields) {
		return nil, false
	}
	get := func(name string) string {
		if i, ok := w.idx[name]; ok && cols[i] != "-" {
			return cols[i]
		}
		return ""
	}
	ip := get("c-ip")
	uri := get("cs-uri-stem")
	if !isIP(ip) || uri == "" || uri[0] != '/' {
		return nil, false
	}
	if q := get("cs-uri-query"); q != "" {
		uri += "?" + q
	}
	ev := &model.Event{Kind: model.KindWeb, Format: "iis_w3c", SrcIP: ip, URI: uri, Method: get("cs-method"),
		HTTPProto: get("cs-version"), Host: get("cs-host"), DstIP: get("s-ip"),
		UA:      strings.ReplaceAll(get("cs(user-agent)"), "+", " "),
		Referer: get("cs(referer)"),
		XFF:     firstNonEmptyStr(get("x-forwarded-for"), get("cs(x-forwarded-for)")),
	}
	if !isMethod(ev.Method) {
		return nil, false
	}
	if d, t := get("date"), get("time"); d != "" && t != "" {
		ev.Time, _ = time.ParseInLocation("2006-01-02 15:04:05", d+" "+t, time.UTC)
	}
	ev.Status, _ = strconv.Atoi(get("sc-status"))
	ev.Bytes, _ = strconv.ParseInt(get("sc-bytes"), 10, 64)
	ev.DstPort, _ = strconv.Atoi(get("s-port"))
	if ms, err := strconv.ParseFloat(get("time-taken"), 64); err == nil {
		ev.ReqTime = ms / 1000
	}
	if ev.Status == 0 {
		return nil, false
	}
	return ev, true
}

func firstNonEmptyStr(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
