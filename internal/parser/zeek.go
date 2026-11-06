package parser

import (
	"strconv"
	"strings"

	"netsa/internal/model"
)

// Zeek（原 Bro）流量日志：conn.log、http.log、ssl.log、files.log，支持制表符分隔（带 #path / #fields 表头，
// 没有表头时按 Zeek 默认字段顺序）与 JSON（LogAscii::use_json=T，或经 Filebeat / Fluent Bit 转发）。
//   - conn.log：会话事件，含双向字节数、包数与连接状态（S0 无应答、REJ 被拒绝、SF 正常结束），用于扫描、外传、
//     带宽型 DDoS 与外连情报；
//   - http.log：Web 事件，含请求体与响应体长度；装了 http-post-body 类脚本时 post_body 字段参与规则匹配；
//   - ssl.log：TLS 握手（版本、加密套件、SNI，装了 ja3 / ja4 包时还有客户端指纹）；
//   - files.log：传输的文件（类型、文件名、大小、MD5 / SHA1 / SHA256）。
// ssl.log 与 files.log 描述的是 conn.log 中已经记录过的连接，作为辅助记录（Event.Aux）只用于情报匹配、指纹、
// 文件证据与关联，不重复计入连接统计。

type zeekKind int

const (
	zeekConn zeekKind = iota + 1
	zeekHTTP
	zeekSSL
	zeekFiles
)

var zeekNames = map[zeekKind]string{zeekConn: "zeek_conn", zeekHTTP: "zeek_http", zeekSSL: "zeek_ssl", zeekFiles: "zeek_files"}

// Zeek 默认的字段顺序（没有表头时使用；ssl.log 的 ja3 / ja4 等扩展字段只能靠表头或 JSON 识别）。
var zeekDefaultFields = map[zeekKind][]string{
	zeekConn: strings.Fields(`ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
		local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents`),
	zeekHTTP: strings.Fields(`ts uid id.orig_h id.orig_p id.resp_h id.resp_p trans_depth method host uri referrer version user_agent
		origin request_body_len response_body_len status_code status_msg info_code info_msg tags username password proxied
		orig_fuids orig_filenames orig_mime_types resp_fuids resp_filenames resp_mime_types`),
	zeekSSL: strings.Fields(`ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher curve server_name resumed last_alert
		next_protocol established ssl_history cert_chain_fps client_cert_chain_fps sni_matches_cert`),
	zeekFiles: strings.Fields(`ts fuid uid id.orig_h id.orig_p id.resp_h id.resp_p source depth analyzers mime_type filename duration
		local_orig is_orig seen_bytes total_bytes missing_bytes overflow_bytes timedout parent_fuid md5 sha1 sha256 extracted
		extracted_cutoff extracted_size`),
}

// zeekStates 是 conn.log 的连接状态。
var zeekStates = map[string]bool{"S0": true, "S1": true, "SF": true, "REJ": true, "S2": true, "S3": true, "RSTO": true, "RSTR": true,
	"RSTOS0": true, "RSTRH": true, "SH": true, "SHR": true, "OTH": true}

// ZeekTSV 按字段声明解析 Zeek 的制表符分隔日志。字段来自表头（#fields）时 header 为 true，否则为默认顺序。
type ZeekTSV struct {
	kind   zeekKind
	idx    map[string]int
	min    int // 至少需要的字段数
	header bool
}

func newZeekTSV(kind zeekKind, fields []string, header bool) *ZeekTSV {
	z := &ZeekTSV{kind: kind, idx: make(map[string]int, len(fields)), header: header}
	for i, f := range fields {
		z.idx[f] = i
	}
	need := []string{"ts", "id.orig_h", "id.resp_h"}
	for _, f := range need {
		if i, ok := z.idx[f]; ok && i+1 > z.min {
			z.min = i + 1
		}
	}
	if !header {
		z.min = len(fields) - 2 // 没有表头：字段数接近默认值才采信（老版本少一两列）
	}
	return z
}

// zeekDefaults 是按默认字段顺序识别的解析器（创建后不再修改，所有数据源共用）。
var zeekDefaults = []Parser{ZeekJSON{}, newZeekTSV(zeekConn, zeekDefaultFields[zeekConn], false), newZeekTSV(zeekHTTP, zeekDefaultFields[zeekHTTP], false),
	newZeekTSV(zeekSSL, zeekDefaultFields[zeekSSL], false), newZeekTSV(zeekFiles, zeekDefaultFields[zeekFiles], false)}

// ZeekParsers 返回没有表头时按默认字段顺序识别的 Zeek 解析器与 JSON 解析器。
func ZeekParsers() []Parser { return append([]Parser(nil), zeekDefaults...) }

// NewZeekHeader 按表头构造解析器：path 为 #path 声明的日志类型（可为空，按字段推断），fieldsLine 为 #fields 行。
// 不支持的日志类型（dns.log 由 zeek_dns 解析）返回 nil。
func NewZeekHeader(path, fieldsLine string) *ZeekTSV {
	f := strings.Split(strings.TrimRight(fieldsLine, "\r\n"), "\t")
	if len(f) < 3 || f[0] != "#fields" {
		return nil
	}
	fields := f[1:]
	kind := zeekKindOf(path, func(k string) bool {
		for _, x := range fields {
			if x == k {
				return true
			}
		}
		return false
	})
	if kind == 0 {
		return nil
	}
	return newZeekTSV(kind, fields, true)
}

// zeekKindOf 按 #path / _path 或字段推断日志类型。
func zeekKindOf(path string, has func(string) bool) zeekKind {
	switch path {
	case "conn":
		return zeekConn
	case "http":
		return zeekHTTP
	case "ssl":
		return zeekSSL
	case "files":
		return zeekFiles
	case "":
	default:
		return 0
	}
	switch {
	case has("conn_state"):
		return zeekConn
	case has("status_code") || has("method") && has("uri"):
		return zeekHTTP
	case has("server_name") || has("cipher") && has("version"):
		return zeekSSL
	case has("fuid") && (has("mime_type") || has("seen_bytes")):
		return zeekFiles
	}
	return 0
}

func (z *ZeekTSV) Name() string { return zeekNames[z.kind] }

func (z *ZeekTSV) Parse(line string) (*model.Event, bool) {
	if strings.Count(line, "\t") < z.min-1 {
		return nil, false
	}
	f := strings.Split(line, "\t")
	if len(f) < z.min {
		return nil, false
	}
	get := func(k string) string {
		i, ok := z.idx[k]
		if !ok || i >= len(f) {
			return ""
		}
		return zeekValue(f[i])
	}
	if !z.header && !z.plausible(get) {
		return nil, false
	}
	return zeekEvent(z.kind, get)
}

// plausible 在没有表头时校验关键字段，避免把其他制表符分隔的日志误认成 Zeek。
func (z *ZeekTSV) plausible(get func(string) string) bool {
	if t := get("ts"); t == "" || t[0] < '1' || t[0] > '9' || strings.IndexByte(t, '.') < 0 {
		return false
	}
	switch z.kind {
	case zeekConn:
		return zeekStates[get("conn_state")] && (get("proto") == "tcp" || get("proto") == "udp" || get("proto") == "icmp")
	case zeekHTTP:
		m := get("method")
		return m == "" || strings.ToUpper(m) == m && len(m) <= 16
	case zeekSSL:
		v, c := get("version"), get("cipher")
		return (v == "" || strings.HasPrefix(v, "TLS") || strings.HasPrefix(v, "SSL") || strings.HasPrefix(v, "DTLS")) &&
			(c == "" || strings.HasPrefix(c, "TLS_") || strings.HasPrefix(c, "SSL_"))
	case zeekFiles:
		return strings.HasPrefix(get("fuid"), "F")
	}
	return false
}

// zeekValue 把未设置（-）与空集合（(empty)）转为空串。
func zeekValue(v string) string {
	if v == "-" || v == "(empty)" {
		return ""
	}
	return v
}

// ZeekJSON 解析 JSON 格式的 Zeek 日志（按 _path 或字段判断类型；dns.log 由 json_dns 解析）。
type ZeekJSON struct{}

func (ZeekJSON) Name() string { return "zeek_json" }

func (ZeekJSON) Parse(line string) (*model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"id.orig_h"`) && !strings.Contains(line, `"id.resp_h"`) {
		return nil, false
	}
	m, ok := unmarshalLog(line)
	if !ok {
		return nil, false
	}
	kv := flattenLower(m)
	has := func(k string) bool { _, ok := kv[k]; return ok }
	kind := zeekKindOf(kv["_path"], has)
	if kind == 0 {
		return nil, false
	}
	get := func(k string) string { return zeekValue(kv[k]) }
	return zeekEvent(kind, get)
}

func zeekEvent(kind zeekKind, get func(string) string) (*model.Event, bool) {
	src, dst := get("id.orig_h"), get("id.resp_h")
	if kind == zeekFiles && src == "" {
		// 老版本 files.log 没有连接四元组，只有 tx_hosts / rx_hosts
		dst, src = firstOf(get("tx_hosts")), firstOf(get("rx_hosts"))
	}
	if !isIP(src) || !isIP(dst) {
		return nil, false
	}
	ev := &model.Event{Format: zeekNames[kind], Time: ParseTime(get("ts")), SrcIP: src, DstIP: dst,
		SrcPort: atoi(get("id.orig_p")), DstPort: atoi(get("id.resp_p"))}
	switch kind {
	case zeekConn:
		ev.Kind, ev.Proto, ev.Action = model.KindFirewall, normProto(get("proto")), model.ActionAllow
		ev.SentBytes, ev.RecvBytes = atoi64(get("orig_bytes")), atoi64(get("resp_bytes"))
		ev.Packets = atoi64(get("orig_pkts")) + atoi64(get("resp_pkts"))
		ev.Flags = get("history")
		ev.Duration, _ = strconv.ParseFloat(get("duration"), 64)
		switch st := get("conn_state"); st {
		case "REJ", "RSTOS0", "RSTRH":
			ev.Action, ev.Reply = model.ActionDeny, model.ReplyYes // 目标拒绝了连接（端口关闭）
		case "S0", "SH":
			ev.Reply = model.ReplyNone // 没有应答
		case "S1", "SF", "S2", "S3", "RSTO", "RSTR":
			ev.Reply = model.ReplyYes
		}
		if s := get("service"); s != "" {
			ev.Service = s
		}
	case zeekHTTP:
		uri := get("uri")
		if uri == "" {
			return nil, false
		}
		ev.Kind, ev.Proto = model.KindWeb, "tcp"
		ev.Method, ev.URI, ev.Host = get("method"), uri, get("host")
		ev.Referer, ev.UA = get("referrer"), get("user_agent")
		ev.Status = atoi(get("status_code"))
		ev.Bytes, ev.ReqLength = atoi64(get("response_body_len")), atoi64(get("request_body_len"))
		if v := get("version"); v != "" {
			ev.HTTPProto = "HTTP/" + v
		}
		if b := get("post_body"); b != "" {
			ev.Body = truncBody(b)
		}
		if xff := get("x_forwarded_for"); xff != "" {
			ev.XFF = xff
		}
	case zeekSSL:
		ev.Kind, ev.Proto, ev.Action, ev.Aux = model.KindFirewall, "tcp", model.ActionAllow, true
		ev.TLSProto, ev.TLSCipher, ev.SNI = get("version"), get("cipher"), strings.ToLower(get("server_name"))
		ev.Host = ev.SNI
		switch {
		case get("ja4") != "":
			ev.TLSFinger = "ja4:" + strings.ToLower(get("ja4"))
		case get("ja3") != "":
			ev.TLSFinger = "ja3:" + strings.ToLower(get("ja3"))
		case ev.TLSProto != "" && ev.TLSCipher != "":
			ev.TLSFinger = "tls:" + ev.TLSProto + "/" + ev.TLSCipher
		}
		if e := get("established"); e == "F" || e == "false" {
			ev.Reply = model.ReplyNone
		}
	case zeekFiles:
		ev.Kind, ev.Action, ev.Aux = model.KindFirewall, model.ActionAllow, true
		// 文件的发送方是 tx（下载时为服务端），接收方 rx 作为主体：SrcIP 为接收文件的主机，DstIP 为发送方
		if o := get("is_orig"); o == "T" || o == "true" {
			ev.SrcIP, ev.DstIP = dst, src // 由连接发起方发送（上传）
			ev.SrcPort, ev.DstPort = ev.DstPort, ev.SrcPort
		}
		fi := &model.FileInfo{Name: get("filename"), Mime: get("mime_type"), MD5: strings.ToLower(get("md5")),
			SHA1: strings.ToLower(get("sha1")), SHA256: strings.ToLower(get("sha256")), Proto: strings.ToUpper(get("source"))}
		fi.Size = atoi64(get("total_bytes"))
		if fi.Size == 0 {
			fi.Size = atoi64(get("seen_bytes"))
		}
		ev.File = fi
		ev.Proto = "tcp"
	}
	return ev, true
}

func firstOf(set string) string {
	if i := strings.IndexByte(set, ','); i >= 0 {
		return set[:i]
	}
	return set
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// truncBody 截断请求体（只取前 4 KB 参与匹配）。
func truncBody(b string) string {
	if len(b) > 4096 {
		b = b[:4096]
	}
	return b
}
