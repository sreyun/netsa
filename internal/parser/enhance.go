package parser

import (
	"strconv"
	"strings"

	"netsa/internal/model"
)

// Web 日志的增强字段：建议在 nginx 的 log_format 中增加
//
//	$request_length $upstream_status $upstream_response_time $ssl_protocol $ssl_cipher
//
// 解析后用于成功研判（请求没有转发到后端时载荷没有被应用处理）、WebShell 行为画像（请求长度随命令变化）
// 与客户端指纹（TLS 协议与加密套件，同一工具在不同出口上不变）。JSON 日志与自定义 log_format 按字段名读取；
// combined 格式之后以 key=value 追加的写法（rl=、us=、ssl= 等）同样支持。

// enhanceKeys 是各增强字段的键名（小写，含 ECS 与常见网关的写法）。
var (
	keyReqLength = []string{"request_length", "http.request.bytes", "request_size", "requestsize", "req_len", "rl"}
	keyUpstream  = []string{"upstream_status", "upstreamstatus", "upstream.status", "us"}
	keyUpTime    = []string{"upstream_response_time", "upstreamresponsetime", "upstream.response_time", "urt", "ut"}
	keyTLSProto  = []string{"ssl_protocol", "tls.version", "tls_version", "tlsversion", "ssl"}
	keyTLSCipher = []string{"ssl_cipher", "tls.cipher", "tls_cipher", "tlscipher", "cipher"}
	keyJA3       = []string{"ja3", "tls.client.ja3", "http_ssl_ja3", "ssl_ja3", "ja3_hash"}
	keyJA4       = []string{"ja4", "tls.client.ja4", "http_ssl_ja4", "ssl_ja4"}
)

// fillEnhanced 读取 Web 日志的增强字段（kv 的键已小写）。
func fillEnhanced(ev *model.Event, kv map[string]string) {
	if v := pick(kv, keyReqLength...); v != "" {
		ev.ReqLength, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := pick(kv, keyUpstream...); v != "" {
		ev.Upstream = upstreamStatus(v)
	}
	if v := pick(kv, keyUpTime...); v != "" {
		ev.UpstreamTime = lastFloat(v)
	}
	if v := dash(pick(kv, keyTLSProto...)); v != "" && len(v) <= 16 {
		ev.TLSProto = v
	}
	if v := dash(pick(kv, keyTLSCipher...)); v != "" && len(v) <= 64 {
		ev.TLSCipher = v
	}
	ev.TLSFinger = tlsFinger(ev, pick(kv, keyJA4...), pick(kv, keyJA3...))
}

// tlsFinger 返回客户端 TLS 指纹：优先 JA4、JA3，没有时用“协议/加密套件”（区分度低，只作参考）。
func tlsFinger(ev *model.Event, ja4, ja3 string) string {
	switch {
	case isFinger(ja4):
		return "ja4:" + strings.ToLower(ja4)
	case isFinger(ja3):
		return "ja3:" + strings.ToLower(ja3)
	case ev.TLSProto != "" && ev.TLSCipher != "":
		return "tls:" + ev.TLSProto + "/" + ev.TLSCipher
	}
	return ""
}

func isFinger(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 16 && len(s) <= 64 && s != "-"
}

// upstreamStatus 解析 $upstream_status：“-”为请求没有转发到后端；内部跳转或重试时有多个值（“502, 200”“404 : 200”），取最后一个。
func upstreamStatus(v string) int {
	v = strings.TrimSpace(v)
	if v == "-" || v == "" {
		return -1
	}
	last := v
	if i := strings.LastIndexAny(v, ",:"); i >= 0 {
		last = strings.TrimSpace(v[i+1:])
	}
	if last == "-" {
		return -1
	}
	n, err := strconv.Atoi(last)
	if err != nil || n < 100 || n > 599 {
		return 0
	}
	return n
}

func lastFloat(v string) float64 {
	if i := strings.LastIndexAny(v, ",:"); i >= 0 {
		v = v[i+1:]
	}
	f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
	return f
}
