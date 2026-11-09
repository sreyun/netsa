package model

import (
	"strings"
	"unicode/utf8"
)

// 非 HTTP 请求：TLS、RDP、SMB 等二进制协议发往 HTTP 端口时，nginx 把收到的字节当作请求行记录（\xHH 转义），
// 解析后 URI 是一串二进制。它不是 URI：作为攻击目标显示时只标明协议，原始字节保留在告警证据（已转义）与原始日志中。

// NonHTTPRequest 判断请求行是否根本不是 HTTP（没有请求方法，也不是以 / 开头的路径）。
func NonHTTPRequest(method, uri string) bool {
	return method == "" && uri != "" && uri[0] != '/'
}

// ProbeProtocol 按开头的字节识别发往 HTTP 端口的非 HTTP 协议，识别不出时返回空。
func ProbeProtocol(raw string) string {
	switch {
	case strings.HasPrefix(raw, "\x16\x03"):
		return "TLS 握手"
	case len(raw) > 2 && raw[0]&0x80 != 0 && raw[2] == 0x01 && len(raw) > 4 && raw[3] == 0x03:
		return "SSLv2 握手"
	case strings.Contains(raw, "mstshash") || strings.HasPrefix(raw, "\x03\x00"):
		return "RDP"
	case strings.HasPrefix(raw, "SSH-"):
		return "SSH"
	case strings.Contains(raw, "(DESCRIPTION=") || strings.Contains(raw, "(CONNECT_DATA="):
		return "Oracle TNS"
	case strings.Contains(raw, "\xffSMB") || strings.Contains(raw, "\xfeSMB"):
		return "SMB"
	case strings.HasPrefix(raw, "<policy-file-request/>"):
		return "Flash 策略文件请求"
	case strings.HasPrefix(raw, "JDWP-Handshake"):
		return "JDWP 调试握手"
	case strings.HasPrefix(raw, "\x12\x01\x00"):
		return "SQL Server 预登录"
	case len(raw) >= 12 && raw[4] == 0x01 && raw[5] == 0x00 && raw[6] == 0x00 && raw[7] == 0x01 && raw[8] == 0 && raw[9] == 0:
		// TCP 上的 DNS 查询：2 字节长度 + 报文头（标志 0x0100 标准查询、问题数 1、回答数 0）
		return "DNS 查询（TCP）"
	case strings.HasPrefix(raw, "*1\r\n$") || strings.HasPrefix(raw, "*2\r\n$") || strings.HasPrefix(raw, "*3\r\n$"):
		return "Redis 命令"
	}
	return ""
}

// ProbeLabel 返回非 HTTP 请求作为攻击目标时的说明：能识别的写协议名；可读的文本取开头一段（控制字符转义）；
// 其余二进制统一记为“二进制数据”，同一站点的这类探测合并为一个目标，不再各占一个目标名额。
func ProbeLabel(raw string) string {
	if p := ProbeProtocol(raw); p != "" {
		return "（非 HTTP 请求：" + p + "）"
	}
	if ReadableText(raw) {
		return "（非 HTTP 请求：" + Printable(raw, 40) + "）"
	}
	return "（非 HTTP 请求：二进制数据）"
}

// ReadableText 判断内容是否为可读文本：合法 UTF-8，控制字符只有空白类（制表、回车、换行）。
func ReadableText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' && c != '\r' && c != '\n' || c == 0x7f {
			return false
		}
	}
	return true
}

// Printable 把控制字符与非法 UTF-8 字节转义为 \xHH，max > 0 时超出部分截断并加省略号。
func Printable(s string, max int) string {
	if max <= 0 && !needsEscape(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 || r < 0x20 || r == 0x7f {
			b.WriteString(`\x`)
			b.WriteByte("0123456789abcdef"[s[i]>>4])
			b.WriteByte("0123456789abcdef"[s[i]&0xf])
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
		if max > 0 && b.Len() >= max && i < len(s) {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}

// Clip 把 s 截断到不超过 n 字节，并且不截断多字节字符：按字节直接截断会把中文等字符截成半个，页面上显示为 �。
func Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// needsEscape 判断是否含有控制字符或非法 UTF-8（多字节字符的各字节都不小于 0x80，逐字节检查控制字符即可）。
// PrintableBinary 用于显示二进制载荷：不是可读文本时，所有非 ASCII 字节都转义为 \xHH。
// 随机字节里常有恰好构成合法 UTF-8 的组合（\xd5\xa1 → ա），按字符显示会冒出零散的怪字。
func PrintableBinary(s string, max int) string {
	if ReadableText(s) {
		return Printable(s, max)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f {
			b.WriteString(`\x`)
			b.WriteByte("0123456789abcdef"[c>>4])
			b.WriteByte("0123456789abcdef"[c&0xf])
		} else {
			b.WriteByte(c)
		}
		if max > 0 && b.Len() >= max && i+1 < len(s) {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}

func needsEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return !utf8.ValidString(s)
}

// webTarget 返回 Web 请求作为攻击目标的写法：站点 + 空格 + URI。非 HTTP 请求只标明协议；URI 中的控制字符与非法字节转义，
// 避免页面上出现乱码。
func webTarget(host, method, uri string) string {
	if host == "" {
		host = "-"
	}
	if NonHTTPRequest(method, uri) {
		return host + " " + ProbeLabel(uri)
	}
	return host + " " + Printable(uri, 0)
}

// CleanTarget 整理旧版本保存的攻击目标（站点 + 空格 + 原始请求行）：其中的二进制请求改为按协议说明，
// 控制字符转义（升级后载入快照时调用，已整理过的目标原样返回）。
func CleanTarget(t string) string {
	if !needsEscape(t) {
		return t
	}
	host, rest, ok := strings.Cut(t, " ")
	if !ok || host == "" {
		return Printable(t, 0)
	}
	if rest != "" && rest[0] != '/' {
		return host + " " + ProbeLabel(rest)
	}
	return host + " " + Printable(rest, 0)
}
