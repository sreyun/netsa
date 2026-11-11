// Package detect 实现基于特征规则与行为统计的攻击检测。
package detect

import (
	"html"
	"strings"
	"unicode/utf8"
)

// overlongUTF8 还原 . / \ 的超长 UTF-8 编码（如 %c0%af），这是绕过目录穿越检测的常见写法，合法请求不会出现。
var overlongUTF8 = strings.NewReplacer("\xc0\xae", ".", "\xc0\xaf", "/", "\xc1\x9c", "\\", "\xe0\x80\xae", ".", "\xe0\x80\xaf", "/")

// Normalize 对 URL 做多轮解码与归一化，抵抗双重编码、%u 编码、注释混淆等绕过手法。
func Normalize(s string) string {
	return stripComments(normalizeKeepComments(s))
}

// normalizeKeepComments 与 Normalize 相同，但保留 /* */ 注释：注释里的内容同样要检测。
func normalizeKeepComments(s string) string {
	if s == "" {
		return ""
	}
	// 查询串中的 '+' 表示空格，需要在百分号解码前处理，避免把 %2B 误转。
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i+1] + strings.ReplaceAll(s[i+1:], "+", " ")
	}
	for i := 0; i < 3; i++ {
		d, changed := percentDecode(s)
		if !changed {
			break
		}
		s = d
	}
	if strings.Contains(s, "\xc0") || strings.Contains(s, "\xc1") || strings.Contains(s, "\xe0\x80") {
		s = overlongUTF8.Replace(s)
	}
	if strings.ContainsRune(s, '&') {
		s = unescapeRefs(s)
	}
	return collapseSpace(strings.ToLower(s))
}

// stripComments 去掉 /* */ 注释（抵御 union/**/select 这类注释混淆）。
func stripComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	return collapseSpace(stripSQLComments(s))
}

func unhex(c byte) (byte, bool) {
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

// percentDecode 宽松的百分号解码：非法序列原样保留，支持 IIS 的 %uXXXX。
func percentDecode(s string) (string, bool) {
	if !strings.ContainsRune(s, '%') {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			var r rune
			ok := true
			for j := 2; j < 6; j++ {
				v, good := unhex(s[i+j])
				if !good {
					ok = false
					break
				}
				r = r<<4 | rune(v)
			}
			if ok {
				b.WriteRune(r)
				i += 5
				changed = true
				continue
			}
		}
		if i+2 < len(s) {
			h, ok1 := unhex(s[i+1])
			l, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(h<<4 | l)
				i += 2
				changed = true
				continue
			}
		}
		b.WriteByte('%')
	}
	return b.String(), changed
}

// stripSQLComments 将 /*...*/ 注释替换为空格（MySQL 的 /*!50000select*/ 保留内容）。
func stripSQLComments(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.Index(s[i+2:], "*/")
		if j < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		inner := s[i+2 : i+2+j]
		if strings.HasPrefix(inner, "!") {
			b.WriteString(" " + strings.TrimLeft(inner, "!0123456789") + " ")
		} else {
			b.WriteByte(' ')
		}
		s = s[i+2+j+2:]
	}
	return b.String()
}

func collapseSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f', 0xa0:
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// Printable 将字符串中的不可打印字符转义，并截断到 max 字节，用于展示证据。
func Printable(s string, max int) string {
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
		if max > 0 && b.Len() >= max {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}

// unescapeRefs 只还原真正的字符引用：以分号结尾的命名实体（&lt; &amp;）与数字引用（&#60、&#x3c，分号可省略）。
// html.UnescapeString 还会按最长前缀还原不带分号的旧式实体，查询串里的 &notify_url=、&param=、&region=、&timestamp=
// 会变成 ¬ify_url=、¶m=、®ion=、×tamp=，参数边界被破坏，按参数匹配的规则（如内网地址的 SSRF）因此漏报。
func unescapeRefs(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for {
		i := strings.IndexByte(s, '&')
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		s = s[i:]
		j := 1
		for j < len(s) && j < 40 && (s[j] == '#' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		ref := s[:j]
		numeric := len(ref) > 2 && ref[1] == '#'
		if j < len(s) && s[j] == ';' {
			ref = s[:j+1]
		} else if !numeric {
			b.WriteByte('&') // 不带分号的名称：是参数分隔符，不是实体
			s = s[1:]
			continue
		}
		if u := html.UnescapeString(ref); u != ref {
			b.WriteString(u)
		} else {
			b.WriteString(ref)
		}
		s = s[len(ref):]
	}
}
