// Package detect 实现基于特征规则与行为统计的攻击检测。
package detect

import (
	"html"
	"strings"
	"unicode/utf8"
)

// Normalize 对 URL 做多轮解码与归一化，抵抗双重编码、%u 编码、注释混淆等绕过手法。
func Normalize(s string) string {
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
	if strings.ContainsRune(s, '&') {
		s = html.UnescapeString(s)
	}
	s = strings.ToLower(s)
	if strings.Contains(s, "/*") {
		s = stripSQLComments(s)
	}
	return collapseSpace(s)
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
