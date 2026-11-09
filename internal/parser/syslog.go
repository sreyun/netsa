package parser

import (
	"regexp"
	"strings"
	"time"
)

// SyslogHeader 是从 syslog 报文头中提取出的信息。
type SyslogHeader struct {
	Time time.Time
	Host string
	Tag  string
}

// 报文头正则只匹配头部，正文按匹配结束的位置截取（headMatch）。以 (.*)$ 捕获正文会让正则引擎逐字节扫描整条日志
// （华为会话日志每条约 9µs），而几乎每条日志都要先经过这里。
var (
	reSyslog5424 = regexp.MustCompile(`^<\d{1,3}>1 (\S+) (\S+) (\S+) \S+ \S+ (?:-|(?:\[[^\]]*\])+) ?`)
	reSyslogISO  = regexp.MustCompile(`^(?:<\d{1,3}>)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+`)
	// 兼容 "Oct 22 2026 10:15:01"（华为/思科）与 "Oct 22 10:15:01 2026"（H3C）两种带年份写法
	reSyslog3164 = regexp.MustCompile(`^(?:<\d{1,3}>)?([A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\d{4}\b)?)\s+(\S+)\s+`)
	reSyslogPRI  = regexp.MustCompile(`^<\d{1,3}>\s*`)
	reSyslogTag  = regexp.MustCompile(`^([A-Za-z0-9_\-./]+)(?:\[\d+\])?:\s?`)
)

// headMatch 用只匹配头部的正则匹配 s，返回各捕获组与头部之后的正文；不匹配时返回 nil。
func headMatch(re *regexp.Regexp, s string) ([]string, string) {
	idx := re.FindStringSubmatchIndex(s)
	if idx == nil {
		return nil, ""
	}
	m := make([]string, len(idx)/2)
	for i := range m {
		if a, b := idx[2*i], idx[2*i+1]; a >= 0 {
			m[i] = s[a:b]
		}
	}
	return m, s[idx[1]:]
}

// match3164 是 reSyslog3164 的手写快速匹配：华为、H3C、思科等设备的报文头（"<190>Nov  9 2026 01:47:19 USG6630E "）
// 是数量最多的日志，正则匹配曾占防火墙日志处理的约 5%。只接受字段之间都是空格的规整写法，匹配结果与正则完全一致；
// 制表符、需要回溯才能确定的歧义写法等返回 ok=false，交给正则处理（对照测试见 TestStripSyslogMatchesReference）。
// p 是 PRI 之后的位置（没有 PRI 时为 0）。
func match3164(try bool, line string, p int) (ts, host, body string, ok bool) {
	if !try {
		return
	}
	n := len(line)
	if p > 0 && (p < 3 || p > 5 || !allDigits(line[1:p-1])) { // PRI 必须是 <1~3 位数字>
		return
	}
	digit := func(k int) bool { return k < n && line[k] >= '0' && line[k] <= '9' }
	spaces := func(k int) int {
		for k < n && line[k] == ' ' {
			k++
		}
		return k
	}
	i := p
	if i+3 > n || line[i] < 'A' || line[i] > 'Z' || line[i+1] < 'a' || line[i+1] > 'z' || line[i+2] < 'a' || line[i+2] > 'z' {
		return
	}
	start := i
	if i = spaces(i + 3); i == start+3 || !digit(i) { // 月份之后的空格与日期
		return
	}
	if i++; digit(i) {
		i++
	}
	if i >= n || line[i] != ' ' {
		return
	}
	i = spaces(i)
	if digit(i) && digit(i+1) && digit(i+2) && digit(i+3) && i+4 < n && line[i+4] == ' ' { // 华为 / 思科：日期后的年份
		i = spaces(i + 4)
	}
	if !(digit(i) && digit(i+1) && i+2 < n && line[i+2] == ':' && digit(i+3) && digit(i+4) && i+5 < n && line[i+5] == ':' && digit(i+6) && digit(i+7)) {
		return
	}
	i += 8
	if i < n && line[i] == '.' && digit(i+1) {
		for i++; digit(i); i++ {
		}
	}
	end := i
	if j := spaces(i); j > i && digit(j) && digit(j+1) && digit(j+2) && digit(j+3) && !wordByte(line, j+4) { // H3C：时间后的年份
		end, i = j+4, j+4
	}
	j := spaces(i)
	if j == i || j >= n || reSpace(line[j]) {
		return
	}
	hs := j
	for j < n && !reSpace(line[j]) {
		j++
	}
	if j >= n {
		return
	}
	he := j
	for j < n && reSpace(line[j]) {
		j++
	}
	return line[start:end], line[hs:he], line[j:], true
}

// reSpace 是正则 \s 匹配的字符（RE2：\t \n \f \r 与空格）。
func reSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' }

// wordByte 判断 s[k] 是否为正则 \b 意义上的单词字符（超出范围视为非单词字符）。
func wordByte(s string, k int) bool {
	if k >= len(s) {
		return false
	}
	c := s[k]
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// headMatchIf 在 ok 为真时才进行匹配。
func headMatchIf(ok bool, re *regexp.Regexp, s string) ([]string, string) {
	if !ok {
		return nil, ""
	}
	return headMatch(re, s)
}

// StripSyslog 识别并剥离 RFC3164 / RFC5424 / RFC3339 风格的 syslog 头。
func StripSyslog(line string) (string, SyslogHeader, bool) {
	var h SyslogHeader
	// 快速排除：syslog 行只可能以 "<PRI>"、月份缩写（大写字母）或 "YYYY-MM-DDT" 开头，
	// nginx 等以 IP 开头的日志无需进入正则匹配。
	if len(line) < 16 {
		return line, h, false
	}
	switch c := line[0]; {
	case c == '<', c >= 'A' && c <= 'Z':
	case c >= '0' && c <= '9' && line[4] == '-' && len(line) > 10 && line[10] == 'T':
	default:
		return line, h, false
	}
	// PRI 之后的第一个字符决定可能的格式（5424 为 "1 "，RFC3339 时间以数字开头，3164 以月份缩写开头），
	// 不可能匹配的正则不再尝试
	p := 0
	if line[0] == '<' {
		if j := strings.IndexByte(line[:min(len(line), 5)], '>'); j > 0 {
			p = j + 1
		}
	}
	c := line[p]
	if p > 0 && c == '1' && p+1 < len(line) && line[p+1] == ' ' {
		if m, body := headMatch(reSyslog5424, line); m != nil {
			h.Time, h.Host, h.Tag = ParseTime(m[1]), m[2], m[3]
			return body, h, true
		}
	}
	digit, upper := c >= '0' && c <= '9', c >= 'A' && c <= 'Z'
	var rest string
	if m, body := headMatchIf(digit, reSyslogISO, line); m != nil {
		h.Time, h.Host, rest = ParseTime(m[1]), m[2], body
	} else if ts, host, body, ok := match3164(upper, line, p); ok {
		h.Time, h.Host, rest = ParseTime(strings.Join(strings.Fields(ts), " ")), host, body
	} else if m, body := headMatchIf(upper, reSyslog3164, line); m != nil {
		h.Time, h.Host, rest = ParseTime(strings.Join(strings.Fields(m[1]), " ")), m[2], body
	} else if loc := reSyslogPRI.FindStringIndex(line); loc != nil {
		// 只有 PRI，没有时间头（FortiGate 等设备常见）
		return line[loc[1]:], h, true
	} else {
		return line, h, false
	}
	// 某些设备不发送主机名，此时 Host 实际上是 tag。
	if strings.HasSuffix(h.Host, ":") {
		h.Tag = strings.TrimSuffix(h.Host, ":")
		h.Host = ""
		return rest, h, true
	}
	if m, body := headMatch(reSyslogTag, rest); m != nil {
		h.Tag = m[1]
		rest = body
	}
	return rest, h, true
}
