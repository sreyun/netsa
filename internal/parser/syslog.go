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

var (
	reSyslog5424 = regexp.MustCompile(`^<\d{1,3}>1 (\S+) (\S+) (\S+) \S+ \S+ (?:-|(?:\[[^\]]*\])+) ?(.*)$`)
	reSyslogISO  = regexp.MustCompile(`^(?:<\d{1,3}>)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(.*)$`)
	// 兼容 "Oct 22 2026 10:15:01"（华为/思科）与 "Oct 22 10:15:01 2026"（H3C）两种带年份写法
	reSyslog3164 = regexp.MustCompile(`^(?:<\d{1,3}>)?([A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\d{4}\b)?)\s+(\S+)\s+(.*)$`)
	reSyslogPRI  = regexp.MustCompile(`^<\d{1,3}>\s*`)
	reSyslogTag  = regexp.MustCompile(`^([A-Za-z0-9_\-./]+)(?:\[\d+\])?:\s?(.*)$`)
)

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
	if m := reSyslog5424.FindStringSubmatch(line); m != nil {
		h.Time, h.Host, h.Tag = ParseTime(m[1]), m[2], m[3]
		return m[4], h, true
	}
	var rest string
	if m := reSyslogISO.FindStringSubmatch(line); m != nil {
		h.Time, h.Host, rest = ParseTime(m[1]), m[2], m[3]
	} else if m := reSyslog3164.FindStringSubmatch(line); m != nil {
		h.Time, h.Host, rest = ParseTime(strings.Join(strings.Fields(m[1]), " ")), m[2], m[3]
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
	if m := reSyslogTag.FindStringSubmatch(rest); m != nil {
		h.Tag = m[1]
		rest = m[2]
	}
	return rest, h, true
}
