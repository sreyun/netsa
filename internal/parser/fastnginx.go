package parser

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// fastCombined 以逐字节扫描的方式解析 combined / main 格式，速度约为正则的 5~10 倍；
// 任何不符合预期的情况都返回 false，由正则解析兜底，保证兼容性不下降。
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" ["$http_x_forwarded_for"] ...
type combinedFields struct {
	ip, tm, req, status, bytes, ref, ua, xff string
}

func fastCombined(line string) (f combinedFields, ok bool) {
	i := strings.IndexByte(line, ' ')
	if i <= 0 {
		return f, false
	}
	f.ip = line[:i]
	rest := line[i+1:]
	// ident 与 user
	for k := 0; k < 2; k++ {
		j := strings.IndexByte(rest, ' ')
		if j < 0 {
			return f, false
		}
		rest = rest[j+1:]
	}
	if len(rest) < 2 || rest[0] != '[' {
		return f, false
	}
	j := strings.IndexByte(rest, ']')
	if j < 0 {
		return f, false
	}
	f.tm = rest[1:j]
	rest = rest[j+1:]
	if !strings.HasPrefix(rest, ` "`) {
		return f, false
	}
	var q string
	if q, rest, ok = quoted(rest[1:]); !ok {
		return f, false
	}
	f.req = q
	// 状态码与字节数
	if len(rest) < 5 || rest[0] != ' ' {
		return f, false
	}
	f.status = rest[1:4]
	if f.status[0] < '1' || f.status[0] > '5' || rest[4] != ' ' {
		return f, false
	}
	rest = rest[5:]
	j = strings.IndexByte(rest, ' ')
	if j < 0 {
		f.bytes, rest = rest, ""
	} else {
		f.bytes, rest = rest[:j], rest[j:]
	}
	// 可选的 referer、UA、XFF
	if strings.HasPrefix(rest, ` "`) {
		if f.ref, rest, ok = quoted(rest[1:]); !ok {
			return f, false
		}
		if !strings.HasPrefix(rest, ` "`) {
			return f, false
		}
		if f.ua, rest, ok = quoted(rest[1:]); !ok {
			return f, false
		}
		if strings.HasPrefix(rest, ` "`) {
			if f.xff, _, ok = quoted(rest[1:]); !ok {
				return f, false
			}
		}
	}
	return f, true
}

// quoted 读取以双引号开头的字段，支持反斜杠转义，返回内容与剩余部分。
func quoted(s string) (string, string, bool) {
	if len(s) == 0 || s[0] != '"' {
		return "", s, false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return s[1:i], s[i+1:], true
		}
	}
	return "", s, false
}

var months = map[string]time.Month{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

var zoneCache sync.Map // 偏移秒数 → *time.Location

// parseNginxTime 快速解析 "02/Jan/2006:15:04:05 -0700"，格式不符时回退通用解析。
func parseNginxTime(s string) time.Time {
	if len(s) != 26 || s[2] != '/' || s[6] != '/' || s[11] != ':' || s[20] != ' ' {
		return ParseTime(s)
	}
	num := func(a, b int) (int, bool) {
		n, err := strconv.Atoi(s[a:b])
		return n, err == nil
	}
	day, ok1 := num(0, 2)
	mon, ok2 := months[s[3:6]]
	year, ok3 := num(7, 11)
	hh, ok4 := num(12, 14)
	mm, ok5 := num(15, 17)
	ss, ok6 := num(18, 20)
	tzh, ok7 := num(22, 24)
	tzm, ok8 := num(24, 26)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8) || (s[21] != '+' && s[21] != '-') {
		return ParseTime(s)
	}
	off := (tzh*60 + tzm) * 60
	if s[21] == '-' {
		off = -off
	}
	loc, okz := zoneCache.Load(off)
	if !okz {
		loc, _ = zoneCache.LoadOrStore(off, time.FixedZone("", off))
	}
	return time.Date(year, mon, day, hh, mm, ss, 0, loc.(*time.Location))
}
