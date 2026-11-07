package parser

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Location 是日志中不带时区的时间（syslog、Windows 防火墙、FortiGate 等）所使用的时区，
// 由配置项 timezone 设置；容器内默认 UTC，务必与日志产生方保持一致。
var Location = time.Local

var timeLayouts = []string{
	"02/Jan/2006:15:04:05 -0700", // nginx $time_local
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999 -0700",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
	"Jan _2 2006 15:04:05",
	"Jan _2 15:04:05 2006",
	"Jan _2 15:04:05.999999",
	"Jan _2 15:04:05",
	"02/01/2006:15:04:05",
	"01/02-15:04:05", // Snort fast 告警（无年份）
	"01/02/06-15:04:05",
	"2006/01/02 15:04:05.000",
	time.ANSIC,                          // ModSecurity v3 审计日志 time_stamp
	"02/Jan/2006:15:04:05.999999 -0700", // ModSecurity v2 审计日志
}

// ParseTime 尝试多种常见日志时间格式，失败返回零值。
func ParseTime(s string) time.Time {
	s = strings.TrimSpace(strings.Trim(s, "[]\""))
	if s == "" || s == "-" {
		return time.Time{}
	}
	// nginx $msec / Unix 时间戳
	if c := s[0]; c >= '0' && c <= '9' && !strings.ContainsAny(s, "-/: ") {
		if f, err := strconv.ParseFloat(s, 64); err == nil && f > 1e8 {
			if f > 1e12 { // 毫秒
				f /= 1000
			}
			sec := int64(f)
			return time.Unix(sec, int64((f-float64(sec))*1e9))
		}
	}
	loc := Location
	if loc == nil {
		loc = time.Local
	}
	// 按首字符只试同一类格式，并先试上一次成功的格式：同一数据源的时间格式不变，每次失败的尝试都会分配错误对象。
	// 能匹配同一字符串的几种格式解析出的时间相同，尝试顺序不影响结果
	layouts, hint := digitLayouts, &digitHint
	if c := s[0]; c < '0' || c > '9' {
		layouts, hint = alphaLayouts, &alphaHint
	}
	h := int(hint.Load())
	if h < len(layouts) {
		if t, err := time.ParseInLocation(layouts[h], s, loc); err == nil {
			return withYear(t, loc)
		}
	}
	for i, layout := range layouts {
		if i == h {
			continue
		}
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			hint.Store(int32(i))
			return withYear(t, loc)
		}
	}
	return time.Time{}
}

// withYear 给没有年份的 syslog 时间补上年份（跨年时不超过当前时间 48 小时）。
func withYear(t time.Time, loc *time.Location) time.Time {
	if t.Year() != 0 {
		return t
	}
	now := time.Now().In(loc)
	t = t.AddDate(now.Year(), 0, 0)
	if t.After(now.Add(48 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

// digitLayouts / alphaLayouts 是按首字符（数字 / 字母）分开的时间格式；*Hint 是上一次成功的下标。
var (
	digitLayouts, alphaLayouts []string
	digitHint, alphaHint       atomic.Int32
)

func init() {
	for _, l := range timeLayouts {
		if l[0] >= '0' && l[0] <= '9' {
			digitLayouts = append(digitLayouts, l)
		} else {
			alphaLayouts = append(alphaLayouts, l)
		}
	}
}
