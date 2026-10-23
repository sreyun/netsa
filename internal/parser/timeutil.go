package parser

import (
	"strconv"
	"strings"
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
	for _, layout := range timeLayouts {
		t, err := time.ParseInLocation(layout, s, Location)
		if err != nil {
			continue
		}
		if t.Year() == 0 { // syslog 时间没有年份
			now := time.Now().In(Location)
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(48 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
		}
		return t
	}
	return time.Time{}
}
