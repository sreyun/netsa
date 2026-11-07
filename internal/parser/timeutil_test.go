package parser

import (
	"testing"
	"time"
)

// 各种日志时间格式交替出现（多个数据源）：结果与格式顺序、上一次成功的格式无关。
func TestParseTimeFormats(t *testing.T) {
	old := Location
	Location = time.UTC
	defer func() { Location = old }()
	want := time.Date(2026, 11, 7, 15, 9, 43, 0, time.UTC)
	cases := []string{
		"07/Nov/2026:15:09:43 +0000",
		"2026-11-07T15:09:43Z",
		"2026-11-07T15:09:43.000Z",
		"2026-11-07T15:09:43",
		"2026-11-07 15:09:43 +0000",
		"2026-11-07 15:09:43",
		"2026/11/07 15:09:43",
		"Nov  7 2026 15:09:43",
		"Nov  7 15:09:43 2026",
		"07/11/2026:15:09:43",
		"11/07/26-15:09:43",
		"2026/11/07 15:09:43.000",
		"Sat Nov  7 15:09:43 2026",
		"07/Nov/2026:15:09:43.000000 +0000",
		"[07/Nov/2026:15:09:43 +0000]",
		"1794064183",
	}
	for round := range 3 { // 多轮交替，覆盖“先试上一次成功的格式”的各种状态
		for i, c := range cases {
			if round == 1 {
				c = cases[len(cases)-1-i]
			}
			if got := ParseTime(c); !got.Equal(want) {
				t.Errorf("ParseTime(%q) = %v, want %v", c, got, want)
			}
		}
	}
	// 没有年份的 syslog 时间补上年份，且不在未来
	if got := ParseTime("Jan  1 00:00:01"); got.IsZero() || got.After(time.Now().Add(48*time.Hour)) {
		t.Errorf("syslog 时间: %v", got)
	}
	for _, bad := range []string{"", "-", "not a time", "2026-13-45"} {
		if got := ParseTime(bad); !got.IsZero() {
			t.Errorf("ParseTime(%q) 应失败: %v", bad, got)
		}
	}
	// 同一格式连续出现时不再逐个尝试其他格式（不分配错误对象）
	ParseTime("Nov  7 2026 15:09:43")
	if n := testing.AllocsPerRun(50, func() { ParseTime("Nov  7 2026 15:09:43") }); n > 0 {
		t.Errorf("命中上一次的格式不应分配: %v", n)
	}
}
