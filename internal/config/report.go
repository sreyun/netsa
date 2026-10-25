package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ReportConfig 是周报 / 月报的定时邮件发送。报告也可随时在界面中查看、打印为 PDF。
type ReportConfig struct {
	Recipients []string `yaml:"recipients"` // 收件人
	// Weekly 为周报发送时间，例如 "mon 09:00"（每周一 9 点，发送上一自然周）；Monthly 例如 "1 09:00"（每月 1 日，发送上月）；off 关闭
	Weekly  string     `yaml:"weekly"`
	Monthly string     `yaml:"monthly"`
	SMTP    SMTPConfig `yaml:"smtp"`
}

// SMTPConfig 是发信服务器。密码也可通过环境变量 NETSA_SMTP_PASSWORD 提供。
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	TLS      string `yaml:"tls"` // ssl / starttls / none；为空时 465 端口为 ssl，其余为 starttls
	Insecure bool   `yaml:"insecure_skip_verify"`
}

var weekdays = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday, "thu": time.Thursday,
	"fri": time.Friday, "sat": time.Saturday, "周日": time.Sunday, "周一": time.Monday, "周二": time.Tuesday, "周三": time.Wednesday, "周四": time.Thursday,
	"周五": time.Friday, "周六": time.Saturday}

// ParseWeekly 解析周报发送时间（如 "mon 09:00"），off 或空返回 ok=false。
func ParseWeekly(s string) (day time.Weekday, hm string, ok bool, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "off" {
		return 0, "", false, nil
	}
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, "", false, fmt.Errorf("report.weekly 格式应为“星期 HH:MM”，例如 mon 09:00: %q", s)
	}
	d, known := weekdays[f[0]]
	if !known {
		return 0, "", false, fmt.Errorf("report.weekly 的星期无效（mon ~ sun 或 周一 ~ 周日）: %q", s)
	}
	if _, err := time.Parse("15:04", f[1]); err != nil {
		return 0, "", false, fmt.Errorf("report.weekly 时间格式应为 HH:MM: %q", s)
	}
	return d, f[1], true, nil
}

// ParseMonthly 解析月报发送时间（如 "1 09:00"，日期为 1 ~ 28），off 或空返回 ok=false。
func ParseMonthly(s string) (day int, hm string, ok bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "off" {
		return 0, "", false, nil
	}
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, "", false, fmt.Errorf("report.monthly 格式应为“日期 HH:MM”，例如 1 09:00: %q", s)
	}
	d, err := strconv.Atoi(f[0])
	if err != nil || d < 1 || d > 28 {
		return 0, "", false, fmt.Errorf("report.monthly 的日期应为 1 ~ 28: %q", s)
	}
	if _, err := time.Parse("15:04", f[1]); err != nil {
		return 0, "", false, fmt.Errorf("report.monthly 时间格式应为 HH:MM: %q", s)
	}
	return d, f[1], true, nil
}

func (c *Config) validateReport() error {
	if _, _, _, err := ParseWeekly(c.Report.Weekly); err != nil {
		return err
	}
	if _, _, _, err := ParseMonthly(c.Report.Monthly); err != nil {
		return err
	}
	switch c.Report.SMTP.TLS {
	case "", "ssl", "starttls", "none":
	default:
		return fmt.Errorf("report.smtp.tls 只能为 ssl / starttls / none")
	}
	if c.Report.SMTP.Port < 0 || c.Report.SMTP.Port > 65535 {
		return fmt.Errorf("report.smtp.port 无效")
	}
	return nil
}
