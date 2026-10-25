package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	_ "time/tzdata" // 与主程序一致内嵌时区数据，测试不依赖本机 / GOROOT 的时区库
)

// 随项目发布的所有配置文件都必须能通过严格解析与校验。
func TestShippedConfigs(t *testing.T) {
	files, _ := filepath.Glob("../../configs/*.yaml")
	if len(files) == 0 {
		t.Fatal("未找到配置文件")
	}
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), "rules") {
			continue
		}
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(f, []byte("server:\n  listen: \":8080\"\n  lisen: \":9090\"\n"), 0o644)
	if _, err := Load(f); err == nil || !strings.Contains(err.Error(), "lisen") {
		t.Fatalf("拼写错误的配置项应报错: %v", err)
	}
}

func TestValidate(t *testing.T) {
	c := Default()
	c.Timezone = "Mars/Olympus"
	if c.Validate() == nil {
		t.Fatal("非法时区应报错")
	}
	c = Default()
	c.Server.Username = "admin"
	if c.Validate() == nil {
		t.Fatal("只设置用户名应报错")
	}
	c = Default()
	c.Sources = []SourceConfig{{Name: "a", Paths: []string{"x"}}, {Name: "a", Paths: []string{"y"}}}
	if c.Validate() == nil {
		t.Fatal("数据源重名应报错")
	}
	for _, cl := range []CustomLocation{{CIDR: "10.0.0.0/33", Name: "x"}, {CIDR: "10.0.0.0/8"}} {
		c = Default()
		c.Geo.Custom = []CustomLocation{cl}
		if c.Validate() == nil {
			t.Fatalf("非法自定义网段应报错: %+v", cl)
		}
	}
	c = Default()
	c.Geo.Custom = []CustomLocation{{CIDR: "10.0.0.0/8", Name: "办公网"}, {CIDR: "192.168.1.10", Name: "单个主机"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// 告警归档：默认永久保留，按年设置保留周期，旧的按月配置项不再接受。
func TestArchiveRetention(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) (*Config, error) {
		f := filepath.Join(dir, "c.yaml")
		os.WriteFile(f, []byte(body), 0o644)
		return Load(f)
	}
	c, err := load("archive:\n  dsn: postgres://u:p@127.0.0.1/db\n")
	if err != nil || c.Archive.RetentionYears != 0 || c.Archive.BatchSize != 1000 {
		t.Fatalf("默认应永久保留: %+v %v", c.Archive, err)
	}
	if c, err := load("archive:\n  retention_years: 3\n"); err != nil || c.Archive.RetentionYears != 3 {
		t.Fatalf("按年设置: %+v %v", c, err)
	}
	for _, bad := range []string{"archive:\n  retention_years: -1\n", "archive:\n  retention_years: 101\n", "archive:\n  retention_months: 6\n"} {
		if _, err := load(bad); err == nil {
			t.Errorf("应报错: %q", bad)
		}
	}
}

func TestReportTime(t *testing.T) {
	for v, ok := range map[string]bool{"09:00": true, "23:59": true, "off": true, "": true, "9am": false, "25:00": false} {
		c := Default()
		c.Alert.ReportTime = v
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("report_time %q: %v", v, err)
		}
	}
	if Default().Alert.ReportTime != "09:00" {
		t.Fatal("默认 09:00 推送日报")
	}
}
