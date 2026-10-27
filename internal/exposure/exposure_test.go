package exposure

import (
	"testing"

	"netsa/internal/config"
)

func TestDisabledKeepsEverything(t *testing.T) {
	m, err := Load(config.ExposureConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Enforcing() {
		t.Fatal("默认应关闭")
	}
	if _, ok := m.Lookup("43.242.97.40", 1433, "tcp"); !ok {
		t.Fatal("未启用时应视为已发布")
	}
}

func TestLookup(t *testing.T) {
	m, err := Load(config.ExposureConfig{
		Enabled:      true,
		AllowedPorts: []int{8443},
		Services: []config.ExposureService{
			{PublicIP: "43.242.97.40", PublicPort: 443, Proto: "tcp", Name: "官网"},
			{PublicIP: "43.242.97.40", PublicPort: 53, Proto: "udp", Name: "DNS"},
			{PublicIP: "43.242.97.41", Name: "整机放行"},
			{PublicPort: 2222, Proto: "tcp", Name: "任意地址 SSH 高位端口"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip    string
		port  int
		proto string
		want  bool
	}{
		{"43.242.97.40", 443, "tcp", true},  // 精确映射
		{"43.242.97.40", 443, "udp", false}, // 协议不匹配
		{"43.242.97.40", 53, "udp", true},
		{"43.242.97.40", 1433, "tcp", false}, // 未映射
		{"43.242.97.41", 1433, "tcp", true},  // 整机放行
		{"203.0.113.9", 2222, "tcp", true},   // 不分地址的端口
		{"203.0.113.9", 8443, "tcp", true},   // 兜底白名单
		{"203.0.113.9", 6379, "tcp", false},
		{"43.242.97.40", 0, "tcp", true}, // 端口未知：交给调用方判断
	}
	for _, c := range cases {
		if _, got := m.Lookup(c.ip, c.port, c.proto); got != c.want {
			t.Fatalf("Lookup(%s,%d,%s)=%v, want %v", c.ip, c.port, c.proto, got, c.want)
		}
	}
}

func TestInvalidService(t *testing.T) {
	if _, err := Load(config.ExposureConfig{Enabled: true, Services: []config.ExposureService{{Name: "空映射"}}}); err == nil {
		t.Fatal("既没有公网地址也没有端口时应报错")
	}
}

func TestMutedCounter(t *testing.T) {
	var m *Manager
	if m.Muted() != 0 {
		t.Fatal("nil Manager 应返回 0")
	}
	m.AddMuted() // nil 安全
	mm, _ := Load(config.ExposureConfig{Enabled: true})
	mm.AddMuted()
	if mm.Muted() != 1 {
		t.Fatalf("计数不符: %d", mm.Muted())
	}
}
