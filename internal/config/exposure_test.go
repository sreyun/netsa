package config

import "testing"

func TestValidateIntranet(t *testing.T) {
	cfg := Default()
	cfg.Geo.Intranet = []string{"172.168.100.0/24", "172.168.200.0/24", "192.168.5.5"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法内网网段不应报错: %v", err)
	}
	cfg.Geo.Intranet = []string{"172.168.100.0/33"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("非法内网网段应报错")
	}
}

func TestValidateExposure(t *testing.T) {
	cfg := Default()
	cfg.Exposure = ExposureConfig{
		Enabled:      true,
		AllowedPorts: []int{80, 443},
		Services: []ExposureService{
			{PublicIP: "43.242.97.40", PublicPort: 1433, PrivateIP: "10.0.0.21", PrivatePort: 1433, Proto: "tcp", Name: "业务库"},
			{PublicPort: 2222, Proto: "any", Name: "任意地址高位端口"},
			{PublicIP: "43.242.97.41", Name: "整机放行"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法暴露面配置不应报错: %v", err)
	}

	cases := []struct {
		name string
		cfg  ExposureConfig
	}{
		{"端口越界", ExposureConfig{Services: []ExposureService{{PublicIP: "1.1.1.1", PublicPort: 70000}}}},
		{"协议不支持", ExposureConfig{Services: []ExposureService{{PublicIP: "1.1.1.1", PublicPort: 80, Proto: "sctp"}}}},
		{"公网地址非法", ExposureConfig{Services: []ExposureService{{PublicIP: "1.1.1.1/33", PublicPort: 80}}}},
		{"兜底端口越界", ExposureConfig{AllowedPorts: []int{0}}},
	}
	for _, c := range cases {
		cfg := Default()
		cfg.Exposure = c.cfg
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s 应报错", c.name)
		}
	}
}
