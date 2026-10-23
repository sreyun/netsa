// Package config 负责加载 YAML 配置并填充默认值。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Timezone 是不带时区信息的日志时间所采用的时区，例如 Asia/Shanghai；为空使用系统时区（容器内通常为 UTC）。
	Timezone string         `yaml:"timezone"`
	Server   ServerConfig   `yaml:"server"`
	Home     HomeConfig     `yaml:"home"`
	Sources  []SourceConfig `yaml:"sources"`
	Syslog   SyslogConfig   `yaml:"syslog"`
	RealIP   RealIPConfig   `yaml:"real_ip"`
	Geo      GeoConfig      `yaml:"geo"`
	Intel    IntelConfig    `yaml:"intel"`
	Detect   DetectConfig   `yaml:"detect"`
	Alert    AlertConfig    `yaml:"alert"`
	Storage  StorageConfig  `yaml:"storage"`
}

type ServerConfig struct {
	Listen   string `yaml:"listen"`
	Username string `yaml:"username"` // 非空时启用 HTTP Basic 认证
	Password string `yaml:"password"`
	// WebDir 非空时从该目录加载前端页面（便于定制界面），否则使用内嵌资源
	WebDir string `yaml:"web_dir"`
}

// HomeConfig 是被保护资产所在位置，用于在地图上绘制攻击连线。
type HomeConfig struct {
	Name string  `yaml:"name" json:"name"`
	Lat  float64 `yaml:"lat" json:"lat"`
	Lon  float64 `yaml:"lon" json:"lon"`
}

type SourceConfig struct {
	Name          string   `yaml:"name"`
	Type          string   `yaml:"type"` // auto | nginx | firewall | 具体解析器名
	Paths         []string `yaml:"paths"`
	FromBeginning bool     `yaml:"from_beginning"`
	LogFormat     string   `yaml:"log_format"` // 自定义 nginx log_format
	Host          string   `yaml:"host"`       // 日志中没有 $host 时使用的站点名
}

type SyslogConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	UDP     string `yaml:"udp" json:"udp"`
	TCP     string `yaml:"tcp" json:"tcp"`
}

type RealIPConfig struct {
	// Header: x_forwarded_for | x_real_ip | none（兼容旧配置；设置 Headers 时以 Headers 为准）
	Header string `yaml:"header"`
	// Headers 按优先级依次尝试的客户端地址头：cf_connecting_ip / true_client_ip / ali_cdn_real_ip /
	// x_client_ip / x_real_ip / x_forwarded_for / forwarded（RFC 7239）
	Headers        []string `yaml:"headers"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	// TrustedPresets 内置的可信代理网段，例如 cloudflare
	TrustedPresets []string `yaml:"trusted_presets"`
	// CDNOnly 表示站点只应通过 CDN/负载均衡访问：来自非可信代理的公网直连会被标记为“绕过 CDN 直连源站”
	CDNOnly bool `yaml:"cdn_only"`
}

type GeoConfig struct {
	IP2RegionV4 string       `yaml:"ip2region_v4"`
	IP2RegionV6 string       `yaml:"ip2region_v6"`
	MaxMindCity string       `yaml:"maxmind_city"`
	MaxMindASN  string       `yaml:"maxmind_asn"`
	Online      OnlineConfig `yaml:"online"`
	ReverseDNS  bool         `yaml:"reverse_dns"`
	CacheSize   int          `yaml:"cache_size"`
	EnrichLevel string       `yaml:"enrich_level"` // 达到该威胁等级的 IP 才做在线/rDNS 深度溯源
	// ReloadInterval 定期检查离线定位库文件是否更新（替换 xdb / mmdb 后无需重启），0 表示关闭
	ReloadInterval time.Duration `yaml:"reload_interval"`
	// Custom 自定义网段位置：内网办公区、分支机构、合作方出口等，优先级高于所有定位库
	Custom []CustomLocation `yaml:"custom"`
}

// CustomLocation 是一个自定义网段的位置信息；未填写经纬度时按省市名称换算区划中心。
type CustomLocation struct {
	CIDR        string  `yaml:"cidr"`
	Name        string  `yaml:"name"` // 网段名称，如“北京总部办公网”
	Country     string  `yaml:"country"`
	CountryCode string  `yaml:"country_code"`
	Province    string  `yaml:"province"`
	City        string  `yaml:"city"`
	ISP         string  `yaml:"isp"`
	Lat         float64 `yaml:"lat"`
	Lon         float64 `yaml:"lon"`
}

type OnlineConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"` // ip-api 兼容的批量接口
	Lang    string `yaml:"lang"`
	RDAP    bool   `yaml:"rdap"` // 允许在 IP 详情中按需查询 RDAP/WHOIS
}

type IntelConfig struct {
	Blocklists []BlocklistConfig `yaml:"blocklists"`
	TorExitURL string            `yaml:"tor_exit_url"` // 为空则不拉取
}

type BlocklistConfig struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

type DetectConfig struct {
	RulesFile       string     `yaml:"rules_file"`
	Whitelist       []string   `yaml:"whitelist"`
	SuccessMinBytes int64      `yaml:"success_min_bytes"`
	AlertsPerRule   int        `yaml:"alerts_per_rule"` // 同一 IP 同一规则在节流窗口内最多生成的告警数
	Thresholds      Thresholds `yaml:"thresholds"`
}

type Thresholds struct {
	WebWindow     time.Duration `yaml:"web_window"`
	CCRequests    int           `yaml:"cc_requests"`
	Scan404       int           `yaml:"scan_404"`
	ScanPaths     int           `yaml:"scan_paths"`
	BruteLogin    int           `yaml:"brute_login"`
	Server5xx     int           `yaml:"server_5xx"`
	FwWindow      time.Duration `yaml:"fw_window"`
	PortScanPorts int           `yaml:"port_scan_ports"`
	HostSweep     int           `yaml:"host_sweep"`
	BruteConns    int           `yaml:"brute_conns"`
	FloodEvents   int           `yaml:"flood_events"`
}

type AlertConfig struct {
	Webhooks []WebhookConfig `yaml:"webhooks"`
}

type WebhookConfig struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	Type        string `yaml:"type"` // generic | dingtalk | wecom | feishu
	MinSeverity string `yaml:"min_severity"`
}

type StorageConfig struct {
	Snapshot  string        `yaml:"snapshot"`
	Interval  time.Duration `yaml:"interval"`
	MaxIPs    int           `yaml:"max_ips"`
	MaxAlerts int           `yaml:"max_alerts"`
	Retention time.Duration `yaml:"retention"` // 时间序列保留时长
}

// Default 返回带默认值的配置。
func Default() *Config {
	return &Config{
		Server: ServerConfig{Listen: ":8080"},
		Home:   HomeConfig{Name: "数据中心", Lat: 31.23, Lon: 121.47},
		Syslog: SyslogConfig{UDP: ":5514", TCP: ":5514"},
		RealIP: RealIPConfig{
			Header: "x_forwarded_for",
			TrustedProxies: []string{
				"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
			},
		},
		Geo: GeoConfig{
			IP2RegionV4:    "data/ip2region_v4.xdb",
			IP2RegionV6:    "data/ip2region_v6.xdb",
			MaxMindCity:    "data/GeoLite2-City.mmdb",
			MaxMindASN:     "data/GeoLite2-ASN.mmdb",
			CacheSize:      200000,
			ReloadInterval: 10 * time.Minute,
			EnrichLevel:    "low",
			ReverseDNS:     true,
			Online: OnlineConfig{
				URL:  "http://ip-api.com/batch",
				Lang: "zh-CN",
				RDAP: true,
			},
		},
		Detect: DetectConfig{
			SuccessMinBytes: 1,
			AlertsPerRule:   5,
			Thresholds: Thresholds{
				WebWindow:     time.Minute,
				CCRequests:    600,
				Scan404:       40,
				ScanPaths:     30,
				BruteLogin:    15,
				Server5xx:     30,
				FwWindow:      5 * time.Minute,
				PortScanPorts: 20,
				HostSweep:     20,
				BruteConns:    30,
				FloodEvents:   5000,
			},
		},
		Storage: StorageConfig{
			Interval:  time.Minute,
			MaxIPs:    200000,
			MaxAlerts: 20000,
			Retention: 7 * 24 * time.Hour,
		},
	}
}

// Load 读取配置文件；path 为空时返回默认配置。
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true) // 拼写错误的配置项直接报错，避免静默失效
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("解析配置 %s 失败: %w", path, err)
	}
	cfg.fill()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置 %s 无效: %w", path, err)
	}
	return cfg, nil
}

// Location 返回日志时区。
func (c *Config) Location() (*time.Location, error) {
	if c.Timezone == "" {
		return time.Local, nil
	}
	return time.LoadLocation(c.Timezone)
}

// Validate 检查配置的合法性。
func (c *Config) Validate() error {
	if _, err := c.Location(); err != nil {
		return fmt.Errorf("timezone %q 无效: %w", c.Timezone, err)
	}
	for i, cl := range c.Geo.Custom {
		if _, err := netip.ParsePrefix(strings.TrimSpace(cl.CIDR)); err != nil {
			if _, err2 := netip.ParseAddr(strings.TrimSpace(cl.CIDR)); err2 != nil {
				return fmt.Errorf("geo.custom[%d] 的 cidr %q 无效", i, cl.CIDR)
			}
		}
		if cl.Name == "" {
			return fmt.Errorf("geo.custom[%d] 缺少 name", i)
		}
	}
	if c.Home.Lat < -90 || c.Home.Lat > 90 || c.Home.Lon < -180 || c.Home.Lon > 180 {
		return fmt.Errorf("home 经纬度超出范围")
	}
	if (c.Server.Username == "") != (c.Server.Password == "") {
		return fmt.Errorf("server.username 与 server.password 需同时设置")
	}
	names := map[string]bool{}
	for i, s := range c.Sources {
		if len(s.Paths) == 0 {
			return fmt.Errorf("sources[%d] 未配置 paths", i)
		}
		if names[s.Name] {
			return fmt.Errorf("数据源名称重复: %s", s.Name)
		}
		names[s.Name] = true
	}
	switch c.RealIP.Header {
	case "", "x_forwarded_for", "x_real_ip", "none":
	default:
		return fmt.Errorf("real_ip.header 只能是 x_forwarded_for / x_real_ip / none")
	}
	for _, h := range c.RealIP.Headers {
		switch strings.ToLower(strings.ReplaceAll(h, "-", "_")) {
		case "cf_connecting_ip", "true_client_ip", "ali_cdn_real_ip", "x_client_ip", "x_real_ip", "x_forwarded_for", "forwarded":
		default:
			return fmt.Errorf("real_ip.headers 不支持 %q", h)
		}
	}
	for _, p := range c.RealIP.TrustedPresets {
		if strings.ToLower(p) != "cloudflare" {
			return fmt.Errorf("real_ip.trusted_presets 不支持 %q（可选: cloudflare）", p)
		}
	}
	for _, w := range c.Alert.Webhooks {
		switch strings.ToLower(w.Type) {
		case "", "generic", "dingtalk", "wecom", "wechat", "feishu", "lark":
		default:
			return fmt.Errorf("webhook %s 的 type 不支持: %s", w.Name, w.Type)
		}
	}
	return nil
}

// fill 为 YAML 中显式置零的关键字段补默认值，避免出现 0 阈值。
func (c *Config) fill() {
	d := Default()
	t, dt := &c.Detect.Thresholds, d.Detect.Thresholds
	if t.WebWindow <= 0 {
		t.WebWindow = dt.WebWindow
	}
	if t.FwWindow <= 0 {
		t.FwWindow = dt.FwWindow
	}
	for _, p := range []struct {
		v   *int
		def int
	}{
		{&t.CCRequests, dt.CCRequests}, {&t.Scan404, dt.Scan404}, {&t.ScanPaths, dt.ScanPaths},
		{&t.BruteLogin, dt.BruteLogin}, {&t.Server5xx, dt.Server5xx}, {&t.PortScanPorts, dt.PortScanPorts},
		{&t.HostSweep, dt.HostSweep}, {&t.BruteConns, dt.BruteConns}, {&t.FloodEvents, dt.FloodEvents},
		{&c.Detect.AlertsPerRule, d.Detect.AlertsPerRule},
		{&c.Storage.MaxIPs, d.Storage.MaxIPs}, {&c.Storage.MaxAlerts, d.Storage.MaxAlerts},
		{&c.Geo.CacheSize, d.Geo.CacheSize},
	} {
		if *p.v <= 0 {
			*p.v = p.def
		}
	}
	if c.Storage.Interval <= 0 {
		c.Storage.Interval = d.Storage.Interval
	}
	if c.Storage.Retention <= 0 {
		c.Storage.Retention = d.Storage.Retention
	}
	if c.Geo.Online.URL == "" {
		c.Geo.Online.URL = d.Geo.Online.URL
	}
	if c.Geo.Online.Lang == "" {
		c.Geo.Online.Lang = d.Geo.Online.Lang
	}
	if c.Server.Listen == "" {
		c.Server.Listen = d.Server.Listen
	}
	for i := range c.Sources {
		if c.Sources[i].Type == "" {
			c.Sources[i].Type = "auto"
		}
		if c.Sources[i].Name == "" && len(c.Sources[i].Paths) > 0 {
			c.Sources[i].Name = c.Sources[i].Paths[0]
		}
	}
}
