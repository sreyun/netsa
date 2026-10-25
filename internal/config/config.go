// Package config 负责加载 YAML 配置并填充默认值。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Timezone 是不带时区信息的日志时间所采用的时区，例如 Asia/Shanghai；为空使用系统时区（容器内通常为 UTC）。
	Timezone string `yaml:"timezone"`
	// TimeCorrection 为 auto（默认）时，自动识别实时日志与实际时间之间的整时区偏差并校正（例如日志按 UTC 记录、
	// 却按 timezone 解析导致时间慢 8 小时）；off 关闭。
	TimeCorrection string         `yaml:"time_correction"`
	Server         ServerConfig   `yaml:"server"`
	Home           HomeConfig     `yaml:"home"`
	Sources        []SourceConfig `yaml:"sources"`
	Syslog         SyslogConfig   `yaml:"syslog"`
	RealIP         RealIPConfig   `yaml:"real_ip"`
	Geo            GeoConfig      `yaml:"geo"`
	Intel          IntelConfig    `yaml:"intel"`
	Detect         DetectConfig   `yaml:"detect"`
	Alert          AlertConfig    `yaml:"alert"`
	Archive        ArchiveConfig  `yaml:"archive"`
	RawLog         RawLogConfig   `yaml:"rawlog"`
	Audit          AuditConfig    `yaml:"audit"`
	Report         ReportConfig   `yaml:"report"`
	Storage        StorageConfig  `yaml:"storage"`
}

type ServerConfig struct {
	Listen string `yaml:"listen"`
	// Auth 登录认证，默认开启。仅在可信内网、或由前置统一认证网关负责认证时设为 false。
	Auth *bool `yaml:"auth"`
	// Username / Password 配置文件中的管理员账号（可选，只读）。password 可以是明文，
	// 也可以是 `netsa hash-password` 生成的哈希（推荐）。未配置时首次启动自动创建 admin 并在日志中输出初始密码。
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// UsersFile 账号文件（密码哈希、会话签名密钥、登录审计），为空时放在 storage.snapshot 所在目录（users.json）
	UsersFile string `yaml:"users_file"`
	// SessionTTL 登录有效期，期间有访问会自动续期（默认 12h）；自登录起最长 30 天
	SessionTTL time.Duration `yaml:"session_ttl"`
	// TLSCert / TLSKey 设置后直接以 HTTPS 提供服务（公网部署建议开启，或置于 HTTPS 反向代理之后）
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// WebDir 非空时从该目录加载前端页面（便于定制界面），否则使用内嵌资源
	WebDir string `yaml:"web_dir"`
	// AllowNetworks 允许访问大屏与 API 的来源网段（IP 或 CIDR）；为空表示不限制。本机回环地址始终允许，
	// /healthz 不受限制。部署在反向代理之后时需同时配置 real_ip.trusted_proxies，按真实客户端地址判断。
	AllowNetworks []string `yaml:"allow_networks"`
	// Require2FA 要求所有本地账号启用双因素认证（TOTP）：未启用的账号登录后须先绑定身份验证器
	Require2FA bool `yaml:"require_2fa"`
}

// AuthEnabled 返回是否需要登录（默认开启）。
func (s ServerConfig) AuthEnabled() bool { return s.Auth == nil || *s.Auth }

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
	// Silence 为断流告警阈值：实时日志超过该时间没有新内容时推送告警，例如 10m；off 关闭；为空使用 alert.source_silence
	Silence string `yaml:"silence"`
}

type SyslogConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	UDP     string `yaml:"udp" json:"udp"`
	TCP     string `yaml:"tcp" json:"tcp"`
	// TLS 为 syslog over TLS（RFC 5425，通常 :6514）监听地址；需同时配置 tls_cert / tls_key。
	// 配置 tls_client_ca 时要求发送端出示该 CA 签发的客户端证书（双向认证），防止伪造发送端。
	TLS         string `yaml:"tls" json:"tls"`
	TLSCert     string `yaml:"tls_cert" json:"-"`
	TLSKey      string `yaml:"tls_key" json:"-"`
	TLSClientCA string `yaml:"tls_client_ca" json:"-"`
	// Allowlist 开启发送端白名单：只接收已登记（允许）的发送端的日志。也可在界面中开启；配置为 true 时界面中不能关闭。
	Allowlist bool `yaml:"allowlist" json:"allowlist"`
	// Senders 是配置文件中登记的发送端（界面中只读展示），可按 IP 或网段登记名称、分组与断流告警阈值。
	Senders []SyslogSender `yaml:"senders" json:"-"`
	// RateLimit 为单个发送端每秒最多接收的日志条数（0 不限制），防止异常设备或伪造流量挤占处理能力。
	RateLimit int `yaml:"rate_limit" json:"rate_limit"`
	// SendersFile 保存界面登记的发送端与发送端统计，默认与状态快照放在同一目录（syslog-senders.json）。
	SendersFile string `yaml:"senders_file" json:"-"`
}

// SyslogSender 是一个登记的 syslog 发送端（设备）。
type SyslogSender struct {
	CIDR    string `yaml:"cidr"`    // IP 或网段
	Name    string `yaml:"name"`    // 设备名称，例如“核心防火墙”
	Group   string `yaml:"group"`   // 分组，例如“防火墙”“WAF”“服务器”
	Action  string `yaml:"action"`  // allow（默认）/ block
	Silence string `yaml:"silence"` // 断流告警阈值，例如 10m；off 关闭；为空使用 alert.source_silence
	Note    string `yaml:"note"`
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
	// 分布式暴力破解（撞库）：窗口内同一登录接口的失败登录次数与来源数同时达到阈值
	DistWindow      time.Duration `yaml:"dist_window"`
	DistBruteLogins int           `yaml:"dist_brute_logins"`
	DistBruteIPs    int           `yaml:"dist_brute_ips"`
	// 接口遍历 / 批量爬取：窗口内同一来源对同一接口请求的不同 ID 数达到阈值
	EnumWindow time.Duration `yaml:"enum_window"`
	EnumIDs    int           `yaml:"enum_ids"`
	// 周期性外连（疑似 C2 心跳）：内网主机按固定间隔连接同一外部地址的次数达到阈值
	BeaconConns int `yaml:"beacon_conns"`
	// 主机认证日志（SSH / RDP / VPN …）：窗口（fw_window）内同一来源登录失败次数、尝试的不同账号数达到阈值
	AuthFailures int `yaml:"auth_failures"`
	AuthUsers    int `yaml:"auth_users"`
	// DNS：窗口（fw_window）内同一主机的 NXDOMAIN 查询数、向同一主域名查询的不同子域名数达到阈值
	DNSNXDomain   int `yaml:"dns_nxdomain"`
	DNSSubdomains int `yaml:"dns_subdomains"`
}

type AlertConfig struct {
	// BaseURL 为大屏的访问地址（如 http://10.0.0.5:8080），设置后告警消息附带“查看溯源详情”链接
	BaseURL string `yaml:"base_url"`
	// DedupWindow 同一 IP、同一规则、同一研判结果的告警在该时间内只推送一次
	DedupWindow time.Duration `yaml:"dedup_window"`
	// RobotsFile 保存在界面中添加的机器人；为空时放在 storage.snapshot 所在目录（alert-robots.json）
	RobotsFile string          `yaml:"robots_file"`
	Webhooks   []WebhookConfig `yaml:"webhooks"`
	// ReportTime 每日安全日报的推送时间（HH:MM，按 timezone），推送给勾选了“接收日报”的机器人；off 表示关闭
	ReportTime string `yaml:"report_time"`
	// SourceSilence 为数据源断流告警的默认阈值（文件数据源、syslog 监听与登记的发送端）：超过该时间没有收到日志即推送告警，
	// 恢复后再推送一次；off 关闭。单个数据源 / 发送端可单独设置 silence。
	SourceSilence string `yaml:"source_silence"`
}

// WebhookConfig 是配置文件中的告警推送机器人。
type WebhookConfig struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Type   string `yaml:"type"`   // dingtalk | wecom | feishu | generic
	Secret string `yaml:"secret"` // 钉钉 / 飞书机器人安全设置为“加签”时的密钥
	// Levels 推送的告警等级，可多选：medium（中危）/ high（高危）/ critical（严重）
	Levels []string `yaml:"levels"`
	// MinSeverity 兼容旧配置：推送不低于该等级的告警（设置了 levels 时忽略）
	MinSeverity string `yaml:"min_severity"`
	Disabled    bool   `yaml:"disabled"`
	// Report 接收每日安全日报（推送时间见 alert.report_time）
	Report bool `yaml:"report"`
}

// AuditConfig 是防篡改审计链：登录与操作记录按月写入哈希链文件。
type AuditConfig struct {
	Dir           string `yaml:"dir"`            // 为空时放在 storage.snapshot 所在目录下的 audit（未配置快照时为 data/audit）
	RetentionDays int    `yaml:"retention_days"` // 留存天数，默认 180；0 表示永久保留
}

// RawLogConfig 是原始日志留存：解析后的日志按小时压缩存放在本地，支持按时间、IP、关键字检索与取证导出，
// 并以哈希链清单防篡改。《网络安全法》要求网络日志留存不少于六个月，默认留存 180 天。
type RawLogConfig struct {
	Enabled bool `yaml:"enabled"`
	// Dir 为留存目录；为空时放在 storage.snapshot 所在目录下的 rawlog
	Dir           string  `yaml:"dir"`
	RetentionDays int     `yaml:"retention_days"` // 留存天数，默认 180；0 表示不按时间清理
	MaxSizeGB     float64 `yaml:"max_size_gb"`    // 总容量上限（GB），超过时从最早的日期开始清理；0 表示不限制
	AttacksOnly   bool    `yaml:"attacks_only"`   // 只留存命中攻击规则的事件（节省空间，但无法回溯正常访问）
}

// ArchiveConfig 是可选的告警归档：配置 PostgreSQL 后，告警异步批量写入按月分区的表，长期留存并可按时间 / IP / 规则查询。
// 不配置时不启用，部署仍无任何外部依赖。
type ArchiveConfig struct {
	// DSN 例如 postgres://netsa:密码@127.0.0.1:5432/netsa?sslmode=disable；为空表示不启用。
	// 建议通过环境变量 NETSA_ARCHIVE_DSN 提供，避免密码写入配置文件。
	DSN string `yaml:"dsn"`
	// RetentionYears 按年设置的保留周期：0（默认）表示永久保留；N 表示至少保留最近 N 年，更早的月分区整表删除
	// （按月分区，实际保留 N 年加不足一个月，满足《网络安全法》日志留存不少于六个月的要求）
	RetentionYears int           `yaml:"retention_years"`
	BatchSize      int           `yaml:"batch_size"`     // 每批写入条数（默认 1000）
	FlushInterval  time.Duration `yaml:"flush_interval"` // 未满一批时的最长等待时间（默认 2s）
	QueueSize      int           `yaml:"queue_size"`     // 待写入队列容量（默认 100000），数据库不可用时在此缓冲
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
				WebWindow:       time.Minute,
				CCRequests:      600,
				Scan404:         40,
				ScanPaths:       30,
				BruteLogin:      15,
				Server5xx:       30,
				FwWindow:        5 * time.Minute,
				PortScanPorts:   20,
				HostSweep:       20,
				BruteConns:      30,
				FloodEvents:     5000,
				DistWindow:      10 * time.Minute,
				DistBruteLogins: 100,
				DistBruteIPs:    20,
				EnumWindow:      10 * time.Minute,
				EnumIDs:         300,
				BeaconConns:     8,
				AuthFailures:    10,
				AuthUsers:       5,
				DNSNXDomain:     60,
				DNSSubdomains:   150,
			},
		},
		RawLog: RawLogConfig{RetentionDays: 180},
		Audit:  AuditConfig{RetentionDays: 180},
		Report: ReportConfig{Weekly: "mon 09:00", Monthly: "1 09:00"},
		Alert:  AlertConfig{DedupWindow: 10 * time.Minute, ReportTime: "09:00", SourceSilence: "30m"},
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
	switch c.TimeCorrection {
	case "", "auto", "off":
	default:
		return fmt.Errorf("time_correction 只能为 auto 或 off: %q", c.TimeCorrection)
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
	if t := strings.TrimSpace(c.Alert.ReportTime); t != "" && t != "off" {
		if _, err := time.Parse("15:04", t); err != nil {
			return fmt.Errorf("alert.report_time 格式应为 HH:MM（如 09:00），或 off 关闭日报: %q", t)
		}
	}
	for _, n := range c.Server.AllowNetworks {
		if _, err := ParseNetwork(n); err != nil {
			return fmt.Errorf("server.allow_networks: %w", err)
		}
	}
	if a := c.Archive; a.BatchSize > 10000 || a.QueueSize > 5000000 || a.RetentionYears < 0 || a.RetentionYears > 100 {
		return fmt.Errorf("archive 配置超出范围：batch_size ≤ 10000、queue_size ≤ 5000000、retention_years 为 0（永久保留）~ 100")
	}
	if d := c.Archive.DSN; d != "" && !strings.HasPrefix(d, "postgres://") && !strings.HasPrefix(d, "postgresql://") && !strings.Contains(d, "=") {
		return fmt.Errorf("archive.dsn 格式无效，应形如 postgres://用户:密码@主机:5432/库名?sslmode=disable")
	}
	if err := c.validateReport(); err != nil {
		return err
	}
	if c.Audit.RetentionDays < 0 || c.Audit.RetentionDays > 3650 {
		return fmt.Errorf("audit.retention_days 应为 0（永久）至 3650")
	}
	if r := c.RawLog; r.RetentionDays < 0 || r.RetentionDays > 3650 || r.MaxSizeGB < 0 {
		return fmt.Errorf("rawlog 配置超出范围：retention_days 为 0 至 3650，max_size_gb 不能为负数")
	}
	if err := c.validateSyslog(); err != nil {
		return err
	}
	if _, err := ParseSilence(c.Alert.SourceSilence, 0); err != nil {
		return fmt.Errorf("alert.source_silence: %w", err)
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return fmt.Errorf("server.tls_cert 与 server.tls_key 需同时设置")
	}
	if c.Server.SessionTTL < 0 || (c.Server.SessionTTL > 0 && c.Server.SessionTTL < 5*time.Minute) {
		return fmt.Errorf("server.session_ttl 不能小于 5 分钟")
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
		if _, err := ParseSilence(s.Silence, 0); err != nil {
			return fmt.Errorf("sources[%d].silence: %w", i, err)
		}
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
	if b := c.Alert.BaseURL; b != "" {
		if u, err := url.Parse(b); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("alert.base_url 必须是 http(s) 地址: %q", b)
		}
	}
	for i, w := range c.Alert.Webhooks {
		name := w.Name
		if name == "" {
			name = fmt.Sprintf("#%d", i+1)
		}
		switch strings.ToLower(w.Type) {
		case "", "generic", "dingtalk", "wecom", "wechat", "feishu", "lark":
		default:
			return fmt.Errorf("alert.webhooks %s 的 type 不支持: %s（可选 dingtalk / wecom / feishu / generic）", name, w.Type)
		}
		if u, err := url.Parse(w.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("alert.webhooks %s 的 url 无效", name)
		}
		for _, l := range w.Levels {
			switch strings.ToLower(l) {
			case "medium", "high", "critical":
			default:
				return fmt.Errorf("alert.webhooks %s 的 levels 不支持 %q（可选 medium / high / critical）", name, l)
			}
		}
		if w.MinSeverity != "" {
			switch strings.ToLower(w.MinSeverity) {
			case "low", "medium", "high", "critical":
			default:
				return fmt.Errorf("alert.webhooks %s 的 min_severity 不支持 %q", name, w.MinSeverity)
			}
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
	if t.DistWindow <= 0 {
		t.DistWindow = dt.DistWindow
	}
	if t.EnumWindow <= 0 {
		t.EnumWindow = dt.EnumWindow
	}
	for _, p := range []struct {
		v   *int
		def int
	}{
		{&t.CCRequests, dt.CCRequests}, {&t.Scan404, dt.Scan404}, {&t.ScanPaths, dt.ScanPaths},
		{&t.BruteLogin, dt.BruteLogin}, {&t.Server5xx, dt.Server5xx}, {&t.PortScanPorts, dt.PortScanPorts},
		{&t.HostSweep, dt.HostSweep}, {&t.BruteConns, dt.BruteConns}, {&t.FloodEvents, dt.FloodEvents},
		{&t.DistBruteLogins, dt.DistBruteLogins}, {&t.DistBruteIPs, dt.DistBruteIPs}, {&t.EnumIDs, dt.EnumIDs}, {&t.BeaconConns, dt.BeaconConns},
		{&t.AuthFailures, dt.AuthFailures}, {&t.AuthUsers, dt.AuthUsers}, {&t.DNSNXDomain, dt.DNSNXDomain}, {&t.DNSSubdomains, dt.DNSSubdomains},
		{&c.Detect.AlertsPerRule, d.Detect.AlertsPerRule},
		{&c.Storage.MaxIPs, d.Storage.MaxIPs}, {&c.Storage.MaxAlerts, d.Storage.MaxAlerts},
		{&c.Geo.CacheSize, d.Geo.CacheSize},
	} {
		if *p.v <= 0 {
			*p.v = p.def
		}
	}
	if c.Archive.BatchSize <= 0 {
		c.Archive.BatchSize = 1000
	}
	if c.Archive.FlushInterval <= 0 {
		c.Archive.FlushInterval = 2 * time.Second
	}
	if c.Archive.QueueSize <= 0 {
		c.Archive.QueueSize = 100000
	}
	if c.Alert.DedupWindow <= 0 {
		c.Alert.DedupWindow = d.Alert.DedupWindow
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

// ParseNetwork 解析 IP 或 CIDR 网段。
func ParseNetwork(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("无效的 IP 或网段 %q", s)
}

// ParseSilence 解析断流告警阈值：为空返回 def，off / 0 返回 0（关闭），其余为不小于 1 分钟、不超过 30 天的时长。
func ParseSilence(s string, def time.Duration) (time.Duration, error) {
	switch s = strings.TrimSpace(s); s {
	case "":
		return def, nil
	case "off", "0":
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Minute || d > 30*24*time.Hour {
		return 0, fmt.Errorf("断流告警阈值应为 1m ~ 720h 的时长（如 30m、2h）或 off: %q", s)
	}
	return d, nil
}

// ParseSenderCIDR 解析发送端 IP 或网段；IPv4 前缀至少 /8、IPv6 至少 /16，避免一条规则放行整个地址空间。
func ParseSenderCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return netip.Prefix{}, fmt.Errorf("IP 或网段无效: %q", s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
	}
	if p.Addr().Is4() && p.Bits() < 8 || !p.Addr().Is4() && p.Bits() < 16 {
		return netip.Prefix{}, fmt.Errorf("网段范围过大（IPv4 至少 /8，IPv6 至少 /16）: %q", s)
	}
	return p.Masked(), nil
}

func (c *Config) validateSyslog() error {
	sc := c.Syslog
	if (sc.TLSCert == "") != (sc.TLSKey == "") || sc.TLS != "" && sc.TLSCert == "" {
		return fmt.Errorf("syslog.tls 需同时配置 syslog.tls_cert 与 syslog.tls_key")
	}
	if sc.RateLimit < 0 || sc.RateLimit > 1000000 {
		return fmt.Errorf("syslog.rate_limit 应为 0（不限制）~ 1000000")
	}
	for i, s := range sc.Senders {
		if _, err := ParseSenderCIDR(s.CIDR); err != nil {
			return fmt.Errorf("syslog.senders[%d]: %w", i, err)
		}
		switch s.Action {
		case "", "allow", "block":
		default:
			return fmt.Errorf("syslog.senders[%d].action 只能为 allow 或 block", i)
		}
		if _, err := ParseSilence(s.Silence, 0); err != nil {
			return fmt.Errorf("syslog.senders[%d].silence: %w", i, err)
		}
	}
	return nil
}
