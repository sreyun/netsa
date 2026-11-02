package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// LDAPConfig 是 LDAP / Active Directory 登录（server.ldap）。
type LDAPConfig struct {
	URL      string `yaml:"url"`       // ldaps://ldap.example.com:636
	StartTLS bool   `yaml:"start_tls"` // ldap:// 上升级到 TLS
	// AllowPlain 允许不加密的 ldap://：密码会明文传输，只适用于本机或隔离网络
	AllowPlain bool   `yaml:"allow_plain"`
	CAFile     string `yaml:"ca_file"` // 内部 CA 证书
	// BindDN / BindPasswordEnv 查找用户所用的服务账号；都为空时匿名查找。密码只从环境变量读取
	BindDN          string `yaml:"bind_dn"`
	BindPasswordEnv string `yaml:"bind_password_env"`
	BaseDN          string `yaml:"base_dn"`
	// UserFilter 查找用户的过滤器，%s 替换为转义后的用户名（默认同时匹配 uid 与 sAMAccountName）
	UserFilter string `yaml:"user_filter"`
	// GroupAttr 用户条目上表示所属组的属性（默认 memberOf）
	GroupAttr string `yaml:"group_attr"`
	RoleMap   `yaml:",inline"`
	Timeout   time.Duration `yaml:"timeout"`
}

// OIDCConfig 是 OpenID Connect 单点登录（server.oidc）。
type OIDCConfig struct {
	Issuer          string   `yaml:"issuer"`
	ClientID        string   `yaml:"client_id"`
	ClientSecretEnv string   `yaml:"client_secret_env"` // 客户端密钥只从环境变量读取
	RedirectURL     string   `yaml:"redirect_url"`      // https://soc.example.com/api/auth/oidc/callback
	Scopes          []string `yaml:"scopes"`            // 默认 openid profile email
	UsernameClaim   string   `yaml:"username_claim"`    // 默认 preferred_username，其次 email
	RoleClaim       string   `yaml:"role_claim"`        // 默认 groups
	DisplayName     string   `yaml:"display_name"`      // 登录页按钮上的名称
	RoleMap         `yaml:",inline"`
}

// RoleMap 把外部账号的组映射为平台角色。匹配不到时使用 default_role；default_role 为空表示拒绝登录。
type RoleMap struct {
	AdminGroups   []string `yaml:"admin_groups"`
	AnalystGroups []string `yaml:"analyst_groups"`
	ViewerGroups  []string `yaml:"viewer_groups"`
	DefaultRole   string   `yaml:"default_role"`
}

func (m RoleMap) validate(prefix string) error {
	switch m.DefaultRole {
	case "", "viewer", "analyst":
		return nil
	case "admin":
		return fmt.Errorf("%s.default_role 不能是 admin：匹配不到组的账号不应自动成为管理员", prefix)
	}
	return fmt.Errorf("%s.default_role 只能是 viewer、analyst 或留空（拒绝登录）", prefix)
}

func (c LDAPConfig) validate() error {
	if c.URL == "" {
		return nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return fmt.Errorf("server.ldap.url 应为 ldaps://主机:端口 或 ldap://主机:端口")
	}
	if u.Scheme == "ldap" && !c.StartTLS && !c.AllowPlain {
		return fmt.Errorf("server.ldap：ldap:// 会明文传输密码，请使用 ldaps:// 或 start_tls；确认网络隔离时可设置 allow_plain")
	}
	if c.BaseDN == "" {
		return fmt.Errorf("server.ldap.base_dn 不能为空")
	}
	if c.UserFilter != "" && !strings.Contains(c.UserFilter, "%s") {
		return fmt.Errorf("server.ldap.user_filter 必须包含 %%s")
	}
	return c.RoleMap.validate("server.ldap")
}

func (c OIDCConfig) validate() error {
	if c.Issuer == "" {
		return nil
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return fmt.Errorf("server.oidc.issuer 必须是 https 地址（本机测试可用 http://localhost）")
	}
	if c.ClientID == "" {
		return fmt.Errorf("server.oidc.client_id 不能为空")
	}
	r, err := url.Parse(c.RedirectURL)
	if err != nil || r.Host == "" || !strings.HasSuffix(r.Path, "/api/auth/oidc/callback") {
		return fmt.Errorf("server.oidc.redirect_url 应为 https://平台地址/api/auth/oidc/callback")
	}
	return c.RoleMap.validate("server.oidc")
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ForwardConfig 是一个 SIEM 转发目标（forward 段）。
type ForwardConfig struct {
	Name     string `yaml:"name"`
	Address  string `yaml:"address"`   // 主机:端口
	Protocol string `yaml:"protocol"`  // udp / tcp / tls（默认 tls）
	Format   string `yaml:"format"`    // cef / json / rfc5424（默认 cef）
	MinLevel string `yaml:"min_level"` // 最低转发等级（默认 low）
	CAFile   string `yaml:"ca_file"`   // tls 时校验对端的内部 CA 证书
}

func (c ForwardConfig) validate(i int) error {
	if c.Address == "" {
		return fmt.Errorf("forward[%d].address 不能为空", i)
	}
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return fmt.Errorf("forward[%d].address 应为 主机:端口: %v", i, err)
	}
	switch c.Protocol {
	case "", "udp", "tcp", "tls":
	default:
		return fmt.Errorf("forward[%d].protocol 只能是 udp、tcp 或 tls", i)
	}
	switch c.Format {
	case "", "cef", "json", "rfc5424":
	default:
		return fmt.Errorf("forward[%d].format 只能是 cef、json 或 rfc5424", i)
	}
	return nil
}

// BlockConfig 是联动封禁（block 段）。默认关闭。
type BlockConfig struct {
	Enabled bool `yaml:"enabled"`
	// DefaultTTL / MaxTTL 封禁时长：到期自动解除，避免遗忘的封禁长期影响业务
	DefaultTTL time.Duration `yaml:"default_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
	// Protect 永不封禁的地址或网段（业务出口、合作方、监控）；内网地址始终不封禁
	Protect []string `yaml:"protect"`
	// WebhookURL 封禁生效 / 解除时推送，适配防火墙的管理接口或自动化平台；防火墙也可以定时拉取 /api/block/edl
	WebhookURL      string `yaml:"webhook_url"`
	WebhookTokenEnv string `yaml:"webhook_token_env"`
	// AllowSelfApprove 允许申请人批准自己的申请（只有一位管理员时使用）
	AllowSelfApprove bool `yaml:"allow_self_approve"`
}

// TicketConfig 是一个工单系统（tickets 段）。
type TicketConfig struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	TokenEnv string `yaml:"token_env"` // 以 Authorization: Bearer 发送；只从环境变量读取
	// Body 是请求体模板（Go text/template），为空时发送通用 JSON。字符串值请用 {{json .Title}} 转义
	Body string `yaml:"body"`
	// IDField 响应 JSON 中工单编号的字段，支持点号路径（默认 id）
	IDField string `yaml:"id_field"`
}

// PlaybookConfig 是一条处置剧本（playbooks 段）：事件满足条件时执行一次。
type PlaybookConfig struct {
	Name string       `yaml:"name"`
	When PlaybookWhen `yaml:"when"`
	// 动作：Assign 指派负责人；Status 改为处置中（只接受 investigating）；Note 写入处置记录（处置步骤清单）；
	// Ticket 创建工单（对应 tickets 的 name）；RequestBlock 提交封禁申请（仍需管理员审批）
	Assign       string `yaml:"assign"`
	Status       string `yaml:"status"`
	Note         string `yaml:"note"`
	Ticket       string `yaml:"ticket"`
	RequestBlock bool   `yaml:"request_block"`
}

// PlaybookWhen 是剧本的触发条件，都满足才执行；未填写的条件不限制。
type PlaybookWhen struct {
	MinLevel   string   `yaml:"min_level"`
	Categories []string `yaml:"categories"`
	Proven     bool     `yaml:"proven"`      // 只匹配有证据证明攻击成功的事件
	AssetLevel string   `yaml:"asset_level"` // core / important / normal
}

// IntelFeedConfig 是一个在线情报源（intel.feeds）。
type IntelFeedConfig struct {
	Name string `yaml:"name"`
	// Type：stix 拉取 STIX 2.x bundle；taxii 拉取 TAXII 2.1 集合的 objects；misp 调用 attributes/restSearch；text 每行一个 IP 或网段
	Type     string        `yaml:"type"`
	URL      string        `yaml:"url"`
	TokenEnv string        `yaml:"token_env"` // 只从环境变量读取
	Interval time.Duration `yaml:"interval"`  // 默认 1h
	// MinConfidence STIX 指标的最低可信度（0 表示不限），MISP 只取 to_ids 属性
	MinConfidence int `yaml:"min_confidence"`
}

func (c IntelFeedConfig) validate(i int) error {
	switch c.Type {
	case "stix", "taxii", "misp", "text":
	default:
		return fmt.Errorf("intel.feeds[%d].type 只能是 stix、taxii、misp 或 text", i)
	}
	if c.Name == "" {
		return fmt.Errorf("intel.feeds[%d].name 不能为空", i)
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("intel.feeds[%d].url 应为 http(s) 地址", i)
	}
	return nil
}

func (c *Config) validateIntegrations() error {
	if err := c.Server.LDAP.validate(); err != nil {
		return err
	}
	if err := c.Server.OIDC.validate(); err != nil {
		return err
	}
	for i, f := range c.Forward {
		if err := f.validate(i); err != nil {
			return err
		}
	}
	for i, f := range c.Intel.Feeds {
		if err := f.validate(i); err != nil {
			return err
		}
	}
	tickets := map[string]bool{}
	for i, t := range c.Tickets {
		u, err := url.Parse(t.URL)
		if err != nil || t.Name == "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("tickets[%d] 需要 name 和 http(s) 地址", i)
		}
		tickets[t.Name] = true
	}
	for i, p := range c.Playbooks {
		if p.Name == "" {
			return fmt.Errorf("playbooks[%d].name 不能为空", i)
		}
		if p.Ticket != "" && !tickets[p.Ticket] {
			return fmt.Errorf("playbooks[%d].ticket %q 没有在 tickets 中定义", i, p.Ticket)
		}
		if p.Status != "" && p.Status != "investigating" {
			return fmt.Errorf("playbooks[%d].status 只能是 investigating：关闭事件必须由人确认", i)
		}
	}
	if c.Block.MaxTTL < 0 || c.Block.DefaultTTL < 0 {
		return fmt.Errorf("block 的封禁时长不能为负数")
	}
	return nil
}
