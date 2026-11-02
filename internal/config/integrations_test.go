package config

import (
	"strings"
	"testing"
	"time"
)

func TestIntegrationsValidate(t *testing.T) {
	ok := func(f func(c *Config)) *Config {
		c := Default()
		f(c)
		return c
	}
	for _, c := range []struct {
		name string
		cfg  *Config
		want string
	}{
		{"ldap 明文", ok(func(c *Config) { c.Server.LDAP = LDAPConfig{URL: "ldap://x", BaseDN: "dc=x"} }), "明文"},
		{"ldap 协议", ok(func(c *Config) { c.Server.LDAP = LDAPConfig{URL: "http://x", BaseDN: "dc=x"} }), "ldap"},
		{"ldap base_dn", ok(func(c *Config) { c.Server.LDAP = LDAPConfig{URL: "ldaps://x"} }), "base_dn"},
		{"ldap 过滤器", ok(func(c *Config) { c.Server.LDAP = LDAPConfig{URL: "ldaps://x", BaseDN: "d", UserFilter: "(uid=x)"} }), "%s"},
		{"默认角色不能是管理员", ok(func(c *Config) {
			c.Server.LDAP = LDAPConfig{URL: "ldaps://x", BaseDN: "d", RoleMap: RoleMap{DefaultRole: "admin"}}
		}), "admin"},
		{"oidc 明文", ok(func(c *Config) { c.Server.OIDC = OIDCConfig{Issuer: "http://idp.example.com", ClientID: "c"} }), "https"},
		{"oidc client", ok(func(c *Config) { c.Server.OIDC = OIDCConfig{Issuer: "https://idp"} }), "client_id"},
		{"oidc 回调", ok(func(c *Config) {
			c.Server.OIDC = OIDCConfig{Issuer: "https://idp", ClientID: "c", RedirectURL: "https://x/other"}
		}), "redirect_url"},
		{"转发地址", ok(func(c *Config) { c.Forward = []ForwardConfig{{Address: "noport"}} }), "address"},
		{"转发协议", ok(func(c *Config) { c.Forward = []ForwardConfig{{Address: "a:1", Protocol: "http"}} }), "protocol"},
		{"转发格式", ok(func(c *Config) { c.Forward = []ForwardConfig{{Address: "a:1", Format: "xml"}} }), "format"},
		{"情报类型", ok(func(c *Config) { c.Intel.Feeds = []IntelFeedConfig{{Name: "x", Type: "rss", URL: "https://x"}} }), "type"},
		{"情报地址", ok(func(c *Config) { c.Intel.Feeds = []IntelFeedConfig{{Name: "x", Type: "text", URL: "ftp://x"}} }), "url"},
		{"工单地址", ok(func(c *Config) { c.Tickets = []TicketConfig{{Name: "t", URL: "x"}} }), "tickets"},
		{"剧本引用不存在的工单", ok(func(c *Config) { c.Playbooks = []PlaybookConfig{{Name: "p", Ticket: "none"}} }), "ticket"},
		{"剧本不能关闭事件", ok(func(c *Config) { c.Playbooks = []PlaybookConfig{{Name: "p", Status: "resolved"}} }), "status"},
		{"封禁时长", ok(func(c *Config) { c.Block.MaxTTL = -time.Hour }), "block"},
	} {
		err := c.cfg.validateIntegrations()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: 期望包含 %q，实际 %v", c.name, c.want, err)
		}
	}
	good := ok(func(c *Config) {
		c.Server.LDAP = LDAPConfig{URL: "ldap://x", StartTLS: true, BaseDN: "d", UserFilter: "(uid=%s)"}
		c.Server.OIDC = OIDCConfig{Issuer: "http://localhost:8080/realm", ClientID: "c", RedirectURL: "http://localhost/api/auth/oidc/callback"}
		c.Forward = []ForwardConfig{{Address: "siem:6514"}}
		c.Intel.Feeds = []IntelFeedConfig{{Name: "x", Type: "taxii", URL: "https://x"}}
		c.Tickets = []TicketConfig{{Name: "t", URL: "https://x"}}
		c.Playbooks = []PlaybookConfig{{Name: "p", Ticket: "t", Status: "investigating"}}
	})
	if err := good.validateIntegrations(); err != nil {
		t.Fatal(err)
	}
}
