// Package sso 实现外部账号登录：LDAP / Active Directory 与 OpenID Connect。
package sso

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"netsa/internal/config"
)

// ErrDenied 表示账号通过了外部认证，但组映射不到任何角色，也没有配置默认角色。
var ErrDenied = errors.New("账号没有平台访问权限，请联系管理员配置组映射")

// MapRole 把外部账号的组映射为平台角色，取最高的权限；匹配不到时使用默认角色。组名比较不区分大小写，
// 既可以写完整的 DN 或路径，也可以只写短名（CN 或路径的最后一段）。
func MapRole(m config.RoleMap, groups []string) string {
	has := func(list []string) bool {
		for _, want := range list {
			if want == "" {
				continue
			}
			for _, g := range groups {
				if strings.EqualFold(want, g) || strings.EqualFold(want, groupShortName(g)) {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has(m.AdminGroups):
		return "admin"
	case has(m.AnalystGroups):
		return "analyst"
	case has(m.ViewerGroups):
		return "viewer"
	}
	return m.DefaultRole
}

// groupShortName 取组的短名：DN 取 CN；Keycloak 默认写完整路径（/部门/soc），取最后一段。
func groupShortName(g string) string {
	if strings.HasPrefix(g, "/") {
		p := strings.TrimRight(g, "/")
		return p[strings.LastIndex(p, "/")+1:]
	}
	first, _, _ := strings.Cut(g, ",")
	if k, v, ok := strings.Cut(first, "="); ok && strings.EqualFold(strings.TrimSpace(k), "cn") {
		return strings.TrimSpace(v)
	}
	return g
}

// deniedError 说明账号带了哪些组，管理员才能看出是组映射写错了，还是身份提供方根本没有发组。
func deniedError(groups []string) error {
	if len(groups) > 20 {
		groups = groups[:20]
	}
	return fmt.Errorf("%w（收到的组: %q）", ErrDenied, groups)
}

// LDAP 用 LDAP 校验账号密码。
type LDAP struct {
	cfg     config.LDAPConfig
	tlsConf *tls.Config
	bindPW  string
}

// NewLDAP 创建 LDAP 认证器；未配置时返回 nil。
func NewLDAP(cfg config.LDAPConfig) (*LDAP, error) {
	if cfg.URL == "" {
		return nil, nil
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	l := &LDAP{cfg: cfg, tlsConf: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("读取 LDAP CA 证书: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("LDAP CA 证书无效")
		}
		l.tlsConf.RootCAs = pool
	}
	if cfg.BindPasswordEnv != "" {
		l.bindPW = os.Getenv(cfg.BindPasswordEnv)
	}
	if l.cfg.UserFilter == "" {
		l.cfg.UserFilter = "(|(uid=%s)(sAMAccountName=%s))"
	}
	if l.cfg.GroupAttr == "" {
		l.cfg.GroupAttr = "memberOf"
	}
	if l.cfg.Timeout <= 0 {
		l.cfg.Timeout = 10 * time.Second
	}
	return l, nil
}

func (l *LDAP) dial() (*ldap.Conn, error) {
	c, err := ldap.DialURL(l.cfg.URL, ldap.DialWithTLSConfig(l.tlsConf))
	if err != nil {
		return nil, err
	}
	c.SetTimeout(l.cfg.Timeout)
	if l.cfg.StartTLS {
		if err := c.StartTLS(l.tlsConf); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

// Authenticate 校验账号密码并返回平台角色。
//
// 步骤：用服务账号查找用户（用户名转义，必须唯一）→ 用用户自己的 DN 和密码绑定 → 按组映射角色。
// 空密码在很多目录服务上是匿名绑定、总是成功，必须拒绝。
func (l *LDAP) Authenticate(user, password string) (string, error) {
	if user == "" || password == "" {
		return "", errors.New("用户名或密码为空")
	}
	c, err := l.dial()
	if err != nil {
		return "", fmt.Errorf("连接 LDAP: %w", err)
	}
	defer c.Close()
	if l.cfg.BindDN != "" {
		if err := c.Bind(l.cfg.BindDN, l.bindPW); err != nil {
			return "", fmt.Errorf("LDAP 服务账号绑定失败: %w", err)
		}
	}
	filter := strings.ReplaceAll(l.cfg.UserFilter, "%s", ldap.EscapeFilter(user))
	res, err := c.Search(ldap.NewSearchRequest(l.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(l.cfg.Timeout.Seconds()), false,
		filter, []string{"dn", l.cfg.GroupAttr}, nil))
	if err != nil {
		return "", fmt.Errorf("查找 LDAP 用户: %w", err)
	}
	if len(res.Entries) != 1 {
		return "", errors.New("用户不存在或不唯一")
	}
	entry := res.Entries[0]
	if err := c.Bind(entry.DN, password); err != nil {
		return "", errors.New("用户名或密码错误")
	}
	groups := entry.GetAttributeValues(l.cfg.GroupAttr)
	role := MapRole(l.cfg.RoleMap, groups)
	if role == "" {
		return "", deniedError(groups)
	}
	return role, nil
}
