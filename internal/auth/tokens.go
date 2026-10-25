package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// API 令牌供脚本、SIEM / SOAR 与 Prometheus 调用接口，代替使用账号口令的 HTTP Basic 认证：
// 令牌可单独限定权限与有效期、随时吊销；服务端只保存令牌的 SHA-256 哈希，明文只在创建时显示一次。

// RoleMetrics 是只能读取 /metrics 监控指标的令牌权限。
const RoleMetrics = "metrics"

// TokenPrefix 是令牌的固定前缀，便于在日志与代码仓库中识别和扫描泄露的令牌。
const TokenPrefix = "nsa_"

// APIToken 是一个 API 令牌。
type APIToken struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Prefix   string    `json:"prefix"` // 令牌开头的若干字符，便于识别
	Hash     string    `json:"hash"`
	User     string    `json:"user"` // 所属账号：账号删除后令牌失效，令牌权限不超过账号权限
	Role     string    `json:"role"`
	Created  time.Time `json:"created"`
	Creator  string    `json:"creator"`
	Expires  time.Time `json:"expires,omitempty"`
	LastUsed time.Time `json:"last_used,omitempty"`
	LastIP   string    `json:"last_ip,omitempty"`
}

// TokenView 是令牌在界面上的展示信息（不含哈希）。
type TokenView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Prefix   string    `json:"prefix"`
	User     string    `json:"user"`
	Role     string    `json:"role"`
	Created  time.Time `json:"created"`
	Creator  string    `json:"creator"`
	Expires  time.Time `json:"expires"`
	LastUsed time.Time `json:"last_used"`
	LastIP   string    `json:"last_ip"`
	Expired  bool      `json:"expired"`
}

func (t *APIToken) view(now time.Time) TokenView {
	return TokenView{ID: t.ID, Name: t.Name, Prefix: t.Prefix, User: t.User, Role: t.Role, Created: t.Created, Creator: t.Creator,
		Expires: t.Expires, LastUsed: t.LastUsed, LastIP: t.LastIP, Expired: !t.Expires.IsZero() && now.After(t.Expires)}
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// 令牌错误。
var (
	ErrNoToken     = errors.New("令牌不存在")
	ErrTokenRole   = errors.New("令牌权限不能超过所属账号的权限")
	ErrTokenName   = errors.New("令牌名称为 1~40 个字符")
	ErrTokenLimit  = errors.New("令牌数量已达上限（100 个）")
	ErrTokenExpiry = errors.New("有效期为 0（永久）~ 3650 天")
)

// roleRank 返回角色的权限等级。
func roleRank(r string) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleAnalyst:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// RoleAtLeast 判断角色是否具备 need 所需的权限。
func RoleAtLeast(role, need string) bool {
	return roleRank(role) >= roleRank(need) && roleRank(role) > 0
}

// CreateToken 为账号创建令牌，返回令牌明文（只此一次）。days 为 0 表示永久有效。
func (m *Manager) CreateToken(owner, name, role, creator string, days int) (string, TokenView, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 40 {
		return "", TokenView{}, ErrTokenName
	}
	if days < 0 || days > 3650 {
		return "", TokenView{}, ErrTokenExpiry
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[owner]
	if u == nil {
		return "", TokenView{}, ErrNoUser
	}
	if role != RoleMetrics && (roleRank(role) == 0 || roleRank(role) > roleRank(u.Role)) {
		return "", TokenView{}, ErrTokenRole
	}
	if len(m.tokens) >= 100 {
		return "", TokenView{}, ErrTokenLimit
	}
	b := make([]byte, 32)
	rand.Read(b)
	raw := TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	now := m.now()
	t := &APIToken{ID: randomID()[:12], Name: name, Prefix: raw[:12], Hash: hashToken(raw), User: owner, Role: role, Created: now, Creator: creator}
	if days > 0 {
		t.Expires = now.Add(time.Duration(days) * 24 * time.Hour)
	}
	m.tokens[t.Hash] = t
	if err := m.saveLocked(); err != nil {
		delete(m.tokens, t.Hash)
		return "", TokenView{}, err
	}
	return raw, t.view(now), nil
}

// VerifyToken 校验令牌并返回会话（令牌权限与所属账号当前权限取较低者）。
func (m *Manager) VerifyToken(raw, ip string) (*Session, bool) {
	if !strings.HasPrefix(raw, TokenPrefix) || len(raw) > 128 {
		return nil, false
	}
	h := hashToken(raw)
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.statAt) >= time.Second {
		m.reloadIfChanged()
	}
	t := m.tokens[h]
	if t == nil || !t.Expires.IsZero() && now.After(t.Expires) {
		return nil, false
	}
	u := m.users[t.User]
	if u == nil {
		return nil, false
	}
	role := t.Role
	if role != RoleMetrics && roleRank(u.Role) < roleRank(role) {
		role = u.Role
	}
	// 最近使用时间只在内存中更新，每小时最多写一次文件，避免每个请求都写盘
	persist := now.Sub(t.LastUsed) > time.Hour
	t.LastUsed, t.LastIP = now, ip
	if persist {
		m.saveLocked()
	}
	return &Session{User: u.Name, Role: role, ID: "token:" + t.ID, AuthTime: now, Expires: now.Add(time.Minute), Via: "token"}, true
}

// Tokens 返回全部令牌（新的在前）。
func (m *Manager) Tokens() []TokenView {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]TokenView, 0, len(m.tokens))
	for _, t := range m.tokens {
		out = append(out, t.view(now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// DeleteToken 吊销令牌。
func (m *Manager) DeleteToken(id string) (TokenView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, t := range m.tokens {
		if t.ID == id {
			delete(m.tokens, h)
			return t.view(m.now()), m.saveLocked()
		}
	}
	return TokenView{}, ErrNoToken
}
