package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// 角色。
const (
	RoleAdmin   = "admin"   // 管理员：可管理账号、令牌、告警推送等全部配置
	RoleAnalyst = "analyst" // 运营分析员：可处置事件、标记误报与维护抑制规则，不能修改账号与系统配置
	RoleViewer  = "viewer"  // 只读：查看态势与告警
)

// ValidRole 判断是否为可分配给账号的角色。
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleAnalyst || r == RoleViewer }

// User 是一个登录账号。
type User struct {
	Name       string    `json:"name"`
	Hash       string    `json:"hash"`
	Role       string    `json:"role"`
	Created    time.Time `json:"created"`
	Changed    time.Time `json:"changed"`     // 最近修改密码的时间
	MustChange bool      `json:"must_change"` // 使用初始 / 重置的密码，登录后必须先修改
	Gen        int       `json:"gen"`         // 令牌代数：修改密码、删除账号后递增，使已签发的登录令牌失效
	LastLogin  time.Time `json:"last_login"`
	Source     string    `json:"-"` // config：来自配置文件（只读）；local：账号文件
	// 双因素认证（TOTP）
	TOTPSecret  string   `json:"totp_secret,omitempty"`
	TOTPPending string   `json:"totp_pending,omitempty"` // 绑定中、尚未验证的密钥
	TOTPLast    int64    `json:"totp_last,omitempty"`    // 最近一次成功使用的时间片（防重放）
	Recovery    []string `json:"recovery,omitempty"`     // 恢复码哈希（一次性）
}

// UserView 是账号在界面上的展示信息（不含密码哈希）。
type UserView struct {
	Name       string    `json:"name"`
	Role       string    `json:"role"`
	Created    time.Time `json:"created"`
	Changed    time.Time `json:"changed"`
	MustChange bool      `json:"must_change"`
	LastLogin  time.Time `json:"last_login"`
	Source     string    `json:"source"`
	TwoFactor  bool      `json:"two_factor"`
	Recovery   int       `json:"recovery_left,omitempty"` // 剩余恢复码数量
}

// Session 是一个已登录的会话。
type Session struct {
	User       string
	Role       string
	MustChange bool
	MustEnroll bool      // 策略要求启用双因素认证而该账号尚未启用：登录后必须先绑定
	TwoFactor  bool      // 已启用双因素认证
	ID         string    // 会话标识（用于退出登录时吊销）
	AuthTime   time.Time // 登录时间
	Expires    time.Time
	Via        string // session（浏览器会话）/ basic / token
}

// Record 是一条审计记录：登录尝试，以及账号、告警推送等配置变更与数据导出操作。
type Record struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Action string    `json:"action,omitempty"` // 为空表示登录
	Detail string    `json:"detail,omitempty"`
	OK     bool      `json:"ok"`
	Reason string    `json:"reason,omitempty"`
	Agent  string    `json:"agent,omitempty"`
}

// AuditSink 接收审计记录（防篡改审计链）。
type AuditSink interface{ AppendAudit(Record) }

// Options 是账号管理参数。
type Options struct {
	Audit          AuditSink     // 审计链（可为空）：登录与操作记录同时写入
	ConfigUser     string        // 配置文件中的管理员账号
	ConfigPassword string        // 明文或哈希
	File           string        // 账号文件；为空时只保存在内存中（重启后需重新登录，初始密码会重新生成）
	TTL            time.Duration // 登录有效期，期间有访问会自动续期
	MaxAge         time.Duration // 登录的最长有效期（自登录起），到期后必须重新登录
	InitialAdmin   string        // 首次启动时管理员 admin 的初始密码（为空则随机生成）
	Require2FA     bool          // 要求所有本地账号启用双因素认证（未启用的账号登录后须先绑定）
}

// 登录失败锁定策略。
const (
	pairMaxFail = 5                // 同一账号 + 同一来源 IP 的失败次数：只锁定该组合，攻击者无法借此把管理员锁在门外
	ipMaxFail   = 20               // 同一来源 IP 尝试多个账号（撞库）的失败次数
	userMaxFail = 50               // 同一账号来自所有 IP 的失败次数（分布式暴力破解）
	lockTime    = 15 * time.Minute // 锁定时间
	failWindow  = 15 * time.Minute // 失败次数的统计窗口
	auditCap    = 500
)

type failure struct {
	n     int
	first time.Time
	until time.Time // 锁定截止时间
}

// Manager 管理账号、会话令牌、登录失败锁定与审计。
type Manager struct {
	mu      sync.Mutex
	opt     Options
	users   map[string]*User
	key     []byte               // 会话令牌签名密钥
	revoked map[string]time.Time // 已退出登录的会话 ID → 令牌过期时间
	fails   map[string]*failure  // "u:用户名" / "ip:地址"
	audit   []Record
	fileMod time.Time            // 账号文件的修改时间（命令行修改密码后自动重新加载）
	statAt  time.Time            // 最近一次检查账号文件的时间（每个请求都要校验会话，检查频率限制为每秒一次）
	basicOK sync.Map             // Basic 认证成功结果缓存：摘要 → 到期时间，避免脚本每次请求都做一次耗时的哈希
	tokens  map[string]*APIToken // 令牌哈希 → 令牌
	nowFunc func() time.Time
}

type fileData struct {
	Key     string               `json:"key"`
	Users   []*User              `json:"users"`
	Revoked map[string]time.Time `json:"revoked,omitempty"`
	Audit   []Record             `json:"audit,omitempty"`
	Tokens  []*APIToken          `json:"tokens,omitempty"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{1,31}$`)

// New 创建账号管理器。返回值 initial 不为空时表示刚生成了管理员初始密码，调用方应将其输出到日志。
func New(opt Options) (m *Manager, initial string, err error) {
	if opt.TTL <= 0 {
		opt.TTL = 12 * time.Hour
	}
	if opt.MaxAge <= 0 {
		opt.MaxAge = 30 * 24 * time.Hour
	}
	m = &Manager{opt: opt, users: map[string]*User{}, revoked: map[string]time.Time{}, fails: map[string]*failure{}, tokens: map[string]*APIToken{}, nowFunc: time.Now}
	if err := m.load(); err != nil {
		return nil, "", err
	}
	if opt.ConfigUser != "" {
		if !nameRe.MatchString(opt.ConfigUser) {
			return nil, "", fmt.Errorf("server.username %q 只能包含字母、数字与 _ . @ -，长度 2~32", opt.ConfigUser)
		}
		u := m.users[opt.ConfigUser]
		if u == nil {
			u = &User{Name: opt.ConfigUser, Created: m.now()}
			m.users[u.Name] = u
		}
		u.Hash, u.Role, u.Source, u.MustChange = opt.ConfigPassword, RoleAdmin, "config", false
	}
	if len(m.key) == 0 {
		m.key = make([]byte, 32)
		rand.Read(m.key)
	}
	if !m.hasAdmin() {
		initial = opt.InitialAdmin
		must := initial == ""
		if must {
			initial = RandomPassword()
		}
		m.users["admin"] = &User{Name: "admin", Hash: HashPassword(initial), Role: RoleAdmin, Created: m.now(), Changed: m.now(), MustChange: must, Source: "local"}
		if !must {
			initial = "" // 通过环境变量指定的密码不回显到日志
		}
	}
	if err := m.saveLocked(); err != nil {
		return nil, "", err
	}
	return m, initial, nil
}

func (m *Manager) now() time.Time { return m.nowFunc() }

func (m *Manager) hasAdmin() bool {
	for _, u := range m.users {
		if u.Role == RoleAdmin {
			return true
		}
	}
	return false
}

// load 读取账号文件（调用方持锁或处于初始化阶段）。
func (m *Manager) load() error {
	if m.opt.File == "" {
		return nil
	}
	fi, err := os.Stat(m.opt.File)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(m.opt.File)
	if err != nil {
		return err
	}
	var d fileData
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("解析账号文件 %s 失败: %w", m.opt.File, err)
	}
	if k, err := hex.DecodeString(d.Key); err == nil && len(k) >= 32 {
		m.key = k
	}
	users := map[string]*User{}
	for _, u := range d.Users {
		if u != nil && nameRe.MatchString(u.Name) && ValidRole(u.Role) && IsHash(u.Hash) {
			u.Source = "local"
			users[u.Name] = u
		}
	}
	// 保留配置文件中的账号（不写入账号文件）
	for name, u := range m.users {
		if u.Source == "config" {
			users[name] = u
		}
	}
	m.users = users
	if d.Revoked != nil {
		m.revoked = d.Revoked
	}
	m.audit = d.Audit
	m.tokens = map[string]*APIToken{}
	for _, t := range d.Tokens {
		if t != nil && t.Hash != "" && t.ID != "" {
			m.tokens[t.Hash] = t
		}
	}
	m.fileMod = fi.ModTime()
	return nil
}

// reloadIfChanged 账号文件被命令行（netsa passwd）修改后重新加载（调用方持锁）。
func (m *Manager) reloadIfChanged() {
	if m.opt.File == "" {
		return
	}
	m.statAt = time.Now()
	if fi, err := os.Stat(m.opt.File); err == nil && !fi.ModTime().Equal(m.fileMod) {
		if err := m.load(); err != nil {
			log.Printf("[auth] 重新加载账号文件失败: %v", err)
		}
	}
}

// saveLocked 保存账号文件（权限 0600，包含密码哈希与令牌签名密钥）。
func (m *Manager) saveLocked() error {
	if m.opt.File == "" {
		return nil
	}
	now := m.now()
	for id, exp := range m.revoked {
		if now.After(exp) {
			delete(m.revoked, id)
		}
	}
	d := fileData{Key: hex.EncodeToString(m.key), Revoked: m.revoked, Audit: m.audit}
	for _, u := range m.users {
		if u.Source != "config" {
			d.Users = append(d.Users, u)
		}
	}
	sort.Slice(d.Users, func(i, j int) bool { return d.Users[i].Name < d.Users[j].Name })
	for _, t := range m.tokens {
		d.Tokens = append(d.Tokens, t)
	}
	sort.Slice(d.Tokens, func(i, j int) bool { return d.Tokens[i].Created.Before(d.Tokens[j].Created) })
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.opt.File), 0o755); err != nil {
		return fmt.Errorf("保存账号文件失败: %w", err)
	}
	tmp := m.opt.File + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("保存账号文件失败: %w", err)
	}
	if err := os.Rename(tmp, m.opt.File); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("保存账号文件失败: %w", err)
	}
	if fi, err := os.Stat(m.opt.File); err == nil {
		m.fileMod = fi.ModTime()
	}
	return nil
}

// ---------------- 登录 ----------------

// 登录错误。
var (
	ErrBadCredentials = errors.New("用户名或密码错误")
	ErrLocked         = errors.New("登录失败次数过多，请稍后再试")
)

// TwoFactorRequired 表示口令正确、还需输入双因素验证码；Challenge 是 5 分钟内有效的一次性登录凭据。
type TwoFactorRequired struct{ Challenge string }

func (e *TwoFactorRequired) Error() string { return "需要输入双因素验证码" }

// ErrBasic2FA 表示启用了双因素认证的账号不能使用 HTTP Basic 认证。
var ErrBasic2FA = errors.New("该账号已启用双因素认证，脚本访问请使用 API 令牌（Authorization: Bearer）")

// LockedError 携带剩余锁定时间。
type LockedError struct{ Wait time.Duration }

func (e *LockedError) Error() string {
	m := int(e.Wait.Minutes()) + 1
	return fmt.Sprintf("登录失败次数过多，已临时锁定，请 %d 分钟后再试", m)
}

func (e *LockedError) Unwrap() error { return ErrLocked }

// Login 校验用户名与密码，成功时返回会话与签名令牌。失败计入锁定统计并记录审计日志。
func (m *Manager) Login(user, password, ip, agent string) (*Session, string, error) {
	now := m.now()
	m.mu.Lock()
	m.reloadIfChanged()
	for _, k := range []struct{ key, reason string }{
		{"ip:" + ip, "来源 IP 已锁定"}, {"p:" + user + "|" + ip, "账号在该来源已锁定"}, {"u:" + user, "账号已锁定"},
	} {
		if wait := m.lockedLocked(k.key, now); wait > 0 {
			m.recordLocked(user, ip, agent, false, k.reason)
			m.mu.Unlock()
			return nil, "", &LockedError{wait}
		}
	}
	u := m.users[user]
	var hash string
	if u != nil {
		hash = u.Hash
	}
	m.mu.Unlock()

	// 哈希计算耗时较长，在锁外进行；账号不存在时同样计算一次，避免通过响应时间探测账号
	ok := false
	if u != nil {
		ok = VerifyPassword(hash, password)
	} else {
		VerifyPassword(dummyHash(), password)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !ok {
		m.failLocked("ip:"+ip, now, ipMaxFail, failWindow, lockTime)
		m.failLocked("p:"+user+"|"+ip, now, pairMaxFail, failWindow, lockTime)
		m.failLocked("u:"+user, now, userMaxFail, failWindow, lockTime)
		m.recordLocked(user, ip, agent, false, "用户名或密码错误")
		m.saveLocked()
		return nil, "", ErrBadCredentials
	}
	delete(m.fails, "p:"+user+"|"+ip)
	u = m.users[user]
	if u == nil { // 校验期间账号被删除
		return nil, "", ErrBadCredentials
	}
	if u.TOTPSecret != "" {
		// 口令正确，签发只能用于第二步验证的挑战凭据（不是会话令牌）
		c := claims{U: u.Name, G: u.Gen, SID: randomID(), IAT: now.Unix(), EXP: now.Add(5 * time.Minute).Unix(), T: "2fa"}
		return nil, "", &TwoFactorRequired{Challenge: m.signClaims(c)}
	}
	return m.finishLoginLocked(u, ip, agent, now, "")
}

// finishLoginLocked 完成登录：记录审计并签发会话（调用方持锁）。
func (m *Manager) finishLoginLocked(u *User, ip, agent string, now time.Time, reason string) (*Session, string, error) {
	u.LastLogin = now
	m.recordLocked(u.Name, ip, agent, true, reason)
	m.saveLocked()
	s := m.sessionLocked(u, randomID(), now, now.Add(m.opt.TTL))
	return s, m.sign(s, u.Gen), nil
}

// sessionLocked 构造账号的会话信息（调用方持锁）。
func (m *Manager) sessionLocked(u *User, id string, auth, exp time.Time) *Session {
	return &Session{User: u.Name, Role: u.Role, MustChange: u.MustChange, TwoFactor: u.TOTPSecret != "",
		MustEnroll: m.opt.Require2FA && u.TOTPSecret == "" && u.Source != "config", ID: id, AuthTime: auth, Expires: exp, Via: "session"}
}

// Login2FA 用口令验证后得到的挑战凭据与双因素验证码（或恢复码）完成登录。验证码错误同样计入登录失败锁定。
func (m *Manager) Login2FA(challenge, code, ip, agent string) (*Session, string, error) {
	c, ok := m.parseClaims(challenge)
	now := m.now()
	if !ok || c.T != "2fa" || now.After(time.Unix(c.EXP, 0)) {
		return nil, "", errors.New("登录已超时，请重新输入用户名和密码")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	user := c.U
	for _, k := range []string{"ip:" + ip, "p:" + user + "|" + ip, "u:" + user} {
		if wait := m.lockedLocked(k, now); wait > 0 {
			m.recordLocked(user, ip, agent, false, "双因素验证已锁定")
			return nil, "", &LockedError{wait}
		}
	}
	u := m.users[user]
	if u == nil || u.Gen != c.G || u.TOTPSecret == "" {
		return nil, "", errors.New("登录已失效，请重新输入用户名和密码")
	}
	if _, used := m.revoked[c.SID]; used {
		return nil, "", errors.New("登录已失效，请重新输入用户名和密码")
	}
	via := ""
	if step, ok := verifyTOTP(u.TOTPSecret, code, now, u.TOTPLast); ok {
		u.TOTPLast = step
	} else if i := indexOf(u.Recovery, hashRecovery(code)); len(strings.TrimSpace(code)) >= 8 && i >= 0 {
		u.Recovery = append(u.Recovery[:i:i], u.Recovery[i+1:]...) // 恢复码一次性使用
		via = "（使用恢复码，剩余 " + fmt.Sprint(len(u.Recovery)) + " 个）"
	} else {
		m.failLocked("ip:"+ip, now, ipMaxFail, failWindow, lockTime)
		m.failLocked("p:"+user+"|"+ip, now, pairMaxFail, failWindow, lockTime)
		m.failLocked("u:"+user, now, userMaxFail, failWindow, lockTime)
		m.recordLocked(user, ip, agent, false, "双因素验证码错误")
		m.saveLocked()
		return nil, "", errors.New("验证码错误")
	}
	m.revoked[c.SID] = time.Unix(c.EXP, 0) // 挑战凭据只能使用一次
	delete(m.fails, "p:"+user+"|"+ip)
	reason := "双因素认证"
	if via != "" {
		reason = "已登录" + via
	}
	return m.finishLoginLocked(u, ip, agent, now, reason) // 审计记录写入后不再修改（审计链按内容计算哈希）
}

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

func (m *Manager) lockedLocked(key string, now time.Time) time.Duration {
	if f := m.fails[key]; f != nil && now.Before(f.until) {
		return f.until.Sub(now)
	}
	return 0
}

// failLocked 记录一次失败；窗口内失败次数达到 max 时锁定 lock 时长。
func (m *Manager) failLocked(key string, now time.Time, max int, window, lock time.Duration) {
	f := m.fails[key]
	if f == nil || now.Sub(f.first) > window {
		f = &failure{first: now}
		m.fails[key] = f
	}
	f.n++
	if f.n >= max {
		f.until = now.Add(lock)
		f.n, f.first = 0, now
	}
	if len(m.fails) > 100000 { // 防止大量伪造来源撑爆内存
		for k, v := range m.fails {
			if now.After(v.until) && now.Sub(v.first) > window {
				delete(m.fails, k)
			}
		}
	}
}

func (m *Manager) recordLocked(user, ip, agent string, ok bool, reason string) {
	if len(user) > 64 {
		user = clipUTF8(user, 64)
	}
	if len(agent) > 200 {
		agent = clipUTF8(agent, 200)
	}
	rec := Record{Time: m.now(), User: user, IP: ip, OK: ok, Reason: reason, Agent: agent}
	m.audit = append(m.audit, rec)
	if m.opt.Audit != nil {
		m.opt.Audit.AppendAudit(rec)
	}
	if len(m.audit) > auditCap {
		m.audit = append([]Record(nil), m.audit[len(m.audit)-auditCap:]...)
	}
	if !ok {
		log.Printf("[auth] 登录失败: 用户 %q 来源 %s（%s）", user, ip, reason)
	}
}

// LogAction 记录一次操作（账号与配置变更、数据导出等），持久化到账号文件。
func (m *Manager) LogAction(user, ip, action, detail string, ok bool, reason string) {
	if len(detail) > 200 {
		detail = clipUTF8(detail, 200)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := Record{Time: m.now(), User: user, IP: ip, Action: action, Detail: detail, OK: ok, Reason: reason}
	m.audit = append(m.audit, rec)
	if m.opt.Audit != nil {
		m.opt.Audit.AppendAudit(rec)
	}
	if len(m.audit) > auditCap {
		m.audit = append([]Record(nil), m.audit[len(m.audit)-auditCap:]...)
	}
	m.saveLocked()
}

// ---------------- 会话令牌 ----------------

// 令牌格式：base64url(载荷 JSON) + "." + base64url(HMAC-SHA256(密钥, 载荷))。
// 令牌由服务端签名，重启后仍有效；修改密码（代数递增）或退出登录（吊销会话 ID）后失效。
type claims struct {
	U   string `json:"u"`
	G   int    `json:"g"`
	SID string `json:"sid"`
	IAT int64  `json:"iat"` // 登录时间
	EXP int64  `json:"exp"`
	T   string `json:"t,omitempty"` // 为空表示会话令牌；2fa 表示双因素验证的挑战凭据
}

func (m *Manager) sign(s *Session, gen int) string {
	return m.signClaims(claims{U: s.User, G: gen, SID: s.ID, IAT: s.AuthTime.Unix(), EXP: s.Expires.Unix()})
}

func (m *Manager) signClaims(c claims) string {
	payload, _ := json.Marshal(c)
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// parseClaims 校验签名并解析载荷（不检查有效期与类型）。
func (m *Manager) parseClaims(token string) (claims, bool) {
	var c claims
	p, sig, found := strings.Cut(token, ".")
	if !found || len(token) > 1024 {
		return c, false
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(p))
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, mac.Sum(nil)) {
		return c, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return c, false
	}
	return c, true
}

// Verify 校验令牌并返回会话；refresh 不为空时表示应下发续期后的新令牌（剩余有效期不足一半时）。
func (m *Manager) Verify(token string) (s *Session, refresh string, ok bool) {
	c, ok := m.parseClaims(token)
	if !ok || c.T != "" { // 双因素挑战凭据不能当作会话令牌使用
		return nil, "", false
	}
	now := m.now()
	exp, iat := time.Unix(c.EXP, 0), time.Unix(c.IAT, 0)
	if now.After(exp) || now.Sub(iat) > m.opt.MaxAge {
		return nil, "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.statAt) >= time.Second { // 会话校验是每个请求的热路径，不必每次都读取文件状态
		m.reloadIfChanged()
	}
	u := m.users[c.U]
	if u == nil || u.Gen != c.G {
		return nil, "", false
	}
	if _, gone := m.revoked[c.SID]; gone {
		return nil, "", false
	}
	s = m.sessionLocked(u, c.SID, iat, exp)
	// 滑动续期：剩余有效期不足一半时签发新令牌（不超过最长有效期）
	if exp.Sub(now) < m.opt.TTL/2 {
		s.Expires = now.Add(m.opt.TTL)
		if limit := iat.Add(m.opt.MaxAge); s.Expires.After(limit) {
			s.Expires = limit
		}
		refresh = m.sign(s, u.Gen)
	}
	return s, refresh, true
}

// Logout 吊销会话。
func (m *Manager) Logout(s *Session) {
	if s == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[s.ID] = s.Expires.Add(m.opt.TTL)
	m.saveLocked()
}

// HasUser 判断账号是否存在。
func (m *Manager) HasUser(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.users[name] != nil
}

// CheckBasic 校验 HTTP Basic 认证（供脚本调用 API）。成功结果缓存 5 分钟，失败计入锁定统计。
func (m *Manager) CheckBasic(user, password, ip string) (*Session, error) {
	sum := sha256.Sum256([]byte(user + "\x00" + password))
	key := hex.EncodeToString(sum[:])
	now := m.now()
	if v, ok := m.basicOK.Load(key); ok && now.Before(v.(time.Time)) {
		m.mu.Lock()
		u := m.users[user]
		m.mu.Unlock()
		if u != nil && u.TOTPSecret == "" {
			return &Session{User: u.Name, Role: u.Role, MustChange: u.MustChange, ID: "basic", AuthTime: now, Expires: now.Add(time.Minute), Via: "basic"}, nil
		}
	}
	s, _, err := m.Login(user, password, ip, "HTTP Basic")
	var tfr *TwoFactorRequired
	if errors.As(err, &tfr) {
		return nil, ErrBasic2FA
	}
	if err != nil {
		return nil, err
	}
	s.Via = "basic"
	m.basicOK.Store(key, now.Add(5*time.Minute))
	return s, nil
}

// ---------------- 账号管理 ----------------

// 账号管理错误。
var (
	ErrNoUser       = errors.New("账号不存在")
	ErrReadOnly     = errors.New("该账号来自配置文件 server.username，请在配置文件中修改")
	ErrLastAdmin    = errors.New("至少需要保留一个管理员账号")
	ErrUserExists   = errors.New("账号已存在")
	ErrBadName      = errors.New("用户名只能包含字母、数字与 _ . @ -，长度 2~32")
	ErrBadRole      = errors.New("角色只能为 admin（管理员）、analyst（运营分析员）或 viewer（只读）")
	ErrWrongCurrent = errors.New("当前密码不正确")
)

// bump 使该账号已签发的登录令牌与 Basic 认证缓存全部失效（调用方持锁）。
func (m *Manager) bump(u *User) {
	u.Gen++
	m.basicOK.Range(func(k, _ any) bool { m.basicOK.Delete(k); return true })
}

// ChangePassword 修改自己的密码（需校验当前密码），其他已登录会话随之失效。
func (m *Manager) ChangePassword(user, current, next string) (string, error) {
	m.mu.Lock()
	u := m.users[user]
	if u == nil {
		m.mu.Unlock()
		return "", ErrNoUser
	}
	if u.Source == "config" {
		m.mu.Unlock()
		return "", ErrReadOnly
	}
	hash := u.Hash
	m.mu.Unlock()
	if !VerifyPassword(hash, current) {
		return "", ErrWrongCurrent
	}
	if current == next {
		return "", errors.New("新密码不能与当前密码相同")
	}
	if err := CheckStrength(user, next); err != nil {
		return "", err
	}
	newHash := HashPassword(next)
	m.mu.Lock()
	defer m.mu.Unlock()
	u = m.users[user]
	if u == nil {
		return "", ErrNoUser
	}
	u.Hash, u.MustChange, u.Changed = newHash, false, m.now()
	m.bump(u)
	if err := m.saveLocked(); err != nil {
		return "", err
	}
	now := m.now()
	s := m.sessionLocked(u, randomID(), now, now.Add(m.opt.TTL))
	return m.sign(s, u.Gen), nil
}

// Users 返回全部账号。
func (m *Manager) Users() []UserView {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadIfChanged()
	out := make([]UserView, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, UserView{Name: u.Name, Role: u.Role, Created: u.Created, Changed: u.Changed, MustChange: u.MustChange, LastLogin: u.LastLogin, Source: u.Source,
			TwoFactor: u.TOTPSecret != "", Recovery: len(u.Recovery)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// CreateUser 新增账号（初始密码需在首次登录后修改）。
func (m *Manager) CreateUser(name, role, password string) error {
	if !nameRe.MatchString(name) {
		return ErrBadName
	}
	if !ValidRole(role) {
		return ErrBadRole
	}
	if err := CheckStrength(name, password); err != nil {
		return err
	}
	hash := HashPassword(password)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.users[name] != nil {
		return ErrUserExists
	}
	if len(m.users) >= 200 {
		return errors.New("账号数量已达上限（200 个）")
	}
	now := m.now()
	m.users[name] = &User{Name: name, Hash: hash, Role: role, Created: now, Changed: now, MustChange: true, Source: "local"}
	return m.saveLocked()
}

// UpdateUser 修改角色或重置密码（password 非空时重置，用户下次登录须修改）。
func (m *Manager) UpdateUser(name, role, password string) error {
	if role != "" && !ValidRole(role) {
		return ErrBadRole
	}
	var hash string
	if password != "" {
		if err := CheckStrength(name, password); err != nil {
			return err
		}
		hash = HashPassword(password)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[name]
	if u == nil {
		return ErrNoUser
	}
	if u.Source == "config" {
		return ErrReadOnly
	}
	if role != "" && role != u.Role {
		if u.Role == RoleAdmin && m.adminCount() <= 1 {
			return ErrLastAdmin
		}
		u.Role = role
		m.bump(u) // 角色变化后重新登录以获得新权限
	}
	if hash != "" {
		u.Hash, u.MustChange, u.Changed = hash, true, m.now()
		m.bump(u)
	}
	return m.saveLocked()
}

// DeleteUser 删除账号，其已登录会话立即失效。
func (m *Manager) DeleteUser(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[name]
	if u == nil {
		return ErrNoUser
	}
	if u.Source == "config" {
		return ErrReadOnly
	}
	if u.Role == RoleAdmin && m.adminCount() <= 1 {
		return ErrLastAdmin
	}
	delete(m.users, name)
	for h, t := range m.tokens { // 账号的 API 令牌一并删除
		if t.User == name {
			delete(m.tokens, h)
		}
	}
	m.basicOK.Range(func(k, _ any) bool { m.basicOK.Delete(k); return true })
	return m.saveLocked()
}

// ---------------- 双因素认证 ----------------

// 双因素认证错误。
var (
	ErrTOTPConfig  = errors.New("配置文件中的账号（server.username）不能启用双因素认证，请使用界面创建的账号")
	ErrTOTPEnabled = errors.New("已启用双因素认证")
	ErrTOTPCode    = errors.New("验证码错误，请确认手机时间准确后重试")
	ErrTOTPNone    = errors.New("尚未启用双因素认证")
)

// BeginTOTP 开始绑定：生成新密钥（验证通过前不生效），返回密钥与 otpauth 地址。
func (m *Manager) BeginTOTP(user string) (secret, uri string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[user]
	switch {
	case u == nil:
		return "", "", ErrNoUser
	case u.Source == "config":
		return "", "", ErrTOTPConfig
	case u.TOTPSecret != "":
		return "", "", ErrTOTPEnabled
	}
	u.TOTPPending = NewTOTPSecret()
	return u.TOTPPending, OTPAuthURL("netsa", u.Name, u.TOTPPending), m.saveLocked()
}

// EnableTOTP 用身份验证器显示的验证码确认绑定，返回一次性恢复码与当前会话的新令牌（其他会话随之失效）。
func (m *Manager) EnableTOTP(user, code string) (recovery []string, token string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[user]
	switch {
	case u == nil:
		return nil, "", ErrNoUser
	case u.TOTPSecret != "":
		return nil, "", ErrTOTPEnabled
	case u.TOTPPending == "":
		return nil, "", errors.New("请先生成绑定密钥")
	}
	step, ok := verifyTOTP(u.TOTPPending, code, m.now(), 0)
	if !ok {
		return nil, "", ErrTOTPCode
	}
	plain, hashes := newRecoveryCodes()
	u.TOTPSecret, u.TOTPPending, u.TOTPLast, u.Recovery = u.TOTPPending, "", step, hashes
	m.bump(u)
	if err := m.saveLocked(); err != nil {
		return nil, "", err
	}
	now := m.now()
	return plain, m.sign(m.sessionLocked(u, randomID(), now, now.Add(m.opt.TTL)), u.Gen), nil
}

// DisableTOTP 关闭自己的双因素认证（需同时验证口令与验证码），返回当前会话的新令牌。
func (m *Manager) DisableTOTP(user, password, code string) (string, error) {
	m.mu.Lock()
	u := m.users[user]
	if u == nil {
		m.mu.Unlock()
		return "", ErrNoUser
	}
	if u.TOTPSecret == "" {
		m.mu.Unlock()
		return "", ErrTOTPNone
	}
	hash := u.Hash
	m.mu.Unlock()
	if !VerifyPassword(hash, password) {
		return "", ErrWrongCurrent
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if u = m.users[user]; u == nil || u.TOTPSecret == "" {
		return "", ErrTOTPNone
	}
	if _, ok := verifyTOTP(u.TOTPSecret, code, m.now(), u.TOTPLast); !ok {
		return "", ErrTOTPCode
	}
	u.TOTPSecret, u.TOTPPending, u.TOTPLast, u.Recovery = "", "", 0, nil
	m.bump(u)
	if err := m.saveLocked(); err != nil {
		return "", err
	}
	now := m.now()
	return m.sign(m.sessionLocked(u, randomID(), now, now.Add(m.opt.TTL)), u.Gen), nil
}

// ResetTOTP 由管理员清除账号的双因素认证（手机丢失且恢复码用完时），其已登录会话随之失效。
func (m *Manager) ResetTOTP(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[name]
	if u == nil {
		return ErrNoUser
	}
	if u.TOTPSecret == "" && u.TOTPPending == "" {
		return ErrTOTPNone
	}
	u.TOTPSecret, u.TOTPPending, u.TOTPLast, u.Recovery = "", "", 0, nil
	m.bump(u)
	return m.saveLocked()
}

func (m *Manager) adminCount() int {
	n := 0
	for _, u := range m.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// Audit 返回最近的登录记录（新的在前）。
func (m *Manager) Audit(limit int) []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Record{}
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.audit[i])
	}
	return out
}

// SetPassword 供命令行（netsa passwd）重置密码：账号不存在时以管理员身份创建。
func SetPassword(file, name, password string) error {
	if !nameRe.MatchString(name) {
		return ErrBadName
	}
	if err := CheckStrength(name, password); err != nil {
		return err
	}
	m := &Manager{opt: Options{File: file}, users: map[string]*User{}, revoked: map[string]time.Time{}, fails: map[string]*failure{}, tokens: map[string]*APIToken{}, nowFunc: time.Now}
	if err := m.load(); err != nil {
		return err
	}
	if len(m.key) == 0 {
		m.key = make([]byte, 32)
		rand.Read(m.key)
	}
	now := m.now()
	u := m.users[name]
	if u == nil {
		u = &User{Name: name, Role: RoleAdmin, Created: now, Source: "local"}
		m.users[name] = u
	}
	u.Hash, u.MustChange, u.Changed = HashPassword(password), false, now
	u.Gen++
	return m.saveLocked()
}

func randomID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// clipUTF8 把 s 截断到不超过 n 字节，不截断多字节字符。
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n]
}

// SetAuditSink 设置审计链：之后的登录与操作记录同时写入。
func (m *Manager) SetAuditSink(sink AuditSink) {
	m.mu.Lock()
	m.opt.Audit = sink
	m.mu.Unlock()
}
