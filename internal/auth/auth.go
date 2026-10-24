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
	RoleAdmin  = "admin"  // 管理员：可管理账号与告警推送
	RoleViewer = "viewer" // 只读：查看态势与告警
)

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
}

// Session 是一个已登录的会话。
type Session struct {
	User       string
	Role       string
	MustChange bool
	ID         string    // 会话标识（用于退出登录时吊销）
	AuthTime   time.Time // 登录时间
	Expires    time.Time
}

// Record 是一条登录审计记录。
type Record struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	OK     bool      `json:"ok"`
	Reason string    `json:"reason,omitempty"`
	Agent  string    `json:"agent,omitempty"`
}

// Options 是账号管理参数。
type Options struct {
	ConfigUser     string        // 配置文件中的管理员账号
	ConfigPassword string        // 明文或哈希
	File           string        // 账号文件；为空时只保存在内存中（重启后需重新登录，初始密码会重新生成）
	TTL            time.Duration // 登录有效期，期间有访问会自动续期
	MaxAge         time.Duration // 登录的最长有效期（自登录起），到期后必须重新登录
	InitialAdmin   string        // 首次启动时管理员 admin 的初始密码（为空则随机生成）
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
	fileMod time.Time // 账号文件的修改时间（命令行修改密码后自动重新加载）
	basicOK sync.Map  // Basic 认证成功结果缓存：摘要 → 到期时间，避免脚本每次请求都做一次耗时的哈希
	nowFunc func() time.Time
}

type fileData struct {
	Key     string               `json:"key"`
	Users   []*User              `json:"users"`
	Revoked map[string]time.Time `json:"revoked,omitempty"`
	Audit   []Record             `json:"audit,omitempty"`
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
	m = &Manager{opt: opt, users: map[string]*User{}, revoked: map[string]time.Time{}, fails: map[string]*failure{}, nowFunc: time.Now}
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
		if u != nil && nameRe.MatchString(u.Name) && (u.Role == RoleAdmin || u.Role == RoleViewer) && IsHash(u.Hash) {
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
	m.fileMod = fi.ModTime()
	return nil
}

// reloadIfChanged 账号文件被命令行（netsa passwd）修改后重新加载（调用方持锁）。
func (m *Manager) reloadIfChanged() {
	if m.opt.File == "" {
		return
	}
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
	u.LastLogin = now
	m.recordLocked(user, ip, agent, true, "")
	m.saveLocked()
	s := &Session{User: u.Name, Role: u.Role, MustChange: u.MustChange, ID: randomID(), AuthTime: now, Expires: now.Add(m.opt.TTL)}
	return s, m.sign(s, u.Gen), nil
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
		user = user[:64]
	}
	if len(agent) > 200 {
		agent = agent[:200]
	}
	m.audit = append(m.audit, Record{Time: m.now(), User: user, IP: ip, OK: ok, Reason: reason, Agent: agent})
	if len(m.audit) > auditCap {
		m.audit = append([]Record(nil), m.audit[len(m.audit)-auditCap:]...)
	}
	if !ok {
		log.Printf("[auth] 登录失败: 用户 %q 来源 %s（%s）", user, ip, reason)
	}
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
}

func (m *Manager) sign(s *Session, gen int) string {
	c := claims{U: s.User, G: gen, SID: s.ID, IAT: s.AuthTime.Unix(), EXP: s.Expires.Unix()}
	payload, _ := json.Marshal(c)
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify 校验令牌并返回会话；refresh 不为空时表示应下发续期后的新令牌（剩余有效期不足一半时）。
func (m *Manager) Verify(token string) (s *Session, refresh string, ok bool) {
	p, sig, found := strings.Cut(token, ".")
	if !found || len(token) > 1024 {
		return nil, "", false
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(p))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return nil, "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, "", false
	}
	var c claims
	if json.Unmarshal(raw, &c) != nil {
		return nil, "", false
	}
	now := m.now()
	exp, iat := time.Unix(c.EXP, 0), time.Unix(c.IAT, 0)
	if now.After(exp) || now.Sub(iat) > m.opt.MaxAge {
		return nil, "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadIfChanged()
	u := m.users[c.U]
	if u == nil || u.Gen != c.G {
		return nil, "", false
	}
	if _, gone := m.revoked[c.SID]; gone {
		return nil, "", false
	}
	s = &Session{User: u.Name, Role: u.Role, MustChange: u.MustChange, ID: c.SID, AuthTime: iat, Expires: exp}
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

// CheckBasic 校验 HTTP Basic 认证（供脚本调用 API）。成功结果缓存 5 分钟，失败计入锁定统计。
func (m *Manager) CheckBasic(user, password, ip string) (*Session, error) {
	sum := sha256.Sum256([]byte(user + "\x00" + password))
	key := hex.EncodeToString(sum[:])
	now := m.now()
	if v, ok := m.basicOK.Load(key); ok && now.Before(v.(time.Time)) {
		m.mu.Lock()
		u := m.users[user]
		m.mu.Unlock()
		if u != nil {
			return &Session{User: u.Name, Role: u.Role, MustChange: u.MustChange, ID: "basic", AuthTime: now, Expires: now.Add(time.Minute)}, nil
		}
	}
	s, _, err := m.Login(user, password, ip, "HTTP Basic")
	if err != nil {
		return nil, err
	}
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
	ErrBadRole      = errors.New("角色只能为 admin（管理员）或 viewer（只读）")
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
	s := &Session{User: u.Name, Role: u.Role, ID: randomID(), AuthTime: now, Expires: now.Add(m.opt.TTL)}
	return m.sign(s, u.Gen), nil
}

// Users 返回全部账号。
func (m *Manager) Users() []UserView {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reloadIfChanged()
	out := make([]UserView, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, UserView{Name: u.Name, Role: u.Role, Created: u.Created, Changed: u.Changed, MustChange: u.MustChange, LastLogin: u.LastLogin, Source: u.Source})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// CreateUser 新增账号（初始密码需在首次登录后修改）。
func (m *Manager) CreateUser(name, role, password string) error {
	if !nameRe.MatchString(name) {
		return ErrBadName
	}
	if role != RoleAdmin && role != RoleViewer {
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
	if role != "" && role != RoleAdmin && role != RoleViewer {
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
	m.basicOK.Range(func(k, _ any) bool { m.basicOK.Delete(k); return true })
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
	m := &Manager{opt: Options{File: file}, users: map[string]*User{}, revoked: map[string]time.Time{}, fails: map[string]*failure{}, nowFunc: time.Now}
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
