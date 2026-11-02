// Package block 实现联动封禁：分析员或剧本提交申请，管理员审批后生效，到期自动解除。
//
// 误封业务比漏封一个扫描源的代价大得多，所以有这些边界：内网地址和保护名单永不封禁；不能封禁网段；
// 申请人不能批准自己的申请（可配置）；每条封禁都有有效期。防火墙通过 /api/block/edl 拉取生效名单
// （外部动态列表），也可以配置 Webhook 推送到防火墙管理接口或自动化平台。
package block

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/config"
)

// 状态。
const (
	StatusPending  = "pending"
	StatusActive   = "active"
	StatusRejected = "rejected"
	StatusReleased = "released" // 人工解除
	StatusExpired  = "expired"
)

const (
	defaultTTL = 24 * time.Hour
	defaultMax = 30 * 24 * time.Hour
	maxItems   = 20000
)

// 错误。
var (
	ErrDisabled = errors.New("联动封禁未启用（配置 block.enabled）")
	ErrNotFound = errors.New("封禁记录不存在")
	ErrState    = errors.New("当前状态不能执行该操作")
	ErrSelf     = errors.New("不能批准自己提交的申请，请由另一位管理员审批")
)

// ProtectedError 表示地址不允许封禁。
type ProtectedError struct{ Reason string }

func (e *ProtectedError) Error() string { return e.Reason }

// Item 是一条封禁记录。
type Item struct {
	ID          uint64        `json:"id"`
	IP          string        `json:"ip"`
	Status      string        `json:"status"`
	Reason      string        `json:"reason"`
	IncidentID  uint64        `json:"incident_id,omitempty"`
	RequestedBy string        `json:"requested_by"`
	DecidedBy   string        `json:"decided_by,omitempty"`
	Note        string        `json:"note,omitempty"`
	TTL         time.Duration `json:"ttl"`
	Created     time.Time     `json:"created"`
	Decided     time.Time     `json:"decided,omitzero"`
	Expires     time.Time     `json:"expires,omitzero"`
	Closed      time.Time     `json:"closed,omitzero"`
}

// Options 是封禁管理的参数。
type Options struct {
	Cfg       config.BlockConfig
	Path      string
	IsPrivate func(string) bool      // 内网判断
	Whitelist []string               // detect.whitelist：信任的来源同样不能封禁
	Audit     func(user, msg string) // 审计
	Token     string                 // Webhook 的令牌
}

type event struct {
	Action  string    `json:"action"` // block / unblock
	ID      uint64    `json:"id"`
	IP      string    `json:"ip"`
	Reason  string    `json:"reason,omitempty"`
	Expires time.Time `json:"expires,omitzero"`
}

// Manager 管理封禁记录。
type Manager struct {
	opt     Options
	protect []netip.Prefix
	client  *http.Client
	events  chan event
	failed  atomic.Int64
	nowFunc func() time.Time

	mu    sync.Mutex
	items map[uint64]*Item
	next  uint64
}

// New 创建封禁管理器并加载记录。未启用时返回 nil（方法对 nil 返回 ErrDisabled 或空结果）。
func New(opt Options) (*Manager, error) {
	if !opt.Cfg.Enabled {
		return nil, nil
	}
	m := &Manager{opt: opt, items: map[uint64]*Item{}, client: &http.Client{Timeout: 10 * time.Second}, events: make(chan event, 1000), nowFunc: time.Now}
	if m.opt.Cfg.DefaultTTL <= 0 {
		m.opt.Cfg.DefaultTTL = defaultTTL
	}
	if m.opt.Cfg.MaxTTL <= 0 {
		m.opt.Cfg.MaxTTL = defaultMax
	}
	for _, s := range append(append([]string(nil), opt.Cfg.Protect...), opt.Whitelist...) {
		p, err := parsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("block.protect %q: %w", s, err)
		}
		m.protect = append(m.protect, p)
	}
	if opt.Path != "" {
		data, err := os.ReadFile(opt.Path)
		if err == nil {
			var list []*Item
			if err := json.Unmarshal(data, &list); err != nil {
				return nil, fmt.Errorf("读取封禁记录 %s: %w", opt.Path, err)
			}
			for _, it := range list {
				m.items[it.ID] = it
				if it.ID > m.next {
					m.next = it.ID
				}
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return m, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// check 判断地址能否封禁。只接受单个地址：封禁网段容易误伤整个运营商或业务合作方。
func (m *Manager) check(ip string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", &ProtectedError{"地址无效，只能封禁单个 IP"}
	}
	a = a.Unmap().WithZone("")
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return "", &ProtectedError{"内网或保留地址不能封禁"}
	}
	if m.opt.IsPrivate != nil && m.opt.IsPrivate(a.String()) {
		return "", &ProtectedError{"内网地址不能封禁"}
	}
	for _, p := range m.protect {
		if p.Contains(a) {
			return "", &ProtectedError{"地址在保护名单中，不能封禁：" + p.String()}
		}
	}
	return a.String(), nil
}

func (m *Manager) saveLocked() error {
	if m.opt.Path == "" {
		return nil
	}
	list := make([]*Item, 0, len(m.items))
	for _, it := range m.items {
		list = append(list, it)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	data, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.opt.Path), 0o700); err != nil {
		return err
	}
	tmp := m.opt.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.opt.Path)
}

func (m *Manager) audit(user, msg string) {
	if m.opt.Audit != nil {
		m.opt.Audit(user, msg)
	}
}

// Request 提交封禁申请。同一地址已有待审批或生效中的记录时直接返回该记录。
func (m *Manager) Request(ip, reason string, ttl time.Duration, incident uint64, user string) (*Item, error) {
	if m == nil {
		return nil, ErrDisabled
	}
	addr, err := m.check(ip)
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, errors.New("请填写封禁原因")
	}
	if len([]rune(reason)) > 500 {
		return nil, errors.New("封禁原因不能超过 500 个字符")
	}
	if ttl <= 0 {
		ttl = m.opt.Cfg.DefaultTTL
	}
	if ttl > m.opt.Cfg.MaxTTL {
		ttl = m.opt.Cfg.MaxTTL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, it := range m.items {
		if it.IP == addr && (it.Status == StatusPending || it.Status == StatusActive) {
			cp := *it
			return &cp, nil
		}
	}
	if len(m.items) >= maxItems {
		m.pruneLocked()
	}
	m.next++
	it := &Item{ID: m.next, IP: addr, Status: StatusPending, Reason: reason, IncidentID: incident, RequestedBy: user, TTL: ttl, Created: m.nowFunc()}
	m.items[it.ID] = it
	if err := m.saveLocked(); err != nil {
		log.Printf("[block] 保存封禁记录失败: %v", err)
	}
	m.audit(user, fmt.Sprintf("提交封禁申请 #%d %s，时长 %s", it.ID, addr, ttl))
	cp := *it
	return &cp, nil
}

func (m *Manager) pruneLocked() {
	var closed []*Item
	for _, it := range m.items {
		if it.Status != StatusPending && it.Status != StatusActive {
			closed = append(closed, it)
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].ID < closed[j].ID })
	for i := 0; i < len(closed) && i < maxItems/10; i++ {
		delete(m.items, closed[i].ID)
	}
}

// Approve 批准申请：生效并开始计时。批准前重新检查保护名单，配置可能在申请后发生变化。
func (m *Manager) Approve(id uint64, user string) (*Item, error) {
	if m == nil {
		return nil, ErrDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	it := m.items[id]
	if it == nil {
		return nil, ErrNotFound
	}
	if it.Status != StatusPending {
		return nil, ErrState
	}
	if it.RequestedBy == user && !m.opt.Cfg.AllowSelfApprove {
		return nil, ErrSelf
	}
	if _, err := m.check(it.IP); err != nil {
		return nil, err
	}
	now := m.nowFunc()
	it.Status, it.DecidedBy, it.Decided, it.Expires = StatusActive, user, now, now.Add(it.TTL)
	if err := m.saveLocked(); err != nil {
		log.Printf("[block] 保存封禁记录失败: %v", err)
	}
	m.audit(user, fmt.Sprintf("批准封禁 #%d %s，%s 到期", it.ID, it.IP, it.Expires.Format(time.DateTime)))
	m.emit(event{Action: "block", ID: it.ID, IP: it.IP, Reason: it.Reason, Expires: it.Expires})
	cp := *it
	return &cp, nil
}

// Reject 驳回申请。
func (m *Manager) Reject(id uint64, user, note string) (*Item, error) {
	if m == nil {
		return nil, ErrDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	it := m.items[id]
	if it == nil {
		return nil, ErrNotFound
	}
	if it.Status != StatusPending {
		return nil, ErrState
	}
	now := m.nowFunc()
	it.Status, it.DecidedBy, it.Decided, it.Closed, it.Note = StatusRejected, user, now, now, note
	if err := m.saveLocked(); err != nil {
		log.Printf("[block] 保存封禁记录失败: %v", err)
	}
	m.audit(user, fmt.Sprintf("驳回封禁申请 #%d %s", it.ID, it.IP))
	cp := *it
	return &cp, nil
}

// Release 人工解除生效中的封禁。
func (m *Manager) Release(id uint64, user, note string) (*Item, error) {
	if m == nil {
		return nil, ErrDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	it := m.items[id]
	if it == nil {
		return nil, ErrNotFound
	}
	if it.Status != StatusActive {
		return nil, ErrState
	}
	it.Status, it.Closed, it.Note = StatusReleased, m.nowFunc(), note
	if err := m.saveLocked(); err != nil {
		log.Printf("[block] 保存封禁记录失败: %v", err)
	}
	m.audit(user, fmt.Sprintf("解除封禁 #%d %s", it.ID, it.IP))
	m.emit(event{Action: "unblock", ID: it.ID, IP: it.IP})
	cp := *it
	return &cp, nil
}

// Tick 解除到期的封禁，由后台任务定期调用。
func (m *Manager) Tick() int {
	if m == nil {
		return 0
	}
	now := m.nowFunc()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, it := range m.items {
		if it.Status == StatusActive && now.After(it.Expires) {
			it.Status, it.Closed = StatusExpired, now
			m.audit("系统", fmt.Sprintf("封禁 #%d %s 到期，已自动解除", it.ID, it.IP))
			m.emit(event{Action: "unblock", ID: it.ID, IP: it.IP})
			n++
		}
	}
	if n > 0 {
		if err := m.saveLocked(); err != nil {
			log.Printf("[block] 保存封禁记录失败: %v", err)
		}
	}
	return n
}

// List 返回记录，新的在前，最多 limit 条。
func (m *Manager) List(limit int) []Item {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Item, 0, len(m.items))
	for _, it := range m.items {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Active 返回生效中的地址（已到期但后台任务还没处理的不算），供防火墙拉取。
func (m *Manager) Active() []string {
	if m == nil {
		return nil
	}
	now := m.nowFunc()
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, it := range m.items {
		if it.Status == StatusActive && !now.After(it.Expires) {
			out = append(out, it.IP)
		}
	}
	sort.Strings(out)
	return out
}

// Counts 返回待审批和生效中的数量。
func (m *Manager) Counts() (pending, active int) {
	if m == nil {
		return 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, it := range m.items {
		switch it.Status {
		case StatusPending:
			pending++
		case StatusActive:
			active++
		}
	}
	return pending, active
}

// WebhookFailed 返回 Webhook 推送失败的次数。
func (m *Manager) WebhookFailed() int64 {
	if m == nil {
		return 0
	}
	return m.failed.Load()
}

func (m *Manager) emit(e event) {
	if m.opt.Cfg.WebhookURL == "" {
		return
	}
	select {
	case m.events <- e:
	default:
		m.failed.Add(1)
		log.Printf("[block] Webhook 队列已满，丢弃 %s %s（防火墙仍可从 /api/block/edl 拉取最新名单）", e.Action, e.IP)
	}
}

// Run 推送 Webhook 并定期处理到期。
func (m *Manager) Run(ctx context.Context) {
	if m == nil {
		return
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m.Tick()
		case e := <-m.events:
			m.push(ctx, e)
		}
	}
}

func (m *Manager) push(ctx context.Context, e event) {
	body, err := json.Marshal(e)
	if err != nil {
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.opt.Cfg.WebhookURL, bytes.NewReader(body))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		if m.opt.Token != "" {
			req.Header.Set("Authorization", "Bearer "+m.opt.Token)
		}
		resp, err := m.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
			err = errors.New("HTTP " + strconv.Itoa(resp.StatusCode))
		}
		log.Printf("[block] Webhook 推送 %s %s 失败: %v", e.Action, e.IP, err)
	}
	m.failed.Add(1)
}
