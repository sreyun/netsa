// Package suppress 管理误报抑制规则：运营人员把告警标记为误报时，可按规则、攻击类型、来源 IP / 网段、
// 目标路径的组合抑制后续同类命中。被抑制的命中不产生告警、不计入攻击统计与威胁评分，只累计抑制次数用于审计。
package suppress

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"netsa/internal/model"
)

// Rule 是一条抑制规则：所有已填写的条件同时满足时生效。
type Rule struct {
	ID       string    `json:"id"`
	RuleID   string    `json:"rule_id,omitempty"`  // 检测规则 ID
	Category string    `json:"category,omitempty"` // 攻击类型
	IP       string    `json:"ip,omitempty"`       // 来源 IP 或网段
	Target   string    `json:"target,omitempty"`   // 目标包含的文本（如路径 /api/search），不区分大小写
	Reason   string    `json:"reason"`
	Creator  string    `json:"creator"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitempty"` // 为空表示永久
	Hits     int64     `json:"hits"`
	LastHit  time.Time `json:"last_hit,omitempty"`

	prefix netip.Prefix
	target string     // 小写
	st     *ruleStats // 计数（规则值可安全复制）
}

type ruleStats struct {
	hits atomic.Int64
	last atomic.Int64 // Unix 秒
}

// Manager 管理抑制规则，可并发匹配。
type Manager struct {
	mu     sync.RWMutex
	path   string
	rules  []*Rule
	byRule map[string][]*Rule // 指定了规则 ID 的抑制规则
	other  []*Rule            // 未指定规则 ID 的抑制规则
	total  atomic.Int64       // 累计抑制的命中数
	dirty  atomic.Bool
	now    func() time.Time
}

// Load 加载抑制规则文件（不存在时为空）。path 为空时只保存在内存中。
func Load(path string) (*Manager, error) {
	m := &Manager{path: path, byRule: map[string][]*Rule{}, now: time.Now}
	if path == "" {
		return m, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var saved struct {
		Rules []*Rule `json:"rules"`
		Total int64   `json:"total"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	for _, r := range saved.Rules {
		if r == nil || r.ID == "" || r.prepare() != nil {
			continue
		}
		r.st.hits.Store(r.Hits)
		if !r.LastHit.IsZero() {
			r.st.last.Store(r.LastHit.Unix())
		}
		m.rules = append(m.rules, r)
	}
	m.total.Store(saved.Total)
	m.reindex()
	return m, nil
}

func (r *Rule) prepare() error {
	r.RuleID, r.Category, r.IP, r.Target = strings.TrimSpace(r.RuleID), strings.TrimSpace(r.Category), strings.TrimSpace(r.IP), strings.TrimSpace(r.Target)
	r.Reason = strings.TrimSpace(r.Reason)
	if r.RuleID == "" && r.Category == "" && r.IP == "" && r.Target == "" {
		return errors.New("至少填写一个条件（规则 ID、攻击类型、来源 IP / 网段或目标）")
	}
	if r.IP == "" && r.Target == "" && r.RuleID == "" {
		return errors.New("只按攻击类型抑制范围过大，请同时限定来源 IP、目标或规则")
	}
	if utf8.RuneCountInString(r.Target) > 200 || utf8.RuneCountInString(r.Reason) > 200 || len(r.RuleID) > 64 || utf8.RuneCountInString(r.Category) > 40 {
		return errors.New("条件或原因过长")
	}
	r.prefix = netip.Prefix{}
	if r.IP != "" {
		if p, err := netip.ParsePrefix(r.IP); err == nil {
			r.prefix = p.Masked()
		} else if a, err := netip.ParseAddr(r.IP); err == nil {
			a = a.Unmap()
			r.prefix = netip.PrefixFrom(a, a.BitLen())
		} else {
			return fmt.Errorf("来源 IP 或网段无效: %s", r.IP)
		}
		if r.prefix.Bits() < 8 {
			return errors.New("网段范围过大（前缀至少 /8）")
		}
	}
	r.target = strings.ToLower(r.Target)
	if r.st == nil {
		r.st = &ruleStats{}
	}
	return nil
}

func (m *Manager) reindex() {
	m.byRule, m.other = map[string][]*Rule{}, nil
	for _, r := range m.rules {
		if r.RuleID != "" {
			m.byRule[r.RuleID] = append(m.byRule[r.RuleID], r)
		} else {
			m.other = append(m.other, r)
		}
	}
}

func (r *Rule) matches(ev *model.Event, h *model.Hit, ip netip.Addr, ipOK bool, target *string, now time.Time) bool {
	if !r.Expires.IsZero() && now.After(r.Expires) {
		return false
	}
	if r.Category != "" && r.Category != h.Category {
		return false
	}
	if r.prefix.IsValid() && (!ipOK || !r.prefix.Contains(ip)) {
		return false
	}
	if r.target != "" {
		if *target == "" {
			*target = strings.ToLower(ev.Target())
		}
		if !strings.Contains(*target, r.target) {
			return false
		}
	}
	return true
}

// Filter 去掉被抑制的命中（仅打标签的命中保留）。没有命中被抑制时原样返回，不分配内存。
func (m *Manager) Filter(ev *model.Event, hits []model.Hit) []model.Hit {
	if m == nil || len(hits) == 0 {
		return hits
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.rules) == 0 {
		return hits
	}
	now := m.now()
	ip, err := netip.ParseAddr(ev.SrcIP)
	ipOK := err == nil
	if ipOK {
		ip = ip.Unmap()
	}
	var target string
	var out []model.Hit
	for i := range hits {
		h := &hits[i]
		var hit *Rule
		if !h.TagOnly {
			for _, list := range [2][]*Rule{m.byRule[h.RuleID], m.other} {
				for _, r := range list {
					if r.matches(ev, h, ip, ipOK, &target, now) {
						hit = r
						break
					}
				}
				if hit != nil {
					break
				}
			}
		}
		if hit == nil {
			if out != nil {
				out = append(out, *h)
			}
			continue
		}
		hit.st.hits.Add(1)
		hit.st.last.Store(now.Unix())
		m.total.Add(1)
		m.dirty.Store(true)
		if out == nil {
			out = append(make([]model.Hit, 0, len(hits)), hits[:i]...)
		}
	}
	if out == nil {
		return hits
	}
	return out
}

// Add 新增抑制规则。days 为 0 表示永久。
func (m *Manager) Add(r Rule, days int) (Rule, error) {
	if days < 0 || days > 3650 {
		return Rule{}, errors.New("有效期为 0（永久）~ 3650 天")
	}
	if err := r.prepare(); err != nil {
		return Rule{}, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	r.ID, r.Created, r.Hits, r.LastHit, r.st = hex.EncodeToString(b), m.now(), 0, time.Time{}, &ruleStats{}
	if days > 0 {
		r.Expires = r.Created.Add(time.Duration(days) * 24 * time.Hour)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rules) >= 1000 {
		return Rule{}, errors.New("抑制规则数量已达上限（1000 条）")
	}
	nr := r
	m.rules = append(m.rules, &nr)
	m.reindex()
	return nr.snapshot(), m.saveLocked()
}

// Delete 删除抑制规则。
func (m *Manager) Delete(id string) (Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, r := range m.rules {
		if r.ID == id {
			m.rules = append(m.rules[:i:i], m.rules[i+1:]...)
			m.reindex()
			return r.snapshot(), m.saveLocked()
		}
	}
	return Rule{}, errors.New("抑制规则不存在")
}

func (r *Rule) snapshot() Rule {
	c := Rule{ID: r.ID, RuleID: r.RuleID, Category: r.Category, IP: r.IP, Target: r.Target, Reason: r.Reason, Creator: r.Creator,
		Created: r.Created, Expires: r.Expires, Hits: r.st.hits.Load()}
	if t := r.st.last.Load(); t > 0 {
		c.LastHit = time.Unix(t, 0)
	}
	return c
}

// List 返回全部抑制规则（新的在前）。
func (m *Manager) List() []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Rule, 0, len(m.rules))
	for _, r := range m.rules {
		out = append(out, r.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Total 返回累计抑制的命中数。
func (m *Manager) Total() int64 {
	if m == nil {
		return 0
	}
	return m.total.Load()
}

// Count 返回规则数。
func (m *Manager) Count() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}

// Flush 保存抑制计数（计数变化时，由后台任务定期调用）。
func (m *Manager) Flush() error {
	if m == nil || !m.dirty.Swap(false) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	out := struct {
		Rules []Rule `json:"rules"`
		Total int64  `json:"total"`
	}{Rules: []Rule{}, Total: m.total.Load()}
	for _, r := range m.rules {
		out.Rules = append(out.Rules, r.snapshot())
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("保存抑制规则失败: %w", err)
	}
	return os.Rename(tmp, m.path)
}
