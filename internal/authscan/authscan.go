// Package authscan 管理授权扫描登记：渗透测试、漏洞扫描、等保测评等经过授权的扫描，登记扫描源（地址或网段）
// 与起止时间后，期间这些来源的流量只记录、不告警，不计入攻击统计、威胁评分与自学习；时间窗结束后自动恢复检测。
//
// 与配置文件中的 detect.whitelist（永久信任的来源）和误报抑制（按规则 / 目标抑制某一类误报）不同：
// 授权扫描有明确的时间窗，到期不需要人工撤销；期间命中的攻击类型、目标与次数仍按登记汇总，测试结束后可以核对。
package authscan

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

const (
	maxEntries     = 500
	maxDuration    = 90 * 24 * time.Hour // 单次登记的最长时间窗
	endedKeep      = 180 * 24 * time.Hour
	maxCats        = 30
	maxTargets     = 20
	minPrefixV4    = 16 // 网段范围：IPv4 至少 /16，IPv6 至少 /48
	minPrefixV6    = 48
	startLeeway    = 24 * time.Hour // 开始时间最多回溯一天（补登已经开始的测试）
	immediateSlack = time.Minute    // 立即开始的登记向前覆盖的时间
	lateLogs       = 24 * time.Hour // 登记结束后仍按日志时间匹配多久：积压、补录的日志中，时间窗内的扫描同样放行
	futureWindow   = time.Hour      // 日志时间晚于当前时间超过该值时按当前时间判断（设备时钟错误）
)

// 登记状态。
const (
	StatusPending = "pending" // 未开始
	StatusActive  = "active"  // 生效中
	StatusEnded   = "ended"   // 已结束
)

// Entry 是一条授权扫描登记。
type Entry struct {
	ID         string           `json:"id"`
	IP         string           `json:"ip"` // 扫描源地址或网段
	Start      time.Time        `json:"start"`
	End        time.Time        `json:"end"`
	Note       string           `json:"note"` // 说明：授权单位、测试范围、工单号
	Creator    string           `json:"creator"`
	Created    time.Time        `json:"created"`
	Ended      bool             `json:"ended,omitempty"` // 提前结束
	Status     string           `json:"status"`
	Events     int64            `json:"events"`               // 期间的请求 / 连接数
	Hits       int64            `json:"hits"`                 // 期间按规则本应告警的命中数
	Categories map[string]int64 `json:"categories,omitempty"` // 攻击类型 → 命中次数
	Targets    map[string]int64 `json:"targets,omitempty"`    // 被扫描的目标（站点 / 主机）→ 命中次数
	FirstSeen  time.Time        `json:"first_seen,omitempty"`
	LastSeen   time.Time        `json:"last_seen,omitempty"`

	prefix netip.Prefix
}

func (e *Entry) status(now time.Time) string {
	switch {
	case now.Before(e.Start):
		return StatusPending
	case now.Before(e.End):
		return StatusActive
	}
	return StatusEnded
}

// Manager 管理授权扫描登记，可并发匹配。
type Manager struct {
	mu      sync.Mutex
	path    string
	entries []*Entry
	byID    map[string]*Entry
	// active 是尚未结束的登记（匹配用，按时间判断是否生效）。登记对象的地址、起止时间创建后不再修改：
	// 提前结束时换成新的对象，Match 不加锁读取也不会与修改冲突
	active atomic.Pointer[[]*Entry]
	dirty  bool
	total  atomic.Int64 // 累计按登记放行的命中数
	now    func() time.Time
}

// Load 加载登记文件（不存在时为空）。path 为空时只保存在内存中。
func Load(path string) (*Manager, error) {
	m := &Manager{path: path, now: time.Now}
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			var saved struct {
				Entries []*Entry `json:"entries"`
				Total   int64    `json:"total"`
			}
			if err := json.Unmarshal(data, &saved); err != nil {
				return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
			}
			for _, e := range saved.Entries {
				if e == nil || e.ID == "" {
					continue
				}
				if p, err := parsePrefix(e.IP); err == nil {
					e.prefix = p
					m.entries = append(m.entries, e)
				}
			}
			m.total.Store(saved.Total)
		}
	}
	m.reindexLocked()
	return m, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-(p.Addr().BitLen()-p.Addr().Unmap().BitLen())).Masked()
		if p.Addr().Is4() && p.Bits() < minPrefixV4 || !p.Addr().Is4() && p.Bits() < minPrefixV6 {
			return netip.Prefix{}, fmt.Errorf("网段范围过大（IPv4 至少 /%d，IPv6 至少 /%d）", minPrefixV4, minPrefixV6)
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("扫描源地址或网段无效: %s", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// reindexLocked 重建匹配用的列表（调用方持锁）。
func (m *Manager) reindexLocked() {
	now := m.now()
	var live []*Entry
	m.byID = make(map[string]*Entry, len(m.entries))
	for _, e := range m.entries {
		m.byID[e.ID] = e
		if now.Before(e.End.Add(lateLogs)) {
			live = append(live, e)
		}
	}
	m.active.Store(&live)
}

// Match 返回地址在事件时间所处的生效登记，没有时返回 nil。没有生效中的登记时不做任何解析。
func (m *Manager) Match(ip string, t time.Time) *Entry {
	if m == nil {
		return nil
	}
	live := m.active.Load()
	if live == nil || len(*live) == 0 || ip == "" {
		return nil
	}
	now := m.now()
	if t.IsZero() || t.After(now.Add(futureWindow)) {
		t = now
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	a = a.Unmap()
	for _, e := range *live {
		if !t.Before(e.Start) && t.Before(e.End) && e.prefix.Contains(a) {
			return e
		}
	}
	return nil
}

// Record 把一次被放行的事件计入登记：事件数，以及本应告警的命中（攻击类型、目标）。
func (m *Manager) Record(e *Entry, ev *model.Event, hits []model.Hit) {
	if m == nil || e == nil {
		return
	}
	t := ev.Time
	if t.IsZero() {
		t = m.now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur := m.byID[e.ID]; cur != nil {
		e = cur // 匹配之后被提前结束、换成了新的对象
	}
	e.Events++
	if e.FirstSeen.IsZero() || t.Before(e.FirstSeen) {
		e.FirstSeen = t
	}
	if t.After(e.LastSeen) {
		e.LastSeen = t
	}
	target := ""
	for _, h := range hits {
		if h.TagOnly {
			continue
		}
		e.Hits++
		m.total.Add(1)
		bump(&e.Categories, h.Category, maxCats)
		if target == "" {
			target = targetOf(ev)
		}
		bump(&e.Targets, target, maxTargets)
	}
	m.dirty = true
}

func targetOf(ev *model.Event) string {
	switch {
	case ev.Kind == model.KindWeb && ev.Host != "":
		return ev.Host
	case ev.DstIP != "":
		return ev.DstIP
	}
	return ev.Target()
}

func bump(m *map[string]int64, k string, limit int) {
	if k == "" {
		return
	}
	if *m == nil {
		*m = map[string]int64{}
	}
	if _, ok := (*m)[k]; ok || len(*m) < limit {
		(*m)[k]++
	}
}

// Add 新增一条登记。开始时间为空表示立即开始；最多回溯一天，时间窗最长 90 天。
func (m *Manager) Add(e Entry) (Entry, error) {
	now := m.now()
	e.IP, e.Note = strings.TrimSpace(e.IP), strings.TrimSpace(e.Note)
	p, err := parsePrefix(e.IP)
	if err != nil {
		return Entry{}, err
	}
	if e.Note == "" {
		return Entry{}, errors.New("请填写说明（授权单位、测试范围或工单号）")
	}
	if utf8.RuneCountInString(e.Note) > 200 || utf8.RuneCountInString(e.Creator) > 64 {
		return Entry{}, errors.New("说明过长（最多 200 字）")
	}
	if e.Start.IsZero() {
		// 立即开始：向前留 1 分钟，容许设备与平台之间的时钟误差、只精确到秒的日志时间
		// （否则登记之后马上开始的扫描，日志时间比登记时刻早几百毫秒就匹配不上）
		e.Start = now.Add(-immediateSlack)
	}
	switch {
	case e.End.IsZero():
		return Entry{}, errors.New("请填写结束时间")
	case !e.End.After(e.Start):
		return Entry{}, errors.New("结束时间必须晚于开始时间")
	case !e.End.After(now):
		return Entry{}, errors.New("结束时间已过")
	case e.Start.Before(now.Add(-startLeeway)):
		return Entry{}, errors.New("开始时间最多回溯 24 小时")
	case e.End.Sub(e.Start) > maxDuration:
		return Entry{}, errors.New("单次登记的时间窗最长 90 天")
	}
	b := make([]byte, 6)
	rand.Read(b)
	n := &Entry{ID: hex.EncodeToString(b), IP: p.String(), Start: e.Start, End: e.End, Note: e.Note, Creator: e.Creator, Created: now, prefix: p}
	if p.IsSingleIP() {
		n.IP = p.Addr().String()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	if len(m.entries) >= maxEntries {
		return Entry{}, fmt.Errorf("登记数量已达上限（%d 条），请先删除已结束的登记", maxEntries)
	}
	m.entries = append(m.entries, n)
	m.reindexLocked()
	return n.view(now), m.saveLocked()
}

// Finish 提前结束一条登记（保留记录与期间的统计，之后该来源恢复检测）。
func (m *Manager) Finish(id string) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for i, e := range m.entries {
		if e.ID != id {
			continue
		}
		if !now.Before(e.End) {
			return Entry{}, errors.New("登记已结束")
		}
		n := *e
		n.End, n.Ended = now, true
		if n.Start.After(now) {
			n.Start = now
		}
		m.entries[i] = &n
		m.reindexLocked()
		return n.view(now), m.saveLocked()
	}
	return Entry{}, errors.New("登记不存在")
}

// Delete 删除一条登记。
func (m *Manager) Delete(id string) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.entries {
		if e.ID == id {
			m.entries = append(m.entries[:i:i], m.entries[i+1:]...)
			m.reindexLocked()
			return e.view(m.now()), m.saveLocked()
		}
	}
	return Entry{}, errors.New("登记不存在")
}

func (e *Entry) view(now time.Time) Entry {
	c := *e
	c.Status = e.status(now)
	c.Categories, c.Targets = copyMap(e.Categories), copyMap(e.Targets)
	return c
}

func copyMap(m map[string]int64) map[string]int64 {
	if m == nil {
		return nil
	}
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// List 返回全部登记：生效中的在前，其次未开始，最后已结束（各自按时间倒序）。
func (m *Manager) List() []Entry {
	if m == nil {
		return []Entry{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.view(now))
	}
	rank := map[string]int{StatusActive: 0, StatusPending: 1, StatusEnded: 2}
	sort.Slice(out, func(i, j int) bool {
		if a, b := rank[out[i].Status], rank[out[j].Status]; a != b {
			return a < b
		}
		return out[i].Start.After(out[j].Start)
	})
	return out
}

// Active 返回当前生效中的登记数。
func (m *Manager) Active() int {
	if m == nil {
		return 0
	}
	live := m.active.Load()
	if live == nil {
		return 0
	}
	now, n := m.now(), 0
	for _, e := range *live {
		if !now.Before(e.Start) && now.Before(e.End) {
			n++
		}
	}
	return n
}

// Total 返回累计按登记放行的命中数。
func (m *Manager) Total() int64 {
	if m == nil {
		return 0
	}
	return m.total.Load()
}

// Flush 保存期间的统计并清理结束已久的登记（由后台任务定期调用）；同时让到期的登记不再参与匹配。
func (m *Manager) Flush() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pruned := m.pruneLocked(m.now())
	m.reindexLocked()
	if !m.dirty && !pruned {
		return nil
	}
	m.dirty = false
	return m.saveLocked()
}

// pruneLocked 删除结束超过 180 天的登记（调用方持锁）。
func (m *Manager) pruneLocked(now time.Time) bool {
	kept := m.entries[:0]
	for _, e := range m.entries {
		if now.Before(e.End.Add(endedKeep)) {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(m.entries) {
		return false
	}
	clear(m.entries[len(kept):])
	m.entries = kept
	return true
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	now := m.now()
	out := struct {
		Entries []Entry `json:"entries"`
		Total   int64   `json:"total"`
	}{Entries: []Entry{}, Total: m.total.Load()}
	for _, e := range m.entries {
		out.Entries = append(out.Entries, e.view(now))
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
		return fmt.Errorf("保存授权扫描登记失败: %w", err)
	}
	return os.Rename(tmp, m.path)
}
