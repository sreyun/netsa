package ingest

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
	"unicode"
	"unicode/utf8"

	"netsa/internal/config"
	"netsa/internal/parser"
)

// syslog 接收协议（发送端画像中按位记录）。
const (
	ProtoUDP = 1 << iota
	ProtoTCP
	ProtoTLS
)

var protoNames = [...]string{"UDP", "TCP", "TLS"}

func protoIndex(p int) int {
	switch p {
	case ProtoTCP:
		return 1
	case ProtoTLS:
		return 2
	}
	return 0
}

// 发送端规则动作。
const (
	SenderAllow = "allow"
	SenderBlock = "block"
)

const (
	maxSenderRules   = 2000
	maxSenderStats   = 4096
	rejectNoticeGap  = 6 * time.Hour // 同一未授权发送端的拒绝通知间隔
	maxNoticesQueued = 200
	maxRejectPerHour = 30 // 每小时最多产生的拒绝通知数（伪造源地址的 UDP 洪泛不会刷屏）
)

// SenderRule 是一条发送端登记：按 IP 或网段登记设备名称、分组，允许或阻止其发送日志。
type SenderRule struct {
	ID      string    `json:"id"`
	CIDR    string    `json:"cidr"`
	Name    string    `json:"name,omitempty"`
	Group   string    `json:"group,omitempty"`
	Action  string    `json:"action"`            // allow / block
	Silence string    `json:"silence,omitempty"` // 断流告警阈值；off 关闭；为空使用默认值
	Note    string    `json:"note,omitempty"`
	Source  string    `json:"source"` // config 配置文件（只读）/ ui 界面登记
	Creator string    `json:"creator,omitempty"`
	Created time.Time `json:"created,omitempty"`
	Updated time.Time `json:"updated,omitempty"`

	prefix  netip.Prefix
	silence time.Duration // 生效的断流阈值，0 为关闭
}

// policy 是不可变的规则快照，规则或模式变化时整体替换，匹配时无锁。
type policy struct {
	gen       uint64
	allowlist bool
	exact     map[netip.Addr]*SenderRule
	nets      []*SenderRule // 网段规则，按前缀从长到短
}

func (p *policy) match(a netip.Addr) *SenderRule {
	if r := p.exact[a]; r != nil {
		return r
	}
	for _, r := range p.nets {
		if r.prefix.Contains(a) {
			return r
		}
	}
	return nil
}

// permits 判断规则下是否接收该发送端的日志：阻止规则总是拒绝；白名单模式下只接收允许规则覆盖的发送端。
func (p *policy) permits(r *SenderRule) bool {
	if r != nil && r.Action == SenderBlock {
		return false
	}
	return !p.allowlist || r != nil
}

// senderStat 是一个发送端（源 IP）的运行画像：独立的格式识别、时区校正、限速与统计。
type senderStat struct {
	addr netip.Addr
	ip   string
	pa   atomic.Pointer[parser.Auto] // 格式识别器，首次解析时创建（被拒绝的来源不分配）
	fix  timeFix

	first, last, lastEvent                          atomic.Int64 // UnixNano：首次 / 最近接收时间，最近日志时间
	lines, parsed, failed, bytes, rejected, limited atomic.Int64
	protos                                          atomic.Uint32
	winSec, winCnt                                  atomic.Int64 // 限速窗口（秒）

	gen     atomic.Uint64 // 缓存的判定对应的规则版本
	rule    atomic.Pointer[SenderRule]
	allowed atomic.Bool
	labels  [3]atomic.Pointer[string] // 各监听的数据来源名称，例如 “syslog-udp 核心防火墙(10.0.0.1)”

	mu         sync.Mutex // 保护以下低频字段
	hostname   string     // syslog 头部中的主机名（经中继转发时用于区分设备）
	cert       string     // TLS 客户端证书主题
	sample     string     // 最近一条无法解析的日志
	lastNotice time.Time
	silent     bool     // 已推送断流告警，等待恢复
	ring       [6]int64 // 最近 5 分钟每分钟末的累计行数，用于计算速率
	ringN      int
	loaded     bool // 从文件恢复（重启前已出现过）
}

func newSenderStat(a netip.Addr) *senderStat {
	st := &senderStat{addr: a, ip: a.String()}
	st.fix.name = "syslog 发送端 " + st.ip
	return st
}

// parser 返回发送端的格式识别器（按需创建，并发安全）。
func (st *senderStat) parser() *parser.Auto {
	if p := st.pa.Load(); p != nil {
		return p
	}
	p, _ := parser.NewAuto("auto", "")
	if !st.pa.CompareAndSwap(nil, p) {
		return st.pa.Load()
	}
	return p
}

// detected 返回识别出的格式（还没有解析过日志时为空）。
func (st *senderStat) detected() string {
	if p := st.pa.Load(); p != nil {
		return p.Detected()
	}
	return ""
}

// take 按每秒上限限速，返回是否接收这一条。limit 为 0 不限速。
func (st *senderStat) take(limit, sec int64) bool {
	if limit <= 0 {
		return true
	}
	if st.winSec.Load() != sec {
		st.winSec.Store(sec)
		st.winCnt.Store(0)
	}
	if st.winCnt.Add(1) <= limit {
		return true
	}
	st.limited.Add(1)
	return false
}

func (st *senderStat) touch(now int64, proto int) {
	if st.first.Load() == 0 {
		st.first.CompareAndSwap(0, now)
	}
	st.last.Store(now)
	if p := uint32(proto); st.protos.Load()&p == 0 {
		for {
			old := st.protos.Load()
			if st.protos.CompareAndSwap(old, old|p) {
				break
			}
		}
	}
}

// SenderNotice 是需要推送的发送端通知。
type SenderNotice struct {
	Kind    string // rejected 未授权发送端被拒绝 / new 新发送端（未开启白名单时）/ silent 断流 / recovered 恢复
	IP      string
	Name    string
	Group   string
	Detail  string
	Last    time.Time // 最近一次收到日志的时间
	Silence time.Duration
}

// Senders 管理 syslog 发送端：登记（名称、分组）、白名单 / 阻止、限速与发送端画像。UDP / TCP / TLS 监听共用。
type Senders struct {
	pol       atomic.Pointer[policy]
	rateLimit int64
	defSil    time.Duration
	forced    bool // 配置文件开启了白名单，界面不能关闭

	mu       sync.RWMutex
	stats    map[netip.Addr]*senderStat
	cfgRules []*SenderRule
	uiRules  []*SenderRule
	uiAllow  *bool // 界面设置的白名单开关（优先于配置文件；配置文件强制开启时忽略）
	gen      uint64
	path     string

	nmu        sync.Mutex
	notices    []SenderNotice
	rejectHour int64
	rejectN    int
	dirty      atomic.Bool
	now        func() time.Time
}

// NewSenders 根据 syslog 配置创建发送端管理器；path 为空时界面登记的发送端只保存在内存中。
// defSilence 为断流告警的默认阈值（alert.source_silence），0 表示默认关闭。
func NewSenders(cfg config.SyslogConfig, path string, defSilence time.Duration) (*Senders, error) {
	s := &Senders{rateLimit: int64(cfg.RateLimit), defSil: defSilence, forced: cfg.Allowlist, stats: map[netip.Addr]*senderStat{}, path: path, now: time.Now}
	for i, c := range cfg.Senders {
		r := &SenderRule{ID: fmt.Sprintf("cfg-%d", i+1), CIDR: c.CIDR, Name: c.Name, Group: c.Group, Action: c.Action, Silence: c.Silence, Note: c.Note, Source: "config"}
		if err := s.prepare(r); err != nil {
			return nil, fmt.Errorf("syslog.senders[%d]: %w", i, err)
		}
		s.cfgRules = append(s.cfgRules, r)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.rebuildLocked()
	return s, nil
}

func cleanText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > limit {
		s = string([]rune(s)[:limit])
	}
	return s
}

func (s *Senders) prepare(r *SenderRule) error {
	p, err := config.ParseSenderCIDR(r.CIDR)
	if err != nil {
		return err
	}
	r.prefix = p
	if p.IsSingleIP() {
		r.CIDR = p.Addr().String()
	} else {
		r.CIDR = p.String()
	}
	switch r.Action = strings.TrimSpace(r.Action); r.Action {
	case "":
		r.Action = SenderAllow
	case SenderAllow, SenderBlock:
	default:
		return errors.New("动作只能为 allow（允许）或 block（阻止）")
	}
	r.Name, r.Group, r.Note = cleanText(r.Name, 40), cleanText(r.Group, 20), cleanText(r.Note, 200)
	r.Silence = strings.TrimSpace(r.Silence)
	if r.silence, err = config.ParseSilence(r.Silence, s.defSil); err != nil {
		return err
	}
	return nil
}

// rebuildLocked 生成新的规则快照（调用方持写锁或处于初始化阶段）。
func (s *Senders) rebuildLocked() {
	s.gen++
	p := &policy{gen: s.gen, allowlist: s.allowlistLocked(), exact: map[netip.Addr]*SenderRule{}}
	// 界面登记优先于配置文件：同一地址两处都有时以界面为准
	for _, list := range [][]*SenderRule{s.cfgRules, s.uiRules} {
		for _, r := range list {
			if r.prefix.IsSingleIP() {
				p.exact[r.prefix.Addr()] = r
			} else {
				p.nets = append(p.nets, r)
			}
		}
	}
	sort.SliceStable(p.nets, func(i, j int) bool { return p.nets[i].prefix.Bits() > p.nets[j].prefix.Bits() })
	s.pol.Store(p)
}

func (s *Senders) allowlistLocked() bool {
	if s.forced {
		return true
	}
	return s.uiAllow != nil && *s.uiAllow
}

// admit 返回发送端画像以及是否接收其日志（规则判定按版本缓存，每条消息只需一次原子比较）。
func (s *Senders) admit(a netip.Addr, proto int, listener string) (*senderStat, bool) {
	a = a.Unmap()
	s.mu.RLock()
	st := s.stats[a]
	s.mu.RUnlock()
	fresh := false
	if st == nil {
		s.mu.Lock()
		if st = s.stats[a]; st == nil {
			if len(s.stats) >= maxSenderStats {
				s.evictLocked()
			}
			st = newSenderStat(a)
			s.stats[a] = st
			fresh = true
		}
		s.mu.Unlock()
	}
	ok := s.permitted(st)
	now := s.now()
	st.touch(now.UnixNano(), proto)
	if !ok {
		st.rejected.Add(1)
		s.noteRejected(st, now)
		return st, false
	}
	if fresh && st.rule.Load() == nil && s.noticeQuota(now) {
		s.push(SenderNotice{Kind: "new", IP: st.ip, Detail: "通过 " + listener + " 首次发送日志，尚未登记"})
	}
	return st, true
}

// permitted 判断是否接收该发送端（规则变化后重新判定）。
func (s *Senders) permitted(st *senderStat) bool {
	p := s.pol.Load()
	if st.gen.Load() != p.gen {
		r := p.match(st.addr)
		st.rule.Store(r)
		st.allowed.Store(p.permits(r))
		for i := range st.labels {
			st.labels[i].Store(nil)
		}
		st.gen.Store(p.gen)
	}
	return st.allowed.Load()
}

// label 返回事件的数据来源名称（按监听缓存，避免每条日志拼接字符串）。
func (st *senderStat) label(listener string, proto int) string {
	i := protoIndex(proto)
	if l := st.labels[i].Load(); l != nil {
		return *l
	}
	l := listener + " " + st.ip
	if r := st.rule.Load(); r != nil && r.Name != "" {
		l = listener + " " + r.Name + "(" + st.ip + ")"
	}
	st.labels[i].Store(&l)
	return l
}

func (s *Senders) noteRejected(st *senderStat, now time.Time) {
	st.mu.Lock()
	if now.Sub(st.lastNotice) < rejectNoticeGap {
		st.mu.Unlock()
		return
	}
	st.lastNotice = now
	st.mu.Unlock()
	if !s.noticeQuota(now) {
		return
	}
	detail := "未在白名单中，日志已被拒绝"
	if r := st.rule.Load(); r != nil && r.Action == SenderBlock {
		detail = "已被登记为阻止（" + r.CIDR + "），日志已被拒绝"
	}
	s.push(SenderNotice{Kind: "rejected", IP: st.ip, Detail: detail, Last: now})
}

// noticeQuota 判断本小时内是否还能产生新发送端 / 拒绝通知：伪造大量源地址时最多每小时 maxRejectPerHour 条，不会刷屏。
func (s *Senders) noticeQuota(now time.Time) bool {
	s.nmu.Lock()
	defer s.nmu.Unlock()
	if h := now.Unix() / 3600; h != s.rejectHour {
		s.rejectHour, s.rejectN = h, 0
	}
	s.rejectN++
	return s.rejectN <= maxRejectPerHour
}

func (s *Senders) push(n SenderNotice) {
	s.nmu.Lock()
	if len(s.notices) < maxNoticesQueued {
		s.notices = append(s.notices, n)
	}
	s.nmu.Unlock()
	s.dirty.Store(true)
}

// TakeNotices 取出待推送的通知（由后台任务每分钟调用）。
func (s *Senders) TakeNotices() []SenderNotice {
	if s == nil {
		return nil
	}
	s.nmu.Lock()
	out := s.notices
	s.notices = nil
	s.nmu.Unlock()
	return out
}

// evictLocked 画像数达到上限时淘汰一成：优先淘汰未登记的、最近最久未出现的发送端（伪造源地址的流量无法挤掉已登记设备）。
func (s *Senders) evictLocked() {
	list := make([]*senderStat, 0, len(s.stats))
	for _, st := range s.stats {
		list = append(list, st)
	}
	p := s.pol.Load()
	reg := func(st *senderStat) bool { r := p.match(st.addr); return r != nil && r.Action == SenderAllow }
	sort.Slice(list, func(i, j int) bool {
		if ri, rj := reg(list[i]), reg(list[j]); ri != rj {
			return !ri
		}
		return list[i].last.Load() < list[j].last.Load()
	})
	for _, st := range list[:len(list)/10+1] {
		delete(s.stats, st.addr)
	}
}

// Tick 每分钟调用一次：记录速率采样，检查登记发送端的断流 / 恢复。
func (s *Senders) Tick() {
	if s == nil {
		return
	}
	now := s.now()
	s.mu.RLock()
	list := make([]*senderStat, 0, len(s.stats))
	for _, st := range s.stats {
		list = append(list, st)
	}
	s.mu.RUnlock()
	for _, st := range list {
		s.permitted(st)
		r := st.rule.Load()
		last := time.Unix(0, st.last.Load())
		st.mu.Lock()
		st.ring[st.ringN%len(st.ring)] = st.lines.Load()
		st.ringN++
		var n *SenderNotice
		if r != nil && r.Action == SenderAllow && r.silence > 0 && st.lines.Load() > 0 {
			switch idle := now.Sub(last); {
			case !st.silent && idle > r.silence:
				st.silent = true
				n = &SenderNotice{Kind: "silent", IP: st.ip, Name: r.Name, Group: r.Group, Last: last, Silence: r.silence,
					Detail: "已超过 " + fmtDur(r.silence) + " 未收到日志"}
			case st.silent && idle <= r.silence:
				st.silent = false
				n = &SenderNotice{Kind: "recovered", IP: st.ip, Name: r.Name, Group: r.Group, Last: last, Silence: r.silence, Detail: "已恢复发送日志"}
			}
		} else {
			st.silent = false
		}
		st.mu.Unlock()
		if n != nil {
			s.push(*n)
		}
	}
}

func fmtDur(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%d 天", d/(24*time.Hour))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d 小时", d/time.Hour)
	case d >= time.Minute:
		return fmt.Sprintf("%d 分钟", d/time.Minute)
	}
	return d.String()
}

// ---------------- 展示 ----------------

// SenderView 是发送端的展示信息。
type SenderView struct {
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname,omitempty"`
	Cert       string    `json:"cert,omitempty"`
	Name       string    `json:"name,omitempty"`
	Group      string    `json:"group,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	RuleCIDR   string    `json:"rule_cidr,omitempty"`
	Action     string    `json:"action,omitempty"` // 匹配规则的动作，未登记为空
	Status     string    `json:"status"`           // online 在线 / idle 静默 / silent 断流 / rejected 已拒绝 / blocked 已阻止 / offline 未上线
	Protocols  []string  `json:"protocols"`
	Lines      int64     `json:"lines"`
	Parsed     int64     `json:"parsed"`
	Failed     int64     `json:"failed"`
	Bytes      int64     `json:"bytes"`
	Rejected   int64     `json:"rejected"`
	Limited    int64     `json:"rate_limited"`
	Rate       float64   `json:"rate"` // 近 5 分钟平均每秒日志数
	FirstSeen  time.Time `json:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	LastEvent  time.Time `json:"last_event,omitempty"`
	Detected   string    `json:"detected,omitempty"`
	TimeOffset string    `json:"time_offset,omitempty"`
	Sample     string    `json:"sample_failed,omitempty"`
	Silence    string    `json:"silence"` // 生效的断流阈值，off 为关闭
}

// SenderGroup 是分组汇总。
type SenderGroup struct {
	Name     string  `json:"name"`
	Senders  int     `json:"senders"`
	Online   int     `json:"online"`
	Silent   int     `json:"silent"` // 断流（登记且超过阈值）
	Rejected int     `json:"rejected"`
	Lines    int64   `json:"lines"`
	Rate     float64 `json:"rate"`
}

// SenderReport 是发送端页面的全部数据。
type SenderReport struct {
	Allowlist bool          `json:"allowlist"`
	Forced    bool          `json:"forced"` // 配置文件强制开启白名单
	RateLimit int64         `json:"rate_limit"`
	Silence   string        `json:"default_silence"`
	Senders   []SenderView  `json:"senders"`
	Rules     []SenderRule  `json:"rules"`
	Groups    []SenderGroup `json:"groups"`
	Totals    struct {
		Senders   int   `json:"senders"`
		Online    int   `json:"online"`
		Silent    int   `json:"silent"`
		Unknown   int   `json:"unregistered"` // 未登记的发送端
		Rejected  int   `json:"rejected_senders"`
		Dropped   int64 `json:"rejected_messages"`
		Limited   int64 `json:"rate_limited"`
		Bytes     int64 `json:"bytes"`
		Lines     int64 `json:"lines"`
		RuleCount int   `json:"rules"`
	} `json:"totals"`
}

// idleAfter 为未设置断流阈值时，界面把发送端显示为“静默”的时间。
const idleAfter = 10 * time.Minute

func silenceText(d time.Duration) string {
	if d <= 0 {
		return "off"
	}
	return fmtDur(d)
}

func (st *senderStat) view(now time.Time) SenderView {
	r := st.rule.Load()
	v := SenderView{IP: st.ip, Lines: st.lines.Load(), Parsed: st.parsed.Load(), Failed: st.failed.Load(), Bytes: st.bytes.Load(),
		Rejected: st.rejected.Load(), Limited: st.limited.Load(), Detected: st.detected(), TimeOffset: describeOffset(st.fix.current()),
		Protocols: []string{}, Silence: "off"}
	for i, n := range protoNames {
		if st.protos.Load()&(1<<i) != 0 {
			v.Protocols = append(v.Protocols, n)
		}
	}
	if t := st.first.Load(); t > 0 {
		v.FirstSeen = time.Unix(0, t)
	}
	if t := st.last.Load(); t > 0 {
		v.LastSeen = time.Unix(0, t)
	}
	if t := st.lastEvent.Load(); t > 0 {
		v.LastEvent = time.Unix(0, t)
	}
	st.mu.Lock()
	v.Hostname, v.Cert, v.Sample = st.hostname, st.cert, st.sample
	if n := min(st.ringN, len(st.ring)-1); n > 0 {
		oldest := st.ring[(st.ringN-1-n+len(st.ring)*2)%len(st.ring)]
		v.Rate = float64(v.Lines-oldest) / (float64(n) * 60)
	}
	silent := st.silent
	st.mu.Unlock()
	if r != nil {
		v.Name, v.Group, v.RuleID, v.RuleCIDR, v.Action, v.Silence = r.Name, r.Group, r.ID, r.CIDR, r.Action, silenceText(r.silence)
	}
	idle := now.Sub(v.LastSeen)
	switch {
	case r != nil && r.Action == SenderBlock:
		v.Status = "blocked"
	case !st.allowed.Load():
		v.Status = "rejected"
	case silent:
		v.Status = "silent"
	case idle > idleAfter:
		v.Status = "idle"
	default:
		v.Status = "online"
	}
	return v
}

// Report 返回发送端、登记规则与分组汇总。
func (s *Senders) Report() SenderReport {
	now := s.now()
	var rep SenderReport
	rep.RateLimit, rep.Silence = s.rateLimit, silenceText(s.defSil)
	s.mu.RLock()
	rep.Allowlist, rep.Forced = s.allowlistLocked(), s.forced
	list := make([]*senderStat, 0, len(s.stats))
	for _, st := range s.stats {
		list = append(list, st)
	}
	for _, l := range [][]*SenderRule{s.cfgRules, s.uiRules} {
		for _, r := range l {
			rep.Rules = append(rep.Rules, *r)
		}
	}
	s.mu.RUnlock()
	seen := map[netip.Addr]bool{}
	for _, st := range list {
		s.permitted(st)
		rep.Senders = append(rep.Senders, st.view(now))
		seen[st.addr] = true
	}
	// 登记了但从未出现的单个 IP：显示为未上线，便于发现漏配的设备
	for _, r := range rep.Rules {
		if r.Action == SenderAllow && r.prefix.IsSingleIP() && !seen[r.prefix.Addr()] {
			rep.Senders = append(rep.Senders, SenderView{IP: r.CIDR, Name: r.Name, Group: r.Group, RuleID: r.ID, RuleCIDR: r.CIDR, Action: r.Action,
				Status: "offline", Protocols: []string{}, Silence: silenceText(r.silence)})
		}
	}
	order := map[string]int{"silent": 0, "rejected": 1, "blocked": 2, "online": 3, "idle": 4, "offline": 5}
	sort.Slice(rep.Senders, func(i, j int) bool {
		a, b := rep.Senders[i], rep.Senders[j]
		if order[a.Status] != order[b.Status] {
			return order[a.Status] < order[b.Status]
		}
		if a.Lines != b.Lines {
			return a.Lines > b.Lines
		}
		return a.IP < b.IP
	})
	groups := map[string]*SenderGroup{}
	for _, v := range rep.Senders {
		t := &rep.Totals
		t.Senders++
		t.Lines += v.Lines
		t.Bytes += v.Bytes
		t.Dropped += v.Rejected
		t.Limited += v.Limited
		switch v.Status {
		case "online":
			t.Online++
		case "silent":
			t.Silent++
		case "rejected", "blocked":
			t.Rejected++
		}
		if v.RuleID == "" {
			t.Unknown++
		}
		name := v.Group
		if name == "" {
			name = "未分组"
			if v.RuleID == "" {
				name = "未登记"
			}
		}
		g := groups[name]
		if g == nil {
			g = &SenderGroup{Name: name}
			groups[name] = g
		}
		g.Senders++
		g.Lines += v.Lines
		g.Rate += v.Rate
		switch v.Status {
		case "online":
			g.Online++
		case "silent":
			g.Silent++
		case "rejected", "blocked":
			g.Rejected++
		}
	}
	rep.Totals.RuleCount = len(rep.Rules)
	for _, g := range groups {
		rep.Groups = append(rep.Groups, *g)
	}
	sort.Slice(rep.Groups, func(i, j int) bool {
		if rep.Groups[i].Lines != rep.Groups[j].Lines {
			return rep.Groups[i].Lines > rep.Groups[j].Lines
		}
		return rep.Groups[i].Name < rep.Groups[j].Name
	})
	if rep.Senders == nil {
		rep.Senders = []SenderView{}
	}
	if rep.Rules == nil {
		rep.Rules = []SenderRule{}
	}
	if rep.Groups == nil {
		rep.Groups = []SenderGroup{}
	}
	return rep
}

// Counts 返回发送端总数、在线数、断流数与被拒绝的消息数（供指标与概览使用，开销小）。
func (s *Senders) Counts() (total, online, silent int, rejected int64) {
	if s == nil {
		return
	}
	now := s.now().UnixNano()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, st := range s.stats {
		total++
		rejected += st.rejected.Load()
		if now-st.last.Load() <= int64(idleAfter) && st.allowed.Load() {
			online++
		}
		st.mu.Lock()
		if st.silent {
			silent++
		}
		st.mu.Unlock()
	}
	return
}

// ---------------- 登记与开关 ----------------

// 发送端管理错误。
var (
	ErrNoSenderRule  = errors.New("发送端登记不存在")
	ErrSenderConfig  = errors.New("配置文件中登记的发送端只读，请修改配置文件")
	ErrSenderDup     = errors.New("该 IP / 网段已登记")
	ErrSenderLimit   = errors.New("发送端登记数量已达上限（2000 条）")
	ErrAllowForced   = errors.New("配置文件已开启发送端白名单（syslog.allowlist: true），界面中不能关闭")
	ErrAllowlistOpen = errors.New("白名单中没有允许的发送端，开启后将拒绝所有日志；请先登记发送端，或勾选“将近 24 小时活跃的发送端加入白名单”")
)

func newRuleID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// AddRule 登记发送端（界面操作）。
func (s *Senders) AddRule(r SenderRule, user string) (SenderRule, error) {
	r.Source, r.Creator, r.Created, r.Updated, r.ID = "ui", user, s.now(), time.Time{}, newRuleID()
	if err := s.prepare(&r); err != nil {
		return SenderRule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.uiRules) >= maxSenderRules {
		return SenderRule{}, ErrSenderLimit
	}
	for _, o := range s.uiRules {
		if o.prefix == r.prefix {
			return SenderRule{}, ErrSenderDup
		}
	}
	s.uiRules = append(s.uiRules, &r)
	s.rebuildLocked()
	return r, s.saveLocked()
}

// UpdateRule 修改界面登记的发送端。
func (s *Senders) UpdateRule(id string, r SenderRule) (SenderRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, o := range s.uiRules {
		if o.ID != id {
			continue
		}
		n := *o
		n.CIDR, n.Name, n.Group, n.Action, n.Silence, n.Note, n.Updated = r.CIDR, r.Name, r.Group, r.Action, r.Silence, r.Note, s.now()
		if err := s.prepare(&n); err != nil {
			return SenderRule{}, err
		}
		for _, x := range s.uiRules {
			if x.ID != id && x.prefix == n.prefix {
				return SenderRule{}, ErrSenderDup
			}
		}
		s.uiRules[i] = &n
		s.rebuildLocked()
		return n, s.saveLocked()
	}
	for _, o := range s.cfgRules {
		if o.ID == id {
			return SenderRule{}, ErrSenderConfig
		}
	}
	return SenderRule{}, ErrNoSenderRule
}

// DeleteRule 删除界面登记的发送端。
func (s *Senders) DeleteRule(id string) (SenderRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, o := range s.uiRules {
		if o.ID == id {
			s.uiRules = append(s.uiRules[:i:i], s.uiRules[i+1:]...)
			s.rebuildLocked()
			return *o, s.saveLocked()
		}
	}
	for _, o := range s.cfgRules {
		if o.ID == id {
			return SenderRule{}, ErrSenderConfig
		}
	}
	return SenderRule{}, ErrNoSenderRule
}

// SetAllowlist 开启 / 关闭发送端白名单。includeActive 为真时，先把近 24 小时内发送过日志、尚未登记的发送端登记为允许（分组“自动登记”），
// 避免开启后正在使用的设备被拒绝。返回自动登记的数量。
func (s *Senders) SetAllowlist(on, includeActive bool, user string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !on && s.forced {
		return 0, ErrAllowForced
	}
	added := 0
	if on && includeActive {
		p := s.pol.Load()
		now := s.now()
		for _, st := range s.stats {
			if r := p.match(st.addr); r != nil || st.parsed.Load() == 0 || now.Sub(time.Unix(0, st.last.Load())) > 24*time.Hour {
				continue
			}
			if len(s.uiRules) >= maxSenderRules {
				break
			}
			r := &SenderRule{ID: newRuleID(), CIDR: st.ip, Group: "自动登记", Action: SenderAllow, Source: "ui", Creator: user, Created: now,
				Note: "开启白名单时自动登记的活跃发送端"}
			if s.prepare(r) == nil {
				s.uiRules = append(s.uiRules, r)
				added++
			}
		}
	}
	if on {
		allow := false
		for _, l := range [][]*SenderRule{s.cfgRules, s.uiRules} {
			for _, r := range l {
				allow = allow || r.Action == SenderAllow
			}
		}
		if !allow {
			return 0, ErrAllowlistOpen
		}
	}
	s.uiAllow = &on
	s.rebuildLocked()
	return added, s.saveLocked()
}

// ---------------- 持久化 ----------------

type savedSender struct {
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname,omitempty"`
	Cert      string    `json:"cert,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastEvent time.Time `json:"last_event,omitempty"`
	Lines     int64     `json:"lines"`
	Parsed    int64     `json:"parsed"`
	Failed    int64     `json:"failed"`
	Bytes     int64     `json:"bytes"`
	Rejected  int64     `json:"rejected"`
	Limited   int64     `json:"rate_limited,omitempty"`
	Protos    uint32    `json:"protos"`
	Silent    bool      `json:"silent,omitempty"`
}

type sendersFile struct {
	Allowlist *bool         `json:"allowlist,omitempty"`
	Rules     []*SenderRule `json:"rules"`
	Senders   []savedSender `json:"senders"`
}

func (s *Senders) load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var f sendersFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("解析 %s 失败: %w", s.path, err)
	}
	s.uiAllow = f.Allowlist
	for _, r := range f.Rules {
		if r == nil || r.ID == "" {
			continue
		}
		r.Source = "ui"
		if s.prepare(r) == nil && len(s.uiRules) < maxSenderRules {
			s.uiRules = append(s.uiRules, r)
		}
	}
	for _, v := range f.Senders {
		a, err := netip.ParseAddr(v.IP)
		if err != nil || len(s.stats) >= maxSenderStats {
			continue
		}
		st := newSenderStat(a.Unmap())
		st.hostname, st.cert, st.loaded, st.silent = cleanText(v.Hostname, 64), cleanText(v.Cert, 120), true, v.Silent
		for _, p := range []struct {
			dst *atomic.Int64
			t   time.Time
		}{{&st.first, v.FirstSeen}, {&st.last, v.LastSeen}, {&st.lastEvent, v.LastEvent}} {
			if !p.t.IsZero() {
				p.dst.Store(p.t.UnixNano())
			}
		}
		st.lines.Store(v.Lines)
		st.parsed.Store(v.Parsed)
		st.failed.Store(v.Failed)
		st.bytes.Store(v.Bytes)
		st.rejected.Store(v.Rejected)
		st.limited.Store(v.Limited)
		st.protos.Store(v.Protos & 7)
		s.stats[st.addr] = st
	}
	return nil
}

// Flush 保存登记与发送端统计（由快照任务定期调用）。
func (s *Senders) Flush() error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Senders) saveLocked() error {
	if s.path == "" {
		return nil
	}
	f := sendersFile{Allowlist: s.uiAllow, Rules: s.uiRules, Senders: []savedSender{}}
	if f.Rules == nil {
		f.Rules = []*SenderRule{}
	}
	for _, st := range s.stats {
		if st.lines.Load() == 0 && st.rejected.Load() == 0 {
			continue
		}
		v := savedSender{IP: st.ip, Lines: st.lines.Load(), Parsed: st.parsed.Load(), Failed: st.failed.Load(), Bytes: st.bytes.Load(),
			Rejected: st.rejected.Load(), Limited: st.limited.Load(), Protos: st.protos.Load()}
		for _, p := range []struct {
			src *atomic.Int64
			dst *time.Time
		}{{&st.first, &v.FirstSeen}, {&st.last, &v.LastSeen}, {&st.lastEvent, &v.LastEvent}} {
			if t := p.src.Load(); t > 0 {
				*p.dst = time.Unix(0, t)
			}
		}
		st.mu.Lock()
		v.Hostname, v.Cert, v.Silent = st.hostname, st.cert, st.silent
		st.mu.Unlock()
		f.Senders = append(f.Senders, v)
	}
	sort.Slice(f.Senders, func(i, j int) bool { return f.Senders[i].IP < f.Senders[j].IP })
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("保存 syslog 发送端失败: %w", err)
	}
	s.dirty.Store(false)
	return os.Rename(tmp, s.path)
}

// syslogHostname 从 syslog 头部提取主机名：RFC 5424 “<PRI>1 时间 主机 …”、RFC 3164 “<PRI>Mmm dd hh:mm:ss 主机 …”
// 或 “<PRI>ISO时间 主机 …”。无法识别时返回空。
func syslogHostname(line string) string {
	if len(line) < 8 || line[0] != '<' {
		return ""
	}
	end := strings.IndexByte(line[:min(len(line), 6)], '>')
	if end < 2 {
		return ""
	}
	rest := line[end+1:]
	var host string
	switch {
	case strings.HasPrefix(rest, "1 "): // RFC 5424
		f := strings.SplitN(rest, " ", 4)
		if len(f) >= 3 {
			host = f[2]
		}
	case len(rest) > 16 && rest[3] == ' ' && rest[6] == ' ' && rest[9] == ':' && rest[12] == ':': // RFC 3164
		f := strings.SplitN(strings.TrimLeft(rest[15:], " "), " ", 2)
		host = f[0]
	default:
		f := strings.SplitN(rest, " ", 3)
		if len(f) >= 2 && len(f[0]) >= 19 && f[0][4] == '-' && strings.IndexByte(f[0], 'T') == 10 {
			host = f[1]
		}
	}
	if host == "-" || host == "" || len(host) > 64 || strings.HasSuffix(host, ":") {
		return ""
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == ':') {
			return ""
		}
	}
	return host
}
