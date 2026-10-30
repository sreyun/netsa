package store

import (
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"netsa/internal/model"
)

// 事件处置状态。
const (
	IncOpen          = "open"           // 待处理
	IncInvestigating = "investigating"  // 处置中
	IncResolved      = "resolved"       // 已处置
	IncFalsePositive = "false_positive" // 误报
	IncIgnored       = "ignored"        // 忽略
)

// IncidentStatusLabel 是状态的中文名称。
var IncidentStatusLabel = map[string]string{IncOpen: "待处理", IncInvestigating: "处置中", IncResolved: "已处置", IncFalsePositive: "误报", IncIgnored: "忽略"}

// incidentSLA 是各等级事件的处置时限（从事件创建起）。
var incidentSLA = [...]time.Duration{7 * 24 * time.Hour, 72 * time.Hour, 24 * time.Hour, 4 * time.Hour, time.Hour}

// SLA 返回该等级事件的处置时限。
func SLA(s model.Severity) time.Duration { return incidentSLA[max(min(int(s), 4), 0)] }

// slaFor 返回事件的处置时限：涉及核心资产时按高一级的等级计算。
func slaFor(s model.Severity, assetLevel string) time.Duration {
	if assetLevel == "core" && s < model.SevCritical {
		s++
	}
	return SLA(s)
}

func assetRank(l string) int {
	switch l {
	case "core":
		return 3
	case "important":
		return 2
	case "normal":
		return 1
	}
	return 0
}

const (
	incidentGap   = 24 * time.Hour // 同一来源超过该时间没有新告警时，再出现的告警归入新事件
	maxIncidents  = 20000
	maxIncNotes   = 200
	maxIncTargets = 20
	maxIncRules   = 30
)

// IncidentNote 是一条处置记录。
type IncidentNote struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	Action string    `json:"action,omitempty"` // 状态变化、指派等（系统生成的说明）
	Text   string    `json:"text,omitempty"`   // 处置人填写的备注
}

// Incident 是一个安全事件：同一来源在一段时间内的告警合并在一起处置。
type Incident struct {
	ID         uint64         `json:"id"`
	Key        string         `json:"key"` // 来源 IP
	Location   string         `json:"location,omitempty"`
	Severity   model.Severity `json:"severity"`
	Status     string         `json:"status"`
	Assignee   string         `json:"assignee,omitempty"`
	Alerts     int            `json:"alerts"`  // 生成的告警条数（受 detect.alerts_per_rule 节流）
	Hits       int            `json:"hits"`    // 命中次数：含被规则节流、未生成告警的重复命中
	Muted      int            `json:"muted"`   // 其中未生成告警的命中数（Hits - Alerts）
	Success    int            `json:"success"` // 疑似攻击成功的告警数
	Categories map[string]int `json:"categories"`
	Phases     map[string]int `json:"phases"`
	Rules      map[string]int `json:"rules"`       // 规则 → 命中次数（含被节流的重复命中）
	RuleAlerts map[string]int `json:"rule_alerts"` // 规则 → 告警条数
	Targets    map[string]int `json:"targets"`
	Assets     map[string]int `json:"assets,omitempty"`      // 涉及的资产
	AssetLevel string         `json:"asset_level,omitempty"` // 涉及资产的最高重要性
	FirstSeen  time.Time      `json:"first_seen"`            // 首条告警的日志时间
	LastSeen   time.Time      `json:"last_seen"`
	Created    time.Time      `json:"created"` // 以下为系统时间
	Updated    time.Time      `json:"updated"`
	Due        time.Time      `json:"due"` // 处置截止时间
	Closed     time.Time      `json:"closed,omitempty"`
	Reminded   bool           `json:"reminded,omitempty"` // 已发送超时提醒
	Notes      []IncidentNote `json:"notes"`
	ClosedSev  model.Severity `json:"closed_severity,omitempty"` // 关闭时的最高等级：之后出现更高等级的告警时自动重新打开
}

// ensureMaps 补全旧快照中缺失的字段。
func (i *Incident) ensureMaps() {
	for _, m := range []*map[string]int{&i.Categories, &i.Phases, &i.Rules, &i.Targets, &i.RuleAlerts} {
		if *m == nil {
			*m = map[string]int{}
		}
	}
	// 旧快照只有告警计数：命中数按告警数回填，保证 Hits >= Alerts
	if i.Hits < i.Alerts {
		i.Hits = i.Alerts
	}
	if i.Muted < 0 || i.Muted > i.Hits-i.Alerts {
		i.Muted = i.Hits - i.Alerts
	}
	if i.Notes == nil {
		i.Notes = []IncidentNote{}
	}
	if IncidentStatusLabel[i.Status] == "" {
		i.Status = IncOpen
	}
}

// active 判断事件是否仍需处置。
func (i *Incident) active() bool { return i.Status == IncOpen || i.Status == IncInvestigating }

// IncidentView 是列表中的事件摘要。
type IncidentView struct {
	ID         uint64         `json:"id"`
	Key        string         `json:"key"`
	Title      string         `json:"title"`
	Location   string         `json:"location,omitempty"`
	Severity   model.Severity `json:"severity"`
	Status     string         `json:"status"`
	Assignee   string         `json:"assignee,omitempty"`
	Alerts     int            `json:"alerts"`
	Hits       int            `json:"hits"`
	Muted      int            `json:"muted"`
	Success    int            `json:"success"`
	Categories []string       `json:"categories"`
	Phases     []string       `json:"phases"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Created    time.Time      `json:"created"`
	Updated    time.Time      `json:"updated"`
	Due        time.Time      `json:"due"`
	Closed     time.Time      `json:"closed,omitempty"`
	Overdue    bool           `json:"overdue"`
	Assets     []string       `json:"assets,omitempty"`
	AssetLevel string         `json:"asset_level,omitempty"`
	Notes      int            `json:"notes"`
}

// rankKeys 按计数从多到少（相同时按名称）返回前 n 个键。
func rankKeys(m map[string]int, n int) []string {
	kv := make([]KV, 0, len(m))
	for k, v := range m {
		kv = append(kv, KV{Name: k, Value: int64(v)})
	}
	sort.Slice(kv, func(i, j int) bool {
		if kv[i].Value != kv[j].Value {
			return kv[i].Value > kv[j].Value
		}
		return kv[i].Name < kv[j].Name
	})
	out := []string{}
	for i := 0; i < len(kv) && i < n; i++ {
		out = append(out, kv[i].Name)
	}
	return out
}

func (i *Incident) view(now time.Time) IncidentView {
	cats := rankKeys(i.Categories, 4)
	title := i.Key
	switch {
	case len(i.Categories) > 1:
		title += " · " + cats[0] + " 等 " + itoa(len(i.Categories)) + " 类攻击"
	case len(cats) == 1:
		title += " · " + cats[0]
	}
	if i.Success > 0 {
		title += "（疑似成功）"
	}
	var phases []string
	for _, ph := range phaseOrder {
		if i.Phases[ph] > 0 {
			phases = append(phases, ph)
		}
	}
	return IncidentView{ID: i.ID, Key: i.Key, Title: title, Location: i.Location, Severity: i.Severity, Status: i.Status, Assignee: i.Assignee,
		Alerts: i.Alerts, Hits: i.Hits, Muted: i.Muted, Success: i.Success, Categories: cats, Phases: phases, FirstSeen: i.FirstSeen, LastSeen: i.LastSeen,
		Created: i.Created, Updated: i.Updated, Due: i.Due, Closed: i.Closed, Overdue: i.active() && now.After(i.Due), Notes: len(i.Notes), Assets: rankKeys(i.Assets, 5), AssetLevel: i.AssetLevel}
}

// attachIncidentLocked 把告警归入事件（调用方持写锁），返回事件编号。
func (s *Store) attachIncidentLocked(a *model.Alert, p *IPProfile) uint64 {
	now := time.Now()
	inc := s.incidents[s.incByKey[a.SrcIP]]
	if inc != nil && (inc.Status == IncResolved || a.Time.Sub(inc.LastSeen) > incidentGap) {
		inc = nil // 已处置后再次出现、或长时间未活动后再次出现：作为新事件
	}
	if inc == nil {
		s.nextInc++
		inc = &Incident{ID: s.nextInc, Key: a.SrcIP, Severity: a.Severity, Status: IncOpen, Categories: map[string]int{}, Phases: map[string]int{},
			Rules: map[string]int{}, Targets: map[string]int{}, FirstSeen: a.Time, LastSeen: a.Time, Created: now, Updated: now,
			Due: now.Add(slaFor(a.Severity, a.AssetLevel)), Notes: []IncidentNote{}, AssetLevel: a.AssetLevel}
		s.incidents[inc.ID] = inc
		s.incByKey[a.SrcIP] = inc.ID
		s.evictIncidentsLocked()
	}
	if p != nil && p.Geo != nil {
		inc.Location = p.Geo.Location()
	}
	inc.Alerts++
	inc.Hits++
	incBounded(&inc.RuleAlerts, a.RuleID, maxIncRules)
	if a.Result == model.ResultSuccess {
		inc.Success++
	}
	incBounded(&inc.Categories, a.Category, 50)
	incBounded(&inc.Phases, a.Phase, 10)
	incBounded(&inc.Rules, a.RuleID, maxIncRules)
	incBounded(&inc.Targets, a.Target, maxIncTargets)
	if a.Asset != "" {
		incBounded(&inc.Assets, a.Asset, maxIncTargets)
	}
	if assetRank(a.AssetLevel) > assetRank(inc.AssetLevel) {
		inc.AssetLevel = a.AssetLevel
		if due := inc.Created.Add(slaFor(inc.Severity, inc.AssetLevel)); inc.active() && due.Before(inc.Due) {
			inc.Due, inc.Reminded = due, false
		}
	}
	if a.Time.Before(inc.FirstSeen) {
		inc.FirstSeen = a.Time
	}
	if a.Time.After(inc.LastSeen) {
		inc.LastSeen = a.Time
	}
	if a.Severity > inc.Severity {
		inc.Severity = a.Severity
		if inc.active() { // 等级升高后处置时限相应缩短
			if due := inc.Created.Add(slaFor(a.Severity, inc.AssetLevel)); due.Before(inc.Due) {
				inc.Due, inc.Reminded = due, false
			}
		} else if a.Severity > inc.ClosedSev {
			// 标记为误报 / 忽略的事件出现了更高等级的告警：自动重新打开
			inc.Notes = appendNote(inc.Notes, IncidentNote{Time: now, User: "系统", Action: "出现" + a.Severity.Label() + "告警「" + a.Name + "」，自动重新打开（原状态：" + IncidentStatusLabel[inc.Status] + "）"})
			inc.Status, inc.Closed, inc.Due, inc.Reminded = IncOpen, time.Time{}, now.Add(slaFor(a.Severity, inc.AssetLevel)), false
		}
	}
	inc.Updated = now
	return inc.ID
}

// incidentHit 是一次未生成告警的命中。事件内的攻击类型、阶段、目标、疑似成功、资产
// 全部按「命中」口径累计，避免同一个事件里同时出现告警口径与命中口径两套数字。
type incidentHit struct {
	rule, category, phase, target, result string
	asset                                 *model.AssetRef
	at                                    time.Time
}

// muteIncidentLocked 记录一次「命中但未生成告警」的重复命中（调用方持写锁）。
// 只有仍在处置中的事件才累计，已关闭的事件不因节流命中而被改写。
func (s *Store) muteIncidentLocked(ip string, h incidentHit) {
	id, ok := s.incByKey[ip]
	if !ok {
		return
	}
	inc := s.incidents[id]
	if inc == nil || !inc.active() {
		return
	}
	inc.Hits++
	inc.Muted++
	incBounded(&inc.Rules, h.rule, maxIncRules)
	incBounded(&inc.Targets, h.target, maxIncTargets)
	incBounded(&inc.Categories, h.category, 50)
	incBounded(&inc.Phases, h.phase, 10)
	if h.result == model.ResultSuccess {
		inc.Success++
	}
	if h.asset != nil {
		incBounded(&inc.Assets, h.asset.Name, maxIncTargets)
		if assetRank(h.asset.Level) > assetRank(inc.AssetLevel) {
			inc.AssetLevel = h.asset.Level
			if due := inc.Created.Add(slaFor(inc.Severity, inc.AssetLevel)); inc.active() && due.Before(inc.Due) {
				inc.Due, inc.Reminded = due, false
			}
		}
	}
	if h.at.After(inc.LastSeen) {
		inc.LastSeen = h.at
	}
	inc.Updated = time.Now()
}

func appendNote(notes []IncidentNote, n IncidentNote) []IncidentNote {
	notes = append(notes, n)
	if len(notes) > maxIncNotes {
		notes = append([]IncidentNote(nil), notes[len(notes)-maxIncNotes:]...)
	}
	return notes
}

// evictIncidentsLocked 事件数超过上限时一次淘汰一成：先淘汰已关闭的，再按最后更新时间从早到晚淘汰
// （批量淘汰使大量新来源涌入时每条告警的摊还开销保持在常数级）。
func (s *Store) evictIncidentsLocked() {
	if len(s.incidents) <= maxIncidents {
		return
	}
	list := make([]*Incident, 0, len(s.incidents))
	for _, i := range s.incidents {
		list = append(list, i)
	}
	sort.Slice(list, func(a, b int) bool {
		if x, y := list[a], list[b]; x.active() != y.active() {
			return !x.active()
		}
		return list[a].Updated.Before(list[b].Updated)
	})
	for _, victim := range list[:len(list)-maxIncidents*9/10] {
		delete(s.incidents, victim.ID)
		if s.incByKey[victim.Key] == victim.ID {
			delete(s.incByKey, victim.Key)
		}
	}
}

// IncidentQuery 是事件查询条件。
type IncidentQuery struct {
	Status      string // open / investigating / resolved / false_positive / ignored；active 为待处理 + 处置中；closed 为其余；空为全部
	MinSeverity model.Severity
	Assignee    string
	Search      string
	Overdue     bool
	Limit       int
	Offset      int
}

// IncidentCounts 是各状态的事件数。
type IncidentCounts struct {
	Open          int `json:"open"`
	Investigating int `json:"investigating"`
	Resolved      int `json:"resolved"`
	FalsePositive int `json:"false_positive"`
	Ignored       int `json:"ignored"`
	Overdue       int `json:"overdue"`
	Total         int `json:"total"`
}

func (s *Store) incidentCountsLocked(now time.Time) IncidentCounts {
	var c IncidentCounts
	for _, i := range s.incidents {
		c.Total++
		switch i.Status {
		case IncOpen:
			c.Open++
		case IncInvestigating:
			c.Investigating++
		case IncResolved:
			c.Resolved++
		case IncFalsePositive:
			c.FalsePositive++
		case IncIgnored:
			c.Ignored++
		}
		if i.active() && now.After(i.Due) {
			c.Overdue++
		}
	}
	return c
}

// Incidents 查询事件：处置中的事件按超时、等级、更新时间排序，已关闭的按关闭时间倒序。
func (s *Store) Incidents(q IncidentQuery) ([]IncidentView, int, IncidentCounts) {
	now := time.Now()
	search := strings.ToLower(strings.TrimSpace(q.Search))
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := s.incidentCountsLocked(now)
	var list []*Incident
	for _, i := range s.incidents {
		switch q.Status {
		case "":
		case "active":
			if !i.active() {
				continue
			}
		case "closed":
			if i.active() {
				continue
			}
		default:
			if i.Status != q.Status {
				continue
			}
		}
		if i.Severity < q.MinSeverity || q.Assignee != "" && i.Assignee != q.Assignee || q.Overdue && !(i.active() && now.After(i.Due)) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(i.Key+" "+i.Location+" "+strings.Join(rankKeys(i.Categories, 50), " ")+" "+strings.Join(rankKeys(i.Assets, 50), " ")+" "+itoa(int(i.ID))), search) {
			continue
		}
		list = append(list, i)
	}
	sort.Slice(list, func(a, b int) bool {
		x, y := list[a], list[b]
		if x.active() != y.active() {
			return x.active()
		}
		if x.active() {
			if xo, yo := now.After(x.Due), now.After(y.Due); xo != yo {
				return xo
			}
			if x.Severity != y.Severity {
				return x.Severity > y.Severity
			}
		}
		if !x.Updated.Equal(y.Updated) {
			return x.Updated.After(y.Updated)
		}
		return x.ID > y.ID
	})
	total := len(list)
	if q.Offset > 0 {
		list = list[min(q.Offset, len(list)):]
	}
	if q.Limit > 0 && len(list) > q.Limit {
		list = list[:q.Limit]
	}
	out := make([]IncidentView, len(list))
	for k, i := range list {
		out[k] = i.view(now)
	}
	return out, total, counts
}

// IncidentDetail 是事件详情：事件信息、处置记录、相关告警与命中规则。
type IncidentDetail struct {
	IncidentView
	Notes     []IncidentNote `json:"notes_list"`
	Rules     []KV           `json:"rules"`
	Targets   []KV           `json:"targets"`
	AlertList []*model.Alert `json:"alert_list"` // 事件中仍保留在内存中的告警（最近 200 条）
	SLA       string         `json:"sla"`
}

// Incident 返回事件详情。
func (s *Store) Incident(id uint64) *IncidentDetail {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i := s.incidents[id]
	if i == nil {
		return nil
	}
	d := &IncidentDetail{IncidentView: i.view(time.Now()), Notes: append([]IncidentNote{}, i.Notes...), AlertList: []*model.Alert{}, SLA: slaFor(i.Severity, i.AssetLevel).String()}
	for k, v := range i.Rules {
		name := s.ruleNames[k]
		if name == "" {
			name = k
		} else {
			name = k + " " + name
		}
		alerts, ok := i.RuleAlerts[k]
		if !ok {
			alerts = v // 旧快照没有 rule_alerts
		}
		d.Rules = append(d.Rules, KV{Name: name, Value: int64(v), Alerts: int64(alerts)})
	}
	sort.Slice(d.Rules, func(a, b int) bool { return d.Rules[a].Value > d.Rules[b].Value })
	d.Targets = topN(intMap(i.Targets), 10, ident)
	n := len(s.alerts)
	for k := 0; k < n && len(d.AlertList) < 200; k++ {
		idx := (s.alertHead - 1 - k + 2*n) % n
		if n < s.maxAlerts {
			idx = n - 1 - k
		}
		if a := s.alerts[idx]; a.IncidentID == id {
			d.AlertList = append(d.AlertList, a)
		}
	}
	return d
}

func intMap(m map[string]int) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = int64(v)
	}
	return out
}

// IncidentUpdate 是一次处置操作：修改状态、指派与 / 或填写备注（为空的字段不修改）。
type IncidentUpdate struct {
	Status   string  `json:"status"`
	Assignee *string `json:"assignee"`
	Note     string  `json:"note"`
}

// 处置错误。
var (
	ErrNoIncident = errors.New("事件不存在")
	ErrIncStatus  = errors.New("无效的事件状态")
	ErrIncEmpty   = errors.New("请选择状态、负责人或填写处置备注")
	ErrIncNote    = errors.New("处置备注不能超过 1000 个字符")
	ErrIncClose   = errors.New("标记为已处置、误报或忽略时请填写处置说明")
)

// UpdateIncidents 对一个或多个事件执行处置操作，返回更新后的事件。关闭事件（已处置 / 误报 / 忽略）必须填写说明。
func (s *Store) UpdateIncidents(ids []uint64, user string, u IncidentUpdate) ([]IncidentView, error) {
	u.Note = strings.TrimSpace(u.Note)
	if u.Status != "" && IncidentStatusLabel[u.Status] == "" {
		return nil, ErrIncStatus
	}
	if u.Status == "" && u.Assignee == nil && u.Note == "" {
		return nil, ErrIncEmpty
	}
	if utf8.RuneCountInString(u.Note) > 1000 {
		return nil, ErrIncNote
	}
	if (u.Status == IncResolved || u.Status == IncFalsePositive || u.Status == IncIgnored) && u.Note == "" {
		return nil, ErrIncClose
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// 先确认全部事件存在再修改：批量处置中途遇到不存在（已被淘汰）的事件时，前面的事件不能已经被改掉，
	// 否则接口报错、研判反馈与审计都按失败处理，事件状态却已部分变更。重复的编号只处理一次
	list := make([]*Incident, 0, len(ids))
	seen := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		i := s.incidents[id]
		if i == nil {
			return nil, ErrNoIncident
		}
		list = append(list, i)
	}
	var out []IncidentView
	for _, i := range list {
		var actions []string
		if u.Status != "" && u.Status != i.Status {
			actions = append(actions, "状态："+IncidentStatusLabel[i.Status]+" → "+IncidentStatusLabel[u.Status])
			wasActive := i.active()
			i.Status = u.Status
			switch {
			case !i.active():
				i.Closed, i.ClosedSev = now, i.Severity
			case !wasActive: // 重新打开
				i.Closed, i.Due, i.Reminded = time.Time{}, now.Add(slaFor(i.Severity, i.AssetLevel)), false
			}
		}
		if u.Assignee != nil && *u.Assignee != i.Assignee {
			a := strings.TrimSpace(*u.Assignee)
			if a == "" {
				actions = append(actions, "取消指派")
			} else {
				actions = append(actions, "指派给 "+a)
			}
			i.Assignee = a
		}
		if len(actions) == 0 && u.Note == "" {
			out = append(out, i.view(now))
			continue
		}
		i.Notes = appendNote(i.Notes, IncidentNote{Time: now, User: user, Action: strings.Join(actions, "；"), Text: u.Note})
		i.Updated = now
		out = append(out, i.view(now))
	}
	return out, nil
}

// TakeOverdue 返回新超时（尚未提醒）的事件并标记为已提醒，供后台任务推送超时提醒。
func (s *Store) TakeOverdue() []IncidentView {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []IncidentView
	for _, i := range s.incidents {
		if i.active() && !i.Reminded && now.After(i.Due) {
			i.Reminded = true
			out = append(out, i.view(now))
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Severity > out[b].Severity })
	return out
}

// IncidentPeriod 是一段时间内的事件处置统计（报表使用）。
type IncidentPeriod struct {
	Created       int            `json:"created"`        // 期间新建的事件
	Closed        int            `json:"closed"`         // 期间关闭的事件
	BySeverity    map[string]int `json:"by_severity"`    // 期间新建事件的等级分布
	ByStatus      map[string]int `json:"by_status"`      // 期间新建事件的当前状态
	FalsePositive int            `json:"false_positive"` // 期间关闭为误报的事件
	OnTime        int            `json:"on_time"`        // 在处置时限内关闭的事件
	MTTR          string         `json:"mttr,omitempty"` // 平均处置时长（创建到关闭）
	SLARate       float64        `json:"sla_rate"`       // 按时关闭率（0~1，没有关闭的事件时为 -1）
	OpenNow       int            `json:"open_now"`       // 当前仍未关闭的事件
	OverdueNow    int            `json:"overdue_now"`
	Top           []IncidentView `json:"top"` // 期间等级最高的事件
}

// IncidentStats 返回 [from, to) 期间的事件处置统计。
func (s *Store) IncidentStats(from, to time.Time) IncidentPeriod {
	now := time.Now()
	st := IncidentPeriod{BySeverity: map[string]int{}, ByStatus: map[string]int{}, SLARate: -1}
	var total time.Duration
	var top []*Incident
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, i := range s.incidents {
		if i.active() {
			st.OpenNow++
			if now.After(i.Due) {
				st.OverdueNow++
			}
		}
		if !i.Created.Before(from) && i.Created.Before(to) {
			st.Created++
			st.BySeverity[i.Severity.String()]++
			st.ByStatus[i.Status]++
			top = append(top, i)
		}
		if !i.active() && !i.Closed.Before(from) && i.Closed.Before(to) {
			st.Closed++
			total += i.Closed.Sub(i.Created)
			if !i.Closed.After(i.Due) {
				st.OnTime++
			}
			if i.Status == IncFalsePositive {
				st.FalsePositive++
			}
		}
	}
	if st.Closed > 0 {
		st.MTTR = (total / time.Duration(st.Closed)).Round(time.Minute).String()
		st.SLARate = float64(st.OnTime) / float64(st.Closed)
	}
	sort.Slice(top, func(a, b int) bool {
		if top[a].Severity != top[b].Severity {
			return top[a].Severity > top[b].Severity
		}
		return top[a].Alerts > top[b].Alerts
	})
	for k := 0; k < len(top) && k < 10; k++ {
		st.Top = append(st.Top, top[k].view(now))
	}
	return st
}
