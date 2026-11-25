package aiuse

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Query 是统计查询条件。
type Query struct {
	From, To time.Time // 起止日期（含），按配置时区的自然日
	IP       string    // 只看一个终端
	Service  string    // 只看一个服务
	Limit    int       // 终端列表的条数上限（默认 500）
}

// Totals 是查询范围内的汇总。
type Totals struct {
	Subjects     int   `json:"subjects"`      // 使用 AI 服务的终端数
	Services     int   `json:"services"`      // 用到的服务数
	Queries      int64 `json:"queries"`       // DNS 查询
	Conns        int64 `json:"conns"`         // 连接 / 请求
	Denied       int64 `json:"denied"`        // 被拦截的尝试
	Up           int64 `json:"up"`            // 上传字节
	Down         int64 `json:"down"`          // 下载字节
	OverseasUp   int64 `json:"overseas_up"`   // 境外服务的上传字节
	OverseasSubj int   `json:"overseas_subj"` // 使用境外服务的终端数
	DenySubjects int   `json:"deny_subjects"` // 使用了“禁止”类服务的终端数
	NewServices  int   `json:"new_services"`  // 范围内首次出现的服务数
}

// ServiceRow 是一个服务在查询范围内的统计。
type ServiceRow struct {
	Service
	Subjects int       `json:"subjects"`
	Queries  int64     `json:"queries"`
	Conns    int64     `json:"conns"`
	Denied   int64     `json:"denied"`
	Up       int64     `json:"up"`
	Down     int64     `json:"down"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	FirstAll time.Time `json:"first_all"` // 首次出现（不受统计保留期限制）
	New      bool      `json:"new,omitempty"`
}

// SubjectRow 是一个终端在查询范围内的统计。资产、负责人与部门由接口层按资产台账填写。
type SubjectRow struct {
	IP       string    `json:"ip"`
	Asset    string    `json:"asset,omitempty"`
	Owner    string    `json:"owner,omitempty"`
	Dept     string    `json:"dept,omitempty"`
	Services []string  `json:"services"` // 按使用量从多到少
	Queries  int64     `json:"queries"`
	Conns    int64     `json:"conns"`
	Denied   int64     `json:"denied"`
	Up       int64     `json:"up"`
	Down     int64     `json:"down"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Deny     bool      `json:"deny,omitempty"`     // 用过“禁止”类服务
	Overseas bool      `json:"overseas,omitempty"` // 用过境外服务
}

// DayRow 是一天的统计。
type DayRow struct {
	Date       string `json:"date"`
	Subjects   int    `json:"subjects"`
	Requests   int64  `json:"requests"` // 查询 + 连接
	Up         int64  `json:"up"`
	OverseasUp int64  `json:"overseas_up"`
	Denied     int64  `json:"denied"`
}

// RankItem 是排行中的一项。
type RankItem struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// Report 是统计结果。
type Report struct {
	From        string       `json:"from"`
	To          string       `json:"to"`
	Totals      Totals       `json:"totals"`
	Services    []ServiceRow `json:"services"`
	Subjects    []SubjectRow `json:"subjects"`
	SubjectsAll int          `json:"subjects_all"` // 终端总数（列表可能被截断）
	Daily       []DayRow     `json:"daily"`
	Categories  []RankItem   `json:"categories"` // 按类别的终端数
	Candidates  []Candidate  `json:"candidates"`
	Endpoints   []Endpoint   `json:"endpoints"`
	Coverage    Coverage     `json:"coverage"`
	Detail      []ServiceUse `json:"detail,omitempty"` // 只看一个终端时：按服务、按天的明细
}

// ServiceUse 是一个终端在一天内使用一个服务的记录。
type ServiceUse struct {
	Date    string `json:"date"`
	Service string `json:"service"`
	Name    string `json:"name"`
	Queries int64  `json:"queries"`
	Conns   int64  `json:"conns"`
	Denied  int64  `json:"denied"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	First   int64  `json:"first"`
	Last    int64  `json:"last"`
}

// Coverage 说明统计口径的可用性。
type Coverage struct {
	SNI           bool   `json:"sni"`   // 接入了 TLS 握手日志（Zeek ssl.log）
	Bytes         bool   `json:"bytes"` // 有会话字节被归到 AI 服务（上传量可用）
	Records       int    `json:"records"`
	MaxRecords    int    `json:"max_records"`
	Dropped       int64  `json:"dropped"`
	RetentionDays int    `json:"retention_days"`
	Since         string `json:"since,omitempty"` // 最早的记录日期
	Services      int    `json:"services"`        // 目录中的服务数
}

// Range 把页面的范围选项（today / 7d / 30d / month）换算为起止日期。
func (m *Manager) Range(rng string) (from, to time.Time) {
	now := m.now().In(m.loc)
	to = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, m.loc)
	switch rng {
	case "today":
		return to, to
	case "30d":
		return to.AddDate(0, 0, -29), to
	case "month":
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, m.loc), to
	}
	return to.AddDate(0, 0, -6), to
}

// cellRow 是复制出来的一条记录：汇总在锁外进行。
type cellRow struct {
	k cellKey
	c cell
}

// subjAgg 是一个终端的汇总。一个终端通常只用几个服务、几天，用切片线性查找，比每个终端建三个 map 快得多。
type subjAgg struct {
	row         SubjectRow
	first, last int64
	uses        []svcUse
	days        []day // 有使用的日子（不重复）
}

type svcUse struct {
	id   string
	n    int64 // 使用量（排序用）
	used bool  // 用过（不只是被拦截的尝试）
}

func (sa *subjAgg) use(id string, n int64, used bool) {
	for i := range sa.uses {
		if sa.uses[i].id == id {
			sa.uses[i].n += n
			sa.uses[i].used = sa.uses[i].used || used
			return
		}
	}
	sa.uses = append(sa.uses, svcUse{id: id, n: n, used: used})
}

func (sa *subjAgg) usedOn(d day) {
	for _, x := range sa.days {
		if x == d {
			return
		}
	}
	sa.days = append(sa.days, d)
}

type svcAgg struct {
	row         ServiceRow
	first, last int64
}

// Report 汇总查询范围内的使用情况。持锁期间只复制范围内的记录与目录，汇总在锁外进行：
// 满规模（30 万条记录）时汇总要几百毫秒，此前全程持锁，期间流水线的统计都要等它。
func (m *Manager) Report(q Query) *Report {
	if m == nil {
		return &Report{}
	}
	if q.To.IsZero() {
		_, q.To = m.Range("7d")
	}
	if q.From.IsZero() || q.From.After(q.To) {
		q.From = q.To
	}
	if q.Limit <= 0 {
		q.Limit = 500
	}
	d0, d1 := m.dayOf(q.From), m.dayOf(q.To)
	m.mu.Lock()
	rows := m.rowsLocked(d0, d1, q.IP, q.Service)
	svcs := make(map[string]Service, len(m.services))
	for id, s := range m.services {
		svcs[id] = *s
	}
	firstSeen := make(map[string]time.Time, len(m.svcSeen))
	for id, s := range m.svcSeen {
		firstSeen[id] = s.First
	}
	var cands []Candidate
	var eps []Endpoint
	if q.IP == "" && q.Service == "" {
		for _, c := range m.candidates {
			if !c.Ignored {
				cp := *c
				cp.clients = nil
				cands = append(cands, cp)
			}
		}
		for _, e := range m.endpoints {
			cp := *e
			cp.clients = nil
			eps = append(eps, cp)
		}
	}
	cov := m.coverageLocked()
	m.mu.Unlock()

	r := &Report{From: q.From.In(m.loc).Format("2006-01-02"), To: q.To.In(m.loc).Format("2006-01-02"), Subjects: []SubjectRow{},
		Services: []ServiceRow{}, Candidates: []Candidate{}, Endpoints: []Endpoint{}, Coverage: cov}
	svc := map[string]*svcAgg{}
	subjects := map[string]*subjAgg{}
	days := map[day]*DayRow{}
	for i := range rows {
		k, c := rows[i].k, &rows[i].c
		s, ok := svcs[k.svc]
		if !ok {
			continue
		}
		a := svc[k.svc]
		if a == nil {
			a = &svcAgg{row: ServiceRow{Service: s}, first: c.first, last: c.last}
			svc[k.svc] = a
		}
		a.row.Queries += c.queries
		a.row.Conns += c.conns
		a.row.Denied += c.denied
		a.row.Up = satAdd(a.row.Up, c.up)
		a.row.Down = satAdd(a.row.Down, c.down)
		a.first, a.last = min(a.first, c.first), max(a.last, c.last)
		sa := subjects[k.ip]
		if sa == nil {
			sa = &subjAgg{row: SubjectRow{IP: k.ip}, first: c.first, last: c.last}
			subjects[k.ip] = sa
		}
		sa.row.Queries += c.queries
		sa.row.Conns += c.conns
		sa.row.Denied += c.denied
		sa.row.Up = satAdd(sa.row.Up, c.up)
		sa.row.Down = satAdd(sa.row.Down, c.down)
		sa.first, sa.last = min(sa.first, c.first), max(sa.last, c.last)
		used := c.queries+c.conns > 0 || c.up > 0 // 只有被拦截的尝试不算“使用”
		sa.use(k.svc, c.queries+c.conns+c.denied+c.up/65536+1, used)
		if used {
			sa.usedOn(k.d)
			if s.Policy == PolicyDeny {
				sa.row.Deny = true
			}
			if s.Region == RegionOverseas {
				sa.row.Overseas = true
				r.Totals.OverseasUp = satAdd(r.Totals.OverseasUp, c.up)
			}
		}
		dr := days[k.d]
		if dr == nil {
			dr = &DayRow{}
			days[k.d] = dr
		}
		dr.Requests += c.queries + c.conns
		dr.Up = satAdd(dr.Up, c.up)
		dr.Denied += c.denied
		if s.Region == RegionOverseas {
			dr.OverseasUp = satAdd(dr.OverseasUp, c.up)
		}
		r.Totals.Queries += c.queries
		r.Totals.Conns += c.conns
		r.Totals.Denied += c.denied
		r.Totals.Up = satAdd(r.Totals.Up, c.up)
		r.Totals.Down = satAdd(r.Totals.Down, c.down)
		if q.IP != "" {
			r.Detail = append(r.Detail, ServiceUse{Date: m.dateOf(k.d).Format("2006-01-02"), Service: k.svc, Name: s.Name, Queries: c.queries, Conns: c.conns,
				Denied: c.denied, Up: c.up, Down: c.down, First: c.first, Last: c.last})
		}
	}
	// 按终端汇总后再数各服务、类别、每天的使用者：比逐条记录维护按地址的集合快得多
	svcSubj := map[string]int{}
	catSubj := map[string]int64{}
	daySubj := map[day]int{}
	var cats []string
	for _, sa := range subjects {
		cats = cats[:0]
		nUsed := 0
		for _, u := range sa.uses {
			if !u.used {
				continue
			}
			nUsed++
			svcSubj[u.id]++
			if c := svcs[u.id].Category; !slices.Contains(cats, c) {
				cats = append(cats, c)
			}
		}
		for _, c := range cats {
			catSubj[c]++
		}
		for _, d := range sa.days {
			daySubj[d]++
		}
		sort.Slice(sa.uses, func(i, j int) bool {
			if sa.uses[i].n != sa.uses[j].n {
				return sa.uses[i].n > sa.uses[j].n
			}
			return sa.uses[i].id < sa.uses[j].id
		})
		ids := make([]string, len(sa.uses))
		for i, u := range sa.uses {
			ids[i] = u.id
		}
		sa.row.Services = ids
		sa.row.First, sa.row.Last = time.Unix(sa.first, 0).In(m.loc), time.Unix(sa.last, 0).In(m.loc)
		if sa.row.Deny {
			r.Totals.DenySubjects++
		}
		if sa.row.Overseas {
			r.Totals.OverseasSubj++
		}
		if nUsed > 0 {
			r.Totals.Subjects++
		}
		r.Subjects = append(r.Subjects, sa.row)
	}
	for id, a := range svc {
		a.row.Subjects = svcSubj[id]
		a.row.First, a.row.Last = time.Unix(a.first, 0).In(m.loc), time.Unix(a.last, 0).In(m.loc)
		if t, ok := firstSeen[id]; ok {
			a.row.FirstAll = t.In(m.loc)
			a.row.New = m.dayOf(t) >= d0 && m.dayOf(t) <= d1
		}
		if a.row.New {
			r.Totals.NewServices++
		}
		if a.row.Subjects > 0 {
			r.Totals.Services++
		}
		r.Services = append(r.Services, a.row)
	}
	sort.Slice(r.Services, func(i, j int) bool {
		a, b := r.Services[i], r.Services[j]
		if a.Subjects != b.Subjects {
			return a.Subjects > b.Subjects
		}
		if a.Queries+a.Conns != b.Queries+b.Conns {
			return a.Queries+a.Conns > b.Queries+b.Conns
		}
		return a.ID < b.ID
	})
	r.SubjectsAll = len(r.Subjects)
	sort.Slice(r.Subjects, func(i, j int) bool {
		a, b := r.Subjects[i], r.Subjects[j]
		if a.Deny != b.Deny {
			return a.Deny
		}
		if a.Up != b.Up {
			return a.Up > b.Up
		}
		if len(a.Services) != len(b.Services) {
			return len(a.Services) > len(b.Services)
		}
		if a.Queries+a.Conns != b.Queries+b.Conns {
			return a.Queries+a.Conns > b.Queries+b.Conns
		}
		return a.IP < b.IP
	})
	if len(r.Subjects) > q.Limit {
		r.Subjects = r.Subjects[:q.Limit]
	}
	for d := d0; d <= d1 && d-d0 < 400; d++ {
		row := DayRow{}
		if dr := days[d]; dr != nil {
			row = *dr
		}
		row.Date = m.dateOf(d).Format("2006-01-02")
		row.Subjects = daySubj[d]
		r.Daily = append(r.Daily, row)
	}
	for cat, n := range catSubj {
		r.Categories = append(r.Categories, RankItem{Name: cat, Value: n})
	}
	sort.Slice(r.Categories, func(i, j int) bool {
		if r.Categories[i].Value != r.Categories[j].Value {
			return r.Categories[i].Value > r.Categories[j].Value
		}
		return r.Categories[i].Name < r.Categories[j].Name
	})
	sort.Slice(r.Detail, func(i, j int) bool {
		if r.Detail[i].Date != r.Detail[j].Date {
			return r.Detail[i].Date > r.Detail[j].Date
		}
		return r.Detail[i].Last > r.Detail[j].Last
	})
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.Clients != b.Clients {
			return a.Clients > b.Clients
		}
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		return a.Domain < b.Domain
	})
	r.Candidates = append(r.Candidates, cands[:min(len(cands), 200)]...)
	sort.Slice(eps, func(i, j int) bool {
		a, b := eps[i], eps[j]
		if a.Internal != b.Internal {
			return a.Internal
		}
		if a.Clients != b.Clients {
			return a.Clients > b.Clients
		}
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		return a.Host < b.Host
	})
	r.Endpoints = append(r.Endpoints, eps[:min(len(eps), 200)]...)
	return r
}

// rowsLocked 复制自然日范围内（可按终端、服务筛选）的记录（调用方持锁）。
func (m *Manager) rowsLocked(d0, d1 day, ip, svc string) []cellRow {
	rows := make([]cellRow, 0, 256)
	for k, c := range m.cells {
		if k.d < d0 || k.d > d1 || ip != "" && k.ip != ip || svc != "" && k.svc != svc {
			continue
		}
		rows = append(rows, cellRow{k: k, c: *c})
	}
	return rows
}

func (m *Manager) coverageLocked() Coverage {
	cv := Coverage{SNI: m.sniSeen, Bytes: m.bytesSeen, Records: len(m.cells), MaxRecords: m.maxRecs, Dropped: m.dropped, RetentionDays: m.keepDays,
		Services: len(m.services)}
	if m.minDay != 0 && len(m.cells) > 0 {
		cv.Since = m.dateOf(m.minDay).Format("2006-01-02")
	}
	return cv
}

// Brief 是周报 / 月报中的 AI 使用摘要：只有汇总与服务排行，不列出具体终端（报告会通过邮件发送给更多人）。
type Brief struct {
	Subjects     int        `json:"subjects"`
	Services     int        `json:"services"`
	OverseasSubj int        `json:"overseas_subj"`
	OverseasUp   int64      `json:"overseas_up"`
	Up           int64      `json:"up"`
	DenySubjects int        `json:"deny_subjects"`
	Denied       int64      `json:"denied"`
	BytesKnown   bool       `json:"bytes_known"`
	Top          []RankItem `json:"top"`           // 服务 → 终端数
	DenyServices []string   `json:"deny_services"` // 有人使用的“禁止”类服务
	NewServices  []string   `json:"new_services"`
}

// Brief 汇总起止日期内的使用情况。没有任何记录时返回 nil。
func (m *Manager) Brief(from, to time.Time) *Brief {
	if m == nil {
		return nil
	}
	r := m.Report(Query{From: from, To: to, Limit: 1})
	if r.Totals.Subjects == 0 && r.Totals.Denied == 0 {
		return nil
	}
	b := &Brief{Subjects: r.Totals.Subjects, Services: r.Totals.Services, OverseasSubj: r.Totals.OverseasSubj, OverseasUp: r.Totals.OverseasUp,
		Up: r.Totals.Up, DenySubjects: r.Totals.DenySubjects, Denied: r.Totals.Denied, BytesKnown: r.Coverage.Bytes, Top: []RankItem{},
		DenyServices: []string{}, NewServices: []string{}}
	for _, s := range r.Services {
		if s.Subjects == 0 {
			continue
		}
		if len(b.Top) < 10 {
			b.Top = append(b.Top, RankItem{Name: s.Name, Value: int64(s.Subjects)})
		}
		if s.Policy == PolicyDeny {
			b.DenyServices = append(b.DenyServices, s.Name)
		}
		if s.New {
			b.NewServices = append(b.NewServices, s.Name)
		}
	}
	return b
}

// ---------------- 目录管理 ----------------

// CatalogItem 是目录中的一项及其近 30 天的使用者数。
type CatalogItem struct {
	Service
	Subjects30 int `json:"subjects_30d"`
}

// Catalog 返回生效的服务目录（按目录顺序）。
func (m *Manager) Catalog() []CatalogItem {
	if m == nil {
		return []CatalogItem{}
	}
	cut := m.dayOf(m.now()) - 29
	m.mu.Lock()
	rows := m.rowsLocked(cut, m.dayOf(m.now())+1, "", "")
	out := make([]CatalogItem, 0, len(m.order))
	for _, id := range m.order {
		s := *m.services[id]
		s.Domains = append([]string(nil), s.Domains...)
		out = append(out, CatalogItem{Service: s})
	}
	m.mu.Unlock()
	users := map[string]map[string]bool{} // 锁外统计近 30 天的使用者
	for _, r := range rows {
		if r.c.queries+r.c.conns > 0 {
			if users[r.k.svc] == nil {
				users[r.k.svc] = map[string]bool{}
			}
			users[r.k.svc][r.k.ip] = true
		}
	}
	for i := range out {
		out[i].Subjects30 = len(users[out[i].ID])
	}
	return out
}

// SetPolicy 在页面设定服务的使用策略；policy 为空时清除页面设定（恢复配置文件中的策略）。返回生效后的服务。
func (m *Manager) SetPolicy(id, policy string) (Service, error) {
	if m == nil {
		return Service{}, errors.New("AI 使用统计未启用")
	}
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "inherit" {
		policy = ""
	}
	if err := validPolicy(policy); err != nil {
		return Service{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.services[id]; !ok {
		return Service{}, fmt.Errorf("服务 %s 不存在", id)
	}
	if policy == "" {
		delete(m.uiPol, id)
	} else {
		m.uiPol[id] = policy
	}
	m.rebuildLocked()
	m.dirty = true
	return *m.services[id], nil
}

// AddService 在页面登记服务（目录中没有的 AI 服务、API 中转站、单位自建的模型服务）。
func (m *Manager) AddService(s Service) (Service, error) {
	if m == nil {
		return Service{}, errors.New("AI 使用统计未启用")
	}
	b := make([]byte, 5)
	rand.Read(b)
	s.ID, s.Source, s.PolicyFrom = "ui-"+hex.EncodeToString(b), SourceUI, ""
	s.Category = strings.TrimSpace(s.Category)
	s.Region = strings.TrimSpace(s.Region)
	s.Policy = strings.ToLower(strings.TrimSpace(s.Policy))
	if err := s.prepare(); err != nil {
		return Service{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.uiSvcs) >= maxServices {
		return Service{}, fmt.Errorf("页面登记的服务最多 %d 个", maxServices)
	}
	for _, d := range s.Domains {
		for _, u := range m.uiSvcs {
			for _, x := range u.Domains {
				if x == d {
					return Service{}, fmt.Errorf("域名 %s 已登记在 %s 中", d, u.Name)
				}
			}
		}
	}
	if s.Policy != "" {
		m.uiPol[s.ID] = s.Policy
	}
	s.Policy = ""
	m.uiSvcs = append(m.uiSvcs, s)
	// 登记后不再作为疑似域名列出
	for _, d := range s.Domains {
		delete(m.candidates, registered(strings.TrimPrefix(d, "*")))
	}
	m.rebuildLocked()
	m.dirty = true
	return *m.services[s.ID], nil
}

// DeleteService 删除页面登记的服务及其使用记录。内置与配置文件中的服务不能删除（可在配置中停用）。
func (m *Manager) DeleteService(id string) (Service, error) {
	if m == nil {
		return Service{}, errors.New("AI 使用统计未启用")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.uiSvcs {
		if s.ID != id {
			continue
		}
		m.uiSvcs = append(m.uiSvcs[:i:i], m.uiSvcs[i+1:]...)
		delete(m.uiPol, id)
		delete(m.svcSeen, id)
		for k := range m.cells {
			if k.svc == id {
				delete(m.cells, k)
			}
		}
		m.rebuildLocked()
		m.dirty = true
		return s, nil
	}
	if _, ok := m.services[id]; ok {
		return Service{}, errors.New("内置与配置文件中的服务不能删除，可在配置文件 ai_usage.disable 中停用")
	}
	return Service{}, fmt.Errorf("服务 %s 不存在", id)
}

// IgnoreCandidate 忽略（或恢复）一个疑似 AI 域名。
func (m *Manager) IgnoreCandidate(domain string, ignore bool) error {
	if m == nil {
		return errors.New("AI 使用统计未启用")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.candidates[strings.ToLower(strings.TrimSpace(domain))]
	if c == nil {
		return fmt.Errorf("疑似域名 %s 不存在", domain)
	}
	c.Ignored = ignore
	m.dirty = true
	return nil
}

// Service 返回目录中的服务。
func (m *Manager) Service(id string) (Service, bool) {
	if m == nil {
		return Service{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.services[id]
	if !ok {
		return Service{}, false
	}
	return *s, true
}

// UsageRow 是一个终端在查询范围内使用一个服务的汇总（导出 CSV 使用）。
type UsageRow struct {
	IP      string
	Service Service
	Queries int64
	Conns   int64
	Denied  int64
	Up      int64
	Down    int64
	First   time.Time
	Last    time.Time
}

// Rows 返回查询范围内按“终端 + 服务”汇总的记录，按终端、服务排序。
func (m *Manager) Rows(q Query) []UsageRow {
	if m == nil {
		return nil
	}
	d0, d1 := m.dayOf(q.From), m.dayOf(q.To)
	m.mu.Lock()
	rows := m.rowsLocked(d0, d1, q.IP, q.Service)
	svcs := make(map[string]Service, len(m.services))
	for id, s := range m.services {
		svcs[id] = *s
	}
	m.mu.Unlock()
	type key struct{ ip, svc string }
	agg := map[key]*UsageRow{}
	for i := range rows {
		k, c := rows[i].k, &rows[i].c
		s, ok := svcs[k.svc]
		if !ok {
			continue
		}
		first, last := time.Unix(c.first, 0).In(m.loc), time.Unix(c.last, 0).In(m.loc)
		r := agg[key{k.ip, k.svc}]
		if r == nil {
			r = &UsageRow{IP: k.ip, Service: s, First: first, Last: last}
			agg[key{k.ip, k.svc}] = r
		}
		r.Queries += c.queries
		r.Conns += c.conns
		r.Denied += c.denied
		r.Up = satAdd(r.Up, c.up)
		r.Down = satAdd(r.Down, c.down)
		if first.Before(r.First) {
			r.First = first
		}
		if last.After(r.Last) {
			r.Last = last
		}
	}
	out := make([]UsageRow, 0, len(agg))
	for _, r := range agg {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].Service.ID < out[j].Service.ID
	})
	return out
}
