package store

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/model"
)

// KV 是排行榜条目。
type KV struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

func topN[K comparable](m map[K]int64, n int, name func(K) string) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{name(k), v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func ident(s string) string { return s }

// Overview 是态势总览数据。
type Overview struct {
	Totals       Totals           `json:"totals"`
	UniqueIPs    int              `json:"unique_ips"`
	Attackers    int              `json:"attackers"`
	LevelCounts  map[string]int   `json:"level_counts"`
	SevCounts    map[string]int64 `json:"sev_counts"`
	Categories   []KV             `json:"categories"`
	Phases       map[string]int64 `json:"phases"`
	Results      map[string]int64 `json:"results"`
	TopRules     []KV             `json:"top_rules"`
	TopCountries []KV             `json:"top_countries"`
	TopProvinces []KV             `json:"top_provinces"`
	TopCities    []KV             `json:"top_cities"`
	TopISPs      []KV             `json:"top_isps"`
	TopNetTypes  []KV             `json:"top_net_types"`
	TopPorts     []KV             `json:"top_ports"`
	TopTargets   []KV             `json:"top_targets"`
	ThreatIndex  float64          `json:"threat_index"`
	ThreatLevel  string           `json:"threat_level"`
	BlockRate    float64          `json:"block_rate"`
	Recent       struct {
		Attacks   int64 `json:"attacks"`
		Attackers int   `json:"attackers"`
	} `json:"recent"` // 最近 60 分钟
	From         time.Time `json:"from"`
	To           time.Time `json:"to"`
	SurfaceScore int       `json:"surface_score"`
	Findings     int       `json:"findings"`
	CountryCount int       `json:"country_count"` // 攻击来源国家/地区数
	CityCount    int       `json:"city_count"`    // 攻击来源城市数
}

func isAttacker(p *IPProfile) bool { return p.Attacks > 0 || len(p.Intel) > 0 }

func (s *Store) Overview() *Overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o := &Overview{
		Totals: s.totals, UniqueIPs: len(s.ips), LevelCounts: map[string]int{}, SevCounts: map[string]int64{},
		Phases: copyMap(s.phases), Results: copyMap(s.results), From: s.minTime, To: s.maxTime,
	}
	for i, v := range s.sevCount {
		o.SevCounts[model.Severity(i).String()] = v
	}
	o.Categories = topN(s.categories, 0, ident)
	o.TopRules = topN(s.rules, 10, func(id string) string { return s.ruleNames[id] })

	countries, provinces, cities, isps, nettypes, targets := map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}, map[string]int64{}
	recentCut := s.maxTime.Add(-time.Hour)
	for _, p := range s.ips {
		if !isAttacker(p) {
			continue
		}
		o.Attackers++
		o.LevelCounts[p.Level.String()]++
		if p.LastSeen.After(recentCut) {
			o.Recent.Attackers++
		}
		country, prov, city, isp, nt := "未知", "", "", "", "未知"
		if g := p.Geo; g != nil {
			if g.Country != "" {
				country = g.Country
			}
			// 省份使用中国地图中的规范名称（"广东省" 与 "广东" 合并统计）
			prov = g.ProvinceMap
			if g.City != "" {
				if prov != "" {
					city = placeName(prov, "", g.City)
				} else {
					city = placeName(country, g.Province, g.City)
				}
			}
			isp = g.ISP
			if g.NetType != "" {
				nt = g.NetType
			}
		}
		countries[country]++
		if prov != "" {
			provinces[prov]++
		}
		if city != "" {
			cities[city]++
		}
		if isp != "" {
			isps[isp]++
		}
		nettypes[nt]++
		for t, n := range p.Targets {
			if len(targets) < 20000 || targets[t] > 0 {
				targets[t] += int64(n)
			}
		}
	}
	o.TopCountries = topN(countries, 15, ident)
	o.TopProvinces = topN(provinces, 15, ident)
	o.TopCities = topN(cities, 15, ident)
	o.CountryCount, o.CityCount, o.Findings = len(countries), len(cities), len(s.surf.Findings)
	if _, ok := countries["未知"]; ok {
		o.CountryCount--
	}
	o.TopISPs = topN(isps, 10, ident)
	o.TopNetTypes = topN(nettypes, 0, ident)
	o.TopTargets = topN(targets, 10, ident)
	o.TopPorts = topN(s.surf.Ports, 10, func(p int) string {
		name, _ := serviceInfo(p)
		return itoa(p) + "/" + name
	})
	if s.totals.Attacks > 0 {
		o.BlockRate = math.Round(float64(s.totals.Blocked)/float64(s.totals.Attacks)*1000) / 10
	}

	// 威胁指数：最近 60 分钟按严重程度加权的攻击量，经指数饱和映射到 0-100。
	var weighted float64
	cut := recentCut.Unix() / 60
	for k, b := range s.buckets {
		if k >= cut {
			o.Recent.Attacks += b.Attacks
			weighted += float64(b.Sev[1]) + 3*float64(b.Sev[2]) + 8*float64(b.Sev[3]) + 20*float64(b.Sev[4])
		}
	}
	o.ThreatIndex = math.Round(100 * (1 - math.Exp(-weighted/600)))
	switch {
	case o.ThreatIndex >= 80:
		o.ThreatLevel = "critical"
	case o.ThreatIndex >= 60:
		o.ThreatLevel = "high"
	case o.ThreatIndex >= 35:
		o.ThreatLevel = "medium"
	case o.ThreatIndex >= 10:
		o.ThreatLevel = "low"
	default:
		o.ThreatLevel = "info"
	}
	o.SurfaceScore = s.surfaceScoreLocked()
	return o
}

func copyMap[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }

// Timeline 返回最近 minutes 分钟（以最新日志时间为基准）的趋势数据。
func (s *Store) Timeline(minutes int) []Bucket {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.maxTime.IsZero() {
		return nil
	}
	if minutes <= 0 {
		minutes = 60
	}
	end := s.maxTime.Unix() / 60
	start := end - int64(minutes) + 1
	if min := s.minTime.Unix() / 60; start < min && minutes > 60 {
		start = min
	}
	step := int64(1)
	if n := end - start + 1; n > 360 {
		step = (n + 359) / 360
	}
	var out []Bucket
	for t := start; t <= end; t += step {
		agg := Bucket{T: t * 60}
		for k := t; k < t+step; k++ {
			if b := s.buckets[k]; b != nil {
				agg.Web += b.Web
				agg.Fw += b.Fw
				agg.Attacks += b.Attacks
				agg.Blocked += b.Blocked
				for i := range agg.Sev {
					agg.Sev[i] += b.Sev[i]
				}
			}
		}
		out = append(out, agg)
	}
	return out
}

// AttackerSummary 是攻击者列表条目。
type AttackerSummary struct {
	IP         string         `json:"ip"`
	Score      float64        `json:"score"`
	Level      model.Severity `json:"level"`
	MaxSev     model.Severity `json:"max_severity"`
	Attacks    int64          `json:"attacks"`
	Events     int64          `json:"events"`
	Successes  int64          `json:"successes"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Categories []string       `json:"categories"`
	Phases     []string       `json:"phases"`
	Tags       []string       `json:"tags"`
	Intel      []string       `json:"intel,omitempty"`
	Location   string         `json:"location"`
	Country    string         `json:"country"`
	Province   string         `json:"province,omitempty"`
	City       string         `json:"city,omitempty"`
	ISP        string         `json:"isp,omitempty"`
	ASN        uint           `json:"asn,omitempty"`
	NetType    string         `json:"net_type,omitempty"`
	Confidence string         `json:"confidence,omitempty"`
	Lat        float64        `json:"lat,omitempty"`
	Lon        float64        `json:"lon,omitempty"`
	HasCoord   bool           `json:"has_coord"`
	ViaProxy   bool           `json:"via_proxy,omitempty"`
}

var phaseOrder = []string{model.PhaseRecon, model.PhaseCredential, model.PhaseExploit, model.PhasePersistence, model.PhaseImpact}

func summarize(p *IPProfile) AttackerSummary {
	a := AttackerSummary{
		IP: p.IP, Score: p.Score, Level: p.Level, MaxSev: p.MaxSev, Attacks: p.Attacks, Events: p.Events,
		Successes: p.Successes, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen, Intel: p.Intel, ViaProxy: len(p.Proxies) > 0,
	}
	cats := make(map[string]int64, len(p.Categories))
	for k, v := range p.Categories {
		cats[k] = int64(v)
	}
	for _, kv := range topN(cats, 4, ident) {
		a.Categories = append(a.Categories, kv.Name)
	}
	for _, ph := range phaseOrder {
		if p.Phases[ph] > 0 {
			a.Phases = append(a.Phases, ph)
		}
	}
	for t := range p.Tags {
		a.Tags = append(a.Tags, t)
	}
	sort.Strings(a.Tags)
	if g := p.Geo; g != nil {
		a.Location, a.Country, a.Province, a.City = g.Location(), g.Country, g.Province, g.City
		a.ISP, a.ASN, a.NetType, a.Confidence = g.ISP, g.ASN, g.NetType, g.Confidence
		a.Lat, a.Lon, a.HasCoord = g.Lat, g.Lon, g.HasCoord
	}
	return a
}

// AttackerQuery 攻击者查询条件。
type AttackerQuery struct {
	MinLevel model.Severity
	Search   string
	Sort     string // score | attacks | last
	Limit    int
	Offset   int
}

func (s *Store) Attackers(q AttackerQuery) ([]AttackerSummary, int) {
	s.mu.RLock()
	var list []AttackerSummary
	search := strings.ToLower(q.Search)
	for _, p := range s.ips {
		if !isAttacker(p) || p.Level < q.MinLevel {
			continue
		}
		a := summarize(p)
		if search != "" && !strings.Contains(strings.ToLower(a.IP+" "+a.Location+" "+strings.Join(a.Tags, " ")+" "+strings.Join(a.Categories, " ")), search) {
			continue
		}
		list = append(list, a)
	}
	s.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool {
		x, y := list[i], list[j]
		switch q.Sort {
		case "attacks":
			if x.Attacks != y.Attacks {
				return x.Attacks > y.Attacks
			}
		case "last":
			if !x.LastSeen.Equal(y.LastSeen) {
				return x.LastSeen.After(y.LastSeen)
			}
		}
		if x.Score != y.Score {
			return x.Score > y.Score
		}
		return x.Attacks > y.Attacks
	})
	total := len(list)
	if q.Offset > 0 {
		if q.Offset >= len(list) {
			return nil, total
		}
		list = list[q.Offset:]
	}
	if q.Limit > 0 && len(list) > q.Limit {
		list = list[:q.Limit]
	}
	return list, total
}

// IPDetail 是 IP 溯源详情。
type IPDetail struct {
	Summary AttackerSummary `json:"summary"`
	Profile *IPProfile      `json:"profile"`
	Chain   []ChainStep     `json:"chain"`
	Rules   []RuleHit       `json:"rules"`
	Related *Correlation    `json:"related"` // 同源关联分析
}

type ChainStep struct {
	Phase string    `json:"phase"`
	First time.Time `json:"first"`
	Count int       `json:"count"`
}

type RuleHit struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Severity model.Severity `json:"severity"`
	Count    int            `json:"count"`
}

// IPDetail 返回 IP 溯源详情。同源关联分析在释放读锁后分批进行，不会长时间阻塞日志写入。
func (s *Store) IPDetail(ip string) *IPDetail {
	d := s.ipDetail(ip)
	if d != nil && isAttacker(d.Profile) {
		d.Related = s.correlate(d.Profile)
	}
	return d
}

func (s *Store) ipDetail(ip string) *IPDetail {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.ips[ip]
	if p == nil {
		return nil
	}
	cp := *p
	cp.Categories, cp.Rules, cp.RuleNames, cp.RuleSev = copyMap(p.Categories), copyMap(p.Rules), copyMap(p.RuleNames), copyMap(p.RuleSev)
	cp.Phases, cp.PhaseFirst, cp.Results, cp.Targets = copyMap(p.Phases), copyMap(p.PhaseFirst), copyMap(p.Results), copyMap(p.Targets)
	cp.Ports, cp.Status, cp.UAs, cp.Tags = copyMap(p.Ports), copyMap(p.Status), copyMap(p.UAs), copyMap(p.Tags)
	cp.Proxies = copyMap(p.Proxies)
	cp.CatSev, cp.CatPhase = copyMap(p.CatSev), copyMap(p.CatPhase)
	cp.Recent = append([]*model.Alert(nil), p.Recent...)
	cp.Intel = append([]string(nil), p.Intel...)
	d := &IPDetail{Summary: summarize(p), Profile: &cp}
	for _, ph := range phaseOrder {
		if n := p.Phases[ph]; n > 0 {
			d.Chain = append(d.Chain, ChainStep{ph, p.PhaseFirst[ph], n})
		}
	}
	for id, n := range p.Rules {
		d.Rules = append(d.Rules, RuleHit{id, p.RuleNames[id], p.RuleSev[id], n})
	}
	sort.Slice(d.Rules, func(i, j int) bool {
		if d.Rules[i].Severity != d.Rules[j].Severity {
			return d.Rules[i].Severity > d.Rules[j].Severity
		}
		return d.Rules[i].Count > d.Rules[j].Count
	})
	return d
}

// AlertQuery 告警查询条件。
type AlertQuery struct {
	MinSeverity model.Severity
	Category    string
	IP          string
	Result      string
	Kind        string
	Search      string
	SinceID     uint64
	Limit       int
}

// AlertSummary 说明告警列表与攻击命中计数之间的关系：同一 IP 同一规则在节流窗口内只记录前若干条告警，
// 其余重复命中只累加计数，因此“告警条数”少于“攻击命中次数”。
type AlertSummary struct {
	Retained      map[string]int   `json:"retained"`       // 当前保留的告警（按等级）
	RetainedTotal int              `json:"retained_total"` // 当前保留的告警条数（受 max_alerts 限制）
	Recorded      int64            `json:"recorded"`       // 累计生成的告警条数
	Hits          map[string]int64 `json:"hits"`           // 攻击命中次数（按等级，含被节流的重复命中）
	HitsTotal     int64            `json:"hits_total"`
	PerRule       int              `json:"per_rule"` // 同一 IP 同一规则在窗口内最多记录的告警数
	Window        string           `json:"window"`
	MaxAlerts     int              `json:"max_alerts"`
}

func (s *Store) AlertSummary() *AlertSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := &AlertSummary{Retained: map[string]int{}, Hits: map[string]int64{}, Recorded: s.totals.Alerts, HitsTotal: s.totals.Attacks,
		PerRule: s.perRule, Window: throttleWindow.String(), MaxAlerts: s.maxAlerts, RetainedTotal: len(s.alerts)}
	for _, a := range s.alerts {
		res.Retained[a.Severity.String()]++
	}
	for sev, n := range s.sevCount {
		res.Hits[model.Severity(sev).String()] = n
	}
	return res
}

func (s *Store) Alerts(q AlertQuery) []*model.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if q.Limit <= 0 {
		q.Limit = 200
	}
	search := strings.ToLower(q.Search)
	var out []*model.Alert
	n := len(s.alerts)
	for i := 0; i < n && len(out) < q.Limit; i++ {
		// 从最新往前遍历环形缓冲区
		idx := (s.alertHead - 1 - i + 2*n) % n
		if n < s.maxAlerts {
			idx = n - 1 - i
		}
		a := s.alerts[idx]
		if a.ID <= q.SinceID ||
			a.Severity < q.MinSeverity ||
			(q.Category != "" && a.Category != q.Category) ||
			(q.IP != "" && a.SrcIP != q.IP) ||
			(q.Result != "" && a.Result != q.Result) ||
			(q.Kind != "" && string(a.Kind) != q.Kind) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(a.Name+" "+a.Target+" "+a.Evidence+" "+a.SrcIP+" "+a.Location), search) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// MapIP 是某一地点下的攻击源摘要。
type MapIP struct {
	IP      string         `json:"ip"`
	Score   float64        `json:"score"`
	Level   model.Severity `json:"level"`
	Attacks int64          `json:"attacks"`
	ISP     string         `json:"isp,omitempty"`
}

// MapPoint 是攻击来源地图上的一个地点（按 国家/省/市 聚合，城市未知时按省或国家）。
type MapPoint struct {
	Name        string         `json:"name"`
	Label       string         `json:"label,omitempty"`    // 自定义网段名称
	Internal    bool           `json:"internal,omitempty"` // 内网攻击源（命中自定义网段）
	Country     string         `json:"country"`
	Province    string         `json:"province,omitempty"`
	City        string         `json:"city,omitempty"`
	WorldName   string         `json:"world_name,omitempty"`
	ProvinceMap string         `json:"province_map,omitempty"`
	CityMap     string         `json:"city_map,omitempty"`
	Lat         float64        `json:"lat"`
	Lon         float64        `json:"lon"`
	CoordSource string         `json:"coord_source"` // maxmind / ip-api（精确）或 city / province / country（区划中心）
	Attackers   int            `json:"attackers"`
	Attacks     int64          `json:"attacks"`
	Level       model.Severity `json:"level"`
	IPs         []MapIP        `json:"ips"`
	sumLat      float64        // 精确坐标累加
	sumLon      float64
	exact       int
}

// MapRegion 是用于地图着色的区域统计。
type MapRegion struct {
	Name      string         `json:"name"`     // 展示名称
	MapName   string         `json:"map_name"` // 地图中的区域名
	Attackers int            `json:"attackers"`
	Attacks   int64          `json:"attacks"`
	Level     model.Severity `json:"level"`
}

// MapResult 是地图接口返回的数据。
type MapResult struct {
	Points    []*MapPoint  `json:"points"`
	Countries []*MapRegion `json:"countries"`
	Provinces []*MapRegion `json:"provinces"`
	NoCoord   int          `json:"no_coord"`
	Total     int          `json:"total"`
}

func addRegion(m map[string]*MapRegion, key, name string, p *IPProfile) {
	if key == "" {
		return
	}
	r := m[key]
	if r == nil {
		r = &MapRegion{Name: name, MapName: key}
		m[key] = r
	}
	r.Attackers++
	r.Attacks += p.Attacks
	if p.Level > r.Level {
		r.Level = p.Level
	}
}

func sortedRegions(m map[string]*MapRegion) []*MapRegion {
	out := make([]*MapRegion, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Attacks > out[j].Attacks })
	return out
}

// MapData 返回攻击来源地图数据：地点（带 IP 列表）、国家与中国省份的着色统计。
func (s *Store) MapData(minLevel model.Severity) *MapResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := &MapResult{}
	pts := map[string]*MapPoint{}
	countries, provinces := map[string]*MapRegion{}, map[string]*MapRegion{}
	for _, p := range s.ips {
		if !isAttacker(p) || p.Level < minLevel {
			continue
		}
		res.Total++
		g := p.Geo
		// 内网地址只有命中自定义网段（有具体办公地点）时才上图，且不参与国家 / 省份着色
		if g == nil || g.Private && g.Label == "" {
			res.NoCoord++
			continue
		}
		if !g.Private {
			addRegion(countries, g.WorldName, g.Country, p)
			addRegion(provinces, g.ProvinceMap, g.ProvinceMap, p)
		}
		if !g.HasCoord {
			res.NoCoord++
			continue
		}
		key := g.CountryCode + "|" + g.Province + "|" + g.City
		switch {
		case g.Label != "":
			key = "label|" + g.Label
		case g.City == "" && g.Province == "" && g.CoordSource != "country":
			// 只有精确坐标、没有地名时按约 10km 网格聚合
			key = fmt.Sprintf("xy|%.1f|%.1f", g.Lat, g.Lon)
		}
		mp := pts[key]
		if mp == nil {
			mp = &MapPoint{Country: g.Country, Province: g.Province, City: g.City, WorldName: g.WorldName,
				ProvinceMap: g.ProvinceMap, CityMap: g.CityMap, CoordSource: g.CoordSource}
			mp.Name = placeName(g.Country, g.Province, g.City)
			if g.Label != "" {
				mp.Label, mp.Internal, mp.Name = g.Label, g.Private, g.Label
			}
			pts[key] = mp
		}
		if g.CoordSource == "maxmind" || g.CoordSource == "ip-api" {
			// 精确坐标优先：同一城市多个 IP 取精确坐标的均值
			mp.exact++
			mp.sumLat += g.Lat
			mp.sumLon += g.Lon
			mp.CoordSource = g.CoordSource
		} else if mp.exact == 0 {
			// 区划中心点：同一地点的近似坐标相同
			mp.Lat, mp.Lon = g.Lat, g.Lon
		}
		mp.Attackers++
		mp.Attacks += p.Attacks
		if p.Level > mp.Level {
			mp.Level = p.Level
		}
		mp.IPs = append(mp.IPs, MapIP{IP: p.IP, Score: p.Score, Level: p.Level, Attacks: p.Attacks, ISP: g.ISP})
	}
	for _, mp := range pts {
		if mp.exact > 0 {
			mp.Lat, mp.Lon = mp.sumLat/float64(mp.exact), mp.sumLon/float64(mp.exact)
		}
		sort.Slice(mp.IPs, func(i, j int) bool {
			if mp.IPs[i].Score != mp.IPs[j].Score {
				return mp.IPs[i].Score > mp.IPs[j].Score
			}
			return mp.IPs[i].Attacks > mp.IPs[j].Attacks
		})
		if len(mp.IPs) > 10 {
			mp.IPs = mp.IPs[:10]
		}
		res.Points = append(res.Points, mp)
	}
	sort.Slice(res.Points, func(i, j int) bool { return res.Points[i].Attacks > res.Points[j].Attacks })
	if len(res.Points) > 800 {
		res.Points = res.Points[:800]
	}
	res.Countries, res.Provinces = sortedRegions(countries), sortedRegions(provinces)
	return res
}

// placeName 生成地点展示名，例如 "中国 广东省 深圳市"，省市相同（直辖市）时去重。
func placeName(country, province, city string) string {
	parts := []string{country}
	for _, s := range []string{province, city} {
		if s != "" && s != parts[len(parts)-1] && !strings.HasPrefix(s, parts[len(parts)-1]) {
			parts = append(parts, s)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// SurfaceReport 是攻击面分析结果。
type SurfaceReport struct {
	Score          int            `json:"score"`
	Findings       []*Finding     `json:"findings"`
	Services       []*Service     `json:"services"`
	Endpoints      []*Endpoint    `json:"endpoints"`
	EndpointTotal  int            `json:"endpoint_total"`
	Hosts          []KV           `json:"hosts"`
	Tech           []KV           `json:"tech"`
	TopPorts       []KV           `json:"top_ports"`
	ExploitBlocked int64          `json:"exploit_blocked"`
	ExploitPassed  int64          `json:"exploit_passed"`
	SeverityCount  map[string]int `json:"severity_count"`
}

var findingWeight = [...]int{0, 2, 5, 12, 25}

func (s *Store) surfaceScoreLocked() int {
	score := 0
	for _, f := range s.surf.Findings {
		score += findingWeight[f.Severity]
	}
	if s.surf.ExploitPassed > 20 && s.surf.ExploitBlocked == 0 {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (s *Store) Surface() *SurfaceReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sf := s.surf
	r := &SurfaceReport{
		Score: s.surfaceScoreLocked(), ExploitBlocked: sf.ExploitBlocked, ExploitPassed: sf.ExploitPassed,
		EndpointTotal: len(sf.Endpoints), SeverityCount: map[string]int{},
	}
	for _, f := range sf.Findings {
		c := *f
		r.Findings = append(r.Findings, &c)
		r.SeverityCount[f.Severity.String()]++
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Count > b.Count
	})
	if s.surf.ExploitPassed > 20 && s.surf.ExploitBlocked == 0 {
		r.Findings = append(r.Findings, &Finding{
			ID: "waf", Title: "未观测到 WAF 拦截", Category: "防护缺失", Severity: model.SevMedium, Asset: "全部站点",
			Evidence:    itoa(int(sf.ExploitPassed)) + " 次漏洞利用请求均未被拦截（无 403/406 等拦截响应）",
			Remediation: "部署 WAF（如 ModSecurity、云 WAF）或在 nginx 中配置基础拦截规则",
			Count:       sf.ExploitPassed,
		})
	}
	for _, sv := range sf.Services {
		c := *sv
		r.Services = append(r.Services, &c)
	}
	sort.Slice(r.Services, func(i, j int) bool {
		a, b := r.Services[i], r.Services[j]
		if a.Exposed != b.Exposed {
			return a.Exposed
		}
		if a.Risk != b.Risk {
			return a.Risk > b.Risk
		}
		return a.Sources > b.Sources
	})
	if len(r.Services) > 300 {
		r.Services = r.Services[:300]
	}
	hosts := map[string]int64{}
	for _, ep := range sf.Endpoints {
		hosts[ep.Host] += ep.Hits
		c := *ep
		c.Methods, c.Status, c.Tech = copyMap(ep.Methods), copyMap(ep.Status), append([]string(nil), ep.Tech...)
		r.Endpoints = append(r.Endpoints, &c)
	}
	sort.Slice(r.Endpoints, func(i, j int) bool {
		a, b := r.Endpoints[i], r.Endpoints[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Attacks != b.Attacks {
			return a.Attacks > b.Attacks
		}
		return a.Hits > b.Hits
	})
	if len(r.Endpoints) > 500 {
		r.Endpoints = r.Endpoints[:500]
	}
	r.Hosts = topN(hosts, 50, ident)
	tech := map[string]int64{}
	for k, v := range sf.Tech {
		tech[k] = int64(v)
	}
	r.Tech = topN(tech, 0, ident)
	r.TopPorts = topN(sf.Ports, 15, func(p int) string {
		name, _ := serviceInfo(p)
		return itoa(p) + "/" + name
	})
	return r
}

// Summary 返回单个 IP 的摘要。
func (s *Store) Summary(ip string) (AttackerSummary, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.ips[ip]
	if p == nil {
		return AttackerSummary{}, false
	}
	return summarize(p), true
}

// Blocklist 返回达到指定等级的攻击者（不含内网地址），按评分降序。
func (s *Store) Blocklist(min model.Severity) []AttackerSummary {
	list, _ := s.Attackers(AttackerQuery{MinLevel: min, Sort: "score"})
	out := list[:0]
	for _, a := range list {
		if a.NetType == "内网" {
			continue
		}
		skip := false
		for _, t := range a.Tags {
			if strings.HasPrefix(t, "搜索引擎爬虫") {
				skip = true
			}
		}
		if !skip {
			out = append(out, a)
		}
	}
	return out
}
