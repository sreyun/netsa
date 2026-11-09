package store

import (
	"net/netip"
	"sort"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

// 内部对外：内网主机攻击外部地址、连接已知恶意地址（木马回连 C2）、周期性外连、攻击后回连、数据外传等异常连接的外部目标。
//
// 这类告警以发起连接的内网主机为主体（攻击源画像），内网地址没有地理位置，攻击来源地图上原先完全看不到；
// 这里另外记录外部目标及其归属地，地图上从受保护资产飞向这些目标，与外部对内的攻击飞线区分显示。

const (
	maxOutbound = 500                // 记录的外部目标数上限（满了淘汰最久没有再出现的）
	maxOutHosts = 5                  // 每个目标记录的内网主机数
	outboundTTL = 7 * 24 * time.Hour // 超过这么久没有再出现的目标不再显示
)

// OutboundDst 是一个外部目标。
type OutboundDst struct {
	IP       string         `json:"ip"`
	Hits     int64          `json:"hits"`
	Level    model.Severity `json:"level"`
	Category string         `json:"category"` // 最高等级命中的攻击类型
	Name     string         `json:"name"`     // 最高等级命中的名称
	Hosts    []string       `json:"hosts"`    // 发起连接的内网主机（最多 5 个）
	First    time.Time      `json:"first"`
	Last     time.Time      `json:"last"`
	Geo      *geo.Info      `json:"geo,omitempty"`
}

// outboundEvent 判断事件是否为内部对外：来源是内网（或流量方向标为出站），目标是公网地址。
func outboundEvent(ev *model.Event) bool {
	if ev.DstIP == "" || ev.DstIP == ev.SrcIP || ev.Response {
		return false
	}
	if a, err := netip.ParseAddr(ev.DstIP); err != nil || !geo.IsPublic(a) {
		return false
	}
	return ev.Outbound || geo.IsPrivate(ev.SrcIP)
}

// observeOutboundLocked 记录内部对外的攻击或异常连接（调用方持写锁），返回是否新记录了这个外部目标。
func (s *Store) observeOutboundLocked(ev *model.Event, hits []model.Hit, t time.Time) (added bool) {
	if !outboundEvent(ev) {
		return false
	}
	var top *model.Hit
	for i := range hits {
		if h := &hits[i]; !h.TagOnly && (top == nil || h.Severity > top.Severity) {
			top = h
		}
	}
	if top == nil {
		return false
	}
	d := s.outbound[ev.DstIP]
	if d == nil {
		added = true
		if len(s.outbound) >= maxOutbound {
			s.evictOutboundLocked()
		}
		d = &OutboundDst{IP: ev.DstIP, First: t}
		if s.GeoLookup != nil {
			d.Geo = s.GeoLookup(ev.DstIP)
		}
		s.outbound[ev.DstIP] = d
	}
	d.Hits++
	if top.Severity >= d.Level || d.Category == "" {
		d.Level, d.Category, d.Name = max(d.Level, top.Severity), top.Category, top.Name
	}
	if t.After(d.Last) {
		d.Last = t
	}
	if t.Before(d.First) {
		d.First = t
	}
	if len(d.Hosts) < maxOutHosts && !containsStr(d.Hosts, ev.SrcIP) {
		d.Hosts = append(d.Hosts, ev.SrcIP)
	}
	return added
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// evictOutboundLocked 淘汰最久没有再出现的外部目标。
func (s *Store) evictOutboundLocked() {
	var oldest string
	var at time.Time
	for ip, d := range s.outbound {
		if oldest == "" || d.Last.Before(at) {
			oldest, at = ip, d.Last
		}
	}
	delete(s.outbound, oldest)
}

// pruneOutboundLocked 清理超过保留期没有再出现的外部目标（定期维护时调用）。
func (s *Store) pruneOutboundLocked(now time.Time) {
	for ip, d := range s.outbound {
		if now.Sub(d.Last) > outboundTTL {
			delete(s.outbound, ip)
		}
	}
}

// MapOutbound 是地图上同一地点的外部目标（内部对外）。
type MapOutbound struct {
	Key         string         `json:"key"`
	Name        string         `json:"name"`
	Country     string         `json:"country"`
	Province    string         `json:"province,omitempty"`
	City        string         `json:"city,omitempty"`
	WorldName   string         `json:"world_name,omitempty"`
	ProvinceMap string         `json:"province_map,omitempty"`
	CityMap     string         `json:"city_map,omitempty"`
	Lat         float64        `json:"lat"`
	Lon         float64        `json:"lon"`
	CoordSource string         `json:"coord_source,omitempty"`
	Targets     int            `json:"targets"` // 外部地址数
	Hosts       int            `json:"hosts"`   // 涉及的内网主机数（去重，按每个地址最多 5 台统计）
	Hits        int64          `json:"hits"`
	Level       model.Severity `json:"level"`
	Items       []*OutboundDst `json:"items"` // 按等级、次数排列的前 10 个地址
	hostSet     map[string]bool
}

// outboundPoints 按地点汇总外部目标（调用方持读锁）。
func (s *Store) outboundPoints(minLevel model.Severity) (pts []*MapOutbound, total, noCoord int) {
	byKey := map[string]*MapOutbound{}
	for _, d := range s.outbound {
		if d.Level < minLevel || s.maxTime.Sub(d.Last) > outboundTTL {
			continue
		}
		total++
		g := d.Geo
		key := ""
		if g != nil && !g.Private {
			key = mapKey(g)
		}
		if key == "" {
			noCoord++
			continue
		}
		mp := byKey[key]
		if mp == nil {
			mp = &MapOutbound{Key: key, Country: g.Country, Province: g.Province, City: g.City, WorldName: g.WorldName,
				ProvinceMap: g.ProvinceMap, CityMap: g.CityMap, Lat: g.Lat, Lon: g.Lon, CoordSource: g.CoordSource, hostSet: map[string]bool{}}
			mp.Name = placeName(g.Country, g.Province, g.City)
			if g.Label != "" {
				mp.Name = g.Label
			}
			byKey[key] = mp
		}
		mp.Targets++
		mp.Hits += d.Hits
		mp.Level = max(mp.Level, d.Level)
		for _, h := range d.Hosts {
			mp.hostSet[h] = true
		}
		mp.Items = append(mp.Items, d)
	}
	for _, mp := range byKey {
		mp.Hosts = len(mp.hostSet)
		sort.Slice(mp.Items, func(i, j int) bool {
			if mp.Items[i].Level != mp.Items[j].Level {
				return mp.Items[i].Level > mp.Items[j].Level
			}
			return mp.Items[i].Hits > mp.Items[j].Hits
		})
		if len(mp.Items) > 10 {
			mp.Items = mp.Items[:10]
		}
		// 返回副本：接口序列化发生在解锁之后，不能与写入共享对象
		items := make([]*OutboundDst, len(mp.Items))
		for i, d := range mp.Items {
			c := *d
			c.Hosts = append([]string(nil), d.Hosts...)
			c.Geo = nil
			items[i] = &c
		}
		mp.Items = items
		pts = append(pts, mp)
	}
	sort.Slice(pts, func(i, j int) bool {
		if pts[i].Level != pts[j].Level {
			return pts[i].Level > pts[j].Level
		}
		return pts[i].Hits > pts[j].Hits
	})
	if len(pts) > 300 {
		pts = pts[:300]
	}
	return pts, total, noCoord
}

// outboundList 返回外部目标列表（快照用，调用方持读锁）。
func (s *Store) outboundList() []*OutboundDst {
	out := make([]*OutboundDst, 0, len(s.outbound))
	for _, d := range s.outbound {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
