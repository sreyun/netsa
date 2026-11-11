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
// 只有防火墙会话 / 流量记录（以及解析器标为出站的事件）的目的地址才是内网主机主动连接的对端：
// DNS 日志的目的地址是被查询的 DNS 服务器（恶意的是域名，不是解析器），访问日志的是记录日志的服务器自己，
// 认证日志的是被登录的主机。把它们当成外部目标会在地图上画出飞向 8.8.8.8 或本单位网站的“内部对外”飞线。
func outboundEvent(ev *model.Event) bool {
	if ev.DstIP == "" || ev.DstIP == ev.SrcIP || ev.Response {
		return false
	}
	if ev.Kind != model.KindFirewall && !ev.Outbound {
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
	sumLat      float64 // 精确坐标累加
	sumLon      float64
	exact       int
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
				ProvinceMap: g.ProvinceMap, CityMap: g.CityMap, CoordSource: g.CoordSource, hostSet: map[string]bool{}}
			if g.Label != "" {
				mp.Name = g.Label
			}
			byKey[key] = mp
		}
		if g.Label == "" { // 同一地点的多种写法：展示名取更完整的，不随遍历顺序变化
			if name := placeName(g.Country, g.Province, g.City); betterPlaceName(mp.Name, name) != mp.Name {
				mp.Name, mp.Province, mp.City = name, g.Province, g.City
			}
		}
		// 坐标与攻击来源的标注一致：有精确坐标的成员取均值，否则用区划中心点
		if g.CoordSource == "maxmind" || g.CoordSource == "ip-api" {
			mp.exact++
			mp.sumLat += g.Lat
			mp.sumLon += g.Lon
			mp.CoordSource = g.CoordSource
		} else if mp.exact == 0 {
			mp.Lat, mp.Lon = g.Lat, g.Lon
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
		if mp.exact > 0 {
			mp.Lat, mp.Lon = mp.sumLat/float64(mp.exact), mp.sumLon/float64(mp.exact)
		}
		sort.Slice(mp.Items, func(i, j int) bool {
			if mp.Items[i].Level != mp.Items[j].Level {
				return mp.Items[i].Level > mp.Items[j].Level
			}
			if mp.Items[i].Hits != mp.Items[j].Hits {
				return mp.Items[i].Hits > mp.Items[j].Hits
			}
			return mp.Items[i].IP < mp.Items[j].IP
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
		if pts[i].Hits != pts[j].Hits {
			return pts[i].Hits > pts[j].Hits
		}
		return pts[i].Key < pts[j].Key
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

// GeoPending 返回还缺在线定位的攻击源与内部对外目标（最多 limit 个，等级高、攻击多的在前）。
// 在线定位失败或当时没有结果的地址只有等级再次提升才会重新查询，等级不再变化的一直停在离线库的结果上
// （境外地址只有国家级坐标，在地图上堆在国家中心）；由调用方定期取出这些地址重新发起（geo.Resolver.Enrich 按间隔退避）。
// needs 判断一个定位结果是否还缺在线定位（geo.Resolver.NeedsOnline）。
func (s *Store) GeoPending(minLevel model.Severity, needs func(*geo.Info) bool, limit int) []string {
	if needs == nil || limit <= 0 {
		return nil
	}
	type cand struct {
		ip      string
		level   model.Severity
		attacks int64
	}
	var list []cand
	s.mu.RLock()
	for ip, p := range s.ips {
		// 内网地址不提交在线定位（定位结果里通常已标为内网，这里再按地址判断一次）
		if isAttacker(p) && p.Level >= minLevel && p.Level > model.SevInfo && p.Geo != nil && !geo.IsPrivate(ip) && needs(p.Geo) {
			list = append(list, cand{ip, p.Level, p.Attacks})
		}
	}
	for ip, d := range s.outbound {
		if _, dup := s.ips[ip]; dup && isAttacker(s.ips[ip]) {
			continue
		}
		if d.Geo == nil || needs(d.Geo) {
			list = append(list, cand{ip, d.Level, d.Hits})
		}
	}
	s.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool {
		if list[i].level != list[j].level {
			return list[i].level > list[j].level
		}
		if list[i].attacks != list[j].attacks {
			return list[i].attacks > list[j].attacks
		}
		return list[i].ip < list[j].ip
	})
	if len(list) > limit {
		list = list[:limit]
	}
	out := make([]string, len(list))
	for i, c := range list {
		out[i] = c.ip
	}
	return out
}
