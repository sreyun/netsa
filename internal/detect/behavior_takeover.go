package detect

import (
	"fmt"
	"math"
	"strings"
	"time"

	"netsa/internal/model"
)

// 账号盗用（P3-3）：按账号（账号 + 登录方式 + 主机）记录成功登录的地点：
//   - 不可能的旅行（auth-impossible-travel）：同一账号两次成功登录的地点相距 500 km 以上，换算速度超过 900 km/h，高危；
//   - 首次从新的国家 / 地区登录（auth-new-country）：账号已有 7 天以上、5 次以上的登录记录，本次来自从未出现过的国家，中危；
//   - 多地并发登录（auth-concurrent）：10 分钟内从 3 个以上不同城市成功登录，中危。
// 只看公网来源；云服务器、代理与 VPN 出口（定位为托管 / 代理）的位置不可信，不参与判断。
// 画像不持久化：重启后重新学习（新国家需要再积累 7 天）。

const (
	travelMinKm      = 500
	travelMaxKmh     = 900
	newCountryAge    = 7 * 24 * time.Hour
	newCountryLogins = 5
	concWindow       = 10 * time.Minute
	concCities       = 3
	takeoverRefire   = 6 * time.Hour
	maxAccounts      = 50000
	maxAcctCountries = 16
)

type loginPoint struct {
	ip       string
	at       time.Time
	lat, lon float64
	country  string
	city     string
	precise  bool // 坐标到城市级（不是国家、省份的中心点，精度在 200 公里以内）
}

func (p loginPoint) place() string {
	s := p.country
	if p.city != "" && p.city != p.country {
		s += " " + p.city
	}
	return s + "（" + p.ip + "）"
}

type acctProfile struct {
	first     time.Time
	logins    int
	countries map[string]bool
	last      loginPoint
	recent    []loginPoint
	fired     map[string]time.Time // 规则 → 最近一次告警
}

// observeTakeover 判断成功登录是否为账号盗用（调用方持锁）。
func (b *Behavior) observeTakeover(ev *model.Event) []model.Hit {
	if b.Geo == nil || ev.Action != model.ActionAllow || ev.User == "" || ev.SrcIP == "" || ev.SubjectHost || isPrivateIP(ev.SrcIP) {
		return nil
	}
	g := b.Geo(ev.SrcIP)
	if g == nil || g.Country == "" || g.Hosting || g.Proxy || strings.Contains(g.Country, "内网") || strings.Contains(g.Country, "保留") {
		return nil
	}
	key := strings.ToLower(baseUser(ev.User)) + "|" + ev.Service + "|" + strings.ToLower(ev.Host)
	a := b.accts[key]
	if a == nil {
		if len(b.accts) >= maxAccounts {
			return nil
		}
		a = &acctProfile{first: ev.Time, countries: map[string]bool{}, fired: map[string]time.Time{}}
		b.accts[key] = a
	}
	cur := loginPoint{ip: ev.SrcIP, at: ev.Time, lat: g.Lat, lon: g.Lon, country: g.Country, city: g.City,
		precise: g.City != "" && g.CoordSource != "province" && g.CoordSource != "country" && (g.AccuracyKM == 0 || g.AccuracyKM <= 200)}
	if ev.Time.Before(a.first) {
		a.first = ev.Time
	}
	who := "账号 " + Printable(ev.User, 60) + "（" + ev.Service
	if ev.Host != "" {
		who += " @" + ev.Host
	}
	who += "）"
	hit := func(id, name string, sev model.Severity, evidence string) (model.Hit, bool) {
		if t, ok := a.fired[id]; ok && ev.Time.Sub(t).Abs() < takeoverRefire {
			return model.Hit{}, false
		}
		a.fired[id] = ev.Time
		return model.Hit{RuleID: id, Name: name, Category: CatAccountTakeover, Severity: sev, Phase: model.PhaseExploit, Result: model.ResultSuccess,
			Evidence: Printable(evidence, 400)}, true
	}
	var hits []model.Hit
	// 不可能的旅行：与上一次成功登录比较（两次都有经纬度时）
	// 只比较两个都定位到城市的点：国家、省份的中心点与真实位置可能相差上千公里，同一国家内换个网络就会被算成“飞了两千公里”。
	// 跨国但精度不足的情况由“新国家登录”覆盖
	if p := a.last; p.ip != "" && p.ip != cur.ip && p.precise && cur.precise && (p.lat != 0 || p.lon != 0) && (cur.lat != 0 || cur.lon != 0) {
		km := haversine(p.lat, p.lon, cur.lat, cur.lon)
		h := math.Abs(cur.at.Sub(p.at).Hours())
		if km >= travelMinKm && (h == 0 || km/h > travelMaxKmh) {
			speed := "几乎同时"
			if h > 0 {
				speed = fmt.Sprintf("约 %.0f km/h", km/h)
			}
			if x, ok := hit("auth-impossible-travel", "不可能的旅行（账号疑似被盗用）", model.SevHigh,
				fmt.Sprintf("%s %s 从 %s 登录，%s后从 %s 登录，相距 %.0f km（%s）", who, p.at.Format("01-02 15:04"), p.place(),
					fmtDur(cur.at.Sub(p.at).Abs().Round(time.Minute)), cur.place(), km, speed)); ok {
				hits = append(hits, x)
			}
		}
	}
	// 首次从新的国家 / 地区登录
	if !a.countries[cur.country] && a.logins >= newCountryLogins && ev.Time.Sub(a.first) >= newCountryAge {
		var seen []string
		for c := range a.countries {
			seen = append(seen, c)
		}
		if x, ok := hit("auth-new-country", "首次从新的国家 / 地区登录", model.SevMedium,
			fmt.Sprintf("%s 首次从 %s 登录；此前 %d 次登录均来自 %s", who, cur.place(), a.logins, strings.Join(sortedStrings(seen), "、"))); ok {
			hits = append(hits, x)
		}
	}
	// 多地并发登录
	keep := a.recent[:0]
	for _, p := range a.recent {
		if ev.Time.Sub(p.at).Abs() <= concWindow {
			keep = append(keep, p)
		}
	}
	a.recent = append(keep, cur)
	if len(a.recent) > 8 {
		a.recent = a.recent[len(a.recent)-8:]
	}
	cities := map[string]string{}
	for _, p := range a.recent {
		c := p.country + "|" + p.city
		if _, ok := cities[c]; !ok {
			cities[c] = p.place()
		}
	}
	if len(cities) >= concCities {
		var places []string
		for _, v := range cities {
			places = append(places, v)
		}
		if x, ok := hit("auth-concurrent", "多地并发登录", model.SevMedium,
			fmt.Sprintf("%s %s内从 %d 个不同城市成功登录：%s", who, fmtDur(concWindow), len(cities), strings.Join(sortedStrings(places), "、"))); ok {
			hits = append(hits, x)
		}
	}
	a.logins++
	if len(a.countries) < maxAcctCountries {
		a.countries[cur.country] = true
	}
	if !ev.Time.Before(a.last.at) {
		a.last = cur
	}
	return hits
}

// haversine 返回两点间的球面距离（km）。
func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dlat, dlon := (lat2-lat1)*rad, (lon2-lon1)*rad
	x := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * r * math.Asin(math.Sqrt(x))
}

func sortedStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}

// pruneAccounts 清理 30 天没有登录的账号（调用方持锁）。
func (b *Behavior) pruneAccounts(now time.Time) {
	for k, a := range b.accts {
		if outside(now, a.last.at, 30*24*time.Hour) {
			delete(b.accts, k)
		}
	}
}
