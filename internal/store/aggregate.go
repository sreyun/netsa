package store

import (
	"math/bits"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

// aggregate 是总览接口使用的增量统计。
//
// 原先 /api/overview 每次都要遍历全部画像并重建国家、省份、城市、运营商、网络类型、
// 被攻击目标等统计表（5 万攻击源约 29ms，全部发生在读锁内，会阻塞日志入库）。
// 改为在画像状态变化时增量维护：新建攻击源、等级变化、归属地更新、目标增加、淘汰。
// 读取时只做一次小规模拷贝与排序，写锁等待随之消失。
//
// 「近 1 小时」统计按分钟桶维护，与趋势桶同样是一分钟粒度。
type aggregate struct {
	attackers int
	levels    [5]int
	countries map[string]int64
	provinces map[string]int64
	cities    map[string]int64
	isps      map[string]int64
	nettypes  map[string]int64
	targets   map[string]int64

	lastByMin map[int64]*activity // 分钟 → 该分钟内最后活动的攻击源
	newByMin  map[int64]int       // 分钟 → 首次出现的攻击源数

	// 以下为安全评估（Assess）所需的画像级统计。原先 Assess 每次都要遍历全部画像
	// （5 万攻击源约 22ms，全程持有读锁），改为随画像新增 / 淘汰 / 新增攻击类型增量维护。
	intelHits     int        // 命中威胁情报的攻击源
	brute         int        // 出现暴力破解的攻击源
	scanners      int        // 扫描器 / 测绘 / 目录扫描来源
	ccSources     int        // CC / 洪水攻击来源
	portScanners  int        // 端口扫描 / 主机探测 / 高危服务探测来源
	techAttackers [64]int    // ATT&CK 技术 → 攻击源数
	techSev       [64][5]int // ATT&CK 技术 → 各等级攻击源数（取最高等级用于矩阵着色）
}

type activity struct {
	total int
	high  int // 高危及以上的攻击源数
}

func newAggregate() *aggregate {
	return &aggregate{
		countries: map[string]int64{}, provinces: map[string]int64{}, cities: map[string]int64{},
		isps: map[string]int64{}, nettypes: map[string]int64{}, targets: map[string]int64{},
		lastByMin: map[int64]*activity{}, newByMin: map[int64]int{},
	}
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 }

// aggBump 增减计数并在归零时删除键，避免排行榜里出现计数为 0 的历史条目。
func aggBump(m map[string]int64, k string, delta int64) {
	if k == "" {
		return
	}
	v := m[k] + delta
	if v <= 0 {
		delete(m, k)
		return
	}
	m[k] = v
}

func (a *aggregate) bucket(t time.Time, create bool) *activity {
	k := minuteOf(t)
	b := a.lastByMin[k]
	if b == nil && create {
		b = &activity{}
		a.lastByMin[k] = b
	}
	return b
}

// add 把一个新攻击源加入统计（幂等：已在统计中的画像直接返回）。
func (a *aggregate) add(p *IPProfile) {
	if p.inAgg || !isAttacker(p) {
		return
	}
	p.inAgg = true
	a.attackers++
	a.levels[p.Level]++
	country, prov, city, isp, nt := geoKeys(p)
	aggBump(a.countries, country, 1)
	aggBump(a.provinces, prov, 1)
	aggBump(a.cities, city, 1)
	aggBump(a.isps, isp, 1)
	aggBump(a.nettypes, nt, 1)
	for t, n := range p.Targets {
		aggBump(a.targets, t, int64(n))
	}
	if b := a.bucket(p.LastSeen, true); b != nil {
		b.total++
		if p.Level >= model.SevHigh {
			b.high++
		}
	}
	a.newByMin[minuteOf(p.FirstSeen)]++
	a.addAssess(p)
}

// remove 把一个攻击源从统计中移除（淘汰画像时调用）。
func (a *aggregate) remove(p *IPProfile) {
	if !p.inAgg {
		return
	}
	a.removeAssess(p)
	p.inAgg = false
	a.attackers--
	if p.Level >= model.SevInfo && p.Level <= model.SevCritical {
		a.levels[p.Level]--
	}
	country, prov, city, isp, nt := geoKeys(p)
	aggBump(a.countries, country, -1)
	aggBump(a.provinces, prov, -1)
	aggBump(a.cities, city, -1)
	aggBump(a.isps, isp, -1)
	aggBump(a.nettypes, nt, -1)
	for t, n := range p.Targets {
		aggBump(a.targets, t, -int64(n))
	}
	if b := a.bucket(p.LastSeen, false); b != nil {
		b.total--
		if p.Level >= model.SevHigh {
			b.high--
		}
		if b.total <= 0 {
			delete(a.lastByMin, minuteOf(p.LastSeen))
		}
	}
	if k := minuteOf(p.FirstSeen); a.newByMin[k] > 0 {
		a.newByMin[k]--
		if a.newByMin[k] == 0 {
			delete(a.newByMin, k)
		}
	}
}

// setLevel 在画像威胁等级变化后调整分布（含「近 1 小时高危攻击源」）。
func (a *aggregate) setLevel(p *IPProfile, old model.Severity) {
	if !p.inAgg || old == p.Level {
		return
	}
	if old >= model.SevInfo && old <= model.SevCritical {
		a.levels[old]--
	}
	if p.Level >= model.SevInfo && p.Level <= model.SevCritical {
		a.levels[p.Level]++
	}
	if b := a.bucket(p.LastSeen, false); b != nil {
		switch {
		case old < model.SevHigh && p.Level >= model.SevHigh:
			b.high++
		case old >= model.SevHigh && p.Level < model.SevHigh:
			b.high--
		}
	}
}

// setGeo 在画像归属地变化后（在线溯源完成、定位库热更新）迁移地域统计。
func (a *aggregate) setGeo(p *IPProfile, old *geo.Info) {
	if !p.inAgg {
		return
	}
	oc, op, oci, oi, ont := geoKeysInfo(old)
	aggBump(a.countries, oc, -1)
	aggBump(a.provinces, op, -1)
	aggBump(a.cities, oci, -1)
	aggBump(a.isps, oi, -1)
	aggBump(a.nettypes, ont, -1)

	nc, np, nci, ni, nnt := geoKeysInfo(p.Geo)
	aggBump(a.countries, nc, 1)
	aggBump(a.provinces, np, 1)
	aggBump(a.cities, nci, 1)
	aggBump(a.isps, ni, 1)
	aggBump(a.nettypes, nnt, 1)
}

// moveLastSeen 在画像最近活动时间前移后迁移分钟桶。
func (a *aggregate) moveLastSeen(p *IPProfile, old time.Time) {
	if !p.inAgg || !p.LastSeen.After(old) || minuteOf(old) == minuteOf(p.LastSeen) {
		return
	}
	if b := a.bucket(old, false); b != nil {
		b.total--
		if p.Level >= model.SevHigh {
			b.high--
		}
		if b.total <= 0 {
			delete(a.lastByMin, minuteOf(old))
		}
	}
	if b := a.bucket(p.LastSeen, true); b != nil {
		b.total++
		if p.Level >= model.SevHigh {
			b.high++
		}
	}
}

// moveFirstSeen 在乱序日志把首次出现时间提前后迁移「新增攻击源」分钟桶。
func (a *aggregate) moveFirstSeen(p *IPProfile, old time.Time) {
	if !p.inAgg || minuteOf(old) == minuteOf(p.FirstSeen) {
		return
	}
	if k := minuteOf(old); a.newByMin[k] > 0 {
		a.newByMin[k]--
		if a.newByMin[k] == 0 {
			delete(a.newByMin, k)
		}
	}
	a.newByMin[minuteOf(p.FirstSeen)]++
}

// addTarget 累计被攻击目标；画像此时可能刚升级为攻击源，先补登记再累计，避免漏计已有目标。
func (a *aggregate) addTarget(p *IPProfile, target string) {
	if !p.inAgg {
		a.add(p) // 首次攻击：add 会把当前已有的目标一次性计入
		if p.inAgg {
			return
		}
		return
	}
	aggBump(a.targets, target, 1)
}

// recent 返回不早于 cutMinute（分钟）的攻击源数、其中高危及以上的数量、以及首次出现数。
func (a *aggregate) recent(cutMinute int64) (attackers, high, created int) {
	for k, b := range a.lastByMin {
		if k >= cutMinute {
			attackers += b.total
			high += b.high
		}
	}
	for k, n := range a.newByMin {
		if k >= cutMinute {
			created += n
		}
	}
	return
}

// prune 清理过期的活动桶（只保留近 2 小时，够「近 1 小时」统计使用）。
func (a *aggregate) prune(before time.Time) {
	cut := minuteOf(before)
	for k := range a.lastByMin {
		if k < cut {
			delete(a.lastByMin, k)
		}
	}
	for k := range a.newByMin {
		if k < cut {
			delete(a.newByMin, k)
		}
	}
}

// rebuild 在快照恢复后按画像重建统计（一次性 O(N)，只在启动时发生）。
func (a *aggregate) rebuild(ips map[string]*IPProfile) {
	*a = *newAggregate()
	for _, p := range ips {
		p.inAgg, p.aggMask, p.aggFlags = false, 0, 0
		if isAttacker(p) {
			a.add(p)
		}
	}
}

// ---------------- 安全评估（Assess）的增量统计 ----------------

// 画像级攻击手法标记：与 Assess 中按攻击类型归类四个计数的口径完全一致。
const (
	flagBrute uint8 = 1 << iota // 暴力破解
	flagScan                    // 扫描器 / 网络空间测绘 / 目录扫描
	flagCC                      // CC 攻击 / 洪水攻击
	flagPort                    // 端口扫描 / 主机探测 / 高危服务探测
)

// profileFlags 汇总画像的攻击手法标记（按攻击类型，而不是按次数）。
func profileFlags(p *IPProfile) uint8 {
	var f uint8
	for cat := range p.CatSev {
		switch cat {
		case "暴力破解":
			f |= flagBrute
		case "扫描器", "网络空间测绘", "目录扫描":
			f |= flagScan
		case "CC攻击", "洪水攻击":
			f |= flagCC
		case "端口扫描", "主机探测", "高危服务探测":
			f |= flagPort
		}
	}
	return f
}

// syncFlags 让聚合中的手法计数与画像当前标记一致，返回增减的差值（供调用方累加）。
func (a *aggregate) syncFlags(p *IPProfile) (brute, scan, cc, port int) {
	nf := profileFlags(p)
	changed := nf ^ p.aggFlags
	if changed&flagBrute != 0 {
		brute = sign(nf&flagBrute != 0)
	}
	if changed&flagScan != 0 {
		scan = sign(nf&flagScan != 0)
	}
	if changed&flagCC != 0 {
		cc = sign(nf&flagCC != 0)
	}
	if changed&flagPort != 0 {
		port = sign(nf&flagPort != 0)
	}
	p.aggFlags = nf
	return
}

func sign(add bool) int {
	if add {
		return 1
	}
	return -1
}

// addAssess 在画像进入统计时累计评估所需的计数（含 ATT&CK 矩阵）。
func (a *aggregate) addAssess(p *IPProfile) {
	if len(p.Intel) > 0 {
		a.intelHits++
	}
	brute, scan, cc, port := a.syncFlags(p)
	a.brute += brute
	a.scanners += scan
	a.ccSources += cc
	a.portScanners += port

	var mask uint64
	for cat, sev := range p.CatSev {
		m := catTechMask[cat]
		mask |= m
		for b := m; b != 0; b &= b - 1 {
			a.techSev[bits.TrailingZeros64(b)][sev]++
		}
	}
	for b := mask; b != 0; b &= b - 1 {
		a.techAttackers[bits.TrailingZeros64(b)]++
	}
	p.aggMask = mask
}

// removeAssess 在画像被淘汰时回减评估计数。
func (a *aggregate) removeAssess(p *IPProfile) {
	if len(p.Intel) > 0 {
		a.intelHits--
	}
	p.aggFlags = 0 // 让 syncFlags 以「全部清零」为基准做差
	brute, scan, cc, port := a.syncFlags(p)
	a.brute -= brute
	a.scanners -= scan
	a.ccSources -= cc
	a.portScanners -= port

	for b := p.aggMask; b != 0; b &= b - 1 {
		a.techAttackers[bits.TrailingZeros64(b)]--
	}
	for cat, sev := range p.CatSev {
		for b := catTechMask[cat]; b != 0; b &= b - 1 {
			a.techSev[bits.TrailingZeros64(b)][sev]--
		}
	}
	p.aggMask = 0
}

// addCategory 在画像新增一种攻击类型后更新评估统计（同一技术只计一次攻击源）。
func (a *aggregate) addCategory(p *IPProfile, cat string, sev model.Severity) {
	if !p.inAgg {
		return // 尚未成为攻击源：由随后的 add 一次性统计
	}
	m := catTechMask[cat]
	for b := m &^ p.aggMask; b != 0; b &= b - 1 {
		a.techAttackers[bits.TrailingZeros64(b)]++
	}
	for b := m; b != 0; b &= b - 1 {
		a.techSev[bits.TrailingZeros64(b)][sev]++
	}
	p.aggMask |= m

	brute, scan, cc, port := a.syncFlags(p)
	a.brute += brute
	a.scanners += scan
	a.ccSources += cc
	a.portScanners += port
}

// setCategorySeverity 在同类攻击出现更高等级后调整矩阵着色用的等级直方图。
func (a *aggregate) setCategorySeverity(p *IPProfile, cat string, old, sev model.Severity) {
	if !p.inAgg || old == sev {
		return
	}
	for b := catTechMask[cat]; b != 0; b &= b - 1 {
		i := bits.TrailingZeros64(b)
		if a.techSev[i][old] > 0 {
			a.techSev[i][old]--
		}
		a.techSev[i][sev]++
	}
}

// matrixAcc 把增量统计转成 ATT&CK 矩阵累加器（供 buildMatrixLocked 拼装各战术与技术的命中数）。
func (a *aggregate) matrixAcc() *matrixAcc {
	m := &matrixAcc{}
	for i := range m.attackers {
		m.attackers[i] = a.techAttackers[i]
		for sev := model.SevCritical; sev >= model.SevInfo; sev-- {
			if a.techSev[i][sev] > 0 {
				m.maxSev[i] = sev
				break
			}
		}
	}
	return m
}
