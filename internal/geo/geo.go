// Package geo 实现多数据源 IP 溯源定位：离线库（ip2region、MaxMind）+ 在线接口 + 反向 DNS，
// 并对多源结果交叉比对给出置信度。
package geo

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SourceResult 是单个数据源的定位结果。
type SourceResult struct {
	Source      string  `json:"source"`
	Label       string  `json:"label,omitempty"` // 自定义网段名称
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code,omitempty"`
	Province    string  `json:"province,omitempty"`
	City        string  `json:"city,omitempty"`
	District    string  `json:"district,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	ASN         uint    `json:"asn,omitempty"`
	ASOrg       string  `json:"as_org,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	AccuracyKM  int     `json:"accuracy_km,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	RDNS        string  `json:"rdns,omitempty"`
	Proxy       bool    `json:"proxy,omitempty"`
	Hosting     bool    `json:"hosting,omitempty"`
	Mobile      bool    `json:"mobile,omitempty"`
}

// Info 是融合后的溯源结果。
type Info struct {
	IP          string  `json:"ip"`
	Label       string  `json:"label,omitempty"` // 命中的自定义网段名称
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code,omitempty"`
	Province    string  `json:"province,omitempty"`
	City        string  `json:"city,omitempty"`
	District    string  `json:"district,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	ASN         uint    `json:"asn,omitempty"`
	ASOrg       string  `json:"as_org,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	HasCoord    bool    `json:"has_coord"`
	// CoordSource 坐标来源：maxmind / ip-api 为数据源给出的精确坐标，
	// city / province / country 为按地名换算的区划中心点（近似坐标）。
	CoordSource string         `json:"coord_source,omitempty"`
	AccuracyKM  int            `json:"accuracy_km,omitempty"`
	WorldName   string         `json:"world_name,omitempty"`   // 世界地图区域名
	ProvinceMap string         `json:"province_map,omitempty"` // 中国地图省级区域名
	CityMap     string         `json:"city_map,omitempty"`     // 省级地图地市名
	Timezone    string         `json:"timezone,omitempty"`
	RDNS        string         `json:"rdns,omitempty"`
	NetType     string         `json:"net_type,omitempty"` // 内网 / IDC云主机 / 移动网络 / 代理 / 宽带
	Private     bool           `json:"private,omitempty"`
	Proxy       bool           `json:"proxy,omitempty"`
	Hosting     bool           `json:"hosting,omitempty"`
	Mobile      bool           `json:"mobile,omitempty"`
	Confidence  string         `json:"confidence"` // high / medium / low
	Notes       []string       `json:"notes,omitempty"`
	Sources     []SourceResult `json:"sources"`
	Enriched    bool           `json:"enriched"` // 是否已完成在线 / rDNS 深度溯源
	UpdatedAt   time.Time      `json:"updated_at"`
}

// Location 返回简短的位置描述，例如 "中国 广东省 深圳市 电信"。
func (i *Info) Location() string {
	if i == nil {
		return ""
	}
	var parts []string
	if i.Label != "" {
		parts = append(parts, i.Label)
	}
	for _, s := range []string{i.Country, i.Province, i.City} {
		if s != "" && (len(parts) == 0 || parts[len(parts)-1] != s) {
			parts = append(parts, s)
		}
	}
	if i.ISP != "" {
		parts = append(parts, i.ISP)
	}
	return strings.Join(parts, " ")
}

// PlaceKey 返回用于把同一地点的地址聚合到一起的省、市名称。
// 国内地点按地名库归一：各数据源的写法不同（“广东省 / 广州市”与“广东 / 广州市”，直辖市“北京市 / 北京市”与“北京市 / 北京”），
// 按原始写法聚合会把同一个地点拆成几个；地名库里没有的城市保留去掉后缀的名称。境外地点沿用原始名称。
func (i *Info) PlaceKey() (province, city string) {
	if i == nil {
		return "", ""
	}
	if i.ProvinceMap == "" {
		return i.Province, i.City
	}
	if i.CityMap != "" {
		return i.ProvinceMap, i.CityMap
	}
	c := normPlace(i.City)
	if c == normPlace(i.ProvinceMap) || c == normPlace(i.Province) { // 直辖市：城市就是省级本身
		c = ""
	}
	return i.ProvinceMap, c
}

// Provider 是离线定位数据源。
type Provider interface {
	Name() string
	Lookup(addr netip.Addr) (*SourceResult, error)
}

// Options 定位器参数。
type Options struct {
	Providers  []Provider
	Online     *IPAPI // 为 nil 表示不启用在线查询
	ReverseDNS bool
	CacheSize  int
	HomeLat    float64
	HomeLon    float64
	Gazetteer  *Gazetteer // 为 nil 时不做地名坐标换算
	Custom     *Custom    // 自定义网段位置，优先级最高
}

type entry struct {
	private  bool // 内网/保留地址
	local    []SourceResult
	online   *SourceResult
	rdns     string
	enriched bool
	info     *Info
	// 在线定位的重试状态：已发起的次数与最近一次发起的时间（没有结果时按 onlineBackoff 的间隔重试）；
	// rdnsDone 表示反向解析已经做过（只做一次）
	onlineTries uint8
	onlineAt    time.Time
	rdnsDone    bool
}

// Resolver 负责缓存与多源融合。Lookup 只查询离线库（同步、微秒级），
// Enrich 对重点 IP 异步执行在线查询与反向 DNS，完成后回调 OnUpdate。
type Resolver struct {
	opt      Options
	custom   atomic.Pointer[Custom] // 可热更新，读取无需加锁
	mu       sync.Mutex
	cache    map[string]*entry
	tasks    map[string]int // 尚未完成的异步任务数，完成后删除，避免无限增长
	onlineQ  chan string
	rdnsQ    chan string
	OnUpdate func(ip string, info *Info)
}

func NewResolver(opt Options) *Resolver {
	if opt.CacheSize <= 0 {
		opt.CacheSize = 100000
	}
	r := &Resolver{
		opt:     opt,
		cache:   map[string]*entry{},
		tasks:   map[string]int{},
		onlineQ: make(chan string, 10000),
		rdnsQ:   make(chan string, 10000),
	}
	r.custom.Store(opt.Custom)
	return r
}

// ProviderNames 返回已启用的数据源名称。
func (r *Resolver) ProviderNames() []string {
	var out []string
	if r.custom.Load() != nil {
		out = append(out, "custom")
	}
	for _, p := range r.opt.Providers {
		if rd, ok := p.(Readier); ok && !rd.Ready() {
			continue
		}
		out = append(out, p.Name())
	}
	if r.opt.Online != nil {
		out = append(out, r.opt.Online.Name())
	}
	if r.opt.ReverseDNS {
		out = append(out, "rdns")
	}
	if r.opt.Gazetteer != nil {
		out = append(out, "gazetteer")
	}
	return out
}

// Gazetteer 返回地名库（可能为 nil）。
func (r *Resolver) Gazetteer() *Gazetteer { return r.opt.Gazetteer }

// Start 启动在线查询与反向 DNS 后台任务。
func (r *Resolver) Start(ctx context.Context) {
	if r.opt.Online != nil {
		go r.opt.Online.run(ctx, r.onlineQ, r.onlineDone)
	}
	if r.opt.ReverseDNS {
		for i := 0; i < 4; i++ {
			go r.rdnsWorker(ctx)
		}
	}
}

// onlineDone 处理一批在线定位的结果：err 非空表示整批失败（之后按退避间隔重试）；
// 接口没有返回的地址同样保持“没有在线结果”，之后可以重试。
func (r *Resolver) onlineDone(res map[string]*SourceResult, batch []string, err error) {
	for _, ip := range batch {
		if err != nil {
			r.fail(ip)
			continue
		}
		if sr := res[ip]; sr != nil {
			r.mu.Lock()
			if e := r.cache[ip]; e != nil && !e.private { // 查询期间被划入内网：结果不再适用
				e.online = sr
			}
			r.mu.Unlock()
		}
		r.finish(ip)
	}
}

func (r *Resolver) rdnsWorker(ctx context.Context) {
	res := &net.Resolver{}
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-r.rdnsQ:
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			names, _ := res.LookupAddr(c, ip)
			cancel()
			name := ""
			if len(names) > 0 {
				name = strings.TrimSuffix(names[0], ".")
			}
			r.mu.Lock()
			if e := r.cache[ip]; e != nil {
				e.rdns = name
			}
			r.mu.Unlock()
			r.finish(ip)
		}
	}
}

// done 记录一项异步任务结束（调用方持锁）。
func (r *Resolver) done(ip string) {
	if r.tasks[ip] <= 1 {
		delete(r.tasks, ip)
		return
	}
	r.tasks[ip]--
}

// finish 在某一项异步任务完成后重新融合并回调。
func (r *Resolver) finish(ip string) {
	r.mu.Lock()
	r.done(ip)
	e := r.cache[ip]
	if e == nil {
		r.mu.Unlock()
		return
	}
	e.info = r.merge(ip, e)
	info := e.info
	r.mu.Unlock()
	if r.OnUpdate != nil {
		r.OnUpdate(ip, info)
	}
}

// fail 处理异步任务失败（网络错误、接口限流、队列已满）：标记为尚未完成溯源，之后调用 Enrich 时按退避间隔重试。
func (r *Resolver) fail(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done(ip)
	if e := r.cache[ip]; e != nil {
		e.enriched = false
	}
}

// Lookup 使用离线数据源定位 IP（带缓存）。
func (r *Resolver) Lookup(ip string) *Info {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return &Info{IP: ip, Confidence: "low"}
	}
	addr = addr.Unmap()
	r.mu.Lock()
	if e, ok := r.cache[ip]; ok {
		info := e.info
		r.mu.Unlock()
		return info
	}
	r.mu.Unlock()

	e := &entry{private: isPrivate(addr)}
	e.local = r.lookupLocal(addr, e.private)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= r.opt.CacheSize {
		r.evict()
	}
	e.info = r.merge(ip, e)
	r.cache[ip] = e
	return e.info
}

// lookupLocal 查询自定义网段与离线库。内网与保留地址只认自定义网段，未命中时按类别标注，
// 绝不提交定位库查询（否则 172.168.100.0/24 这类被内网误用的公网段会返回「美国」）。
func (r *Resolver) lookupLocal(addr netip.Addr, nonPublic bool) []SourceResult {
	var out []SourceResult
	if sr, _ := r.custom.Load().Lookup(addr); sr != nil {
		out = append(out, *sr)
	}
	if nonPublic {
		if len(out) == 0 {
			if IsInternal(addr) {
				out = append(out, SourceResult{Source: "private", Country: "内网", Province: "局域网", Lat: r.opt.HomeLat, Lon: r.opt.HomeLon})
			} else {
				out = append(out, SourceResult{Source: "private", Country: "保留地址", Province: "非公网地址"})
			}
		}
		return out
	}
	for _, p := range r.opt.Providers {
		if sr, err := p.Lookup(addr); err == nil && sr != nil {
			out = append(out, *sr)
		}
	}
	return out
}

// 在线定位没有结果时（网络错误、接口限流、队列已满，或接口没有返回该地址）的重试间隔：
// 10 分钟起逐次加倍，最长 6 小时。此前失败的地址只有等级再次提升才会重试，等级不再变化的攻击源
// 一直停在离线库的结果上：境外地址只有国家级坐标，在地图上堆在国家中心。
func onlineBackoff(tries uint8) time.Duration {
	if tries == 0 {
		return 0
	}
	return min(10*time.Minute<<min(tries-1, 6), 6*time.Hour)
}

// Enrich 将 IP 加入在线查询与 rDNS 队列。反向解析只做一次；在线定位拿到结果后不再重复，
// 没有结果的按 onlineBackoff 的间隔在之后的调用中重试（调用方可以放心地重复调用）。
// 缓存中没有该地址时先用离线库定位。
func (r *Resolver) Enrich(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || isPrivate(addr.Unmap()) {
		return
	}
	if r.opt.Online == nil && !r.opt.ReverseDNS {
		return
	}
	now := time.Now()
	r.mu.Lock()
	e := r.cache[ip]
	if e == nil {
		r.mu.Unlock()
		r.Lookup(ip)
		r.mu.Lock()
		e = r.cache[ip]
	}
	if e == nil || e.private || r.tasks[ip] > 0 {
		r.mu.Unlock()
		return
	}
	online := r.opt.Online != nil && e.online == nil && now.Sub(e.onlineAt) >= onlineBackoff(e.onlineTries)
	rdns := r.opt.ReverseDNS && !e.rdnsDone
	n := 0
	if online {
		n++
		e.onlineAt = now
		if e.onlineTries < 255 {
			e.onlineTries++
		}
	}
	if rdns {
		n++
		e.rdnsDone = true
	}
	if n == 0 {
		r.mu.Unlock()
		return
	}
	e.enriched = true
	r.tasks[ip] = n
	r.mu.Unlock()
	if online {
		select {
		case r.onlineQ <- ip:
		default:
			r.fail(ip)
		}
	}
	if rdns {
		select {
		case r.rdnsQ <- ip:
		default:
			r.mu.Lock()
			if e := r.cache[ip]; e != nil {
				e.rdnsDone = false
			}
			r.mu.Unlock()
			r.fail(ip)
		}
	}
}

// NeedsOnline 判断一个定位结果是否还缺在线定位：已启用在线库、公网地址、结果里没有在线库的数据。
// 供调用方定期为这样的攻击源重新调用 Enrich。
func (r *Resolver) NeedsOnline(info *Info) bool {
	if r == nil || r.opt.Online == nil || info == nil || info.Private {
		return false
	}
	name := r.opt.Online.Name()
	for i := range info.Sources {
		if info.Sources[i].Source == name {
			return false
		}
	}
	return true
}

// evict 淘汰一半缓存（调用方持锁），正在异步溯源的条目保留。
func (r *Resolver) evict() {
	n := 0
	for k := range r.cache {
		if n >= len(r.cache)/2 {
			break
		}
		if r.tasks[k] == 0 {
			delete(r.cache, k)
			n++
		}
	}
}

// 数据源优先级：国内地址优先 ip2region（国内库精度更高），境外地址优先 MaxMind / 在线库。
var (
	prioCN    = []string{"custom", "ip2region", "ip-api", "maxmind", "private"}
	prioWorld = []string{"custom", "maxmind", "ip-api", "ip2region", "private"}
	prioCoord = []string{"custom", "maxmind", "ip-api", "private"}
)

func (r *Resolver) merge(ip string, e *entry) *Info {
	all := append([]SourceResult(nil), e.local...)
	if e.online != nil {
		all = append(all, *e.online)
	}
	info := &Info{IP: ip, Sources: all, RDNS: e.rdns, UpdatedAt: time.Now(), Enriched: e.enriched}
	if len(all) == 0 {
		info.Confidence = "low"
		info.Notes = append(info.Notes, "未配置离线定位库或数据库中无此地址")
		return info
	}
	bySrc := map[string]*SourceResult{}
	for i := range all {
		bySrc[all[i].Source] = &all[i]
	}
	first := func(order []string, get func(*SourceResult) string) string {
		for _, s := range order {
			if sr := bySrc[s]; sr != nil {
				if v := get(sr); v != "" {
					return v
				}
			}
		}
		return ""
	}
	cc := first(prioWorld, func(s *SourceResult) string { return strings.ToUpper(s.CountryCode) })
	order := prioWorld
	if cc == "CN" || cc == "" && first(prioCN, func(s *SourceResult) string { return s.Country }) == "中国" {
		order = prioCN
	}
	// 各数据源国家判定不一致时，位置字段只采用与最终国家一致的数据源，避免拼接出不存在的地点
	agree := func(s *SourceResult) bool {
		return cc == "" || s.CountryCode == "" || strings.EqualFold(s.CountryCode, cc)
	}
	pickLoc := func(get func(*SourceResult) string) string {
		return first(order, func(s *SourceResult) string {
			if !agree(s) {
				return ""
			}
			return get(s)
		})
	}
	info.CountryCode = cc
	info.Country = countryNameZH(cc)
	if info.Country == "" {
		info.Country = pickLoc(func(s *SourceResult) string { return s.Country })
	}
	info.Province = pickLoc(func(s *SourceResult) string { return s.Province })
	info.City = pickLoc(func(s *SourceResult) string { return s.City })
	info.District = pickLoc(func(s *SourceResult) string { return s.District })
	info.ISP = pickLoc(func(s *SourceResult) string { return s.ISP })
	info.ASOrg = first(prioWorld, func(s *SourceResult) string { return s.ASOrg })
	info.Timezone = first(prioWorld, func(s *SourceResult) string { return s.Timezone })
	for _, s := range prioWorld {
		if sr := bySrc[s]; sr != nil && sr.ASN > 0 {
			info.ASN = sr.ASN
			break
		}
	}
	for _, s := range prioCoord {
		if sr := bySrc[s]; sr != nil && agree(sr) && (sr.Lat != 0 || sr.Lon != 0) {
			info.Lat, info.Lon, info.AccuracyKM, info.HasCoord = sr.Lat, sr.Lon, sr.AccuracyKM, true
			info.CoordSource = s
			break
		}
	}
	if custom := bySrc["custom"]; custom != nil {
		info.Label = custom.Label
	}
	if !bySrcPrivate(bySrc) {
		// 英文国家名（ip2region 境外数据为英文）用于匹配世界地图区域
		var en []string
		for _, sr := range all {
			if agree(&sr) && sr.Country != "" {
				en = append(en, sr.Country)
			}
		}
		pl := r.opt.Gazetteer.Resolve(info, en...)
		info.WorldName, info.ProvinceMap, info.CityMap = pl.WorldName, pl.ProvinceMap, pl.CityMap
		// 坐标所属的地点与最终采信的地点不一致时（如国内地址的省市取自 ip2region、坐标来自在线库），
		// 改用所采信地点的中心点，保证地图标注与归属地一致：
		//   - 采信到城市：坐标来源的城市不同；
		//   - 采信到省级（直辖市，或地名库里没有该城市）：坐标来源的省份不同。直辖市在地名库中是省级，
		//     只比城市会漏掉“归属北京、坐标在上海”的地址，同一地点多个攻击源取均值后标注会落到两地之间。
		if src := bySrc[info.CoordSource]; info.HasCoord && src != nil && info.CoordSource != "custom" {
			mismatch := false
			switch pl.Level {
			case "city":
				mismatch = normPlace(src.City) != "" && normPlace(src.City) != normPlace(info.City)
			case "province":
				mismatch = r.opt.Gazetteer.outsideProvince(pl.ProvinceMap, src.Province, src.City, info.Lat, info.Lon)
			}
			if mismatch {
				info.Lat, info.Lon, info.AccuracyKM, info.CoordSource = pl.Lat, pl.Lon, 0, pl.Level
			}
		}
		if !info.HasCoord && pl.Level != "" {
			info.Lat, info.Lon, info.HasCoord, info.CoordSource = pl.Lat, pl.Lon, true, pl.Level
		}
	}
	if info.ISP == "" {
		info.ISP = info.ASOrg
	}
	for _, sr := range all {
		info.Proxy = info.Proxy || sr.Proxy
		info.Hosting = info.Hosting || sr.Hosting
		info.Mobile = info.Mobile || sr.Mobile
		if info.RDNS == "" && sr.RDNS != "" {
			info.RDNS = sr.RDNS
		}
		if sr.Source == "private" {
			info.Private = true
		}
	}
	if e.private {
		info.Private = true
		// 未配置坐标的内网网段默认落在受保护资产所在位置；保留 / 文档地址没有真实位置，不给坐标
		if !info.HasCoord && IsInternal(addrOf(ip)) {
			info.Lat, info.Lon, info.HasCoord, info.CoordSource = r.opt.HomeLat, r.opt.HomeLon, true, "private"
		}
	}
	if !info.Hosting && isCloudISP(info.ISP+" "+info.ASOrg+" "+info.RDNS) {
		info.Hosting = true
	}
	info.Confidence, info.Notes = confidence(all, info)
	info.NetType = netType(info)
	return info
}

// confidence 交叉比对各数据源，给出定位置信度与说明。
func confidence(all []SourceResult, info *Info) (string, []string) {
	var notes []string
	if info.Label != "" {
		notes = append(notes, "命中自定义网段「"+info.Label+"」，位置以配置为准")
		if info.Private {
			notes = append(notes, "内网地址，来源为内部主机")
		}
		return "high", notes
	}
	if info.Private {
		if info.Country == "保留地址" {
			return "high", []string{"保留 / 非公网地址，不属于任何真实地理位置（常见于测试或异常日志）"}
		}
		return "high", []string{"内网地址，来源为内部主机"}
	}
	countries := map[string]bool{}
	cities := map[string][]string{}
	for _, sr := range all {
		if sr.CountryCode != "" {
			countries[strings.ToUpper(sr.CountryCode)] = true
		}
		if c := normPlace(sr.City); c != "" {
			cities[c] = append(cities[c], sr.Source)
		}
	}
	if len(countries) > 1 {
		var cs []string
		for c := range countries {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		notes = append(notes, "多个数据源国家判定不一致("+strings.Join(cs, "/")+")，可能为 Anycast、跨境线路或新分配地址")
	}
	level := "low"
	switch {
	case len(countries) > 1:
		level = "low"
	case maxAgree(cities) >= 2:
		level = "high"
		notes = append(notes, "多个数据源城市级定位一致")
	case info.City != "":
		level = "medium"
		if len(cities) > 1 {
			notes = append(notes, "多个数据源城市级定位存在差异，以优先级更高的数据源为准")
		}
	case info.Province != "":
		level = "medium"
	}
	if info.AccuracyKM > 0 && info.AccuracyKM <= 20 && level == "medium" {
		level = "high"
	}
	if info.Hosting {
		notes = append(notes, "IDC/云主机地址：定位结果为机房位置，攻击者可能通过租用的服务器发起攻击")
	}
	if info.Proxy {
		notes = append(notes, "该地址被标记为代理/VPN出口，真实来源可能在其后方")
	}
	if info.Mobile {
		notes = append(notes, "移动网络地址，基站出口 IP 共享程度高，定位通常只到城市级")
	}
	return level, notes
}

func maxAgree(m map[string][]string) int {
	n := 0
	for _, v := range m {
		seen := map[string]bool{}
		for _, s := range v {
			seen[s] = true
		}
		if len(seen) > n {
			n = len(seen)
		}
	}
	return n
}

var placeSuffix = strings.NewReplacer("特别行政区", "", "自治区", "", "自治州", "", "地区", "", "省", "", "市", "", "区", "", "县", "", " ", "", "-", "")

func normPlace(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return ""
	}
	return strings.ToLower(placeSuffix.Replace(s))
}

var cloudKeywords = []string{
	"amazon", "aws", "google", "microsoft", "azure", "alibaba", "aliyun", "阿里", "tencent", "腾讯", "huawei cloud", "华为云",
	"baidu", "百度", "ucloud", "优刻得", "kingsoft", "金山云", "qingcloud", "青云", "digitalocean", "linode", "akamai", "vultr",
	"choopa", "ovh", "hetzner", "contabo", "oracle", "ibm", "softlayer", "leaseweb", "m247", "datacamp", "cdn77", "hostinger",
	"scaleway", "kamatera", "hostwinds", "colocrossing", "psychz", "quadranet", "frantech", "ponynet", "g-core", "gcore",
	"zenlayer", "data center", "datacenter", "hosting", "server", "cloud", "vps", "idc", "数据中心", "云计算", "云服务",
}

func isCloudISP(s string) bool {
	s = strings.ToLower(s)
	for _, k := range cloudKeywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func netType(i *Info) string {
	switch {
	case i.Private && i.Country == "保留地址":
		return "保留地址"
	case i.Private:
		return "内网"
	case i.Proxy:
		return "代理/VPN"
	case i.Hosting:
		return "IDC/云主机"
	case i.Mobile:
		return "移动网络"
	case i.ISP != "":
		return "宽带/企业专线"
	}
	return ""
}

// isPrivate 判断地址是否为内网 / 保留（非公网）地址，见 internal.go 中的网段集合。
func isPrivate(a netip.Addr) bool { return IsNonPublic(a.Unmap()) }

// QueueLen 返回尚未完成的在线查询与 rDNS 任务数（含排队与进行中）。
func (r *Resolver) QueueLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tasks)
}

func bySrcPrivate(m map[string]*SourceResult) bool { return m["private"] != nil }
