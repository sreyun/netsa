package geo

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/oschwald/geoip2-golang"
)

// Reloader 是支持热更新的离线库：Reload 检查库文件是否被替换，有变化时重新加载并返回 true。
// 加载失败时继续使用旧库，下一轮检查时重试。
type Reloader interface {
	Reload() (bool, error)
}

// Readier 报告离线库是否已成功加载（配置了路径但文件尚未就绪时为 false）。
type Readier interface {
	Ready() bool
}

// fileStamp 记录库文件的修改时间与大小，用于判断文件是否被替换。
type fileStamp struct {
	mod  time.Time
	size int64
}

// settle 为文件写入完成的等待时间：刚被修改的文件可能仍在复制中，留到下一轮再加载。
const settle = 3 * time.Second

// dbFile 是一个可热更新的库文件。
type dbFile struct {
	path    string
	stamp   fileStamp
	checked bool
}

// changed 返回文件当前状态，以及是否需要（重新）加载：文件存在、与上次加载时不同且已写入完成。
// 启动时的首次检查不等待，保证立即可用。
func (f *dbFile) changed() (fileStamp, bool) {
	first := !f.checked
	f.checked = true
	if f.path == "" {
		return fileStamp{}, false
	}
	fi, err := os.Stat(f.path)
	if err != nil || fi.IsDir() {
		return fileStamp{}, false
	}
	st := fileStamp{fi.ModTime(), fi.Size()}
	if st == f.stamp || !first && time.Since(st.mod) < settle {
		return st, false
	}
	return st, true
}

// ---------------- ip2region ----------------

// IP2Region 读取 ip2region xdb 离线库（国内地址可精确到城市与运营商），支持热更新。
type IP2Region struct {
	mu       sync.Mutex
	v4, v6   *xdb.Searcher
	v4f, v6f dbFile
}

// OpenIP2Region 打开 v4 / v6 xdb 文件。两个路径都为空时返回 nil；
// 文件暂不存在时返回未就绪的实例，文件出现后由 Reload 加载。
func OpenIP2Region(v4Path, v6Path string) (*IP2Region, error) {
	if v4Path == "" && v6Path == "" {
		return nil, nil
	}
	p := &IP2Region{v4f: dbFile{path: v4Path}, v6f: dbFile{path: v6Path}}
	if _, err := p.Reload(); err != nil {
		return nil, err
	}
	return p, nil
}

func loadXDB(path string) (*xdb.Searcher, error) {
	header, err := xdb.LoadHeaderFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 头失败: %w", path, err)
	}
	ver, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	buf, err := xdb.LoadContentFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return xdb.NewWithBuffer(ver, buf)
}

func (p *IP2Region) Reload() (bool, error) {
	changed := false
	for _, f := range []struct {
		file *dbFile
		dst  **xdb.Searcher
	}{{&p.v4f, &p.v4}, {&p.v6f, &p.v6}} {
		st, ok := f.file.changed()
		if !ok {
			continue
		}
		s, err := loadXDB(f.file.path)
		if err != nil {
			return changed, err
		}
		p.mu.Lock()
		*f.dst = s // 整库载入内存，旧实例无需关闭，由 GC 回收
		p.mu.Unlock()
		f.file.stamp, changed = st, true
	}
	return changed, nil
}

func (p *IP2Region) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.v4 != nil || p.v6 != nil
}

func (*IP2Region) Name() string { return "ip2region" }

func (p *IP2Region) Lookup(addr netip.Addr) (*SourceResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.v4
	if addr.Is6() {
		s = p.v6
	}
	if s == nil {
		return nil, nil
	}
	region, err := s.Search(addr.String())
	if err != nil {
		return nil, err
	}
	return parseRegion(region), nil
}

// parseRegion 兼容两种格式：
// 新版 国家|省份|城市|ISP|国家代码；旧版 国家|区域|省份|城市|ISP。
func parseRegion(region string) *SourceResult {
	f := strings.Split(region, "|")
	for i := range f {
		if f[i] == "0" || strings.EqualFold(f[i], "Reserved") {
			f[i] = ""
		}
	}
	sr := &SourceResult{Source: "ip2region"}
	switch {
	case len(f) >= 5 && len(f[4]) == 2 && strings.ToUpper(f[4]) == f[4]:
		sr.Country, sr.Province, sr.City, sr.ISP, sr.CountryCode = f[0], f[1], f[2], f[3], f[4]
	case len(f) >= 5:
		sr.Country, sr.Province, sr.City, sr.ISP = f[0], f[2], f[3], f[4]
		if sr.Country == "中国" {
			sr.CountryCode = "CN"
		}
	case len(f) >= 1:
		sr.Country = f[0]
	}
	if sr.Country == "" {
		return nil
	}
	// ip2region 将港澳台标记为 中国|香港特别行政区|...|CN，统一为独立地区代码以便与其他数据源比对
	if sr.Country == "中国" {
		for prefix, code := range map[string]string{"香港": "HK", "澳门": "MO", "台湾": "TW"} {
			if strings.HasPrefix(sr.Province, prefix) {
				sr.CountryCode = code
			}
		}
	}
	return sr
}

// ---------------- MaxMind GeoLite2 / GeoIP2 ----------------

// MaxMind 读取 GeoLite2-City 与 GeoLite2-ASN（可只提供其中之一），提供经纬度与 ASN，支持热更新。
type MaxMind struct {
	mu          sync.RWMutex
	city, asn   *geoip2.Reader
	cityf, asnf dbFile
}

// OpenMaxMind 打开 City / ASN 库，规则同 OpenIP2Region。
func OpenMaxMind(cityPath, asnPath string) (*MaxMind, error) {
	if cityPath == "" && asnPath == "" {
		return nil, nil
	}
	m := &MaxMind{cityf: dbFile{path: cityPath}, asnf: dbFile{path: asnPath}}
	if _, err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *MaxMind) Reload() (bool, error) {
	changed := false
	for _, f := range []struct {
		file *dbFile
		dst  **geoip2.Reader
	}{{&m.cityf, &m.city}, {&m.asnf, &m.asn}} {
		st, ok := f.file.changed()
		if !ok {
			continue
		}
		rd, err := geoip2.Open(f.file.path)
		if err != nil {
			return changed, fmt.Errorf("打开 %s 失败: %w", f.file.path, err)
		}
		m.mu.Lock()
		old := *f.dst
		*f.dst = rd
		m.mu.Unlock()
		if old != nil {
			old.Close() // 已持写锁替换，不会再有查询使用旧实例
		}
		f.file.stamp, changed = st, true
	}
	return changed, nil
}

func (m *MaxMind) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.city != nil || m.asn != nil
}

func (*MaxMind) Name() string { return "maxmind" }

func zh(names map[string]string) string {
	if v := names["zh-CN"]; v != "" {
		return v
	}
	return names["en"]
}

func (m *MaxMind) Lookup(addr netip.Addr) (*SourceResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ip := net.IP(addr.AsSlice())
	sr := &SourceResult{Source: "maxmind"}
	if m.city != nil {
		c, err := m.city.City(ip)
		if err != nil {
			return nil, err
		}
		sr.Country = zh(c.Country.Names)
		sr.CountryCode = c.Country.IsoCode
		if len(c.Subdivisions) > 0 {
			sr.Province = zh(c.Subdivisions[0].Names)
		}
		sr.City = zh(c.City.Names)
		sr.Lat, sr.Lon = c.Location.Latitude, c.Location.Longitude
		sr.AccuracyKM = int(c.Location.AccuracyRadius)
		sr.Timezone = c.Location.TimeZone
		sr.Proxy = c.Traits.IsAnonymousProxy
	}
	if m.asn != nil {
		if a, err := m.asn.ASN(ip); err == nil {
			sr.ASN = a.AutonomousSystemNumber
			sr.ASOrg = a.AutonomousSystemOrganization
		}
	}
	if sr.Country == "" && sr.ASN == 0 {
		return nil, nil
	}
	return sr, nil
}
