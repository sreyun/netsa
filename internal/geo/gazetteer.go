package geo

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"path"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// Gazetteer 基于内嵌的 ECharts 地图数据（世界国家边界、中国省级与地市级区划中心点）
// 为只有地名、没有经纬度的定位结果提供近似坐标，并给出各级地图中的区域名称，
// 使离线部署（仅 ip2region）时攻击源也能落到具体城市。
type Gazetteer struct {
	world     map[string]point // world.json 区域名 → 最大多边形质心
	worldNorm map[string]string
	provinces map[string]*cnProvince // 归一化省名 → 省
	provList  []*cnProvince
}

type point struct{ Lon, Lat float64 }

type cnProvince struct {
	Name   string // china.json 中的名称，如 "广东"
	File   string // 省级地图文件名（不含扩展名），如 "guangdong"
	CP     point
	cities map[string]cnCity // 归一化城市名 → 城市
}

type cnCity struct {
	Name string // 省级地图中的名称，如 "深圳市"
	CP   point
}

// Place 是地名库解析结果。
type Place struct {
	Lat, Lon    float64
	Level       string // city / province / country，为空表示未能解析
	WorldName   string // 世界地图区域名
	ProvinceMap string // 中国地图省级区域名
	CityMap     string // 省级地图中的地市名
}

type featureProps struct {
	ID         string `json:"id"`
	Properties struct {
		ID   string    `json:"id"`
		Name string    `json:"name"`
		CP   []float64 `json:"cp"`
		// 部分地图文件（如台湾）以经纬度字段代替 cp
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	} `json:"properties"`
	Geometry struct {
		Type        string          `json:"type"`
		Coordinates json.RawMessage `json:"coordinates"`
	} `json:"geometry"`
}

type featureCollection struct {
	Features []featureProps `json:"features"`
}

// LoadGazetteer 从静态资源中加载 vendor/world.json 与 vendor/china/*.json。
func LoadGazetteer(fsys fs.FS) (*Gazetteer, error) {
	g := &Gazetteer{world: map[string]point{}, worldNorm: map[string]string{}, provinces: map[string]*cnProvince{}}
	if err := g.loadWorld(fsys, "vendor/world.json"); err != nil {
		return nil, err
	}
	if err := g.loadChina(fsys, "vendor/china"); err != nil {
		return nil, err
	}
	return g, nil
}

func readFC(fsys fs.FS, name string) (*featureCollection, error) {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	var fc featureCollection
	if err := json.Unmarshal(b, &fc); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", name, err)
	}
	return &fc, nil
}

func (g *Gazetteer) loadWorld(fsys fs.FS, name string) error {
	fc, err := readFC(fsys, name)
	if err != nil {
		return err
	}
	for _, f := range fc.Features {
		n := f.Properties.Name
		if n == "" {
			continue
		}
		if c, ok := largestPolygonCentroid(f.Geometry.Type, f.Geometry.Coordinates); ok {
			g.world[n] = c
			g.worldNorm[normWorld(n)] = n
		}
	}
	return nil
}

// largestPolygonCentroid 计算面积最大的外环多边形的质心，
// 避免海外领地（如阿拉斯加、法属圭亚那）把国家中心拉偏。
func largestPolygonCentroid(typ string, raw json.RawMessage) (point, bool) {
	var rings [][][]float64 // 每个多边形的外环
	switch typ {
	case "Polygon":
		var poly [][][]float64
		if json.Unmarshal(raw, &poly) != nil || len(poly) == 0 {
			return point{}, false
		}
		rings = append(rings, poly[0])
	case "MultiPolygon":
		var multi [][][][]float64
		if json.Unmarshal(raw, &multi) != nil {
			return point{}, false
		}
		for _, poly := range multi {
			if len(poly) > 0 {
				rings = append(rings, poly[0])
			}
		}
	default:
		return point{}, false
	}
	best, bestArea := point{}, 0.0
	for _, ring := range rings {
		var a, cx, cy float64
		for i := 0; i+1 < len(ring); i++ {
			if len(ring[i]) < 2 || len(ring[i+1]) < 2 {
				continue
			}
			x0, y0, x1, y1 := ring[i][0], ring[i][1], ring[i+1][0], ring[i+1][1]
			cross := x0*y1 - x1*y0
			a += cross
			cx += (x0 + x1) * cross
			cy += (y0 + y1) * cross
		}
		if a == 0 {
			continue
		}
		if math.Abs(a/2) > bestArea {
			bestArea = math.Abs(a / 2)
			best = point{Lon: cx / (3 * a), Lat: cy / (3 * a)}
		}
	}
	return best, bestArea > 0
}

func (g *Gazetteer) loadChina(fsys fs.FS, dir string) error {
	fc, err := readFC(fsys, path.Join(dir, "china.json"))
	if err != nil {
		return err
	}
	byCode := map[string]*cnProvince{}
	for _, f := range fc.Features {
		p := f.Properties
		if p.Name == "" || len(p.CP) < 2 {
			continue
		}
		prov := &cnProvince{Name: p.Name, CP: point{p.CP[0], p.CP[1]}, cities: map[string]cnCity{}}
		g.provList = append(g.provList, prov)
		g.provinces[normProvince(p.Name)] = prov
		id := p.ID
		if id == "" {
			id = f.ID
		}
		if len(id) >= 2 {
			byCode[id[:2]] = prov
		}
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		file := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || file == "china" || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		pfc, err := readFC(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		var cities []cnCity
		var sumLon, sumLat float64
		code := ""
		for _, f := range pfc.Features {
			p := f.Properties
			if len(p.CP) < 2 && (p.Latitude != 0 || p.Longitude != 0) {
				p.CP = []float64{p.Longitude, p.Latitude}
			}
			if p.Name == "" || len(p.CP) < 2 {
				continue
			}
			c := cnCity{Name: p.Name, CP: point{p.CP[0], p.CP[1]}}
			cities = append(cities, c)
			sumLon += c.CP.Lon
			sumLat += c.CP.Lat
			if id := firstNonEmpty(f.ID, p.ID); code == "" && len(id) >= 2 {
				code = id[:2]
			}
		}
		if len(cities) == 0 {
			continue
		}
		// 优先按行政区划代码匹配省份，缺少代码时（如台湾）按地市中心点的均值就近匹配
		prov := byCode[code]
		if prov == nil {
			prov = g.nearestProvince(point{sumLon / float64(len(cities)), sumLat / float64(len(cities))})
		}
		if prov == nil {
			continue
		}
		prov.File = file
		for _, c := range cities {
			prov.cities[normPlace(c.Name)] = c
		}
	}
	return nil
}

func (g *Gazetteer) nearestProvince(p point) *cnProvince {
	var best *cnProvince
	bestD := math.MaxFloat64
	for _, prov := range g.provList {
		d := math.Hypot(prov.CP.Lon-p.Lon, prov.CP.Lat-p.Lat)
		if d < bestD {
			best, bestD = prov, d
		}
	}
	return best
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

var provSuffix = strings.NewReplacer("特别行政区", "", "维吾尔自治区", "", "壮族自治区", "", "回族自治区", "", "自治区", "", "省", "", "市", "", " ", "")

func normProvince(s string) string { return provSuffix.Replace(strings.TrimSpace(s)) }

// ChinaMaps 返回省级地图名称 → 地图文件名，供前端下钻加载。
func (g *Gazetteer) ChinaMaps() map[string]string {
	out := map[string]string{}
	if g == nil {
		return out
	}
	for _, p := range g.provList {
		if p.File != "" {
			out[p.Name] = p.File
		}
	}
	return out
}

// 世界地图中名称与常见英文名不一致的国家/地区（按 ISO 3166 代码）。
var worldAlias = map[string]string{
	"CN": "China", "HK": "China", "MO": "China", "TW": "China",
	"KR": "Korea", "KP": "Dem. Rep. Korea", "CZ": "Czech Rep.", "LA": "Lao PDR", "CD": "Dem. Rep. Congo", "CG": "Congo",
	"BA": "Bosnia and Herz.", "DO": "Dominican Rep.", "CF": "Central African Rep.", "GQ": "Eq. Guinea", "SS": "S. Sudan",
	"MK": "Macedonia", "SZ": "Swaziland", "CI": "Côte d'Ivoire", "MM": "Myanmar", "PS": "Palestine", "TL": "Timor-Leste",
	"VC": "St. Vin. and Gren.", "AG": "Antigua and Barb.", "SB": "Solomon Is.", "KY": "Cayman Is.", "FO": "Faeroe Is.",
	"FK": "Falkland Is.", "TF": "Fr. S. Antarctic Lands", "PF": "Fr. Polynesia", "MP": "N. Mariana Is.", "IO": "Br. Indian Ocean Ter.",
	"ST": "São Tomé and Principe", "PM": "St. Pierre and Miquelon", "HM": "Heard I. and McDonald Is.", "GS": "S. Geo. and S. Sandw. Is.",
	"CV": "Cape Verde", "TC": "Turks and Caicos Is.", "VI": "U.S. Virgin Is.", "EH": "W. Sahara", "RU": "Russia", "US": "United States",
	"GB": "United Kingdom", "VN": "Vietnam", "SY": "Syria", "IR": "Iran", "BN": "Brunei", "BO": "Bolivia", "TZ": "Tanzania",
	"VE": "Venezuela", "MD": "Moldova", "FM": "Micronesia", "AX": "Aland", "CW": "Curaçao",
}

var enRegions = display.Regions(language.English)

func normWorld(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// WorldName 将国家代码或名称映射为世界地图中的区域名。
func (g *Gazetteer) WorldName(cc string, names ...string) string {
	if g == nil {
		return ""
	}
	cc = strings.ToUpper(cc)
	if n, ok := worldAlias[cc]; ok {
		if _, exists := g.world[n]; exists {
			return n
		}
	}
	cands := append([]string(nil), names...)
	if r, err := language.ParseRegion(cc); err == nil && len(cc) == 2 && enRegions != nil {
		cands = append(cands, enRegions.Name(r))
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if _, ok := g.world[c]; ok {
			return c
		}
		if n, ok := g.worldNorm[normWorld(c)]; ok {
			return n
		}
	}
	return ""
}

func isChina(cc, country string) bool {
	switch strings.ToUpper(cc) {
	case "CN", "HK", "MO", "TW":
		return true
	}
	return cc == "" && strings.HasPrefix(country, "中国")
}

// Resolve 解析 Info 中的地名，返回各级地图名称与近似坐标。
func (g *Gazetteer) Resolve(info *Info, englishNames ...string) Place {
	var pl Place
	if g == nil || info == nil || info.Private {
		return pl
	}
	pl.WorldName = g.WorldName(info.CountryCode, englishNames...)
	if isChina(info.CountryCode, info.Country) {
		pl.WorldName = "China"
		provName := info.Province
		switch strings.ToUpper(info.CountryCode) {
		case "HK":
			provName = "香港"
		case "MO":
			provName = "澳门"
		case "TW":
			provName = "台湾"
		}
		prov := g.provinces[normProvince(provName)]
		city := normPlace(info.City)
		if prov == nil && city != "" {
			prov = g.provinceOfCity(city)
		}
		if prov != nil {
			pl.ProvinceMap = prov.Name
			if c, ok := prov.cities[city]; ok && city != "" {
				pl.CityMap = c.Name
				pl.Lon, pl.Lat, pl.Level = c.CP.Lon, c.CP.Lat, "city"
				return pl
			}
			pl.Lon, pl.Lat, pl.Level = prov.CP.Lon, prov.CP.Lat, "province"
			return pl
		}
	}
	if c, ok := g.world[pl.WorldName]; ok {
		pl.Lon, pl.Lat, pl.Level = c.Lon, c.Lat, "country"
	}
	return pl
}

// provinceOfCity 在省份未知时按城市名反查（仅在城市名唯一时返回）。
func (g *Gazetteer) provinceOfCity(city string) *cnProvince {
	var found *cnProvince
	for _, p := range g.provList {
		if _, ok := p.cities[city]; ok {
			if found != nil {
				return nil
			}
			found = p
		}
	}
	return found
}
