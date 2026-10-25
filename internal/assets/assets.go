// Package assets 管理资产台账与漏洞：从 CMDB / 表格导入资产（IP / 网段、域名、负责人、部门、业务重要性、等保级别），
// 从漏洞扫描器（Nessus、OpenVAS、绿盟等导出的 CSV）导入漏洞。
//
// 检测流水线据此为攻击事件标注目标资产，并做漏洞关联：攻击利用的 CVE 在目标资产上存在且未修复时，
// 提升为严重并判定为疑似成功；攻击类型 / 组件与资产上的未修复漏洞一致时提升等级。
package assets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"netsa/internal/model"
)

// 资产重要性。
const (
	LevelCore      = "core"      // 核心
	LevelImportant = "important" // 重要
	LevelNormal    = "normal"    // 一般
)

// LevelLabel 是重要性的中文名称。
var LevelLabel = map[string]string{LevelCore: "核心", LevelImportant: "重要", LevelNormal: "一般"}

// LevelRank 用于比较重要性（越大越重要）。
func LevelRank(l string) int {
	switch l {
	case LevelCore:
		return 3
	case LevelImportant:
		return 2
	case LevelNormal:
		return 1
	}
	return 0
}

// 漏洞状态。
const (
	VulnOpen     = "open"     // 未修复
	VulnFixed    = "fixed"    // 已修复
	VulnAccepted = "accepted" // 风险接受
)

// VulnStatusLabel 是漏洞状态的中文名称。
var VulnStatusLabel = map[string]string{VulnOpen: "未修复", VulnFixed: "已修复", VulnAccepted: "风险接受"}

const (
	maxAssets = 50000
	maxVulns  = 200000
)

// Asset 是一项资产。
type Asset struct {
	ID         string    `json:"id"`
	IP         string    `json:"ip"`              // IP 或网段，可为空（只按域名识别）
	Hosts      []string  `json:"hosts,omitempty"` // 域名，支持 *.example.com
	Name       string    `json:"name"`
	Owner      string    `json:"owner,omitempty"`
	Dept       string    `json:"dept,omitempty"`
	Importance string    `json:"importance"`     // core / important / normal
	MLPS       int       `json:"mlps,omitempty"` // 等保级别（1 ~ 5），0 为未定级
	Env        string    `json:"env,omitempty"`  // 生产 / 测试 等
	Tags       []string  `json:"tags,omitempty"`
	Note       string    `json:"note,omitempty"`
	Source     string    `json:"source"` // ui / import
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`

	prefix netip.Prefix
}

// Vuln 是资产上的一个漏洞。
type Vuln struct {
	ID       string         `json:"id"`
	IP       string         `json:"ip,omitempty"`
	Host     string         `json:"host,omitempty"`
	Port     int            `json:"port,omitempty"`
	CVE      []string       `json:"cve,omitempty"`
	Name     string         `json:"name"`
	Severity model.Severity `json:"severity"`
	Product  string         `json:"product,omitempty"`
	Solution string         `json:"solution,omitempty"`
	Status   string         `json:"status"`
	Source   string         `json:"source,omitempty"` // 导入的文件 / 扫描器
	Found    time.Time      `json:"found"`
	Updated  time.Time      `json:"updated"`

	classes []string // 漏洞类型 / 组件关键字类别
}

func (v *Vuln) key() string {
	id := strings.Join(v.CVE, ",")
	if id == "" {
		id = strings.ToLower(v.Name)
	}
	target := v.IP
	if target == "" {
		target = strings.ToLower(v.Host)
	}
	return fmt.Sprintf("%s|%d|%s", target, v.Port, id)
}

// ---------------- 关联特征 ----------------

var cveRe = regexp.MustCompile(`(?i)CVE-(\d{4})-(\d{4,7})((?:/\d{4,7})*)`)

// ExtractCVEs 从文本中提取 CVE 编号，支持“CVE-2021-41773/42013”这类简写。
func ExtractCVEs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range cveRe.FindAllStringSubmatch(s, -1) {
		ids := []string{m[2]}
		if m[3] != "" {
			ids = append(ids, strings.Split(strings.TrimPrefix(m[3], "/"), "/")...)
		}
		for _, id := range ids {
			c := "CVE-" + m[1] + "-" + id
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// classKeywords 是漏洞类型 / 组件的关键字类别：攻击命中与漏洞名称落在同一类别时视为相关。
var classKeywords = []struct {
	class string
	words []string
}{
	{"sqli", []string{"sql注入", "sql injection", "sqli"}},
	{"xss", []string{"xss", "跨站脚本", "cross-site scripting", "cross site scripting"}},
	{"cmd", []string{"命令注入", "命令执行", "代码执行", "command injection", "code execution", "rce", "os command"}},
	{"traversal", []string{"目录穿越", "路径穿越", "目录遍历", "文件包含", "任意文件读取", "path traversal", "directory traversal", "file inclusion", "lfi"}},
	{"upload", []string{"文件上传", "file upload", "webshell"}},
	{"deser", []string{"反序列化", "deserialization", "deserialisation"}},
	{"ssrf", []string{"ssrf", "服务端请求伪造", "server-side request forgery"}},
	{"xxe", []string{"xxe", "xml外部实体", "xml external entity"}},
	{"expr", []string{"表达式注入", "ognl", "spel", "el injection", "模板注入", "ssti"}},
	{"weakpass", []string{"弱口令", "弱密码", "默认口令", "默认密码", "weak password", "default password", "default credential", "暴力破解"}},
	{"struts", []string{"struts"}},
	{"weblogic", []string{"weblogic"}},
	{"log4j", []string{"log4j", "log4shell"}},
	{"thinkphp", []string{"thinkphp"}},
	{"shiro", []string{"shiro"}},
	{"fastjson", []string{"fastjson"}},
	{"spring", []string{"spring"}},
	{"jboss", []string{"jboss"}},
	{"tomcat", []string{"tomcat"}},
	{"redis", []string{"redis"}},
	{"phpunit", []string{"phpunit"}},
	{"confluence", []string{"confluence"}},
	{"exchange", []string{"exchange", "proxyshell", "proxylogon"}},
}

// categoryClass 把检测规则的攻击类型映射到关键字类别。
var categoryClass = map[string]string{
	"SQL注入": "sqli", "XSS跨站脚本": "xss", "命令/代码执行": "cmd", "目录穿越/文件包含": "traversal", "WebShell后门": "upload",
	"反序列化": "deser", "SSRF": "ssrf", "XXE": "xxe", "表达式注入": "expr", "暴力破解": "weakpass",
}

// Classes 返回文本所属的关键字类别。
func Classes(texts ...string) []string {
	var out []string
	s := strings.ToLower(strings.Join(texts, " "))
	compact := strings.ReplaceAll(s, " ", "") // “SQL 注入”与“SQL注入”都能匹配
	for _, c := range classKeywords {
		for _, w := range c.words {
			if strings.Contains(s, w) || strings.Contains(compact, w) {
				out = append(out, c.class)
				break
			}
		}
	}
	return out
}

// ---------------- 管理器 ----------------

// index 是不可变的查找快照，资产或漏洞变化时整体替换，流水线查找无锁。
type index struct {
	exact   map[netip.Addr]*Asset
	nets    []*Asset // 按前缀从长到短
	hosts   map[string]*Asset
	suffix  []suffixAsset // 通配符域名
	vulnIP  map[string][]*Vuln
	vulnHst map[string][]*Vuln
}

type suffixAsset struct {
	suffix string // ".example.com"
	a      *Asset
}

// Manager 管理资产与漏洞。
type Manager struct {
	mu     sync.Mutex
	path   string
	assets []*Asset
	vulns  []*Vuln
	idx    atomic.Pointer[index]
	now    func() time.Time
}

// Load 加载资产文件（不存在时为空）。path 为空时只保存在内存中。
func Load(path string) (*Manager, error) {
	m := &Manager{path: path, now: time.Now}
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			var f fileData
			if err := json.Unmarshal(data, &f); err != nil {
				return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
			}
			for _, a := range f.Assets {
				if a != nil && a.prepare() == nil {
					m.assets = append(m.assets, a)
				}
			}
			for _, v := range f.Vulns {
				if v != nil && v.prepare() == nil {
					m.vulns = append(m.vulns, v)
				}
			}
		}
	}
	m.reindex()
	return m, nil
}

type fileData struct {
	Assets []*Asset `json:"assets"`
	Vulns  []*Vuln  `json:"vulns"`
}

func cleanText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > limit {
		s = string([]rune(s)[:limit])
	}
	return s
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("IP 或网段无效: %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[:i], ":") {
		h = h[:i] // 去掉端口
	}
	return strings.TrimSuffix(h, ".")
}

func (a *Asset) prepare() error {
	a.IP, a.Name = strings.TrimSpace(a.IP), cleanText(a.Name, 60)
	a.Owner, a.Dept, a.Env, a.Note = cleanText(a.Owner, 40), cleanText(a.Dept, 60), cleanText(a.Env, 20), cleanText(a.Note, 300)
	var hosts []string
	for _, h := range a.Hosts {
		if h = normHost(h); h != "" && len(h) <= 253 && len(hosts) < 50 {
			hosts = append(hosts, h)
		}
	}
	a.Hosts = hosts
	var tags []string
	for _, t := range a.Tags {
		if t = cleanText(t, 20); t != "" && len(tags) < 20 {
			tags = append(tags, t)
		}
	}
	a.Tags = tags
	if a.IP == "" && len(a.Hosts) == 0 {
		return errors.New("资产需填写 IP / 网段或域名")
	}
	a.prefix = netip.Prefix{}
	if a.IP != "" {
		p, err := parsePrefix(a.IP)
		if err != nil {
			return err
		}
		if p.Addr().Is4() && p.Bits() < 8 || !p.Addr().Is4() && p.Bits() < 16 {
			return fmt.Errorf("网段范围过大: %s", a.IP)
		}
		a.prefix = p
		if p.IsSingleIP() {
			a.IP = p.Addr().String()
		} else {
			a.IP = p.String()
		}
	}
	if a.Name == "" {
		a.Name = a.IP
		if a.Name == "" {
			a.Name = a.Hosts[0]
		}
	}
	if LevelLabel[a.Importance] == "" {
		a.Importance = ParseImportance(a.Importance)
	}
	if a.MLPS < 0 || a.MLPS > 5 {
		a.MLPS = 0
	}
	return nil
}

func (v *Vuln) prepare() error {
	v.IP, v.Host = strings.TrimSpace(v.IP), normHost(v.Host)
	if v.IP != "" {
		a, err := netip.ParseAddr(v.IP)
		if err != nil {
			return fmt.Errorf("漏洞的 IP 无效: %q", v.IP)
		}
		v.IP = a.Unmap().String()
	}
	if v.IP == "" && v.Host == "" {
		return errors.New("漏洞需填写 IP 或主机名")
	}
	v.Name, v.Product, v.Solution = cleanText(v.Name, 200), cleanText(v.Product, 80), cleanText(v.Solution, 500)
	var cves []string
	for _, c := range append(v.CVE, ExtractCVEs(v.Name)...) {
		for _, x := range ExtractCVEs(c) {
			if !contains(cves, x) && len(cves) < 20 {
				cves = append(cves, x)
			}
		}
	}
	v.CVE = cves
	if v.Name == "" {
		if len(cves) == 0 {
			return errors.New("漏洞需填写名称或 CVE 编号")
		}
		v.Name = cves[0]
	}
	if v.Port < 0 || v.Port > 65535 {
		v.Port = 0
	}
	if VulnStatusLabel[v.Status] == "" {
		v.Status = ParseVulnStatus(v.Status)
	}
	v.Severity = max(min(v.Severity, model.SevCritical), model.SevInfo)
	v.classes = Classes(v.Name, v.Product)
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) reindex() {
	idx := &index{exact: map[netip.Addr]*Asset{}, hosts: map[string]*Asset{}, vulnIP: map[string][]*Vuln{}, vulnHst: map[string][]*Vuln{}}
	for _, a := range m.assets {
		if a.prefix.IsValid() {
			if a.prefix.IsSingleIP() {
				idx.exact[a.prefix.Addr()] = a
			} else {
				idx.nets = append(idx.nets, a)
			}
		}
		for _, h := range a.Hosts {
			if strings.HasPrefix(h, "*.") {
				idx.suffix = append(idx.suffix, suffixAsset{h[1:], a})
			} else {
				idx.hosts[h] = a
			}
		}
	}
	sort.SliceStable(idx.nets, func(i, j int) bool { return idx.nets[i].prefix.Bits() > idx.nets[j].prefix.Bits() })
	sort.SliceStable(idx.suffix, func(i, j int) bool { return len(idx.suffix[i].suffix) > len(idx.suffix[j].suffix) })
	for _, v := range m.vulns {
		if v.Status != VulnOpen {
			continue // 只有未修复的漏洞参与关联
		}
		if v.IP != "" {
			idx.vulnIP[v.IP] = append(idx.vulnIP[v.IP], v)
		}
		if v.Host != "" {
			idx.vulnHst[v.Host] = append(idx.vulnHst[v.Host], v)
		}
	}
	m.idx.Store(idx)
}

func (idx *index) byIP(ip string) *Asset {
	if ip == "" {
		return nil
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	a = a.Unmap()
	if as := idx.exact[a]; as != nil {
		return as
	}
	for _, as := range idx.nets {
		if as.prefix.Contains(a) {
			return as
		}
	}
	return nil
}

func (idx *index) byHost(h string) *Asset {
	if h == "" {
		return nil
	}
	h = normHost(h)
	if a := idx.hosts[h]; a != nil {
		return a
	}
	for _, s := range idx.suffix {
		if strings.HasSuffix(h, s.suffix) {
			return s.a
		}
	}
	return nil
}

// Match 是一个事件的资产上下文。
type Match struct {
	Asset *Asset
	Vulns []*Vuln // 目标上未修复的漏洞
}

// Lookup 返回事件目标（目的 IP、站点域名）对应的资产与未修复漏洞。未登记资产且没有漏洞时返回 nil。
func (m *Manager) Lookup(ev *model.Event) *Match {
	if m == nil {
		return nil
	}
	idx := m.idx.Load()
	if len(idx.exact) == 0 && len(idx.nets) == 0 && len(idx.hosts) == 0 && len(idx.suffix) == 0 && len(idx.vulnIP) == 0 && len(idx.vulnHst) == 0 {
		return nil
	}
	if ev.Outbound { // 出站流量（外连）：内网发起方是资产，不关联漏洞
		if a := idx.byIP(ev.SrcIP); a != nil {
			return &Match{Asset: a}
		}
		return nil
	}
	host := ""
	if ev.Kind == model.KindWeb {
		host = ev.Host
	}
	a := idx.byIP(ev.DstIP)
	if a == nil {
		a = idx.byHost(host)
	}
	var vulns []*Vuln
	if ev.DstIP != "" {
		vulns = idx.vulnIP[ev.DstIP]
	}
	if h := normHost(host); h != "" {
		vulns = append(vulns[:len(vulns):len(vulns)], idx.vulnHst[h]...)
	}
	if a != nil && len(vulns) == 0 && a.prefix.IsSingleIP() {
		vulns = idx.vulnIP[a.IP] // 只有域名的 Web 日志：按资产登记的 IP 关联漏洞
	}
	if a == nil && len(vulns) == 0 {
		return nil
	}
	return &Match{Asset: a, Vulns: vulns}
}

// Correlate 判断命中与漏洞的关系：返回最相关的漏洞，exact 表示 CVE 精确一致。
func (mt *Match) Correlate(h *model.Hit) (v *Vuln, exact bool) {
	if mt == nil || len(mt.Vulns) == 0 || h.TagOnly {
		return nil, false
	}
	cves := ExtractCVEs(h.Name)
	for _, x := range mt.Vulns {
		for _, c := range cves {
			if contains(x.CVE, c) {
				return x, true
			}
		}
	}
	classes := Classes(h.Name)
	if c := categoryClass[h.Category]; c != "" {
		classes = append(classes, c)
	}
	var best *Vuln
	for _, x := range mt.Vulns {
		for _, c := range classes {
			if contains(x.classes, c) && (best == nil || x.Severity > best.Severity) {
				best = x
			}
		}
	}
	return best, false
}

// ---------------- 增删改 ----------------

// 资产管理错误。
var (
	ErrNoAsset    = errors.New("资产不存在")
	ErrNoVuln     = errors.New("漏洞不存在")
	ErrAssetLimit = errors.New("资产数量已达上限（50000）")
	ErrAssetDup   = errors.New("该 IP / 网段已登记为资产")
)

func (m *Manager) findLocked(a *Asset) *Asset {
	for _, o := range m.assets {
		if a.IP != "" && o.IP == a.IP || a.IP == "" && o.IP == "" && len(a.Hosts) > 0 && contains(o.Hosts, a.Hosts[0]) {
			return o
		}
	}
	return nil
}

// AddAsset 登记资产。
func (m *Manager) AddAsset(a Asset) (Asset, error) {
	if err := a.prepare(); err != nil {
		return Asset{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.findLocked(&a) != nil {
		return Asset{}, ErrAssetDup
	}
	if len(m.assets) >= maxAssets {
		return Asset{}, ErrAssetLimit
	}
	a.ID, a.Source, a.Created, a.Updated = newID(), "ui", m.now(), m.now()
	m.assets = append(m.assets, &a)
	m.reindex()
	return a, m.saveLocked()
}

// UpdateAsset 修改资产。
func (m *Manager) UpdateAsset(id string, a Asset) (Asset, error) {
	if err := a.prepare(); err != nil {
		return Asset{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, o := range m.assets {
		if o.ID != id {
			continue
		}
		if d := m.findLocked(&a); d != nil && d.ID != id {
			return Asset{}, ErrAssetDup
		}
		a.ID, a.Source, a.Created, a.Updated = o.ID, o.Source, o.Created, m.now()
		m.assets[i] = &a
		m.reindex()
		return a, m.saveLocked()
	}
	return Asset{}, ErrNoAsset
}

// DeleteAsset 删除资产（资产上的漏洞保留）。
func (m *Manager) DeleteAsset(id string) (Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, o := range m.assets {
		if o.ID == id {
			m.assets = append(m.assets[:i:i], m.assets[i+1:]...)
			m.reindex()
			return *o, m.saveLocked()
		}
	}
	return Asset{}, ErrNoAsset
}

// SetVulnStatus 修改漏洞状态（修复后标记为已修复，不再参与关联）。
func (m *Manager) SetVulnStatus(id, status string) (Vuln, error) {
	if VulnStatusLabel[status] == "" {
		return Vuln{}, errors.New("漏洞状态只能为 open / fixed / accepted")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, v := range m.vulns {
		if v.ID == id {
			nv := *v
			nv.Status, nv.Updated = status, m.now()
			m.vulns[i] = &nv
			m.reindex()
			return nv, m.saveLocked()
		}
	}
	return Vuln{}, ErrNoVuln
}

// DeleteVuln 删除漏洞。
func (m *Manager) DeleteVuln(id string) (Vuln, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, v := range m.vulns {
		if v.ID == id {
			m.vulns = append(m.vulns[:i:i], m.vulns[i+1:]...)
			m.reindex()
			return *v, m.saveLocked()
		}
	}
	return Vuln{}, ErrNoVuln
}

// ImportResult 是一次导入的结果。
type ImportResult struct {
	Added   int      `json:"added"`
	Updated int      `json:"updated"`
	Removed int      `json:"removed"` // 替换模式下删除的旧记录
	Skipped int      `json:"skipped"`
	Errors  []string `json:"errors"` // 前 50 条错误
}

func (r *ImportResult) fail(line int, err error) {
	r.Skipped++
	if len(r.Errors) < 50 {
		r.Errors = append(r.Errors, fmt.Sprintf("第 %d 行：%v", line, err))
	}
}

// ImportAssets 批量导入资产：merge 按 IP（或域名）更新已有资产、追加新资产；replace 先清空界面以外导入的资产。
func (m *Manager) ImportAssets(list []Asset, lines []int, replace bool) (ImportResult, error) {
	res := ImportResult{Errors: []string{}}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if replace {
		kept := m.assets[:0:0]
		for _, a := range m.assets {
			if a.Source == "ui" {
				kept = append(kept, a)
			} else {
				res.Removed++
			}
		}
		m.assets = kept
	}
	for i := range list {
		a := list[i]
		if err := a.prepare(); err != nil {
			res.fail(lines[i], err)
			continue
		}
		if o := m.findLocked(&a); o != nil {
			a.ID, a.Source, a.Created, a.Updated = o.ID, o.Source, o.Created, now
			na := a
			for j, x := range m.assets { // 替换为新对象，不修改检测流水线可能正在读取的旧对象
				if x == o {
					m.assets[j] = &na
				}
			}
			res.Updated++
			continue
		}
		if len(m.assets) >= maxAssets {
			res.fail(lines[i], ErrAssetLimit)
			continue
		}
		a.ID, a.Source, a.Created, a.Updated = newID(), "import", now, now
		m.assets = append(m.assets, &a)
		res.Added++
	}
	m.reindex()
	return res, m.saveLocked()
}

// ImportVulns 批量导入漏洞：merge 按（IP / 主机、端口、CVE 或名称）更新；replace 用本次扫描结果替换全部漏洞
// （上次存在、本次未出现的漏洞视为已修复，标记为 fixed 而不是删除，便于统计修复情况）。
func (m *Manager) ImportVulns(list []Vuln, lines []int, replace bool, source string) (ImportResult, error) {
	res := ImportResult{Errors: []string{}}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	// 更新时替换为新对象：检测流水线无锁读取旧索引中的漏洞对象，不能原地修改
	byKey := map[string]int{}
	for i, v := range m.vulns {
		byKey[v.key()] = i
	}
	seen := map[string]bool{}
	for i := range list {
		v := list[i]
		if err := v.prepare(); err != nil {
			res.fail(lines[i], err)
			continue
		}
		if v.Severity == model.SevInfo {
			res.Skipped++ // 信息类结果不作为漏洞
			continue
		}
		k := v.key()
		seen[k] = true
		if idx, ok := byKey[k]; ok {
			o := m.vulns[idx]
			status := o.Status
			if v.Status != VulnOpen || status == VulnFixed { // 再次扫描到已修复的漏洞：重新打开
				status = v.Status
			}
			v.ID, v.Found, v.Updated, v.Status, v.Source = o.ID, o.Found, now, status, source
			v.prepare()
			nv := v
			m.vulns[idx] = &nv
			res.Updated++
			continue
		}
		if len(m.vulns) >= maxVulns {
			res.fail(lines[i], errors.New("漏洞数量已达上限（200000）"))
			continue
		}
		v.ID, v.Found, v.Updated, v.Source = newID(), now, now, source
		nv := v
		m.vulns = append(m.vulns, &nv)
		byKey[k] = len(m.vulns) - 1
		res.Added++
	}
	if replace {
		for i, v := range m.vulns {
			if !seen[v.key()] && v.Status == VulnOpen {
				nv := *v
				nv.Status, nv.Updated = VulnFixed, now
				m.vulns[i] = &nv
				res.Removed++
			}
		}
	}
	m.reindex()
	return res, m.saveLocked()
}

// ---------------- 查询 ----------------

// AssetView 是资产及其漏洞统计。
type AssetView struct {
	Asset
	ImportanceLabel string         `json:"importance_label"`
	OpenVulns       int            `json:"open_vulns"`
	VulnBySeverity  map[string]int `json:"vuln_by_severity"`
}

// Assets 返回资产列表（按重要性、未修复漏洞数排序）。
func (m *Manager) Assets(q, importance string) []AssetView {
	q = strings.ToLower(strings.TrimSpace(q))
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.idx.Load()
	out := []AssetView{}
	for _, a := range m.assets {
		if importance != "" && a.Importance != importance {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(a.IP+" "+a.Name+" "+a.Owner+" "+a.Dept+" "+strings.Join(a.Hosts, " ")+" "+strings.Join(a.Tags, " ")), q) {
			continue
		}
		v := AssetView{Asset: *a, ImportanceLabel: LevelLabel[a.Importance], VulnBySeverity: map[string]int{}}
		for _, x := range m.assetVulnsLocked(idx, a) {
			v.OpenVulns++
			v.VulnBySeverity[x.Severity.String()]++
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if r1, r2 := LevelRank(out[i].Importance), LevelRank(out[j].Importance); r1 != r2 {
			return r1 > r2
		}
		if out[i].OpenVulns != out[j].OpenVulns {
			return out[i].OpenVulns > out[j].OpenVulns
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// assetVulnsLocked 返回资产上未修复的漏洞（按 IP / 网段与域名匹配）。
func (m *Manager) assetVulnsLocked(idx *index, a *Asset) []*Vuln {
	var out []*Vuln
	if a.prefix.IsSingleIP() {
		out = append(out, idx.vulnIP[a.IP]...)
	} else if a.prefix.IsValid() {
		for ip, list := range idx.vulnIP {
			if addr, err := netip.ParseAddr(ip); err == nil && a.prefix.Contains(addr) {
				out = append(out, list...)
			}
		}
	}
	for _, h := range a.Hosts {
		out = append(out, idx.vulnHst[h]...)
	}
	return out
}

// VulnQuery 是漏洞查询条件。
type VulnQuery struct {
	IP          string
	Status      string
	MinSeverity model.Severity
	Search      string
	Limit       int
}

// VulnView 是漏洞及其所属资产。
type VulnView struct {
	Vuln
	Asset           string `json:"asset,omitempty"`
	AssetImportance string `json:"asset_importance,omitempty"`
	Owner           string `json:"owner,omitempty"`
}

// Vulns 查询漏洞（按状态、等级、资产重要性排序），返回列表与总数。
func (m *Manager) Vulns(q VulnQuery) ([]VulnView, int) {
	search := strings.ToLower(strings.TrimSpace(q.Search))
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.idx.Load()
	out := []VulnView{}
	for _, v := range m.vulns {
		if q.Status != "" && v.Status != q.Status || v.Severity < q.MinSeverity || q.IP != "" && v.IP != q.IP {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(v.IP+" "+v.Host+" "+v.Name+" "+strings.Join(v.CVE, " ")+" "+v.Product), search) {
			continue
		}
		vv := VulnView{Vuln: *v}
		a := idx.byIP(v.IP)
		if a == nil {
			a = idx.byHost(v.Host)
		}
		if a != nil {
			vv.Asset, vv.AssetImportance, vv.Owner = a.Name, a.Importance, a.Owner
		}
		out = append(out, vv)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Status == VulnOpen) != (b.Status == VulnOpen) {
			return a.Status == VulnOpen
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if r1, r2 := LevelRank(a.AssetImportance), LevelRank(b.AssetImportance); r1 != r2 {
			return r1 > r2
		}
		return a.IP < b.IP
	})
	total := len(out)
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, total
}

// Summary 是资产与漏洞概况（安全评估、合规报告使用）。
type Summary struct {
	Assets       int            `json:"assets"`
	ByImportance map[string]int `json:"by_importance"`
	MLPS         map[int]int    `json:"mlps"` // 等保级别 → 资产数
	NoOwner      int            `json:"no_owner"`
	Vulns        int            `json:"vulns"`
	OpenVulns    int            `json:"open_vulns"`
	OpenBySev    map[string]int `json:"open_by_severity"`
	Fixed        int            `json:"fixed"`
	Accepted     int            `json:"accepted"`
	CoreOpenHigh int            `json:"core_open_high"` // 核心资产上未修复的高危及以上漏洞
	Oldest       time.Time      `json:"oldest_open,omitempty"`
}

// Summary 返回资产与漏洞概况。
func (m *Manager) Summary() Summary {
	s := Summary{ByImportance: map[string]int{}, MLPS: map[int]int{}, OpenBySev: map[string]int{}}
	if m == nil {
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.idx.Load()
	for _, a := range m.assets {
		s.Assets++
		s.ByImportance[a.Importance]++
		if a.MLPS > 0 {
			s.MLPS[a.MLPS]++
		}
		if a.Owner == "" {
			s.NoOwner++
		}
	}
	for _, v := range m.vulns {
		s.Vulns++
		switch v.Status {
		case VulnOpen:
			s.OpenVulns++
			s.OpenBySev[v.Severity.String()]++
			if s.Oldest.IsZero() || v.Found.Before(s.Oldest) {
				s.Oldest = v.Found
			}
			if v.Severity >= model.SevHigh {
				a := idx.byIP(v.IP)
				if a == nil {
					a = idx.byHost(v.Host)
				}
				if a != nil && a.Importance == LevelCore {
					s.CoreOpenHigh++
				}
			}
		case VulnFixed:
			s.Fixed++
		case VulnAccepted:
			s.Accepted++
		}
	}
	return s
}

// AssetByID 返回资产及其漏洞。
func (m *Manager) AssetByID(id string) (*Asset, []Vuln) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.assets {
		if a.ID == id {
			c := *a
			var vs []Vuln
			for _, v := range m.assetVulnsLocked(m.idx.Load(), a) {
				vs = append(vs, *v)
			}
			return &c, vs
		}
	}
	return nil, nil
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	f := fileData{Assets: m.assets, Vulns: m.vulns}
	if f.Assets == nil {
		f.Assets = []*Asset{}
	}
	if f.Vulns == nil {
		f.Vulns = []*Vuln{}
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("保存资产失败: %w", err)
	}
	return os.Rename(tmp, m.path)
}
