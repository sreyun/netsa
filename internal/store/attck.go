package store

import (
	"math/bits"
	"sort"

	"netsa/internal/model"
)

// CatC2 是内网主机（或本机）外连威胁情报地址的攻击类型，属于失陷迹象。
const CatC2 = "恶意外连"

// CatBeacon 是内网主机按固定间隔回连同一外部地址（疑似 C2 心跳），CatCrawl 是接口遍历 / 批量爬取。
const (
	CatBeacon = "可疑外连"
	CatCrawl  = "数据爬取/越权遍历"
)

// CatMalware 是安全设备（IDS / IPS / 防火墙威胁日志）报出的恶意软件与远控通信。
const CatMalware = "恶意软件/远控"

// Tactic 是 MITRE ATT&CK 战术。
type Tactic struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	EN   string `json:"en"`
}

// Technique 是 MITRE ATT&CK 技术。
type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

// tactics 按攻击链顺序排列（只列出能从网络 / Web / 防火墙日志中观测到的战术）。
var tactics = []Tactic{
	{"TA0043", "侦察", "Reconnaissance"}, {"TA0001", "初始访问", "Initial Access"}, {"TA0002", "执行", "Execution"},
	{"TA0003", "持久化", "Persistence"}, {"TA0005", "防御规避", "Defense Evasion"}, {"TA0006", "凭证访问", "Credential Access"},
	{"TA0007", "发现", "Discovery"}, {"TA0009", "收集", "Collection"}, {"TA0011", "命令与控制", "Command and Control"}, {"TA0040", "影响", "Impact"},
}

var techniques = map[string]Technique{
	"T1595.001": {"T1595.001", "主动扫描：IP 段扫描", "TA0043"},
	"T1595.002": {"T1595.002", "主动扫描：漏洞扫描", "TA0043"},
	"T1595.003": {"T1595.003", "主动扫描：字典扫描", "TA0043"},
	"T1190":     {"T1190", "利用面向公众的应用", "TA0001"},
	"T1189":     {"T1189", "路过式攻击（XSS）", "TA0001"},
	"T1059":     {"T1059", "命令与脚本解释器", "TA0002"},
	"T1505.003": {"T1505.003", "服务端组件：WebShell", "TA0003"},
	"T1036":     {"T1036", "伪装（来源地址伪造）", "TA0005"},
	"T1110":     {"T1110", "暴力破解", "TA0006"},
	"T1552.001": {"T1552.001", "文件中的凭证", "TA0006"},
	"T1552.005": {"T1552.005", "云实例元数据 API", "TA0006"},
	"T1083":     {"T1083", "文件和目录发现", "TA0007"},
	"T1046":     {"T1046", "网络服务发现", "TA0007"},
	"T1018":     {"T1018", "远程系统发现", "TA0007"},
	"T1119":     {"T1119", "自动化收集（接口遍历 / 爬取）", "TA0009"},
	"T1071":     {"T1071", "应用层协议通信（外连 C2）", "TA0011"},
	"T1498":     {"T1498", "网络拒绝服务", "TA0040"},
	"T1499":     {"T1499", "终端拒绝服务（CC）", "TA0040"},
	"T1071.004": {"T1071.004", "应用层协议：DNS（隧道 / 带外回连）", "TA0011"},
	"T1568.002": {"T1568.002", "动态解析：域名生成算法（DGA）", "TA0011"},
	"T1568":     {"T1568", "动态解析（动态域名）", "TA0011"},
	"T1572":     {"T1572", "协议隧道（内网穿透）", "TA0011"},
	"T1496":     {"T1496", "资源劫持（挖矿）", "TA0040"},
	"T1070.001": {"T1070.001", "清除 Windows 事件日志", "TA0005"},
	"T1136":     {"T1136", "创建账号", "TA0003"},
	"T1098":     {"T1098", "账号操纵（加入特权组）", "TA0003"},
	"T1543":     {"T1543", "创建或修改系统进程（服务）", "TA0003"},
	"T1053":     {"T1053", "计划任务", "TA0003"},
	"T1078":     {"T1078", "有效账号", "TA0001"},
}

// categoryTechniques 把检测的攻击类型映射到 ATT&CK 技术。
var categoryTechniques = map[string][]string{
	"SQL注入":      {"T1190"},
	"XSS跨站脚本":    {"T1189"},
	"目录穿越/文件包含":  {"T1190", "T1083"},
	"命令/代码执行":    {"T1190", "T1059"},
	"表达式注入":      {"T1190", "T1059"},
	"SSRF":       {"T1190", "T1552.005"},
	"XXE":        {"T1190"},
	"反序列化":       {"T1190", "T1059"},
	"WebShell后门": {"T1505.003"},
	"已知漏洞利用":     {"T1190"},
	"IoT僵尸网络":    {"T1190"},
	"敏感文件探测":     {"T1083", "T1552.001"},
	"管理后台探测":     {"T1595.003"},
	"目录扫描":       {"T1595.003"},
	"扫描器":        {"T1595.002"},
	"自动化工具":      {"T1595.002"},
	"网络空间测绘":     {"T1595.001"},
	"端口扫描":       {"T1595.001"},
	"协议异常":       {"T1046"},
	"高危服务探测":     {"T1046"},
	"主机探测":       {"T1018"},
	"暴力破解":       {"T1110"},
	"IP伪造":       {"T1036"},
	"CC攻击":       {"T1499"},
	"洪水攻击":       {"T1498"},
	CatC2:        {"T1071"},
	CatMalware:   {"T1071"},
	CatBeacon:    {"T1071"},
	CatCrawl:     {"T1119"},
	"DNS隧道":      {"T1071.004"},
	"带外探测回连":     {"T1071.004", "T1190"},
	"DGA域名":      {"T1568.002"},
	"动态域名/内网穿透":  {"T1568", "T1572"},
	"挖矿":         {"T1496"},
	"主机安全事件":     {"T1070.001", "T1543", "T1053"},
	"账号异常":       {"T1136", "T1098", "T1078"},
}

// techniqueCategories 是 categoryTechniques 的反向索引。
var techniqueCategories = func() map[string][]string {
	m := map[string][]string{}
	for cat, ts := range categoryTechniques {
		for _, t := range ts {
			m[t] = append(m[t], cat)
		}
	}
	for _, cats := range m {
		sort.Strings(cats)
	}
	return m
}()

// techIndex 为每个技术分配位下标，catTechMask 为每个攻击类型对应技术的位掩码（技术数不超过 64）。
var techIndex, catTechMask = func() (map[string]int, map[string]uint64) {
	ids := make([]string, 0, len(techniques))
	for id := range techniques {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	idx := map[string]int{}
	for i, id := range ids {
		idx[id] = i
	}
	masks := map[string]uint64{}
	for cat, ts := range categoryTechniques {
		for _, t := range ts {
			masks[cat] |= 1 << idx[t]
		}
	}
	return idx, masks
}()

// TechniqueCategories 返回映射到该 ATT&CK 技术的攻击类型（用于按技术下钻）。
func TechniqueCategories(id string) []string { return techniqueCategories[id] }

// TechniqueRef 是攻击源使用过的技术。
type TechniqueRef struct {
	Technique
	TacticName string `json:"tactic_name"`
	Hits       int    `json:"hits"`
}

// techniquesOf 返回攻击源使用过的 ATT&CK 技术（按战术顺序）。
func techniquesOf(cats map[string]int) []TechniqueRef {
	hits := map[string]int{}
	for cat, n := range cats {
		for _, t := range categoryTechniques[cat] {
			hits[t] += n
		}
	}
	out := make([]TechniqueRef, 0, len(hits))
	for id, n := range hits {
		t := techniques[id]
		out = append(out, TechniqueRef{Technique: t, TacticName: tacticName(t.Tactic), Hits: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := tacticIndex(out[i].Tactic), tacticIndex(out[j].Tactic); a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func tacticIndex(id string) int {
	for i, t := range tactics {
		if t.ID == id {
			return i
		}
	}
	return len(tactics)
}

func tacticName(id string) string {
	if i := tacticIndex(id); i < len(tactics) {
		return tactics[i].Name
	}
	return id
}

// TechniqueStat 是 ATT&CK 矩阵中的一个技术。
type TechniqueStat struct {
	Technique
	Hits        int64          `json:"hits"`
	Attackers   int            `json:"attackers"`
	MaxSeverity model.Severity `json:"max_severity"`
	Categories  []string       `json:"categories"`
}

// TacticStat 是 ATT&CK 矩阵中的一列（战术）。
type TacticStat struct {
	Tactic
	Hits       int64           `json:"hits"`
	Techniques []TechniqueStat `json:"techniques"`
}

// AttackMatrix 是按 ATT&CK 战术 / 技术汇总的攻击态势。
type AttackMatrix struct {
	Tactics  []TacticStat `json:"tactics"`
	Observed int          `json:"observed"` // 观测到的技术数
	Total    int          `json:"total"`    // 可检测的技术数
	Unmapped int64        `json:"unmapped"` // 未映射到 ATT&CK 的攻击命中（如自定义规则、威胁情报）
}

// attackMatrixLocked 汇总 ATT&CK 矩阵（调用方持读锁）。所有可检测的技术都会列出，未观测到的命中数为 0，
// 便于同时看出攻击者用到了哪些手法、平台对哪些手法具备检测能力。
// matrixAcc 累计各技术的攻击源数与最高等级。每个攻击源用位掩码记录用到的技术、计数放在数组中，
// 遍历数万个画像时不做 map 分配，缩短读锁占用；安全评估在收集其他指标的同一次遍历中累计。
type matrixAcc struct {
	attackers [64]int
	maxSev    [64]model.Severity
	mask      uint64 // 当前画像用到的技术
}

// category 累计当前画像的一个攻击类型。
func (a *matrixAcc) category(cat string, sev model.Severity) {
	m := catTechMask[cat]
	a.mask |= m
	for b := m; b != 0; b &= b - 1 {
		if i := bits.TrailingZeros64(b); sev > a.maxSev[i] {
			a.maxSev[i] = sev
		}
	}
}

// done 结束当前画像。
func (a *matrixAcc) done() {
	for b := a.mask; b != 0; b &= b - 1 {
		a.attackers[bits.TrailingZeros64(b)]++
	}
	a.mask = 0
}

func (s *Store) attackMatrixLocked() *AttackMatrix {
	var acc matrixAcc
	for _, p := range s.ips {
		if p.Attacks == 0 {
			continue
		}
		for cat := range p.Categories {
			acc.category(cat, p.CatSev[cat])
		}
		acc.done()
	}
	return s.buildMatrixLocked(&acc)
}

// buildMatrixLocked 由累计结果生成 ATT&CK 矩阵（调用方持读锁）。
func (s *Store) buildMatrixLocked(acc *matrixAcc) *AttackMatrix {
	attackers, maxSev := acc.attackers, acc.maxSev
	m := &AttackMatrix{Total: len(techniques)}
	for cat, n := range s.categories {
		if len(categoryTechniques[cat]) == 0 {
			m.Unmapped += n
		}
	}
	for _, tc := range tactics {
		ts := TacticStat{Tactic: tc, Techniques: []TechniqueStat{}}
		for id, t := range techniques {
			if t.Tactic != tc.ID {
				continue
			}
			st := TechniqueStat{Technique: t, Categories: techniqueCategories[id]}
			for _, cat := range st.Categories {
				st.Hits += s.categories[cat]
			}
			if i, ok := techIndex[id]; ok {
				st.Attackers, st.MaxSeverity = attackers[i], maxSev[i]
			}
			if st.Hits > 0 {
				m.Observed++
			}
			ts.Hits += st.Hits
			ts.Techniques = append(ts.Techniques, st)
		}
		sort.Slice(ts.Techniques, func(i, j int) bool {
			a, b := ts.Techniques[i], ts.Techniques[j]
			if a.Hits != b.Hits {
				return a.Hits > b.Hits
			}
			return a.ID < b.ID
		})
		m.Tactics = append(m.Tactics, ts)
	}
	return m
}

// AttackMatrix 返回 ATT&CK 矩阵。
func (s *Store) AttackMatrix() *AttackMatrix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.attackMatrixLocked()
}

// matchTechnique 判断攻击类型集合是否包含映射到该技术的类型。
func matchTechnique(cats map[string]int, id string) bool {
	for _, cat := range techniqueCategories[id] {
		if cats[cat] > 0 {
			return true
		}
	}
	return false
}

// categoryInTechnique 判断攻击类型是否映射到该技术。
func categoryInTechnique(cat, id string) bool {
	for _, t := range categoryTechniques[cat] {
		if t == id {
			return true
		}
	}
	return false
}
