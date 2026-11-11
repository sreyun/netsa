package store

import (
	"fmt"
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"netsa/internal/detect"
	"netsa/internal/exposure"
	"netsa/internal/geo"
	"netsa/internal/model"
)

// Endpoint 是一个真实存在（返回 2xx/3xx）的 Web 资产入口。
type Endpoint struct {
	Host       string              `json:"host"`
	Path       string              `json:"path"`
	Methods    map[string]int      `json:"methods"`
	Hits       int64               `json:"hits"`
	Attacks    int64               `json:"attacks"`
	Attackers  int                 `json:"attackers"`
	Status     map[int]int         `json:"status"`
	Sensitive  string              `json:"sensitive,omitempty"`
	Severity   model.Severity      `json:"severity"`
	Tech       []string            `json:"tech,omitempty"`
	FirstSeen  time.Time           `json:"first_seen"`
	LastSeen   time.Time           `json:"last_seen"`
	atk        map[string]struct{} // 攻击者集合（有上限）
	sens       *sensitiveRule      // 敏感资源分类缓存
	classified bool
	// 正常（非攻击）2xx 响应大小的均值与方差（Welford 算法），用于复核攻击请求的“疑似成功”研判
	NormN    int64   `json:"norm_n,omitempty"`
	NormMean float64 `json:"norm_mean,omitempty"`
	NormVar  float64 `json:"norm_var,omitempty"`
	// Sizes 是站点首页正常响应最常见的几个大小（只记录首页）：同一个首页按是否压缩、是否登录、健康检查与浏览器访问
	// 会有几种固定的大小，均值与方差判断不了时，按出现次数识别扫描器拿到的兜底页面
	Sizes     []sizeCount `json:"sizes,omitempty"`
	SizeTotal int64       `json:"size_total,omitempty"`
	// SensBytes 是敏感入口登记时的响应大小：之后确认该大小是站点的兜底页面时，据此撤销这个并不存在的敏感入口
	SensBytes int64 `json:"sens_bytes,omitempty"`
}

// sizeCount 是一个响应大小的出现次数（Space-Saving 算法：E 为替换进来时继承的计数，N-E 是确定的下限）。
type sizeCount struct {
	B int64 `json:"b"`
	N int64 `json:"n"`
	E int64 `json:"e,omitempty"`
}

const (
	homeSizeSlots = 8  // 记录的首页常见大小个数
	homeSizeMin   = 10 // 确定出现过的次数下限
	homeSizeShare = 50 // 且至少占首页正常响应的 1/50
)

// noteSize 记录一次首页正常响应的大小，返回该大小是否由此成为常见大小。
func (ep *Endpoint) noteSize(b int64) bool {
	was := ep.commonSize(b)
	ep.SizeTotal++
	i := -1
	for k := range ep.Sizes {
		if ep.Sizes[k].B == b {
			i = k
			break
		}
	}
	switch {
	case i >= 0:
		ep.Sizes[i].N++
	case len(ep.Sizes) < homeSizeSlots:
		ep.Sizes = append(ep.Sizes, sizeCount{B: b, N: 1})
	default:
		m := 0
		for k := range ep.Sizes {
			if ep.Sizes[k].N < ep.Sizes[m].N {
				m = k
			}
		}
		ep.Sizes[m] = sizeCount{B: b, N: ep.Sizes[m].N + 1, E: ep.Sizes[m].N}
	}
	return !was && ep.commonSize(b)
}

// commonSize 判断响应大小是不是首页常见的正常大小：确定出现过至少 10 次，且占首页正常响应的 2% 以上。
// 只比较完全相同的字节数：真实存在的敏感文件恰好与首页的某种响应一样大，几乎不可能。
func (ep *Endpoint) commonSize(b int64) bool {
	if ep == nil || b <= 0 {
		return false
	}
	for _, s := range ep.Sizes {
		if s.B == b {
			n := s.N - s.E
			return n >= homeSizeMin && n*homeSizeShare >= ep.SizeTotal
		}
	}
	return false
}

// observeNormal 记录一次正常响应的大小。
func (ep *Endpoint) observeNormal(bytes int64) {
	ep.NormN++
	x := float64(bytes)
	d := x - ep.NormMean
	ep.NormMean += d / float64(ep.NormN)
	ep.NormVar += d * (x - ep.NormMean)
}

// baselineMatches 判断攻击请求的响应是否就是该接口的正常页面：要求接口的正常响应大小稳定
// （至少 5 个样本、变异系数不超过 10%），且本次响应与均值相差不超过 5% 或 2 个标准差。
// 响应大小本身波动较大的接口无法据此判断，保留原研判，宁可多报也不漏掉真实的攻击成功。
func (ep *Endpoint) baselineMatches(bytes int64) bool {
	if ep == nil || ep.NormN < 5 || bytes <= 0 || ep.NormMean <= 0 {
		return false
	}
	std := math.Sqrt(ep.NormVar / float64(ep.NormN-1))
	if std/ep.NormMean > 0.1 {
		return false
	}
	return math.Abs(float64(bytes)-ep.NormMean) <= math.Max(0.05*ep.NormMean, 2*std)
}

// baselineExceeded 判断响应是否明显大于稳定的接口基线：比正常响应多出至少一半、4 个标准差和 512 字节。
// 只看变大：读到文件、拖出数据都会让响应变大，而错误提示页通常更小，不能作为成功证据。
func (ep *Endpoint) baselineExceeded(bytes int64) bool {
	if ep == nil || ep.NormN < 5 || ep.NormMean <= 0 {
		return false
	}
	std := math.Sqrt(ep.NormVar / float64(ep.NormN-1))
	if std/ep.NormMean > 0.1 {
		return false
	}
	return float64(bytes)-ep.NormMean >= math.Max(math.Max(0.5*ep.NormMean, 4*std), 512)
}

// hasHomeBaseline 判断是否已学到站点首页的正常响应：只有学到之后，才能确认一个 200 不是兜底页面。
func (sf *surface) hasHomeBaseline(host string) bool {
	ep := sf.Endpoints[host+" /"]
	return ep != nil && ep.NormN >= 5
}

// Service 是从防火墙日志中观测到的网络服务（目的 IP:端口）。
type Service struct {
	DstIP    string           `json:"dst_ip"`
	Port     int              `json:"port"`
	Proto    string           `json:"proto"`
	Name     string           `json:"name"`
	Risk     model.Severity   `json:"risk"`
	Allowed  int64            `json:"allowed"`
	Denied   int64            `json:"denied"`
	Sources  int              `json:"sources"`
	Exposed  bool             `json:"exposed"` // 存在来自公网的放行流量
	LastSeen time.Time        `json:"last_seen"`
	src      map[string]int32 // 来源 → 放行的连接数（有上限）
}

// Finding 是攻击面风险发现。
type Finding struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Category    string         `json:"category"`
	Severity    model.Severity `json:"severity"`
	Asset       string         `json:"asset"`
	Evidence    string         `json:"evidence"`
	Remediation string         `json:"remediation"`
	IPs         []string       `json:"ips,omitempty"` // 相关地址：攻击来源，或失陷主机外连的地址（最多 8 个）
	Count       int64          `json:"count"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	// Proven 表示攻击成功研判有响应码之外的证据。旧版本只凭 2xx 就记为严重，这些历史记录没有该标记，
	// 按高危显示，不作为严重或高置信失陷的依据
	Proven bool `json:"proven,omitempty"`
	// 攻击成功研判记录站点与响应大小：之后确认该大小是站点的兜底页面时，据此撤销扫描开头几条被误记的“疑似成功”
	Host  string `json:"host,omitempty"`
	Bytes int64  `json:"bytes,omitempty"`
	// Sizes 是这条攻击成功研判中各次命中的不同响应大小：同一接口的研判合并了多次命中（扫描器拿到兜底页面、
	// 真实利用拿到命令输出），只撤销兜底页面大小的那部分，全部是兜底页面时才删除。SizesFull 表示超出上限、没有记全
	Sizes     []int64 `json:"sizes,omitempty"`
	SizesFull bool    `json:"sizes_full,omitempty"`
	// Verified 表示“防火墙管理服务对公网放行”是按应答或同一来源反复连接确认的：快照恢复时清理旧版本误记的
	// 记录不撤销它（每个来源的连接数不持久化，恢复后已无法再按连接次数核对）
	Verified bool `json:"verified,omitempty"`
}

const maxFindingSizes = 16

// noteSize 记录一次成功命中的响应大小。
func (f *Finding) noteSize(b int64) {
	if b <= 0 || slices.Contains(f.Sizes, b) {
		return
	}
	if len(f.Sizes) == 0 && f.Bytes > 0 && f.Bytes != b {
		f.Sizes = append(f.Sizes, f.Bytes) // 旧版本的记录：先补上第一次命中的大小
	}
	if len(f.Sizes) >= maxFindingSizes {
		f.SizesFull = true
		return
	}
	f.Sizes = append(f.Sizes, b)
}

// dropSize 撤销响应为兜底页面大小的命中，返回这条研判是否只剩兜底页面（应删除）。
func (f *Finding) dropSize(b int64) bool {
	sizes := f.Sizes
	if len(sizes) == 0 && f.Bytes > 0 {
		sizes = []int64{f.Bytes} // 旧版本只记录了第一次命中的大小
	}
	i := slices.Index(sizes, b)
	if i < 0 {
		return false
	}
	f.Sizes = slices.Delete(slices.Clone(sizes), i, i+1)
	return len(f.Sizes) == 0 && !f.SizesFull
}

// effectiveSev 返回发现的有效等级：没有证据的攻击成功研判最高高危。
func (f *Finding) effectiveSev() model.Severity {
	if f.Category == "攻击成功研判" && !f.Proven && f.Severity > model.SevHigh {
		return model.SevHigh
	}
	return f.Severity
}

type surface struct {
	Endpoints map[string]*Endpoint `json:"endpoints"`
	Services  map[string]*Service  `json:"services"`
	Findings  map[string]*Finding  `json:"findings"`
	Tech      map[string]int       `json:"tech"`
	Ports     map[int]int64        `json:"ports"` // 被探测的目的端口
	// 漏洞利用类攻击的结果统计，用于评估 WAF 防护有效性
	ExploitBlocked int64 `json:"exploit_blocked"`
	ExploitPassed  int64 `json:"exploit_passed"`
	// Fallback 是各站点已确认的兜底页面大小（首页的常见响应大小、3 个以上不同探测路径返回的同一大小）。随快照保存：
	// 扫描器每晚从 /.env、/.git/HEAD 开始探测，重启后不必再等 3 个路径才认出兜底页面
	Fallback map[string][]int64 `json:"fallback,omitempty"`
	// soft 记录各站点敏感路径 / WebShell 探测返回 200 时的响应大小 → 路径（有上限），用于识别兜底页（不持久化，运行中重新学习）
	soft map[string]map[int64]map[string]struct{}
	// findMin 是发现最后出现时间的下界（不持久化，零值表示未知）：表满时据此跳过不可能腾出位置的扫描
	findMin time.Time
}

const (
	maxSoftHosts    = 2000
	maxSoftSizes    = 64
	softSamePath    = 3  // 不同探测路径返回完全相同大小的次数达到该值即判定为兜底页
	maxFallbackSize = 16 // 每个站点保存的兜底页面大小个数
)

// isFallback 判断响应大小是否是站点已确认的兜底页面大小。
func (sf *surface) isFallback(host string, bytes int64) bool {
	return bytes > 0 && slices.Contains(sf.Fallback[host], bytes)
}

// confirmFallback 记下站点的兜底页面大小，并撤销此前按这个大小误记的“攻击成功”与敏感入口。
func (sf *surface) confirmFallback(host string, bytes int64) {
	if sf.addFallback(host, bytes) {
		sf.dropCatchAll(host, bytes)
	}
}

// addFallback 只记下兜底页面大小，返回是否新增。
func (sf *surface) addFallback(host string, bytes int64) bool {
	if bytes <= 0 || sf.isFallback(host, bytes) {
		return false
	}
	if sf.Fallback == nil {
		sf.Fallback = map[string][]int64{}
	}
	list := sf.Fallback[host]
	if list == nil && len(sf.Fallback) >= maxSoftHosts {
		return false
	}
	if len(list) >= maxFallbackSize {
		list = list[1:] // 最早确认的让位：站点改版后旧的兜底页面大小不再出现
	}
	sf.Fallback[host] = append(slices.Clip(list), bytes)
	return true
}

// nearSize 判断两个响应大小是否只差几个字节（1% 以内，至少容许 2 字节）：同一个首页按请求头的不同（压缩方式、
// 是否带 Cookie）会有几个字节的差别，扫描器拿到的兜底页面与健康检查拿到的首页常常就差这几个字节。
func nearSize(a, b int64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= max(2, min(a, b)/100)
}

// nearCommon 判断响应大小是否与首页的某个常见大小只差几个字节（ep 为首页入口，可以为 nil）。
// 单独一次接近不足以判定兜底页面（真实的小文件也可能恰好接近），只用于有第二份证据的场合。
func (ep *Endpoint) nearCommon(b int64) bool {
	if ep == nil || b <= 0 {
		return false
	}
	for _, s := range ep.Sizes {
		if ep.commonSize(s.B) && nearSize(b, s.B) {
			return true
		}
	}
	return false
}

// legacyFake 判断是不是旧版本登记的假敏感入口：没有记录响应大小、从来没有正常访问、只被攻击请求以 200 / 206 访问过
// （扫描器带 Range 头探测 /backup.sql 时，兜底页面返回 206）。站点确认有兜底页面、入口又没有“敏感资源暴露”时撤销。
func legacyFake(ep *Endpoint) bool {
	if ep.Sensitive == "" || ep.SensBytes != 0 || ep.NormN != 0 || ep.Attacks < ep.Hits || len(ep.Status) == 0 {
		return false
	}
	for st := range ep.Status {
		if st != 200 && st != 206 {
			return false // 302 跳转到登录页等：入口确实存在
		}
	}
	return true
}

// cleanLegacy 在快照恢复时按已学到的首页常见大小与兜底页面大小清理一次旧版本留下的记录（只遍历一遍）：
//   - 没有记录响应大小的“敏感资源暴露”：从证据中取大小，是已确认的兜底页面大小，或与首页常见大小只差几个字节；
//   - 站点确认有兜底页面后，旧版本登记、没有“敏感资源暴露”的假敏感入口（见 legacyFake）。
//
// 返回撤销的入口数。
func (sf *surface) cleanLegacy() int {
	n := 0
	for id, f := range sf.Findings {
		if f.Category != "敏感资源暴露" || f.Bytes != 0 || !strings.HasPrefix(id, "sens:") {
			continue
		}
		key := strings.TrimPrefix(id, "sens:")
		host, _, _ := strings.Cut(key, " ")
		b := evidenceBytes(f.Evidence)
		if ep := sf.Endpoints[key]; b <= 0 || ep != nil && ep.NormN > 0 {
			continue
		}
		if !sf.isFallback(host, b) {
			if !sf.Endpoints[host+" /"].nearCommon(b) {
				continue
			}
			sf.addFallback(host, b)
		}
		sf.dropEndpoint(key)
		n++
	}
	for key, ep := range sf.Endpoints {
		if len(sf.Fallback[ep.Host]) > 0 && legacyFake(ep) && sf.Findings["sens:"+key] == nil {
			sf.dropEndpoint(key)
			n++
		}
	}
	return n
}

// maxFindings 是攻击面发现的数量上限。
const maxFindings = 5000

// homePage 判断非首页路径的响应大小是否与站点首页的正常响应一致（兜底页面的最强证据）。
func (sf *surface) homePage(host, path string, bytes int64) bool {
	if bytes <= 0 || resourceKey(path) == "/" {
		return false
	}
	ep := sf.Endpoints[host+" /"]
	return ep != nil && (ep.baselineMatches(bytes) || ep.commonSize(bytes))
}

// catchAll 判断一个 200 响应是否其实是站点的兜底页面：单页应用把所有路径都返回 index.html、统一错误页返回 200 时，
// 扫描器探测 /.env、/.git/config、webshell 路径都会得到 200，但拿到的只是首页。判断依据（自动学习，无需配置）：
//   - 响应大小与该站点首页的正常响应一致（大小稳定的首页按均值与方差，几种固定大小的首页按常见大小）；
//   - 或已有 3 个以上不同的探测路径返回了完全相同的大小（真实存在的不同敏感文件几乎不可能大小完全一致）；
//   - 或是此前已确认的兜底页面大小（随快照保存）。
func (sf *surface) catchAll(host, path string, bytes int64) bool {
	if bytes <= 0 {
		return false
	}
	if sf.isFallback(host, bytes) {
		return true
	}
	path = resourceKey(path)
	if path != "/" {
		if ep := sf.Endpoints[host+" /"]; ep != nil && (ep.baselineMatches(bytes) || ep.commonSize(bytes)) {
			return true
		}
	}
	if sf.soft == nil {
		sf.soft = map[string]map[int64]map[string]struct{}{}
	}
	sizes := sf.soft[host]
	if sizes == nil {
		if len(sf.soft) >= maxSoftHosts {
			for h := range sf.soft { // 满了让出一个站点（统计不持久化，被淘汰的站点之后重新学习），而不是从此不再学习新站点
				delete(sf.soft, h)
				break
			}
		}
		sizes = map[int64]map[string]struct{}{}
		sf.soft[host] = sizes
	}
	paths := sizes[bytes]
	if paths == nil {
		if len(sizes) >= maxSoftSizes {
			// 满了淘汰路径最少的一个大小：动态页面每次大小不同，只出现过一次的大小占满名额后，
			// 兜底页面再也无法靠“3 个不同路径大小相同”识别
			var victim int64
			least := -1
			for b, p := range sizes {
				if least < 0 || len(p) < least {
					victim, least = b, len(p)
					if least <= 1 {
						break
					}
				}
			}
			delete(sizes, victim)
		}
		paths = map[string]struct{}{}
		sizes[bytes] = paths
	}
	if len(paths) < softSamePath {
		paths[path] = struct{}{}
		// 3 个不同路径大小完全相同；或 2 个、且与首页的常见大小只差几个字节（两份证据）
		if len(paths) == softSamePath || len(paths) == 2 && sf.Endpoints[host+" /"].nearCommon(bytes) {
			sf.confirmFallback(host, bytes)
			return true
		}
	}
	return len(paths) >= softSamePath || sf.isFallback(host, bytes)
}

// retractSuccess 撤销来源地址名下没有证据的“疑似攻击成功”记录（分析员把该来源的事件标为误报或忽略时调用，
// 例如授权的漏洞扫描、本站 pdf 预览被误判），返回撤销的条数。有响应码之外证据的（Proven）保留；
// 一条记录涉及多个来源时只去掉这个来源，全部去掉后才删除。
func (sf *surface) retractSuccess(ip string) int {
	n := 0
	for id, f := range sf.Findings {
		if f.Category != "攻击成功研判" || f.Proven || !slices.Contains(f.IPs, ip) {
			continue
		}
		if f.IPs = slices.DeleteFunc(f.IPs, func(x string) bool { return x == ip }); len(f.IPs) == 0 {
			delete(sf.Findings, id)
			n++
		}
	}
	return n
}

// dropCatchAll 撤销站点上响应为兜底页面大小的“疑似攻击成功”：兜底页面要等到 3 个不同探测路径返回同样大小才能认出，
// 扫描开头的几条探测在此之前已被记为成功（例如 /..\..\windows\win.ini 拿到的其实是首页），确认后不应再列为疑似失陷。
// 有响应码之外证据的（Proven）不撤销。同时撤销按这个大小登记的敏感入口与“敏感资源暴露”：/.env、/backup.sql
// 拿到的同样只是首页，并没有这些文件。
func (sf *surface) dropCatchAll(host string, bytes int64) {
	prefix := "sens:" + host + " "
	home := sf.Endpoints[host+" /"]
	homeSize := home.commonSize(bytes) // 首页的常见大小：旧记录中只差几个字节的同样是兜底页面
	for id, f := range sf.Findings {
		switch {
		case f.Category == "攻击成功研判" && !f.Proven && f.Host == host:
			if f.dropSize(bytes) {
				delete(sf.Findings, id)
			}
		case f.Category == "敏感资源暴露" && strings.HasPrefix(id, prefix) && f.Bytes == bytes:
			sf.dropEndpoint(strings.TrimPrefix(id, "sens:"))
		case f.Category == "敏感资源暴露" && strings.HasPrefix(id, prefix) && f.Bytes == 0:
			// 旧版本的记录没有响应大小，从证据文本“响应 N 字节”中取
			if b := evidenceBytes(f.Evidence); b == bytes || homeSize && b > 0 && nearSize(b, bytes) {
				if ep := sf.Endpoints[strings.TrimPrefix(id, "sens:")]; ep == nil || ep.NormN == 0 {
					sf.addFallback(host, b)
				}
				sf.dropEndpoint(strings.TrimPrefix(id, "sens:"))
			}
		}
	}
	for key, ep := range sf.Endpoints {
		if ep.Host == host && ep.NormN == 0 && (ep.Sensitive != "" && ep.SensBytes == bytes || legacyFake(ep) && sf.Findings["sens:"+key] == nil) {
			sf.dropEndpoint(key)
		}
	}
}

// successKept 判断只凭 2xx 的 Web“攻击成功”在攻击面中是否还有对应的记录（target 为 Event.Target()：站点 + 空格 + URI）。
// 确认响应是兜底页面、来源被标为误报后，攻击成功研判与敏感资源暴露会被撤销，资产攻击链路中对应的“突破”随之
// 只作为需核实的迹象，与疑似失陷资产的口径一致。取不到路径时按仍保留处理。
func (sf *surface) successKept(cat, target string) bool {
	host, uri, ok := strings.Cut(target, " ")
	if !ok || host == "" || uri == "" || len(target) >= 200 { // 记录时截断到 200 字节：路径可能不完整
		return true
	}
	key := siteHost(host) + " " + normPath(uri)
	if cat == "敏感文件探测" {
		return sf.Findings["sens:"+key] != nil
	}
	return sf.Findings["succ:"+cat+":"+key] != nil
}

// purgeSelfRFI 撤销旧版本按“远程文件包含”记录的本站地址（pdf.js 的 viewer.html?file=https://本站:443/…pdf），
// 快照恢复时调用，返回撤销的条数。检测早已不再这样判断，但留存的记录会一直列为疑似失陷资产。
// 只撤销没有证据、只有一个来源的：合并了其他来源的记录里可能有真实的远程文件包含。
func (sf *surface) purgeSelfRFI() int {
	n := 0
	for id, f := range sf.Findings {
		if f.Category != "攻击成功研判" || f.Proven || len(f.IPs) > 1 || !strings.Contains(f.Evidence, "远程文件包含") {
			continue
		}
		h := f.Host
		if h == "" || h == "-" {
			h, _, _ = strings.Cut(f.Asset, "/")
		}
		if sf.hasHomeBaseline(h) && detect.SelfReferenceRFI(f.Evidence, h) { // 只对有正常访问的真实站点清理
			delete(sf.Findings, id)
			n++
		}
	}
	return n
}

// dropEndpoint 删除一个并不存在的入口（兜底页面返回的 200 被登记成的敏感入口）及其“敏感资源暴露”发现。
// 有正常访问的入口不删除：它确实存在，只是这一次的响应恰好是兜底页面的大小。
func (sf *surface) dropEndpoint(key string) {
	if ep := sf.Endpoints[key]; ep != nil {
		if ep.NormN > 0 {
			return
		}
		for _, t := range ep.Tech {
			if sf.Tech[t]--; sf.Tech[t] <= 0 {
				delete(sf.Tech, t)
			}
		}
		delete(sf.Endpoints, key)
	}
	delete(sf.Findings, "sens:"+key)
}

// evidenceBytes 从“…返回 200，响应 N 字节”的证据文本中取出响应大小，取不到时返回 -1。
func evidenceBytes(ev string) int64 {
	_, rest, ok := strings.Cut(ev, "响应 ")
	if !ok {
		return -1
	}
	num, _, ok := strings.Cut(rest, " 字节")
	if !ok {
		return -1
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// resourceKey 把指向同一资源的路径变体归一：百分号编码、重复斜杠、/./ 与 ../、末尾斜杠、;参数（Tomcat / Spring）。
// 攻击者绕过 WAF 时常用 //.env、/./.env、/.env;.css、/%2e%65nv 等变体反复读取同一个真实文件，
// 这些响应的大小当然相同，不能算作「不同探测路径返回相同大小」而误判为兜底页面、把真实泄露改判为未取到内容。
func resourceKey(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		p = strings.ToLower(u)
	}
	if strings.IndexByte(p, ';') >= 0 {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			segs[i], _, _ = strings.Cut(s, ";")
		}
		p = strings.Join(segs, "/")
	}
	return path.Clean("/" + p)
}

func newSurface() *surface {
	return &surface{
		Endpoints: map[string]*Endpoint{}, Services: map[string]*Service{}, Findings: map[string]*Finding{},
		Tech: map[string]int{}, Ports: map[int]int64{},
	}
}

const (
	maxEndpoints = 20000
	maxServices  = 20000
	maxSetSize   = 2000
	evictShare   = 20 // 表满时一次淘汰 1/evictShare：把 O(n) 的选择摊到多次插入上
)

// evictKeys 从 m 中选出最先淘汰的 n 个键（first(a, b) 表示 a 比 b 更该淘汰），用定长堆部分选择，不对全表排序。
func evictKeys[V any](m map[string]V, n int, first func(a, b V) bool) []string {
	type kv struct {
		k string
		v V
	}
	tk := newTopK(n, func(a, b kv) bool {
		if first(a.v, b.v) {
			return true
		}
		if first(b.v, a.v) {
			return false
		}
		return a.k < b.k
	})
	for k, v := range m {
		tk.add(kv{k, v})
	}
	out := make([]string, 0, len(tk.h))
	for _, x := range tk.h {
		out = append(out, x.k)
	}
	return out
}

// evictServices 服务数达到上限时淘汰一批：先淘汰没有公网放行的、风险低的，同级按最后出现时间从早到晚。
func (sf *surface) evictServices() {
	rank := func(sv *Service) int {
		r := 0
		if sv.Exposed {
			r += 2
		}
		if sv.Risk >= model.SevMedium {
			r++
		}
		return r
	}
	for _, k := range evictKeys(sf.Services, maxServices/evictShare, func(a, b *Service) bool {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		return a.LastSeen.Before(b.LastSeen)
	}) {
		delete(sf.Services, k)
	}
}

// evictEndpoints 入口数达到上限时淘汰一批：各站点的首页、敏感入口、有正常访问基线的入口最后淘汰，
// 同级按最后出现时间从早到晚；淘汰时同步扣减技术栈计数。发现另有上限与淘汰，不随入口删除。
func (sf *surface) evictEndpoints() {
	rank := func(ep *Endpoint) int {
		r := 0
		if ep.Path == "/" {
			r += 4
		}
		if ep.Sensitive != "" {
			r += 2
		}
		if ep.NormN > 0 {
			r++
		}
		return r
	}
	for _, k := range evictKeys(sf.Endpoints, maxEndpoints/evictShare, func(a, b *Endpoint) bool {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		return a.LastSeen.Before(b.LastSeen)
	}) {
		for _, t := range sf.Endpoints[k].Tech {
			if sf.Tech[t]--; sf.Tech[t] <= 0 {
				delete(sf.Tech, t)
			}
		}
		delete(sf.Endpoints, k)
	}
}

type sensitiveRule struct {
	re          *regexp.Regexp
	title       string
	sev         model.Severity
	remediation string
}

var sensitiveRules = []sensitiveRule{
	{regexp.MustCompile(`/\.(git|svn|hg|bzr)(/|$)|/\.ds_store$`), "源代码仓库泄露", model.SevCritical,
		"删除 Web 目录中的版本库目录；nginx 中添加 location ~ /\\.(git|svn|hg) { deny all; }"},
	{regexp.MustCompile(`/\.env(\.\w+)?$|/\.aws/credentials$|/id_[rd]sa$|/\.htpasswd$|/\.git-credentials$|/credentials(\.json|\.xml)?$|/\.kube/config$`), "密钥/凭证文件可公开访问", model.SevCritical,
		"立即删除该文件并轮换其中涉及的全部密钥、口令与令牌"},
	{regexp.MustCompile(`/[^/]*(backup|bak|db|database|dump|site|www|wwwroot|web|htdocs|admin|sql|config|old)[^/]*\.(zip|rar|tar|tar\.gz|tgz|7z|xz|lz|zst|sql|sql\.gz|bak|bkp|dump|mdb|sqlite)$|\.(sql|bak|bkp)(\.(gz|xz|lz|zst|bz2|zip|7z))?$|\.(php|asp|aspx|jsp|inc|conf|ini)(\.|_|-)(bak|bkp|backup|old|orig|original|save|copy)$`), "备份/数据库文件可下载", model.SevCritical,
		"删除 Web 目录下的备份文件，备份应存放在不可通过 HTTP 访问的位置"},
	{regexp.MustCompile(`/web-inf/|/meta-inf/|/web\.config$|/wp-config\.php\.\w+$|/application(-\w+)?\.(properties|ya?ml)$|/config\.(php|inc|json|ya?ml|xml)\.(bak|old|swp)$|/\.user\.ini$`), "配置文件泄露", model.SevHigh,
		"禁止访问配置文件，检查是否泄露数据库连接串等敏感信息"},
	{regexp.MustCompile(`/(phpinfo|php_info|info|test)\.php$|/server-(status|info)$|/(nginx|ngx|basic)_status$|/(check|req|upstream)_status$|/status/format/(json|html|prometheus)$|/apisix/prometheus/metrics$|/actuator/(env|heapdump|threaddump|configprops|mappings|beans|trace|httptrace|logfile|jolokia|gateway/routes)|/heapdump$|/_profiler|/debug/pprof|/elmah\.axd$|/trace\.axd$|/druid/(index|sql|websession)\.html$`), "调试/监控接口暴露", model.SevHigh,
		"关闭生产环境调试接口，或在反向代理上限制为内网/白名单访问"},
	// 通用后台入口：路径本身即可判定为管理面（需要 2xx/3xx 才会进入本分类，见 observeWeb）。
	// 与下面按产品名匹配的规则互补——「/admin/login」「/manage」「/dashboard」这类通用路径
	// 同样属于对外暴露的运维入口，此前只能靠特征规则按低危背景扫描处理，会漏掉真正的暴露面。
	{regexp.MustCompile(`^/(admin|manage|management|backend|dashboard|sysadmin|admincp|adminpanel)(/|$)`), "管理后台/运维入口对外暴露", model.SevMedium,
		"管理后台应仅允许 VPN 或白名单访问，并启用强口令与多因素认证"},
	{regexp.MustCompile(`/(phpmyadmin|pma|adminer[^/]*\.php|manager/html|host-manager|jmx-console|web-console|jenkins|kibana|grafana|nacos|xxl-job-admin|solr|swagger-ui(\.html)?|v2/api-docs|v3/api-docs|wp-login\.php|wp-admin|administrator)(/|$)`), "管理后台/运维入口对外暴露", model.SevMedium,
		"管理后台应仅允许 VPN 或白名单访问，并启用强口令与多因素认证"},
	// console 只认第一、二级目录（/console、/nacos/console）：业务接口里常有这个词（/app/api/console/push-messages），不是管理后台
	{regexp.MustCompile(`^(/[^/]+)?/console(/|$)`), "管理后台/运维入口对外暴露", model.SevMedium,
		"管理后台应仅允许 VPN 或白名单访问，并启用强口令与多因素认证"},
	{regexp.MustCompile(`/(logs?|storage/logs)/[^/]*\.(log|txt)$|/[^/]*(error|access|debug|laravel)[^/]*\.log$|/nohup\.out$`), "日志文件可公开访问", model.SevMedium,
		"禁止通过 Web 访问日志目录，日志中可能包含会话、口令或内部路径"},
}

// reclassify 按当前的敏感资源规则重新核对已登记的敏感入口（快照恢复时调用，返回撤销的条数）：规则收紧后，
// 旧版本误判的入口（如业务接口 /app/api/console/push-messages 被当成管理后台）不再列为敏感资源，对应的发现一并撤销。
func (sf *surface) reclassify() int {
	n := 0
	for key, ep := range sf.Endpoints {
		if ep.Sensitive == "" || classifySensitive(ep.Path) != nil {
			continue
		}
		ep.Sensitive, ep.Severity, ep.sens, ep.classified = "", model.SevInfo, nil, true
		delete(sf.Findings, "sens:"+key)
		n++
	}
	return n
}

// purgeFakeHosts 删除旧版本按虚构的 Host 头登记的入口与对应的发现（快照恢复时调用，返回删除的入口数）：
// 扫描器把 OAST 子域名、随机串域名写进 Host 头，攻击面的“识别到的站点”里因此列出几十个并不存在的站点。
func (sf *surface) purgeFakeHosts() int {
	n := 0
	for key, ep := range sf.Endpoints {
		if ep.Host == "" || ep.Host == "-" || !detect.FakeSiteHost(ep.Host) {
			continue
		}
		delete(sf.Endpoints, key)
		delete(sf.Findings, "sens:"+key)
		n++
	}
	return n
}

// stripNUL 清理旧版本写入发现的 NUL（快照恢复时调用）：华为防火墙直接发送的 syslog 末尾带 NUL，旧版本把它连同句号
// 带进了策略名，证据里显示为「default.\x00」，界面上是一个乱码字符。
func (sf *surface) stripNUL() {
	clean := func(s string) string {
		if !strings.Contains(s, "\x00") {
			return s
		}
		return strings.ReplaceAll(strings.ReplaceAll(s, ".\x00", ""), "\x00", "")
	}
	for _, f := range sf.Findings {
		f.Title, f.Evidence = clean(f.Title), clean(f.Evidence)
	}
}

func classifySensitive(path string) *sensitiveRule {
	p := strings.ToLower(path)
	for i := range sensitiveRules {
		if sensitiveRules[i].re.MatchString(p) {
			return &sensitiveRules[i]
		}
	}
	return nil
}

var techRules = []struct {
	re   *regexp.Regexp
	tech string
}{
	{regexp.MustCompile(`\.php\d?$`), "PHP"},
	{regexp.MustCompile(`\.(jsp|jspx|do)$`), "Java"},
	{regexp.MustCompile(`\.action$`), "Struts2"},
	{regexp.MustCompile(`\.(aspx|ashx|asmx|axd)$`), "ASP.NET"},
	{regexp.MustCompile(`\.asp$`), "ASP"},
	{regexp.MustCompile(`\.(cgi|pl)$`), "CGI"},
	{regexp.MustCompile(`^/wp-(content|includes|admin|login)`), "WordPress"},
	{regexp.MustCompile(`^/actuator`), "Spring Boot"},
	{regexp.MustCompile(`^/druid/`), "Druid"},
	{regexp.MustCompile(`^/nacos`), "Nacos"},
	{regexp.MustCompile(`^/graphql`), "GraphQL"},
	{regexp.MustCompile(`^/(swagger|v2/api-docs|v3/api-docs)`), "Swagger"},
	{regexp.MustCompile(`^/phpmyadmin`), "phpMyAdmin"},
	{regexp.MustCompile(`^/jenkins`), "Jenkins"},
	{regexp.MustCompile(`^/seeyon`), "致远OA"},
	{regexp.MustCompile(`^/(weaver|wui|ecology)`), "泛微OA"},
	{regexp.MustCompile(`^/(ispirit|general)/`), "通达OA"},
	{regexp.MustCompile(`^/api/`), "REST API"},
}

// normPath 去掉查询串并将 ID 类路径段（纯数字、UUID、16 位以上十六进制）泛化，避免资产数量爆炸。
// 控制字符与非法字节转义（与攻击目标 Event.Target 的写法一致，入口、发现的键在记录与核对时相同，页面上也不出现乱码）。
// 单次扫描实现，位于单线程聚合路径上，避免正则开销。
func normPath(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	uri = model.Printable(uri, 0)
	if uri == "" {
		return "/"
	}
	// 每条 Web 日志都要归一一次（入口登记、成功复核）：逐段扫描，只有需要替换的段才分配新字符串
	lower := strings.ToLower(uri)
	var b strings.Builder
	last := 0 // lower[last:] 尚未写入 b
	for start := 0; start <= len(lower); {
		end := strings.IndexByte(lower[start:], '/')
		if end < 0 {
			end = len(lower)
		} else {
			end += start
		}
		if rep := segPlaceholder(lower[start:end]); rep != "" {
			if b.Len() == 0 {
				b.Grow(len(lower))
			}
			b.WriteString(lower[last:start])
			b.WriteString(rep)
			last = end
		}
		start = end + 1
	}
	p := lower
	if last > 0 {
		b.WriteString(lower[last:])
		p = b.String()
	}
	return truncate(p, 200)
}

// segPlaceholder 返回路径段的占位符（数字 ID、UUID、哈希），不需要替换时返回空。
func segPlaceholder(s string) string {
	switch {
	case s == "":
	case isDigits(s):
		return "{id}"
	case isUUID(s):
		return "{uuid}"
	case len(s) >= 16 && isHex(s):
		return "{hash}"
	}
	return ""
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	return isHex(s[:8]) && isHex(s[9:13]) && isHex(s[14:18]) && isHex(s[19:23]) && isHex(s[24:])
}

// 端口 → 服务名与对公网开放时的风险等级。
var services = map[int]struct {
	name string
	risk model.Severity
}{
	21: {"FTP", model.SevHigh}, 22: {"SSH", model.SevMedium}, 23: {"Telnet", model.SevCritical}, 25: {"SMTP", model.SevLow},
	53: {"DNS", model.SevLow}, 80: {"HTTP", model.SevInfo}, 110: {"POP3", model.SevLow}, 111: {"RPCbind", model.SevHigh},
	135: {"MSRPC", model.SevHigh}, 137: {"NetBIOS", model.SevHigh}, 139: {"NetBIOS", model.SevHigh}, 143: {"IMAP", model.SevLow},
	161: {"SNMP", model.SevHigh}, 389: {"LDAP", model.SevHigh}, 443: {"HTTPS", model.SevInfo}, 445: {"SMB", model.SevCritical},
	465: {"SMTPS", model.SevLow}, 587: {"SMTP", model.SevLow}, 873: {"Rsync", model.SevHigh}, 993: {"IMAPS", model.SevLow},
	995: {"POP3S", model.SevLow}, 1080: {"SOCKS", model.SevHigh}, 1099: {"Java RMI", model.SevHigh}, 1433: {"MSSQL", model.SevHigh},
	1521: {"Oracle", model.SevHigh}, 2049: {"NFS", model.SevHigh}, 2375: {"Docker API", model.SevCritical}, 2376: {"Docker TLS", model.SevHigh},
	2379: {"etcd", model.SevCritical}, 3306: {"MySQL", model.SevHigh}, 3389: {"RDP", model.SevHigh}, 4848: {"GlassFish", model.SevHigh},
	5432: {"PostgreSQL", model.SevHigh}, 5601: {"Kibana", model.SevHigh}, 5672: {"RabbitMQ", model.SevMedium}, 5900: {"VNC", model.SevHigh},
	5984: {"CouchDB", model.SevHigh}, 5985: {"WinRM", model.SevHigh}, 6379: {"Redis", model.SevCritical}, 6443: {"K8s API", model.SevHigh},
	7001: {"WebLogic", model.SevHigh}, 8080: {"HTTP-Alt", model.SevLow}, 8443: {"HTTPS-Alt", model.SevLow}, 8848: {"Nacos", model.SevHigh},
	8888: {"HTTP-Alt", model.SevLow}, 9000: {"PHP-FPM/Portainer", model.SevMedium}, 9090: {"Prometheus", model.SevMedium},
	9200: {"Elasticsearch", model.SevCritical}, 9300: {"Elasticsearch", model.SevHigh}, 10250: {"Kubelet", model.SevCritical},
	11211: {"Memcached", model.SevCritical}, 15672: {"RabbitMQ Web", model.SevMedium}, 27017: {"MongoDB", model.SevCritical},
	50070: {"Hadoop", model.SevHigh},
}

func serviceInfo(port int) (string, model.Severity) {
	if s, ok := services[port]; ok {
		return s.name, s.risk
	}
	return "port-" + strconv.Itoa(port), model.SevInfo
}

// observeWeb 更新 Web 资产与风险发现（调用方持锁）。
// siteHost 返回请求所属站点的键：空 Host 与虚构的 Host 头（OAST、随机串域名、云元数据地址）都记在 "-" 下。
// 攻击面登记、基线复核、兜底页面判断必须用同一个键，否则把 Host 换成 OAST 子域名的请求绕过兜底页面复核。
func siteHost(h string) string {
	if h == "" || detect.FakeSiteHost(h) {
		return "-"
	}
	return h
}

func (sf *surface) observeWeb(ev *model.Event, hits []model.Hit, attacked bool) {
	host := siteHost(ev.Host)
	path := normPath(ev.URI)
	exists := ev.Status >= 200 && ev.Status < 400
	key := host + " " + path
	ep := sf.Endpoints[key]
	// 敏感资源分类只在可能产生影响时计算（新登记入口、或 2xx/3xx 响应可能暴露敏感资源），
	// 并缓存在入口上；扫描器大量的 404 请求不再逐条执行分类正则。
	var sens *sensitiveRule
	if exists {
		if ep != nil && ep.classified {
			sens = ep.sens
		} else {
			sens = classifySensitive(path)
			if ep != nil {
				ep.sens, ep.classified = sens, true
			}
		}
	}
	// 敏感路径返回的 200 其实是兜底页面（单页应用、统一错误页）：资源并不存在，不登记、不报暴露。扫描器带 Range 头
	// 请求时兜底页面返回 206，同样处理。已登记、但从来没有正常访问的敏感入口再次被探测时重新核对：旧版本把
	// 兜底页面登记成了 /.env、/backup.sql 这类敏感入口
	ok2xx := ev.Status == 200 || ev.Status == 206
	fake := sens != nil && ok2xx && (ep == nil || ep.Sensitive != "" && ep.NormN == 0) && sf.catchAll(host, path, ev.Bytes)
	if fake {
		sens = nil
		if ep != nil {
			sf.dropEndpoint(key)
			ep = nil
		}
	}
	// 攻击请求只在命中敏感资源时才登记为新入口：对所有路径都返回 200 的站点（SPA 兜底路由），
	// 扫描器的随机路径不会污染资产清单；已有入口上的攻击仍会被统计。
	if ep == nil && exists && !fake && (!attacked || sens != nil) && len(sf.Endpoints) >= maxEndpoints {
		sf.evictEndpoints() // 满了淘汰一批，新站点的首页仍能登记基线
	}
	if ep == nil && exists && !fake && (!attacked || sens != nil) && len(sf.Endpoints) < maxEndpoints {
		ep = &Endpoint{Host: host, Path: path, Methods: map[string]int{}, Status: map[int]int{}, FirstSeen: ev.Time,
			atk: map[string]struct{}{}, sens: sens, classified: true}
		for _, t := range techRules {
			if t.re.MatchString(path) {
				ep.Tech = append(ep.Tech, t.tech)
				sf.Tech[t.tech]++
			}
		}
		if sens != nil {
			ep.Sensitive, ep.Severity = sens.title, sens.sev
			if ok2xx {
				ep.SensBytes = ev.Bytes
			}
		}
		sf.Endpoints[key] = ep
	}
	if ep != nil {
		ep.Hits++
		if ev.Method != "" && len(ep.Methods) < 20 {
			ep.Methods[ev.Method]++
		}
		ep.Status[ev.Status]++
		if ev.Time.After(ep.LastSeen) {
			ep.LastSeen = ev.Time
		}
		if !attacked && ev.Status >= 200 && ev.Status < 300 && ev.Bytes > 0 {
			ep.observeNormal(ev.Bytes)
			// 首页的常见响应大小即兜底页面的大小：确认后立即撤销此前按这个大小误记的成功与敏感入口
			if path == "/" && ev.Status == 200 && ep.noteSize(ev.Bytes) {
				sf.confirmFallback(host, ev.Bytes)
			}
		}
		if attacked {
			ep.Attacks++
			if len(ep.atk) < maxSetSize {
				ep.atk[ev.SrcIP] = struct{}{}
				ep.Attackers = max(ep.Attackers, len(ep.atk))
			}
		}
	}

	asset := host + path
	if host == "-" {
		asset = path
	}
	// 敏感资源被成功访问（兜底页面返回的 200 / 206 已在上面排除；已登记的入口再次核对首页基线）。
	// 检测规则判为“敏感文件探测 / 成功”（已经过兜底页面复核）的命中，即使路径不在攻击面的分类规则内也记暴露：
	// 否则真实读到的 /appsettings.json、/.ssh/id_ed25519 既不列入暴露面，链路研判还会把它说成“兜底页面”
	if ok2xx && ev.Bytes > 0 {
		title, sev, rem := "", model.SevInfo, ""
		if sens != nil {
			title, sev, rem = sens.title, sens.sev, sens.remediation
		} else if h := sensitiveSuccess(hits); h != nil {
			title, sev, rem = "敏感文件可公开访问", h.Severity, "删除或移出 Web 目录中的配置、密钥、备份与源码文件，并在 Web 服务器上禁止访问这类文件"
		}
		if title != "" {
			var fallback bool
			if attacked || ep == nil || ep.NormN == 0 {
				fallback = sf.catchAll(host, path, ev.Bytes)
			} else {
				// 有正常访问的已登记入口（管理后台等）只做只读核对：动态页面每次大小不同，写入同大小统计会占满名额
				fallback = sf.isFallback(host, ev.Bytes) || sf.homePage(host, path, ev.Bytes)
			}
			if !fallback {
				sf.finding("sens:"+key, title, "敏感资源暴露", sev, asset,
					ev.SrcIP+" 访问返回 "+strconv.Itoa(ev.Status)+"，响应 "+strconv.FormatInt(ev.Bytes, 10)+" 字节", rem, ev.SrcIP, ev.Time)
				if f := sf.Findings["sens:"+key]; f != nil && f.Bytes == 0 {
					f.Host, f.Bytes = host, ev.Bytes
				}
			}
		}
	}
	// WAF 防护效果只统计外部来源：内网来源（内部漏洞扫描器、运维）不经过边界的 WAF，计入会把拦截率拉到接近 0
	outside := !geo.IsPrivate(ev.SrcIP)
	for _, h := range hits {
		if h.TagOnly || h.Phase == model.PhaseRecon {
			continue
		}
		switch {
		case !outside:
		case h.Result == model.ResultBlocked:
			sf.ExploitBlocked++
		case h.Result == model.ResultSuccess || h.Result == model.ResultPassed || h.Result == model.ResultError:
			sf.ExploitPassed++
		}
		if h.Result == model.ResultSuccess && h.Severity >= model.SevHigh {
			rem := successRemediation[h.Category]
			if rem == "" {
				rem = "核查该接口是否存在对应漏洞，排查服务器是否已被入侵，并在 WAF 中加入拦截规则"
			}
			id := "succ:" + h.Category + ":" + key
			sf.finding(id, "疑似攻击成功: "+h.Category, "攻击成功研判", h.Severity, asset,
				ev.SrcIP+" "+ev.Method+" 返回 "+strconv.Itoa(ev.Status)+"，"+h.Name+": "+h.Evidence, rem, ev.SrcIP, ev.Time)
			if f := sf.Findings[id]; f != nil {
				if h.Proven {
					f.Proven = true
				}
				if f.Bytes == 0 {
					f.Host, f.Bytes = host, ev.Bytes
				}
				f.noteSize(ev.Bytes)
			}
		}
	}
}

// sensitiveSuccess 返回判为成功的敏感文件探测命中（verifySuccess 已按兜底页面复核过），没有时返回 nil。
func sensitiveSuccess(hits []model.Hit) *model.Hit {
	for i := range hits {
		if h := &hits[i]; h.Category == "敏感文件探测" && h.Result == model.ResultSuccess && !h.TagOnly {
			return h
		}
	}
	return nil
}

// observeFw 更新网络服务暴露面（调用方持锁）。published 表示目标端口确实做过对外映射：
// 未映射的端口即使被默认策略放行，也不存在可访问的服务，不能据此判定「对公网开放」。
func (sf *surface) observeFw(ev *model.Event, published bool) {
	if ev.DstPort <= 0 || ev.DstPort > 65535 { // 越界的端口（解析错位、伪造的日志）不能让端口表无上限增长
		return
	}
	// 内网主机访问公网（出站流量）不是本方对外提供的服务，不计入暴露面
	if ev.DstIP != "" && geo.IsPrivate(ev.SrcIP) && !geo.IsPrivate(ev.DstIP) {
		return
	}
	sf.Ports[ev.DstPort]++
	key := ev.DstIP + ":" + strconv.Itoa(ev.DstPort) + "/" + ev.Proto
	sv := sf.Services[key]
	if sv == nil {
		// 只有被放行、且端口确实对外发布（DNAT 映射）的连接才能证明服务真实存在；
		// 被拒绝的探测、以及未映射端口上的放行日志只计入“被探测端口”统计。
		if ev.Action != model.ActionAllow || !published {
			return
		}
		if len(sf.Services) >= maxServices {
			sf.evictServices() // 满了淘汰一批最没有价值的，而不是从此不再登记：否则新的高危服务暴露永远报不出来
		}
		name, risk := serviceInfo(ev.DstPort)
		sv = &Service{DstIP: ev.DstIP, Port: ev.DstPort, Proto: ev.Proto, Name: name, Risk: risk, src: map[string]int32{}}
		sf.Services[key] = sv
	}
	if _, ok := sv.src[ev.SrcIP]; ok || len(sv.src) < maxSetSize {
		if ev.Action == model.ActionAllow && sv.src[ev.SrcIP] < 1<<30 {
			sv.src[ev.SrcIP]++
		} else if !ok {
			sv.src[ev.SrcIP] = 0
		}
		sv.Sources = max(sv.Sources, len(sv.src))
	}
	switch ev.Action {
	case model.ActionAllow:
		sv.Allowed++
		if published && !geo.IsPrivate(ev.SrcIP) {
			sv.Exposed = true
			if ev.Reach == model.ReachDevice {
				sf.deviceExposure(ev, sv, key)
			} else if sv.Risk >= model.SevMedium {
				sf.finding("svc:"+key, "高危服务对公网开放: "+sv.Name, "服务暴露", sv.Risk, key,
					"防火墙放行了来自公网 "+ev.SrcIP+" 的连接", "通过安全组/防火墙将该端口限制为内网或白名单访问，必要时修改默认端口并启用认证", ev.SrcIP, ev.Time)
			}
		}
	case model.ActionDeny:
		sv.Denied++
	}
	if ev.Time.After(sv.LastSeen) {
		sv.LastSeen = ev.Time
	}
}

// purgeUnusedDevice 撤销旧版本只凭策略匹配日志记下的“防火墙管理服务对公网放行”（快照恢复时调用，返回撤销的条数）：
// 每个来源的连接数没有保存，按平均每个来源不到 deviceUseMin 次判断为扫描器的探测。新的访问照常按 deviceExposure 记录。
// 当前版本按应答 / 反复连接确认的记录带 Verified 标记，不撤销：否则每次重启都删掉合法的发现。
func (sf *surface) purgeUnusedDevice() int {
	n := 0
	for id, f := range sf.Findings {
		if !strings.HasPrefix(id, "dev:") || f.Verified {
			continue
		}
		sv := sf.Services[strings.TrimPrefix(id, "dev:")]
		if sv == nil || sv.Allowed < int64(deviceUseMin*max(1, sv.Sources)) {
			delete(sf.Findings, id)
			n++
		}
	}
	return n
}

// deviceUseMin 是同一来源对防火墙自身同一端口放行的连接数：达到它说明端口上确实有服务在应答。
// 互联网扫描器对一个端口只连一两次；端口没有服务时，暴力破解工具也不会一直重连。
const deviceUseMin = 10

// deviceExposure 记录公网到防火墙自身（local 安全域）的放行访问。
//
// 华为 / H3C 的策略匹配日志（POLICYPERMIT）只说明策略放行，没有会话与应答：默认策略（或范围过大的策略）放行了
// untrust → local 时，扫描器探测的每个端口都会记一条“放行”，把它们都当成“管理服务对公网放行”会在每个公网地址上
// 报出 NETCONF、HTTP 管理等一大串并不存在的服务。所以：
//   - 有证据表明服务在应答（会话有应答、或同一来源反复连接）时，按端口记“防火墙管理服务对公网放行”；
//   - 否则按策略合并记一条“防火墙策略放行公网访问设备自身”：这才是需要处置的配置问题。
func (sf *surface) deviceExposure(ev *model.Event, sv *Service, key string) {
	name, sev := exposure.DeviceRisk(ev.DstPort, ev.Proto)
	if sev <= model.SevInfo {
		return // VPN / 路由协议本就面向外部，不作为风险
	}
	by := ""
	if ev.Policy != "" {
		by = "按策略「" + ev.Policy + "」"
	}
	if ev.Reply == model.ReplyYes || sv.src[ev.SrcIP] >= deviceUseMin {
		why := "目标有应答"
		if ev.Reply != model.ReplyYes {
			why = fmt.Sprintf("该来源已连接 %d 次", sv.src[ev.SrcIP])
		}
		sf.finding("dev:"+key, "防火墙管理服务对公网放行: "+name, "服务暴露", sev, key,
			"防火墙"+by+"放行了来自公网 "+ev.SrcIP+" 到设备自身（local 安全域）的连接（"+why+"）",
			"在防火墙上把管理服务限制为内网或运维堡垒机地址访问（华为：local 安全域策略与接口 service-manage），"+
				"关闭 Telnet / HTTP / SNMP v1、v2c 等明文管理协议，改用 SSH / HTTPS / SNMPv3", ev.SrcIP, ev.Time)
		if f := sf.Findings["dev:"+key]; f != nil {
			f.Verified = true
		}
		return
	}
	policy := ev.Policy
	if policy == "" {
		policy = "未记录策略名"
	}
	psev := model.SevMedium
	if strings.EqualFold(ev.Policy, "default") {
		psev = model.SevHigh // 默认策略放行：所有端口都对公网放开了
	}
	sf.finding("devpol:"+ev.Source+"|"+policy, "防火墙策略放行公网访问设备自身: "+policy, "服务暴露", psev, ev.Source,
		"防火墙"+by+"放行了来自公网 "+ev.SrcIP+" 到设备自身 "+ev.DstIP+":"+strconv.Itoa(ev.DstPort)+"（"+name+"）的连接；"+
			"日志只记录了策略匹配，看不出端口上是否有服务，但该策略对公网放开了设备自身",
		"把默认安全策略改为拒绝，到 local 安全域的策略只放行确需的协议与来源（运维地址、VPN 对端）；"+
			"检查范围为 any 的策略是否同时匹配了公网到设备自身的流量", ev.SrcIP, ev.Time)
}

// findingRank 是发现的保留优先级：失陷迹象与有证据的成功最后淘汰，其次是服务与敏感资源暴露，没有证据的疑似成功最先淘汰。
func findingRank(f *Finding) int {
	switch {
	case f.Category == "失陷迹象" || f.Proven:
		return 3
	case f.Category == "服务暴露" || f.Category == "敏感资源暴露":
		return 2
	case f.Category != "攻击成功研判" && f.Severity >= model.SevHigh:
		return 1
	}
	return 0
}

// evictFindings 发现数达到上限时一次淘汰一批（约 1/evictShare），返回是否腾出了位置：直接丢弃新发现的话，
// 数量到上限后新的真实风险再也记不进来。按保留优先级从低到高、同级按最后出现时间从早到晚；只淘汰最后出现早于 t 的
// （回放更早的历史日志不挤掉较新的发现）。findMin 是全部记录最后出现时间的下界：t 不晚于它时没有可淘汰的，不必扫描。
func (sf *surface) evictFindings(t time.Time) bool {
	if !sf.findMin.IsZero() && !t.After(sf.findMin) {
		return false
	}
	type cand struct {
		id   string
		rank int
		last time.Time
	}
	tk := newTopK(maxFindings/evictShare, func(a, b cand) bool {
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if !a.last.Equal(b.last) {
			return a.last.Before(b.last)
		}
		return a.id < b.id
	})
	var lo time.Time
	for id, f := range sf.Findings {
		if lo.IsZero() || f.LastSeen.Before(lo) {
			lo = f.LastSeen
		}
		if f.LastSeen.Before(t) {
			tk.add(cand{id, findingRank(f), f.LastSeen})
		}
	}
	sf.findMin = lo // 删除只会抬高最小值，之后新增的更早记录在 finding 中下调它
	for _, c := range tk.h {
		delete(sf.Findings, c.id)
	}
	return len(tk.h) > 0
}

func (sf *surface) finding(id, title, cat string, sev model.Severity, asset, evidence, remediation, ip string, t time.Time) {
	evidence = printable(evidence) // 证据来自日志内容
	f := sf.Findings[id]
	if f == nil {
		if len(sf.Findings) >= maxFindings && !sf.evictFindings(t) {
			return
		}
		if !sf.findMin.IsZero() && t.Before(sf.findMin) {
			sf.findMin = t
		}
		f = &Finding{ID: id, Title: title, Category: cat, Severity: sev, Asset: asset, Evidence: evidence, Remediation: remediation, FirstSeen: t}
		sf.Findings[id] = f
	}
	f.Count++
	if sev > f.Severity { // 同一发现后续出现更严重的情况（如外连被放行）时升级
		f.Severity, f.Evidence = sev, evidence
	}
	if ip != "" && len(f.IPs) < 8 && !slices.Contains(f.IPs, ip) {
		f.IPs = append(f.IPs, ip)
	}
	if t.After(f.LastSeen) {
		f.LastSeen = t
	}
}

var successRemediation = map[string]string{
	"暴力破解":       "立即核查该账号的登录记录，重置口令并启用登录失败锁定与多因素认证",
	"WebShell后门": "立即排查并删除可疑脚本文件，检查上传功能与服务器是否已被控制",
	"SQL注入":      "使用参数化查询修复注入点，核查数据库是否有异常访问与数据外泄",
	"命令/代码执行":    "立即修复漏洞并排查服务器是否存在异常进程、计划任务与外连",
}
