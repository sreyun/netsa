package detect

import (
	"fmt"
	"math/bits"
	"strings"

	"netsa/internal/model"
)

// 本文件补充两类扫描行为的识别：
//
//   - 兜底页面上的目录扫描：单页应用、统一兜底页把不存在的路径都返回首页（200），目录扫描拿不到 404，
//     按 404 统计的 bhv-dirscan 发现不了。学习站点首页（/）的响应大小，其他路径返回同样大小的 200 按“未找到”计。
//   - 自动化漏洞扫描（bhv-vulnscan）：nuclei、xray、AWVS 这类工具换成浏览器 UA 后，单条请求只能各自命中规则，
//     看不出是一次扫描。同一来源在 web_window 内带攻击载荷的请求达到 10 次、涉及 3 类以上攻击时，按整段扫描识别，
//     并从 UA、OAST 回连域名、工具留下的文件名中认出工具。

// homeSize 记录站点首页 200 响应的大小（最多 4 种：压缩与未压缩的响应大小不同）。
type homeSize struct {
	sizes map[int64]int
	n     int
}

const maxHomeSizes = 4

// softMiss 判断一个 200 响应是否其实是兜底页面：与站点首页的常见响应大小相同、且不是首页本身。
// 首页的请求用于学习：至少 5 次、占首页响应 20% 以上的大小才算首页的大小。
func (b *Behavior) softMiss(ev *model.Event, host, path string) bool {
	if ev.Status != 200 || ev.Bytes <= 0 {
		return false
	}
	h := b.homes[host]
	if path == "/" {
		if ev.Method != "GET" {
			return false
		}
		if h == nil {
			if len(b.homes) >= maxSurgeSites {
				return false
			}
			h = &homeSize{sizes: map[int64]int{}}
			b.homes[host] = h
		}
		if _, ok := h.sizes[ev.Bytes]; !ok && len(h.sizes) >= maxHomeSizes {
			// 首页改版后大小变化：淘汰出现最少的大小
			var least int64
			for s, c := range h.sizes {
				if _, ok := h.sizes[least]; !ok || c < h.sizes[least] {
					least = s
				}
			}
			h.n -= h.sizes[least]
			delete(h.sizes, least)
		}
		h.sizes[ev.Bytes]++
		if h.n++; h.n > 1<<20 { // 长期运行时让旧的统计逐渐淡出
			h.n = 0
			for s, c := range h.sizes {
				h.sizes[s] = c / 2
				h.n += c / 2
			}
		}
		return false
	}
	if h == nil || h.n < 5 {
		return false
	}
	c := h.sizes[ev.Bytes]
	return c >= 5 && c*5 >= h.n
}

// scanSignals 是一个请求（或一个窗口）命中的攻击特征，用于识别自动化漏洞扫描。
type scanSignals struct {
	attacked bool   // 命中了中危以上的规则
	cats     uint32 // 命中的攻击分类（位图）
	attacks  int    // 带攻击载荷的请求数
	tool     string // 从扫描器特征识别出的工具
}

// 计入漏洞扫描判断的攻击分类。
var scanCats = []string{CatSQLi, CatXSS, CatTraversal, CatCmdExec, CatExpr, CatSSRF, CatXXE, CatDeser, CatWebShell, CatCVE,
	CatSensitive, CatVulnEndpoint}

var scanCatBit = func() map[string]uint32 {
	m := make(map[string]uint32, len(scanCats))
	for i, c := range scanCats {
		m[c] = 1 << i
	}
	return m
}()

func (s *scanSignals) add(h *model.Hit) {
	if h.TagOnly {
		return
	}
	if bit, ok := scanCatBit[h.Category]; ok {
		s.cats |= bit
		s.attacks = 1
	}
	if s.tool == "" && (h.RuleID == "ua-scanner" || h.RuleID == "scan-artifact") {
		s.tool = toolOf(h.Evidence)
	}
}

func (s *scanSignals) merge(o scanSignals) {
	s.cats |= o.cats
	s.attacks += o.attacks
	if s.tool == "" {
		s.tool = o.tool
	}
}

// scanning 判断窗口内的攻击请求是否构成自动化漏洞扫描：带载荷的请求达到 10 次，且涉及 3 类以上攻击。
func (s *scanSignals) scanning() bool {
	return s.attacks >= 10 && bits.OnesCount32(s.cats) >= 3
}

func (s *scanSignals) hit(win string, misses int) model.Hit {
	var names []string
	for i, c := range scanCats {
		if s.cats&(1<<i) != 0 {
			names = append(names, c)
		}
	}
	name := "自动化漏洞扫描"
	ev := fmt.Sprintf("%s内 %d 次请求带有攻击载荷，涉及 %s 共 %d 类", win, s.attacks, strings.Join(names, "、"), len(names))
	if misses > 0 {
		ev += fmt.Sprintf("，%d 次请求的路径不存在（404 或兜底页面）", misses)
	}
	if s.tool != "" {
		name += "（" + s.tool + "）"
		ev += "；工具特征：" + s.tool
	}
	return model.Hit{RuleID: "bhv-vulnscan", Name: name, Category: CatScanner, Severity: model.SevMedium, Phase: model.PhaseRecon,
		Result: model.ResultUnknown, Evidence: ev}
}

// toolOf 从扫描器特征（UA、OAST 回连域名、工具留下的文件名）中认出工具。
func toolOf(text string) string {
	t := strings.ToLower(text)
	for _, k := range []struct{ key, tool string }{
		{"nuclei", "nuclei"}, {"oast.", "nuclei"}, {"interact.sh", "nuclei"}, {"interactsh", "nuclei"},
		{"acunetix", "AWVS"}, {"wvs", "AWVS"}, {"bxss.me", "AWVS"},
		{"burpcollaborator", "Burp Suite"}, {"oastify", "Burp Suite"}, {"burp", "Burp Suite"},
		{"nessus", "Nessus"}, {"openvas", "OpenVAS"}, {"appscan", "AppScan"}, {"netsparker", "Netsparker"},
		{"xray", "xray"}, {"sqlmap", "sqlmap"}, {"nikto", "Nikto"}, {"goby", "Goby"}, {"wpscan", "WPScan"},
		{"dirsearch", "dirsearch"}, {"gobuster", "gobuster"}, {"feroxbuster", "feroxbuster"}, {"ffuf", "ffuf"},
		{"dirbuster", "DirBuster"}, {"wfuzz", "wfuzz"}, {"dnslog", "DNSLog 平台"}, {"ceye.io", "DNSLog 平台"},
	} {
		if strings.Contains(t, k.key) {
			return k.tool
		}
	}
	return ""
}
