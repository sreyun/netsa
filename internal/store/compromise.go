package store

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
	"netsa/internal/risk"
)

// c2Hit 检测内网主机（或本机出站流量）连接威胁情报地址的行为。放行的连接为严重，被拦截的连接为高危
// （拦截说明主机已在尝试回连）；只命中 Tor 出口节点时为中危（可能是正常的匿名浏览）。
func (s *Store) c2Hit(ev *model.Event) *model.Hit {
	if ev.DstIP == "" || geo.IsPrivate(ev.DstIP) || !ev.Outbound && !geo.IsPrivate(ev.SrcIP) {
		return nil
	}
	names := s.IntelMatch(ev.DstIP)
	if len(names) == 0 {
		return nil
	}
	// 会话日志记录了应答包数时据此区分：对端没有应答说明连接未建立（主机仍在尝试回连，与被拦截同级）
	sev, res, act := model.SevCritical, model.ResultAllowed, "已放行"
	switch {
	case ev.Action == model.ActionDeny:
		sev, res, act = model.SevHigh, model.ResultBlocked, "已拦截"
	case ev.Reply == model.ReplyNone:
		sev, res, act = model.SevHigh, model.ResultFailed, "已放行但对端无应答，连接未建立"
	case ev.Reply == model.ReplyYes:
		act = "已放行且对端有应答，连接已建立"
	}
	if len(names) == 1 && names[0] == "Tor出口节点" {
		sev = min(sev, model.SevMedium)
	}
	// 按情报类别定级：远控与通用黑名单维持原样；矿池按挖矿处置；恶意软件投递、钓鱼、攻击来源不足以判定失陷
	name, cat := "外连威胁情报地址（疑似失陷）", CatC2
	blocked := res != model.ResultAllowed
	switch s.intelKind(names) {
	case "mining":
		name, cat, sev = "外连情报标记的矿池地址（疑似挖矿）", CatMining, model.SevHigh
	case "malware":
		name, cat, sev = "外连情报标记的恶意软件投递地址", CatMalDomain, pick(blocked, model.SevMedium, model.SevHigh)
	case "phishing":
		name, cat, sev = "外连情报标记的钓鱼网站", CatPhishing, pick(blocked, model.SevLow, model.SevMedium)
	case "attacker":
		// 不归入恶意外连：攻击来源名单不说明主机失陷（恶意外连的分类底线为中危，被拦截时也会被抬回中危）
		name, cat, sev = "外连已知的攻击来源地址", "威胁情报", pick(blocked, model.SevLow, model.SevMedium)
	}
	dst := ev.DstIP
	if ev.DstPort > 0 {
		dst += fmt.Sprintf(":%d", ev.DstPort)
	}
	if ev.Proto != "" {
		dst += "/" + ev.Proto
	}
	return &model.Hit{RuleID: "c2-egress", Name: name, Category: cat, Severity: sev, Phase: model.PhasePersistence,
		Result: res, Evidence: ev.SrcIP + " → " + dst + "（" + act + "），命中 " + strings.Join(names, "、"), Feeds: feedNames(names)}
}

// calibrated 让状态库生成的情报命中经过自学习校准与统一定级（与流水线中的命中一致）。
func (s *Store) calibrated(ev *model.Event, h model.Hit) model.Hit {
	if s.Calibrate != nil {
		if out := s.Calibrate(ev, []model.Hit{h}); len(out) == 1 {
			h = out[0]
		}
	}
	risk.Finalize(&h)
	return h
}

func pick(cond bool, a, b model.Severity) model.Severity {
	if cond {
		return a
	}
	return b
}

// intelRank 是情报类别的严重程度：同时命中多个情报时按最严重的类别处理。
var intelRank = map[string]int{"c2": 5, "mining": 4, "malware": 3, "": 2, "phishing": 1, "attacker": 0}

// intelKind 返回命中的情报中最严重的类别（Tor 出口节点不参与，单独处理）。
func (s *Store) intelKind(names []string) string {
	best, rank := "", -1
	for _, n := range names {
		if n == "Tor出口节点" {
			continue
		}
		k := ""
		if s.IntelKind != nil {
			k = s.IntelKind(n)
		}
		if r, ok := intelRank[k]; ok && r > rank {
			best, rank = k, r
		}
	}
	return best
}

// feedNames 是参与准确率统计的情报源：Tor 出口列表是事实性的名单，不按研判结论统计。
func feedNames(names []string) []string {
	var out []string
	for _, n := range names {
		if n != "Tor出口节点" {
			out = append(out, n)
		}
	}
	return out
}

// Compromised 是一个疑似失陷的资产。
type Compromised struct {
	Asset      string         `json:"asset"`
	Kind       string         `json:"kind"`       // web：Web 资产（接口被攻击成功）；host：主机（外连恶意地址）
	Confidence string         `json:"confidence"` // high / medium
	Severity   model.Severity `json:"severity"`
	Indicators []string       `json:"indicators"`
	IPs        []string       `json:"ips"` // 攻击来源，或主机外连的恶意地址
	Count      int64          `json:"count"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Advice     string         `json:"advice"`
	Chain      string         `json:"chain,omitempty"` // 资产攻击链路的查询标识（站点域名或主机地址）
	evidenced  bool           // 至少有一条带证据的迹象（主机外连、或有证据的攻击成功）
}

// 攻击成功即意味着可在服务器上执行代码或已植入后门的攻击类型，研判为高置信失陷。
var highImpact = map[string]bool{"WebShell后门": true, "命令/代码执行": true, "表达式注入": true, "反序列化": true, CatC2: true}

// compromisedLocked 汇总疑似失陷资产（调用方持读锁）：攻击成功研判按资产合并，外连恶意地址按主机列出。
func (s *Store) compromisedLocked() []*Compromised {
	byAsset := map[string]*Compromised{}
	var out []*Compromised
	for _, f := range s.surf.Findings {
		var kind string
		switch f.Category {
		case "攻击成功研判":
			kind = "web"
		case "失陷迹象":
			// 只凭固定间隔的外连（中危）不足以判定失陷：定时调用接口、监控探活、软件更新同样规律。
			// 命中威胁情报、安全设备报出恶意软件等高危迹象才列为疑似失陷主机，规律外连仍在攻击面中提示
			if f.effectiveSev() < model.SevHigh {
				continue
			}
			kind = "host"
		default:
			continue
		}
		c := byAsset[kind+"|"+f.Asset]
		if c == nil {
			c = &Compromised{Asset: f.Asset, Kind: kind, Confidence: "medium", FirstSeen: f.FirstSeen}
			c.Chain = f.Asset
			if kind == "web" {
				if c.Chain = f.Host; c.Chain == "" || c.Chain == "-" {
					c.Chain, _, _ = strings.Cut(f.Asset, "/")
				}
			}
			byAsset[kind+"|"+f.Asset] = c
			out = append(out, c)
		}
		cat := strings.TrimPrefix(f.Title, "疑似攻击成功: ")
		sev := f.effectiveSev()
		// 主机：命中情报的外连与安全设备报出的恶意软件为高置信；仅凭周期性外连判断的为中置信。
		// Web：只有带证据的成功（命令执行、WebShell 等）才是高置信
		if kind == "host" && sev >= model.SevHigh || kind == "web" && highImpact[cat] && f.Proven {
			c.Confidence = "high"
		}
		if kind == "host" || f.Proven {
			c.evidenced = true
		}
		if sev > c.Severity {
			c.Severity = sev
		}
		c.Indicators = append(c.Indicators, f.Title+"："+f.Evidence)
		for _, ip := range f.IPs {
			if len(c.IPs) < 10 && !slices.Contains(c.IPs, ip) {
				c.IPs = append(c.IPs, ip)
			}
		}
		c.Count += f.Count
		if f.FirstSeen.Before(c.FirstSeen) {
			c.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(c.LastSeen) {
			c.LastSeen = f.LastSeen
		}
		if c.Advice == "" || highImpact[cat] {
			c.Advice = f.Remediation
		}
	}
	// 同一资产命中多种攻击成功研判（如 SQL 注入成功后又出现 WebShell 访问）时提升为高置信。
	// 至少要有一条带证据：扫描器会把各类载荷都打一遍，只凭 2xx 的多种“成功”说明不了失陷
	for _, c := range out {
		if len(c.Indicators) >= 2 && c.evidenced {
			c.Confidence = "high"
		}
		sort.Strings(c.Indicators)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Confidence != b.Confidence {
			return a.Confidence == "high"
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.LastSeen.After(b.LastSeen)
	})
	return out
}

// CompromisedAssets 返回疑似失陷资产。
func (s *Store) CompromisedAssets() []*Compromised {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.compromisedLocked()
}

func hasCategory(hits []model.Hit, cat string) bool {
	for _, h := range hits {
		if h.Category == cat && !h.TagOnly {
			return true
		}
	}
	return false
}

func hitOf(hits []model.Hit, cat string) model.Hit {
	for _, h := range hits {
		if h.Category == cat && !h.TagOnly {
			return h
		}
	}
	return model.Hit{}
}

// verifySuccess 用接口的正常响应基线复核“疑似成功”：攻击请求的响应与该接口正常访问时的响应大小一致
// （例如注入载荷被忽略、返回的仍是正常页面），说明攻击并未改变应用行为，改判为“未拦截”。
// 响应与站点首页相同（兜底页面）同样不算成功；响应明显大于稳定的接口基线、或脚本确实发生了交互，
// 才是响应码之外的第二份证据，等级裁决据此升为严重。
// 返回的切片为副本，不修改调用方的数据。
func (s *Store) verifySuccess(ev *model.Event, hits []model.Hit) []model.Hit {
	host := ev.Host
	if host == "" {
		host = "-"
	}
	ep := s.surf.Endpoints[host+" "+normPath(ev.URI)]
	var out []model.Hit
	edit := func(i int) *model.Hit {
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		return &out[i]
	}
	for i, h := range hits {
		if h.Result != model.ResultSuccess {
			continue
		}
		if h.Category == "敏感文件探测" || h.Category == "WebShell后门" {
			// 敏感文件与 WebShell 以资源存在 / 交互成功为准，不按接口基线复核；但兜底页返回的 200（单页应用、统一错误页）不算
			if s.surf.catchAll(host, normPath(ev.URI), ev.Bytes) {
				e := edit(i)
				e.Result, e.Proven, e.Disproven = model.ResultPassed, false, true
				e.Severity = min(e.Severity, model.SevMedium)
				e.Evidence += "（响应与站点首页或其他探测路径的大小相同，是兜底页面返回的 200，判定为未取到内容）"
				continue
			}
			if h.Category == "WebShell后门" && !h.Proven && s.surf.hasHomeBaseline(host) && webshellInteraction(ev, h.RuleID) {
				e := edit(i)
				e.Proven = true
				e.Evidence += "（响应不同于站点首页，脚本确实发生了交互）"
			}
			continue
		}
		switch {
		case ep.baselineMatches(ev.Bytes):
			// 复核为「未成功」：撤销成功判定，等级回落到高危封顶（严重需要第二份证据）。
			// 接口确实存在，盲注成功时页面大小也可能不变，所以不再往下降
			e := edit(i)
			e.Result, e.Proven = model.ResultPassed, false
			e.Severity = min(e.Severity, model.SevHigh)
			e.Evidence += "（响应大小与该接口正常响应一致，判定为未成功）"
		case s.surf.homePage(host, normPath(ev.URI), ev.Bytes):
			// 与站点首页的大小相同：路径不存在，返回的是兜底页面（单页应用把所有路径都返回首页），载荷没有到达应用。
			// 这是有证据的未成功，最高按中危处置；扫描器打一整套载荷时不会再刷出成片的高危
			s.surf.catchAll(host, normPath(ev.URI), ev.Bytes) // 同时计入同大小路径统计
			e := edit(i)
			e.Result, e.Proven, e.Disproven = model.ResultPassed, false, true
			e.Severity = min(e.Severity, model.SevMedium)
			e.Evidence += "（响应与站点首页大小相同，是兜底页面返回的 200，判定为未成功）"
		case s.surf.catchAll(host, normPath(ev.URI), ev.Bytes):
			// 只是多个探测路径大小相同：多半是兜底页面，但通过不同漏洞点读到同一个文件时大小也会相同，
			// 证据不如首页基线，只撤销成功判定、按高危封顶
			e := edit(i)
			e.Result, e.Proven = model.ResultPassed, false
			e.Severity = min(e.Severity, model.SevHigh)
			e.Evidence += "（响应与其他探测路径的大小相同，判定为未成功）"
		case !h.Proven && ep.baselineExceeded(ev.Bytes):
			e := edit(i)
			e.Proven = true
			e.Evidence += fmt.Sprintf("（响应 %d 字节，明显大于该接口正常的约 %.0f 字节，可能已取到额外数据）", ev.Bytes, ep.NormMean)
		}
	}
	if out == nil {
		return hits
	}
	return out
}

// webshellInteraction 判断请求是否在与脚本交互：POST 提交、带命令参数，或执行上传目录中的脚本。
// 只是 GET 访问一个名字可疑的脚本不算，合法脚本也可能叫这个名字。
func webshellInteraction(ev *model.Event, rule string) bool {
	return ev.Method == "POST" || rule == "webshell-param" || rule == "webshell-upload"
}

// hostFinding 把 DNS 与主机认证日志中的失陷迹象记入攻击面发现（疑似失陷资产据此汇总）。
func (s *Store) hostFinding(ev *model.Event, hits []model.Hit) {
	for i := range hits {
		h := &hits[i]
		if h.TagOnly {
			continue
		}
		switch h.RuleID {
		case "dns-oob":
			s.surf.finding("dns-oob:"+ev.SrcIP, "内网主机解析带外探测平台域名（漏洞可能已被利用）", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
				"盲打类漏洞（RCE、SSRF、Log4j、反序列化）被触发时，目标会解析攻击者的 DNSLog 域名：排查该主机近期受到的攻击与对外服务的中间件版本，"+
					"检查是否有新增进程、文件与外连；在出口 DNS 拦截该类域名", ev.Host, ev.Time)
		case "intel-dns":
			// 远控、矿池域名是失陷迹象；恶意软件投递、钓鱼域名说明有人访问过，只告警不列为失陷
			if h.Severity >= model.SevHigh {
				s.surf.finding("intel-dns:"+ev.SrcIP, "内网主机解析情报标记的远控 / 矿池域名", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
					"排查该主机上发起这些查询的进程、计划任务与自启动项，使用终端安全软件查杀；在出口 DNS 与防火墙拦截该域名", ev.Host, ev.Time)
			}
		case "dns-mining":
			s.surf.finding("dns-mining:"+ev.SrcIP, "内网主机解析矿池域名（疑似挖矿木马）", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
				"排查 CPU 占用异常的进程、计划任务与自启动项，清除挖矿程序；在出口 DNS 与防火墙封禁矿池域名与端口", ev.Host, ev.Time)
		case "dns-tunnel", "dns-tunnel-volume":
			s.surf.finding("dns-tunnel:"+ev.SrcIP, "内网主机疑似使用 DNS 隧道（数据外传 / 远控）", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
				"核查该主机上发起这些查询的进程；在 DNS 服务器限制外部递归、拦截超长与高熵子域名，必要时隔离主机", ev.Host, ev.Time)
		case "dns-dga", "dns-nxdomain":
			if h.Severity >= model.SevHigh {
				s.surf.finding("dns-dga:"+ev.SrcIP, "内网主机查询大量随机域名（疑似 DGA 僵尸程序）", "失陷迹象", h.Severity, ev.SrcIP, h.Evidence,
					"使用终端安全软件全盘查杀，排查恶意进程与自启动项；在 DNS 服务器上记录并拦截该主机的异常查询", ev.Host, ev.Time)
			}
		case "auth-brute-ok":
			target := ev.Host
			if target == "" {
				target = ev.DstIP
			}
			if target == "" {
				target = ev.Service
			}
			s.surf.finding("auth-ok:"+target+":"+ev.User, "暴力破解后登录成功（账号疑似失陷）", "失陷迹象", h.Severity, target, ev.SrcIP+"："+h.Evidence,
				"立即修改该账号口令并检查登录后的操作（命令历史、新增文件与账号、计划任务）；封禁来源地址，"+
					"对外暴露的 SSH / RDP / VPN 启用多因素认证或仅允许经堡垒机访问", ev.SrcIP, ev.Time)
		case "host-log-cleared", "host-admin-group":
			host := ev.Host
			if host == "" {
				host = ev.SrcIP
			}
			s.surf.finding(h.RuleID+":"+host, h.Name, "失陷迹象", h.Severity, host, h.Evidence,
				"核实该操作是否为授权变更；无法解释时按入侵处置：保全现有日志、排查登录记录与新增账号，重置相关账号口令", ev.SrcIP, ev.Time)
		}
	}
}
