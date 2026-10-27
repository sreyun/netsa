package store

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
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
	sev, res := model.SevCritical, model.ResultAllowed
	if ev.Action == model.ActionDeny {
		sev, res = model.SevHigh, model.ResultBlocked
	}
	if len(names) == 1 && names[0] == "Tor出口节点" {
		sev = min(sev, model.SevMedium)
	}
	dst := ev.DstIP
	if ev.DstPort > 0 {
		dst += fmt.Sprintf(":%d", ev.DstPort)
	}
	if ev.Proto != "" {
		dst += "/" + ev.Proto
	}
	act := "已放行"
	if res == model.ResultBlocked {
		act = "已拦截"
	}
	return &model.Hit{RuleID: "c2-egress", Name: "外连威胁情报地址（疑似失陷）", Category: CatC2, Severity: sev, Phase: model.PhasePersistence,
		Result: res, Evidence: ev.SrcIP + " → " + dst + "（" + act + "），命中 " + strings.Join(names, "、")}
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
			kind = "host"
		default:
			continue
		}
		c := byAsset[kind+"|"+f.Asset]
		if c == nil {
			c = &Compromised{Asset: f.Asset, Kind: kind, Confidence: "medium", FirstSeen: f.FirstSeen}
			byAsset[kind+"|"+f.Asset] = c
			out = append(out, c)
		}
		cat := strings.TrimPrefix(f.Title, "疑似攻击成功: ")
		// 主机：命中情报的外连与安全设备报出的恶意软件为高置信；仅凭周期性外连判断的为中置信
		if kind == "host" && f.Severity >= model.SevHigh || kind == "web" && highImpact[cat] {
			c.Confidence = "high"
		}
		if f.Severity > c.Severity {
			c.Severity = f.Severity
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
	// 同一资产命中多种攻击成功研判（如 SQL 注入成功后又出现 WebShell 访问）时提升为高置信
	for _, c := range out {
		if len(c.Indicators) >= 2 {
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
// 返回的切片为副本，不修改调用方的数据。
func (s *Store) verifySuccess(ev *model.Event, hits []model.Hit) []model.Hit {
	var ep *Endpoint
	looked := false
	var out []model.Hit
	for i, h := range hits {
		if h.Result != model.ResultSuccess || h.Category == "敏感文件探测" || h.Category == "WebShell后门" {
			continue // 敏感文件与 WebShell 以资源存在 / 交互成功为准，不按页面大小复核
		}
		if !looked {
			looked = true
			host := ev.Host
			if host == "" {
				host = "-"
			}
			ep = s.surf.Endpoints[host+" "+normPath(ev.URI)]
		}
		if !ep.baselineMatches(ev.Bytes) {
			continue
		}
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		// 复核为「未成功」：撤销成功升级，等级回落到高危封顶（严重需要成功或失陷证据）。
		out[i].Result = model.ResultPassed
		if out[i].Severity > model.SevHigh {
			out[i].Severity = model.SevHigh
		}
		out[i].Evidence += "（响应大小与该接口正常响应一致，判定为未成功）"
	}
	if out == nil {
		return hits
	}
	return out
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
