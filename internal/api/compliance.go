package api

import (
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"netsa/internal/auth"
)

// 合规检查结果。
const (
	CompPass    = "pass"    // 符合
	CompPartial = "partial" // 部分符合
	CompFail    = "fail"    // 不符合
	CompNA      = "na"      // 不适用 / 无法判断
)

var compLabel = map[string]string{CompPass: "符合", CompPartial: "部分符合", CompFail: "不符合", CompNA: "不适用"}

// CompItem 是一个测评项的检查结果。
type CompItem struct {
	Layer    string `json:"layer"`    // 层面：安全区域边界 / 安全计算环境 / 安全管理中心 / 安全运维管理 / 法律法规
	Control  string `json:"control"`  // 控制点与条款号，例如 “8.1.3.3 入侵防范 a)”
	Require  string `json:"require"`  // 要求原文（摘要）
	Status   string `json:"status"`   // pass / partial / fail / na
	Label    string `json:"label"`    // 中文结果
	Evidence string `json:"evidence"` // 平台给出的证据
	Advice   string `json:"advice,omitempty"`
}

// CompLayer 是一个层面的汇总。
type CompLayer struct {
	Name    string  `json:"name"`
	Pass    int     `json:"pass"`
	Partial int     `json:"partial"`
	Fail    int     `json:"fail"`
	NA      int     `json:"na"`
	Rate    float64 `json:"rate"` // 符合率（部分符合按一半计，不适用不计入）
}

// ComplianceReport 是等保 2.0 合规检查报告。
type ComplianceReport struct {
	Title     string      `json:"title"`
	Standard  string      `json:"standard"`
	Org       string      `json:"org"`
	Level     string      `json:"level"`
	Generated time.Time   `json:"generated"`
	Rate      float64     `json:"rate"`
	Pass      int         `json:"pass"`
	Partial   int         `json:"partial"`
	Fail      int         `json:"fail"`
	NA        int         `json:"na"`
	Layers    []CompLayer `json:"layers"`
	Items     []CompItem  `json:"items"`
	Systems   map[int]int `json:"systems"` // 资产台账中的等保定级分布
	Notice    string      `json:"notice"`
}

func pick3(ok, partial bool) string {
	switch {
	case ok:
		return CompPass
	case partial:
		return CompPartial
	}
	return CompFail
}

// BuildCompliance 依据平台可观测的技术证据生成等保 2.0 第三级相关测评项的检查结果。
func (s *Server) BuildCompliance() *ComplianceReport {
	v := s.visibility(nil)
	ov := s.Store.Overview()
	t := ov.Totals
	m := s.Store.Metrics()
	stats := s.Ingest.Stats()
	r := &ComplianceReport{Title: "网络安全等级保护 2.0 合规检查报告", Standard: "GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》（第三级）",
		Org: s.Cfg.Home.Name, Level: "第三级", Generated: s.now(), Systems: map[int]int{},
		Notice: "本报告依据 netsa 平台可观测的技术证据（日志接入、检测、告警、审计、资产与漏洞数据）自动判定，仅覆盖与安全审计、入侵防范、集中管控、" +
			"身份鉴别、漏洞与事件管理相关的部分测评项，供日常自查与整改跟踪使用，不能替代测评机构的正式等级测评结论。"}
	add := func(layer, control, require, status, evidence, advice string) {
		if status == CompPass {
			advice = ""
		}
		r.Items = append(r.Items, CompItem{Layer: layer, Control: control, Require: require, Status: status, Label: compLabel[status], Evidence: evidence, Advice: advice})
	}
	retention := v.RawLogDays >= 180 || v.RawLogDays == -1 || v.Archive
	retentionText := "未启用原始日志留存与告警归档"
	switch {
	case v.RawLogDays == -1:
		retentionText = "原始日志永久留存"
	case v.RawLogDays > 0:
		retentionText = fmt.Sprintf("原始日志留存 %d 天", v.RawLogDays)
	}
	if v.Archive {
		retentionText += "；告警归档至 PostgreSQL（保留 " + yearsText(s.Cfg.Archive.RetentionYears) + "）"
	}
	notify := v.Robots > 0 || s.Cfg.Report.SMTP.Host != ""
	senders, silentSenders := 0, 0
	if s.Ingest.Senders != nil {
		rep := s.Ingest.Senders.Report()
		senders, silentSenders = rep.Totals.Senders, rep.Totals.Silent
	}
	threatFeeds := false
	for _, st := range stats {
		for _, f := range []string{"snort", "suricata", "paloalto", "json_firewall", "kv_firewall"} {
			if strings.Contains(st.Detected, f) {
				threatFeeds = true
			}
		}
	}

	// ---------------- 安全区域边界 ----------------
	L := "安全区域边界"
	add(L, "8.1.3.3 入侵防范 a)", "应在关键网络节点处检测、防止或限制从外部发起的网络攻击行为",
		pick3(t.Web > 0 && t.Firewall > 0, t.Web > 0 || t.Firewall > 0),
		fmt.Sprintf("已接入 Web 日志 %s 条、防火墙 / 网络设备日志 %s 条，累计检测攻击 %s 次", human(t.Web), human(t.Firewall), human(t.Attacks)),
		"同时接入对外业务的 Web 访问日志与边界防火墙日志，覆盖应用层与网络层攻击检测")
	add(L, "8.1.3.3 入侵防范 b)", "应在关键网络节点处检测、防止或限制从内部发起的网络攻击行为",
		pick3(t.DNS > 0 && t.Outbound+t.Egress > 0, t.DNS > 0 || t.Outbound+t.Egress > 0),
		fmt.Sprintf("DNS 日志 %s 条，出站流量日志 %s 条（用于发现内网主机外连恶意地址、DNS 隧道、DGA 与横向扫描）", human(t.DNS), human(t.Outbound+t.Egress)),
		"接入内网 DNS 服务器查询日志，并让防火墙记录出站连接日志")
	add(L, "8.1.3.3 入侵防范 c)", "应采取技术措施对网络行为进行分析，实现对网络攻击特别是新型网络攻击行为的分析",
		pick3(v.Intel > 0, true), fmt.Sprintf("已启用行为分析（CC、扫描、暴力破解、撞库、接口遍历、C2 心跳、DNS 隧道），威胁情报源 %d 个", v.Intel),
		"配置威胁情报黑名单（intel.blocklists）与 Tor 出口节点列表，提升对新型攻击来源的识别")
	add(L, "8.1.3.3 入侵防范 d)", "当检测到攻击行为时，记录攻击源 IP、攻击类型、攻击目标、攻击时间，在发生严重入侵事件时应提供报警",
		pick3(notify, t.Alerts > 0), fmt.Sprintf("告警记录包含来源、类型、目标、时间与研判结果，累计 %s 条；启用的告警推送 %d 个", human(t.Alerts), v.Robots),
		"在“告警推送”中配置钉钉 / 企业微信 / 飞书机器人或邮件，确保严重事件即时通知")
	add(L, "8.1.3.4 恶意代码和垃圾邮件防范 a)", "应在关键网络节点处对恶意代码进行检测和清除，并维护恶意代码防护机制的升级和更新",
		pick3(false, threatFeeds || t.DNS > 0), "平台可汇聚 IDS / IPS / 下一代防火墙的威胁日志并识别挖矿、远控外连等迹象；恶意代码清除需由边界防护设备完成",
		"在边界部署具备恶意代码检测的设备（IPS / 防病毒网关），并将其威胁日志接入平台")
	add(L, "8.1.3.5 安全审计 a)", "应在网络边界、重要网络节点进行安全审计，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计",
		pick3(t.Firewall > 0 && t.Auth > 0, t.Firewall > 0 || t.Auth > 0),
		fmt.Sprintf("网络设备日志 %s 条，主机 / VPN 认证日志 %s 条，syslog 发送端 %d 个", human(t.Firewall), human(t.Auth), senders),
		"将防火墙、VPN 与重要服务器的认证日志（auth.log / Windows 安全事件）集中接入")
	add(L, "8.1.3.5 安全审计 c)", "应对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖等",
		pick3(v.RawLogDays != 0, v.Archive), retentionText+"；原始日志分段以 SHA-256 哈希链登记，可校验是否被篡改",
		"开启 rawlog（原始日志留存，带防篡改哈希链）并定期执行完整性校验")

	// ---------------- 安全计算环境（netsa 平台自身与接入的主机） ----------------
	L = "安全计算环境"
	users, twoFA, roles := 0, 0, map[string]int{}
	if s.Auth != nil {
		for _, u := range s.Auth.Users() {
			users++
			roles[u.Role]++
			if u.TwoFactor {
				twoFA++
			}
		}
	}
	add(L, "8.1.4.1 身份鉴别 a)", "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性，身份鉴别信息具有复杂度要求并定期更换",
		pick3(v.AuthEnabled, false), fmt.Sprintf("平台登录认证：%s；账号 %d 个，口令强制复杂度（至少 8 位、至少两类字符），初始口令须修改", onOff(v.AuthEnabled), users),
		"开启平台登录认证（server.username / 账号文件）")
	add(L, "8.1.4.1 身份鉴别 b)", "应具有登录失败处理功能，应配置并启用结束会话、限制非法登录次数和当登录连接超时自动退出等相关措施",
		pick3(v.AuthEnabled, false), "连续登录失败按来源、账号锁定；会话超时自动失效；修改口令后其他会话失效", "开启平台登录认证")
	add(L, "8.1.4.1 身份鉴别 c)", "当进行远程管理时，应采取必要措施防止鉴别信息在网络传输过程中被窃听",
		pick3(v.HTTPS, false), "平台访问："+map[bool]string{true: "HTTPS", false: "HTTP（明文）"}[v.HTTPS], "配置 server.tls_cert / tls_key 启用 HTTPS，或通过 HTTPS 反向代理访问")
	add(L, "8.1.4.1 身份鉴别 d)", "应采用口令、密码技术、生物技术等两种或两种以上组合的鉴别技术对用户进行身份鉴别",
		pick3(v.Require2FA, twoFA > 0), fmt.Sprintf("强制双因素认证：%s；已启用动态口令的账号 %d / %d", onOff(v.Require2FA), twoFA, users),
		"开启 server.require_2fa，所有账号绑定动态口令（TOTP）")
	add(L, "8.1.4.2 访问控制 c)", "应授予管理用户所需的最小权限，实现管理用户的权限分离",
		pick3(roles[auth.RoleAnalyst]+roles[auth.RoleViewer] > 0 && roles[auth.RoleAdmin] > 0, v.AuthEnabled),
		fmt.Sprintf("管理员 %d、运营分析员 %d、只读 %d 个账号；系统配置、事件处置、查看分别授权", roles[auth.RoleAdmin], roles[auth.RoleAnalyst], roles[auth.RoleViewer]),
		"为值班人员创建运营分析员 / 只读账号，管理员账号仅用于系统配置")
	trailOK, trailText := false, "未启用审计链"
	if s.Trail != nil {
		vr := s.Trail.Verify()
		st := s.Trail.Stats()
		trailOK = vr.OK
		trailText = fmt.Sprintf("平台操作审计链记录 %d 条，留存 %s，哈希链校验%s", st.Entries, daysText(st.Retention), map[bool]string{true: "通过", false: "未通过"}[vr.OK])
	}
	add(L, "8.1.4.3 安全审计 a)", "应启用安全审计功能，审计覆盖到每个用户，对重要的用户行为和重要安全事件进行审计",
		pick3(s.Trail != nil && t.Auth > 0, s.Trail != nil),
		trailText+fmt.Sprintf("；接入的主机认证日志 %s 条", human(t.Auth)), "接入重要服务器的认证日志，覆盖主机层面的用户行为审计")
	add(L, "8.1.4.3 安全审计 c)", "应对审计记录进行保护，定期备份，避免受到未预期的删除、修改或覆盖等",
		pick3(trailOK, false), trailText, "保持审计链启用并定期在“系统管理 → 审计”中校验完整性、导出备份")
	add(L, "8.1.4.3 安全审计 d)", "应对审计进程进行保护，防止未经授权的中断",
		pick3(s.Ingest.DefaultSilence > 0 && t.Auth > 0, s.Ingest.DefaultSilence > 0),
		fmt.Sprintf("数据源断流告警：%s；可识别“安全日志被清除”等审计中断行为（需接入 Windows 安全事件）", silenceText(s.Ingest.DefaultSilence)),
		"配置 alert.source_silence 并接入主机安全事件日志")
	add(L, "8.1.4.4 入侵防范 e)", "应能发现可能存在的已知漏洞，并在经过充分测试评估后，及时修补漏洞",
		vulnStatus(s), vulnText(s), "定期导入漏洞扫描结果（资产与漏洞 → 导入），修复核心资产上的高危漏洞后标记为已修复")
	add(L, "8.1.4.4 入侵防范 f)", "应能够检测到对重要节点进行入侵的行为，并在发生严重入侵事件时提供报警",
		pick3(t.Auth > 0 && notify, t.Auth > 0 || notify), fmt.Sprintf("主机认证日志 %s 条（暴力破解、密码喷洒、破解成功检测），告警推送 %d 个", human(t.Auth), v.Robots),
		"接入重要服务器的认证日志并配置告警推送")

	// ---------------- 安全管理中心 ----------------
	L = "安全管理中心"
	add(L, "8.1.5.2 审计管理 a)", "应对审计管理员进行身份鉴别，只允许其通过特定的命令或操作界面进行安全审计操作，并对这些操作进行审计",
		pick3(v.AuthEnabled && s.Trail != nil, s.Trail != nil), "审计记录的查看、导出、校验仅限管理员，且这些操作本身记入审计链", "开启平台登录认证")
	add(L, "8.1.5.4 集中管控 a)", "应划分出特定的管理区域，对分布在网络中的安全设备或安全组件进行管控",
		pick3(v.AllowNetworks, false), "管理访问来源限制（server.allow_networks）："+onOff(v.AllowNetworks), "配置 server.allow_networks 只允许运维管理网段访问平台")
	add(L, "8.1.5.4 集中管控 c)", "应对网络链路、安全设备、网络设备和服务器等的运行状况进行集中监测",
		pick3(s.Ingest.DefaultSilence > 0 && senders > 0 && silentSenders == 0, s.Ingest.DefaultSilence > 0),
		fmt.Sprintf("数据源断流告警 %s；syslog 发送端 %d 个，当前断流 %d 个；提供 /metrics 监控指标", silenceText(s.Ingest.DefaultSilence), senders, silentSenders),
		"在“数据源 → Syslog 发送端”中登记设备并设置断流阈值，处理断流的设备")
	add(L, "8.1.5.4 集中管控 d)", "应对分散在各个设备上的审计数据进行收集汇总和集中分析，并保证审计记录的留存时间符合法律法规要求",
		pick3(len(stats) > 0 && retention, len(stats) > 0), fmt.Sprintf("数据源 %d 个、syslog 发送端 %d 个；%s", len(stats), senders, retentionText),
		"开启原始日志留存（rawlog.retention_days ≥ 180）或配置告警归档")
	add(L, "8.1.5.4 集中管控 e)", "应对安全策略、恶意代码、补丁升级等安全相关事项进行集中管理",
		pick3(false, s.Assets != nil && s.Assets.Summary().Vulns > 0), "平台集中跟踪漏洞与修复状态；补丁下发与安全策略需由专门的管理系统完成",
		"导入漏洞扫描结果，并结合补丁管理系统跟踪修复")
	add(L, "8.1.5.4 集中管控 f)", "应能对网络中发生的各类安全事件进行识别、报警和分析",
		pick3(notify && t.Attacks > 0, t.Attacks > 0), fmt.Sprintf("安全事件 %d 个（待处理 %d、处置中 %d），支持事件聚合、指派、处置记录与超时提醒", m.Incidents.Total, m.Incidents.Open, m.Incidents.Investigating),
		"配置告警推送，并由值班人员在“事件处置”中跟踪处置")

	// ---------------- 安全运维管理 ----------------
	L = "安全运维管理"
	if s.Assets != nil {
		a := s.Assets.Summary()
		r.Systems = a.MLPS
		add(L, "8.1.10.2 资产管理 a)", "应编制并保存与保护对象相关的资产清单，包括资产责任部门、重要程度和所处位置等内容",
			pick3(a.Assets > 0 && a.NoOwner == 0, a.Assets > 0), fmt.Sprintf("资产台账 %d 个（核心 %d、重要 %d），未填写负责人 %d 个", a.Assets, a.ByImportance["core"], a.ByImportance["important"], a.NoOwner),
			"导入 CMDB 资产清单，补全负责人、部门与重要程度")
		st := CompNA
		if a.Vulns > 0 {
			st = pick3(a.OpenBySev["critical"]+a.OpenBySev["high"] == 0, true)
		}
		add(L, "8.1.10.5 漏洞和风险管理 a)", "应采取必要的措施识别安全漏洞和隐患，对发现的安全漏洞和隐患及时进行修补或评估可能的影响后进行修补",
			st, fmt.Sprintf("漏洞 %d 个，未修复 %d 个（严重 %d、高危 %d），已修复 %d 个，风险接受 %d 个", a.Vulns, a.OpenVulns, a.OpenBySev["critical"], a.OpenBySev["high"], a.Fixed, a.Accepted),
			"按“严重 → 高危”的顺序修复漏洞，无法修复的评估影响后标记为风险接受")
	}
	inc := m.Incidents
	incStatus := CompNA
	if inc.Total > 0 {
		incStatus = pick3(inc.Overdue == 0 && inc.Resolved+inc.FalsePositive+inc.Ignored > 0, true)
	}
	add(L, "8.1.10.11 安全事件处置 c)", "应在安全事件报告和响应处理过程中，分析和鉴定事件产生的原因，收集证据，记录处理过程，总结经验教训",
		incStatus, fmt.Sprintf("事件 %d 个：已处置 %d、误报 %d、忽略 %d，当前超时未处置 %d 个；关闭事件必须填写处置说明，处置过程全程记录", inc.Total, inc.Resolved, inc.FalsePositive, inc.Ignored, inc.Overdue),
		"及时处置超时事件，关闭时写明原因与处置措施")

	// ---------------- 法律法规 ----------------
	add("法律法规", "《网络安全法》第二十一条", "采取监测、记录网络运行状态、网络安全事件的技术措施，并按照规定留存相关的网络日志不少于六个月",
		pick3(retention, v.RawLogDays > 0 || len(stats) > 0), retentionText, "开启 rawlog 并将 retention_days 设置为不少于 180 天，或配置告警长期归档")

	// 汇总
	layers := map[string]*CompLayer{}
	var order []string
	for _, it := range r.Items {
		l := layers[it.Layer]
		if l == nil {
			l = &CompLayer{Name: it.Layer}
			layers[it.Layer] = l
			order = append(order, it.Layer)
		}
		switch it.Status {
		case CompPass:
			l.Pass++
			r.Pass++
		case CompPartial:
			l.Partial++
			r.Partial++
		case CompFail:
			l.Fail++
			r.Fail++
		default:
			l.NA++
			r.NA++
		}
	}
	rate := func(p, h, f int) float64 {
		if p+h+f == 0 {
			return -1
		}
		return (float64(p) + float64(h)/2) / float64(p+h+f)
	}
	for _, name := range order {
		l := layers[name]
		l.Rate = rate(l.Pass, l.Partial, l.Fail)
		r.Layers = append(r.Layers, *l)
	}
	r.Rate = rate(r.Pass, r.Partial, r.Fail)
	// 不符合的排在前面，便于整改
	slices.SortStableFunc(r.Items, func(a, b CompItem) int {
		rank := map[string]int{CompFail: 0, CompPartial: 1, CompPass: 2, CompNA: 3}
		if a.Layer != b.Layer {
			return slices.Index(order, a.Layer) - slices.Index(order, b.Layer)
		}
		return rank[a.Status] - rank[b.Status]
	})
	return r
}

func onOff(b bool) string {
	if b {
		return "已启用"
	}
	return "未启用"
}

func daysText(d int) string {
	if d == 0 {
		return "永久"
	}
	return fmt.Sprintf("%d 天", d)
}

func yearsText(y int) string {
	if y == 0 {
		return "永久"
	}
	return fmt.Sprintf("%d 年", y)
}

func silenceText(d time.Duration) string {
	if d <= 0 {
		return "未启用"
	}
	return "已启用（" + d.String() + "）"
}

func vulnStatus(s *Server) string {
	if s.Assets == nil {
		return CompFail
	}
	a := s.Assets.Summary()
	if a.Vulns == 0 {
		return CompFail
	}
	return pick3(a.CoreOpenHigh == 0, true)
}

func vulnText(s *Server) string {
	if s.Assets == nil {
		return "未启用资产与漏洞管理"
	}
	a := s.Assets.Summary()
	if a.Vulns == 0 {
		return "尚未导入漏洞扫描结果"
	}
	return fmt.Sprintf("已导入漏洞 %d 个，未修复 %d 个，其中核心资产高危及以上 %d 个", a.Vulns, a.OpenVulns, a.CoreOpenHigh)
}

var compTpl = template.Must(template.New("comp").Funcs(reportFuncs).Funcs(template.FuncMap{
	"rate": func(f float64) string {
		if f < 0 {
			return "-"
		}
		return fmt.Sprintf("%.0f%%", f*100)
	},
}).Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.R.Title}}</title>
<style>{{css}} td.st{white-space:nowrap;font-weight:600}</style></head><body><div class="page">
<h1>{{if .R.Org}}{{.R.Org}} · {{end}}{{.R.Title}}</h1>
<div class="meta">依据 {{.R.Standard}} · 生成时间 {{dt .R.Generated}} · netsa 网络安全态势感知平台</div>
{{if .Print}}<div class="toolbar"><button id="print">打印 / 导出 PDF</button></div><script src="/print.js"></script>{{end}}
<div class="kpis">
<div class="kpi"><b>{{rate .R.Rate}}</b><span>技术项符合率</span></div>
<div class="kpi"><b class="ok">{{.R.Pass}}</b><span>符合</span></div>
<div class="kpi"><b class="warn">{{.R.Partial}}</b><span>部分符合</span></div>
<div class="kpi"><b class="bad">{{.R.Fail}}</b><span>不符合</span></div>
<div class="kpi"><b class="na">{{.R.NA}}</b><span>不适用</span></div>
</div>
<h2>一、各层面符合情况</h2>
<table><tr><th>层面</th><th class="n">符合</th><th class="n">部分符合</th><th class="n">不符合</th><th class="n">不适用</th><th class="n">符合率</th></tr>
{{range .R.Layers}}<tr><td>{{.Name}}</td><td class="n">{{.Pass}}</td><td class="n">{{.Partial}}</td><td class="n">{{.Fail}}</td><td class="n">{{.NA}}</td><td class="n">{{rate .Rate}}</td></tr>{{end}}</table>
<h2>二、检查明细与整改建议</h2>
<table><tr><th style="width:150px">控制点</th><th>要求</th><th style="width:64px">结果</th><th>证据</th><th>整改建议</th></tr>
{{range .R.Items}}<tr><td>{{.Layer}}<br><b>{{.Control}}</b></td><td>{{.Require}}</td><td class="st {{if eq .Status "pass"}}ok{{else if eq .Status "partial"}}warn{{else if eq .Status "fail"}}bad{{else}}na{{end}}">{{.Label}}</td><td>{{.Evidence}}</td><td>{{.Advice}}</td></tr>{{end}}</table>
<div class="foot">{{.R.Notice}}</div>
</div></body></html>`))

// compliance 返回等保 2.0 合规检查报告（管理员）：format=html 返回可打印的报告页。
func (s *Server) compliance(w http.ResponseWriter, r *http.Request) {
	extendDeadline(w, time.Minute)
	rep := s.BuildCompliance()
	s.audit(r, "生成等保合规报告", fmt.Sprintf("符合 %d、部分符合 %d、不符合 %d", rep.Pass, rep.Partial, rep.Fail), nil)
	if r.URL.Query().Get("format") == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="netsa-mlps-`+rep.Generated.Format("20060102")+`.html"`)
		}
		compTpl.Execute(w, map[string]any{"R": rep, "Print": true})
		return
	}
	writeJSON(w, rep)
}
