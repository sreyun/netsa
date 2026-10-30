// Package pipeline 将采集、真实 IP 还原、特征检测、行为分析、画像存储、溯源与告警串联起来。
package pipeline

import (
	"context"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"netsa/internal/alert"
	"netsa/internal/assets"
	"netsa/internal/detect"
	"netsa/internal/exposure"
	"netsa/internal/geo"
	"netsa/internal/intel"
	"netsa/internal/learn"
	"netsa/internal/model"
	"netsa/internal/rawlog"
	"netsa/internal/risk"
	"netsa/internal/safe"
	"netsa/internal/store"
	"netsa/internal/suppress"
)

type item struct {
	ev          *model.Event
	hits        []model.Hit
	whitelisted bool
}

// Pipeline 是事件处理流水线：多个 worker 并行做无状态检测，单个聚合协程做有状态分析与入库。
type Pipeline struct {
	Engine      *detect.Engine
	Behavior    *detect.Behavior
	Store       *store.Store
	Geo         *geo.Resolver
	RealIP      *RealIP
	Notifier    *alert.Notifier
	EnrichLevel model.Severity
	OnAlert     func(*model.Alert)
	Suppress    *suppress.Manager // 误报抑制规则（可为空）
	Raw         *rawlog.Store     // 原始日志留存（可为空）
	Assets      *assets.Manager   // 资产与漏洞（可为空）
	Exposure    *exposure.Manager // 对外发布服务清单（DNAT 映射，可为空）
	Learn       *learn.Learner    // 自学习：按研判准确率校准规则等级（可为空）

	whitelist []netip.Prefix
	processed atomic.Int64
}

// SetWhitelist 设置白名单（这些来源只统计流量，不做攻击检测）。
func (p *Pipeline) SetWhitelist(list []string) {
	p.whitelist = nil
	for _, s := range list {
		if pr, err := netip.ParsePrefix(s); err == nil {
			p.whitelist = append(p.whitelist, pr.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			p.whitelist = append(p.whitelist, netip.PrefixFrom(a, a.BitLen()))
		}
	}
}

func (p *Pipeline) whitelisted(ip string) bool {
	if len(p.whitelist) == 0 {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, pr := range p.whitelist {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

// Processed 返回已处理事件数。
func (p *Pipeline) Processed() int64 { return p.processed.Load() }

// Run 启动流水线，in 关闭且全部处理完成后关闭返回的通道；ctx 取消时立即停止。
// 输入为事件批次：worker 并行完成真实 IP 还原与特征检测，聚合协程按批写入状态库（每批只加一次锁）。
func (p *Pipeline) Run(ctx context.Context, in <-chan []*model.Event, workers int) <-chan struct{} {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	agg := make(chan []item, workers*4)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				var batch []*model.Event
				select {
				case b, ok := <-in:
					if !ok {
						return
					}
					batch = b
				case <-ctx.Done():
					return
				}
				items := make([]item, len(batch))
				for j, ev := range batch {
					items[j] = p.safeInspect(ev)
				}
				select {
				case agg <- items:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(agg)
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for items := range agg {
			p.safeAggregate(items)
		}
	}()
	return done
}

// safeInspect 对单条事件做异常保护：畸形日志触发的异常只丢弃该条的检测结果（事件仍会计入统计）。
func (p *Pipeline) safeInspect(ev *model.Event) (it item) {
	defer func() {
		if r := recover(); r != nil {
			safe.Report("检测事件 "+ev.SrcIP, r)
			it = item{ev: ev}
		}
	}()
	return p.inspect(ev)
}

// safeAggregate 对一批事件的入库与后续处理做异常保护，聚合协程不会因个别数据退出。
func (p *Pipeline) safeAggregate(items []item) {
	defer func() {
		if r := recover(); r != nil {
			safe.Report("汇总事件", r)
		}
	}()
	p.aggregate(items)
}

// inspect 是无状态处理：真实 IP 还原、白名单判断与特征检测。
func (p *Pipeline) inspect(ev *model.Event) item {
	it := item{ev: ev}
	if p.RealIP != nil {
		if h := p.RealIP.Apply(ev); h != nil {
			h.Result = p.Engine.Result(ev)
			it.hits = append(it.hits, *h)
		}
	}
	// 白名单用于信任的访问来源（如内部扫描器）；DNS 查询与主机事件的主体是内网主机本身（检测的是其是否失陷），不受白名单影响
	if ev.Kind != model.KindDNS && !ev.SubjectHost && p.whitelisted(ev.SrcIP) {
		it.whitelisted, it.hits = true, nil
		return it
	}
	it.hits = append(it.hits, p.Engine.Inspect(ev)...)
	return it
}

func (p *Pipeline) aggregate(items []item) {
	evs := make([]*model.Event, len(items))
	hits := make([][]model.Hit, len(items))
	for i, it := range items {
		evs[i], hits[i] = it.ev, it.hits
		if !it.whitelisted && p.Behavior != nil {
			hits[i] = append(hits[i], p.Behavior.Observe(it.ev)...)
		}
		reach, why := exposure.ReachUnknown, ""
		if it.ev.Kind == model.KindFirewall {
			reach, why = p.reachOf(it.ev)
			it.ev.Reach = reach // 攻击面按同一证据判断服务是否真实对外开放
			if reach == exposure.ReachYes {
				p.Exposure.Learn(it.ev, why) // 有会话证据的对外服务自动识别，免手工登记
			}
			if reach == exposure.ReachNo {
				p.Exposure.RecordUnreached(it.ev) // 按策略汇总，提示源安全域配置过宽的放行策略
			}
			// 候选映射统计：外部来源访问公网地址端口且被放行，用于提示可能漏登记的 DNAT 映射。
			// 只记录不生效，避免误判成「已发布」后真实攻击不再告警；会话证据表明没有到达服务、或打到防火墙自身的放行不计入。
			p.Exposure.Observe(it.ev.DstIP, it.ev.DstPort, it.ev.Proto, it.ev.SrcIP,
				it.ev.Action == model.ActionAllow && reach != exposure.ReachNo && reach != exposure.ReachDevice, it.ev.Time)
		}
		hits[i] = p.gateExposure(it.ev, hits[i], reach, why)
		hits[i] = p.Suppress.Filter(it.ev, hits[i])
		hits[i] = p.Learn.Calibrate(hits[i]) // 资产漏洞关联之前：有漏洞证据的升级不受校准影响
		if p.Assets != nil && len(hits[i]) > 0 {
			hits[i] = p.enrichAssets(it.ev, hits[i])
		}
		// 资产与漏洞关联可能把命中抬到严重（目标确实存在未修复漏洞），必须再过一次等级裁决：
		// 已拦截的仍然只到高危，未拦截且可判定成功的才维持严重。
		for j := range hits[i] {
			risk.Finalize(&hits[i][j])
		}
	}
	p.Raw.Write(evs, hits)
	results := p.Store.RecordBatch(evs, hits)
	p.processed.Add(int64(len(items)))
	for i, res := range results {
		ev := evs[i]
		if ev.Outbound && len(res.Alerts) == 0 { // 出站流量只有外连威胁情报地址时才产生告警
			continue
		}
		for _, a := range res.Alerts {
			if p.OnAlert != nil {
				p.OnAlert(a)
			}
			// 告警事件推送：按各机器人选择的等级过滤，同一 IP、规则、研判结果在去重窗口内只推送一次
			if p.Notifier.Wants(a.Severity) {
				p.Notifier.Notify(a.SrcIP+"|"+a.RuleID+"|"+a.Result, alert.Event{
					Kind: "alert", Severity: a.Severity, Title: a.Name, Category: a.Category, Result: a.Result, Phase: a.Phase,
					IP: a.SrcIP, Location: a.Location, Target: a.Target, Method: a.Method, Status: a.Status, Evidence: a.Evidence,
					Score: res.Score, Source: a.Source, Time: a.Time,
					Asset: assetText(a), Vuln: a.Vuln,
				})
			}
		}
		if (res.LevelUp || res.NewIP) && res.Level >= p.EnrichLevel && res.Level > model.SevInfo && p.Geo != nil {
			p.Geo.Enrich(ev.SrcIP)
		}
		// 攻击源威胁等级升级：仅在等级因多次攻击累积而高于本次命中的最高等级时推送
		// （由单条高危 / 严重告警直接触发的升级已由该告警本身推送，不重复）
		if res.LevelUp && res.Level >= model.SevMedium && res.Level > maxHitSev(hits[i]) && p.Notifier.Wants(res.Level) {
			if s, ok := p.Store.Summary(ev.SrcIP); ok {
				p.Notifier.Notify("escalation|"+s.IP+"|"+s.Level.String(), alert.Event{
					Kind: "escalation", Severity: s.Level, Title: "攻击源威胁等级升至" + s.Level.Label(), IP: s.IP, Location: s.Location,
					Score: s.Score, Attacks: s.Attacks, Categories: s.Categories, Time: s.LastSeen,
				})
			}
		}
	}
}

// internalTarget 在内网资产台账中使用 DNAT 映射后的私网地址匹配：
// 防火墙日志记录的是公网侧的目标地址，直接用它查资产会永远匹配不到内网资产。
// 仅当配置了精确映射（public_ip + public_port → private_ip）时生效，返回事件副本，不修改调用方数据。
func (p *Pipeline) internalTarget(ev *model.Event) *model.Event {
	// 防火墙日志记录了 DNAT 后的地址时直接使用（无需手工登记映射）
	if ev.NatDstIP != "" && ev.NatDstIP != ev.DstIP && geo.IsPrivate(ev.NatDstIP) {
		cp := *ev
		cp.DstIP = ev.NatDstIP
		return &cp
	}
	m, ok := p.Exposure.Lookup(ev.DstIP, ev.DstPort, ev.Proto)
	if !ok || m == nil || m.PrivateIP == "" || m.PrivateIP == ev.DstIP {
		return ev
	}
	cp := *ev
	cp.DstIP = m.PrivateIP
	if m.PrivatePort > 0 {
		cp.DstPort = m.PrivatePort
	}
	return &cp
}

// enrichAssets 为攻击事件标注目标资产，并关联目标上未修复的漏洞：
// 攻击利用的 CVE 在目标上存在时提升为严重，未被拦截时判定为疑似成功；攻击类型 / 组件与目标上的高危漏洞一致时等级提升一级。
// 需要修改命中时复制切片，不修改调用方的数据。
func (p *Pipeline) enrichAssets(ev *model.Event, hits []model.Hit) []model.Hit {
	attack := false
	for i := range hits {
		attack = attack || !hits[i].TagOnly
	}
	if !attack {
		return hits
	}
	mt := p.Assets.Lookup(p.internalTarget(ev))
	if mt == nil {
		return hits
	}
	if a := mt.Asset; a != nil {
		ev.Asset = &model.AssetRef{Name: a.Name, Level: a.Importance, Owner: a.Owner}
	}
	var out []model.Hit
	for i := range hits {
		v, exact := mt.Correlate(&hits[i])
		if v == nil {
			continue
		}
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		h := &out[i]
		h.Vuln = v.Name
		if len(v.CVE) > 0 && !strings.Contains(v.Name, v.CVE[0]) {
			h.Vuln = v.CVE[0] + " " + v.Name
		}
		switch {
		case exact:
			// 精确命中：目标确实存在该漏洞。是否达到「严重」交由统一策略判断——
			// 已拦截的探测只到高危，未拦截且分类可判定成功的才升为严重。
			// 已拦截、或响应表明请求失败（如 404：利用的路径不存在、防火墙会话无应答）的不改判为成功
			if h.Result != model.ResultBlocked && h.Result != model.ResultFailed {
				h.Result = model.ResultSuccess
			}
			if h.Severity < model.SevHigh {
				h.Severity = model.SevHigh
			}
			h.Evidence = truncEvidence(h.Evidence + "；目标存在该漏洞且未修复")
		case v.Severity >= model.SevHigh && h.Severity < model.SevHigh:
			h.Severity = model.SevHigh
			h.Evidence = truncEvidence(h.Evidence + "；目标存在同类未修复漏洞")
		}
	}
	if out == nil {
		return hits
	}
	return out
}

// assetText 是告警推送中的目标资产描述。
func assetText(a *model.Alert) string {
	if a.Asset == "" {
		return ""
	}
	s := a.Asset + "（" + assets.LevelLabel[a.AssetLevel]
	if a.Owner != "" {
		s += "，负责人 " + a.Owner
	}
	return s + "）"
}

func truncEvidence(s string) string {
	if len(s) <= 400 {
		return s
	}
	n := 400
	for n > 0 && !utf8.RuneStart(s[n]) { // 不截断多字节字符
		n--
	}
	return s[:n]
}

// maxHitSev 返回命中中的最高攻击等级（不含仅打标签的命中）。
func maxHitSev(hits []model.Hit) model.Severity {
	m := model.SevInfo
	for _, h := range hits {
		if !h.TagOnly && h.Severity > m {
			m = h.Severity
		}
	}
	return m
}

// gateExposure 过滤「目标端口并未对外发布」的探测类命中。
//
// 互联网背景扫描会持续探测 1433 / 6379 / 3389 等端口，防火墙通常只是按默认策略记录并放行；
// 如果该端口没有 DNAT 映射，探测不可能到达任何服务，把它记成一条高危告警只会淹没有效信号。
// 这类命中降级为仅打标签（不生成告警、不计入威胁评分与攻击统计），仍然保留在画像标签与
// 攻击面的被探测端口统计中，便于事后回溯。
//
// 判断依据分两层：
//  1. 防火墙日志自身记录的会话证据（安全域、DNAT 后地址、应答包数，见 exposure.Reach）：
//     表明没有到达服务的降级为仅打标签；表明到达了服务（或打到防火墙自身）的保持告警，不再按清单过滤。
//  2. 没有会话证据时，按手工登记的 DNAT 清单（exposure.enabled）判断。
func (p *Pipeline) gateExposure(ev *model.Event, hits []model.Hit, reach exposure.Verdict, why string) []model.Hit {
	if ev.Kind != model.KindFirewall || len(hits) == 0 {
		return hits
	}
	switch reach {
	case exposure.ReachNo:
		out := rewriteProbes(hits, func(h *model.Hit) {
			h.TagOnly = true
			h.Severity = model.SevInfo
			h.Evidence = truncEvidence(h.Evidence + "；防火墙放行" + policyText(ev) + "，但" + why + "，不计入攻击统计")
		})
		if out != nil {
			p.Exposure.AddUnreached()
			return out
		}
		return hits
	case exposure.ReachDevice:
		// 打到防火墙自身的管理 / VPN 服务端口：互联网扫描的单次探测不可处置，只打标签；
		// 「管理服务对公网放行」作为暴露面风险单独记录（攻击面），针对该端口的暴力破解等行为照常告警
		out := rewriteSingleProbes(hits, func(h *model.Hit) {
			h.TagOnly = true
			h.Severity = model.SevInfo
			h.Evidence = truncEvidence(h.Evidence + "；会话证据：" + why + "，已作为暴露面风险记录（攻击面分析），单次探测不计入攻击统计")
		})
		if out != nil {
			p.Exposure.AddUnreached()
			return out
		}
		return hits
	case exposure.ReachYes:
		suffix := "；会话证据：" + why
		if out := rewriteProbes(hits, func(h *model.Hit) { h.Evidence = truncEvidence(h.Evidence + suffix) }); out != nil {
			return out
		}
		return hits
	}
	if !p.Exposure.Enforcing() {
		return hits
	}
	// 目标是内网地址：说明已经过 DNAT，或本身就是东西向流量，按真实暴露处理
	if ev.DstIP == "" || geo.IsPrivate(ev.DstIP) {
		return hits
	}
	if _, ok := p.Exposure.Lookup(ev.DstIP, ev.DstPort, ev.Proto); ok {
		return hits
	}
	out := rewriteProbes(hits, func(h *model.Hit) {
		h.TagOnly = true
		h.Severity = model.SevInfo
		h.Evidence = truncEvidence(h.Evidence + "；目标 " + ev.DstIP + ":" + strconv.Itoa(ev.DstPort) +
			" 未配置对外映射（DNAT），该端口没有对外服务，不计入攻击统计")
	})
	if out == nil {
		return hits
	}
	p.Exposure.AddMuted()
	return out
}

// reachOf 按会话证据判断一次放行的外部访问是否到达了服务。只看外部来源被放行的访问：
// 被拦截的访问已按拦截处理，内网来源属于东西向流量。
func (p *Pipeline) reachOf(ev *model.Event) (exposure.Verdict, string) {
	if !p.Exposure.ReachCheck() || ev.Action != model.ActionAllow || ev.SrcIP == "" || geo.IsPrivate(ev.SrcIP) {
		return exposure.ReachUnknown, ""
	}
	return p.Exposure.Reach(ev)
}

// rewriteProbes 复制命中切片（不修改调用方的数据），对依赖「目标端口确有服务」的命中执行 fn；没有这类命中时返回 nil。
func rewriteProbes(hits []model.Hit, fn func(h *model.Hit)) []model.Hit {
	var out []model.Hit
	for i := range hits {
		if !exposureFilterable(hits[i]) {
			continue
		}
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		fn(&out[i])
	}
	return out
}

// rewriteSingleProbes 与 rewriteProbes 相同，但只处理单次的端口探测（不含端口级暴力破解等行为检测）。
func rewriteSingleProbes(hits []model.Hit, fn func(h *model.Hit)) []model.Hit {
	var out []model.Hit
	for i := range hits {
		if hits[i].Category != detect.CatRiskService && hits[i].Category != detect.CatIoT {
			continue
		}
		if out == nil {
			out = append([]model.Hit(nil), hits...)
		}
		fn(&out[i])
	}
	return out
}

// policyText 返回防火墙日志中命中的策略描述，例如「（策略：允许本地上外网）」。
func policyText(ev *model.Event) string {
	if ev.Policy == "" {
		return ""
	}
	return "（策略：" + ev.Policy + "）"
}

// exposureFilterable 判断命中是否依赖「目标端口确有服务」这一前提：只有端口探测与端口级
// 暴力破解会被未发布端口过滤；设备（IPS/IDS/WAF）明确判定的威胁、端口扫描、主机探测与
// 流量洪泛仍然告警——它们反映的是攻击者行为，与目标是否开放无关。
func exposureFilterable(h model.Hit) bool {
	switch h.Category {
	case detect.CatRiskService, detect.CatIoT:
		return true
	}
	return h.RuleID == "bhv-fwbrute"
}

// OnGeoUpdate 在在线溯源 / rDNS 完成后更新画像，并根据 rDNS 识别测绘机构与搜索引擎。
// 需在启动定位器前赋给 geo.Resolver.OnUpdate。
func (p *Pipeline) OnGeoUpdate(ip string, info *geo.Info) {
	p.Store.UpdateGeo(ip, info)
	if name := intel.ClassifyRDNS(info.RDNS); name != "" {
		tag := "网络空间测绘: " + name
		if intel.IsSearchEngine(name) {
			tag = "搜索引擎爬虫: " + name
		}
		p.Store.Tag(ip, tag, info.RDNS)
	}
	if info.Proxy {
		p.Store.Tag(ip, "代理/VPN出口", "")
	}
	if info.Hosting {
		p.Store.Tag(ip, "IDC/云主机", info.ISP)
	}
}
