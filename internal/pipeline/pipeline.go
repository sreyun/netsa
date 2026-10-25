// Package pipeline 将采集、真实 IP 还原、特征检测、行为分析、画像存储、溯源与告警串联起来。
package pipeline

import (
	"context"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"netsa/internal/alert"
	"netsa/internal/assets"
	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/intel"
	"netsa/internal/model"
	"netsa/internal/rawlog"
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
			h.Result = detect.WebResult(ev, 1)
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
		hits[i] = p.Suppress.Filter(it.ev, hits[i])
		if p.Assets != nil && len(hits[i]) > 0 {
			hits[i] = p.enrichAssets(it.ev, hits[i])
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
	mt := p.Assets.Lookup(ev)
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
			h.Severity = model.SevCritical
			if h.Result == model.ResultPassed || h.Result == model.ResultUnknown || h.Result == model.ResultError || h.Result == model.ResultAllowed || h.Result == "" {
				h.Result = model.ResultSuccess
			}
			h.Evidence = truncEvidence(h.Evidence + "；目标存在该漏洞且未修复")
		case v.Severity >= model.SevHigh && h.Severity < model.SevCritical:
			h.Severity++
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
