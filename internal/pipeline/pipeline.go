// Package pipeline 将采集、真实 IP 还原、特征检测、行为分析、画像存储、溯源与告警串联起来。
package pipeline

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"netsa/internal/alert"
	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/intel"
	"netsa/internal/model"
	"netsa/internal/safe"
	"netsa/internal/store"
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
	if p.whitelisted(ev.SrcIP) {
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
	}
	results := p.Store.RecordBatch(evs, hits)
	p.processed.Add(int64(len(items)))
	for i, res := range results {
		ev := evs[i]
		if ev.Outbound {
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
