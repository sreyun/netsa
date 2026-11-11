package api

import (
	"bytes"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netsa/internal/model"
	"netsa/internal/risk"
)

// promWriter 生成 Prometheus 文本格式（text/plain; version=0.0.4）。
// 同一指标的样本集中输出（格式要求一个指标的所有行连在一起），HELP / TYPE 只输出一次；
// 标签完全相同的重复样本只保留第一条（重复的序列会让采集端报错或丢弃样本）。
type promWriter struct {
	order []string                 // 指标名，按第一次出现的顺序
	fam   map[string]*bytes.Buffer // 指标名 → HELP / TYPE 与样本
	dup   map[string]bool          // 已输出的序列（指标名 + 标签）
}

func newPromWriter() *promWriter {
	return &promWriter{fam: map[string]*bytes.Buffer{}, dup: map[string]bool{}}
}

func promEscape(s string) string {
	return strings.NewReplacer(`\`, `\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// metric 写一个样本。labels 为成对的键、值。
func (p *promWriter) metric(name, typ, help string, v float64, labels ...string) {
	var series strings.Builder
	series.WriteString(name)
	if len(labels) > 1 {
		series.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				series.WriteByte(',')
			}
			series.WriteString(labels[i] + `="` + promEscape(labels[i+1]) + `"`)
		}
		series.WriteByte('}')
	}
	key := series.String()
	if p.dup[key] {
		return
	}
	p.dup[key] = true
	b := p.fam[name]
	if b == nil {
		b = &bytes.Buffer{}
		b.WriteString("# HELP " + name + " " + help + "\n# TYPE " + name + " " + typ + "\n")
		p.fam[name] = b
		p.order = append(p.order, name)
	}
	b.WriteString(key)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	b.WriteByte('\n')
}

// bytes 按指标第一次出现的顺序输出全部内容。
func (p *promWriter) bytes() []byte {
	var out bytes.Buffer
	for _, name := range p.order {
		out.Write(p.fam[name].Bytes())
	}
	return out.Bytes()
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func unixSec(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixMilli()) / 1000
}

// metrics 输出 Prometheus 指标：采集与数据源健康、syslog 发送端、检测与告警、事件处置、误报抑制、推送与归档、运行时。
// 可用会话、Basic 认证或 API 令牌（推荐创建“指标采集”角色的只读令牌）访问。
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	p := newPromWriter()
	p.metric("netsa_build_info", "gauge", "版本信息", 1, "version", s.Version)
	p.metric("netsa_uptime_seconds", "gauge", "运行时长（秒）", time.Since(s.started).Seconds())
	for _, f := range s.Forward.Stats() {
		p.metric("netsa_forward_sent_total", "counter", "转发到 SIEM 的告警数", float64(f.Sent), "target", f.Name)
		p.metric("netsa_forward_dropped_total", "counter", "因队列已满未能转发的告警数", float64(f.Dropped), "target", f.Name)
		p.metric("netsa_forward_failed_total", "counter", "转发失败次数", float64(f.Failed), "target", f.Name)
	}
	if s.Block != nil {
		pending, active := s.Block.Counts()
		p.metric("netsa_block_pending", "gauge", "待审批的封禁申请数", float64(pending))
		p.metric("netsa_block_active", "gauge", "生效中的封禁数", float64(active))
		p.metric("netsa_block_webhook_failed_total", "counter", "封禁 Webhook 推送失败次数", float64(s.Block.WebhookFailed()))
	}
	if s.Playbooks != nil {
		runs, dropped := s.Playbooks.Stats()
		p.metric("netsa_playbook_runs_total", "counter", "处置剧本执行次数", float64(runs))
		p.metric("netsa_playbook_dropped_total", "counter", "因队列已满未能处理的事件数", float64(dropped))
	}
	p.metric("netsa_events_processed_total", "counter", "已处理的日志事件数", float64(s.Pipeline.Processed()))

	// 同名同类型的数据源合并为一条序列：默认配置里 ssh 有两个候选路径（/var/log/auth.log 与 /var/log/secure），
	// 各输出一条的话标签完全相同，采集端会报重复序列。行数相加，任一路径在跟踪即视为正常运行。
	type srcAgg struct {
		name, typ                      string
		lines, parsed, failed, skipped int64
		silent, up                     bool
		last                           time.Time
	}
	var srcs []*srcAgg
	byKey := map[string]*srcAgg{}
	for _, st := range s.Ingest.Stats() {
		key := st.Name + "\x00" + st.Type
		a := byKey[key]
		if a == nil {
			a = &srcAgg{name: st.Name, typ: st.Type}
			byKey[key] = a
			srcs = append(srcs, a)
		}
		a.lines, a.parsed, a.failed, a.skipped = a.lines+st.Lines, a.parsed+st.Parsed, a.failed+st.Failed, a.skipped+st.Skipped
		a.silent = a.silent || st.Silent
		a.up = a.up || st.Status == "tailing" || st.Status == "listening" || st.Status == "done"
		if st.LastEvent.After(a.last) {
			a.last = st.LastEvent
		}
	}
	for _, a := range srcs {
		l := []string{"source", a.name, "type", a.typ}
		p.metric("netsa_source_lines_total", "counter", "数据源读取的日志行数", float64(a.lines), l...)
		p.metric("netsa_source_parsed_total", "counter", "数据源解析成功的行数", float64(a.parsed), l...)
		p.metric("netsa_source_failed_total", "counter", "数据源无法解析的行数", float64(a.failed), l...)
		p.metric("netsa_source_skipped_total", "counter", "数据源跳过的行数（注释、空行等）", float64(a.skipped), l...)
		p.metric("netsa_source_silent", "gauge", "数据源是否断流（超过阈值没有新日志）", b2f(a.silent), l...)
		p.metric("netsa_source_up", "gauge", "数据源是否正常运行（跟踪 / 监听中）", b2f(a.up), l...)
		p.metric("netsa_source_last_event_timestamp_seconds", "gauge", "数据源最新一条日志的时间", unixSec(a.last), l...)
	}
	if ss := s.Ingest.Senders; ss != nil {
		rep := ss.Report()
		t := rep.Totals
		p.metric("netsa_syslog_allowlist_enabled", "gauge", "是否开启 syslog 发送端白名单", b2f(rep.Allowlist))
		for _, kv := range []struct {
			k string
			v int
		}{{"online", t.Online}, {"silent", t.Silent}, {"rejected", t.Rejected}, {"unregistered", t.Unknown}, {"all", t.Senders}} {
			p.metric("netsa_syslog_senders", "gauge", "syslog 发送端数（按状态）", float64(kv.v), "status", kv.k)
		}
		p.metric("netsa_syslog_rejected_messages_total", "counter", "被拒绝的 syslog 消息 / 连接数（未授权或已阻止的发送端）", float64(t.Dropped))
		p.metric("netsa_syslog_rate_limited_total", "counter", "超过单发送端速率上限被丢弃的 syslog 日志数", float64(t.Limited))
		p.metric("netsa_syslog_bytes_total", "counter", "接收的 syslog 字节数", float64(t.Bytes))
		for _, g := range rep.Groups {
			p.metric("netsa_syslog_group_lines_total", "counter", "各分组发送端的日志行数", float64(g.Lines), "group", g.Name)
			p.metric("netsa_syslog_group_silent", "gauge", "各分组中断流的发送端数", float64(g.Silent), "group", g.Name)
		}
	}

	m := s.Store.Metrics()
	p.metric("netsa_events_total", "counter", "记录的事件数（按类型）", float64(m.Totals.Web), "kind", "web")
	p.metric("netsa_events_total", "counter", "记录的事件数（按类型）", float64(m.Totals.Firewall), "kind", "firewall")
	p.metric("netsa_attacks_total", "counter", "攻击命中数", float64(m.Totals.Attacks))
	p.metric("netsa_attacks_blocked_total", "counter", "已拦截的攻击数", float64(m.Totals.Blocked))
	p.metric("netsa_attacks_success_total", "counter", "疑似攻击成功数", float64(m.Totals.Success))
	p.metric("netsa_alerts_total", "counter", "产生的告警数", float64(m.Totals.Alerts))
	if s.Exposure != nil {
		p.metric("netsa_exposure_enabled", "gauge", "是否启用对外发布服务清单（DNAT 映射）", b2f(s.Exposure.Enforcing()))
		p.metric("netsa_exposure_mappings", "gauge", "对外发布服务映射条数", float64(s.Exposure.Count()))
		p.metric("netsa_exposure_muted_total", "counter", "因端口未对外发布而降级为仅打标签的探测数", float64(s.Exposure.Muted()))
		p.metric("netsa_exposure_unreached_total", "counter", "防火墙放行但会话证据表明未到达服务、降级为仅打标签的探测数", float64(s.Exposure.Unreached()))
		p.metric("netsa_exposure_learned", "gauge", "根据会话证据自动识别的对外服务数", float64(s.Exposure.LearnedCount()))
	}

	// 自学习结果在检测中自动生效的次数：rule / target 为按误报结论下调，escalate 为确认攻击源复现升级
	if s.Learn != nil {
		ap := s.Learn.AppliedStats()
		for _, kv := range []struct {
			kind string
			n    int64
		}{{"rule", ap.Rule}, {"target", ap.Target}, {"escalate", ap.Escalated}} {
			p.metric("netsa_learn_applied_total", "counter", "自学习结果自动作用于检测命中的次数", float64(kv.n), "kind", kv.kind)
		}
	}

	// 等级裁决：规则声明与最终判定不一致的次数（按 原等级→最终等级 统计）。
	// 持续出现 critical→high 说明规则把未成功的利用写成了严重；high→critical 说明成功升级在生效。
	for _, a := range risk.Adjustments() {
		p.metric("netsa_severity_adjusted_total", "counter", "威胁等级被策略自动调整的次数",
			float64(a.Count), "from", a.From.String(), "to", a.To.String())
	}

	// 响应缓存：条目数接近上限说明查询参数组合过多（LRU 会淘汰冷键，热键保留）
	if s.cache != nil {
		entries, hits, misses := s.cache.stats()
		p.metric("netsa_response_cache_entries", "gauge", "聚合接口响应缓存条目数（LRU）", float64(entries))
		p.metric("netsa_response_cache_bytes", "gauge", "接口响应缓存占用的字节数", float64(s.cache.size()))
		p.metric("netsa_response_cache_hits_total", "counter", "响应缓存命中次数", float64(hits))
		p.metric("netsa_response_cache_misses_total", "counter", "响应缓存未命中（重新计算）次数", float64(misses))
	}
	if s.Notifier != nil {
		p.metric("netsa_notify_dedup_entries", "gauge", "告警去重表中未过期的键数量", float64(s.Notifier.DedupSize()))
	}

	// 流水线背压：队列长度持续接近容量说明聚合入库跟不上采集速度
	p.metric("netsa_pipeline_queue_depth", "gauge", "事件投递队列中待处理的批次数", float64(s.Ingest.QueueLen()))
	p.metric("netsa_pipeline_queue_capacity", "gauge", "事件投递队列容量", float64(s.Ingest.QueueCap()))
	for i := model.SevLow; i <= model.SevCritical; i++ {
		p.metric("netsa_attacks_by_severity_total", "counter", "各等级的攻击命中数", float64(m.SevCount[i]), "severity", i.String())
		p.metric("netsa_attackers", "gauge", "各威胁等级的攻击源数", float64(m.Attackers[i]), "level", i.String())
	}
	p.metric("netsa_profiles", "gauge", "IP 画像数（含正常访客）", float64(m.Profiles))
	p.metric("netsa_last_log_timestamp_seconds", "gauge", "最新日志时间", unixSec(m.MaxTime))
	if m.Score != nil {
		p.metric("netsa_security_score", "gauge", "最近一次安全评分（0~100）", float64(m.Score.Score))
		p.metric("netsa_compromised_assets", "gauge", "疑似失陷资产数", float64(m.Score.Compromised))
	}
	c := m.Incidents
	for _, kv := range []struct {
		k string
		v int
	}{{"open", c.Open}, {"investigating", c.Investigating}, {"resolved", c.Resolved}, {"false_positive", c.FalsePositive}, {"ignored", c.Ignored}} {
		p.metric("netsa_incidents", "gauge", "安全事件数（按处置状态）", float64(kv.v), "status", kv.k)
	}
	p.metric("netsa_incidents_overdue", "gauge", "超过处置时限仍未关闭的事件数", float64(c.Overdue))
	p.metric("netsa_suppression_rules", "gauge", "误报抑制规则数", float64(s.Suppress.Count()))
	p.metric("netsa_suppressed_hits_total", "counter", "被误报抑制规则过滤的命中数", float64(s.Suppress.Total()))

	for _, rb := range s.Notifier.Info().Robots {
		l := []string{"robot", rb.Name, "type", rb.Type}
		p.metric("netsa_notify_messages_total", "counter", "告警推送成功的消息数", float64(rb.Stats.Messages), l...)
		p.metric("netsa_notify_failed_total", "counter", "告警推送失败的消息数", float64(rb.Stats.Failed), l...)
		p.metric("netsa_notify_queued", "gauge", "等待推送的告警数", float64(rb.Stats.Queued), l...)
		p.metric("netsa_notify_suppressed_total", "counter", "因频率限制被合并汇总的告警数", float64(rb.Stats.Suppressed), l...)
	}
	if s.Archive != nil {
		failed, dropped, _ := s.Archive.Health()
		written, _ := s.Archive.Counts()
		p.metric("netsa_archive_written_total", "counter", "成功归档的告警条数", float64(written))
		p.metric("netsa_archive_failed_batches_total", "counter", "告警归档写入失败的批次数", float64(failed))
		p.metric("netsa_archive_dropped_total", "counter", "因队列已满未能归档的告警数", float64(dropped))
	}

	if s.RawLog != nil {
		written, dropped, n := s.RawLog.Counters()
		p.metric("netsa_rawlog_written_total", "counter", "留存的原始日志条数", float64(written))
		p.metric("netsa_rawlog_dropped_total", "counter", "因写入跟不上未能留存的原始日志条数", float64(dropped))
		p.metric("netsa_rawlog_bytes_total", "counter", "留存的原始日志字节数（压缩前）", float64(n))
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	p.metric("netsa_go_goroutines", "gauge", "goroutine 数", float64(runtime.NumGoroutine()))
	p.metric("netsa_go_heap_bytes", "gauge", "堆内存占用（字节）", float64(ms.HeapAlloc))
	p.metric("netsa_go_sys_bytes", "gauge", "向系统申请的内存（字节）", float64(ms.Sys))
	p.metric("netsa_go_gc_total", "counter", "GC 次数", float64(ms.NumGC))
	p.metric("netsa_geo_queue", "gauge", "等待在线溯源的 IP 数", float64(s.Geo.QueueLen()))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(p.bytes())
}
