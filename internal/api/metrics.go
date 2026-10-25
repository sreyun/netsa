package api

import (
	"bytes"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netsa/internal/model"
)

// promWriter 生成 Prometheus 文本格式（text/plain; version=0.0.4）。
type promWriter struct {
	b    bytes.Buffer
	seen map[string]bool
}

func promEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// metric 写一个样本；同名指标的 HELP / TYPE 只输出一次。labels 为成对的键、值。
func (p *promWriter) metric(name, typ, help string, v float64, labels ...string) {
	if !p.seen[name] {
		p.seen[name] = true
		p.b.WriteString("# HELP " + name + " " + help + "\n# TYPE " + name + " " + typ + "\n")
	}
	p.b.WriteString(name)
	if len(labels) > 0 {
		p.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				p.b.WriteByte(',')
			}
			p.b.WriteString(labels[i] + `="` + promEscape(labels[i+1]) + `"`)
		}
		p.b.WriteByte('}')
	}
	p.b.WriteByte(' ')
	p.b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	p.b.WriteByte('\n')
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
	p := &promWriter{seen: map[string]bool{}}
	p.metric("netsa_build_info", "gauge", "版本信息", 1, "version", s.Version)
	p.metric("netsa_uptime_seconds", "gauge", "运行时长（秒）", time.Since(s.started).Seconds())
	p.metric("netsa_events_processed_total", "counter", "已处理的日志事件数", float64(s.Pipeline.Processed()))

	for _, st := range s.Ingest.Stats() {
		l := []string{"source", st.Name, "type", st.Type}
		p.metric("netsa_source_lines_total", "counter", "数据源读取的日志行数", float64(st.Lines), l...)
		p.metric("netsa_source_parsed_total", "counter", "数据源解析成功的行数", float64(st.Parsed), l...)
		p.metric("netsa_source_failed_total", "counter", "数据源无法解析的行数", float64(st.Failed), l...)
		p.metric("netsa_source_skipped_total", "counter", "数据源跳过的行数（注释、空行等）", float64(st.Skipped), l...)
		p.metric("netsa_source_silent", "gauge", "数据源是否断流（超过阈值没有新日志）", b2f(st.Silent), l...)
		p.metric("netsa_source_up", "gauge", "数据源是否正常运行（跟踪 / 监听中）", b2f(st.Status == "tailing" || st.Status == "listening" || st.Status == "done"), l...)
		p.metric("netsa_source_last_event_timestamp_seconds", "gauge", "数据源最新一条日志的时间", unixSec(st.LastEvent), l...)
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
	}
	if s.Archive != nil {
		failed, dropped, _ := s.Archive.Health()
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
	w.Write(p.b.Bytes())
}
