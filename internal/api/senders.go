package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"netsa/internal/alert"
	"netsa/internal/ingest"
	"netsa/internal/model"
)

// syslogSenders 返回 syslog 发送端：白名单开关、登记规则、发送端画像与分组汇总。
func (s *Server) syslogSenders(w http.ResponseWriter, r *http.Request) {
	if s.Ingest.Senders == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	rep := s.Ingest.Senders.Report()
	writeJSON(w, map[string]any{"enabled": s.Cfg.Syslog.Enabled, "listen": map[string]string{"udp": s.Cfg.Syslog.UDP, "tcp": s.Cfg.Syslog.TCP, "tls": s.Cfg.Syslog.TLS},
		"mutual_tls": s.Cfg.Syslog.TLSClientCA != "", "report": rep})
}

type senderForm struct {
	CIDR    string `json:"cidr"`
	Name    string `json:"name"`
	Group   string `json:"group"`
	Action  string `json:"action"`
	Silence string `json:"silence"`
	Note    string `json:"note"`
}

func (f senderForm) rule() ingest.SenderRule {
	return ingest.SenderRule{CIDR: f.CIDR, Name: f.Name, Group: f.Group, Action: f.Action, Silence: f.Silence, Note: f.Note}
}

func senderAction(a string) string {
	if a == ingest.SenderBlock {
		return "阻止"
	}
	return "允许"
}

func (s *Server) senderError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingest.ErrNoSenderRule):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ingest.ErrSenderConfig), errors.Is(err, ingest.ErrAllowForced):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ingest.ErrSenderDup):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func (s *Server) sendersReady(w http.ResponseWriter) bool {
	if s.Ingest == nil || s.Ingest.Senders == nil {
		writeError(w, http.StatusServiceUnavailable, "syslog 发送端管理未启用")
		return false
	}
	return true
}

func (s *Server) senderCreate(w http.ResponseWriter, r *http.Request) {
	if !s.sendersReady(w) {
		return
	}
	var f senderForm
	if !decodeForm(w, r, &f) {
		return
	}
	user := ""
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	rule, err := s.Ingest.Senders.AddRule(f.rule(), user)
	s.audit(r, "登记 syslog 发送端", f.CIDR+" "+f.Name+"（"+senderAction(f.Action)+"，分组 "+orDash(f.Group)+"）", err)
	if err != nil {
		s.senderError(w, err)
		return
	}
	writeJSON(w, rule)
}

func (s *Server) senderUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.sendersReady(w) {
		return
	}
	var f senderForm
	if !decodeForm(w, r, &f) {
		return
	}
	rule, err := s.Ingest.Senders.UpdateRule(r.PathValue("id"), f.rule())
	s.audit(r, "修改 syslog 发送端", f.CIDR+" "+f.Name+"（"+senderAction(f.Action)+"，分组 "+orDash(f.Group)+"）", err)
	if err != nil {
		s.senderError(w, err)
		return
	}
	writeJSON(w, rule)
}

func (s *Server) senderDelete(w http.ResponseWriter, r *http.Request) {
	if !s.sendersReady(w) {
		return
	}
	rule, err := s.Ingest.Senders.DeleteRule(r.PathValue("id"))
	s.audit(r, "删除 syslog 发送端", rule.CIDR+" "+rule.Name, err)
	if err != nil {
		s.senderError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// senderPolicy 开启 / 关闭发送端白名单：{"allowlist": true, "include_active": true}。
func (s *Server) senderPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.sendersReady(w) {
		return
	}
	var f struct {
		Allowlist     bool `json:"allowlist"`
		IncludeActive bool `json:"include_active"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	user := ""
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	n, err := s.Ingest.Senders.SetAllowlist(f.Allowlist, f.IncludeActive, user)
	detail := "关闭"
	if f.Allowlist {
		detail = "开启"
		if n > 0 {
			detail += "，自动登记 " + strconv.Itoa(n) + " 个活跃发送端"
		}
	}
	s.audit(r, "syslog 发送端白名单", detail, err)
	if err != nil {
		s.senderError(w, err)
		return
	}
	writeJSON(w, map[string]any{"allowlist": f.Allowlist, "added": n})
}

// pushSenderNotices 推送 syslog 发送端通知：未授权发送端被拒绝、新发送端、登记设备断流与恢复。
func (s *Server) pushSenderNotices() {
	if s.Ingest == nil {
		return
	}
	for _, n := range s.Ingest.Senders.TakeNotices() {
		who := n.IP
		if n.Name != "" {
			who = n.Name + "（" + n.IP + "）"
		}
		ev := alert.Event{Kind: "notice", Link: "#tab=sources", Time: time.Now(), Lines: []string{"发送端：" + who}}
		if n.Group != "" {
			ev.Lines = append(ev.Lines, "分组："+n.Group)
		}
		switch n.Kind {
		case "rejected":
			ev.Severity, ev.Title = model.SevMedium, "未授权的 syslog 发送端 "+n.IP
			ev.Lines = append(ev.Lines, "说明："+n.Detail,
				"处置建议：确认是否为新接入的设备，是则在“数据源 → Syslog 发送端”中登记；否则排查该地址（可能是伪造日志或探测）")
		case "new":
			ev.Severity, ev.Title = model.SevLow, "发现新的 syslog 发送端 "+n.IP
			ev.Lines = append(ev.Lines, "说明："+n.Detail, "处置建议：在“数据源 → Syslog 发送端”中登记设备名称与分组；如需只接收已登记设备的日志，可开启发送端白名单")
		case "silent":
			ev.Severity, ev.Title = model.SevHigh, "数据源断流 "+who
			ev.Lines = append(ev.Lines, "说明："+n.Detail, "最后收到日志："+n.Last.In(s.now().Location()).Format("2006-01-02 15:04:05"),
				"影响：该设备上发生的攻击将无法被感知（监测盲区）", "处置建议：检查设备 syslog 配置、网络连通性与设备运行状态")
		case "recovered":
			ev.Severity, ev.Title = model.SevHigh, "数据源已恢复 "+who
			ev.Lines = append(ev.Lines, "说明："+n.Detail)
		default:
			continue
		}
		s.Notifier.Notify("", ev)
	}
}

// pushSourceNotices 推送数据源断流 / 恢复、解析失败率过高与告警归档异常。
func (s *Server) pushSourceNotices() {
	if s.Ingest == nil {
		return
	}
	now := time.Now()
	for _, n := range s.Ingest.CheckSilence(now) {
		ev := alert.Event{Kind: "notice", Link: "#tab=sources", Time: now, Lines: []string{"数据源：" + n.Source, "说明：" + n.Detail}}
		switch n.Kind {
		case "silent":
			ev.Severity, ev.Title = model.SevHigh, "数据源断流 "+n.Source
			ev.Lines = append(ev.Lines, "最后读到日志："+n.Last.In(s.now().Location()).Format("2006-01-02 15:04"),
				"影响：该数据源覆盖的业务上发生的攻击将无法被感知（监测盲区）", "处置建议：检查日志文件是否被移动 / 停止写入、采集权限与磁盘空间")
		case "recovered":
			ev.Severity, ev.Title = model.SevHigh, "数据源已恢复 "+n.Source
		case "parse_errors":
			ev.Severity, ev.Title = model.SevMedium, "日志解析失败率过高 "+n.Source
			ev.Lines = append(ev.Lines, "处置建议：在“数据源”页查看无法解析的样例日志，确认 nginx log_format 或设备日志格式是否变更")
		default:
			continue
		}
		s.Notifier.Notify("", ev)
	}
	if s.Archive == nil {
		return
	}
	failed, dropped, lastErr := s.Archive.Health()
	h := &s.archHealth
	switch {
	case dropped > h.dropped && now.Sub(h.alerted) >= time.Hour:
		h.alerted = now
		s.Notifier.Notify("", alert.Event{Kind: "notice", Severity: model.SevHigh, Title: "告警归档队列已满，部分告警未归档", Link: "#tab=archive", Time: now,
			Lines: []string{"本分钟丢弃：" + strconv.FormatInt(dropped-h.dropped, 10) + " 条", "最近错误：" + orDash(lastErr),
				"处置建议：检查 PostgreSQL 是否可用、写入是否变慢，必要时增大 archive.queue_size"}})
	case failed > h.failed:
		h.failing++
		if h.failing == 3 && now.Sub(h.alerted) >= time.Hour { // 连续 3 分钟写入失败
			h.alerted, h.down = now, true
			s.Notifier.Notify("", alert.Event{Kind: "notice", Severity: model.SevHigh, Title: "告警归档写入失败", Link: "#tab=archive", Time: now,
				Lines: []string{"说明：已连续 3 分钟写入 PostgreSQL 失败，告警暂存于内存队列", "最近错误：" + orDash(lastErr)}})
		}
	default:
		h.failing = 0
		if h.down {
			h.down = false
			s.Notifier.Notify("", alert.Event{Kind: "notice", Severity: model.SevHigh, Title: "告警归档已恢复写入", Link: "#tab=archive", Time: now,
				Lines: []string{"说明：PostgreSQL 写入已恢复正常"}})
		}
	}
	h.failed, h.dropped = failed, dropped
}

// archiveHealth 是告警归档异常检测的状态（仅后台任务访问）。
type archiveHealth struct {
	failed, dropped int64
	failing         int
	down            bool
	alerted         time.Time
}
