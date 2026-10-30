package api

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsa/internal/alert"
	"netsa/internal/auth"
	"netsa/internal/learn"
	"netsa/internal/model"
	"netsa/internal/store"
	"netsa/internal/suppress"
)

// learnFeedback 把分析员的处置结论交给自学习：已处置为确认攻击，误报为误报，其余状态（重新打开、忽略）撤回之前的结论。
// 批量处置（最多 500 个事件）的结论一次交给自学习，只重算、落盘一次。
func (s *Server) learnFeedback(list []store.IncidentView, user string) {
	if s.Learn == nil {
		return
	}
	cases := make([]learn.Case, 0, len(list))
	for _, v := range list {
		verdict := learn.VerdictNone
		switch v.Status {
		case store.IncResolved:
			verdict = learn.VerdictTP
		case store.IncFalsePositive:
			verdict = learn.VerdictFP
		}
		c := learn.Case{Incident: v.ID, Source: v.Key, Verdict: verdict, User: user, Rules: map[string]int{}}
		if verdict != learn.VerdictNone {
			d := s.Store.Incident(v.ID)
			if d == nil {
				continue
			}
			for _, kv := range d.Rules {
				id, _, _ := strings.Cut(kv.Name, " ") // 事件中的规则名为「规则 ID 规则名称」
				c.Rules[id] += int(kv.Value)
			}
			for i, kv := range d.Targets {
				if i == 5 {
					break
				}
				c.Targets = append(c.Targets, kv.Name)
			}
		}
		cases = append(cases, c)
	}
	s.Learn.Feedback(cases...)
}

// learnReport 返回自学习状态：规则准确率、自动校准、待确认的建议、进化日志、平台安全异常与合规趋势。
func (s *Server) learnReport(w http.ResponseWriter, r *http.Request) {
	rep := s.Learn.Report()
	// 已有相同条件的抑制规则时不再提示
	if s.Suppress != nil && len(rep.Suggestions) > 0 {
		exist := map[string]bool{}
		for _, x := range s.Suppress.List() {
			exist[x.RuleID+"|"+strings.ToLower(x.Target)+"|"+x.IP] = true
		}
		out := rep.Suggestions[:0]
		for _, sg := range rep.Suggestions {
			if !exist[sg.RuleID+"|"+strings.ToLower(sg.Target)+"|"+sg.IP] {
				out = append(out, sg)
			}
		}
		rep.Suggestions = out
	}
	writeJSON(w, map[string]any{"enabled": s.Learn != nil, "report": rep})
}

// learnSuggestion 采纳（创建误报抑制）或忽略一条自学习建议。采纳等同于人工添加抑制规则，需要运营分析员以上权限。
func (s *Server) learnSuggestion(w http.ResponseWriter, r *http.Request) {
	if s.Learn == nil {
		writeError(w, http.StatusNotFound, "未启用自学习")
		return
	}
	id, act := r.PathValue("id"), r.PathValue("action")
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	sg, ok := s.Learn.Suggestion(id)
	if !ok {
		writeError(w, http.StatusNotFound, learn.ErrNoSuggestion.Error())
		return
	}
	switch act {
	case "apply":
		if s.Suppress == nil {
			writeError(w, http.StatusBadRequest, "未启用误报抑制")
			return
		}
		rule, err := s.Suppress.Add(suppress.Rule{RuleID: sg.RuleID, IP: sg.IP, Target: sg.Target, Reason: sg.Reason, Creator: user}, 0)
		s.audit(r, "添加误报抑制", describeSuppress(sg.RuleID, "", sg.IP, sg.Target)+" 原因：采纳"+sg.Reason, err)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.Learn.Resolve(id, user, "apply")
		writeJSON(w, map[string]any{"ok": true, "rule": rule})
	case "dismiss":
		err := s.Learn.Resolve(id, user, "dismiss")
		s.audit(r, "忽略自学习建议", sg.Reason, err)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusNotFound, "未知操作")
	}
}

// learnPin 锁定 / 解锁规则（管理员）：锁定的规则不参与自动校准，已下调的立即恢复。
func (s *Server) learnPin(w http.ResponseWriter, r *http.Request) {
	if s.Learn == nil {
		writeError(w, http.StatusNotFound, "未启用自学习")
		return
	}
	rule := strings.TrimSpace(r.PathValue("rule"))
	if rule == "" || len(rule) > 128 {
		writeError(w, http.StatusBadRequest, "规则 ID 无效")
		return
	}
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	pin := r.PathValue("action") == "pin"
	s.Learn.Pin(rule, user, pin)
	act := "锁定规则（不参与自动校准）"
	if !pin {
		act = "解锁规则（恢复自动校准）"
	}
	s.audit(r, act, rule, nil)
	writeJSON(w, map[string]any{"ok": true})
}

// learnTick 由后台任务每分钟调用：每小时执行一次合规自检，每天凌晨校验审计链完整性，并保存学习状态。
func (s *Server) learnTick(now time.Time) {
	if s.Learn == nil {
		return
	}
	if s.Cfg.Learn.ComplianceOn() && (s.lastComp.IsZero() || now.Sub(s.lastComp) >= time.Hour) {
		s.lastComp = now
		s.complianceWatch(now)
	}
	if s.Cfg.Learn.ComplianceOn() && s.Trail != nil && now.Hour() == 3 && s.lastVerify != now.Format("2006-01-02") {
		s.lastVerify = now.Format("2006-01-02")
		if v := s.Trail.Verify(); !v.OK {
			title := "审计日志完整性自检失败"
			s.notify("audit-verify", alert.Event{Kind: "notice", Severity: model.SevHigh, Title: title, Link: "#tab=audit", Time: now,
				Lines: append([]string{"审计链可能被篡改或文件缺失，请立即核查（系统管理 → 审计日志 → 校验完整性）"}, firstN(v.Problems, 5)...)})
			s.Trail.AppendAudit(auth.Record{Time: now, User: "系统", Action: "审计链自检", Detail: title + "：" + strings.Join(firstN(v.Problems, 3), "；"), OK: false})
		}
	}
	if err := s.Learn.Save(); err != nil {
		log.Printf("[learn] 保存学习状态失败: %v", err)
	}
}

func firstN(list []string, n int) []string {
	if len(list) > n {
		return list[:n]
	}
	return list
}

// complianceWatch 执行一次等保合规自检，测评项结果下降时推送告警并记入审计链。
func (s *Server) complianceWatch(now time.Time) {
	rep := s.BuildCompliance()
	items := make([]learn.CompItem, 0, len(rep.Items))
	for _, it := range rep.Items {
		items = append(items, learn.CompItem{Control: it.Control, Status: it.Status, Label: it.Label, Evidence: it.Evidence, Advice: it.Advice})
	}
	var down []learn.CompChange
	for _, c := range s.Learn.CheckCompliance(items, rep.Rate, now) {
		if c.Degraded {
			down = append(down, c)
		}
	}
	if len(down) == 0 {
		return
	}
	sev := model.SevMedium
	lines := []string{"符合率：" + strconv.FormatFloat(rep.Rate*100, 'f', 0, 64) + "%"}
	for i, c := range down {
		if c.To == "fail" {
			sev = model.SevHigh
		}
		if i < 6 {
			lines = append(lines, c.Control+"："+compLabel[c.From]+" → "+compLabel[c.To]+"（"+c.Evidence+"）")
		}
	}
	if len(down) > 6 {
		lines = append(lines, "另有 "+strconv.Itoa(len(down)-6)+" 项，请在报表合规页查看")
	}
	title := strconv.Itoa(len(down)) + " 个等保测评项结果下降"
	s.notify("compliance|"+now.Format("2006010215"), alert.Event{Kind: "notice", Severity: sev, Title: "合规自检：" + title,
		Link: "#tab=reports", Time: now, Lines: lines})
	if s.Trail != nil {
		s.Trail.AppendAudit(auth.Record{Time: now, User: "系统", Action: "合规自检", Detail: title + "：" + strings.Join(lines[1:], "；"), OK: false})
	}
}

// PlatformAnomaly 推送平台自身的安全异常（由审计链包装器回调，必须非阻塞）。
func (s *Server) PlatformAnomaly(a learn.Anomaly) {
	s.notify("platform|"+a.Kind+"|"+a.User, alert.Event{Kind: "notice", Severity: a.Severity, Title: "平台安全：" + a.Title,
		Link: "#tab=learn", Time: a.Time, Lines: []string{a.Detail, "账号：" + a.User, "来源：" + orDash(a.IP)}})
}

// notify 推送一条通知（未配置推送时忽略）。
func (s *Server) notify(key string, ev alert.Event) {
	if s.Notifier != nil {
		s.Notifier.Notify(key, ev)
	}
}
