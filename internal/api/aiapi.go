package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsa/internal/ai"
	"netsa/internal/auth"
	"netsa/internal/model"
	"netsa/internal/safe"
	"netsa/internal/store"
)

// incidentFacts 把事件整理为发送给模型的摘要（按配置脱敏），并附上平台自学习的规则准确率供参考。
func (s *Server) incidentFacts(d *store.IncidentDetail, m *ai.Masker) string {
	var sb strings.Builder
	line := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			sb.WriteString(k + "：" + m.Mask(v) + "\n")
		}
	}
	loc := s.now().Location()
	line("事件", "#"+strconv.FormatUint(d.ID, 10)+" "+d.Title)
	line("攻击来源", d.Key+"（"+d.Location+"）")
	line("等级 / 状态", d.Severity.Label()+" / "+store.IncidentStatusLabel[d.Status])
	line("时间", d.FirstSeen.In(loc).Format("2006-01-02 15:04:05")+" ~ "+d.LastSeen.In(loc).Format("2006-01-02 15:04:05"))
	line("规模", "告警 "+strconv.Itoa(d.Alerts)+" 条，命中 "+strconv.Itoa(d.Hits)+" 次，疑似成功 "+strconv.Itoa(d.Success)+" 次")
	line("攻击类型", strings.Join(d.Categories, "、"))
	line("攻击阶段", strings.Join(d.Phases, "、"))
	line("涉及资产", strings.Join(d.Assets, "、")+" "+d.AssetLevel)
	var rules, targets []string
	for i, kv := range d.Rules {
		if i < 15 {
			rules = append(rules, kv.Name+" × "+strconv.FormatInt(kv.Value, 10))
		}
	}
	for i, kv := range d.Targets {
		if i < 8 {
			targets = append(targets, kv.Name+" × "+strconv.FormatInt(kv.Value, 10))
		}
	}
	line("命中规则", strings.Join(rules, "；"))
	line("主要目标", strings.Join(targets, "；"))
	if s.Learn != nil {
		involved := map[string]bool{}
		for _, kv := range d.Rules {
			id, _, _ := strings.Cut(kv.Name, " ")
			involved[id] = true
		}
		var hist []string
		for _, st := range s.Learn.Report().Rules {
			if involved[st.Rule] && st.TP+st.FP > 0 {
				hist = append(hist, st.Rule+" 历史研判 "+strconv.Itoa(st.TP+st.FP)+" 次（确认 "+strconv.Itoa(st.TP)+"、误报 "+strconv.Itoa(st.FP)+"）")
			}
		}
		line("平台历史研判", strings.Join(hist, "；"))
	}
	sb.WriteString("最近告警（新的在前）：\n")
	for i, a := range d.AlertList {
		if i == 20 {
			break
		}
		// 先脱敏再截断：先截断可能把内网地址切成不完整的形式（如 10.20.30），脱敏规则不再识别，
		// 地址的前几段会原样发给外部模型；按字符截断，不产生非法 UTF-8
		ev := clipRunes(m.Mask(a.Evidence), 300)
		ua := clipRunes(m.Mask(a.UA), 120)
		sb.WriteString("- " + a.Time.In(loc).Format("01-02 15:04:05") + " " + a.RuleID + " " + a.Name + " [" + a.Severity.Label() + "/" + a.Result + "] 目标 " +
			m.Mask(a.Target) + " | 证据 " + ev)
		if ua != "" {
			sb.WriteString(" | UA " + ua)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// clipRunes 按字符截断到最多 n 个字符（不截断多字节字符）。
func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// triage 研判一个事件，结论写入事件处置记录并记入审计链。user 为触发人（自动研判为「系统」）。
func (s *Server) triage(ctx context.Context, id uint64, user, ip string) (ai.Verdict, error) {
	d := s.Store.Incident(id)
	if d == nil {
		return ai.Verdict{}, store.ErrNoIncident
	}
	facts := s.incidentFacts(d, ai.NewMasker(s.AI.Desensitize()))
	v, sent, err := s.AI.Triage(ctx, facts)
	detail := "事件 #" + strconv.FormatUint(id, 10) + "，模型 " + s.AI.Model() + "，发送 " + strconv.Itoa(sent) + " 字节"
	if s.AI.Desensitize() {
		detail += "（已脱敏）"
	}
	if err == nil {
		detail += "，结论 " + ai.VerdictLabel[v.Verdict]
		if _, uerr := s.Store.UpdateIncidents([]uint64{id}, "AI（"+s.AI.Model()+"）", store.IncidentUpdate{Note: v.Note()}); uerr != nil {
			log.Printf("[ai] 写入事件 #%d 处置记录失败: %v", id, uerr)
		}
	}
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	switch {
	case s.Auth != nil && user != "系统":
		s.Auth.LogAction(user, ip, "AI 研判", detail, err == nil, reason)
	case s.Trail != nil:
		s.Trail.AppendAudit(auth.Record{Time: time.Now(), User: user, IP: ip, Action: "AI 研判", Detail: detail, OK: err == nil, Reason: reason})
	}
	return v, err
}

// incidentAI 对事件执行 AI 研判（运营分析员以上）。
func (s *Server) incidentAI(w http.ResponseWriter, r *http.Request) {
	if s.AI == nil {
		writeError(w, http.StatusNotFound, "未启用外部模型（配置 ai.enabled 后可用）")
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, store.ErrNoIncident.Error())
		return
	}
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	extendDeadline(w, 3*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	v, err := s.triage(ctx, id, user, s.clientIP(r))
	switch {
	case errors.Is(err, store.ErrNoIncident):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ai.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case err != nil:
		writeError(w, http.StatusBadGateway, err.Error())
	default:
		writeJSON(w, map[string]any{"verdict": v, "label": ai.VerdictLabel[v.Verdict]})
	}
}

// aiTick 由后台任务每分钟调用：开启 ai.auto_triage 时，对新出现的高危及以上待处理事件自动研判（每轮最多 3 个，受每小时上限约束）。
// 研判在单独的协程中进行，不阻塞其他后台任务。
func (s *Server) aiTick(ctx context.Context) {
	if !s.AI.AutoTriage() || !s.aiBusy.CompareAndSwap(false, true) {
		return
	}
	if s.aiDone == nil {
		s.aiDone = map[uint64]bool{}
	}
	list, _, _ := s.Store.Incidents(store.IncidentQuery{Status: "active", MinSeverity: model.SevHigh, Limit: 50})
	var todo []uint64
	for _, v := range list {
		if len(todo) == 3 {
			break
		}
		if time.Since(v.Created) < 24*time.Hour && !s.aiDone[v.ID] {
			todo = append(todo, v.ID)
		}
	}
	if len(todo) == 0 {
		s.aiBusy.Store(false)
		return
	}
	for _, id := range todo {
		s.aiDone[id] = true
	}
	if len(s.aiDone) > 10000 {
		s.aiDone = map[uint64]bool{}
	}
	go func() {
		defer s.aiBusy.Store(false)
		defer func() {
			if p := recover(); p != nil {
				safe.Report("AI 自动研判", p)
			}
		}()
		for _, id := range todo {
			c, cancel := context.WithTimeout(ctx, 150*time.Second)
			_, err := s.triage(c, id, "系统", "")
			cancel()
			if errors.Is(err, ai.ErrRateLimited) {
				return
			}
			if err != nil {
				log.Printf("[ai] 自动研判事件 #%d 失败: %v", id, err)
			}
		}
	}()
}
