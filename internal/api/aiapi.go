package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"netsa/internal/ai"
	"netsa/internal/auth"
	"netsa/internal/learn"
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
	line("规模", "告警 "+strconv.Itoa(d.Alerts)+" 条，命中 "+strconv.Itoa(d.Hits)+" 次，疑似成功 "+strconv.Itoa(d.Success)+" 次（其中有证据 "+strconv.Itoa(d.Proven)+" 次）")
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
		// 自学习积累的人工结论：同一来源、同一规则在同一目标上的历史结论（本单位环境中的误报规律）
		ids := make([]string, 0, len(involved))
		for id := range involved {
			ids = append(ids, id)
		}
		var targets []string
		for _, kv := range d.Targets {
			targets = append(targets, kv.Name)
		}
		h := s.Learn.History(d.Key, ids, targets, d.ID)
		if h.SourceTP+h.SourceFP > 0 {
			line("该来源历史研判", "确认攻击 "+strconv.Itoa(h.SourceTP)+" 次、误报 "+strconv.Itoa(h.SourceFP)+" 次")
		}
		var ctx []string
		for _, c := range h.Contexts {
			ctx = append(ctx, c.Rule+" @ "+c.Target+"：确认攻击 "+strconv.Itoa(c.TP)+" 次、误报 "+strconv.Itoa(c.FP)+" 次")
		}
		line("同规则同目标历史研判", strings.Join(ctx, "；"))
		// 本单位分析员处理过的相似案例（含纠正过模型的判断）：让模型吸取本环境的经验
		if sim := s.Learn.Similar(ids, targets, d.ID, 5); len(sim) > 0 {
			sb.WriteString("本单位相似案例（分析员结论）：\n")
			for _, c := range sim {
				v := "确认攻击"
				if c.Verdict == learn.VerdictFP {
					v = "误报"
				}
				item := "- " + c.Rule + " @ " + c.Target + "：" + v
				if c.Corrected != "" {
					item += "（模型曾判断为" + ai.VerdictLabel[c.Corrected] + "，被分析员纠正）"
				}
				if c.Note != "" {
					item += "，说明：" + c.Note
				}
				sb.WriteString(m.Mask(item) + "\n")
			}
		}
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
		sb.WriteString("- " + a.Time.In(loc).Format("01-02 15:04:05") + " " + a.RuleID + " " + a.Name + " [" + a.Severity.Label() + "/" + a.Result + proofTag(a.Proven) + "] 目标 " +
			m.Mask(a.Target) + " | 证据 " + ev)
		if ua != "" {
			sb.WriteString(" | UA " + ua)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// proofTag 标注告警是否有响应码之外的成功证据。
func proofTag(proven bool) string {
	if proven {
		return "/有证据"
	}
	return ""
}

// clipRunes 按字符截断到最多 n 个字符（不截断多字节字符）。
func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

const (
	aiDowngradeConfidence = 85  // 模型判为误报时下调事件等级所需的最低置信度
	aiDowngradeMinRate    = 0.6 // 已有评估时要求的最低一致率
)

// triage 研判一个事件，结论写入事件处置记录并记入审计链。user 为触发人（自动研判为「系统」）。
func (s *Server) triage(ctx context.Context, id uint64, user, ip string) (ai.Verdict, error) {
	d := s.Store.Incident(id)
	if d == nil {
		return ai.Verdict{}, store.ErrNoIncident
	}
	desens := s.AI.Desensitize()
	facts := s.incidentFacts(d, ai.NewMasker(desens))
	v, sent, err := s.AI.Triage(ctx, facts)
	detail := "事件 #" + strconv.FormatUint(id, 10) + "，模型 " + s.AI.Model() + "，发送 " + strconv.Itoa(sent) + " 字节"
	if desens {
		detail += "（已脱敏）"
	}
	if err == nil {
		detail += "，结论 " + ai.VerdictLabel[v.Verdict]
		// 自学习评估的模型可信度写在结论旁边；本次结论在分析员处置后用于更新一致率（不作为学习样本）
		// 没有得到结论不是模型的判断，不计入一致率的统计
		if !v.Unparsed {
			v.Trust = s.Learn.Trust(v.Model)
			rules, targets := []string{}, []string{}
			for _, kv := range d.Rules {
				id, _, _ := strings.Cut(kv.Name, " ")
				rules = append(rules, id)
			}
			for _, kv := range d.Targets {
				targets = append(targets, kv.Name)
			}
			s.Learn.RecordAI(id, learn.AIRecord{Verdict: v.Verdict, Confidence: v.Confidence, Model: v.Model, Rules: rules, Targets: targets, Time: v.Time})
		}
		if _, uerr := s.Store.UpdateIncidents([]uint64{id}, "AI（"+v.Model+"）", store.IncidentUpdate{Note: v.Note()}); uerr != nil {
			log.Printf("[ai] 写入事件 #%d 处置记录失败: %v", id, uerr)
		}
		// 模型高置信判为误报：下调事件等级（不关闭事件，也不作为学习样本），减少分析员在这类事件上的时间。
		// 分析员的结论已经证明这个模型不可靠时不下调
		if !v.Unparsed && v.Verdict == "false_positive" && v.Confidence >= aiDowngradeConfidence && s.AI.AutoDowngrade() {
			if rate, known := s.Learn.TrustRate(v.Model); !known || rate >= aiDowngradeMinRate {
				reason := "模型 " + v.Model + " 判为疑似误报（置信度 " + strconv.Itoa(v.Confidence) + "%）"
				if from, ok := s.Store.AIDowngrade(id, reason); ok {
					v.Downgraded = from.Label()
					detail += "，事件等级由" + from.Label() + "下调一级"
				}
			}
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
	if !s.AI.Enabled() {
		writeError(w, http.StatusNotFound, ai.ErrDisabled.Error())
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
	budget := s.AI.CallBudget()
	extendDeadline(w, budget+30*time.Second)
	ctx, cancel := context.WithTimeout(r.Context(), budget)
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

// maxAIQueue 是批量研判队列的长度上限，与批量处置一次最多 500 个事件保持一致。
const maxAIQueue = 500

// incidentAIBatch 把选中的事件加入后台研判队列（运营分析员以上）。模型一次研判可能要几十秒，
// 不能在一个请求里等完；队列由 aiTick 消费，受每小时调用上限约束。
func (s *Server) incidentAIBatch(w http.ResponseWriter, r *http.Request) {
	if !s.AI.Enabled() {
		writeError(w, http.StatusNotFound, ai.ErrDisabled.Error())
		return
	}
	var form struct {
		IDs []uint64 `json:"ids"`
	}
	if !decodeForm(w, r, &form) {
		return
	}
	if len(form.IDs) == 0 || len(form.IDs) > maxAIQueue {
		writeError(w, http.StatusBadRequest, "一次选择 1 到 "+strconv.Itoa(maxAIQueue)+" 个事件")
		return
	}
	s.aiQueueMu.Lock()
	queued := map[uint64]bool{}
	for _, id := range s.aiQueue {
		queued[id] = true
	}
	added := 0
	for _, id := range form.IDs {
		if queued[id] || len(s.aiQueue) >= maxAIQueue || s.Store.Incident(id) == nil {
			continue
		}
		queued[id] = true
		s.aiQueue = append(s.aiQueue, id)
		added++
	}
	pending := len(s.aiQueue)
	s.aiQueueMu.Unlock()
	s.audit(r, "批量 AI 研判", "加入队列 "+strconv.Itoa(added)+" 个事件", nil)
	writeJSON(w, map[string]any{"queued": added, "pending": pending, "per_tick": aiPerTick})
}

// aiPerTick 是后台每分钟最多研判的事件数。
const aiPerTick = 3

// takeAIQueue 取出队列前面最多 n 个事件。
func (s *Server) takeAIQueue(n int) []uint64 {
	s.aiQueueMu.Lock()
	defer s.aiQueueMu.Unlock()
	n = min(n, len(s.aiQueue))
	out := append([]uint64(nil), s.aiQueue[:n]...)
	s.aiQueue = s.aiQueue[n:]
	return out
}

// aiTick 由后台任务每分钟调用：先处理批量研判队列；开启 ai.auto_triage 时，再对新出现的高危及以上
// （可扩大到中危）待处理事件自动研判。每轮最多 3 个，受每小时上限约束。
// 研判在单独的协程中进行，不阻塞其他后台任务。
func (s *Server) aiTick(ctx context.Context) {
	if !s.AI.Enabled() || !s.aiBusy.CompareAndSwap(false, true) {
		return
	}
	if s.aiDone == nil {
		s.aiDone = map[uint64]bool{}
	}
	todo := s.takeAIQueue(aiPerTick)
	if s.AI.AutoTriage() && len(todo) < aiPerTick {
		minSev := model.SevHigh
		if s.AI.AutoTriageMedium() {
			minSev = model.SevMedium
		}
		// 列表按等级从高到低排序，严重的事件优先研判
		list, _, _ := s.Store.Incidents(store.IncidentQuery{Status: "active", MinSeverity: minSev, Limit: 50})
		for _, v := range list {
			if len(todo) == aiPerTick {
				break
			}
			if time.Since(v.Created) < 24*time.Hour && !s.aiDone[v.ID] && !slices.Contains(todo, v.ID) {
				todo = append(todo, v.ID)
			}
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
			c, cancel := context.WithTimeout(ctx, s.AI.CallBudget())
			_, err := s.triage(c, id, "系统", "")
			cancel()
			if errors.Is(err, ai.ErrRateLimited) {
				return
			}
			if err != nil && !errors.Is(err, store.ErrNoIncident) {
				log.Printf("[ai] 自动研判事件 #%d 失败: %v", id, err)
			}
		}
	}()
}

// aiSettings 返回外部模型配置（不含密钥）与接入状态（管理员）。
func (s *Server) aiSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"settings": s.AI.View(), "status": s.AI.Status()})
}

// aiSettingsUpdate 保存外部模型配置并立即生效（管理员）。密钥只写入服务端，审计记录中只记录「已更新 / 未变更」。
func (s *Server) aiSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var u ai.Update
	if !decodeForm(w, r, &u) {
		return
	}
	user := "anonymous"
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	before := s.AI.View()
	v, warn, err := s.AI.Apply(u, user)
	s.audit(r, "修改外部模型配置", aiAuditDetail(before, u), err)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if v.Enabled {
		log.Printf("[ai] %s 修改了外部模型配置：%s（%s），立即生效", user, v.Model, v.BaseURL)
	} else {
		log.Printf("[ai] %s 停用了外部模型", user)
	}
	writeJSON(w, map[string]any{"settings": v, "status": s.AI.Status(), "warning": warn})
}

// aiTest 用界面上尚未保存的配置测试模型连通性（管理员）。
func (s *Server) aiTest(w http.ResponseWriter, r *http.Request) {
	var u ai.Update
	if !decodeForm(w, r, &u) {
		return
	}
	extendDeadline(w, 4*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	res, err := s.AI.Test(ctx, u)
	if err == nil && !res.OK {
		err = errors.New(res.Error)
	}
	s.audit(r, "测试外部模型连接", u.Model+"（"+clipRunes(strings.TrimSpace(u.BaseURL), 200)+"）", err)
	switch {
	case errors.Is(err, ai.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case err != nil && !res.OK && res.Model == "":
		writeError(w, http.StatusBadRequest, err.Error()) // 配置校验未通过，没有发出请求
	default:
		writeJSON(w, res)
	}
}

// aiAuditDetail 描述一次配置变更（不含密钥）。地址变更与关闭脱敏使用固定措辞，平台行为基线据此识别高危变更。
func aiAuditDetail(before ai.View, u ai.Update) string {
	parts := []string{"停用"}
	if u.Enabled {
		parts[0] = "启用"
	}
	if u.Protocol != "" {
		parts = append(parts, "协议 "+clipRunes(strings.TrimSpace(u.Protocol), 16))
	}
	parts = append(parts, "模型 "+clipRunes(strings.TrimSpace(u.Model), 64))
	base := clipRunes(strings.TrimRight(strings.TrimSpace(u.BaseURL), "/"), 200)
	if before.BaseURL != "" && base != before.BaseURL {
		parts = append(parts, "地址变更 "+before.BaseURL+" → "+base)
	} else {
		parts = append(parts, "地址 "+base)
	}
	switch {
	case u.ClearKey:
		parts = append(parts, "不使用密钥")
	case strings.TrimSpace(u.APIKey) != "":
		parts = append(parts, "密钥已更新")
	default:
		parts = append(parts, "密钥未变更")
	}
	if before.Desensitize && !u.Desensitize {
		parts = append(parts, "关闭发送前脱敏")
	} else if !u.Desensitize {
		parts = append(parts, "未脱敏")
	}
	if u.AutoTriage {
		parts = append(parts, "自动研判高危事件")
	}
	limit := u.MaxPerHour
	if limit <= 0 {
		limit = 30 // 与服务端默认值一致
	}
	parts = append(parts, "每小时上限 "+strconv.Itoa(limit)+" 次")
	return strings.Join(parts, "，")
}

// aiModels 读取接口提供的模型列表（管理员）：使用界面上尚未保存的地址与密钥，方便选择准确的模型名称。
func (s *Server) aiModels(w http.ResponseWriter, r *http.Request) {
	var u ai.Update
	if !decodeForm(w, r, &u) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	list, err := s.AI.Models(ctx, u)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"models": list})
}
