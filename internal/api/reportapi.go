package api

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsa/internal/alert"
	"netsa/internal/model"
	"netsa/internal/safe"
	"netsa/internal/store"
)

// BuildReport 生成每日安全日报：安全评分与结论、近 24 小时攻击态势、疑似失陷资产与优先处置事项。
func (s *Server) BuildReport() alert.Event {
	a := s.Store.Assess(s.visibility(nil))
	d := s.Store.DailySummary(24 * time.Hour)
	now := s.now()
	ev := alert.Event{Kind: "report", Time: time.Now(),
		Title: fmt.Sprintf("%s（安全评分 %d · %s %s）", now.Format("2006-01-02"), a.Score, a.Grade, a.GradeLabel)}
	switch {
	case a.Score < 40:
		ev.Severity = model.SevCritical
	case a.Score < 60:
		ev.Severity = model.SevHigh
	case a.Score < 80:
		ev.Severity = model.SevMedium
	default:
		ev.Severity = model.SevLow
	}
	line := func(format string, args ...any) { ev.Lines = append(ev.Lines, fmt.Sprintf(format, args...)) }
	line("安全评分 %d 分（%s %s）：%s", a.Score, a.Grade, a.GradeLabel, a.Verdict)
	trend := ""
	if d.PrevAttacks > 0 {
		pct := math.Round(float64(d.Attacks-d.PrevAttacks) * 100 / float64(d.PrevAttacks))
		switch {
		case pct > 0:
			trend = fmt.Sprintf("，较前 24 小时上升 %.0f%%", pct)
		case pct < 0:
			trend = fmt.Sprintf("，较前 24 小时下降 %.0f%%", -pct)
		default:
			trend = "，与前 24 小时持平"
		}
	}
	block := ""
	if d.Attacks > 0 {
		block = fmt.Sprintf("，拦截率 %.1f%%", float64(d.Blocked)*100/float64(d.Attacks))
	}
	line("近 24 小时攻击 %d 次%s%s，疑似成功 %d 次", d.Attacks, trend, block, d.Success)
	line("活动攻击源 %d 个（新增 %d 个），其中高危以上 %d 个", d.Attackers, d.NewAttackers, d.HighActive)
	if n := len(a.Compromised); n > 0 {
		high := 0
		var names []string
		for _, c := range a.Compromised {
			if c.Confidence == "high" {
				high++
			}
			if len(names) < 3 {
				names = append(names, c.Asset)
			}
		}
		line("疑似失陷资产 %d 个（高置信 %d 个）：%s", n, high, strings.Join(names, "、"))
	} else {
		line("未发现攻击成功或外连恶意地址等失陷迹象")
	}
	if len(d.TopCats) > 0 {
		var parts []string
		for _, kv := range d.TopCats {
			parts = append(parts, fmt.Sprintf("%s %d 条", kv.Name, kv.Value))
		}
		line("主要攻击类型：%s", strings.Join(parts, "、"))
	}
	if len(d.TopAttackers) > 0 {
		var parts []string
		for _, t := range d.TopAttackers {
			loc := t.Country
			if t.City != "" {
				loc += " " + t.City
			}
			parts = append(parts, fmt.Sprintf("%s（%s，评分 %.0f）", t.IP, strings.TrimSpace(loc), t.Score))
		}
		line("主要攻击源：%s", strings.Join(parts, "、"))
	}
	if c := a.ActionCount; c["P0"]+c["P1"] > 0 {
		var top []string
		for _, act := range a.Actions {
			if act.Priority <= "P1" && len(top) < 3 {
				top = append(top, act.Priority+" "+act.Title)
			}
		}
		line("待处置：P0 %d 项、P1 %d 项；优先处理：%s", c["P0"], c["P1"], strings.Join(top, "；"))
	}
	return ev
}

// sendReport 立即向指定机器人发送安全日报（界面中的“发送日报”）。
func (s *Server) sendReport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, err := s.Notifier.SendReport(ctx, r.PathValue("id"), s.BuildReport())
	s.audit(r, "发送安全日报", r.PathValue("id"), err)
	if err == alert.ErrNotFound {
		s.alertError(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": err == nil, "error": errText(err)})
}

// RunBackground 执行后台任务直到 ctx 结束：每小时记录一次安全评分（启动 2 分钟后先记录一次），
// 每天在 alert.report_time 向勾选了“接收日报”的机器人推送安全日报。
func (s *Server) RunBackground(ctx context.Context) {
	reportAt := strings.TrimSpace(s.Cfg.Alert.ReportTime)
	lastReport := ""
	lastScore := time.Time{}
	first := time.NewTimer(2 * time.Minute)
	defer first.Stop()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					safe.Report("后台任务", p)
				}
			}()
			now := s.now()
			s.remindOverdue()
			s.pushSenderNotices()
			s.pushSourceNotices()
			s.scheduleReports(now)
			s.learnTick(now)
			s.aiTick(ctx)
			if time.Since(lastScore) >= time.Hour-time.Minute {
				lastScore = time.Now()
				s.Store.RecordScore(s.Store.Assess(s.visibility(nil)))
			}
			if reportAt == "" || reportAt == "off" || now.Format("15:04") != reportAt || lastReport == now.Format("2006-01-02") {
				return
			}
			lastReport = now.Format("2006-01-02")
			c, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			n, err := s.Notifier.SendReport(c, "", s.BuildReport())
			switch {
			case err != nil:
				log.Printf("[alert] 安全日报推送失败（成功 %d 个机器人）: %v", n, err)
			case n > 0:
				log.Printf("[alert] 已向 %d 个机器人推送安全日报", n)
			}
		}()
	}
}

// remindOverdue 推送超过处置时限仍未关闭的安全事件（每个事件只提醒一次）。超时事件较多时合并为一条通知。
func (s *Server) remindOverdue() {
	list := s.Store.TakeOverdue()
	if len(list) == 0 {
		return
	}
	line := func(v store.IncidentView) string {
		return "#" + strconv.FormatUint(v.ID, 10) + "：" + v.Title + "（" + v.Severity.Label() + "，" + store.IncidentStatusLabel[v.Status] + "，负责人 " + orDash(v.Assignee) + "）"
	}
	if len(list) == 1 {
		v := list[0]
		s.Notifier.Notify("", alert.Event{Kind: "notice", Severity: v.Severity, Title: "安全事件超时未处置 #" + strconv.FormatUint(v.ID, 10),
			IP: v.Key, Location: v.Location, Link: "#tab=incidents&incident=" + strconv.FormatUint(v.ID, 10), Time: time.Now(),
			Lines: []string{"事件：" + v.Title, "当前状态：" + store.IncidentStatusLabel[v.Status], "负责人：" + orDash(v.Assignee),
				"处置时限：" + v.Due.In(s.now().Location()).Format("2006-01-02 15:04") + " 前", "告警数：" + strconv.Itoa(v.Alerts)}})
		return
	}
	lines := []string{"超时事件：" + strconv.Itoa(len(list)) + " 个"}
	for i, v := range list {
		if i == 8 {
			lines = append(lines, "其余：另有 "+strconv.Itoa(len(list)-8)+" 个，请在事件处置页查看")
			break
		}
		lines = append(lines, "事件 "+line(v))
	}
	s.Notifier.Notify("", alert.Event{Kind: "notice", Severity: list[0].Severity, Title: strconv.Itoa(len(list)) + " 个安全事件超时未处置",
		Link: "#tab=incidents&overdue=1", Time: time.Now(), Lines: lines})
}
