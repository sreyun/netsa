package api

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"netsa/internal/assets"
	"netsa/internal/config"
	"netsa/internal/ingest"
	"netsa/internal/mailer"
	"netsa/internal/model"
	"netsa/internal/store"
)

// PeriodTotals 是一个周期的汇总。
type PeriodTotals struct {
	Events       int64    `json:"events"`
	Web          int64    `json:"web"`
	Firewall     int64    `json:"firewall"`
	DNS          int64    `json:"dns"`
	Auth         int64    `json:"auth"`
	Attacks      int64    `json:"attacks"`
	Blocked      int64    `json:"blocked"`
	Success      int64    `json:"success"`
	Alerts       int64    `json:"alerts"`
	Attackers    int      `json:"attackers"`
	NewAttackers int64    `json:"new_attackers"`
	Sev          [5]int64 `json:"sev"`
}

// RankItem 是排行中的一项。
type RankItem struct {
	Name   string `json:"name"`
	Value  int64  `json:"value"`
	Detail string `json:"detail,omitempty"`
}

// DayRow 是趋势中的一天。
type DayRow struct {
	Date    string `json:"date"`
	Attacks int64  `json:"attacks"`
	Alerts  int64  `json:"alerts"`
	Success int64  `json:"success"`
	Pct     int    `json:"pct"` // 相对最大值的百分比（报告中的柱状条）
}

// PeriodReport 是周报 / 月报。
type PeriodReport struct {
	Kind        string               `json:"kind"` // week / month
	Title       string               `json:"title"`
	Org         string               `json:"org"`
	From        string               `json:"from"`
	To          string               `json:"to"`
	PrevFrom    string               `json:"prev_from"`
	PrevTo      string               `json:"prev_to"`
	Generated   time.Time            `json:"generated"`
	Summary     []string             `json:"summary"`
	Totals      PeriodTotals         `json:"totals"`
	Prev        PeriodTotals         `json:"prev"`
	Daily       []DayRow             `json:"daily"`
	Categories  []RankItem           `json:"categories"`
	Attackers   []RankItem           `json:"attackers"`
	Countries   []RankItem           `json:"countries"`
	Incidents   store.IncidentPeriod `json:"incidents"`
	Score       int                  `json:"score"`
	Grade       string               `json:"grade"`
	GradeLabel  string               `json:"grade_label"`
	ScoreFrom   int                  `json:"score_from"` // 周期开始时的评分（-1 表示没有记录）
	Dimensions  []*store.Dimension   `json:"dimensions"`
	Compromised []*store.Compromised `json:"compromised"`
	Actions     []*store.Action      `json:"actions"`
	Vulns       *assets.Summary      `json:"vulns,omitempty"`
	Sources     []ingest.Stat        `json:"sources"`
	Senders     *ingest.SenderReport `json:"-"`
	SenderTotal map[string]int       `json:"senders,omitempty"`
	Suppressed  int64                `json:"suppressed"`
	Notes       []string             `json:"notes"`
	Email       map[string]any       `json:"email,omitempty"`
}

// periodRange 计算报告的日期范围：recent 为截至今天的最近 7 / 30 天；last 为上一个自然周（周一 ~ 周日）/ 上一个自然月。
func periodRange(kind, rng string, now time.Time) (from, to time.Time) {
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	switch {
	case kind == "month" && rng == "last":
		first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		return first.AddDate(0, -1, 0), first.AddDate(0, 0, -1)
	case kind == "month":
		return day.AddDate(0, 0, -29), day
	case rng == "last":
		wd := (int(now.Weekday()) + 6) % 7 // 周一为 0
		monday := day.AddDate(0, 0, -wd)
		return monday.AddDate(0, 0, -7), monday.AddDate(0, 0, -1)
	}
	return day.AddDate(0, 0, -6), day
}

func sumDays(days []store.DayStat) (PeriodTotals, map[string]int64, map[string]int64, map[string]int64) {
	var t PeriodTotals
	cats, ips, countries := map[string]int64{}, map[string]int64{}, map[string]int64{}
	for _, d := range days {
		t.Events += d.Events
		t.Web += d.Web
		t.Firewall += d.Firewall
		t.DNS += d.DNS
		t.Auth += d.Auth
		t.Attacks += d.Attacks
		t.Blocked += d.Blocked
		t.Success += d.Success
		t.Alerts += d.Alerts
		t.NewAttackers += d.NewAttackers
		for i := range t.Sev {
			t.Sev[i] += d.Sev[i]
		}
		for k, v := range d.Categories {
			cats[k] += v
		}
		for k, v := range d.Attackers {
			ips[k] += v
		}
		for k, v := range d.Countries {
			countries[k] += v
		}
	}
	t.Attackers = len(ips)
	return t, cats, ips, countries
}

func rank(m map[string]int64, n int) []RankItem {
	out := make([]RankItem, 0, len(m))
	for k, v := range m {
		out = append(out, RankItem{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// change 描述环比变化，例如“较上周 +35%”。
func change(cur, prev int64, unit string) string {
	switch {
	case prev == 0 && cur == 0:
		return "与" + unit + "持平"
	case prev == 0:
		return unit + "为 0"
	}
	p := float64(cur-prev) * 100 / float64(prev)
	if p >= 0 {
		return fmt.Sprintf("较%s +%.0f%%", unit, p)
	}
	return fmt.Sprintf("较%s %.0f%%", unit, p)
}

// BuildPeriodReport 生成周报 / 月报。
func (s *Server) BuildPeriodReport(kind, rng string) *PeriodReport {
	if kind != "month" {
		kind = "week"
	}
	now := s.now()
	from, to := periodRange(kind, rng, now)
	span := int(to.Sub(from).Hours()/24+0.5) + 1
	pFrom, pTo := from.AddDate(0, 0, -span), from.AddDate(0, 0, -1)
	unit, label := "上周", "安全周报"
	if kind == "month" {
		unit, label = "上月", "安全月报"
	}
	if rng != "last" {
		unit = "上一周期"
	}
	r := &PeriodReport{Kind: kind, Org: s.Cfg.Home.Name, From: from.Format("2006-01-02"), To: to.Format("2006-01-02"),
		PrevFrom: pFrom.Format("2006-01-02"), PrevTo: pTo.Format("2006-01-02"), Generated: now, Notes: []string{}, Summary: []string{}}
	r.Title = fmt.Sprintf("%s（%s ~ %s）", label, r.From, r.To)
	days := s.Store.Days(r.From, r.To)
	var cats, ips, countries map[string]int64
	r.Totals, cats, ips, countries = sumDays(days)
	prevDays := s.Store.Days(r.PrevFrom, r.PrevTo)
	r.Prev, _, _, _ = sumDays(prevDays)
	cmp := func(cur, prev int64) string {
		if len(prevDays) == 0 {
			return "上一周期无统计数据"
		}
		return change(cur, prev, unit)
	}
	r.Categories, r.Countries = rank(cats, 10), rank(countries, 10)
	for _, it := range rank(ips, 10) {
		if sum, ok := s.Store.Summary(it.Name); ok {
			it.Detail = strings.TrimSpace(sum.Location + " · " + sum.Level.Label() + " · " + strings.Join(sum.Categories[:min(len(sum.Categories), 3)], "、"))
		}
		r.Attackers = append(r.Attackers, it)
	}
	byDate := map[string]store.DayStat{}
	for _, d := range days {
		byDate[d.Date] = d
	}
	var peak int64 = 1
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		ds := byDate[d.Format("2006-01-02")]
		r.Daily = append(r.Daily, DayRow{Date: d.Format("01-02"), Attacks: ds.Attacks, Alerts: ds.Alerts, Success: ds.Success})
		peak = max(peak, ds.Attacks)
	}
	for i := range r.Daily {
		r.Daily[i].Pct = int(r.Daily[i].Attacks * 100 / peak)
	}
	if len(days) == 0 || days[0].Date > r.From {
		first := "（暂无）"
		if len(days) > 0 {
			first = days[0].Date
		}
		r.Notes = append(r.Notes, "按天汇总自 "+first+" 起记录，此前的日期没有统计数据")
	}
	r.Incidents = s.Store.IncidentStats(from, to.AddDate(0, 0, 1))
	a := s.Store.Assess(s.visibility(nil))
	r.Score, r.Grade, r.GradeLabel, r.Dimensions = a.Score, a.Grade, a.GradeLabel, a.Dimensions
	r.ScoreFrom = -1
	for _, p := range a.History {
		if !p.T.Before(from) {
			r.ScoreFrom = p.Score
			break
		}
	}
	r.Compromised = a.Compromised[:min(len(a.Compromised), 10)]
	r.Actions = a.Actions[:min(len(a.Actions), 8)]
	if s.Assets != nil {
		v := s.Assets.Summary()
		if v.Assets > 0 || v.Vulns > 0 {
			r.Vulns = &v
		}
	}
	r.Sources = s.Ingest.Stats()
	if s.Ingest.Senders != nil {
		rep := s.Ingest.Senders.Report()
		r.Senders = &rep
		r.SenderTotal = map[string]int{"senders": rep.Totals.Senders, "online": rep.Totals.Online, "silent": rep.Totals.Silent, "rejected": rep.Totals.Rejected}
	}
	r.Suppressed = s.Suppress.Total()

	// 结论
	t := r.Totals
	r.Summary = append(r.Summary, fmt.Sprintf("共处理日志 %s 条，检测到攻击 %s 次（%s），涉及 %d 个攻击源，其中新出现 %d 个。",
		human(t.Events), human(t.Attacks), cmp(t.Attacks, r.Prev.Attacks), t.Attackers, t.NewAttackers))
	if t.Success > 0 {
		r.Summary = append(r.Summary, fmt.Sprintf("研判为疑似攻击成功 %d 次（%s），需重点核查相关资产。", t.Success, cmp(t.Success, r.Prev.Success)))
	} else if t.Attacks > 0 {
		r.Summary = append(r.Summary, fmt.Sprintf("未发现攻击成功的迹象，%.0f%% 的攻击已被拦截。", float64(t.Blocked)*100/float64(max(t.Attacks, 1))))
	}
	inc := r.Incidents
	line := fmt.Sprintf("新建安全事件 %d 个，关闭 %d 个", inc.Created, inc.Closed)
	if inc.SLARate >= 0 {
		line += fmt.Sprintf("，按时处置率 %.0f%%，平均处置时长 %s", inc.SLARate*100, cnDuration(inc.MTTR))
	}
	if inc.OverdueNow > 0 {
		line += fmt.Sprintf("；当前仍有 %d 个事件超过处置时限", inc.OverdueNow)
	}
	r.Summary = append(r.Summary, line+"。")
	sc := fmt.Sprintf("当前安全评分 %d（%s）", r.Score, r.GradeLabel)
	if r.ScoreFrom >= 0 && r.ScoreFrom != r.Score {
		sc += fmt.Sprintf("，周期初为 %d", r.ScoreFrom)
	}
	if n := len(a.Compromised); n > 0 {
		sc += fmt.Sprintf("；存在 %d 个疑似失陷资产", n)
	}
	r.Summary = append(r.Summary, sc+"。")
	if r.Vulns != nil && r.Vulns.OpenVulns > 0 {
		r.Summary = append(r.Summary, fmt.Sprintf("资产上尚有 %d 个未修复漏洞，其中核心资产高危及以上 %d 个。", r.Vulns.OpenVulns, r.Vulns.CoreOpenHigh))
	}
	for _, st := range r.Sources {
		if st.Silent {
			r.Summary = append(r.Summary, "数据源 "+st.Name+" 已断流，存在监测盲区。")
		}
	}
	return r
}

func human(n int64) string {
	switch {
	case n >= 100000000:
		return fmt.Sprintf("%.2f 亿", float64(n)/1e8)
	case n >= 10000:
		return fmt.Sprintf("%.1f 万", float64(n)/1e4)
	}
	return fmt.Sprint(n)
}

func (s *Server) emailInfo() map[string]any {
	rc := s.Cfg.Report
	info := map[string]any{"configured": rc.SMTP.Host != "" && rc.SMTP.From != "", "recipients": len(rc.Recipients)}
	if _, _, ok, _ := config.ParseWeekly(rc.Weekly); ok {
		info["weekly"] = rc.Weekly
	}
	if _, _, ok, _ := config.ParseMonthly(rc.Monthly); ok {
		info["monthly"] = rc.Monthly
	}
	return info
}

// periodicReport 返回周报 / 月报：period=week|month，range=recent（最近 7 / 30 天，默认）| last（上一自然周 / 月）；format=html 返回可打印的报告页。
func (s *Server) periodicReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	extendDeadline(w, time.Minute)
	rep := s.BuildPeriodReport(q.Get("period"), q.Get("range"))
	if q.Get("format") == "html" {
		s.audit(r, "查看安全报告", rep.Title, nil)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if q.Get("download") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="netsa-`+rep.Kind+`-`+rep.To+`.html"`)
		}
		renderPeriodHTML(w, rep, true)
		return
	}
	rep.Email = s.emailInfo()
	writeJSON(w, rep)
}

func (s *Server) smtpConfig() mailer.Config {
	c := s.Cfg.Report.SMTP
	pw := c.Password
	if pw == "" {
		pw = os.Getenv("NETSA_SMTP_PASSWORD")
	}
	return mailer.Config{Host: c.Host, Port: c.Port, Username: c.Username, Password: pw, From: c.From, TLS: c.TLS, Insecure: c.Insecure}
}

// SendPeriodReport 生成并通过邮件发送报告，返回报告标题。
func (s *Server) SendPeriodReport(kind, rng string, to []string) (string, error) {
	if len(to) == 0 {
		to = s.Cfg.Report.Recipients
	}
	rep := s.BuildPeriodReport(kind, rng)
	var b strings.Builder
	renderPeriodHTML(&b, rep, false)
	html := b.String()
	subject := "netsa " + rep.Title
	if rep.Org != "" {
		subject = "netsa " + rep.Org + " " + rep.Title
	}
	return rep.Title, mailer.Send(s.smtpConfig(), to, subject, html,
		[]mailer.Attachment{{Name: "netsa-" + rep.Kind + "-" + rep.To + ".html", ContentType: "text/html; charset=UTF-8", Data: []byte(html)}})
}

// reportEmail 立即通过邮件发送报告：{"period":"week","range":"last","to":["a@example.com"]}，to 为空时发送给配置的收件人。
func (s *Server) reportEmail(w http.ResponseWriter, r *http.Request) {
	var f struct {
		Period string   `json:"period"`
		Range  string   `json:"range"`
		To     []string `json:"to"`
	}
	if !decodeForm(w, r, &f) {
		return
	}
	if len(f.To) > 50 {
		writeError(w, http.StatusBadRequest, "收件人过多（最多 50 个）")
		return
	}
	extendDeadline(w, 2*time.Minute)
	title, err := s.SendPeriodReport(f.Period, f.Range, f.To)
	s.audit(r, "发送安全报告邮件", title+" → "+strings.Join(orDefault(f.To, s.Cfg.Report.Recipients), ","), err)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "title": title})
}

func orDefault(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}

// sevTotal 返回中危及以上的攻击数（报告中的高风险攻击）。
func sevTotal(t PeriodTotals) int64 {
	return t.Sev[model.SevMedium] + t.Sev[model.SevHigh] + t.Sev[model.SevCritical]
}

// scheduleReports 按 report.weekly / report.monthly 定时发送上一自然周 / 月的报告（未配置邮件服务器或收件人时不发送）。
func (s *Server) scheduleReports(now time.Time) {
	rc := s.Cfg.Report
	if rc.SMTP.Host == "" || len(rc.Recipients) == 0 {
		return
	}
	today, hm := now.Format("2006-01-02"), now.Format("15:04")
	send := func(kind string) {
		title, err := s.SendPeriodReport(kind, "last", nil)
		if err != nil {
			log.Printf("[report] %s邮件发送失败: %v", title, err)
			return
		}
		log.Printf("[report] 已发送%s邮件给 %d 个收件人", title, len(rc.Recipients))
	}
	if d, t, ok, _ := config.ParseWeekly(rc.Weekly); ok && now.Weekday() == d && hm == t && s.sched.weekly != today {
		s.sched.weekly = today
		go send("week") // 发信可能较慢，不阻塞其他后台任务
	}
	if d, t, ok, _ := config.ParseMonthly(rc.Monthly); ok && now.Day() == d && hm == t && s.sched.monthly != today {
		s.sched.monthly = today
		go send("month")
	}
}

// reportSchedule 记录定时报告的发送日期（仅后台任务访问）。
type reportSchedule struct{ weekly, monthly string }

// cnDuration 把 Go 时长字符串（如 2h15m0s）格式化为中文（2 小时 15 分钟）。
func cnDuration(s string) string {
	d, err := time.ParseDuration(s)
	if err != nil {
		return s
	}
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d 天 %d 小时", d/(24*time.Hour), d%(24*time.Hour)/time.Hour)
	case d >= time.Hour:
		return fmt.Sprintf("%d 小时 %d 分钟", d/time.Hour, d%time.Hour/time.Minute)
	case d >= time.Minute:
		return fmt.Sprintf("%d 分钟", d/time.Minute)
	}
	return "不到 1 分钟"
}
