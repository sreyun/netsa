package api

import (
	"encoding/csv"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsa/internal/archive"
	"netsa/internal/model"
)

// archiveQuery 从请求参数解析历史告警查询条件。时间支持 RFC3339、2006-01-02T15:04（页面日期时间控件）与 2006-01-02，
// 不带时区的按配置时区解析；未指定时默认最近 7 天。
func (s *Server) archiveQuery(r *http.Request) (archive.Query, error) {
	v := r.URL.Query()
	loc, err := s.Cfg.Location()
	if err != nil {
		loc = time.Local
	}
	parse := func(name string, def time.Time) (time.Time, error) {
		raw := strings.TrimSpace(v.Get(name))
		if raw == "" {
			return def, nil
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t, nil
		}
		for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
			if t, err := time.ParseInLocation(layout, raw, loc); err == nil {
				return t, nil
			}
		}
		return time.Time{}, errors.New("时间格式无效: " + raw)
	}
	now := time.Now()
	q := archive.Query{
		IP: v.Get("ip"), Rule: v.Get("rule"), MinSeverity: model.ParseSeverity(v.Get("severity")), Category: v.Get("category"),
		Result: v.Get("result"), Kind: v.Get("kind"), Phase: v.Get("phase"), Search: v.Get("q"), Limit: qint(r, "limit", 100), Offset: qint(r, "offset", 0),
	}
	if v.Get("severity") == "" {
		q.MinSeverity = model.SevInfo
	}
	if q.From, err = parse("from", now.AddDate(0, 0, -7)); err != nil {
		return q, err
	}
	if q.To, err = parse("to", now.Add(time.Minute)); err != nil {
		return q, err
	}
	if !q.To.After(q.From) {
		return q, errors.New("结束时间必须晚于开始时间")
	}
	return q, nil
}

func (s *Server) archiveDisabled(w http.ResponseWriter) bool {
	if s.Archive == nil {
		writeErrorCode(w, http.StatusNotFound, "未启用告警归档（配置 archive.dsn 或环境变量 NETSA_ARCHIVE_DSN 后启用）", "archive_disabled")
		return true
	}
	return false
}

func archiveErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, archive.ErrBusy):
		writeErrorCode(w, http.StatusTooManyRequests, err.Error(), "busy")
	case errors.Is(err, archive.ErrNotReady):
		writeErrorCode(w, http.StatusServiceUnavailable, err.Error(), "archive_unavailable")
	default:
		writeErrorCode(w, http.StatusBadRequest, err.Error(), "bad_request")
	}
}

func (s *Server) archiveStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Archive.Status(r.Context()))
}

func (s *Server) archiveAlerts(w http.ResponseWriter, r *http.Request) {
	if s.archiveDisabled(w) {
		return
	}
	q, err := s.archiveQuery(r)
	if err != nil {
		archiveErr(w, err)
		return
	}
	res, err := s.Archive.Search(r.Context(), q)
	if err != nil {
		archiveErr(w, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) archiveStats(w http.ResponseWriter, r *http.Request) {
	if s.archiveDisabled(w) {
		return
	}
	q, err := s.archiveQuery(r)
	if err != nil {
		archiveErr(w, err)
		return
	}
	st, err := s.Archive.Stats(r.Context(), q)
	if err != nil {
		archiveErr(w, err)
		return
	}
	writeJSON(w, st)
}

// exportDetail 生成导出审计的说明：时间范围、实际使用的筛选条件与导出条数。
func exportDetail(q archive.Query, loc *time.Location, n int) string {
	parts := []string{"时间 " + q.From.In(loc).Format("2006-01-02 15:04") + " ~ " + q.To.In(loc).Format("2006-01-02 15:04")}
	for _, f := range []struct{ k, v string }{{"IP", q.IP}, {"规则", q.Rule}, {"类型", q.Category}, {"结果", q.Result}, {"来源", q.Kind}, {"阶段", q.Phase}, {"关键字", q.Search}} {
		if v := strings.TrimSpace(f.v); v != "" {
			parts = append(parts, f.k+" "+v)
		}
	}
	if q.MinSeverity > model.SevInfo {
		parts = append(parts, "等级 ≥ "+q.MinSeverity.Label())
	}
	return strings.Join(parts, "，") + "，共 " + strconv.Itoa(n) + " 条"
}

var resultLabel = map[string]string{
	model.ResultBlocked: "已拦截", model.ResultFailed: "失败", model.ResultError: "服务异常", model.ResultSuccess: "疑似成功",
	model.ResultPassed: "未拦截", model.ResultAllowed: "防火墙放行", model.ResultUnknown: "未知",
}

// archiveExport 导出历史告警为 CSV（流式写出，最多 20 万条），并记录操作审计。
func (s *Server) archiveExport(w http.ResponseWriter, r *http.Request) {
	if s.archiveDisabled(w) {
		return
	}
	q, err := s.archiveQuery(r)
	if err != nil {
		archiveErr(w, err)
		return
	}
	loc, err := s.Cfg.Location()
	if err != nil {
		loc = time.Local
	}
	started := false
	var cw *csv.Writer
	n, err := s.Archive.Export(r.Context(), q, func(row archive.Row) error {
		if !started { // 第一行数据到达后才写响应头，查询失败时仍可返回 JSON 错误
			started = true
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=netsa-alerts-"+s.now().Format("20060102-150405")+".csv")
			w.Write([]byte("\xEF\xBB\xBF")) // UTF-8 BOM，便于 Excel 识别中文
			cw = csv.NewWriter(w)
			cw.Write([]string{"时间", "等级", "规则ID", "规则名称", "攻击类型", "研判结果", "来源IP", "归属地", "请求方法", "目标", "响应码", "证据", "User-Agent", "数据源", "实例"})
		}
		status := ""
		if row.Status != 0 {
			status = strconv.Itoa(row.Status)
		}
		res := resultLabel[row.Result]
		if res == "" {
			res = row.Result
		}
		return cw.Write(csvSafe([]string{row.Time.In(loc).Format("2006-01-02 15:04:05"), row.Severity.Label(), row.RuleID, row.Name, row.Category,
			res, row.SrcIP, row.Location, row.Method, row.Target, status, row.Evidence, row.UA, row.Source, row.Instance}))
	})
	s.audit(r, "导出历史告警", exportDetail(q, loc, n), err)
	if !started {
		if err != nil {
			archiveErr(w, err)
			return
		}
		// 没有数据：返回只有表头的 CSV
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=netsa-alerts-empty.csv")
		w.Write([]byte("\xEF\xBB\xBF时间,等级,规则ID,规则名称,攻击类型,研判结果,来源IP,归属地,请求方法,目标,响应码,证据,User-Agent,数据源,实例\n"))
		return
	}
	cw.Flush()
}
