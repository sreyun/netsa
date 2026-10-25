package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"netsa/internal/rawlog"
)

// rawSem 限制同时进行的原始日志检索（检索需要解压扫描磁盘文件，防止并发的大范围检索耗尽 IO）。
var rawSem = make(chan struct{}, 2)

func (s *Server) rawlogStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.RawLog.Status())
}

// rawQuery 解析检索条件：from / to（RFC 3339 或 Unix 秒，默认最近 1 小时）、ip、q 关键字、source、attacks=1、limit。
func (s *Server) rawQuery(r *http.Request) rawlog.Query {
	q := r.URL.Query()
	to, from := qtime(q.Get("to")), qtime(q.Get("from"))
	if to.IsZero() {
		to = time.Now()
	}
	if from.IsZero() {
		from = to.Add(-time.Hour)
	}
	return rawlog.Query{From: from, To: to, IP: q.Get("ip"), Keyword: q.Get("q"), Source: q.Get("source"), AttacksOnly: q.Get("attacks") == "1",
		Limit: clamp(qint(r, "limit", 200), 1, 5000)}
}

func (s *Server) rawSearch(w http.ResponseWriter, r *http.Request, q rawlog.Query) (rawlog.Result, bool) {
	if s.RawLog == nil {
		writeError(w, http.StatusNotFound, "未启用原始日志留存（配置 rawlog.enabled: true）")
		return rawlog.Result{}, false
	}
	select {
	case rawSem <- struct{}{}:
		defer func() { <-rawSem }()
	default:
		writeError(w, http.StatusTooManyRequests, "检索任务较多，请稍后重试")
		return rawlog.Result{}, false
	}
	extendDeadline(w, time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.RawLog.Search(ctx, q)
	if errors.Is(err, rawlog.ErrRange) {
		writeError(w, http.StatusBadRequest, err.Error())
		return res, false
	}
	return res, true
}

// rawlogSearch 检索原始日志（运营分析员以上；原始日志可能包含 Cookie、令牌等敏感信息）。
func (s *Server) rawlogSearch(w http.ResponseWriter, r *http.Request) {
	q := s.rawQuery(r)
	res, ok := s.rawSearch(w, r, q)
	if !ok {
		return
	}
	s.audit(r, "检索原始日志", rawDesc(q)+"，命中 "+strconv.Itoa(len(res.Records))+" 条", nil)
	writeJSON(w, res)
}

// rawlogExport 导出检索结果（取证留档），文本格式。
func (s *Server) rawlogExport(w http.ResponseWriter, r *http.Request) {
	q := s.rawQuery(r)
	q.Limit = clamp(qint(r, "limit", 5000), 1, 5000)
	res, ok := s.rawSearch(w, r, q)
	if !ok {
		return
	}
	s.audit(r, "导出原始日志", rawDesc(q)+"，共 "+strconv.Itoa(len(res.Records))+" 条", nil)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="netsa-rawlog-`+time.Now().Format("20060102-150405")+`.log"`)
	w.Header().Set("Cache-Control", "no-store")
	rawlog.Export(w, res.Records, s.now().Location())
}

// rawlogVerify 校验留存日志的完整性（哈希链与分段内容），管理员操作。
func (s *Server) rawlogVerify(w http.ResponseWriter, r *http.Request) {
	if s.RawLog == nil {
		writeError(w, http.StatusNotFound, "未启用原始日志留存")
		return
	}
	extendDeadline(w, 5*time.Minute)
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	res := s.RawLog.Verify(ctx)
	var err error
	if len(res.Problems) > 0 {
		err = errors.New(strconv.Itoa(len(res.Problems)) + " 个问题")
	}
	s.audit(r, "校验原始日志完整性", "校验 "+strconv.Itoa(res.Files)+" 个分段，一致 "+strconv.Itoa(res.OK)+" 个", err)
	writeJSON(w, res)
}

func rawDesc(q rawlog.Query) string {
	d := q.From.Format("01-02 15:04") + " ~ " + q.To.Format("01-02 15:04")
	if q.IP != "" {
		d += " IP " + q.IP
	}
	if q.Keyword != "" {
		d += " 关键字 " + q.Keyword
	}
	if q.Source != "" {
		d += " 数据源 " + q.Source
	}
	return d
}
