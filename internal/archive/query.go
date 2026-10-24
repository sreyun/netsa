package archive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"netsa/internal/model"
)

// Query 是历史告警查询条件。
type Query struct {
	From, To    time.Time
	IP          string // IP 或网段（CIDR）
	Rule        string // 规则 ID（精确）或规则名称（包含）
	MinSeverity model.Severity
	Category    string
	Result      string
	Kind        string
	Phase       string // 攻击链阶段
	Search      string // 在目标、证据、规则名称中查找
	Limit       int
	Offset      int
}

// 查询限制：防止单次查询拖垮数据库。
const (
	maxLimit     = 500
	maxOffset    = 100000
	queryTimeout = 20 * time.Second
	exportMax    = 200000
)

// ErrBusy 表示同时进行的历史查询过多。
var ErrBusy = errors.New("历史查询过多，请稍后重试")

// ErrExportBusy 表示已有导出任务在进行。
var ErrExportBusy = fmt.Errorf("%w：已有历史告警导出任务正在进行", ErrBusy)

// where 根据条件生成 WHERE 子句与参数（全部使用参数绑定，杜绝 SQL 注入）。
func (q *Query) where() (string, []any, error) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if !q.From.IsZero() {
		conds = append(conds, "time >= "+arg(q.From))
	}
	if !q.To.IsZero() {
		conds = append(conds, "time < "+arg(q.To))
	}
	if s := strings.TrimSpace(q.IP); s != "" {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return "", nil, fmt.Errorf("IP 或网段格式无效: %s", s)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		conds = append(conds, "src_ip <<= "+arg(p.Masked()))
	}
	if s := strings.TrimSpace(q.Rule); s != "" {
		v := arg(s)
		conds = append(conds, "(rule_id = "+v+" OR rule_name ILIKE "+arg("%"+escapeLike(s)+"%")+" ESCAPE '\\')")
	}
	if q.MinSeverity > model.SevInfo {
		conds = append(conds, "severity >= "+arg(int16(q.MinSeverity)))
	}
	for _, f := range []struct{ col, v string }{{"category", q.Category}, {"result", q.Result}, {"kind", q.Kind}, {"phase", q.Phase}} {
		if s := strings.TrimSpace(f.v); s != "" {
			conds = append(conds, f.col+" = "+arg(s))
		}
	}
	if s := strings.TrimSpace(q.Search); s != "" {
		if len([]rune(s)) > 100 {
			return "", nil, errors.New("关键字过长")
		}
		v := arg("%" + escapeLike(s) + "%")
		conds = append(conds, "(target ILIKE "+v+" ESCAPE '\\' OR evidence ILIKE "+v+" ESCAPE '\\' OR rule_name ILIKE "+v+" ESCAPE '\\')")
	}
	if len(conds) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args, nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Row 是一条历史告警。
type Row struct {
	Time     time.Time      `json:"time"`
	AlertID  int64          `json:"alert_id"`
	Instance string         `json:"instance,omitempty"`
	SrcIP    string         `json:"src_ip"`
	Location string         `json:"location,omitempty"`
	RuleID   string         `json:"rule_id"`
	Name     string         `json:"name"`
	Category string         `json:"category,omitempty"`
	Severity model.Severity `json:"severity"`
	Phase    string         `json:"phase,omitempty"`
	Result   string         `json:"result,omitempty"`
	Kind     string         `json:"kind,omitempty"`
	Method   string         `json:"method,omitempty"`
	Status   int            `json:"status,omitempty"`
	Target   string         `json:"target,omitempty"`
	Evidence string         `json:"evidence,omitempty"`
	UA       string         `json:"ua,omitempty"`
	Source   string         `json:"source,omitempty"`
}

const selectCols = `time, alert_id, instance, src, COALESCE(location, ''), rule_id, rule_name, COALESCE(category, ''), severity,
	COALESCE(phase, ''), COALESCE(result, ''), COALESCE(kind, ''), COALESCE(method, ''), COALESCE(status, 0),
	COALESCE(target, ''), COALESCE(evidence, ''), COALESCE(ua, ''), COALESCE(source, '')`

func scanRow(rows pgx.Rows) (Row, error) {
	var r Row
	var sev int16
	var status int32
	err := rows.Scan(&r.Time, &r.AlertID, &r.Instance, &r.SrcIP, &r.Location, &r.RuleID, &r.Name, &r.Category, &sev,
		&r.Phase, &r.Result, &r.Kind, &r.Method, &status, &r.Target, &r.Evidence, &r.UA, &r.Source)
	r.Severity, r.Status = model.Severity(sev), int(status)
	return r, err
}

// Result 是一页查询结果。
type Result struct {
	Items   []Row `json:"items"`
	HasMore bool  `json:"has_more"`
}

func (a *Archive) acquire(ctx context.Context) error {
	if !a.ready.Load() {
		return ErrNotReady
	}
	select {
	case a.querySem <- struct{}{}:
		return nil
	case <-time.After(5 * time.Second):
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Archive) release() { <-a.querySem }

// Search 按条件分页查询历史告警（按时间倒序）。多取一条判断是否还有下一页，避免对大表计数。
func (a *Archive) Search(ctx context.Context, q Query) (*Result, error) {
	q.Limit = min(max(q.Limit, 1), maxLimit)
	q.Offset = min(max(q.Offset, 0), maxOffset)
	where, args, err := q.where()
	if err != nil {
		return nil, err
	}
	if err := a.acquire(ctx); err != nil {
		return nil, err
	}
	defer a.release()
	c, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	sql := "SELECT " + selectCols + " FROM " + Table + where + " ORDER BY time DESC, alert_id DESC LIMIT " +
		strconv.Itoa(q.Limit+1) + " OFFSET " + strconv.Itoa(q.Offset)
	rows, err := a.pool.Query(c, sql, args...)
	if err != nil {
		return nil, queryErr(err)
	}
	defer rows.Close()
	res := &Result{Items: []Row{}}
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, queryErr(err)
		}
		res.Items = append(res.Items, r)
	}
	if err := rows.Err(); err != nil {
		return nil, queryErr(err)
	}
	if len(res.Items) > q.Limit {
		res.Items, res.HasMore = res.Items[:q.Limit], true
	}
	return res, nil
}

// Stats 是查询范围内的统计。
type Stats struct {
	Total      int64            `json:"total"`
	BySeverity map[string]int64 `json:"by_severity"`
	TopIPs     []NameCount      `json:"top_ips"`
	TopRules   []NameCount      `json:"top_rules"`
	Trend      []NameCount      `json:"trend"`  // 告警趋势（配置时区），粒度见 Bucket
	Bucket     string           `json:"bucket"` // hour（数据跨度 3 天以内）/ day（400 天以内）/ month
	FirstSeen  time.Time        `json:"first_seen"`
	LastSeen   time.Time        `json:"last_seen"`
}

// NameCount 是名称与计数。
type NameCount struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	Count int64  `json:"count"`
}

// Stats 统计查询范围内的告警：总数、各等级、TOP 来源 IP、TOP 规则与每日趋势。
func (a *Archive) Stats(ctx context.Context, q Query) (*Stats, error) {
	where, args, err := q.where()
	if err != nil {
		return nil, err
	}
	if err := a.acquire(ctx); err != nil {
		return nil, err
	}
	defer a.release()
	c, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	st := &Stats{BySeverity: map[string]int64{}, TopIPs: []NameCount{}, TopRules: []NameCount{}, Trend: []NameCount{}, Bucket: "day"}
	// 一次扫描得到总数、各等级与时间范围
	rows, err := a.pool.Query(c, "SELECT severity, count(*), min(time), max(time) FROM "+Table+where+" GROUP BY severity", args...)
	if err != nil {
		return nil, queryErr(err)
	}
	for rows.Next() {
		var sev int16
		var n int64
		var first, last time.Time
		if err := rows.Scan(&sev, &n, &first, &last); err != nil {
			rows.Close()
			return nil, queryErr(err)
		}
		st.Total += n
		st.BySeverity[model.Severity(sev).String()] = n
		if st.FirstSeen.IsZero() || first.Before(st.FirstSeen) {
			st.FirstSeen = first
		}
		if last.After(st.LastSeen) {
			st.LastSeen = last
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, queryErr(err)
	}
	if st.Total == 0 {
		return st, nil
	}
	top := func(sql string, dst *[]NameCount) error {
		rows, err := a.pool.Query(c, sql, args...)
		if err != nil {
			return queryErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var nc NameCount
			if err := rows.Scan(&nc.Name, &nc.Label, &nc.Count); err != nil {
				return queryErr(err)
			}
			*dst = append(*dst, nc)
		}
		return queryErr(rows.Err())
	}
	if err := top("SELECT src, COALESCE(max(location), ''), count(*) FROM "+Table+where+" GROUP BY src ORDER BY 3 DESC LIMIT 10", &st.TopIPs); err != nil {
		return nil, err
	}
	if err := top("SELECT rule_id, max(rule_name), count(*) FROM "+Table+where+" GROUP BY rule_id ORDER BY 3 DESC LIMIT 10", &st.TopRules); err != nil {
		return nil, err
	}
	// 趋势粒度按实际数据跨度选择，短时间范围（如从总览趋势图下钻的几分钟）也能看出分布
	format := "YYYY-MM-DD"
	switch span := st.LastSeen.Sub(st.FirstSeen); {
	case span <= 72*time.Hour:
		format, st.Bucket = "YYYY-MM-DD HH24:00", "hour"
	case span > 400*24*time.Hour:
		format, st.Bucket = "YYYY-MM", "month"
	}
	ts := "time AT TIME ZONE " + quoteLiteral(a.opt.Location.String())
	if a.opt.Location == time.Local {
		ts = "time"
	}
	// 取最近的 400 个时间段（倒序取再反转）
	if err := top("SELECT to_char("+ts+", '"+format+"') AS d, '', count(*) FROM "+Table+where+" GROUP BY d ORDER BY d DESC LIMIT 400", &st.Trend); err != nil {
		return nil, err
	}
	slices.Reverse(st.Trend)
	return st, nil
}

// quoteLiteral 生成 SQL 字符串字面量（仅用于程序内部的时区名）。
func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Export 按条件导出历史告警（时间倒序，最多 exportMax 条），逐行回调，不在内存中缓存全部结果。
func (a *Archive) Export(ctx context.Context, q Query, fn func(Row) error) (int, error) {
	where, args, err := q.where()
	if err != nil {
		return 0, err
	}
	if err := a.acquire(ctx); err != nil {
		return 0, err
	}
	defer a.release()
	// 导出耗时较长，同时只允许一个，避免占满查询名额影响其他人检索
	select {
	case a.exportSem <- struct{}{}:
		defer func() { <-a.exportSem }()
	default:
		return 0, ErrExportBusy
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	rows, err := a.pool.Query(c, "SELECT "+selectCols+" FROM "+Table+where+" ORDER BY time DESC, alert_id DESC LIMIT "+strconv.Itoa(exportMax), args...)
	if err != nil {
		return 0, queryErr(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return n, queryErr(err)
		}
		if err := fn(r); err != nil {
			return n, err
		}
		n++
	}
	return n, queryErr(rows.Err())
}

// queryErr 把超时等错误转换为易懂的提示，并去掉可能包含的连接口令。
func queryErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("查询超时，请缩小时间范围或增加筛选条件")
	}
	return scrub(err)
}
