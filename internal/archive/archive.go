// Package archive 将告警异步批量写入 PostgreSQL 按月分区表，用于长期留存与历史查询（可选功能）。
//
// 写入路径与实时分析解耦：告警先进入内存队列，后台协程按批（COPY）写入；数据库暂时不可用时在队列中缓冲并退避重试，
// 队列满时丢弃并计数，绝不阻塞日志处理。分区按配置时区的自然月创建，过期分区整表删除，清理成本与数据量无关。
package archive

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"netsa/internal/model"
	"netsa/internal/safe"
)

// Table 是归档表名（分区表的父表）。
const Table = "netsa_alerts"

// Options 是归档参数。
type Options struct {
	DSN             string
	RetentionMonths int // 负数表示永久保留
	BatchSize       int
	FlushInterval   time.Duration
	QueueSize       int
	Instance        string         // 写入实例名（多台 netsa 共用一个数据库时区分来源）
	Location        *time.Location // 按此时区划分自然月
}

// Archive 是告警归档器。
type Archive struct {
	opt  Options
	pool *pgxpool.Pool
	q    chan *model.Alert

	parts     sync.Map // 已确认存在的月分区：月份起始时间 Unix → struct{}
	querySem  chan struct{}
	exportSem chan struct{}
	ready     atomic.Bool // 表结构已就绪，可以写入与查询
	readyCh   chan struct{}

	written, dropped, expired, failed, duplicates atomic.Int64

	// 内容相同告警的出现次数（只在写入协程中访问），用于生成可重复计算的告警指纹
	occur                map[uint64]uint32
	mu                   sync.Mutex
	lastErr              string
	lastErrAt, lastWrite time.Time

	cancel context.CancelFunc
	done   chan struct{}
	now    func() time.Time
}

// Open 连接数据库、建表并启动后台写入与维护协程。
func Open(ctx context.Context, opt Options) (*Archive, error) {
	if opt.Location == nil {
		opt.Location = time.Local
	}
	if opt.BatchSize <= 0 {
		opt.BatchSize = 1000
	}
	if opt.FlushInterval <= 0 {
		opt.FlushInterval = 2 * time.Second
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = 100000
	}
	cfg, err := pgxpool.ParseConfig(opt.DSN)
	if err != nil {
		return nil, fmt.Errorf("archive.dsn 无效: %w", scrub(err))
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = 10 * time.Minute
	cfg.ConnConfig.RuntimeParams["application_name"] = "netsa"
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	// 每个连接建立时创建一次写入用的临时表（会话级，连接断开自动删除），批量写入时无需再执行 DDL
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, stageDDL)
		return err
	}
	// 连接池延迟建立连接：数据库暂时不可用时 netsa 照常启动并实时分析，归档在后台重连，期间告警在队列中缓冲
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("archive.dsn 无效: %w", scrub(err))
	}
	a := &Archive{opt: opt, pool: pool, q: make(chan *model.Alert, opt.QueueSize), querySem: make(chan struct{}, 4), exportSem: make(chan struct{}, 1),
		done: make(chan struct{}), readyCh: make(chan struct{}), now: time.Now, occur: map[uint64]uint32{}}
	runCtx, runCancel := context.WithCancel(context.Background())
	a.cancel = runCancel
	go a.connect(runCtx)
	go a.run(runCtx)
	return a, nil
}

// connect 初始化表结构与近期分区，失败时退避重试，成功后开始写入并启动定期维护。
func (a *Archive) connect(ctx context.Context) {
	backoff := time.Second
	for {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := a.migrate(c)
		if err == nil {
			now := a.now().In(a.opt.Location)
			for _, m := range []int{-1, 0, 1} { // 上月、本月、下月
				if err = a.ensurePartition(c, monthStart(now, m)); err != nil {
					break
				}
			}
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			a.ready.Store(true)
			close(a.readyCh)
			log.Printf("[archive] 已连接告警归档数据库 %s（保留 %d 个月）", a.Server(), a.opt.RetentionMonths)
			a.maintain(ctx)
			return
		}
		a.setErr(fmt.Errorf("连接归档数据库失败，%s后重试: %w", backoff, err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// WaitReady 等待归档数据库就绪（测试与离线分析使用）。
func (a *Archive) WaitReady(ctx context.Context) error {
	select {
	case <-a.readyCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ErrNotReady 表示归档数据库尚未连接成功。
var ErrNotReady = errors.New("告警归档数据库暂不可用，请稍后重试（详见数据源页面的归档状态）")

// Server 返回数据库地址（不含用户名与密码），用于界面展示。
func (a *Archive) Server() string {
	c := a.pool.Config().ConnConfig
	return fmt.Sprintf("%s:%d/%s", c.Host, c.Port, c.Database)
}

// Add 投递一条告警（非阻塞）。队列满时丢弃并计数，不影响实时分析。
func (a *Archive) Add(al *model.Alert) {
	if a == nil || al == nil {
		return
	}
	select {
	case a.q <- al:
	default:
		if n := a.dropped.Add(1); n == 1 || n%10000 == 0 {
			log.Printf("[archive] 写入队列已满，已丢弃 %d 条告警（数据库写入跟不上或不可用）", n)
		}
	}
}

// Close 停止接收并在超时前写完队列中剩余的告警。
func (a *Archive) Close(timeout time.Duration) {
	if a == nil {
		return
	}
	a.cancel()
	select {
	case <-a.done:
	case <-time.After(timeout):
		log.Printf("[archive] 关闭超时，队列中仍有 %d 条告警未写入", len(a.q))
	}
	a.pool.Close()
}

// ---------------- 表结构与分区 ----------------

var ddl = []string{
	`CREATE TABLE IF NOT EXISTS ` + Table + ` (
		time      timestamptz NOT NULL,
		alert_id  bigint      NOT NULL,
		instance  text        NOT NULL DEFAULT '',
		src_ip    inet,
		src       text        NOT NULL,
		location  text,
		rule_id   text        NOT NULL,
		rule_name text        NOT NULL,
		category  text,
		severity  smallint    NOT NULL,
		phase     text,
		result    text,
		kind      text,
		method    text,
		status    integer,
		target    text,
		evidence  text,
		ua        text,
		source    text,
		lat       double precision,
		lon       double precision,
		fp        bigint
	) PARTITION BY RANGE (time)`,
	`ALTER TABLE ` + Table + ` ADD COLUMN IF NOT EXISTS fp bigint`,
	// 告警指纹唯一：同一份日志被重复分析（from_beginning 重启、analyze 重复补录）时不会产生重复归档
	`CREATE UNIQUE INDEX IF NOT EXISTS ` + Table + `_fp_idx ON ` + Table + ` (fp, time)`,
	`CREATE INDEX IF NOT EXISTS ` + Table + `_time_idx ON ` + Table + ` (time DESC)`,
	// inet 的 B-Tree 索引同样可用于网段查询（src_ip <<= '10.0.0.0/8'）
	`CREATE INDEX IF NOT EXISTS ` + Table + `_ip_idx ON ` + Table + ` (src_ip, time DESC)`,
	`CREATE INDEX IF NOT EXISTS ` + Table + `_rule_idx ON ` + Table + ` (rule_id, time DESC)`,
	`CREATE INDEX IF NOT EXISTS ` + Table + `_sev_idx ON ` + Table + ` (severity, time DESC)`,
	// 默认分区兜底：时间落在已建分区之外的告警不会写入失败
	`CREATE TABLE IF NOT EXISTS ` + Table + `_default PARTITION OF ` + Table + ` DEFAULT`,
}

// lockKey 是建表 / 建分区时使用的事务级咨询锁，多个 netsa 实例共用一个数据库时串行执行 DDL。
const lockKey = 7366201

func (a *Archive) migrate(ctx context.Context) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("初始化归档表失败: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return fmt.Errorf("初始化归档表失败: %w", err)
	}
	for _, q := range ddl {
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("初始化归档表失败: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// monthStart 返回 t 所在月份偏移 delta 个月后的月初（t 的时区）。
func monthStart(t time.Time, delta int) time.Time {
	return time.Date(t.Year(), t.Month()+time.Month(delta), 1, 0, 0, 0, 0, t.Location())
}

// partitionName 返回月分区表名，例如 netsa_alerts_p202610。
func partitionName(month time.Time) string {
	return fmt.Sprintf("%s_p%04d%02d", Table, month.Year(), int(month.Month()))
}

// ensurePartition 确保月分区存在。为兼容默认分区中已有该月数据的情况，先建独立表、把默认分区中该月的数据迁入，
// 再 ATTACH 为分区（ATTACH 会自动创建父表上定义的索引），全部在一个事务内完成。
func (a *Archive) ensurePartition(ctx context.Context, month time.Time) error {
	key := month.Unix()
	if _, ok := a.parts.Load(key); ok {
		return nil
	}
	from, to := month, monthStart(month, 1)
	name := partitionName(month)
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", name).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		// 分区边界由程序生成（非用户输入），DDL 不支持参数绑定，使用格式化的字面量
		lo, hi := from.Format(time.RFC3339), to.Format(time.RFC3339)
		stmts := []string{
			fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS INCLUDING CONSTRAINTS)`, name, Table),
			fmt.Sprintf(`WITH moved AS (DELETE FROM %s_default WHERE time >= '%s' AND time < '%s' RETURNING *) INSERT INTO %s SELECT * FROM moved`, Table, lo, hi, name),
			fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM ('%s') TO ('%s')`, Table, name, lo, hi),
		}
		for _, q := range stmts {
			if _, err := tx.Exec(ctx, q); err != nil {
				return fmt.Errorf("创建分区 %s 失败: %w", name, err)
			}
		}
		log.Printf("[archive] 已创建分区 %s（%s ~ %s）", name, from.Format("2006-01-02"), to.Format("2006-01-02"))
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	a.parts.Store(key, struct{}{})
	return nil
}

// cutoff 返回保留期的起点（早于此时间的告警不再写入，相应分区会被删除）；永久保留时返回零值。
func (a *Archive) cutoff(now time.Time) time.Time {
	if a.opt.RetentionMonths < 0 {
		return time.Time{}
	}
	return monthStart(now.In(a.opt.Location), -(a.opt.RetentionMonths - 1))
}

// maintain 就绪时与之后每小时检查：提前创建下月分区，删除超过保留期的分区，并清理默认分区中的过期数据。
func (a *Archive) maintain(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for first := true; ; first = false {
		if !first { // 就绪后立即执行一次，之后每小时一次
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					safe.Report("归档维护", r)
				}
			}()
			c, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			now := a.now().In(a.opt.Location)
			for _, m := range []int{0, 1} {
				if err := a.ensurePartition(c, monthStart(now, m)); err != nil {
					a.setErr(err)
				}
			}
			if err := a.dropExpired(c, now); err != nil {
				a.setErr(err)
			}
		}()
	}
}

// dropExpired 删除整月都早于保留期的分区。
func (a *Archive) dropExpired(ctx context.Context, now time.Time) error {
	cut := a.cutoff(now)
	if cut.IsZero() {
		return nil
	}
	parts, err := a.partitions(ctx)
	if err != nil {
		return err
	}
	for _, p := range parts {
		if p.Default || p.To.After(cut) { // 分区内仍有保留期内的数据
			continue
		}
		if _, err := a.pool.Exec(ctx, "DROP TABLE IF EXISTS "+pgx.Identifier{p.Name}.Sanitize()); err != nil {
			return fmt.Errorf("删除过期分区 %s 失败: %w", p.Name, err)
		}
		a.parts.Delete(p.From.Unix())
		log.Printf("[archive] 已删除过期分区 %s（保留 %d 个月）", p.Name, a.opt.RetentionMonths)
	}
	_, err = a.pool.Exec(ctx, "DELETE FROM "+Table+"_default WHERE time < $1", cut)
	return err
}

// PartitionInfo 是一个分区的信息。
type PartitionInfo struct {
	Name    string    `json:"name"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Rows    int64     `json:"rows"` // 估算行数（统计信息），避免对大表做全量计数
	Bytes   int64     `json:"bytes"`
	Default bool      `json:"default,omitempty"`
}

func (a *Archive) partitions(ctx context.Context) ([]PartitionInfo, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT c.relname, GREATEST(c.reltuples, 0)::bigint, pg_total_relation_size(c.oid)
		FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = to_regclass($1)`, Table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PartitionInfo
	for rows.Next() {
		var p PartitionInfo
		if err := rows.Scan(&p.Name, &p.Rows, &p.Bytes); err != nil {
			return nil, err
		}
		if p.Name == Table+"_default" {
			p.Default = true
		} else if t, err := time.ParseInLocation("200601", strings.TrimPrefix(p.Name, Table+"_p"), a.opt.Location); err == nil {
			p.From, p.To = t, monthStart(t, 1)
		} else {
			continue // 非本程序创建的分区
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Default != out[j].Default {
			return !out[i].Default
		}
		return out[i].From.After(out[j].From)
	})
	return out, rows.Err()
}

// ---------------- 写入 ----------------

var columns = []string{"time", "alert_id", "instance", "src_ip", "src", "location", "rule_id", "rule_name", "category", "severity",
	"phase", "result", "kind", "method", "status", "target", "evidence", "ua", "source", "lat", "lon", "fp"}

// item 是待写入的告警及其指纹。
type item struct {
	al *model.Alert
	fp int64
}

// fingerprint 计算告警指纹：由告警内容（时间、来源、规则、目标、证据等，不含每次运行都会变化的告警编号）
// 与该内容在本次运行中的出现序号组成。重复分析同一份日志时，内容与出现顺序相同，指纹相同而被去重；
// 同一秒内内容完全相同的多条真实告警序号不同，仍会全部保留。只在写入协程中调用。
func (a *Archive) fingerprint(al *model.Alert) int64 {
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(al.Time.UnixNano()))
	h.Write(buf[:])
	for _, s := range []string{al.SrcIP, al.RuleID, al.Target, al.Method, al.Evidence, al.UA, al.Source, al.Result, string(al.Kind)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	binary.LittleEndian.PutUint64(buf[:], uint64(al.Status))
	h.Write(buf[:])
	content := h.Sum64()
	if len(a.occur) >= 200000 { // 相同内容的告警总是在相近时间出现，计数表定期清空即可
		clear(a.occur)
	}
	n := a.occur[content]
	a.occur[content] = n + 1
	binary.LittleEndian.PutUint32(buf[:4], n)
	h.Write(buf[:4])
	return int64(h.Sum64())
}

// clean 处理写入数据库的文本：PostgreSQL 的 text 不允许 NUL 字节且要求合法 UTF-8，
// 日志中的攻击载荷可能包含两者，不处理会导致整批写入失败。
func clean(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return clean(s)
}

// row 把告警转换为一行；返回 false 表示早于保留期，不写入。
func (a *Archive) row(it item, now, cut time.Time) ([]any, bool) {
	al := it.al
	t := al.Time
	if t.IsZero() || t.After(now.Add(time.Hour)) { // 设备时钟错误产生的未来时间按接收时间记录
		t = now
	}
	if !cut.IsZero() && t.Before(cut) {
		return nil, false
	}
	var ip any
	if addr, err := netip.ParseAddr(al.SrcIP); err == nil {
		addr = addr.Unmap()
		ip = netip.PrefixFrom(addr, addr.BitLen())
	}
	var status, lat, lon any
	if al.Status != 0 {
		status = int32(al.Status)
	}
	if al.Lat != 0 || al.Lon != 0 {
		lat, lon = al.Lat, al.Lon
	}
	return []any{
		t, int64(al.ID), a.opt.Instance, ip, clean(al.SrcIP), nullable(al.Location), clean(al.RuleID), clean(al.Name), nullable(al.Category),
		int16(al.Severity), nullable(al.Phase), nullable(al.Result), nullable(string(al.Kind)), nullable(al.Method), status,
		nullable(al.Target), nullable(al.Evidence), nullable(al.UA), nullable(al.Source), lat, lon, it.fp,
	}, true
}

// run 是写入循环：凑满一批或到达刷新间隔时写入；失败时保留本批并指数退避重试。
func (a *Archive) run(ctx context.Context) {
	defer close(a.done)
	batch := make([]item, 0, a.opt.BatchSize)
	tick := time.NewTicker(a.opt.FlushInterval)
	defer tick.Stop()
	backoff := time.Duration(0)
	var retryAt time.Time
	flush := func(c context.Context) {
		if len(batch) == 0 || time.Now().Before(retryAt) || !a.ready.Load() {
			return
		}
		if err := a.write(c, batch); err != nil {
			if c.Err() != nil { // 正在关闭：保留本批，由退出前的刷新写入
				return
			}
			a.failed.Add(1)
			a.setErr(err)
			if !retryable(err) {
				a.writeEach(c, batch) // 数据问题：逐条写入，跳过有问题的告警
				batch = batch[:0]
				return
			}
			backoff = min(max(backoff*2, time.Second), 30*time.Second)
			retryAt = time.Now().Add(backoff)
			return
		}
		backoff, retryAt = 0, time.Time{}
		batch = batch[:0]
	}
	for {
		// 本批已满（通常是在等待重试）时暂停从队列读取，积压由有界队列缓冲，队列满后新告警丢弃并计数
		in := a.q
		if len(batch) >= a.opt.BatchSize {
			in = nil
		}
		select {
		case al := <-in:
			batch = append(batch, item{al, a.fingerprint(al)})
			if len(batch) >= a.opt.BatchSize {
				flush(ctx)
			}
		case <-tick.C:
			flush(ctx)
		case <-ctx.Done():
			// 退出前写完队列中剩余的告警
			c, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			retryAt = time.Time{}
			for {
				select {
				case al := <-a.q:
					batch = append(batch, item{al, a.fingerprint(al)})
					if len(batch) >= a.opt.BatchSize {
						flush(c)
					}
					continue
				default:
				}
				break
			}
			flush(c)
			return
		}
	}
}

// write 批量写入一批告警：COPY 到会话级临时表后插入归档表（分区表自动路由到对应月分区），
// 指纹已存在的告警（重复分析同一份日志）跳过并计数。
func (a *Archive) write(ctx context.Context, batch []item) (err error) {
	defer func() {
		if r := recover(); r != nil {
			safe.Report("归档写入", r)
			err = fmt.Errorf("内部错误: %v", r)
		}
	}()
	now := a.now()
	cut := a.cutoff(now)
	rows := make([][]any, 0, len(batch))
	months := map[int64]time.Time{}
	expired := 0
	for _, it := range batch {
		r, ok := a.row(it, now, cut)
		if !ok {
			expired++
			continue
		}
		t := r[0].(time.Time)
		m := monthStart(t.In(a.opt.Location), 0)
		months[m.Unix()] = m
		rows = append(rows, r)
	}
	// 写入前确保涉及的月分区存在（只为保留期内的月份建分区，其余落入默认分区）
	for _, m := range months {
		if !m.Before(cut) && !m.After(now.Add(32*24*time.Hour)) {
			if err := a.ensurePartition(ctx, m); err != nil {
				return partitionError{err} // 建分区失败（如多实例并发、锁超时）与告警数据无关，整批稍后重试
			}
		}
	}
	if len(rows) > 0 {
		c, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		inserted, err := a.insert(c, rows)
		if err != nil {
			return err
		}
		a.written.Add(inserted)
		a.duplicates.Add(int64(len(rows)) - inserted)
	}
	a.expired.Add(int64(expired))
	a.mu.Lock()
	a.lastWrite = now
	a.mu.Unlock()
	return nil
}

// stageDDL 是批量写入的临时中转表，列与 columns 一致；ON COMMIT DELETE ROWS 使每个事务结束后自动清空。
const stageDDL = `CREATE TEMP TABLE IF NOT EXISTS netsa_stage (
	time timestamptz, alert_id bigint, instance text, src_ip inet, src text, location text, rule_id text, rule_name text,
	category text, severity smallint, phase text, result text, kind text, method text, status integer, target text,
	evidence text, ua text, source text, lat double precision, lon double precision, fp bigint
) ON COMMIT DELETE ROWS`

var insertSQL = `INSERT INTO ` + Table + ` (` + strings.Join(columns, ", ") + `) SELECT ` + strings.Join(columns, ", ") +
	` FROM netsa_stage ON CONFLICT DO NOTHING`

// insert 在一个事务内把行 COPY 到临时表（事务结束自动清空），再插入归档表并跳过重复指纹，返回实际插入的行数。
func (a *Archive) insert(ctx context.Context, rows [][]any) (int64, error) {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"netsa_stage"}, columns, pgx.CopyFromRows(rows)); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, insertSQL)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}

// writeEach 逐条写入（批量写入因个别数据失败时使用），无法写入的告警丢弃并计数。
func (a *Archive) writeEach(ctx context.Context, batch []item) {
	for _, it := range batch {
		if err := a.write(ctx, []item{it}); err != nil {
			a.dropped.Add(1)
			if retryable(err) {
				return // 连接问题：剩余的下次再写也会失败，直接放弃本批
			}
		}
	}
}

type partitionError struct{ error }

func (e partitionError) Unwrap() error { return e.error }

// retryable 判断错误是否值得重试：连接 / 网络 / 资源类错误重试；数据类（22）与约束类（23）错误不重试。
func retryable(err error) bool {
	if errors.As(err, &partitionError{}) {
		return true
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return !strings.HasPrefix(pg.Code, "22") && !strings.HasPrefix(pg.Code, "23") && !strings.HasPrefix(pg.Code, "42")
	}
	return true
}

func (a *Archive) setErr(err error) {
	msg := scrub(err).Error()
	a.mu.Lock()
	changed := msg != a.lastErr
	a.lastErr, a.lastErrAt = msg, a.now()
	a.mu.Unlock()
	if changed {
		log.Printf("[archive] %s", msg)
	}
}

// scrub 去掉错误信息中可能包含的连接口令。
func scrub(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if i := strings.Index(s, "password="); i >= 0 {
		j := strings.IndexAny(s[i:], " &")
		if j < 0 {
			j = len(s) - i
		}
		s = s[:i] + "password=****" + s[i+j:]
	}
	if i := strings.Index(s, "://"); i >= 0 {
		if at := strings.Index(s[i:], "@"); at > 0 {
			if colon := strings.Index(s[i+3:i+at], ":"); colon >= 0 {
				s = s[:i+3+colon+1] + "****" + s[i+at:]
			}
		}
	}
	return errors.New(s)
}

// ---------------- 状态 ----------------

// Status 是归档运行状态。
type Status struct {
	Enabled         bool            `json:"enabled"`
	Connected       bool            `json:"connected"`
	Server          string          `json:"server,omitempty"`
	Written         int64           `json:"written"`
	Queued          int             `json:"queued"`
	Dropped         int64           `json:"dropped"`
	Expired         int64           `json:"expired"`
	Duplicates      int64           `json:"duplicates"` // 重复分析同一份日志产生、已跳过的告警
	FailedBatches   int64           `json:"failed_batches"`
	LastWrite       time.Time       `json:"last_write"`
	LastError       string          `json:"last_error,omitempty"`
	LastErrorAt     time.Time       `json:"last_error_at"`
	RetentionMonths int             `json:"retention_months"`
	Partitions      []PartitionInfo `json:"partitions"`
}

// Status 返回运行状态（包含分区列表，需要查询数据库）。
func (a *Archive) Status(ctx context.Context) Status {
	if a == nil {
		return Status{Partitions: []PartitionInfo{}}
	}
	st := Status{Enabled: true, Server: a.Server(), Written: a.written.Load(), Queued: len(a.q), Dropped: a.dropped.Load(),
		Expired: a.expired.Load(), Duplicates: a.duplicates.Load(), FailedBatches: a.failed.Load(), RetentionMonths: a.opt.RetentionMonths, Partitions: []PartitionInfo{}}
	a.mu.Lock()
	st.LastWrite, st.LastError, st.LastErrorAt = a.lastWrite, a.lastErr, a.lastErrAt
	a.mu.Unlock()
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !a.ready.Load() {
		return st
	}
	if parts, err := a.partitions(c); err == nil {
		st.Connected = true
		st.Partitions = parts
	} else if st.LastError == "" {
		st.LastError = scrub(err).Error()
	}
	return st
}

// Counts 返回已写入与丢弃的告警数（不访问数据库）。
func (a *Archive) Counts() (written, dropped int64) {
	if a == nil {
		return 0, 0
	}
	return a.written.Load(), a.dropped.Load()
}
