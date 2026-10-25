// Package rawlog 留存解析后的原始日志，供事后取证、按 IP / 关键字检索与告警前后的原始日志回溯。
//
// 存储结构：<dir>/<YYYYMMDD>/<HH>.log.gz，按事件时间分小时存放（离线导入的历史日志也落在对应的小时里，检索时间范围准确）。
// 每个分段是若干个首尾相接的 gzip 成员（重新打开追加时写入新的成员），每行为
// “毫秒时间戳 \t 类型 \t 数据源 \t 来源IP \t 目的IP \t 标记 \t 原始日志”。
// 每个分段附带一个 IP 布隆过滤器（<HH>.bloom），按 IP 检索时跳过不包含该 IP 的分段。
// 分段关闭时计算 SHA-256 写入哈希链清单（manifest.jsonl），可校验日志是否被篡改或删除。
//
// 写入在独立协程中进行，检测流水线只做一次非阻塞投递；写入跟不上时丢弃并计数，不影响实时检测。
package rawlog

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/model"
	"netsa/internal/safe"
)

// Options 是留存配置。
type Options struct {
	Dir           string
	RetentionDays int   // 留存天数（0 表示不按时间清理）
	MaxBytes      int64 // 总容量上限（0 表示不限制），超过时从最早的日期开始删除
	AttacksOnly   bool  // 只留存命中攻击规则的事件
	Location      *time.Location
}

type batch struct {
	evs    []*model.Event
	attack []bool
}

// Store 是原始日志留存。
type Store struct {
	opt    Options
	q      chan batch
	done   chan struct{}
	cancel context.CancelFunc

	mu   sync.Mutex // 保护 segs 与清单
	segs map[string]*segment
	last string // 清单最后一条的哈希

	written, dropped, bytesIn atomic.Int64
	expired                   atomic.Int64 // 时间早于留存期限、未写入的日志
	opens                     int          // 本分钟新打开的历史分段数（受 mu 保护）
	opensMin                  int64
	lastErr                   atomic.Pointer[string]
	closed                    atomic.Bool
}

// Open 创建留存目录并启动写入协程。
func Open(ctx context.Context, opt Options) (*Store, error) {
	if opt.Dir == "" {
		return nil, errors.New("rawlog.dir 不能为空")
	}
	if opt.Location == nil {
		opt.Location = time.Local
	}
	if err := os.MkdirAll(opt.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("创建原始日志目录失败: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Store{opt: opt, q: make(chan batch, 512), done: make(chan struct{}), segs: map[string]*segment{}, cancel: cancel}
	s.last = s.manifestTail()
	go s.run(ctx)
	return s, nil
}

// Write 投递一批事件（非阻塞）。hits 与 evs 一一对应，用于标记攻击事件。
func (s *Store) Write(evs []*model.Event, hits [][]model.Hit) {
	if s == nil || len(evs) == 0 || s.closed.Load() {
		return
	}
	b := batch{evs: evs, attack: make([]bool, len(evs))}
	any := false
	for i := range evs {
		for _, h := range hits[i] {
			if !h.TagOnly {
				b.attack[i] = true
				break
			}
		}
		any = any || b.attack[i]
	}
	if s.opt.AttacksOnly && !any {
		return
	}
	select {
	case s.q <- b:
	default:
		s.dropped.Add(int64(len(evs)))
	}
}

func (s *Store) setErr(err error) {
	msg := err.Error()
	s.lastErr.Store(&msg)
	log.Printf("[rawlog] %v", err)
}

func (s *Store) run(ctx context.Context) {
	defer close(s.done)
	flush := time.NewTicker(2 * time.Second)
	defer flush.Stop()
	clean := time.NewTimer(10 * time.Second)
	defer clean.Stop()
	for {
		select {
		case b := <-s.q:
			s.safeWrite(b)
		case <-flush.C:
			s.maintain(false)
		case <-clean.C:
			s.cleanup()
			clean.Reset(time.Hour)
		case <-ctx.Done():
			// 写完队列中剩余的日志再退出
			for {
				select {
				case b := <-s.q:
					s.safeWrite(b)
					continue
				default:
				}
				break
			}
			s.maintain(true)
			return
		}
	}
}

func (s *Store) safeWrite(b batch) {
	defer func() {
		if p := recover(); p != nil {
			safe.Report("原始日志留存", p)
		}
	}()
	now := time.Now()
	var cut time.Time
	if s.opt.RetentionDays > 0 {
		cut = now.AddDate(0, 0, -s.opt.RetentionDays)
	}
	for i, ev := range b.evs {
		if s.opt.AttacksOnly && !b.attack[i] {
			continue
		}
		t := ev.Time
		// 未来的时间（发送端时钟错误或伪造）按接收时间归档：否则会生成不会被按天清理的未来目录
		if t.IsZero() || t.After(now.Add(time.Hour)) {
			t = now
		}
		if !cut.IsZero() && t.Before(cut) {
			s.expired.Add(1) // 早于留存期限：写入后也会在下次清理时删除
			continue
		}
		seg, err := s.segmentFor(&t, now)
		if err != nil {
			s.setErr(err)
			s.dropped.Add(1)
			continue
		}
		n, err := seg.append(t, ev, b.attack[i])
		if err != nil {
			s.setErr(err)
			s.dropped.Add(1)
			continue
		}
		s.written.Add(1)
		s.bytesIn.Add(int64(n))
	}
}

// key 返回事件所属分段的键（YYYYMMDD/HH）。
func (s *Store) key(t time.Time) string {
	return t.In(s.opt.Location).Format("20060102/15")
}

const maxOpenSegments = 6

// maxHistoryOpens 是每分钟最多新打开的历史分段数。时间戳在多个小时之间来回跳动的日志（时钟混乱或伪造）
// 会让分段反复关闭、计算哈希、再打开，超过后按接收时间归档。
const maxHistoryOpens = 30

// segmentFor 返回事件所属的分段；历史分段打开过于频繁时改按接收时间归档（*t 改为 now）。
func (s *Store) segmentFor(t *time.Time, now time.Time) (*segment, error) {
	k, cur := s.key(*t), s.key(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	if seg := s.segs[k]; seg != nil {
		seg.used = now
		return seg, nil
	}
	if k != cur {
		if m := now.Unix() / 60; m != s.opensMin {
			s.opensMin, s.opens = m, 0
		}
		if s.opens >= maxHistoryOpens {
			k, *t = cur, now
			if seg := s.segs[k]; seg != nil {
				seg.used = now
				return seg, nil
			}
		} else {
			s.opens++
		}
	}
	if len(s.segs) >= maxOpenSegments { // 关闭最久未写入的分段，当前小时的分段（通常最大）不关闭
		var old *segment
		for _, sg := range s.segs {
			if sg.key != cur && (old == nil || sg.used.Before(old.used)) {
				old = sg
			}
		}
		s.closeLocked(old)
	}
	seg, err := openSegment(s.opt.Dir, k)
	if err != nil {
		return nil, err
	}
	s.segs[k] = seg
	return seg, nil
}

// maintain 刷新缓冲区（检索能看到 2 秒前写入的日志），关闭 2 分钟未写入的分段；final 为真时关闭全部分段。
func (s *Store) maintain(final bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, seg := range s.segs {
		if final || now.Sub(seg.used) > 2*time.Minute {
			s.closeLocked(seg)
			continue
		}
		if err := seg.flush(); err != nil {
			s.setErr(err)
		}
	}
}

func (s *Store) closeLocked(seg *segment) {
	delete(s.segs, seg.key)
	sum, size, err := seg.close()
	if err != nil {
		s.setErr(err)
		return
	}
	if sum != "" {
		s.appendManifestLocked(seg.key+".log.gz", size, sum)
	}
}

// Close 停止接收，写完队列中剩余的日志并关闭全部分段（最多等待 timeout）。
func (s *Store) Close(timeout time.Duration) {
	if s == nil {
		return
	}
	s.closed.Store(true)
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(timeout):
	}
}

// ---------------- 分段 ----------------

const (
	bloomBits = 1 << 20 // 每个分段 128KB，10 万个不同 IP 时误判率约万分之二
	bloomK    = 4
)

type bloom []byte

func bloomHash(s string) (uint64, uint64) {
	h := fnv.New64a()
	h.Write([]byte(s))
	a := h.Sum64()
	return a, a>>33 | a<<31 | 1
}

func (b bloom) add(s string) {
	h1, h2 := bloomHash(s)
	for i := uint64(0); i < bloomK; i++ {
		p := (h1 + i*h2) % bloomBits
		b[p>>3] |= 1 << (p & 7)
	}
}

func (b bloom) has(s string) bool {
	if len(b) != bloomBits/8 {
		return true // 没有过滤器（或已损坏）时不跳过
	}
	h1, h2 := bloomHash(s)
	for i := uint64(0); i < bloomK; i++ {
		p := (h1 + i*h2) % bloomBits
		if b[p>>3]&(1<<(p&7)) == 0 {
			return false
		}
	}
	return true
}

type segment struct {
	key   string
	path  string
	f     *os.File
	gz    *gzip.Writer
	w     *bufio.Writer
	bloom bloom
	dirty bool
	used  time.Time
	line  []byte
}

func openSegment(dir, key string) (*segment, error) {
	path := filepath.Join(dir, filepath.FromSlash(key)+".log.gz")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	seg := &segment{key: key, path: path, f: f, bloom: make(bloom, bloomBits/8), used: time.Now()}
	if old, err := os.ReadFile(bloomPath(path)); err == nil && len(old) == len(seg.bloom) {
		copy(seg.bloom, old) // 重新打开时合并已有的过滤器
	}
	seg.gz, _ = gzip.NewWriterLevel(f, gzip.BestSpeed)
	seg.w = bufio.NewWriterSize(seg.gz, 64<<10)
	return seg, nil
}

func bloomPath(logPath string) string { return strings.TrimSuffix(logPath, ".log.gz") + ".bloom" }

// clean 把原始日志中的换行等控制字符替换为空格，保证一行一条。
func clean(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\r' || c == 0 {
			c = ' '
		}
		dst = append(dst, c)
	}
	return dst
}

func field(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || c == '\n' || c == '\r' {
			c = ' '
		}
		dst = append(dst, c)
	}
	return append(dst, '\t')
}

func (seg *segment) append(t time.Time, ev *model.Event, attack bool) (int, error) {
	b := seg.line[:0]
	b = strconv.AppendInt(b, t.UnixMilli(), 10)
	b = append(b, '\t')
	b = field(b, string(ev.Kind))
	b = field(b, ev.Source)
	b = field(b, ev.SrcIP)
	b = field(b, ev.DstIP)
	if attack {
		b = append(b, 'A')
	}
	if ev.Outbound {
		b = append(b, 'O')
	}
	b = append(b, '\t')
	b = clean(b, ev.Raw)
	b = append(b, '\n')
	seg.line = b
	if ev.SrcIP != "" {
		seg.bloom.add(ev.SrcIP)
	}
	if ev.DstIP != "" {
		seg.bloom.add(ev.DstIP)
	}
	seg.dirty = true
	return seg.w.Write(b)
}

func (seg *segment) flush() error {
	if !seg.dirty {
		return nil
	}
	seg.dirty = false
	if err := seg.w.Flush(); err != nil {
		return err
	}
	if err := seg.gz.Flush(); err != nil {
		return err
	}
	return os.WriteFile(bloomPath(seg.path), seg.bloom, 0o640)
}

// close 结束当前 gzip 成员并关闭文件，返回文件的 SHA-256 与大小。
func (seg *segment) close() (string, int64, error) {
	err := seg.w.Flush()
	if e := seg.gz.Close(); err == nil {
		err = e
	}
	if e := seg.f.Close(); err == nil {
		err = e
	}
	if e := os.WriteFile(bloomPath(seg.path), seg.bloom, 0o640); err == nil {
		err = e
	}
	if err != nil {
		return "", 0, fmt.Errorf("关闭原始日志分段 %s 失败: %w", seg.key, err)
	}
	sum, size, err := fileSHA256(seg.path)
	return sum, size, err
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// ---------------- 哈希链清单 ----------------

// ManifestEntry 是清单中的一条记录：Hash = SHA-256(Prev + File + Size + SHA256 + Time)。
type ManifestEntry struct {
	Time   time.Time `json:"time"`
	File   string    `json:"file"`
	Size   int64     `json:"size"`
	SHA256 string    `json:"sha256"`
	Prev   string    `json:"prev"`
	Hash   string    `json:"hash"`
}

func (e *ManifestEntry) compute() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|%s|%s", e.Prev, e.File, e.Size, e.SHA256, e.Time.UTC().Format(time.RFC3339Nano))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Store) manifestPath() string { return filepath.Join(s.opt.Dir, "manifest.jsonl") }

func (s *Store) manifestTail() string {
	entries, _ := readManifest(s.manifestPath())
	if n := len(entries); n > 0 {
		return entries[n-1].Hash
	}
	return ""
}

func readManifest(path string) ([]ManifestEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ManifestEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e ManifestEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

func (s *Store) appendManifestLocked(file string, size int64, sum string) {
	e := ManifestEntry{Time: time.Now().UTC(), File: file, Size: size, SHA256: sum, Prev: s.last}
	e.Hash = e.compute()
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(s.manifestPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		s.setErr(err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		s.setErr(err)
		return
	}
	s.last = e.Hash
}

// VerifyResult 是完整性校验结果。
type VerifyResult struct {
	Entries   int       `json:"entries"`
	Files     int       `json:"files"`    // 校验的分段数
	OK        int       `json:"ok"`       // 内容与清单一致
	Open      int       `json:"open"`     // 正在写入、尚未登记的分段
	Expired   int       `json:"expired"`  // 已按留存策略清理
	ChainOK   bool      `json:"chain_ok"` // 哈希链完整
	Problems  []string  `json:"problems"` // 篡改、缺失等问题
	CheckedAt time.Time `json:"checked_at"`
}

// Verify 校验哈希链与各分段内容：链断裂说明清单被修改；分段哈希不一致说明日志被篡改；留存期内的分段缺失说明被删除。
func (s *Store) Verify(ctx context.Context) VerifyResult {
	res := VerifyResult{ChainOK: true, Problems: []string{}, CheckedAt: time.Now()}
	s.mu.Lock()
	open := map[string]bool{}
	for k := range s.segs {
		open[k+".log.gz"] = true
	}
	s.mu.Unlock()
	entries, err := readManifest(s.manifestPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Problems = append(res.Problems, "读取清单失败: "+err.Error())
	}
	res.Entries = len(entries)
	latest := map[string]ManifestEntry{}
	prev := ""
	for i, e := range entries {
		if e.Prev != prev || e.compute() != e.Hash {
			if res.ChainOK {
				res.Problems = append(res.Problems, fmt.Sprintf("清单第 %d 条记录（%s）的哈希链不连续，清单可能被修改", i+1, e.File))
			}
			res.ChainOK = false
		}
		prev = e.Hash
		latest[e.File] = e
	}
	cut := ""
	if s.opt.RetentionDays > 0 {
		cut = time.Now().In(s.opt.Location).AddDate(0, 0, -s.opt.RetentionDays).Format("20060102")
	}
	files := make([]string, 0, len(latest))
	for f := range latest {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		if ctx.Err() != nil {
			res.Problems = append(res.Problems, "校验超时，部分分段未校验")
			break
		}
		e := latest[f]
		if open[f] {
			res.Open++
			continue
		}
		res.Files++
		sum, size, err := fileSHA256(filepath.Join(s.opt.Dir, filepath.FromSlash(f)))
		switch {
		case errors.Is(err, os.ErrNotExist):
			if cut != "" && f[:8] < cut || s.removed(f) {
				res.Expired++
			} else {
				res.Problems = append(res.Problems, f+" 在留存期内但已缺失（可能被删除）")
			}
		case err != nil:
			res.Problems = append(res.Problems, f+" 读取失败: "+err.Error())
		case sum != e.SHA256 || size != e.Size:
			res.Problems = append(res.Problems, f+" 内容与登记的哈希不一致（可能被篡改）")
		default:
			res.OK++
		}
	}
	// 磁盘上存在但清单中没有的分段（正在写入的除外）
	days, _ := os.ReadDir(s.opt.Dir)
	for _, d := range days {
		if !d.IsDir() {
			continue
		}
		segs, _ := os.ReadDir(filepath.Join(s.opt.Dir, d.Name()))
		for _, sg := range segs {
			f := d.Name() + "/" + sg.Name()
			if strings.HasSuffix(f, ".log.gz") && !open[f] {
				if _, ok := latest[f]; !ok {
					res.Open++ // 进程异常退出时未登记的分段，下次关闭时登记
				}
			}
		}
	}
	return res
}

// removed 判断分段是否因容量上限被清理（清理时写入 .removed 标记）。
func (s *Store) removed(file string) bool {
	_, err := os.Stat(filepath.Join(s.opt.Dir, "removed", strings.ReplaceAll(file, "/", "_")))
	return err == nil
}

// ---------------- 清理 ----------------

// cleanup 按留存天数与容量上限删除最早的日期目录（当前正在写入的分段所在日期不删除）。
func (s *Store) cleanup() {
	days, err := os.ReadDir(s.opt.Dir)
	if err != nil {
		return
	}
	type day struct {
		name string
		size int64
	}
	var list []day
	var total int64
	for _, d := range days {
		if !d.IsDir() || len(d.Name()) != 8 {
			continue
		}
		var sz int64
		files, _ := os.ReadDir(filepath.Join(s.opt.Dir, d.Name()))
		for _, f := range files {
			if info, err := f.Info(); err == nil {
				sz += info.Size()
			}
		}
		list = append(list, day{d.Name(), sz})
		total += sz
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	cut := ""
	if s.opt.RetentionDays > 0 {
		cut = time.Now().In(s.opt.Location).AddDate(0, 0, -s.opt.RetentionDays).Format("20060102")
	}
	today := time.Now().In(s.opt.Location).Format("20060102")
	for _, d := range list {
		if d.name >= today {
			break
		}
		expired := cut != "" && d.name < cut
		over := s.opt.MaxBytes > 0 && total > s.opt.MaxBytes
		if !expired && !over {
			break
		}
		if !expired { // 因容量上限提前清理：留下标记，完整性校验时不报“缺失”
			os.MkdirAll(filepath.Join(s.opt.Dir, "removed"), 0o750)
			files, _ := os.ReadDir(filepath.Join(s.opt.Dir, d.name))
			for _, f := range files {
				os.WriteFile(filepath.Join(s.opt.Dir, "removed", d.name+"_"+f.Name()), nil, 0o640)
			}
		}
		if err := os.RemoveAll(filepath.Join(s.opt.Dir, d.name)); err != nil {
			s.setErr(err)
			continue
		}
		total -= d.size
		reason := "超过留存天数"
		if !expired {
			reason = "超过容量上限"
		}
		log.Printf("[rawlog] 已清理 %s 的原始日志（%s，%.1f MB）", d.name, reason, float64(d.size)/(1<<20))
	}
}

// ---------------- 状态 ----------------

// DayInfo 是一天的留存情况。
type DayInfo struct {
	Date  string `json:"date"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

// Status 是留存状态。
type Status struct {
	Enabled       bool      `json:"enabled"`
	Dir           string    `json:"dir"`
	RetentionDays int       `json:"retention_days"`
	MaxBytes      int64     `json:"max_bytes"`
	AttacksOnly   bool      `json:"attacks_only"`
	Written       int64     `json:"written"`
	Dropped       int64     `json:"dropped"`
	Expired       int64     `json:"expired"`  // 时间早于留存期限、未写入
	BytesIn       int64     `json:"bytes_in"` // 写入的原始字节（压缩前）
	DiskBytes     int64     `json:"disk_bytes"`
	Oldest        string    `json:"oldest,omitempty"`
	Newest        string    `json:"newest,omitempty"`
	Days          []DayInfo `json:"days"`
	LastError     string    `json:"last_error,omitempty"`
}

// Status 返回留存状态。
func (s *Store) Status() Status {
	if s == nil {
		return Status{Days: []DayInfo{}}
	}
	st := Status{Enabled: true, Dir: s.opt.Dir, RetentionDays: s.opt.RetentionDays, MaxBytes: s.opt.MaxBytes, AttacksOnly: s.opt.AttacksOnly,
		Written: s.written.Load(), Dropped: s.dropped.Load(), Expired: s.expired.Load(), BytesIn: s.bytesIn.Load(), Days: []DayInfo{}}
	if e := s.lastErr.Load(); e != nil {
		st.LastError = *e
	}
	days, _ := os.ReadDir(s.opt.Dir)
	for _, d := range days {
		if !d.IsDir() || len(d.Name()) != 8 {
			continue
		}
		di := DayInfo{Date: d.Name()}
		files, _ := os.ReadDir(filepath.Join(s.opt.Dir, d.Name()))
		for _, f := range files {
			if info, err := f.Info(); err == nil {
				di.Bytes += info.Size()
				if strings.HasSuffix(f.Name(), ".log.gz") {
					di.Files++
				}
			}
		}
		st.DiskBytes += di.Bytes
		st.Days = append(st.Days, di)
	}
	sort.Slice(st.Days, func(i, j int) bool { return st.Days[i].Date > st.Days[j].Date })
	if n := len(st.Days); n > 0 {
		st.Newest, st.Oldest = st.Days[0].Date, st.Days[n-1].Date
	}
	return st
}

// Counters 返回写入条数、丢弃条数与写入的原始字节数（只读内存计数）。
func (s *Store) Counters() (written, dropped, bytes int64) {
	if s == nil {
		return
	}
	return s.written.Load(), s.dropped.Load(), s.bytesIn.Load()
}
