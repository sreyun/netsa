// Package audit 是防篡改的操作审计链：登录、账号与配置变更、数据导出、事件处置等操作按时间追加写入按月分割的
// JSONL 文件（<dir>/audit-YYYYMM.jsonl），每条记录的哈希包含上一条记录的哈希，任何修改、删除、插入都会使校验失败。
// 按留存天数清理旧文件时，把被删除文件最后一条记录的哈希写入锚点文件，校验从锚点继续，留存清理不会被误判为篡改。
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netsa/internal/auth"
)

// Entry 是一条审计记录。
type Entry struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Action string    `json:"action,omitempty"` // 为空表示登录
	Detail string    `json:"detail,omitempty"`
	OK     bool      `json:"ok"`
	Reason string    `json:"reason,omitempty"`
	Agent  string    `json:"agent,omitempty"`
	Prev   string    `json:"prev"`
	Hash   string    `json:"hash"`
}

func (e *Entry) compute() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%q|%q|%q|%q|%t|%q|%q", e.Prev, e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.User, e.IP, e.Action, e.Detail, e.OK, e.Reason, e.Agent)
	return hex.EncodeToString(h.Sum(nil))
}

const recentCap = 2000

// Trail 是审计链。
type Trail struct {
	mu        sync.Mutex
	dir       string
	retention int // 留存天数，0 表示永久
	seq       uint64
	last      string
	recent    []Entry // 最近的记录（内存缓存，新的在后）
	now       func() time.Time
	lastClean time.Time
}

// Open 打开审计目录并恢复链尾（最后一条记录的序号与哈希）。retentionDays 为 0 表示永久保留。
func Open(dir string, retentionDays int) (*Trail, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("创建审计目录失败: %w", err)
	}
	t := &Trail{dir: dir, retention: retentionDays, now: time.Now}
	files := t.files()
	for i := len(files) - 1; i >= 0 && t.last == ""; i-- {
		entries, _ := readFile(files[i])
		if n := len(entries); n > 0 {
			t.seq, t.last = entries[n-1].Seq, entries[n-1].Hash
		}
	}
	if t.last == "" {
		t.last = t.anchor()
	}
	// 恢复最近的记录到内存
	for i := len(files) - 1; i >= 0 && len(t.recent) < recentCap; i-- {
		entries, _ := readFile(files[i])
		t.recent = append(entries, t.recent...)
	}
	if len(t.recent) > recentCap {
		t.recent = t.recent[len(t.recent)-recentCap:]
	}
	return t, nil
}

func (t *Trail) files() []string {
	list, _ := filepath.Glob(filepath.Join(t.dir, "audit-*.jsonl"))
	sort.Strings(list)
	return list
}

func (t *Trail) anchorPath() string { return filepath.Join(t.dir, "anchor.json") }

func (t *Trail) anchor() string {
	var a struct {
		Hash string `json:"hash"`
	}
	if b, err := os.ReadFile(t.anchorPath()); err == nil {
		json.Unmarshal(b, &a)
	}
	return a.Hash
}

func readFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e Entry
		if len(sc.Bytes()) > 0 && json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n]
}

// AppendAudit 追加一条记录（实现 auth.AuditSink）。写盘失败只记录日志，不影响业务操作。
func (t *Trail) AppendAudit(r auth.Record) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if r.Time.IsZero() {
		r.Time = t.now()
	}
	e := Entry{Seq: t.seq + 1, Time: r.Time, User: clip(r.User, 64), IP: clip(r.IP, 64), Action: clip(r.Action, 64), Detail: clip(r.Detail, 500),
		OK: r.OK, Reason: clip(r.Reason, 300), Agent: clip(r.Agent, 200), Prev: t.last}
	e.Hash = e.compute()
	b, _ := json.Marshal(e)
	path := filepath.Join(t.dir, "audit-"+e.Time.Format("200601")+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err == nil {
		_, err = f.Write(append(b, '\n'))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		log.Printf("[audit] 写入审计记录失败: %v", err)
		return
	}
	t.seq, t.last = e.Seq, e.Hash
	t.recent = append(t.recent, e)
	if len(t.recent) > recentCap {
		t.recent = append([]Entry(nil), t.recent[len(t.recent)-recentCap:]...)
	}
	if t.retention > 0 && t.now().Sub(t.lastClean) > 6*time.Hour {
		t.lastClean = t.now()
		t.cleanupLocked()
	}
}

// cleanupLocked 删除超过留存期的月份文件（整月都早于留存期才删除），并更新锚点。
func (t *Trail) cleanupLocked() {
	cut := t.now().AddDate(0, 0, -t.retention)
	for _, f := range t.files() {
		m, err := time.ParseInLocation("200601", strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "audit-"), ".jsonl"), time.Local)
		if err != nil || !m.AddDate(0, 1, 0).Before(cut) {
			continue
		}
		entries, _ := readFile(f)
		if n := len(entries); n > 0 {
			a, _ := json.Marshal(map[string]any{"hash": entries[n-1].Hash, "seq": entries[n-1].Seq, "file": filepath.Base(f), "removed": t.now()})
			if err := os.WriteFile(t.anchorPath(), a, 0o640); err != nil {
				log.Printf("[audit] 写入锚点失败: %v", err)
				return
			}
		}
		if err := os.Remove(f); err == nil {
			log.Printf("[audit] 已按留存策略清理 %s", filepath.Base(f))
		}
	}
}

// Query 是审计检索条件。
type Query struct {
	From, To time.Time
	User     string
	Action   string // login 表示只看登录；其余为操作名包含的文本
	Search   string
	Failed   bool // 只看失败
	Limit    int
}

func (q *Query) match(e *Entry) bool {
	if !q.From.IsZero() && e.Time.Before(q.From) || !q.To.IsZero() && e.Time.After(q.To) || q.User != "" && e.User != q.User || q.Failed && e.OK {
		return false
	}
	switch {
	case q.Action == "login":
		if e.Action != "" {
			return false
		}
	case q.Action != "" && !strings.Contains(e.Action, q.Action):
		return false
	}
	if s := strings.ToLower(q.Search); s != "" && !strings.Contains(strings.ToLower(e.User+" "+e.IP+" "+e.Action+" "+e.Detail+" "+e.Reason), s) {
		return false
	}
	return true
}

// Search 检索审计记录（新的在前）。先查内存中的最近记录，不够时再按月份从新到旧读取文件。
func (t *Trail) Search(q Query) []Entry {
	if q.Limit <= 0 {
		q.Limit = 200
	}
	out := []Entry{}
	t.mu.Lock()
	recent := t.recent
	oldest := uint64(0)
	if len(recent) > 0 {
		oldest = recent[0].Seq
	}
	for i := len(recent) - 1; i >= 0 && len(out) < q.Limit; i-- {
		if q.match(&recent[i]) {
			out = append(out, recent[i])
		}
	}
	files := t.files()
	t.mu.Unlock()
	if len(out) >= q.Limit || oldest <= 1 {
		return out
	}
	for i := len(files) - 1; i >= 0 && len(out) < q.Limit; i-- {
		entries, _ := readFile(files[i])
		for j := len(entries) - 1; j >= 0 && len(out) < q.Limit; j-- {
			if e := &entries[j]; e.Seq < oldest && q.match(e) {
				out = append(out, *e)
			}
		}
	}
	return out
}

// VerifyResult 是审计链校验结果。
type VerifyResult struct {
	Entries   int       `json:"entries"`
	Files     int       `json:"files"`
	OK        bool      `json:"ok"`
	FirstSeq  uint64    `json:"first_seq"`
	LastSeq   uint64    `json:"last_seq"`
	Anchored  bool      `json:"anchored"` // 旧记录已按留存策略清理，从锚点开始校验
	Problems  []string  `json:"problems"`
	CheckedAt time.Time `json:"checked_at"`
}

// Verify 校验整条审计链：每条记录的哈希、与上一条的链接、序号连续。
func (t *Trail) Verify() VerifyResult {
	res := VerifyResult{OK: true, Problems: []string{}, CheckedAt: time.Now()}
	t.mu.Lock()
	files := t.files()
	anchor := t.anchor()
	t.mu.Unlock()
	prev, seq := anchor, uint64(0)
	res.Anchored = anchor != ""
	first := true
	for _, f := range files {
		entries, err := readFile(f)
		if err != nil {
			res.Problems = append(res.Problems, filepath.Base(f)+" 读取失败: "+err.Error())
			res.OK = false
			continue
		}
		res.Files++
		for _, e := range entries {
			res.Entries++
			if first {
				res.FirstSeq, first = e.Seq, false
				if !res.Anchored && e.Seq != 1 {
					res.Problems = append(res.Problems, fmt.Sprintf("链首记录序号为 %d（应为 1），早期记录可能被删除", e.Seq))
				}
			} else if e.Seq != seq+1 {
				res.Problems = append(res.Problems, fmt.Sprintf("%s：序号 %d 之后是 %d，中间的记录缺失", filepath.Base(f), seq, e.Seq))
			}
			if e.Prev != prev {
				res.Problems = append(res.Problems, fmt.Sprintf("%s：第 %d 条记录与上一条记录的哈希不衔接（记录被删除、插入或修改）", filepath.Base(f), e.Seq))
			}
			if e.compute() != e.Hash {
				res.Problems = append(res.Problems, fmt.Sprintf("%s：第 %d 条记录内容与哈希不一致（记录被修改）", filepath.Base(f), e.Seq))
			}
			prev, seq = e.Hash, e.Seq
			if len(res.Problems) >= 50 {
				break
			}
		}
	}
	res.LastSeq = seq
	res.OK = len(res.Problems) == 0
	return res
}

// Export 按条件导出审计记录（按时间先后）：format 为 csv 或 jsonl。
func (t *Trail) Export(w io.Writer, q Query, format string, loc *time.Location) error {
	q.Limit = max(q.Limit, 1)
	list := t.Search(q)
	if format == "jsonl" {
		enc := json.NewEncoder(w)
		for i := len(list) - 1; i >= 0; i-- {
			if err := enc.Encode(list[i]); err != nil {
				return err
			}
		}
		return nil
	}
	io.WriteString(w, "\ufeff")
	cw := csv.NewWriter(w)
	cw.Write([]string{"序号", "时间", "账号", "来源IP", "操作", "详情", "结果", "原因", "哈希"})
	for i := len(list) - 1; i >= 0; i-- {
		e := list[i]
		action := e.Action
		if action == "" {
			action = "登录"
		}
		result := "成功"
		if !e.OK {
			result = "失败"
		}
		cw.Write(csvSafe([]string{strconv.FormatUint(e.Seq, 10), e.Time.In(loc).Format("2006-01-02 15:04:05"), e.User, e.IP, action, e.Detail, result, e.Reason, e.Hash}))
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe 防止 CSV 公式注入（以 = + - @ 制表符开头的单元格加前缀 '）。
func csvSafe(row []string) []string {
	for i, v := range row {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			row[i] = "'" + v
		}
	}
	return row
}

// Stats 返回审计概况（合规报告使用）。
type Stats struct {
	Entries   uint64    `json:"entries"`
	Oldest    time.Time `json:"oldest,omitempty"`
	Retention int       `json:"retention_days"`
}

// Stats 返回记录总数、最早记录时间与留存策略。
func (t *Trail) Stats() Stats {
	if t == nil {
		return Stats{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st := Stats{Entries: t.seq, Retention: t.retention}
	if files := t.files(); len(files) > 0 {
		if entries, _ := readFile(files[0]); len(entries) > 0 {
			st.Oldest = entries[0].Time
		}
	}
	return st
}

// ErrDisabled 表示未启用审计链。
var ErrDisabled = errors.New("未启用审计链")
