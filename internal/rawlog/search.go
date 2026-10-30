package rawlog

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/parser"
)

// Query 是检索条件。
type Query struct {
	From, To    time.Time // 事件时间范围（必填）
	IP          string    // 来源或目的 IP（精确匹配）
	Keyword     string    // 原始日志包含的文本（不区分大小写）
	Source      string    // 数据源名称包含的文本
	AttacksOnly bool
	Limit       int   // 最多返回的条数（默认 200，最多 5000）
	MaxBytes    int64 // 最多扫描的解压后字节数（默认 4GB）
}

// Record 是一条原始日志。
type Record struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Source string    `json:"source"`
	SrcIP  string    `json:"src_ip,omitempty"`
	DstIP  string    `json:"dst_ip,omitempty"`
	Attack bool      `json:"attack,omitempty"`
	Raw    string    `json:"raw"`
}

// Result 是检索结果（按时间倒序）。
type Result struct {
	Records   []Record `json:"records"`
	Segments  int      `json:"segments"` // 时间范围内的分段数
	Scanned   int      `json:"scanned"`  // 实际扫描的分段数（按 IP 检索时布隆过滤器跳过了其余分段）
	Bytes     int64    `json:"bytes"`    // 扫描的解压后字节数
	Truncated bool     `json:"truncated"`
	Reason    string   `json:"reason,omitempty"` // 结果不完整的原因
	Took      string   `json:"took"`
}

// 检索错误。
var (
	ErrRange = errors.New("请指定检索的时间范围（最长 31 天）")
)

const maxRange = 31 * 24 * time.Hour

func parseLine(line []byte) (Record, bool) {
	var parts [7][]byte
	for i := 0; i < 6; i++ {
		j := bytes.IndexByte(line, '\t')
		if j < 0 {
			return Record{}, false
		}
		parts[i], line = line[:j], line[j+1:]
	}
	parts[6] = line
	ms, err := strconv.ParseInt(string(parts[0]), 10, 64)
	if err != nil {
		return Record{}, false
	}
	return Record{Time: time.UnixMilli(ms), Kind: string(parts[1]), Source: string(parts[2]), SrcIP: string(parts[3]), DstIP: string(parts[4]),
		Attack: bytes.IndexByte(parts[5], 'A') >= 0, Raw: string(parts[6])}, true
}

// segmentsIn 返回时间范围内存在的分段（键为 YYYYMMDD/HH），按时间倒序。
func (s *Store) segmentsIn(from, to time.Time) []string {
	var out []string
	loc := s.opt.Location
	start := from.In(loc).Truncate(time.Hour)
	// Truncate 按 UTC 对齐；时区偏移不是整小时（如 +5:30）时从前一小时开始，避免漏掉
	start = time.Date(start.Year(), start.Month(), start.Day(), start.Hour(), 0, 0, 0, loc).Add(-time.Hour)
	for t := to.In(loc); !t.Before(start); t = t.Add(-time.Hour) {
		k := t.Format("20060102/15")
		if len(out) > 0 && out[len(out)-1] == k {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.opt.Dir, filepath.FromSlash(k)+".log.gz")); err == nil {
			out = append(out, k)
		}
	}
	return out
}

// Search 检索原始日志。超过扫描量或 ctx 结束时返回已找到的结果并标记为不完整。
func (s *Store) Search(ctx context.Context, q Query) (Result, error) {
	began := time.Now()
	res := Result{Records: []Record{}}
	if q.From.IsZero() || q.To.IsZero() || q.To.Before(q.From) || q.To.Sub(q.From) > maxRange {
		return res, ErrRange
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}
	q.Limit = min(q.Limit, 5000)
	if q.MaxBytes <= 0 {
		q.MaxBytes = 4 << 30
	}
	kw := []byte(strings.ToLower(strings.TrimSpace(q.Keyword)))
	src := strings.ToLower(strings.TrimSpace(q.Source))
	// 与入库时一致地规范化地址（IPv4 映射地址、大小写、方括号），否则布隆过滤器与精确匹配都会漏掉
	ip, _ := parser.NormIP(q.IP)
	ipB := []byte(ip)
	segs := s.segmentsIn(q.From, q.To)
	res.Segments = len(segs)
	fromMs, toMs := q.From.UnixMilli(), q.To.UnixMilli()
	lower := make([]byte, 0, 4096)
	for _, k := range segs {
		if ctx.Err() != nil {
			res.Truncated, res.Reason = true, "检索超时，结果不完整，请缩小时间范围或增加过滤条件"
			break
		}
		if res.Bytes >= q.MaxBytes {
			res.Truncated, res.Reason = true, "扫描量达到上限，结果不完整，请缩小时间范围或增加过滤条件"
			break
		}
		path := filepath.Join(s.opt.Dir, filepath.FromSlash(k)+".log.gz")
		if ip != "" {
			if b, err := os.ReadFile(bloomPath(path)); err == nil && !bloom(b).has(ip) {
				continue
			}
		}
		res.Scanned++
		// 保留该分段中时间最新的 Limit 条
		var found []Record
		budget := false // 扫描量在本分段中途达到上限
		err := scanSegment(ctx, path, func(line []byte) bool {
			res.Bytes += int64(len(line)) + 1
			if res.Bytes >= q.MaxBytes {
				budget = true
				return false
			}
			if ip != "" && !bytes.Contains(line, ipB) || len(kw) > 0 && !containsFold(line, kw, &lower) {
				return true
			}
			r, ok := parseLine(line)
			if !ok {
				return true
			}
			if ms := r.Time.UnixMilli(); ms < fromMs || ms > toMs || q.AttacksOnly && !r.Attack ||
				ip != "" && r.SrcIP != ip && r.DstIP != ip || src != "" && !strings.Contains(strings.ToLower(r.Source), src) {
				return true
			}
			found = append(found, r)
			if len(found) >= 2*q.Limit { // 只保留按时间最新的 Limit 条（写入顺序不一定是时间顺序）
				sort.SliceStable(found, func(i, j int) bool { return found[i].Time.After(found[j].Time) })
				found = found[:q.Limit]
			}
			return true
		})
		// 本分段没有扫描完（超时或达到扫描量上限）：结果必须标记为不完整。
		// 此前只在下一个分段开始前检查，最后一个分段被截断时结果会被误报为完整
		cut := ""
		switch {
		case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
			cut = "检索超时，结果不完整，请缩小时间范围或增加过滤条件"
		case budget:
			cut = "扫描量达到上限，结果不完整，请缩小时间范围或增加过滤条件"
		case err != nil:
			res.Reason = "部分分段读取失败: " + err.Error()
		}
		sort.SliceStable(found, func(i, j int) bool { return found[i].Time.After(found[j].Time) })
		res.Records = append(res.Records, found...)
		if len(res.Records) >= q.Limit {
			// 分段按时间倒序扫描；继续扫描更早的分段不会得到更新的日志
			res.Records = res.Records[:q.Limit]
			res.Truncated = true
			if res.Reason == "" {
				res.Reason = "结果较多，仅显示最新的 " + strconv.Itoa(q.Limit) + " 条"
			}
			break
		}
		if cut != "" {
			res.Truncated = true
			if res.Reason == "" {
				res.Reason = cut
			}
			break
		}
	}
	res.Took = time.Since(began).Round(time.Millisecond).String()
	return res, nil
}

// containsFold 判断 line 是否包含小写的 kw（ASCII 不区分大小写；中文等按原样匹配）。
func containsFold(line, kw []byte, buf *[]byte) bool {
	if bytes.Contains(line, kw) {
		return true
	}
	b := (*buf)[:0]
	for _, c := range line {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	*buf = b
	return bytes.Contains(b, kw)
}

// scanSegment 逐行读取分段（多个 gzip 成员连续读取；正在写入的分段末尾不完整时读到已刷新的位置为止）。
func scanSegment(ctx context.Context, path string, fn func([]byte) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 256<<10))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	defer gz.Close()
	br := bufio.NewReaderSize(gz, 256<<10)
	n := 0
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			if !fn(line[:len(line)-1]) {
				return nil
			}
		} else if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) { // 超长行：跳过
				_, err = br.ReadSlice('\n')
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if n++; n%4096 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// Export 把检索结果按行写出（取证导出）：“时间 \t 数据源 \t 来源IP \t 原始日志”。
func Export(w io.Writer, recs []Record, loc *time.Location) error {
	bw := bufio.NewWriter(w)
	for i := len(recs) - 1; i >= 0; i-- { // 导出按时间先后
		r := recs[i]
		bw.WriteString(r.Time.In(loc).Format("2006-01-02 15:04:05.000"))
		bw.WriteByte('\t')
		bw.WriteString(r.Source)
		bw.WriteByte('\t')
		bw.WriteString(r.SrcIP)
		bw.WriteByte('\t')
		bw.WriteString(r.Raw)
		bw.WriteByte('\n')
	}
	return bw.Flush()
}
