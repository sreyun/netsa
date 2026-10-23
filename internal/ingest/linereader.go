package ingest

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// MaxLineBytes 是单行日志的最大长度，超出部分被截断，防止异常日志耗尽内存或中断读取。
const MaxLineBytes = 1 << 20

// lineReader 逐行读取，支持跨读取周期的半行拼接与超长行截断。
type lineReader struct {
	r       *bufio.Reader
	pending []byte
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 64*1024)}
}

// next 返回下一行完整日志及本次消耗的字节数；ok 为 false 表示已读到当前末尾，
// 未以换行结束的内容会保留下来，等待后续写入补全。
func (lr *lineReader) next() (line string, n int, ok bool, err error) {
	for {
		chunk, err := lr.r.ReadSlice('\n')
		n += len(chunk)
		if room := MaxLineBytes - len(lr.pending); room > 0 {
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			lr.pending = append(lr.pending, chunk...)
		}
		switch {
		case err == nil:
			line = strings.TrimRight(string(lr.pending), "\r\n")
			lr.clear()
			return line, n, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", n, false, err
		}
	}
}

// flush 取出末尾未以换行结束的最后一行（用于批量读取到文件结尾时）。
func (lr *lineReader) flush() (string, bool) {
	if len(lr.pending) == 0 {
		return "", false
	}
	line := strings.TrimRight(string(lr.pending), "\r\n")
	lr.clear()
	return line, line != ""
}

// reset 切换到新的数据源并丢弃残留的半行。
func (lr *lineReader) reset(r io.Reader) {
	lr.r.Reset(r)
	lr.clear()
}

func (lr *lineReader) clear() {
	if cap(lr.pending) > 64*1024 {
		lr.pending = nil // 释放偶发超长行占用的大缓冲区
		return
	}
	lr.pending = lr.pending[:0]
}
