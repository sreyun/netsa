package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 文件读取位置的断点：升级、重启期间写入文件的日志，在重新启动后从上次读到的位置继续读取，而不是从文件末尾开始
// （此前重启期间写入的日志全部漏掉，升级一次就丢几十秒到几分钟的日志）。
//
// 断点按路径记录读到的位置与文件开头的摘要。重启时文件开头不变、且长度不小于断点位置，说明还是同一个文件，
// 从断点继续；文件在停机期间被轮转（开头变了，或变短了），新文件的内容都是停机之后写的，从头读取。
// 需要补读的内容超过 maxCatchup 时只读最新的部分并记录日志：长时间停机后一次补读几十 GB 会拖住启动后的实时检测。
//
// 断点在日志送入处理队列之后才前移；进程被强制结束时，最后几秒读到的日志可能重复处理（告警归档按内容去重），
// 不会漏掉。

const (
	prefixLen  = 256     // 用来识别同一个文件的开头字节数
	maxCatchup = 1 << 30 // 重启后最多补读的字节数
)

// checkpoint 是一个文件的读取断点。
type checkpoint struct {
	Offset    int64     `json:"offset"`
	PrefixLen int       `json:"prefix_len"`
	Prefix    string    `json:"prefix"` // 文件开头 PrefixLen 字节的 SHA-256
	Updated   time.Time `json:"updated"`
}

// Checkpoints 保存各文件的读取断点（并发安全）。
type Checkpoints struct {
	mu    sync.Mutex
	path  string
	m     map[string]checkpoint
	dirty bool
}

// LoadCheckpoints 读取断点文件；文件不存在时返回空的断点表。path 为空时不保存（离线分析）。
func LoadCheckpoints(path string) (*Checkpoints, error) {
	c := &Checkpoints{path: path, m: map[string]checkpoint{}}
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &c.m); err != nil {
		log.Printf("[ingest] 读取断点文件 %s 失败，按没有断点处理: %v", path, err)
		c.m = map[string]checkpoint{}
	}
	return c, nil
}

func (c *Checkpoints) get(path string) (checkpoint, bool) {
	if c == nil {
		return checkpoint{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.m[path]
	return cp, ok
}

func (c *Checkpoints) set(path string, cp checkpoint) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.m[path]; ok && old.Offset == cp.Offset && old.Prefix == cp.Prefix {
		return
	}
	cp.Updated = time.Now()
	c.m[path] = cp
	c.dirty = true
}

// Save 在断点有变化时写入文件（先写临时文件再改名）。
func (c *Checkpoints) Save() error {
	if c == nil || c.path == "" {
		return nil
	}
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return nil
	}
	// 只保留最近 30 天更新过的断点：按日期命名、已经删除的日志不必一直记着
	for p, cp := range c.m {
		if time.Since(cp.Updated) > 30*24*time.Hour {
			delete(c.m, p)
		}
	}
	data, err := json.MarshalIndent(c.m, "", "  ")
	c.dirty = false
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// filePrefix 返回文件开头 n 字节（不超过 prefixLen）的摘要与实际读到的长度。
func filePrefix(f *os.File, n int) (string, int) {
	if n <= 0 || n > prefixLen {
		n = prefixLen
	}
	buf := make([]byte, n)
	got, _ := f.ReadAt(buf, 0)
	sum := sha256.Sum256(buf[:got])
	return hex.EncodeToString(sum[:]), got
}

// resumeAt 根据断点决定刚打开的文件从哪里开始读：返回起始位置与说明（为空表示没有可用的断点，按原来的规则处理）。
func resumeAt(f *os.File, size int64, cp checkpoint) (int64, string) {
	if cp.PrefixLen <= 0 {
		return 0, ""
	}
	if prefix, got := filePrefix(f, cp.PrefixLen); got == cp.PrefixLen && prefix == cp.Prefix && size >= cp.Offset {
		if size-cp.Offset > maxCatchup {
			return size - maxCatchup, "停机期间写入的日志超过 1GB，只补读最新的 1GB"
		}
		return cp.Offset, "从上次读到的位置继续"
	}
	// 停机期间文件被轮转或截断：新文件的内容都是停机之后写入的
	if size > maxCatchup {
		return size - maxCatchup, "文件已在停机期间轮转，新文件超过 1GB，只读最新的 1GB"
	}
	return 0, "文件已在停机期间轮转，从头读取"
}
