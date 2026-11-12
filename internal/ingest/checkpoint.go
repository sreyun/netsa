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
// 断点停在已读完整行的末尾，并且只越过已经处理完的批次（tracker.go：每批送出时记下读取位置，从头连续处理完的
// 最后一批之后才生效）；退出时处理流水线先处理完队列中已有的日志（有时限），没处理完的部分下次启动重新读取。
// 进程被强制结束时，最后几秒读到的日志可能重复处理（告警归档按内容去重），不会漏掉。
//
// 温备机同步来的断点标记为 Foreign（MarkForeign）：主备共用存储时文件相同，接管后从主机读到的位置继续；
// 本机文件与主机上的不是同一个时按没有断点处理（从末尾开始），而不是当作停机期间轮转的新文件从头读取。

const (
	prefixLen  = 256                 // 用来识别同一个文件的开头字节数
	maxCatchup = 1 << 30             // 重启后最多补读的字节数
	keepIdle   = 30 * 24 * time.Hour // 超过这么久没有更新的断点在保存时丢弃

	// CheckpointFile 是读取断点文件在状态目录中的文件名。
	CheckpointFile = "ingest-offsets.json"
)

// checkpoint 是一个文件的读取断点。
type checkpoint struct {
	Offset    int64     `json:"offset"`
	PrefixLen int       `json:"prefix_len"`
	Prefix    string    `json:"prefix"` // 文件开头 PrefixLen 字节的 SHA-256
	Updated   time.Time `json:"updated"`
	// Foreign 表示断点由温备机从主机同步而来：只有文件开头与之相符（同一个文件）时才使用
	Foreign bool `json:"foreign,omitempty"`
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
	// 位置没有变化时不重写文件；但每天刷新一次更新时间：长期没有新日志、仍在跟踪的文件不会因 30 天未更新被丢弃断点
	if old, ok := c.m[path]; ok && old.Offset == cp.Offset && old.Prefix == cp.Prefix && !old.Foreign && time.Since(old.Updated) < 24*time.Hour {
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
		if time.Since(cp.Updated) > keepIdle {
			delete(c.m, p)
		}
	}
	data, err := json.MarshalIndent(c.m, "", "  ")
	c.dirty = false
	c.mu.Unlock()
	if err == nil {
		err = writeAtomic(c.path, data)
	}
	if err != nil {
		c.mu.Lock()
		c.dirty = true // 下次保存时重试，而不是等到断点再次变化
		c.mu.Unlock()
	}
	return err
}

// writeAtomic 先写临时文件并落盘再改名：掉电后不会留下空的或写了一半的断点文件。
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// MarkForeign 把断点文件中的断点都标记为从主机同步而来（温备机每次同步后调用）。文件不存在时什么也不做，
// 文件损坏时删除（接管时按没有断点处理）。
func MarkForeign(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	m := map[string]checkpoint{}
	if err := json.Unmarshal(data, &m); err != nil {
		return os.Remove(path)
	}
	for p, cp := range m {
		cp.Foreign = true
		m[p] = cp
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, out)
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

// resumeAt 根据断点决定刚打开的文件从哪里开始读：返回起始位置与说明；ok 为 false 表示断点不可用，按原来的规则处理
// （说明不为空时记录日志）。
func resumeAt(f *os.File, size int64, cp checkpoint) (pos int64, why string, ok bool) {
	if cp.PrefixLen <= 0 || cp.Offset < 0 {
		return 0, "", false
	}
	if prefix, got := filePrefix(f, cp.PrefixLen); got == cp.PrefixLen && prefix == cp.Prefix && size >= cp.Offset {
		if size-cp.Offset > maxCatchup {
			return size - maxCatchup, "停机期间写入的日志超过 1GB，只补读最新的 1GB", true
		}
		if cp.Foreign {
			return cp.Offset, "从主机同步的断点继续（主备读取的是同一个文件）", true
		}
		return cp.Offset, "从上次读到的位置继续", true
	}
	if cp.Foreign {
		// 断点来自主机：本机的文件与主机上的不是同一个，不能推断它的内容都是停机之后写入的
		return 0, "断点从主机同步而来，本机文件与主机上的不是同一个，按没有断点处理", false
	}
	// 停机期间文件被轮转或截断：新文件的内容都是停机之后写入的
	if size > maxCatchup {
		return size - maxCatchup, "文件已在停机期间轮转，新文件超过 1GB，只读最新的 1GB", true
	}
	return 0, "文件已在停机期间轮转，从头读取", true
}
