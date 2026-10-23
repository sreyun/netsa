// Package ingest 负责采集日志：实时跟踪文件（支持通配符、轮转、截断）、批量读取（支持 .gz）与 syslog 接收。
// 解析后的事件按批投递（每批最多 BatchSize 条），降低高吞吐下的通道与调度开销。
package ingest

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/parser"
)

// BatchSize 是单批投递的最大事件数。
const BatchSize = 256

// Stat 是数据源运行状态。
type Stat struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Type      string    `json:"type"`
	Detected  string    `json:"detected"`
	Status    string    `json:"status"`
	Lines     int64     `json:"lines"`
	Parsed    int64     `json:"parsed"`
	Failed    int64     `json:"failed"`
	Skipped   int64     `json:"skipped"`
	LastEvent time.Time `json:"last_event"`
	LastError string    `json:"last_error,omitempty"`
	Sample    string    `json:"sample_failed,omitempty"` // 最近一条无法解析的日志，便于排查格式
}

type source struct {
	name, path, typ, host string
	parser                *parser.Auto

	lines, parsed, failed, skipped atomic.Int64
	lastEvent                      atomic.Int64 // UnixNano

	mu        sync.Mutex // 保护以下低频字段
	status    string
	lastError string
	sample    string

	batch    []*model.Event // 仅由该数据源的读取协程（或 syslog 汇聚协程）访问
	detectFn func() string  // 非空时用于展示识别出的格式（syslog 汇总多个发送端）
}

func (s *source) setStatus(status, errMsg string) {
	s.mu.Lock()
	s.status, s.lastError = status, errMsg
	s.mu.Unlock()
}

func (s *source) stat() Stat {
	s.mu.Lock()
	st := Stat{Name: s.name, Path: s.path, Type: s.typ, Status: s.status, LastError: s.lastError, Sample: s.sample}
	s.mu.Unlock()
	st.Lines, st.Parsed, st.Failed, st.Skipped = s.lines.Load(), s.parsed.Load(), s.failed.Load(), s.skipped.Load()
	if ns := s.lastEvent.Load(); ns != 0 {
		st.LastEvent = time.Unix(0, ns)
	}
	if s.detectFn != nil {
		st.Detected = s.detectFn()
	} else {
		st.Detected = s.parser.Detected()
	}
	return st
}

// Manager 管理所有数据源，并把解析后的事件批量写入 Out。
type Manager struct {
	Out     chan []*model.Event
	mu      sync.Mutex
	sources []*source
	wg      sync.WaitGroup
}

// NewManager 创建管理器，buffer 为输出通道可缓存的批数。
func NewManager(buffer int) *Manager {
	return &Manager{Out: make(chan []*model.Event, buffer)}
}

func (m *Manager) add(name, path, typ, logFormat, host string) (*source, error) {
	p, err := parser.NewAuto(typ, logFormat)
	if err != nil {
		return nil, err
	}
	s := &source{name: name, path: path, typ: typ, host: host, parser: p, status: "starting"}
	m.mu.Lock()
	m.sources = append(m.sources, s)
	m.mu.Unlock()
	return s, nil
}

// Stats 返回所有数据源状态。
func (m *Manager) Stats() []Stat {
	m.mu.Lock()
	srcs := append([]*source(nil), m.sources...)
	m.mu.Unlock()
	out := make([]Stat, 0, len(srcs))
	for _, s := range srcs {
		out = append(out, s.stat())
	}
	return out
}

// Wait 等待所有批量读取任务结束。
func (m *Manager) Wait() { m.wg.Wait() }

// Close 在全部批量读取结束后关闭输出通道，通知下游处理完毕（仅用于离线分析）。
func (m *Manager) Close() { close(m.Out) }

// parseLine 解析一行，成功时返回事件（不投递）。
func (s *source) parseLine(line string) *model.Event { return s.parseLineWith(s.parser, line) }

// parseLineWith 使用指定解析器解析（syslog 按发送端分别识别格式）。
func (s *source) parseLineWith(p *parser.Auto, line string) *model.Event {
	s.lines.Add(1)
	if strings.HasPrefix(line, "#Fields:") {
		p.Directive(line) // W3C（IIS）字段声明
	}
	if parser.Skippable(line) {
		s.skipped.Add(1)
		return nil
	}
	ev, ok := p.Parse(line)
	if !ok {
		s.failed.Add(1)
		if len(line) > 300 {
			line = line[:300]
		}
		s.mu.Lock()
		s.sample = line
		s.mu.Unlock()
		return nil
	}
	s.parsed.Add(1)
	ev.Source = s.name
	if ev.Host == "" && ev.Kind == model.KindWeb && s.host != "" {
		ev.Host = s.host
	}
	if ns := ev.Time.UnixNano(); ns > s.lastEvent.Load() {
		s.lastEvent.Store(ns)
	}
	return ev
}

// handle 解析一行并放入当前批次，批次满时投递。
func (m *Manager) handle(ctx context.Context, s *source, line string) {
	if ev := s.parseLine(line); ev != nil {
		s.batch = append(s.batch, ev)
		if len(s.batch) >= BatchSize {
			m.flush(ctx, s)
		}
	}
}

// flush 投递当前批次。
func (m *Manager) flush(ctx context.Context, s *source) {
	if len(s.batch) == 0 {
		return
	}
	select {
	case m.Out <- s.batch:
	case <-ctx.Done():
	}
	s.batch = make([]*model.Event, 0, BatchSize)
}

// ReadFile 一次性读取整个文件（支持 .gz），用于离线分析。
func (m *Manager) ReadFile(ctx context.Context, path, typ, logFormat, host string) error {
	s, err := m.add(filepath.Base(path), path, typ, logFormat, host)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		s.setStatus("error", err.Error())
		return err
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer f.Close()
		s.setStatus("reading", "")
		var r io.Reader = f
		if strings.HasSuffix(path, ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				s.setStatus("error", err.Error())
				return
			}
			defer gz.Close()
			r = gz
		}
		lr := newLineReader(r)
		status, msg := "done", ""
		for ctx.Err() == nil {
			line, _, ok, err := lr.next()
			if ok {
				m.handle(ctx, s, line)
				continue
			}
			if last, has := lr.flush(); has {
				m.handle(ctx, s, last)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				status, msg = "error", err.Error()
			}
			break
		}
		m.flush(ctx, s)
		s.setStatus(status, msg)
	}()
	return nil
}

// StartSource 启动一个配置的文件数据源：展开通配符并持续跟踪，周期性发现新文件。
func (m *Manager) StartSource(ctx context.Context, sc config.SourceConfig) error {
	// 预先校验 log_format / 类型是否合法
	if _, err := parser.NewAuto(sc.Type, sc.LogFormat); err != nil {
		return err
	}
	started := map[string]bool{}
	scan := func(first bool) {
		for _, pattern := range sc.Paths {
			matches, _ := filepath.Glob(pattern)
			if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
				matches = []string{pattern} // 文件尚不存在，等待创建
			}
			sort.Strings(matches)
			for _, path := range matches {
				if started[path] || strings.HasSuffix(path, ".gz") {
					continue
				}
				started[path] = true
				name := sc.Name
				if len(matches) > 1 || strings.ContainsAny(pattern, "*?[") {
					name = sc.Name + ":" + filepath.Base(path)
				}
				s, err := m.add(name, path, sc.Type, sc.LogFormat, sc.Host)
				if err != nil {
					log.Printf("[ingest] %s: %v", path, err)
					continue
				}
				// 首轮发现的文件按配置决定是否从头读取；之后新出现的文件总是从头读取
				go m.tail(ctx, s, path, sc.FromBeginning || !first)
			}
		}
	}
	scan(true)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				scan(false)
			}
		}
	}()
	return nil
}

// tail 以轮询方式跟踪文件（跨平台），处理 logrotate 的重命名与 copytruncate 两种轮转方式。
// 持续有数据时连续读取并按批投递；读到末尾时先投递未满的批次再等待，保证实时性。
func (m *Manager) tail(ctx context.Context, s *source, path string, fromStart bool) {
	var (
		f      *os.File
		fi     os.FileInfo
		lr     *lineReader
		offset int64
		first  = true
	)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	sleep := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	idle := 250 * time.Millisecond
	for {
		if f == nil {
			var err error
			f, err = os.Open(path)
			if err != nil {
				s.setStatus("waiting", err.Error())
				// 启动时文件尚不存在：之后创建的文件内容全部是新数据，需要从头读取
				fromStart = true
				if !sleep(2 * time.Second) {
					return
				}
				continue
			}
			fi, _ = f.Stat()
			offset = 0
			if first && !fromStart {
				offset, _ = f.Seek(0, io.SeekEnd)
			}
			first = false
			lr = newLineReader(f)
			s.setStatus("tailing", "")
		}
		line, n, ok, err := lr.next()
		offset += int64(n)
		if ok {
			m.handle(ctx, s, line)
			idle = 250 * time.Millisecond
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			s.setStatus("tailing", err.Error())
		}
		m.flush(ctx, s)
		// 空闲时逐步拉长轮询间隔（最长 1 秒），有新数据时立即恢复
		if !sleep(idle) {
			return
		}
		if idle < time.Second {
			idle += 250 * time.Millisecond
		}
		nfi, err := os.Stat(path)
		switch {
		case err != nil:
			// 文件被移走，等待新文件出现
		case !os.SameFile(fi, nfi):
			// 文件被轮转（重命名后新建）：先读完旧文件在轮转前写入的剩余内容，再切换到新文件从头读取
			for {
				line, _, ok, _ := lr.next()
				if !ok {
					break
				}
				m.handle(ctx, s, line)
			}
			m.flush(ctx, s)
			f.Close()
			f = nil
		case nfi.Size() < offset:
			// copytruncate：文件被截断，从头读取
			f.Seek(0, io.SeekStart)
			lr.reset(f)
			offset = 0
		}
	}
}
