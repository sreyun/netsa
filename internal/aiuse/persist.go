package aiuse

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// 状态文件：页面登记的服务与策略、按天的使用记录、服务首次出现时间、疑似 AI 域名与 AI 接口。
// 记录可能有几十万条，按紧凑字段名写成 JSON 后 gzip 压缩；有变化时最多每 5 分钟写一次（退出时立即写）。

const (
	fileVersion  = 1
	saveInterval = 5 * time.Minute
	maxFileBytes = 512 << 20 // 解压后的上限，防止损坏或伪造的文件耗尽内存
)

type savedCell struct {
	D day    `json:"d"`
	S string `json:"s"`
	I string `json:"i"`
	Q int64  `json:"q,omitempty"`
	C int64  `json:"c,omitempty"`
	X int64  `json:"x,omitempty"`
	U int64  `json:"u,omitempty"`
	W int64  `json:"w,omitempty"`
	F int64  `json:"f"`
	L int64  `json:"l"`
}

type savedCandidate struct {
	Candidate
	List []string `json:"list,omitempty"`
}

type savedEndpoint struct {
	Endpoint
	List []string `json:"list,omitempty"`
}

type savedFile struct {
	Version    int               `json:"version"`
	Services   []Service         `json:"services,omitempty"`
	Policies   map[string]string `json:"policies,omitempty"`
	Seen       map[string]*seen  `json:"seen,omitempty"`
	Cells      []savedCell       `json:"cells,omitempty"`
	Candidates []savedCandidate  `json:"candidates,omitempty"`
	Endpoints  []savedEndpoint   `json:"endpoints,omitempty"`
	BytesSeen  bool              `json:"bytes_seen,omitempty"`
	SNISeen    bool              `json:"sni_seen,omitempty"`
	Dropped    int64             `json:"dropped,omitempty"`
}

// Load 创建统计并恢复状态文件（不存在时为空）。
func Load(opt Options) (*Manager, error) {
	m, err := New(opt)
	if err != nil {
		return nil, err
	}
	path := m.path
	m.path = ""
	return m, m.SetPath(path)
}

// SetPath 设置状态文件并恢复上次保存的状态（文件不存在时忽略）。只在启动实时服务时调用一次：
// 离线分析不读取、也不写入历史状态。
func (m *Manager) SetPath(path string) error {
	if m == nil || path == "" {
		return nil
	}
	m.mu.Lock()
	m.path = path
	m.mu.Unlock()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	var sf savedFile
	if err := json.NewDecoder(io.LimitReader(zr, maxFileBytes)).Decode(&sf); err != nil {
		return fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	m.restore(&sf)
	return nil
}

// restore 恢复保存的状态：无效的服务、策略与记录跳过（配置可能已经变化）。
func (m *Manager) restore(sf *savedFile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range sf.Services {
		s.Source = SourceUI
		if len(m.uiSvcs) < maxServices && s.prepare() == nil {
			m.uiSvcs = append(m.uiSvcs, s)
		}
	}
	m.rebuildLocked()
	for id, p := range sf.Policies {
		if _, ok := m.services[id]; ok && validPolicy(p) == nil {
			m.uiPol[id] = p
		}
	}
	m.rebuildLocked()
	cut := m.dayOf(m.now()) - day(m.keepDays)
	for _, c := range sf.Cells {
		if _, ok := m.services[c.S]; !ok || c.D < cut || c.I == "" || len(m.cells) >= m.maxRecs {
			continue
		}
		m.cells[cellKey{d: c.D, svc: m.services[c.S].ID, ip: c.I}] = &cell{queries: c.Q, conns: c.C, denied: c.X, up: c.U, down: c.W, first: c.F, last: c.L}
		if m.minDay == 0 || c.D < m.minDay {
			m.minDay = c.D
		}
	}
	for id, s := range sf.Seen {
		if _, ok := m.services[id]; ok && s != nil {
			m.svcSeen[m.services[id].ID] = s
		}
	}
	for _, sc := range sf.Candidates {
		c := sc.Candidate
		if c.Domain == "" || len(m.candidates) >= maxCandidates {
			continue
		}
		c.clients = map[string]struct{}{}
		for _, ip := range sc.List {
			if len(c.clients) < maxSetSize {
				c.clients[ip] = struct{}{}
			}
		}
		c.Clients = max(c.Clients, len(c.clients))
		cp := c
		m.candidates[c.Domain] = &cp
	}
	for _, se := range sf.Endpoints {
		e := se.Endpoint
		if e.Host == "" || e.Kind == "" || len(m.endpoints) >= maxEndpoints {
			continue
		}
		e.clients = map[string]struct{}{}
		for _, ip := range se.List {
			if len(e.clients) < maxSetSize {
				e.clients[ip] = struct{}{}
			}
		}
		e.Clients = max(e.Clients, len(e.clients))
		cp := e
		m.endpoints[e.Host+"|"+e.Kind] = &cp
	}
	m.bytesSeen, m.sniSeen, m.dropped = sf.BytesSeen, sf.SNISeen, sf.Dropped
	m.lastSave = m.now()
}

// snapshotLocked 复制要保存的状态（调用方持锁）；编码与写文件在锁外进行。
func (m *Manager) snapshotLocked() *savedFile {
	sf := &savedFile{Version: fileVersion, Services: append([]Service(nil), m.uiSvcs...), Policies: map[string]string{}, Seen: map[string]*seen{},
		BytesSeen: m.bytesSeen, SNISeen: m.sniSeen, Dropped: m.dropped}
	for k, v := range m.uiPol {
		sf.Policies[k] = v
	}
	for k, v := range m.svcSeen {
		cp := *v
		sf.Seen[k] = &cp
	}
	sf.Cells = make([]savedCell, 0, len(m.cells))
	for k, c := range m.cells {
		sf.Cells = append(sf.Cells, savedCell{D: k.d, S: k.svc, I: k.ip, Q: c.queries, C: c.conns, X: c.denied, U: c.up, W: c.down, F: c.first, L: c.last})
	}
	for _, c := range m.candidates {
		sc := savedCandidate{Candidate: *c}
		for ip := range c.clients {
			sc.List = append(sc.List, ip)
		}
		sf.Candidates = append(sf.Candidates, sc)
	}
	for _, e := range m.endpoints {
		se := savedEndpoint{Endpoint: *e}
		for ip := range e.clients {
			se.List = append(se.List, ip)
		}
		sf.Endpoints = append(sf.Endpoints, se)
	}
	return sf
}

// Flush 在有变化时保存状态：force 为 false 时距上次保存不足 5 分钟不写（定期维护调用），退出时 force 为 true。
func (m *Manager) Flush(force bool) error {
	if m == nil || m.path == "" {
		return nil
	}
	m.mu.Lock()
	if !m.dirty || !force && m.now().Sub(m.lastSave) < saveInterval {
		m.mu.Unlock()
		return nil
	}
	sf := m.snapshotLocked()
	m.dirty, m.lastSave = false, m.now()
	m.mu.Unlock()
	if err := writeFile(m.path, sf); err != nil {
		m.mu.Lock()
		m.dirty = true // 下次重试
		m.mu.Unlock()
		return fmt.Errorf("保存 AI 使用统计失败: %w", err)
	}
	return nil
}

func writeFile(path string, sf *savedFile) error {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sf); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
