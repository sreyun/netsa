package store

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netsa/internal/model"
)

// snapshotHead 是快照中除画像以外的部分。
type snapshotHead struct {
	Version    int                  `json:"version"`
	SavedAt    time.Time            `json:"saved_at"`
	Alerts     []*model.Alert       `json:"alerts"`
	NextID     uint64               `json:"next_id"`
	Buckets    map[int64]*Bucket    `json:"buckets"`
	Totals     Totals               `json:"totals"`
	Categories map[string]int64     `json:"categories"`
	Rules      map[string]int64     `json:"rules"`
	RuleNames  map[string]string    `json:"rule_names"`
	SevCount   [5]int64             `json:"sev_count"`
	Phases     map[string]int64     `json:"phases"`
	Results    map[string]int64     `json:"results"`
	MinTime    time.Time            `json:"min_time"`
	MaxTime    time.Time            `json:"max_time"`
	Surface    *surface             `json:"surface"`
	Scores     []ScorePoint         `json:"score_history,omitempty"`
	Incidents  map[uint64]*Incident `json:"incidents,omitempty"`
	NextInc    uint64               `json:"next_incident,omitempty"`
	Days       map[string]*DayStat  `json:"days,omitempty"`
}

type snapshot struct {
	snapshotHead
	Profiles map[string]*IPProfile `json:"profiles"`
}

// saveChunk 为分批编码画像时每批的数量：批与批之间释放读锁，保存快照时不会长时间阻塞日志入库与大屏查询。
const saveChunk = 2048

// Save 将状态写入快照文件（.gz 后缀时压缩），先写临时文件再原子替换。
// 画像分批在读锁内编码，压缩与写盘在锁外进行；状态规模很大时也只会短暂占用锁。
func (s *Store) Save(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	// 快照包含攻击源画像等敏感安全数据，仅允许服务账号读取
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	err = s.writeSnapshot(f, strings.HasSuffix(path, ".gz"))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) writeSnapshot(f io.Writer, compress bool) error {
	out := f
	var gz *gzip.Writer
	if compress {
		gz, _ = gzip.NewWriterLevel(f, gzip.BestSpeed)
		out = gz
	}
	w := bufio.NewWriterSize(out, 256<<10)

	s.mu.RLock()
	head := snapshotHead{
		Version: 1, SavedAt: time.Now(), NextID: s.nextID, Buckets: s.buckets, Totals: s.totals,
		Categories: s.categories, Rules: s.rules, RuleNames: s.ruleNames, SevCount: s.sevCount, Phases: s.phases,
		Results: s.results, MinTime: s.minTime, MaxTime: s.maxTime, Surface: s.surf, Scores: s.scores, Incidents: s.incidents, NextInc: s.nextInc, Days: s.days,
	}
	n := len(s.alerts)
	head.Alerts = make([]*model.Alert, 0, n)
	for i := 0; i < n; i++ {
		idx := i
		if n == s.maxAlerts {
			idx = (s.alertHead + i) % n
		}
		head.Alerts = append(head.Alerts, s.alerts[idx])
	}
	headJSON, err := json.Marshal(&head)
	ips := make([]string, 0, len(s.ips))
	for ip := range s.ips {
		ips = append(ips, ip)
	}
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	// {...头部字段..., "profiles": {"ip": {...}, ...}}
	w.Write(headJSON[:len(headJSON)-1])
	w.WriteString(`,"profiles":{`)
	first := true
	var buf []byte
	for i := 0; i < len(ips); i += saveChunk {
		end := min(i+saveChunk, len(ips))
		buf = buf[:0]
		s.mu.RLock()
		for _, ip := range ips[i:end] {
			p := s.ips[ip]
			if p == nil { // 编码期间已被淘汰
				continue
			}
			b, err := json.Marshal(p)
			if err != nil {
				s.mu.RUnlock()
				return err
			}
			if !first {
				buf = append(buf, ',')
			}
			first = false
			key, _ := json.Marshal(ip)
			buf = append(buf, key...)
			buf = append(buf, ':')
			buf = append(buf, b...)
		}
		s.mu.RUnlock()
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	w.WriteString("}}\n")
	if err := w.Flush(); err != nil {
		return err
	}
	if gz != nil {
		return gz.Close()
	}
	return nil
}

// Load 从快照恢复状态；文件不存在时不报错。
func (s *Store) Load(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var r interface {
		Read([]byte) (int, error)
	} = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	var snap snapshot
	if err := json.NewDecoder(r).Decode(&snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Profiles != nil {
		s.ips = snap.Profiles
	}
	for ip, p := range s.ips {
		if p.IP == "" {
			p.IP = ip
		}
		if p.Attacks > 0 {
			p.ensureAttackMaps() // 兼容旧版本快照中缺失的字段
		}
		if p.Attacks > 0 || len(p.Intel) > 0 {
			p.recompute() // 评分规则可能已更新，按当前规则重新计算等级
		}
		s.rebuildSketch(p)
	}
	if len(snap.Alerts) > s.maxAlerts {
		snap.Alerts = snap.Alerts[len(snap.Alerts)-s.maxAlerts:]
	}
	// 快照中的告警按时间先后排列，写指针从 0 开始即可保持环形缓冲区语义
	s.alerts, s.alertHead = snap.Alerts, 0
	s.nextID = snap.NextID
	if snap.Buckets != nil {
		s.buckets = snap.Buckets
	}
	s.totals = snap.Totals
	for _, m := range []struct {
		dst *map[string]int64
		src map[string]int64
	}{{&s.categories, snap.Categories}, {&s.rules, snap.Rules}, {&s.phases, snap.Phases}, {&s.results, snap.Results}} {
		if m.src != nil {
			*m.dst = m.src
		}
	}
	if snap.RuleNames != nil {
		s.ruleNames = snap.RuleNames
	}
	s.sevCount = snap.SevCount
	s.minTime, s.maxTime = snap.MinTime, snap.MaxTime
	if sf := snap.Surface; sf != nil {
		def := newSurface()
		if sf.Endpoints == nil {
			sf.Endpoints = def.Endpoints
		}
		if sf.Services == nil {
			sf.Services = def.Services
		}
		if sf.Findings == nil {
			sf.Findings = def.Findings
		}
		if sf.Tech == nil {
			sf.Tech = def.Tech
		}
		if sf.Ports == nil {
			sf.Ports = def.Ports
		}
		for _, ep := range sf.Endpoints {
			ep.atk = map[string]struct{}{}
			if ep.Methods == nil {
				ep.Methods = map[string]int{}
			}
			if ep.Status == nil {
				ep.Status = map[int]int{}
			}
		}
		for _, sv := range sf.Services {
			sv.src = map[string]struct{}{}
		}
		s.surf = sf
	}
	if len(snap.Scores) > maxScorePoints {
		snap.Scores = snap.Scores[len(snap.Scores)-maxScorePoints:]
	}
	s.scores = snap.Scores
	if snap.Incidents != nil {
		s.incidents = snap.Incidents
	}
	s.nextInc = snap.NextInc
	if snap.Days != nil {
		s.days = snap.Days
		s.curDay, s.dayEnd = nil, 0
	}
	s.incByKey = map[string]uint64{}
	for id, inc := range s.incidents {
		if inc == nil {
			delete(s.incidents, id)
			continue
		}
		inc.ID = id
		inc.ensureMaps()
		if id > s.nextInc {
			s.nextInc = id
		}
		if cur := s.incidents[s.incByKey[inc.Key]]; cur == nil || cur.ID < id {
			s.incByKey[inc.Key] = id
		}
	}
	return nil
}
