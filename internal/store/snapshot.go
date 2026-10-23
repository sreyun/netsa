package store

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netsa/internal/model"
)

type snapshot struct {
	Version    int                   `json:"version"`
	SavedAt    time.Time             `json:"saved_at"`
	Profiles   map[string]*IPProfile `json:"profiles"`
	Alerts     []*model.Alert        `json:"alerts"`
	NextID     uint64                `json:"next_id"`
	Buckets    map[int64]*Bucket     `json:"buckets"`
	Totals     Totals                `json:"totals"`
	Categories map[string]int64      `json:"categories"`
	Rules      map[string]int64      `json:"rules"`
	RuleNames  map[string]string     `json:"rule_names"`
	SevCount   [5]int64              `json:"sev_count"`
	Phases     map[string]int64      `json:"phases"`
	Results    map[string]int64      `json:"results"`
	MinTime    time.Time             `json:"min_time"`
	MaxTime    time.Time             `json:"max_time"`
	Surface    *surface              `json:"surface"`
}

// Save 将状态写入快照文件（.gz 后缀时压缩），先写临时文件再原子替换。
func (s *Store) Save(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	var w interface {
		Write([]byte) (int, error)
	} = f
	var gz *gzip.Writer
	if strings.HasSuffix(path, ".gz") {
		gz = gzip.NewWriter(f)
		w = gz
	}
	s.mu.RLock()
	snap := snapshot{
		Version: 1, SavedAt: time.Now(), Profiles: s.ips, NextID: s.nextID, Buckets: s.buckets, Totals: s.totals,
		Categories: s.categories, Rules: s.rules, RuleNames: s.ruleNames, SevCount: s.sevCount, Phases: s.phases,
		Results: s.results, MinTime: s.minTime, MaxTime: s.maxTime, Surface: s.surf,
	}
	n := len(s.alerts)
	for i := 0; i < n; i++ {
		idx := i
		if n == s.maxAlerts {
			idx = (s.alertHead + i) % n
		}
		snap.Alerts = append(snap.Alerts, s.alerts[idx])
	}
	err = json.NewEncoder(w).Encode(&snap)
	s.mu.RUnlock()
	if gz != nil {
		if cerr := gz.Close(); err == nil {
			err = cerr
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
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
	return nil
}
