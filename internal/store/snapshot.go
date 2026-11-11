package store

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netsa/internal/model"
)

// snapshotVersion 是当前快照结构版本。修改持久化字段的含义时递增，并在 migrateSnapshot
// 中补齐旧版本默认值。旧版本程序读到更高版本会静默丢弃不认识的字段并回写，
// 因此 Load 对「版本高于本程序」的快照一律拒绝，并先备份原文件再以空状态启动。
const snapshotVersion = 2

// ErrSnapshotTooNew 表示快照由更新版本的程序写入，当前版本无法安全解析。
var ErrSnapshotTooNew = errors.New("快照由更新版本的程序写入，当前版本无法安全读取")

// snapshotMeta 是快照头部中规模有上限、在一次读锁内编码即可的部分。
type snapshotMeta struct {
	Version    int                   `json:"version"`
	SavedAt    time.Time             `json:"saved_at"`
	NextID     uint64                `json:"next_id"`
	Buckets    map[int64]*Bucket     `json:"buckets"`
	Totals     Totals                `json:"totals"`
	Categories map[string]int64      `json:"categories"`
	Rules      map[string]int64      `json:"rules"`
	RuleNames  map[string]string     `json:"rule_names"`
	RuleMeta   map[string]ruleMeta   `json:"rule_meta,omitempty"`
	RuleTally  map[string]*ruleTally `json:"rule_tally,omitempty"`
	Outbound   []*OutboundDst        `json:"outbound,omitempty"`
	SevCount   [5]int64              `json:"sev_count"`
	Phases     map[string]int64      `json:"phases"`
	Results    map[string]int64      `json:"results"`
	MinTime    time.Time             `json:"min_time"`
	MaxTime    time.Time             `json:"max_time"`
	Scores     []ScorePoint          `json:"score_history,omitempty"`
	NextInc    uint64                `json:"next_incident,omitempty"`
}

// snapshotHead 是快照中除画像以外的部分。告警、事件、每日汇总、攻击面与链路的规模可达数万条，保存时分段编码
// （writeSnapshot），解析时与原来的单个对象相同。
type snapshotHead struct {
	snapshotMeta
	Alerts    []*model.Alert       `json:"alerts"`
	Surface   *surface             `json:"surface"`
	Incidents map[uint64]*Incident `json:"incidents,omitempty"`
	Days      map[string]*DayStat  `json:"days,omitempty"`
	Chains    chainList            `json:"asset_chains,omitempty"` // 资产攻击链路
}

type snapshot struct {
	snapshotHead
	Profiles map[string]*IPProfile `json:"profiles"`
}

// saveChunk 为分批编码画像时每批的数量：批与批之间释放读锁，保存快照时不会长时间阻塞日志入库与大屏查询。
const saveChunk = 2048

// Save 将状态写入快照文件（.gz 后缀时压缩），先写临时文件再原子替换。
// 头部与画像分段、分批在读锁内编码，压缩与写盘在锁外进行；状态规模很大时也只会短暂占用锁。
func (s *Store) Save(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mark := s.journalMark()
	tmp := path + ".tmp"
	// 快照包含攻击源画像等敏感安全数据，仅允许服务账号读取
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	err = s.writeSnapshot(f, strings.HasSuffix(path, ".gz"))
	if err == nil {
		// 先落盘再改名：随后会按这份快照整理已落盘的处置记录日志，断电时快照若只改了名、内容还没写回，
		// 快照是残缺的、日志里对应的处置记录又已丢弃
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// 快照已经包含 mark 之前的处置记录，可以丢弃；失败也不影响数据，重放时按更新时间跳过
	if err := s.compactJournal(mark); err != nil {
		log.Printf("[store] 整理处置记录日志失败: %v", err)
	}
	return nil
}

// surfaceRest 是攻击面中除入口、服务、发现以外的部分（字段与 surface 的 JSON 标签一致）。
type surfaceRest struct {
	Tech           map[string]int     `json:"tech"`
	Ports          map[int]int64      `json:"ports"`
	ExploitBlocked int64              `json:"exploit_blocked"`
	ExploitPassed  int64              `json:"exploit_passed"`
	Fallback       map[string][]int64 `json:"fallback,omitempty"`
}

// writeSnapshot 写出快照。头部分段编码，画像分批编码，批与批之间释放读锁：
//   - 标量、计数表、分钟桶在一次读锁内编码（规模有上限）；
//   - 告警是写时复制的（markAlertLocked 替换整个对象），读锁内只复制指针，编码在锁外；
//   - 事件、每日汇总、攻击面的入口 / 服务 / 发现、资产链路、画像在读锁内按批编码，批间放锁。
//
// 满规模时（2 万条告警、400 天汇总、2 万个入口、2 万个事件）整体编码要数百毫秒到一秒以上，一次持锁做完
// 会让每分钟一次的定时保存阻塞日志入库与大屏查询。段与段之间不是同一时刻的状态（画像与头部原本也不是）。
func (s *Store) writeSnapshot(f io.Writer, compress bool) error {
	out := f
	var gz *gzip.Writer
	if compress {
		gz, _ = gzip.NewWriterLevel(f, gzip.BestSpeed)
		out = gz
	}
	w := bufio.NewWriterSize(out, 256<<10)

	s.mu.RLock()
	meta := snapshotMeta{
		Version: snapshotVersion, SavedAt: time.Now(), NextID: s.nextID, Buckets: s.buckets, Totals: s.totals,
		Categories: s.categories, Rules: s.rules, RuleNames: s.ruleNames, RuleMeta: s.ruleMeta, RuleTally: s.tally, SevCount: s.sevCount, Phases: s.phases,
		Results: s.results, MinTime: s.minTime, MaxTime: s.maxTime, Scores: s.scores, NextInc: s.nextInc, Outbound: s.outboundList(),
	}
	metaJSON, err := json.Marshal(&meta)
	n := len(s.alerts)
	alerts := make([]*model.Alert, 0, n)
	for i := 0; i < n; i++ {
		idx := i
		if n == s.maxAlerts {
			idx = (s.alertHead + i) % n
		}
		alerts = append(alerts, s.alerts[idx])
	}
	incKeys := mapKeys(s.incidents)
	dayKeys := mapKeys(s.days)
	sf := s.surf
	var epKeys, svKeys, fdKeys []string
	var restJSON []byte
	if sf != nil && err == nil {
		epKeys, svKeys, fdKeys = mapKeys(sf.Endpoints), mapKeys(sf.Services), mapKeys(sf.Findings)
		restJSON, err = json.Marshal(surfaceRest{Tech: sf.Tech, Ports: sf.Ports, ExploitBlocked: sf.ExploitBlocked, ExploitPassed: sf.ExploitPassed, Fallback: sf.Fallback})
	}
	chains := s.chainTracks()
	ips := mapKeys(s.ips)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	// 键的排序在锁外：输出顺序固定，便于比较两份快照
	for _, k := range [][]string{dayKeys, epKeys, svKeys, fdKeys, ips} {
		sort.Strings(k)
	}
	sort.Slice(incKeys, func(i, j int) bool { return incKeys[i] < incKeys[j] })
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Kind != chains[j].Kind {
			return chains[i].Kind < chains[j].Kind
		}
		return chains[i].Key < chains[j].Key
	})

	// {...头部字段..., "alerts": [...], ..., "profiles": {"ip": {...}, ...}}
	w.Write(metaJSON[:len(metaJSON)-1])
	w.WriteString(`,"alerts":`)
	alertsJSON, err := json.Marshal(alerts)
	if err != nil {
		return err
	}
	w.Write(alertsJSON)
	if len(incKeys) > 0 {
		w.WriteString(`,"incidents":`)
		if err := writeObject(s, w, incKeys, saveChunk, func(k uint64) any {
			if v := s.incidents[k]; v != nil {
				return v
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if len(dayKeys) > 0 {
		w.WriteString(`,"days":`)
		// 每天最多记 2000 个攻击源等明细：每批只编码几天
		if err := writeObject(s, w, dayKeys, 8, func(k string) any {
			if v := s.days[k]; v != nil {
				return v
			}
			return nil
		}); err != nil {
			return err
		}
	}
	w.WriteString(`,"surface":`)
	if sf == nil {
		w.WriteString("null")
	} else {
		w.WriteString(`{"endpoints":`)
		if err := writeObject(s, w, epKeys, saveChunk, func(k string) any {
			if v := sf.Endpoints[k]; v != nil {
				return v
			}
			return nil
		}); err != nil {
			return err
		}
		w.WriteString(`,"services":`)
		if err := writeObject(s, w, svKeys, saveChunk, func(k string) any {
			if v := sf.Services[k]; v != nil {
				return v
			}
			return nil
		}); err != nil {
			return err
		}
		w.WriteString(`,"findings":`)
		if err := writeObject(s, w, fdKeys, saveChunk, func(k string) any {
			if v := sf.Findings[k]; v != nil {
				return v
			}
			return nil
		}); err != nil {
			return err
		}
		w.WriteByte(',')
		w.Write(restJSON[1:])
	}
	if len(chains) > 0 {
		w.WriteString(`,"asset_chains":[`)
		first := true
		var buf []byte
		for i := 0; i < len(chains); i += 256 {
			buf = buf[:0]
			s.mu.RLock()
			for _, tr := range chains[i:min(i+256, len(chains))] {
				if s.chains[chainKey{tr.Kind, tr.Key}] != tr { // 编码期间已被清理或淘汰
					continue
				}
				b, err := json.Marshal(tr)
				if err != nil {
					s.mu.RUnlock()
					return err
				}
				if !first {
					buf = append(buf, ',')
				}
				first = false
				buf = append(buf, b...)
			}
			s.mu.RUnlock()
			if _, err := w.Write(buf); err != nil {
				return err
			}
		}
		w.WriteByte(']')
	}
	w.WriteString(`,"profiles":`)
	if err := writeObject(s, w, ips, saveChunk, func(ip string) any {
		if p := s.ips[ip]; p != nil { // 编码期间已被淘汰的跳过
			return p
		}
		return nil
	}); err != nil {
		return err
	}
	w.WriteString("}\n")
	if err := w.Flush(); err != nil {
		return err
	}
	if gz != nil {
		return gz.Close()
	}
	return nil
}

// mapKeys 返回 map 的全部键（调用方持锁）。
func mapKeys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// writeObject 把 keys 对应的条目写成 JSON 对象 {"k": v, ...}：每 chunk 条在一次读锁内编码，批间释放读锁。
// get 在读锁内调用，条目已不存在时返回 nil（跳过）。
func writeObject[K comparable](s *Store, w *bufio.Writer, keys []K, chunk int, get func(K) any) error {
	w.WriteByte('{')
	first := true
	var buf []byte
	for i := 0; i < len(keys); i += chunk {
		buf = buf[:0]
		s.mu.RLock()
		for _, k := range keys[i:min(i+chunk, len(keys))] {
			v := get(k)
			if v == nil {
				continue
			}
			b, err := json.Marshal(v)
			if err != nil {
				s.mu.RUnlock()
				return err
			}
			if !first {
				buf = append(buf, ',')
			}
			first = false
			key, _ := json.Marshal(fmt.Sprint(k))
			buf = append(buf, key...)
			buf = append(buf, ':')
			buf = append(buf, b...)
		}
		s.mu.RUnlock()
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return w.WriteByte('}')
}

// migrateSnapshot 把旧版本快照升级到当前版本；版本高于本程序时返回 ErrSnapshotTooNew。
func migrateSnapshot(snap *snapshot) error {
	if snap.Version > snapshotVersion {
		return fmt.Errorf("%w（快照 v%d，本程序支持至 v%d）", ErrSnapshotTooNew, snap.Version, snapshotVersion)
	}
	if snap.Version < 1 {
		snap.Version = 1
	}
	if snap.Version < 2 {
		// v1 → v2：事件新增「命中 / 告警」双计数与每规则告警数。旧快照里 Rules 只统计过告警，
		// 因此命中数按告警数回填，RuleAlerts 与 Rules 一致。
		for _, inc := range snap.Incidents {
			if inc == nil {
				continue
			}
			if inc.Hits < inc.Alerts {
				inc.Hits = inc.Alerts
			}
			if inc.Muted < 0 || inc.Muted > inc.Hits-inc.Alerts {
				inc.Muted = inc.Hits - inc.Alerts
			}
			if inc.RuleAlerts == nil {
				inc.RuleAlerts = make(map[string]int, len(inc.Rules))
				for k, v := range inc.Rules {
					inc.RuleAlerts[k] = v
				}
			}
		}
		snap.Version = 2
	}
	return nil
}

// snapshotLoadError 在返回错误前把有问题的快照文件改名备份，避免被下一次保存覆盖；
// 目录不可写等无法备份的情况不掩盖原始错误。
func snapshotLoadError(path, suffix string, err error) error {
	backup := path + "." + suffix + ".bak"
	if _, statErr := os.Stat(backup); statErr == nil {
		backup = fmt.Sprintf("%s.%s.%s.bak", path, suffix, time.Now().Format("20060102-150405"))
	}
	if renameErr := os.Rename(path, backup); renameErr != nil {
		return fmt.Errorf("%w（原文件备份失败: %v）", err, renameErr)
	}
	return fmt.Errorf("%w；原文件已备份为 %s", err, backup)
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
	// Windows 下重命名被打开的文件会失败：备份前先显式关闭，defer 里只做兜底。
	closed := false
	closeFile := func() {
		if !closed {
			closed = true
			f.Close()
		}
	}
	defer closeFile()
	br := bufio.NewReaderSize(f, 1<<16)
	var r io.Reader = br
	// 按文件头判断是否压缩，而不是只看扩展名：把未压缩的快照改名为 .gz（切换 storage.snapshot 配置、恢复备份）时照常读取
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			// gzip 头损坏同样先备份：否则以空状态启动后，下一次定时保存会覆盖掉原文件
			closeFile()
			return snapshotLoadError(path, "corrupt", fmt.Errorf("解析快照失败: %w", err))
		}
		defer gz.Close()
		r = gz
	}
	var snap snapshot
	if err := json.NewDecoder(r).Decode(&snap); err != nil {
		// 文件损坏（截断、gzip 异常）时先备份：否则下一次定时保存会用空状态覆盖掉它
		closeFile()
		return snapshotLoadError(path, "corrupt", fmt.Errorf("解析快照失败: %w", err))
	}
	if err := migrateSnapshot(&snap); err != nil {
		closeFile()
		return snapshotLoadError(path, fmt.Sprintf("v%d", snap.Version), err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.Profiles != nil {
		s.ips = snap.Profiles
	}
	future := snap.SavedAt.Add(time.Hour) // 旧版本按设备的未来时间记下的画像时间收敛到保存时间
	if snap.SavedAt.IsZero() {
		future = time.Now().Add(time.Hour)
	}
	for ip, p := range s.ips {
		if p.IP == "" {
			p.IP = ip
		}
		if p.LastSeen.After(future) {
			p.LastSeen = future.Add(-time.Hour)
		}
		if p.FirstSeen.After(p.LastSeen) {
			p.FirstSeen = p.LastSeen
		}
		if p.Attacks > 0 {
			p.ensureAttackMaps() // 兼容旧版本快照中缺失的字段
		}
		cleanProfile(p) // 旧版本保存的二进制请求目标、日志中的控制字符
		if p.Attacks > 0 || len(p.Intel) > 0 {
			p.recompute(nil, nil) // 评分规则可能已更新，按当前规则重新计算等级
		}
		s.rebuildSketch(p)
	}
	s.agg.rebuild(s.ips) // 增量统计不持久化，按恢复后的画像重建一次
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
	if snap.RuleMeta != nil {
		s.ruleMeta = snap.RuleMeta
	}
	if snap.RuleTally != nil {
		s.tally = snap.RuleTally
	}
	s.retracted = map[string]bool{}
	// 旧版本快照没有规则的攻击类型与阶段：按保留的告警补齐（停用的误报规则据此从评分与排行中剔除）
	for _, a := range s.alerts {
		if a != nil && a.RuleID != "" {
			if _, ok := s.ruleMeta[a.RuleID]; !ok {
				s.ruleMeta[a.RuleID] = ruleMeta{Category: a.Category, Phase: a.Phase}
			}
		}
	}
	if len(s.excluded) > 0 { // 运行中重新载入快照（如恢复备份）：已停用的误报规则继续不计入评分
		for _, p := range s.ips {
			if p.Attacks > 0 {
				p.recompute(s.excluded, s.ruleMeta)
				if p.retractedOnly = retractedOnlyOf(p, s.excluded); p.retractedOnly {
					s.retracted[p.IP] = true
				}
			}
		}
		s.agg.rebuild(s.ips)
	}
	s.sevCount = snap.SevCount
	s.minTime, s.maxTime = snap.MinTime, snap.MaxTime
	if sf := snap.Surface; sf != nil {
		for p := range sf.Ports { // 旧版本没有限制端口范围：清理越界的键
			if p <= 0 || p > 65535 {
				delete(sf.Ports, p)
			}
		}
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
			sv.src = map[string]int32{}
		}
		sf.purgeSelfRFI()      // 旧版本把本站的 pdf 预览地址记成了远程文件包含
		sf.cleanLegacy()       // 旧版本把兜底页面登记成的敏感入口与敏感资源暴露
		sf.purgeUnusedDevice() // 旧版本只凭策略匹配日志记下的防火墙管理服务
		sf.reclassify()        // 规则收紧后旧版本误判的敏感入口
		sf.stripNUL()          // 旧版本把华为 syslog 末尾的 NUL 带进了策略名
		sf.purgeFakeHosts()    // 旧版本按虚构的 Host 头登记的入口
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
	s.chains = map[chainKey]*chainTrack{}
	for _, tr := range snap.Chains {
		if tr == nil || tr.Key == "" || tr.Kind == "" {
			continue
		}
		tr.reindex()
		s.chains[chainKey{tr.Kind, tr.Key}] = tr
	}
	s.cleanTargetsLocked()
	s.outbound = map[string]*OutboundDst{}
	for _, d := range snap.Outbound {
		if d != nil && d.IP != "" && len(s.outbound) < maxOutbound {
			s.outbound[d.IP] = d
		}
	}
	s.incByKey = map[string]uint64{}
	for id, inc := range s.incidents {
		if inc == nil {
			delete(s.incidents, id)
			continue
		}
		inc.ID = id
		inc.ensureMaps()
		inc.migrateGrade(time.Now())
		if id > s.nextInc {
			s.nextInc = id
		}
		if cur := s.incidents[s.incByKey[inc.Key]]; cur == nil || cur.ID < id {
			s.incByKey[inc.Key] = id
		}
	}
	return nil
}

// chainList 是快照中的资产攻击链路。解析失败（格式变化、内容损坏）时只丢弃这一部分并记录日志，
// 不让整个快照（事件处置记录、画像）因此无法恢复。
type chainList []*chainTrack

func (c *chainList) UnmarshalJSON(b []byte) error {
	var list []*chainTrack
	if err := json.Unmarshal(b, &list); err != nil {
		log.Printf("[store] 快照中的资产攻击链路无法解析，已忽略: %v", err)
		*c = nil
		return nil
	}
	*c = list
	return nil
}
