// Package alert 将安全告警推送到钉钉、企业微信、飞书机器人及通用 Webhook。
//
// 每个机器人独立选择推送等级（中危 / 高危 / 严重，可多选），并各自运行一个发送协程：
// 短时间内的多条告警合并为一条消息，按平台限制控制发送频率，超出部分汇总为“另有 N 条”，不会静默丢失。
package alert

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/safe"
)

// batchWait 为收到第一条告警后等待合并的时间（测试中缩短）。
var batchWait = 2 * time.Second

const (
	queueSize  = 200 // 每个机器人的待发送队列
	maxBatch   = 50  // 单条消息最多合并的告警数
	retryDelay = 10 * time.Second
	sendTO     = 15 * time.Second
	historyCap = 100
)

// Stats 是机器人的推送统计。
type Stats struct {
	Messages   int64     `json:"messages"`   // 成功发送的消息数
	Events     int64     `json:"events"`     // 已推送的告警事件数
	Failed     int64     `json:"failed"`     // 发送失败的消息数
	Suppressed int64     `json:"suppressed"` // 因频率限制被合并汇总的告警数
	LastOK     time.Time `json:"last_ok"`
	LastError  string    `json:"last_error,omitempty"`
	LastErrAt  time.Time `json:"last_error_at"`
	Queued     int       `json:"queued"`
}

// Record 是一次推送记录。
type Record struct {
	Time   time.Time `json:"time"`
	Robot  string    `json:"robot"`
	Title  string    `json:"title"`
	Events int       `json:"events"`
	OK     bool      `json:"ok"`
	Error  string    `json:"error,omitempty"`
}

type worker struct {
	mu         sync.Mutex
	robot      Robot
	stats      Stats
	suppressed map[model.Severity]int
	q          chan Event
	cancel     context.CancelFunc
}

func (w *worker) snapshot() Robot {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := w.robot
	r.Levels = append([]string(nil), r.Levels...)
	return r
}

// Notifier 管理告警推送机器人。配置文件中的机器人只读；在界面中添加的机器人保存在 robots_file 中。
type Notifier struct {
	mu      sync.Mutex
	workers map[string]*worker
	order   []string
	path    string // 界面添加的机器人的保存位置，为空表示只保存在内存中
	baseURL string
	dedup   time.Duration
	client  *http.Client
	ctx     context.Context // Run 之后有效
	seen    map[string]time.Time
	history []Record
	want    atomic.Uint32 // 有启用中的机器人订阅的等级（按位）
}

// New 根据配置创建推送器，并加载 path 中保存的界面机器人。
func New(cfg config.AlertConfig, path string) (*Notifier, error) {
	n := &Notifier{
		workers: map[string]*worker{}, path: path, baseURL: strings.TrimRight(cfg.BaseURL, "/"), dedup: cfg.DedupWindow,
		client: &http.Client{Timeout: sendTO}, seen: map[string]time.Time{},
	}
	if n.dedup <= 0 {
		n.dedup = 10 * time.Minute
	}
	for i, h := range cfg.Webhooks {
		r := Robot{ID: fmt.Sprintf("config-%d", i+1), Name: h.Name, Type: h.Type, URL: h.URL, Secret: h.Secret,
			Levels: h.Levels, Enabled: !h.Disabled, Report: h.Report, Source: "config"}
		if len(r.Levels) == 0 {
			r.Levels = levelsFrom(h.MinSeverity)
		}
		if err := r.Validate(false); err != nil {
			return nil, fmt.Errorf("alert.webhooks %s: %w", h.Name, err)
		}
		n.add(&r)
	}
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
		default:
			var saved struct {
				Robots []Robot `json:"robots"`
			}
			if err := json.Unmarshal(data, &saved); err != nil {
				return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
			}
			for i := range saved.Robots {
				r := saved.Robots[i]
				r.Source = "ui"
				if err := r.Validate(true); err != nil || r.ID == "" {
					log.Printf("[alert] 忽略 %s 中无效的机器人 %q: %v", path, r.Name, err)
					continue
				}
				n.add(&r)
			}
		}
	}
	n.updateWant()
	return n, nil
}

// levelsFrom 把旧配置的 min_severity 换算为等级列表；未配置时默认推送高危与严重。
func levelsFrom(min string) []string {
	if min == "" {
		return []string{"high", "critical"}
	}
	m := model.ParseSeverity(min)
	var out []string
	for _, l := range LevelNames {
		if model.ParseSeverity(l) >= m {
			out = append(out, l)
		}
	}
	return out
}

// add 注册机器人（调用方持锁或处于初始化阶段）。
func (n *Notifier) add(r *Robot) *worker {
	w := &worker{robot: *r, q: make(chan Event, queueSize), suppressed: map[model.Severity]int{}}
	n.workers[r.ID] = w
	n.order = append(n.order, r.ID)
	if n.ctx != nil {
		n.start(w)
	}
	return w
}

func (n *Notifier) start(w *worker) {
	ctx, cancel := context.WithCancel(n.ctx)
	w.cancel = cancel
	go n.run(ctx, w)
}

func (n *Notifier) updateWant() {
	var m uint32
	for _, w := range n.workers {
		r := w.snapshot()
		if !r.Enabled {
			continue
		}
		for _, l := range r.Levels {
			m |= 1 << uint(model.ParseSeverity(l))
		}
	}
	n.want.Store(m)
}

// Wants 返回是否有启用中的机器人推送该等级（无锁，供流水线快速判断）。
func (n *Notifier) Wants(s model.Severity) bool {
	return n != nil && n.want.Load()&(1<<uint(s)) != 0
}

// Run 启动所有机器人的发送协程，直到 ctx 结束。
func (n *Notifier) Run(ctx context.Context) {
	n.mu.Lock()
	n.ctx = ctx
	for _, id := range n.order {
		n.start(n.workers[id])
	}
	n.mu.Unlock()
	<-ctx.Done()
}

// Notify 投递一个事件：同一去重键在 dedup_window 内只推送一次，再分发给订阅了该等级的机器人。
// key 为空时不去重。
func (n *Notifier) Notify(key string, ev Event) {
	if !n.Wants(ev.Severity) {
		return
	}
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	if key != "" {
		if t, ok := n.seen[key]; ok && now.Sub(t) < n.dedup {
			return
		}
		if len(n.seen) >= 50000 {
			for k, t := range n.seen {
				if now.Sub(t) >= n.dedup {
					delete(n.seen, k)
				}
			}
			if len(n.seen) >= 50000 { // 仍然过多时整体清空，避免内存无限增长
				n.seen = map[string]time.Time{}
			}
		}
		n.seen[key] = now
	}
	for _, id := range n.order {
		w := n.workers[id]
		w.mu.Lock()
		ok := w.robot.Enabled && w.robot.wants(ev.Severity)
		w.mu.Unlock()
		if !ok {
			continue
		}
		select {
		case w.q <- ev:
		default:
			w.mu.Lock()
			w.suppressed[ev.Severity]++
			w.stats.Suppressed++
			w.mu.Unlock()
		}
	}
}

// run 是单个机器人的发送循环：合并短时间内的告警、按平台频率限制发送、失败时重试一次。
func (n *Notifier) run(ctx context.Context, w *worker) {
	var sent []time.Time // 最近一分钟的发送时间
	for {
		var first Event
		select {
		case <-ctx.Done():
			return
		case first = <-w.q:
		}
		batch := []Event{first}
		extra := map[model.Severity]int{}
		take := func(e Event) {
			if len(batch) < maxBatch {
				batch = append(batch, e)
			} else {
				extra[e.Severity]++
			}
		}
		timer := time.NewTimer(batchWait)
	collect:
		for {
			select {
			case e := <-w.q:
				take(e)
			case <-timer.C:
				break collect
			case <-ctx.Done():
				timer.Stop()
				return
			}
		}
		// 频率限制：最近一分钟的发送次数达到上限时等待，等待期间到达的告警继续合并
		r := w.snapshot()
		limit := r.rateLimit()
		for {
			cut := time.Now().Add(-time.Minute)
			for len(sent) > 0 && sent[0].Before(cut) {
				sent = sent[1:]
			}
			if len(sent) < limit {
				break
			}
			wait := time.NewTimer(time.Until(sent[0].Add(time.Minute)))
			select {
			case <-wait.C:
			case e := <-w.q:
				wait.Stop()
				take(e)
			case <-ctx.Done():
				wait.Stop()
				return
			}
		}
		w.mu.Lock()
		for s, c := range w.suppressed {
			extra[s] += c
		}
		w.suppressed = map[model.Severity]int{}
		w.mu.Unlock()
		b := &Batch{Events: batch, Suppressed: extra, BaseURL: n.baseURL}
		sent = append(sent, time.Now())
		err := n.deliver(ctx, w, b)
		var se *SendError
		if errors.As(err, &se) && se.Retry && ctx.Err() == nil {
			t := time.NewTimer(retryDelay)
			select {
			case <-t.C:
				sent = append(sent, time.Now())
				n.deliver(ctx, w, b)
			case <-ctx.Done():
				t.Stop()
				return
			}
		}
	}
}

// deliver 发送一批事件并记录结果。
func (n *Notifier) deliver(ctx context.Context, w *worker, b *Batch) (err error) {
	defer func() {
		if p := recover(); p != nil {
			safe.Report("推送告警", p)
			err = &SendError{Msg: fmt.Sprint("内部错误: ", p)}
		}
	}()
	r := w.snapshot()
	c, cancel := context.WithTimeout(ctx, sendTO)
	err = post(c, n.client, &r, b)
	cancel()
	events := len(b.Events) + b.suppressedTotal()
	w.mu.Lock()
	if err == nil {
		w.stats.Messages++
		w.stats.Events += int64(events)
		w.stats.LastOK = time.Now()
	} else {
		w.stats.Failed++
		w.stats.LastError, w.stats.LastErrAt = err.Error(), time.Now()
	}
	w.mu.Unlock()
	n.record(r.Name, b.title(), events, err)
	if err != nil {
		log.Printf("[alert] 推送到 %s 失败: %v", r.Name, err)
	}
	return err
}

func (n *Notifier) record(robot, title string, events int, err error) {
	rec := Record{Time: time.Now(), Robot: robot, Title: title, Events: events, OK: err == nil}
	if err != nil {
		rec.Error = err.Error()
	}
	n.mu.Lock()
	n.history = append(n.history, rec)
	if len(n.history) > historyCap {
		n.history = append([]Record(nil), n.history[len(n.history)-historyCap:]...)
	}
	n.mu.Unlock()
}

// ---------------- 管理接口 ----------------

// RobotView 是机器人在界面上的展示信息（不含 Webhook 令牌与签名密钥）。
type RobotView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	TypeLabel string    `json:"type_label"`
	URL       string    `json:"url"` // 已隐藏令牌
	HasSecret bool      `json:"has_secret"`
	Levels    []string  `json:"levels"`
	Enabled   bool      `json:"enabled"`
	Report    bool      `json:"report"`
	Source    string    `json:"source"`
	Created   time.Time `json:"created"`
	Stats     Stats     `json:"stats"`
}

// Info 是推送配置与状态概览。
type Info struct {
	Robots      []RobotView `json:"robots"`
	Persist     bool        `json:"persist"` // 界面添加的机器人是否会保存到磁盘
	File        string      `json:"file,omitempty"`
	BaseURL     string      `json:"base_url"`
	DedupWindow string      `json:"dedup_window"`
	ReportTime  string      `json:"report_time"` // 每日安全日报的推送时间（由 API 层填写）
	History     []Record    `json:"history"`
}

// Info 返回所有机器人及最近的推送记录（新的在前）。
func (n *Notifier) Info() Info {
	n.mu.Lock()
	defer n.mu.Unlock()
	info := Info{Persist: n.path != "", File: n.path, BaseURL: n.baseURL, DedupWindow: n.dedup.String(), Robots: []RobotView{}, History: []Record{}}
	for _, id := range n.order {
		w := n.workers[id]
		w.mu.Lock()
		r := w.robot
		st := w.stats
		w.mu.Unlock()
		st.Queued = len(w.q)
		info.Robots = append(info.Robots, RobotView{
			ID: r.ID, Name: r.Name, Type: r.Type, TypeLabel: TypeLabel(r.Type), URL: r.MaskedURL(), HasSecret: r.Secret != "",
			Levels: append([]string(nil), r.Levels...), Enabled: r.Enabled, Report: r.Report, Source: r.Source, Created: r.Created, Stats: st,
		})
	}
	for i := len(n.history) - 1; i >= 0; i-- {
		info.History = append(info.History, n.history[i])
	}
	return info
}

// ErrNotFound 表示机器人不存在。
var ErrNotFound = errors.New("机器人不存在")

// ErrReadOnly 表示机器人来自配置文件，不能在界面中修改。
var ErrReadOnly = errors.New("该机器人来自配置文件，请修改配置文件 alert.webhooks")

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Create 添加界面机器人并保存。
func (n *Notifier) Create(r Robot) (RobotView, error) {
	r.Source, r.ID, r.Created = "ui", newID(), time.Now()
	if err := r.Validate(true); err != nil {
		return RobotView{}, err
	}
	n.mu.Lock()
	if len(n.workers) >= 50 {
		n.mu.Unlock()
		return RobotView{}, errors.New("机器人数量已达上限（50 个）")
	}
	n.add(&r)
	n.updateWant()
	err := n.saveLocked()
	n.mu.Unlock()
	return n.view(r.ID), err
}

// Update 修改界面机器人。Webhook 地址或密钥留空表示保持不变；clearSecret 为 true 时清除密钥。
func (n *Notifier) Update(id string, r Robot, clearSecret bool) (RobotView, error) {
	n.mu.Lock()
	w := n.workers[id]
	if w == nil {
		n.mu.Unlock()
		return RobotView{}, ErrNotFound
	}
	old := w.snapshot()
	if old.Source != "ui" {
		n.mu.Unlock()
		return RobotView{}, ErrReadOnly
	}
	r.ID, r.Source, r.Created = old.ID, old.Source, old.Created
	if strings.TrimSpace(r.URL) == "" {
		r.URL = old.URL
	}
	if strings.TrimSpace(r.Secret) == "" && !clearSecret {
		r.Secret = old.Secret
	}
	if err := r.Validate(true); err != nil {
		n.mu.Unlock()
		return RobotView{}, err
	}
	w.mu.Lock()
	w.robot = r
	w.mu.Unlock()
	n.updateWant()
	err := n.saveLocked()
	n.mu.Unlock()
	return n.view(id), err
}

// Delete 删除界面机器人。
func (n *Notifier) Delete(id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	w := n.workers[id]
	if w == nil {
		return ErrNotFound
	}
	if w.snapshot().Source != "ui" {
		return ErrReadOnly
	}
	if w.cancel != nil {
		w.cancel()
	}
	delete(n.workers, id)
	for i, x := range n.order {
		if x == id {
			n.order = append(n.order[:i:i], n.order[i+1:]...)
			break
		}
	}
	n.updateWant()
	return n.saveLocked()
}

// Test 立即发送一条测试消息（不经过队列与频率限制），返回发送结果。
// id 不为空时，r 中留空的 Webhook 地址与密钥沿用已保存的值（编辑表单中未修改这两项时）。
func (n *Notifier) Test(ctx context.Context, id string, r Robot) error {
	if id != "" {
		n.mu.Lock()
		w := n.workers[id]
		n.mu.Unlock()
		if w == nil {
			return ErrNotFound
		}
		old := w.snapshot()
		if strings.TrimSpace(r.URL) == "" {
			r.URL = old.URL
		}
		if strings.TrimSpace(r.Secret) == "" {
			r.Secret = old.Secret
		}
		if r.Type == "" {
			r.Name, r.Type, r.Levels, r.Source = old.Name, old.Type, old.Levels, old.Source
		}
		if r.Source == "" {
			r.Source = old.Source
		}
	}
	if err := r.Validate(r.Source != "config"); err != nil {
		return err
	}
	var labels []string
	for _, l := range r.Levels {
		labels = append(labels, model.ParseSeverity(l).Label())
	}
	b := &Batch{BaseURL: n.baseURL, Events: []Event{{Kind: "test", Severity: model.SevInfo, Title: r.Name, Category: strings.Join(labels, "、"), Time: time.Now()}}}
	c, cancel := context.WithTimeout(ctx, sendTO)
	defer cancel()
	err := post(c, n.client, &r, b)
	n.record(r.Name, "测试消息", 0, err)
	return err
}

// SendReport 立即发送安全日报（不经过告警队列，不与告警合并）。id 不为空时只发送给该机器人（界面中的“发送日报”），
// 否则发送给所有启用且勾选了“接收日报”的机器人。返回成功发送的机器人数与第一个错误。
func (n *Notifier) SendReport(ctx context.Context, id string, ev Event) (int, error) {
	ev.Kind = "report"
	n.mu.Lock()
	var targets []*worker
	for _, wid := range n.order {
		w := n.workers[wid]
		r := w.snapshot()
		if id != "" && wid == id || id == "" && r.Enabled && r.Report {
			targets = append(targets, w)
		}
	}
	n.mu.Unlock()
	if id != "" && len(targets) == 0 {
		return 0, ErrNotFound
	}
	sent := 0
	var first error
	for _, w := range targets {
		if err := n.deliver(ctx, w, &Batch{Events: []Event{ev}, BaseURL: n.baseURL}); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		sent++
	}
	return sent, first
}

func (n *Notifier) view(id string) RobotView {
	for _, v := range n.Info().Robots {
		if v.ID == id {
			return v
		}
	}
	return RobotView{}
}

// saveLocked 把界面添加的机器人写入文件（调用方持锁）。文件包含 Webhook 令牌与密钥，权限为 0600。
func (n *Notifier) saveLocked() error {
	if n.path == "" {
		return nil
	}
	var out struct {
		Robots []Robot `json:"robots"`
	}
	out.Robots = []Robot{}
	for _, id := range n.order {
		if r := n.workers[id].snapshot(); r.Source == "ui" {
			out.Robots = append(out.Robots, r)
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(n.path), 0o755); err != nil {
		return fmt.Errorf("保存机器人配置失败: %w", err)
	}
	tmp := n.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("保存机器人配置失败: %w", err)
	}
	if err := os.Rename(tmp, n.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("保存机器人配置失败: %w", err)
	}
	return nil
}
