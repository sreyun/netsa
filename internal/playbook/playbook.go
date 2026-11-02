// Package playbook 实现处置剧本和工单对接：事件满足条件时自动指派、写入处置步骤、创建工单、提交封禁申请。
//
// 剧本只做可逆、需要人继续跟进的动作：不会关闭事件，封禁也只是提交申请。同一剧本对同一事件只执行一次，
// 执行记录写在事件的处置记录里，重启后不会重复执行。
package playbook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
	"netsa/internal/store"
)

const (
	actor     = "处置剧本"
	queueSize = 2000
	doneMark  = "已执行处置剧本「"
)

// Host 是剧本依赖的平台能力。
type Host interface {
	Incident(id uint64) *store.IncidentDetail
	UpdateIncidents(ids []uint64, user string, u store.IncidentUpdate) ([]store.IncidentView, error)
}

// BlockFunc 提交封禁申请。
type BlockFunc func(ip, reason string, incident uint64, user string) error

type ticket struct {
	cfg   config.TicketConfig
	tpl   *template.Template
	token string
}

// TicketData 是工单请求体模板可以使用的字段。
type TicketData struct {
	ID         uint64
	Title      string
	Source     string
	Location   string
	Severity   string
	Status     string
	Categories []string
	Targets    []string
	Assets     []string
	Created    time.Time
	Proven     bool
}

// Engine 执行剧本。
type Engine struct {
	books   []book
	tickets map[string]*ticket
	host    Host
	block   BlockFunc
	client  *http.Client
	queue   chan uint64
	dropped atomic.Int64
	runs    atomic.Int64

	mu      sync.Mutex
	pending map[uint64]bool
}

type book struct {
	config.PlaybookConfig
	min model.Severity
}

// New 校验配置并创建引擎；没有配置剧本时返回 nil（方法对 nil 安全）。
func New(books []config.PlaybookConfig, tickets []config.TicketConfig, host Host, block BlockFunc) (*Engine, error) {
	if len(books) == 0 {
		return nil, nil
	}
	e := &Engine{tickets: map[string]*ticket{}, host: host, block: block, client: &http.Client{Timeout: 15 * time.Second}, queue: make(chan uint64, queueSize), pending: map[uint64]bool{}}
	for _, t := range tickets {
		tk := &ticket{cfg: t}
		if t.TokenEnv != "" {
			tk.token = os.Getenv(t.TokenEnv)
		}
		if t.Body != "" {
			tpl, err := template.New(t.Name).Funcs(template.FuncMap{"json": jsonValue, "join": strings.Join}).Parse(t.Body)
			if err != nil {
				return nil, fmt.Errorf("工单 %s 的请求体模板: %w", t.Name, err)
			}
			tk.tpl = tpl
		}
		e.tickets[t.Name] = tk
	}
	for _, b := range books {
		bk := book{PlaybookConfig: b}
		if b.When.MinLevel != "" {
			s, ok := model.TryParseSeverity(b.When.MinLevel)
			if !ok {
				return nil, fmt.Errorf("剧本 %s 的 min_level %q 无法识别", b.Name, b.When.MinLevel)
			}
			bk.min = s
		}
		e.books = append(e.books, bk)
	}
	return e, nil
}

// jsonValue 把值编码为 JSON，模板里的字符串都来自日志，必须转义。
func jsonValue(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// OnAlert 在产生告警时调用，不阻塞流水线。
func (e *Engine) OnAlert(a *model.Alert) {
	if e == nil || a == nil || a.IncidentID == 0 {
		return
	}
	e.mu.Lock()
	if e.pending[a.IncidentID] {
		e.mu.Unlock()
		return
	}
	e.pending[a.IncidentID] = true
	e.mu.Unlock()
	select {
	case e.queue <- a.IncidentID:
	default:
		e.mu.Lock()
		delete(e.pending, a.IncidentID)
		e.mu.Unlock()
		e.dropped.Add(1)
	}
}

// Stats 返回执行次数和因队列已满而跳过的次数。
func (e *Engine) Stats() (runs, dropped int64) {
	if e == nil {
		return 0, 0
	}
	return e.runs.Load(), e.dropped.Load()
}

// Run 处理队列。
func (e *Engine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-e.queue:
			e.mu.Lock()
			delete(e.pending, id)
			e.mu.Unlock()
			e.process(ctx, id)
		}
	}
}

func (e *Engine) process(ctx context.Context, id uint64) {
	d := e.host.Incident(id)
	if d == nil || (d.Status != store.IncOpen && d.Status != store.IncInvestigating) {
		return
	}
	for i := range e.books {
		b := &e.books[i]
		if !b.matches(d) || executed(d, b.Name) {
			continue
		}
		e.execute(ctx, b, d)
		e.runs.Add(1)
		if d = e.host.Incident(id); d == nil {
			return
		}
	}
}

func (b *book) matches(d *store.IncidentDetail) bool {
	if b.When.MinLevel != "" && d.Severity < b.min {
		return false
	}
	if b.When.Proven && d.Proven == 0 {
		return false
	}
	if b.When.AssetLevel != "" && d.AssetLevel != b.When.AssetLevel {
		return false
	}
	if len(b.When.Categories) > 0 {
		found := false
		for _, want := range b.When.Categories {
			for _, c := range d.Categories {
				found = found || c == want
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func executed(d *store.IncidentDetail, name string) bool {
	mark := doneMark + name + "」"
	for _, n := range d.Notes {
		if strings.HasPrefix(n.Action, mark) {
			return true
		}
	}
	return false
}

func (e *Engine) execute(ctx context.Context, b *book, d *store.IncidentDetail) {
	var results []string
	if b.Ticket != "" {
		if tk := e.tickets[b.Ticket]; tk != nil {
			id, err := tk.create(ctx, e.client, d)
			if err != nil {
				// 工单系统故障不影响其他动作，失败写进处置记录让分析员知道
				log.Printf("[playbook] 事件 #%d 创建工单 %s 失败: %v", d.ID, b.Ticket, err)
				results = append(results, "创建工单失败："+clip(err.Error(), 120))
			} else {
				results = append(results, "已创建工单 "+clip(id, 80))
			}
		}
	}
	if b.RequestBlock && e.block != nil {
		reason := "处置剧本「" + b.Name + "」：事件 #" + strconv.FormatUint(d.ID, 10) + " " + clip(d.Title, 200)
		if err := e.block(d.Key, reason, d.ID, actor); err != nil {
			results = append(results, "未提交封禁申请："+clip(err.Error(), 120))
		} else {
			results = append(results, "已提交封禁申请，待管理员审批")
		}
	}
	note := b.Note
	if len(results) > 0 {
		if note != "" {
			note += "\n"
		}
		note += strings.Join(results, "；")
	}
	note = strings.TrimSpace(note)
	if note == "" {
		note = "无"
	}
	if len([]rune(note)) > 1000 {
		note = string([]rune(note)[:1000])
	}
	u := store.IncidentUpdate{Note: note, Mark: doneMark + b.Name + "」"}
	if b.Assign != "" && d.Assignee == "" {
		a := b.Assign
		u.Assignee = &a
	}
	if b.Status == store.IncInvestigating && d.Status == store.IncOpen {
		u.Status = store.IncInvestigating
	}
	if _, err := e.host.UpdateIncidents([]uint64{d.ID}, actor, u); err != nil {
		log.Printf("[playbook] 事件 #%d 执行剧本 %s 失败: %v", d.ID, b.Name, err)
	}
}

func (t *ticket) create(ctx context.Context, client *http.Client, d *store.IncidentDetail) (string, error) {
	data := TicketData{ID: d.ID, Title: d.Title, Source: d.Key, Location: d.Location, Severity: d.Severity.Label(), Status: d.Status,
		Categories: d.Categories, Assets: d.Assets, Created: d.Created, Proven: d.Proven > 0}
	for _, kv := range d.Targets {
		data.Targets = append(data.Targets, kv.Name)
	}
	var body bytes.Buffer
	if t.tpl != nil {
		if err := t.tpl.Execute(&body, data); err != nil {
			return "", fmt.Errorf("生成请求体: %w", err)
		}
	} else if err := json.NewEncoder(&body).Encode(data); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.URL, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", errors.New("HTTP " + strconv.Itoa(resp.StatusCode))
	}
	field := t.cfg.IDField
	if field == "" {
		field = "id"
	}
	var parsed any
	if json.Unmarshal(raw, &parsed) != nil {
		return "（响应没有工单编号）", nil
	}
	for _, seg := range strings.Split(field, ".") {
		m, ok := parsed.(map[string]any)
		if !ok {
			return "（响应没有工单编号）", nil
		}
		parsed = m[seg]
	}
	switch v := parsed.(type) {
	case string:
		return v, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	}
	return "（响应没有工单编号）", nil
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
