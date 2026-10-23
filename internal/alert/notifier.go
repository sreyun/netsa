// Package alert 将重要安全事件推送到 Webhook（通用 JSON / 钉钉 / 企业微信 / 飞书）。
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// Message 是一条通知。
type Message struct {
	Title    string         `json:"title"`
	Text     string         `json:"text"`
	Severity model.Severity `json:"severity"`
	IP       string         `json:"ip"`
	Location string         `json:"location"`
	Score    float64        `json:"score"`
	Time     time.Time      `json:"time"`
}

type hook struct {
	cfg config.WebhookConfig
	min model.Severity
}

// Notifier 异步发送通知，并限制发送速率（每分钟最多 20 条）。
type Notifier struct {
	hooks  []hook
	q      chan Message
	client *http.Client
}

func New(cfg config.AlertConfig) *Notifier {
	n := &Notifier{q: make(chan Message, 200), client: &http.Client{Timeout: 10 * time.Second}}
	for _, h := range cfg.Webhooks {
		if h.URL == "" {
			continue
		}
		min := model.ParseSeverity(h.MinSeverity)
		if h.MinSeverity == "" {
			min = model.SevHigh
		}
		n.hooks = append(n.hooks, hook{cfg: h, min: min})
	}
	return n
}

// Enabled 返回是否配置了 Webhook。
func (n *Notifier) Enabled() bool { return len(n.hooks) > 0 }

// Send 投递通知（队列满时丢弃）。
func (n *Notifier) Send(m Message) {
	if !n.Enabled() {
		return
	}
	select {
	case n.q <- m:
	default:
	}
}

func (n *Notifier) Run(ctx context.Context) {
	if !n.Enabled() {
		return
	}
	tokens := 20
	refill := time.NewTicker(3 * time.Second)
	defer refill.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refill.C:
			if tokens < 20 {
				tokens++
			}
		case m := <-n.q:
			if tokens <= 0 {
				continue
			}
			tokens--
			for _, h := range n.hooks {
				if m.Severity < h.min {
					continue
				}
				if err := n.post(ctx, h.cfg, m); err != nil {
					log.Printf("[alert] 推送 %s 失败: %v", h.cfg.Name, err)
				}
			}
		}
	}
}

func (n *Notifier) post(ctx context.Context, h config.WebhookConfig, m Message) error {
	md := fmt.Sprintf("### 【%s】%s\n\n- 来源IP：%s\n- 归属地：%s\n- 威胁评分：%.0f\n- 时间：%s\n\n%s",
		m.Severity.Label(), m.Title, m.IP, m.Location, m.Score, m.Time.Format("2006-01-02 15:04:05"), m.Text)
	var body any
	switch strings.ToLower(h.Type) {
	case "dingtalk":
		body = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": m.Title, "text": md}}
	case "wecom", "wechat":
		body = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": md}}
	case "feishu", "lark":
		body = map[string]any{"msg_type": "text", "content": map[string]string{"text": strings.NewReplacer("### ", "", "- ", "").Replace(md)}}
	default:
		body = m
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
