package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"netsa/internal/model"
)

// 机器人类型。
const (
	TypeDingTalk = "dingtalk"
	TypeWeCom    = "wecom"
	TypeFeishu   = "feishu"
	TypeGeneric  = "generic" // 通用 JSON Webhook，只能在配置文件中添加
)

// Robot 是一个告警推送机器人。
type Robot struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	URL     string    `json:"url"`
	Secret  string    `json:"secret,omitempty"` // 钉钉 / 飞书“加签”密钥
	Levels  []string  `json:"levels"`           // 推送等级，可多选：medium / high / critical
	Enabled bool      `json:"enabled"`
	Report  bool      `json:"report"` // 接收每日安全日报
	Source  string    `json:"source"` // ui：界面添加，可编辑；config：配置文件
	Created time.Time `json:"created"`
}

// LevelNames 是可选的推送等级。
var LevelNames = []string{"medium", "high", "critical"}

// NormType 统一机器人类型的别名。
func NormType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "dingtalk", "dingding", "钉钉":
		return TypeDingTalk
	case "wecom", "wechat", "weixin", "企业微信":
		return TypeWeCom
	case "feishu", "lark", "飞书":
		return TypeFeishu
	case "", "generic", "webhook":
		return TypeGeneric
	}
	return ""
}

// TypeLabel 返回类型的中文名。
func TypeLabel(t string) string {
	return map[string]string{TypeDingTalk: "钉钉", TypeWeCom: "企业微信", TypeFeishu: "飞书", TypeGeneric: "通用 Webhook"}[t]
}

// officialHosts 是界面添加机器人时允许的 Webhook 地址，防止通过界面让服务端请求任意地址（SSRF）。
// 私有化部署等其他地址可在配置文件 alert.webhooks 中配置。
var officialHosts = map[string][]string{
	TypeDingTalk: {"oapi.dingtalk.com"},
	TypeWeCom:    {"qyapi.weixin.qq.com"},
	TypeFeishu:   {"open.feishu.cn", "open.larksuite.com"},
}

// Validate 校验机器人配置；strict 为 true 时（界面添加）只允许官方机器人地址。
func (r *Robot) Validate(strict bool) error {
	r.Name = strings.TrimSpace(r.Name)
	r.URL = strings.TrimSpace(r.URL)
	r.Secret = strings.TrimSpace(r.Secret)
	r.Type = NormType(r.Type)
	if r.Type == "" {
		return errors.New("不支持的机器人类型（可选：钉钉 / 企业微信 / 飞书）")
	}
	if strict && r.Type == TypeGeneric {
		return errors.New("通用 Webhook 只能在配置文件 alert.webhooks 中添加")
	}
	if r.Name == "" {
		r.Name = TypeLabel(r.Type) + "机器人"
	}
	if utf8.RuneCountInString(r.Name) > 40 {
		return errors.New("名称不能超过 40 个字符")
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("Webhook 地址无效")
	}
	if strict {
		ok := false
		for _, h := range officialHosts[r.Type] {
			ok = ok || strings.EqualFold(u.Hostname(), h)
		}
		if !ok || u.Scheme != "https" || u.Port() != "" || u.User != nil {
			return fmt.Errorf("%s机器人的 Webhook 地址应以 https://%s 开头", TypeLabel(r.Type), officialHosts[r.Type][0])
		}
		switch r.Type {
		case TypeDingTalk:
			if u.Path != "/robot/send" || u.Query().Get("access_token") == "" {
				return errors.New("钉钉 Webhook 应形如 https://oapi.dingtalk.com/robot/send?access_token=…")
			}
		case TypeWeCom:
			if u.Path != "/cgi-bin/webhook/send" || u.Query().Get("key") == "" {
				return errors.New("企业微信 Webhook 应形如 https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…")
			}
		case TypeFeishu:
			if !strings.HasPrefix(u.Path, "/open-apis/bot/v2/hook/") || len(u.Path) <= len("/open-apis/bot/v2/hook/") {
				return errors.New("飞书 Webhook 应形如 https://open.feishu.cn/open-apis/bot/v2/hook/…")
			}
		}
	}
	if r.Secret != "" && r.Type != TypeDingTalk && r.Type != TypeFeishu {
		r.Secret = "" // 企业微信与通用 Webhook 没有加签机制
	}
	if len(r.Secret) > 256 {
		return errors.New("签名密钥过长")
	}
	seen := map[string]bool{}
	var levels []string
	for _, l := range r.Levels {
		l = strings.ToLower(strings.TrimSpace(l))
		switch l {
		case "medium", "high", "critical":
			if !seen[l] {
				seen[l] = true
				levels = append(levels, l)
			}
		default:
			return fmt.Errorf("不支持的推送等级 %q", l)
		}
	}
	if len(levels) == 0 {
		return errors.New("请至少选择一个推送等级")
	}
	// 按严重程度排序，便于展示
	var sorted []string
	for _, l := range LevelNames {
		if seen[l] {
			sorted = append(sorted, l)
		}
	}
	r.Levels = sorted
	return nil
}

// wants 判断机器人是否推送该等级。
func (r *Robot) wants(s model.Severity) bool {
	for _, l := range r.Levels {
		if model.ParseSeverity(l) == s {
			return true
		}
	}
	return false
}

// MaskedURL 返回隐藏了令牌的 Webhook 地址，用于界面展示（令牌即机器人的发送凭证）。
func (r *Robot) MaskedURL() string {
	u, err := url.Parse(r.URL)
	if err != nil {
		return ""
	}
	mask := func(s string) string {
		if len(s) <= 8 {
			return "****"
		}
		return s[:4] + "****" + s[len(s)-4:]
	}
	switch r.Type {
	case TypeDingTalk, TypeWeCom:
		q := u.Query()
		for _, k := range []string{"access_token", "key"} {
			if v := q.Get(k); v != "" {
				return u.Scheme + "://" + u.Host + u.Path + "?" + k + "=" + mask(v)
			}
		}
	case TypeFeishu:
		if i := strings.LastIndexByte(u.Path, '/'); i >= 0 {
			return u.Scheme + "://" + u.Host + u.Path[:i+1] + mask(u.Path[i+1:])
		}
	}
	return u.Scheme + "://" + u.Host + "/****"
}

// rateLimit 返回机器人每分钟的发送上限（低于各平台限制，留出余量）。
func (r *Robot) rateLimit() int {
	switch r.Type {
	case TypeDingTalk, TypeWeCom:
		return 18 // 官方限制 20 条/分钟
	case TypeFeishu:
		return 60 // 官方限制 100 条/分钟、5 条/秒
	}
	return 60
}

// ---------------- 消息内容 ----------------

// Location 是消息中时间的展示时区（配置项 timezone），由程序启动时设置。日志时间可能带着各自的时区
// （如 UTC 的 Z 结尾时间），直接格式化会与大屏、群聊所在时区相差数小时。
var Location = time.Local

func localTime(t time.Time) time.Time {
	if Location == nil {
		return t
	}
	return t.In(Location)
}

// Event 是一条待推送的安全事件。
type Event struct {
	Kind       string         `json:"kind"` // alert 告警事件 / escalation 攻击源威胁升级 / test 测试消息 / report 安全日报
	Severity   model.Severity `json:"severity"`
	Title      string         `json:"title"`
	Category   string         `json:"category,omitempty"`
	Result     string         `json:"result,omitempty"`
	Phase      string         `json:"phase,omitempty"`
	IP         string         `json:"ip,omitempty"`
	Location   string         `json:"location,omitempty"`
	Target     string         `json:"target,omitempty"`
	Method     string         `json:"method,omitempty"`
	Status     int            `json:"status,omitempty"`
	Evidence   string         `json:"evidence,omitempty"`
	Score      float64        `json:"score,omitempty"`
	Attacks    int64          `json:"attacks,omitempty"`
	Categories []string       `json:"categories,omitempty"`
	Source     string         `json:"source,omitempty"`
	Lines      []string       `json:"lines,omitempty"` // 安全日报的各行内容
	Time       time.Time      `json:"time"`
}

var resultLabel = map[string]string{
	model.ResultBlocked: "已拦截", model.ResultFailed: "失败", model.ResultError: "服务异常", model.ResultSuccess: "疑似成功",
	model.ResultPassed: "未拦截", model.ResultAllowed: "防火墙放行", model.ResultUnknown: "未知",
}

var phaseLabel = map[string]string{
	model.PhaseRecon: "侦察扫描", model.PhaseExploit: "漏洞利用", model.PhaseCredential: "凭证攻击",
	model.PhasePersistence: "后门控制", model.PhaseCollection: "数据窃取", model.PhaseImpact: "破坏影响",
}

// sanitize 处理来自日志的文本（攻击载荷、URL、UA 等均可被攻击者控制）：去除控制字符、截断，
// 并把 Markdown 元字符替换为全角字符、拆开 URL 协议头，避免在群聊中渲染出攻击者构造的链接、图片或格式。
func sanitize(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
			return -1
		}
		return r
	}, s)
	s = mdEscaper.Replace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max]) + "…"
	}
	return strings.TrimSpace(s)
}

var mdEscaper = strings.NewReplacer(
	"[", "［", "]", "］", "(", "（", ")", "）", "<", "＜", ">", "＞", "*", "＊", "_", "＿", "`", "｀",
	"#", "＃", "~", "～", "|", "｜", "!", "！", "://", "[:]//", "@", "＠",
)

func (e *Event) resultText() string {
	if l := resultLabel[e.Result]; l != "" {
		return l
	}
	return e.Result
}

func sevColor(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "#F5222D"
	case model.SevHigh:
		return "#FA541C"
	case model.SevMedium:
		return "#FAAD14"
	}
	return "#1890FF"
}

// kv 是消息中的一行“字段：值”，值已做安全处理。
type kv struct{ k, v string }

func (e *Event) fields() []kv {
	var out []kv
	add := func(k, v string) {
		if v != "" {
			out = append(out, kv{k, v})
		}
	}
	ip := sanitize(e.IP, 64)
	if e.Location != "" {
		ip += "（" + sanitize(e.Location, 60) + "）"
	}
	add("来源 IP", ip)
	switch e.Kind {
	case "escalation":
		add("攻击类型", sanitize(strings.Join(e.Categories, "、"), 120))
		add("累计攻击", strconv.FormatInt(e.Attacks, 10)+" 次")
	default:
		add("攻击类型", sanitize(e.Category, 40))
		target := sanitize(e.Target, 160)
		if e.Method != "" && target != "" {
			target = sanitize(e.Method, 10) + " " + target
		}
		if e.Status > 0 {
			target += "（响应 " + strconv.Itoa(e.Status) + "）"
		}
		add("攻击目标", target)
		add("攻击证据", sanitize(e.Evidence, 200))
		add("攻击阶段", phaseLabel[e.Phase])
		add("数据来源", sanitize(e.Source, 40))
	}
	if e.Score > 0 {
		add("威胁评分", strconv.FormatFloat(e.Score, 'f', 0, 64))
	}
	add("发生时间", localTime(e.Time).Format("2006-01-02 15:04:05"))
	return out
}

// headline 返回事件标题，例如“【严重】SQL注入攻击（疑似成功）”。
func (e *Event) headline() string {
	h := "【" + e.Severity.Label() + "】" + sanitize(e.Title, 60)
	if e.Result == model.ResultSuccess {
		h += "（疑似成功）"
	}
	return h
}

// summary 是事件的单行摘要，用于合并消息。
func (e *Event) summary() string {
	s := "【" + e.Severity.Label() + "】" + localTime(e.Time).Format("15:04:05") + " " + sanitize(e.IP, 64)
	if e.Location != "" {
		s += "（" + sanitize(e.Location, 30) + "）"
	}
	s += " " + sanitize(e.Title, 40)
	if e.Kind == "alert" {
		if e.Target != "" {
			s += " → " + sanitize(e.Target, 60)
		}
		if r := e.resultText(); r != "" {
			s += " [" + r + "]"
		}
	}
	return s
}

// Batch 是一次发送的内容：一条或多条事件，以及因频率限制未单独发送的事件统计。
type Batch struct {
	Events     []Event
	Suppressed map[model.Severity]int // 被合并 / 丢弃的事件数
	BaseURL    string
}

func (b *Batch) suppressedTotal() int {
	n := 0
	for _, v := range b.Suppressed {
		n += v
	}
	return n
}

func (b *Batch) maxSeverity() model.Severity {
	m := model.SevInfo
	for _, e := range b.Events {
		m = max(m, e.Severity)
	}
	for s, n := range b.Suppressed {
		if n > 0 {
			m = max(m, s)
		}
	}
	return m
}

func (b *Batch) detailURL() string {
	if b.BaseURL != "" && len(b.Events) == 1 && b.Events[0].Kind == "report" {
		return strings.TrimRight(b.BaseURL, "/") + "/#tab=assess"
	}
	if b.BaseURL == "" || len(b.Events) != 1 || b.Events[0].IP == "" {
		return strings.TrimRight(b.BaseURL, "/")
	}
	return strings.TrimRight(b.BaseURL, "/") + "/#ip=" + url.QueryEscape(b.Events[0].IP)
}

// title 返回消息标题。所有消息都包含“netsa”与“告警”字样，便于设置钉钉 / 飞书的自定义关键词。
func (b *Batch) title() string {
	if len(b.Events) == 1 && b.suppressedTotal() == 0 {
		if b.Events[0].Kind == "test" {
			return "netsa 告警推送测试"
		}
		if b.Events[0].Kind == "report" {
			return "netsa 安全告警日报 " + sanitize(b.Events[0].Title, 60)
		}
		return "netsa 安全告警 " + b.Events[0].headline()
	}
	counts := map[model.Severity]int{}
	for _, e := range b.Events {
		counts[e.Severity]++
	}
	for s, n := range b.Suppressed {
		counts[s] += n
	}
	total := 0
	var parts []string
	for s := model.SevCritical; s >= model.SevMedium; s-- {
		if counts[s] > 0 {
			total += counts[s]
			parts = append(parts, s.Label()+" "+strconv.Itoa(counts[s]))
		}
	}
	return fmt.Sprintf("netsa 安全告警 %d 条（%s）", total, strings.Join(parts, " · "))
}

const maxListed = 10

// markdown 生成钉钉 / 企业微信使用的 Markdown 正文。
func (b *Batch) markdown(typ string) string {
	var sb strings.Builder
	color := func(s model.Severity, text string) string {
		if typ == TypeWeCom {
			// 企业微信只支持 info（绿）/ comment（灰）/ warning（橙红）三种颜色
			if s >= model.SevHigh {
				return `<font color="warning">` + text + `</font>`
			}
			return `<font color="comment">` + text + `</font>`
		}
		return "<font color=" + sevColor(s) + ">" + text + "</font>"
	}
	if len(b.Events) == 1 && b.suppressedTotal() == 0 {
		e := b.Events[0]
		if e.Kind == "test" {
			sb.WriteString("### netsa 告警推送测试\n\n")
			sb.WriteString("机器人「" + sanitize(e.Title, 40) + "」配置正确，将推送以下等级的告警事件：" + sanitize(e.Category, 40) + "\n\n")
			sb.WriteString("> 发送时间：" + localTime(e.Time).Format("2006-01-02 15:04:05"))
			return sb.String()
		}
		if e.Kind == "report" {
			sb.WriteString("### " + b.title() + "\n\n")
			for _, l := range e.Lines {
				sb.WriteString("- " + sanitize(l, 300) + "\n")
			}
			if u := b.detailURL(); u != "" {
				sb.WriteString("\n[查看安全评估](" + u + ")")
			}
			return sb.String()
		}
		sb.WriteString("### netsa 安全告警\n\n")
		sb.WriteString("**" + color(e.Severity, e.headline()) + "**\n\n")
		for _, f := range e.fields() {
			sb.WriteString("- **" + f.k + "**：" + f.v + "\n")
		}
	} else {
		sb.WriteString("### " + b.title() + "\n\n")
		for i, e := range b.Events {
			if i == maxListed {
				sb.WriteString("- …另有 " + strconv.Itoa(len(b.Events)-maxListed) + " 条\n")
				break
			}
			line := e.summary()
			sb.WriteString("- " + color(e.Severity, line[:strings.Index(line, "】")+len("】")]) + line[strings.Index(line, "】")+len("】"):] + "\n")
		}
		if n := b.suppressedTotal(); n > 0 {
			sb.WriteString("\n> 另有 " + strconv.Itoa(n) + " 条告警因推送频率限制未逐条发送，请在大屏中查看\n")
		}
	}
	if u := b.detailURL(); u != "" {
		label := "查看态势大屏"
		if len(b.Events) == 1 && b.Events[0].IP != "" {
			label = "查看溯源详情"
		}
		sb.WriteString("\n[" + label + "](" + u + ")")
	}
	return sb.String()
}

// feishuCard 生成飞书消息卡片。
func (b *Batch) feishuCard() map[string]any {
	template := map[model.Severity]string{model.SevCritical: "red", model.SevHigh: "orange", model.SevMedium: "yellow"}[b.maxSeverity()]
	if template == "" {
		template = "blue"
	}
	var md strings.Builder
	if len(b.Events) == 1 && b.suppressedTotal() == 0 {
		e := b.Events[0]
		if e.Kind == "test" {
			md.WriteString("机器人「" + sanitize(e.Title, 40) + "」配置正确，将推送以下等级的告警事件：" + sanitize(e.Category, 40) + "\n发送时间：" + localTime(e.Time).Format("2006-01-02 15:04:05"))
			template = "green"
		} else if e.Kind == "report" {
			for _, l := range e.Lines {
				md.WriteString("• " + sanitize(l, 300) + "\n")
			}
			if e.Severity <= model.SevLow {
				template = "green"
			}
		} else {
			md.WriteString("**" + e.headline() + "**\n")
			for _, f := range e.fields() {
				md.WriteString("**" + f.k + "**：" + f.v + "\n")
			}
		}
	} else {
		for i, e := range b.Events {
			if i == maxListed {
				md.WriteString("…另有 " + strconv.Itoa(len(b.Events)-maxListed) + " 条\n")
				break
			}
			md.WriteString(e.summary() + "\n")
		}
		if n := b.suppressedTotal(); n > 0 {
			md.WriteString("另有 " + strconv.Itoa(n) + " 条告警因推送频率限制未逐条发送，请在大屏中查看\n")
		}
	}
	elements := []any{map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": strings.TrimSpace(md.String())}}}
	if u := b.detailURL(); u != "" {
		label := "查看态势大屏"
		if len(b.Events) == 1 && b.Events[0].IP != "" {
			label = "查看溯源详情"
		}
		if len(b.Events) == 1 && b.Events[0].Kind == "report" {
			label = "查看安全评估"
		}
		elements = append(elements, map[string]any{"tag": "action", "actions": []any{map[string]any{
			"tag": "button", "type": "primary", "url": u, "text": map[string]any{"tag": "plain_text", "content": label},
		}}})
	}
	return map[string]any{
		"config":   map[string]any{"wide_screen_mode": true},
		"header":   map[string]any{"template": template, "title": map[string]any{"tag": "plain_text", "content": b.title()}},
		"elements": elements,
	}
}

// body 生成各平台的请求体（未签名）。
func (b *Batch) body(typ string) map[string]any {
	switch typ {
	case TypeDingTalk:
		return map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": b.title(), "text": b.markdown(typ)}}
	case TypeWeCom:
		text := b.markdown(typ)
		if len(text) > 4000 { // 企业微信 Markdown 内容上限 4096 字节
			text = truncateBytes(text, 4000) + "…"
		}
		return map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": text}}
	case TypeFeishu:
		return map[string]any{"msg_type": "interactive", "card": b.feishuCard()}
	}
	// 通用 Webhook：原始结构化数据，便于对接 SOAR / 工单等系统
	suppressed := map[string]int{}
	for s, n := range b.Suppressed {
		suppressed[s.String()] = n
	}
	return map[string]any{"source": "netsa", "title": b.title(), "events": b.Events, "suppressed": suppressed, "url": b.detailURL()}
}

func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ---------------- 发送 ----------------

// sign 按平台要求为请求签名：钉钉在 URL 上附加 timestamp 与 sign；飞书在请求体中附加。
func sign(r *Robot, body map[string]any, now time.Time) string {
	u := r.URL
	if r.Secret == "" {
		return u
	}
	switch r.Type {
	case TypeDingTalk:
		ts := strconv.FormatInt(now.UnixMilli(), 10)
		mac := hmac.New(sha256.New, []byte(r.Secret))
		mac.Write([]byte(ts + "\n" + r.Secret))
		sep := "&"
		if !strings.Contains(u, "?") {
			sep = "?"
		}
		u += sep + "timestamp=" + ts + "&sign=" + url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	case TypeFeishu:
		ts := strconv.FormatInt(now.Unix(), 10)
		mac := hmac.New(sha256.New, []byte(ts+"\n"+r.Secret))
		body["timestamp"] = ts
		body["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	return u
}

// SendError 描述一次推送失败；Retry 表示可稍后重试（网络错误、限流、服务端错误）。
type SendError struct {
	Msg   string
	Retry bool
}

func (e *SendError) Error() string { return e.Msg }

// post 发送一批事件并按平台返回码判断是否成功（这些平台在出错时通常仍返回 HTTP 200）。
func post(ctx context.Context, client *http.Client, r *Robot, b *Batch) error {
	body := b.body(r.Type)
	target := sign(r, body, time.Now())
	data, err := json.Marshal(body)
	if err != nil {
		return &SendError{Msg: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return &SendError{Msg: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "netsa-alert/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return &SendError{Msg: "网络错误: " + scrub(err.Error(), r), Retry: true}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return &SendError{Msg: "HTTP " + strconv.Itoa(resp.StatusCode), Retry: true}
	}
	if resp.StatusCode >= 300 {
		return &SendError{Msg: "HTTP " + strconv.Itoa(resp.StatusCode) + " " + sanitize(string(raw), 120)}
	}
	if r.Type == TypeGeneric {
		return nil
	}
	var res struct {
		ErrCode    *int   `json:"errcode"` // 钉钉 / 企业微信
		ErrMsg     string `json:"errmsg"`
		Code       *int   `json:"code"` // 飞书
		Msg        string `json:"msg"`
		StatusCode *int   `json:"StatusCode"` // 飞书旧版
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return &SendError{Msg: "无法解析平台响应: " + sanitize(string(raw), 120)}
	}
	code, msg := 0, ""
	switch {
	case res.ErrCode != nil:
		code, msg = *res.ErrCode, res.ErrMsg
	case res.Code != nil:
		code, msg = *res.Code, res.Msg
	case res.StatusCode != nil:
		code = *res.StatusCode
	}
	if code == 0 {
		return nil
	}
	return &SendError{Msg: fmt.Sprintf("平台返回错误 %d: %s%s", code, sanitize(msg, 120), errHint(r.Type, code)), Retry: rateLimited(r.Type, code)}
}

// rateLimited 判断平台错误码是否为发送频率超限。
func rateLimited(typ string, code int) bool {
	switch typ {
	case TypeDingTalk:
		return code == 130101
	case TypeWeCom:
		return code == 45009
	case TypeFeishu:
		return code == 11232
	}
	return false
}

// errHint 为常见错误给出处理建议。
func errHint(typ string, code int) string {
	switch {
	case typ == TypeDingTalk && code == 310000:
		return "（安全设置校验失败：请检查加签密钥、自定义关键词需包含“告警”，或 IP 白名单）"
	case typ == TypeDingTalk && code == 300001:
		return "（access_token 无效，机器人可能已被删除）"
	case typ == TypeWeCom && code == 93000:
		return "（Webhook key 无效，机器人可能已被移出群聊）"
	case typ == TypeFeishu && code == 19021:
		return "（签名校验失败：请检查加签密钥与服务器时间）"
	case typ == TypeFeishu && code == 19024:
		return "（关键词校验失败：自定义关键词需包含“告警”或“netsa”）"
	case typ == TypeFeishu && code == 19022:
		return "（IP 不在机器人的白名单中）"
	}
	return ""
}

// scrub 从错误信息中去掉 Webhook 地址中的令牌。
func scrub(s string, r *Robot) string {
	if u, err := url.Parse(r.URL); err == nil {
		if q := u.RawQuery; q != "" {
			s = strings.ReplaceAll(s, q, "****")
		}
		if i := strings.LastIndexByte(u.Path, '/'); r.Type == TypeFeishu && i >= 0 && i+1 < len(u.Path) {
			s = strings.ReplaceAll(s, u.Path[i+1:], "****")
		}
	}
	return s
}
