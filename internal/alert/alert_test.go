package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata"

	"netsa/internal/config"
	"netsa/internal/model"
)

func TestValidateStrict(t *testing.T) {
	ok := []Robot{
		{Type: "钉钉", URL: "https://oapi.dingtalk.com/robot/send?access_token=abc123", Levels: []string{"critical", "HIGH", "high"}},
		{Type: "wecom", URL: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k-123", Levels: []string{"medium"}},
		{Type: "lark", URL: "https://open.larksuite.com/open-apis/bot/v2/hook/uuid-1", Levels: []string{"high"}},
	}
	for i := range ok {
		if err := ok[i].Validate(true); err != nil {
			t.Fatalf("%+v: %v", ok[i], err)
		}
	}
	if ok[0].Type != TypeDingTalk || strings.Join(ok[0].Levels, ",") != "high,critical" || ok[0].Name != "钉钉机器人" {
		t.Fatalf("规范化错误: %+v", ok[0])
	}
	bad := []Robot{
		{Type: "dingtalk", URL: "https://evil.example.com/robot/send?access_token=x", Levels: []string{"high"}},       // 非官方地址（SSRF）
		{Type: "dingtalk", URL: "http://oapi.dingtalk.com/robot/send?access_token=x", Levels: []string{"high"}},       // 非 HTTPS
		{Type: "dingtalk", URL: "https://oapi.dingtalk.com:8443/robot/send?access_token=x", Levels: []string{"high"}}, // 指定端口
		{Type: "dingtalk", URL: "https://oapi.dingtalk.com/robot/send", Levels: []string{"high"}},                     // 缺少令牌
		{Type: "feishu", URL: "https://open.feishu.cn/open-apis/bot/v2/hook/", Levels: []string{"high"}},              // 缺少令牌
		{Type: "generic", URL: "https://example.com/hook", Levels: []string{"high"}},                                  // 通用只允许配置文件
		{Type: "wecom", URL: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k", Levels: nil},                   // 未选等级
		{Type: "wecom", URL: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k", Levels: []string{"low"}},       // 不支持的等级
		{Type: "unknown", URL: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k", Levels: []string{"high"}},    // 未知类型
	}
	for _, r := range bad {
		if err := r.Validate(true); err == nil {
			t.Errorf("应拒绝: %+v", r)
		}
	}
	// 配置文件中的机器人允许其他地址（私有化部署等）
	r := Robot{Type: "generic", URL: "http://10.0.0.5:9000/hook", Levels: []string{"high"}}
	if err := r.Validate(false); err != nil {
		t.Fatal(err)
	}
}

func TestMaskedURL(t *testing.T) {
	cases := map[string]Robot{
		"https://oapi.dingtalk.com/robot/send?access_token=abcd****wxyz":    {Type: TypeDingTalk, URL: "https://oapi.dingtalk.com/robot/send?access_token=abcdSECRETwxyz"},
		"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=1234****7890": {Type: TypeWeCom, URL: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=1234-SECRET-7890"},
		"https://open.feishu.cn/open-apis/bot/v2/hook/aaaa****zzzz":         {Type: TypeFeishu, URL: "https://open.feishu.cn/open-apis/bot/v2/hook/aaaaSECRETzzzz"},
		"http://10.0.0.5:9000/****":                                         {Type: TypeGeneric, URL: "http://10.0.0.5:9000/hook?token=SECRET"},
	}
	for want, r := range cases {
		if got := r.MaskedURL(); got != want || strings.Contains(got, "SECRET") {
			t.Errorf("MaskedURL(%s)=%s want %s", r.URL, got, want)
		}
	}
}

// 来自日志的文本由攻击者控制，不能在群消息中渲染为链接、图片或 @ 提醒。
func TestSanitizeNeutralizesMarkdown(t *testing.T) {
	evil := "/x?q=[点我领奖](https://evil.example/p)![img](http://a/b.png)<font color=red>x</font> @all **b** `c`\n#h"
	s := sanitize(evil, 500)
	for _, bad := range []string{"](", "![", "https://", "http://", "<font", "@all", "**", "`", "\n"} {
		if strings.Contains(s, bad) {
			t.Fatalf("未中和 %q: %s", bad, s)
		}
	}
	if got := sanitize(strings.Repeat("长", 300), 10); got != strings.Repeat("长", 10)+"…" {
		t.Fatalf("截断错误: %s", got)
	}
}

func TestSign(t *testing.T) {
	now := time.UnixMilli(1700000000123)
	r := &Robot{Type: TypeDingTalk, URL: "https://oapi.dingtalk.com/robot/send?access_token=t", Secret: "SECabc"}
	u, _ := url.Parse(sign(r, map[string]any{}, now))
	mac := hmac.New(sha256.New, []byte("SECabc"))
	mac.Write([]byte("1700000000123\nSECabc"))
	if u.Query().Get("timestamp") != "1700000000123" || u.Query().Get("sign") != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || u.Query().Get("access_token") != "t" {
		t.Fatalf("钉钉签名错误: %s", u)
	}
	body := map[string]any{}
	r = &Robot{Type: TypeFeishu, URL: "https://open.feishu.cn/open-apis/bot/v2/hook/x", Secret: "s3"}
	if sign(r, body, now) != r.URL {
		t.Fatal("飞书签名不应修改 URL")
	}
	mac = hmac.New(sha256.New, []byte("1700000000\ns3"))
	if body["timestamp"] != "1700000000" || body["sign"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("飞书签名错误: %v", body)
	}
}

func sampleEvent(sev model.Severity, ip string) Event {
	return Event{Kind: "alert", Severity: sev, Title: "SQL注入", Category: "SQL注入", Result: model.ResultSuccess, Phase: model.PhaseExploit,
		IP: ip, Location: "美国 纽约", Target: "www.example.com/api?id=1", Method: "GET", Status: 200, Evidence: "union select", Score: 88, Time: time.Now()}
}

func TestMessageFormats(t *testing.T) {
	b := &Batch{Events: []Event{sampleEvent(model.SevCritical, "198.51.100.7")}, BaseURL: "http://soc.local:8080/"}
	md := b.markdown(TypeDingTalk)
	for _, want := range []string{"netsa 安全告警", "【严重】SQL注入（疑似成功）", "198.51.100.7", "漏洞利用", "#ip=198.51.100.7"} {
		if !strings.Contains(md, want) {
			t.Fatalf("钉钉消息缺少 %q:\n%s", want, md)
		}
	}
	if !strings.Contains(b.markdown(TypeWeCom), `<font color="warning">`) {
		t.Fatal("企业微信应使用 warning 颜色")
	}
	card := b.body(TypeFeishu)["card"].(map[string]any)
	if card["header"].(map[string]any)["template"] != "red" {
		t.Fatalf("飞书卡片颜色错误: %v", card["header"])
	}
	// 多条合并 + 频率限制汇总
	var evs []Event
	for i := 0; i < 12; i++ {
		evs = append(evs, sampleEvent(model.SevHigh, "203.0.113.9"))
	}
	b = &Batch{Events: evs, Suppressed: map[model.Severity]int{model.SevMedium: 5}}
	if b.title() != "netsa 安全告警 17 条（高危 12 · 中危 5）" {
		t.Fatalf("标题错误: %s", b.title())
	}
	md = b.markdown(TypeDingTalk)
	if !strings.Contains(md, "…另有 2 条") || !strings.Contains(md, "另有 5 条告警因推送频率限制") {
		t.Fatalf("合并消息错误:\n%s", md)
	}
	// 企业微信内容长度限制
	long := sampleEvent(model.SevHigh, "1.1.1.1")
	long.Evidence = strings.Repeat("长", 5000)
	b = &Batch{Events: []Event{long, long, long, long, long, long, long, long, long, long}}
	if c := b.body(TypeWeCom)["markdown"].(map[string]string)["content"]; len(c) > 4096 {
		t.Fatalf("企业微信内容超长: %d", len(c))
	}
}

func TestPostChecksPlatformCode(t *testing.T) {
	var reply string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, reply) }))
	defer srv.Close()
	b := &Batch{Events: []Event{sampleEvent(model.SevHigh, "1.2.3.4")}}
	cases := []struct {
		typ, reply string
		ok, retry  bool
	}{
		{TypeDingTalk, `{"errcode":0,"errmsg":"ok"}`, true, false},
		{TypeDingTalk, `{"errcode":310000,"errmsg":"keywords not in content"}`, false, false},
		{TypeDingTalk, `{"errcode":130101,"errmsg":"send too fast"}`, false, true},
		{TypeWeCom, `{"errcode":45009,"errmsg":"api freq out of limit"}`, false, true},
		{TypeFeishu, `{"code":0,"msg":"success"}`, true, false},
		{TypeFeishu, `{"code":19021,"msg":"sign match fail"}`, false, false},
		{TypeFeishu, `{"StatusCode":0,"StatusMessage":"success"}`, true, false},
		{TypeGeneric, `whatever`, true, false},
	}
	for _, c := range cases {
		reply = c.reply
		err := post(context.Background(), srv.Client(), &Robot{Type: c.typ, URL: srv.URL + "/hook?key=SECRETKEY", Name: "x"}, b)
		var se *SendError
		if (err == nil) != c.ok || (err != nil && (!asSendError(err, &se) || se.Retry != c.retry)) {
			t.Errorf("%s %s: err=%v", c.typ, c.reply, err)
		}
	}
	// 网络错误信息中不能泄露 Webhook 令牌
	srv.Close()
	err := post(context.Background(), &http.Client{Timeout: time.Second}, &Robot{Type: TypeWeCom, URL: srv.URL + "/hook?key=SECRETKEY"}, b)
	if err == nil || strings.Contains(err.Error(), "SECRETKEY") {
		t.Fatalf("错误信息泄露令牌: %v", err)
	}
}

func asSendError(err error, se **SendError) bool {
	e, ok := err.(*SendError)
	*se = e
	return ok
}

// 端到端：等级过滤、去重、合并发送。
func TestNotifierDelivery(t *testing.T) {
	batchWait = 200 * time.Millisecond
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}))
	defer srv.Close()
	n, err := New(config.AlertConfig{Webhooks: []config.WebhookConfig{
		{Name: "only-critical", Type: "generic", URL: srv.URL, Levels: []string{"critical"}},
		{Name: "legacy", Type: "generic", URL: srv.URL, MinSeverity: "medium"},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !n.Wants(model.SevMedium) || n.Wants(model.SevLow) {
		t.Fatal("等级订阅错误")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	n.Notify("k1", sampleEvent(model.SevCritical, "1.1.1.1"))
	n.Notify("k1", sampleEvent(model.SevCritical, "1.1.1.1")) // 去重
	n.Notify("k2", sampleEvent(model.SevMedium, "2.2.2.2"))
	n.Notify("k3", sampleEvent(model.SevLow, "3.3.3.3")) // 无机器人订阅
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		c := len(got)
		mu.Unlock()
		if c >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("应发送 2 条消息（每个机器人各 1 条），实际 %d", len(got))
	}
	counts := map[int]int{}
	for _, m := range got {
		counts[len(m["events"].([]any))]++
	}
	if counts[1] != 1 || counts[2] != 1 {
		t.Fatalf("合并错误: %v", counts)
	}
	info := n.Info()
	if len(info.History) != 2 || !info.History[0].OK || info.Robots[1].Stats.Events != 2 {
		t.Fatalf("统计错误: %+v", info)
	}
}

func TestRobotPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "alert-robots.json")
	n, _ := New(config.AlertConfig{Webhooks: []config.WebhookConfig{{Name: "cfg", Type: "generic", URL: "http://10.0.0.1/h"}}}, path)
	v, err := n.Create(Robot{Name: "安全群", Type: "dingtalk", URL: "https://oapi.dingtalk.com/robot/send?access_token=tok1", Secret: "SEC1", Levels: []string{"high", "critical"}, Enabled: true})
	if err != nil || v.ID == "" || !v.HasSecret || strings.Contains(v.URL, "tok1") {
		t.Fatalf("创建失败: %+v %v", v, err)
	}
	// 编辑时地址与密钥留空表示保持不变
	if _, err := n.Update(v.ID, Robot{Name: "安全群2", Type: "dingtalk", Levels: []string{"medium"}, Enabled: true}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Update("config-1", Robot{Name: "x"}, false); err != ErrReadOnly {
		t.Fatalf("配置文件机器人应只读: %v", err)
	}
	n2, err := New(config.AlertConfig{}, path)
	if err != nil {
		t.Fatal(err)
	}
	info := n2.Info()
	if len(info.Robots) != 1 || info.Robots[0].Name != "安全群2" || !info.Robots[0].HasSecret || info.Robots[0].Levels[0] != "medium" || !n2.Wants(model.SevMedium) {
		t.Fatalf("重新加载错误: %+v", info.Robots)
	}
	if w := n2.workers[v.ID].snapshot(); w.URL != "https://oapi.dingtalk.com/robot/send?access_token=tok1" || w.Secret != "SEC1" {
		t.Fatalf("地址或密钥丢失: %+v", w)
	}
	if err := n2.Delete(v.ID); err != nil || n2.Wants(model.SevMedium) {
		t.Fatalf("删除失败: %v", err)
	}
	if n3, _ := New(config.AlertConfig{}, path); len(n3.Info().Robots) != 0 {
		t.Fatal("删除未持久化")
	}
}

// 消息中的时间按配置的时区展示：日志时间为 UTC（Z 结尾）时不能直接按 UTC 输出，否则群聊中看到的时间慢 8 小时。
func TestMessageTimeZone(t *testing.T) {
	sh, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	old := Location
	Location = sh
	defer func() { Location = old }()
	e := sampleEvent(model.SevHigh, "1.2.3.4")
	e.Time = time.Date(2026, 10, 23, 2, 0, 0, 0, time.UTC)
	md := (&Batch{Events: []Event{e}}).markdown(TypeDingTalk)
	if !strings.Contains(md, "2026-10-23 10:00:00") {
		t.Fatalf("时间未按 Asia/Shanghai 展示:\n%s", md)
	}
}
