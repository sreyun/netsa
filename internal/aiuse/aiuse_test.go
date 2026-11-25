package aiuse

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

var testNow = time.Date(2026, 11, 20, 15, 0, 0, 0, time.FixedZone("CST", 8*3600))

func newTest(t *testing.T, opt Options) *Manager {
	t.Helper()
	if opt.Location == nil {
		opt.Location = testNow.Location()
	}
	m, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return testNow }
	return m
}

func dns(src, name string, at time.Time) *model.Event {
	return &model.Event{Kind: model.KindDNS, SrcIP: src, Host: name, QType: "A", RCode: "NOERROR", Time: at}
}

func sni(src string, sport int, dst, name string, at time.Time) *model.Event {
	return &model.Event{Kind: model.KindFirewall, Aux: true, SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: 443, SNI: name, Host: name, Time: at, Reply: model.ReplyYes}
}

func conn(src string, sport int, dst string, sent, recv int64, at time.Time) *model.Event {
	return &model.Event{Kind: model.KindFirewall, SrcIP: src, SrcPort: sport, DstIP: dst, DstPort: 443, Proto: "tcp", SentBytes: sent, RecvBytes: recv, Time: at}
}

func TestMatcher(t *testing.T) {
	m := newTest(t, Options{})
	mt := m.match.Load()
	cases := map[string]string{
		"api.openai.com":                          "openai-api",
		"chatgpt.com":                             "chatgpt",
		"ab.chatgpt.com":                          "chatgpt",
		"files.oaiusercontent.com":                "chatgpt",
		"openai.com":                              "", // 官网不算使用
		"generativelanguage.googleapis.com":       "gemini-api",
		"us-central1-aiplatform.googleapis.com":   "gemini-api",
		"storage.googleapis.com":                  "",
		"dashscope.aliyuncs.com":                  "dashscope",
		"oss-cn-shanghai.aliyuncs.com":            "",
		"bedrock-runtime.us-east-1.amazonaws.com": "bedrock",
		"s3.amazonaws.com":                        "",
		"ark.cn-beijing.volces.com":               "ark",
		"myres.openai.azure.com":                  "azure-openai",
		"chat.deepseek.com":                       "deepseek",
		"api.deepseek.com":                        "deepseek-api",
		"www.deepseek.com":                        "",
		"www.baidu.com":                           "",
		"yiyan.baidu.com":                         "yiyan",
		"copilot-proxy.githubusercontent.com":     "github-copilot",
		"raw.githubusercontent.com":               "",
		"klingai.kuaishou.com":                    "kling",
	}
	for name, want := range cases {
		if got := mt.match(name); got != want {
			t.Errorf("match(%s) = %q, want %q", name, got, want)
		}
	}
	for in, want := range map[string]string{"API.OpenAI.com.": "api.openai.com", "chatgpt.com:443": "chatgpt.com", "10.0.0.1": "10.0.0.1",
		"localhost": "", "[::1]:80": "", "fe80::1": "", "bad name.com": "", "": ""} {
		if got := normName(in); got != want {
			t.Errorf("normName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormDomain(t *testing.T) {
	for _, bad := range []string{"", "com", "google.com", "aliyuncs.com", "com.cn", "a*.com", "*.*.com", "exa mple.com", "*.com"} {
		if _, err := normDomain(bad); err == nil {
			t.Errorf("normDomain(%q) 应当报错", bad)
		}
	}
	for in, want := range map[string]string{"*.Example-GPT.com": "example-gpt.com", "llm.corp.example.": "llm.corp.example", "ark.*.volces.com": "ark.*.volces.com"} {
		if got, err := normDomain(in); err != nil || got != want {
			t.Errorf("normDomain(%q) = %q, %v", in, got, err)
		}
	}
	for _, s := range Builtin() {
		cp := s
		if err := cp.prepare(); err != nil {
			t.Errorf("内置服务 %s 无效: %v", s.ID, err)
		}
	}
}

func TestDNSUsage(t *testing.T) {
	m := newTest(t, Options{})
	at := testNow.Add(-time.Hour)
	m.Observe(dns("10.0.0.5", "api.openai.com", at))
	m.Observe(dns("10.0.0.5", "API.OPENAI.COM.", at.Add(time.Minute)))
	m.Observe(dns("10.0.0.6", "chat.deepseek.com", at))
	m.Observe(dns("203.0.113.9", "api.openai.com", at)) // 外网来源不是本单位终端
	nx := dns("10.0.0.7", "chatgpt.com", at)
	nx.RCode = "NXDOMAIN" // DNS 拦截
	m.Observe(nx)
	resp := dns("10.0.0.8", "chatgpt.com", at)
	resp.Flags = "R" // 同一次查询的响应记录
	m.Observe(resp)
	m.Observe(dns("10.0.0.5", "www.baidu.com", at))

	r := m.Report(Query{From: at, To: at})
	if r.Totals.Subjects != 2 || r.Totals.Queries != 3 || r.Totals.Denied != 1 || r.Totals.Services != 2 {
		t.Fatalf("totals = %+v", r.Totals)
	}
	if len(r.Subjects) != 3 { // 被拦截的终端也列出（Denied），但不计入使用者
		t.Fatalf("subjects = %+v", r.Subjects)
	}
	var openai *ServiceRow
	for i := range r.Services {
		if r.Services[i].ID == "openai-api" {
			openai = &r.Services[i]
		}
	}
	if openai == nil || openai.Subjects != 1 || openai.Queries != 2 || openai.Region != RegionOverseas {
		t.Fatalf("openai row = %+v", openai)
	}
	if r.Totals.OverseasSubj != 1 {
		t.Fatalf("境外服务的使用者 = %d", r.Totals.OverseasSubj)
	}
}

func TestSNIAndBytes(t *testing.T) {
	m := newTest(t, Options{})
	at := testNow.Add(-10 * time.Minute)
	m.Observe(sni("10.0.0.5", 50000, "104.18.32.47", "chatgpt.com", at))
	m.Observe(conn("10.0.0.5", 50000, "104.18.32.47", 120000, 900000, at.Add(time.Minute))) // 同一条连接（四元组）
	m.Observe(conn("10.0.0.5", 50111, "104.18.32.47", 1000, 2000, at.Add(2*time.Minute)))   // 同一终端到同一地址的另一条连接
	m.Observe(conn("10.0.0.6", 50000, "104.18.32.47", 5000, 5000, at))                      // 其他终端访问同一共享地址：不归属
	m.Observe(conn("10.0.0.5", 50000, "198.51.100.1", 5000, 5000, at))                      // 其他目的地址
	failed := sni("10.0.0.7", 40000, "104.18.32.47", "chatgpt.com", at)
	failed.Reply = model.ReplyNone // 握手没有建立（被拦截）
	m.Observe(failed)
	m.Observe(sni("10.0.0.5", 50001, "10.0.0.20", "chatgpt.com", at)) // 目的是内网地址（内网代理）：不记录

	r := m.Report(Query{From: at, To: at})
	if r.Totals.Conns != 1 || r.Totals.Denied != 1 || r.Totals.Up != 121000 || r.Totals.Down != 902000 {
		t.Fatalf("totals = %+v", r.Totals)
	}
	if !r.Coverage.SNI || !r.Coverage.Bytes {
		t.Fatalf("coverage = %+v", r.Coverage)
	}
	if r.Totals.OverseasUp != 121000 {
		t.Fatalf("境外上传 = %d", r.Totals.OverseasUp)
	}
	// 同一条连接的会话记录只归属一次：四元组已用掉，再来一条同样的记录按“终端 + 地址”归属（仍在有效期内）
	m.Observe(conn("10.0.0.5", 50000, "104.18.32.47", 10, 10, at.Add(3*time.Minute)))
	if r := m.Report(Query{From: at, To: at}); r.Totals.Up != 121010 {
		t.Fatalf("up = %d", r.Totals.Up)
	}
	// 有效期之后不再归属
	m.now = func() time.Time { return testNow.Add(2 * time.Hour) }
	m.Observe(conn("10.0.0.5", 50222, "104.18.32.47", 777, 777, at.Add(time.Hour)))
	if r := m.Report(Query{From: at, To: at}); r.Totals.Up != 121010 {
		t.Fatalf("过期后仍归属：up = %d", r.Totals.Up)
	}
}

func TestCandidates(t *testing.T) {
	m := newTest(t, Options{})
	at := testNow.Add(-time.Hour)
	for _, c := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.6"} {
		m.Observe(dns(c, "api.fast-gpt-proxy.com", at))
	}
	m.Observe(dns("10.0.0.5", "www.egypt.com", at))          // 词中间的 gpt 不算
	m.Observe(dns("10.0.0.5", "relay.openaiproxy.cn", at))   // openai 开头
	m.Observe(dns("10.0.0.5", "newtool.ai", at))             // .ai 顶级域名
	m.Observe(dns("10.0.0.5", "perplexity.ai", at))          // 目录中的服务
	m.Observe(dns("10.0.0.5", "gpt-oss.example.com.cn", at)) // 两级公共后缀
	r := m.Report(Query{From: at, To: at})
	got := map[string]Candidate{}
	for _, c := range r.Candidates {
		got[c.Domain] = c
	}
	if c := got["fast-gpt-proxy.com"]; c.Clients != 2 || c.Hits != 3 || !strings.Contains(c.Reason, "gpt") {
		t.Fatalf("fast-gpt-proxy.com = %+v", c)
	}
	for _, d := range []string{"openaiproxy.cn", "newtool.ai", "example.com.cn"} {
		if _, ok := got[d]; !ok {
			t.Errorf("缺少疑似域名 %s：%v", d, got)
		}
	}
	for _, d := range []string{"egypt.com", "perplexity.ai"} {
		if _, ok := got[d]; ok {
			t.Errorf("不应列出 %s", d)
		}
	}
	if err := m.IgnoreCandidate("newtool.ai", true); err != nil {
		t.Fatal(err)
	}
	r = m.Report(Query{From: at, To: at})
	for _, c := range r.Candidates {
		if c.Domain == "newtool.ai" {
			t.Fatal("忽略后仍列出")
		}
	}
	// 登记为服务后不再列为疑似，之后的查询计入使用
	if _, err := m.AddService(Service{Name: "某 GPT 中转站", Category: CatAPI, Region: RegionDomestic, Domains: []string{"fast-gpt-proxy.com"}, Policy: "deny"}); err != nil {
		t.Fatal(err)
	}
	m.Observe(dns("10.0.0.9", "api.fast-gpt-proxy.com", at))
	r = m.Report(Query{From: at, To: at})
	for _, c := range r.Candidates {
		if c.Domain == "fast-gpt-proxy.com" {
			t.Fatal("登记后仍列为疑似")
		}
	}
	if r.Totals.DenySubjects != 1 {
		t.Fatalf("禁止类服务的使用者 = %d", r.Totals.DenySubjects)
	}
}

func TestEndpoints(t *testing.T) {
	m := newTest(t, Options{})
	at := testNow.Add(-time.Hour)
	web := func(src, dst, host, uri string, port, status int) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: src, DstIP: dst, DstPort: port, Host: host, URI: uri, Method: "POST", Status: status, Time: at}
	}
	m.Observe(web("10.0.0.5", "10.0.0.30", "llm.corp.example:8000", "/v1/chat/completions", 8000, 200))
	m.Observe(web("10.0.0.6", "10.0.0.30", "llm.corp.example:8000", "/v1/chat/completions?x=1", 8000, 200))
	m.Observe(web("10.0.0.5", "10.0.0.31", "", "/api/generate", 11434, 200))        // Ollama 默认端口
	m.Observe(web("10.0.0.5", "10.0.0.32", "chat.corp", "/api/chat", 80, 200))      // 其他端口上的 /api/chat 很常见，不认
	m.Observe(web("198.51.100.7", "", "www.corp.example", "/v1/models", 443, 404))  // 扫描器探测，接口不存在
	m.Observe(web("198.51.100.8", "", "gw.corp.example", "/v1/messages", 443, 401)) // 需要认证：接口存在，来自外网
	r := m.Report(Query{From: at, To: at})
	got := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		got[e.Host+"|"+e.Kind] = e
	}
	if e := got["llm.corp.example:8000|openai"]; e.Clients != 2 || e.Hits != 2 || !e.Internal || e.Path != "/v1/chat/completions" {
		t.Fatalf("openai endpoint = %+v", e)
	}
	if e := got["10.0.0.31:11434|ollama"]; e.Hits != 1 || !e.Internal {
		t.Fatalf("ollama endpoint = %+v（%v）", e, got)
	}
	if e := got["gw.corp.example|anthropic"]; e.External != 1 || e.Internal {
		t.Fatalf("anthropic endpoint = %+v", e)
	}
	if len(got) != 3 {
		t.Fatalf("endpoints = %v", got)
	}
}

func TestPoliciesAndConfig(t *testing.T) {
	m := newTest(t, Options{
		Services: []Service{
			{ID: "chatgpt", Policy: "deny"}, // 覆盖内置的策略
			{Name: "内部大模型网关", Category: CatAPI, Region: RegionDomestic, Domains: []string{"llm.corp.example"}, Policy: "allow"}, // 新增
		},
		Policies: map[string]string{"deepseek": "allow"},
		Disable:  []string{"poe"},
	})
	if s, _ := m.Service("chatgpt"); s.Policy != PolicyDeny || s.PolicyFrom != SourceConfig || s.Name != "ChatGPT" || len(s.Domains) == 0 {
		t.Fatalf("chatgpt = %+v", s)
	}
	if s, _ := m.Service("deepseek"); s.Policy != PolicyAllow {
		t.Fatalf("deepseek = %+v", s)
	}
	if _, ok := m.Service("poe"); ok {
		t.Fatal("停用的服务仍在目录中")
	}
	if m.match.Load().match("llm.corp.example") == "" {
		t.Fatal("配置的服务没有生效")
	}
	if s, err := m.SetPolicy("chatgpt", "restrict"); err != nil || s.Policy != PolicyRestrict || s.PolicyFrom != SourceUI {
		t.Fatalf("SetPolicy = %+v, %v", s, err)
	}
	if s, _ := m.SetPolicy("chatgpt", ""); s.Policy != PolicyDeny || s.PolicyFrom != SourceConfig {
		t.Fatalf("清除页面设定后应恢复配置文件的策略：%+v", s)
	}
	if _, err := m.SetPolicy("chatgpt", "block"); err == nil {
		t.Fatal("无效的策略应当报错")
	}
	for _, opt := range []Options{
		{Policies: map[string]string{"nope": "deny"}},
		{Policies: map[string]string{"chatgpt": "block"}},
		{Services: []Service{{Name: "x", Domains: []string{"google.com"}}}},
		{Services: []Service{{Name: "x", Category: "bad", Domains: []string{"x.example.com"}}}},
	} {
		if _, err := New(opt); err == nil {
			t.Errorf("配置 %+v 应当报错", opt)
		}
	}
	if _, err := m.DeleteService("chatgpt"); err == nil {
		t.Fatal("内置服务不能删除")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aiuse.json.gz")
	m := newTest(t, Options{Path: path})
	at := testNow.Add(-time.Hour)
	m.Observe(sni("10.0.0.5", 50000, "104.18.32.47", "claude.ai", at))
	m.Observe(conn("10.0.0.5", 50000, "104.18.32.47", 4096, 8192, at))
	m.Observe(dns("10.0.0.6", "kimi.com", at.Add(-24*time.Hour)))
	m.Observe(dns("10.0.0.6", "my-llm-relay.com", at))
	svc, err := m.AddService(Service{Name: "自建网关", Category: CatAPI, Region: RegionDomestic, Domains: []string{"gw.corp.example"}})
	if err != nil {
		t.Fatal(err)
	}
	m.SetPolicy("claude", "deny")
	m.Observe(dns("10.0.0.7", "gw.corp.example", at))
	m.Observe(&model.Event{Kind: model.KindWeb, SrcIP: "10.0.0.5", DstIP: "10.0.0.30", Host: "llm.corp:8000", URI: "/v1/chat/completions", Status: 200, Time: at})
	before := m.Report(Query{From: at.Add(-48 * time.Hour), To: at})
	if err := m.Flush(false); err != nil { // 首次保存不受间隔限制（lastSave 为零值）
		t.Fatal(err)
	}
	m2, err := Load(Options{Path: path, Location: testNow.Location()})
	if err != nil {
		t.Fatal(err)
	}
	m2.now = m.now
	after := m2.Report(Query{From: at.Add(-48 * time.Hour), To: at})
	if before.Totals != after.Totals || len(after.Candidates) != 1 || len(after.Endpoints) != 1 {
		t.Fatalf("恢复后不一致：\n%+v\n%+v", before.Totals, after.Totals)
	}
	if s, ok := m2.Service(svc.ID); !ok || s.Name != "自建网关" {
		t.Fatalf("页面登记的服务没有恢复：%+v", s)
	}
	if s, _ := m2.Service("claude"); s.Policy != PolicyDeny {
		t.Fatalf("页面设定的策略没有恢复：%+v", s)
	}
	if !after.Coverage.Bytes || !after.Coverage.SNI {
		t.Fatalf("coverage = %+v", after.Coverage)
	}
	// 没有变化时不重复写；有变化但不足 5 分钟时不写；退出时（force）立即写
	m2.Observe(dns("10.0.0.8", "kimi.com", at))
	if err := m2.Flush(false); err != nil || !m2.dirty {
		t.Fatalf("不足 5 分钟不应保存：dirty=%v err=%v", m2.dirty, err)
	}
	if err := m2.Flush(true); err != nil || m2.dirty {
		t.Fatalf("force 应立即保存：dirty=%v err=%v", m2.dirty, err)
	}
}

func TestRetentionAndCapacity(t *testing.T) {
	m := newTest(t, Options{RetentionDays: 10, MaxRecords: 4})
	for i := 0; i < 3; i++ { // 3 天前、2 天前、1 天前各一条
		m.Observe(dns("10.0.0.5", "kimi.com", testNow.AddDate(0, 0, -3+i)))
	}
	m.Observe(dns("10.0.0.6", "kimi.com", testNow))
	if m.Records() != 4 {
		t.Fatalf("records = %d", m.Records())
	}
	m.Observe(dns("10.0.0.7", "kimi.com", testNow)) // 达到上限：淘汰最早的一天
	if m.Records() != 4 {
		t.Fatalf("records = %d", m.Records())
	}
	r := m.Report(Query{From: testNow.AddDate(0, 0, -3), To: testNow.AddDate(0, 0, -3)})
	if r.Totals.Queries != 0 {
		t.Fatal("最早一天应已淘汰")
	}
	m.Observe(dns("10.0.0.8", "kimi.com", testNow.AddDate(0, 0, -30))) // 早于保留期
	m.now = func() time.Time { return testNow.AddDate(0, 0, 9) }
	m.Prune()
	if r := m.Report(Query{From: testNow.AddDate(0, 0, -5), To: testNow}); r.Totals.Queries != 3 { // 保留 1 天前与今天的

		t.Fatalf("保留期内的记录 = %+v", r.Totals)
	}
}

func TestBriefAndDetail(t *testing.T) {
	m := newTest(t, Options{Policies: map[string]string{"chatgpt": "deny"}})
	at := testNow.Add(-time.Hour)
	if m.Brief(at, at) != nil {
		t.Fatal("没有记录时不应生成摘要")
	}
	m.Observe(dns("10.0.0.5", "chatgpt.com", at))
	m.Observe(dns("10.0.0.5", "chat.deepseek.com", at))
	m.Observe(dns("10.0.0.6", "chat.deepseek.com", at))
	b := m.Brief(at, at)
	if b == nil || b.Subjects != 2 || b.DenySubjects != 1 || len(b.DenyServices) != 1 || b.Top[0].Name != "DeepSeek" || len(b.NewServices) != 2 {
		t.Fatalf("brief = %+v", b)
	}
	r := m.Report(Query{From: at, To: at, IP: "10.0.0.5"})
	if len(r.Detail) != 2 || len(r.Subjects) != 1 || !r.Subjects[0].Deny {
		t.Fatalf("detail = %+v subjects = %+v", r.Detail, r.Subjects)
	}
	if r.Subjects[0].Services[0] == "" {
		t.Fatal("服务列表为空")
	}
}

// 补读积压、离线分析的历史日志：会话按日志时间与握手比较，不因为早于当前时间就当成过期
func TestBytesOnReplayedLogs(t *testing.T) {
	m := newTest(t, Options{})
	at := testNow.Add(-3 * time.Hour)
	m.Observe(sni("10.0.0.5", 50000, "104.18.32.47", "claude.ai", at))
	m.Observe(conn("10.0.0.5", 61000, "104.18.32.47", 3000, 9000, at.Add(40*time.Second))) // 防火墙记录的源端口不同
	late := conn("10.0.0.5", 61001, "104.18.32.47", 5, 5, at.Add(2*time.Hour))             // 握手之后两小时的另一条会话：不归属
	m.Observe(late)
	long := conn("10.0.0.5", 61002, "104.18.32.47", 70000, 1000, at.Add(2*time.Hour)) // 长连接：按时长推算开始时间，在握手附近
	long.Duration = 7200 - 60
	m.Observe(long)
	r := m.Report(Query{From: at, To: at.Add(2 * time.Hour)})
	if r.Totals.Up != 73000 || r.Totals.Down != 10000 {
		t.Fatalf("totals = %+v", r.Totals)
	}
}

func TestIPv6Subject(t *testing.T) {
	m := newTest(t, Options{})
	m.Observe(dns("FD00:0:0:0::5", "kimi.com", testNow))
	r := m.Report(Query{From: testNow, To: testNow, IP: "fd00::5"})
	if len(r.Subjects) != 1 || r.Subjects[0].IP != "fd00::5" {
		t.Fatalf("subjects = %+v", r.Subjects)
	}
}

// 补读积压时握手日志先读完：同一终端与地址的几段使用都能对上，同一地址上的两个服务按时间分开
func TestBytesWhenHandshakesReadFirst(t *testing.T) {
	m := newTest(t, Options{})
	t0 := testNow.Add(-6 * time.Hour)
	m.Observe(sni("10.0.0.5", 40000, "104.18.32.47", "chatgpt.com", t0))
	m.Observe(sni("10.0.0.5", 40001, "104.18.32.47", "chatgpt.com", t0.Add(20*time.Minute))) // 与上一段合并
	m.Observe(sni("10.0.0.5", 40002, "104.18.32.47", "api.openai.com", t0.Add(3*time.Hour))) // 同一共享地址上的另一个服务
	m.Observe(sni("10.0.0.5", 40003, "104.18.32.47", "chatgpt.com", t0.Add(5*time.Hour)))
	m.Observe(conn("10.0.0.5", 1, "104.18.32.47", 100, 0, t0.Add(10*time.Minute)))
	m.Observe(conn("10.0.0.5", 2, "104.18.32.47", 200, 0, t0.Add(45*time.Minute))) // 第一段结束后 25 分钟：仍在段内
	m.Observe(conn("10.0.0.5", 3, "104.18.32.47", 400, 0, t0.Add(3*time.Hour+time.Minute)))
	m.Observe(conn("10.0.0.5", 4, "104.18.32.47", 800, 0, t0.Add(5*time.Hour+time.Minute)))
	m.Observe(conn("10.0.0.5", 5, "104.18.32.47", 1600, 0, t0.Add(2*time.Hour))) // 不在任何一段附近：不归属
	r := m.Report(Query{From: t0, To: testNow})
	up := map[string]int64{}
	for _, s := range r.Services {
		up[s.ID] = s.Up
	}
	if up["chatgpt"] != 1100 || up["openai-api"] != 400 {
		t.Fatalf("up = %v", up)
	}
}
