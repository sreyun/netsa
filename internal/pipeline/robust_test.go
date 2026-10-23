package pipeline

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/store"
)

// 各类日志样本，作为变异的种子。
var robustSeeds = []string{
	`203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET /index.php?id=1%27%20union%20select%201,2-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"`,
	`10.0.0.2 - - [22/Oct/2026:10:15:01 +0800] "POST /login HTTP/1.1" 401 12 "https://a.com/" "Mozilla/5.0" "198.51.100.7, 10.0.0.3"`,
	`www.example.com:443 203.0.113.5 - - [22/Oct/2026:10:15:01 +0800] "GET /${jndi:ldap://x/a} HTTP/2.0" 200 5 "-" "x"`,
	`{"time_iso8601":"2026-10-22T10:15:01+08:00","remote_addr":"203.0.113.9","request":"GET /a?b=<script>alert(1)</script> HTTP/1.1","status":"404","body_bytes_sent":"10","http_user_agent":"x","host":"api.example.com","http_x_forwarded_for":"198.51.100.1"}`,
	`Oct 22 10:15:01 web01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=198.51.100.23 DST=10.0.0.10 LEN=40 PROTO=TCP SPT=54321 DPT=22`,
	`<134>Oct 22 10:15:01 filterlog[1234]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,198.51.100.25,10.0.0.1,51234,445,0,S,123,,64240,,mss`,
	`2026-10-22 10:15:01 DROP TCP 198.51.100.26 10.0.0.12 51000 3389 52 S 1234 0 64240 - - - RECEIVE`,
	`<164>Oct 22 2026 10:15:01 asa01 : %ASA-4-106023: Deny tcp src outside:198.51.100.27/51234 dst inside:10.0.0.13/23 by access-group "outside_in"`,
	`date=2026-10-22 time=10:15:01 devname="FG" srcip=198.51.100.28 srcport=5555 dstip=10.0.0.14 dstport=6379 proto=6 action="accept" attack="Apache.Log4j" severity="critical"`,
	`Oct 22 2026 10:15:01 USG6000 %%01SECIF/6/POLICYDENY(l)[0]:SourceIP=198.51.100.29, DestinationIP=10.0.0.15, SourcePort=4444, DestinationPort=1433, Protocol=TCP`,
	`{"timestamp":"2026-10-22T10:15:01Z","event_type":"alert","src_ip":"198.51.100.40","src_port":5555,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature":"ET EXPLOIT Log4j","category":"Attempted Administrator Privilege Gain","severity":1}}`,
	`10/22-10:15:01.123456  [**] [1:2010935:3] ET SCAN MSSQL [**] [Classification: Bad Traffic] [Priority: 2] {TCP} 198.51.100.41:5555 -> 10.0.0.1:1433`,
	`#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken`,
	`2026-10-22 10:15:01 10.0.0.1 GET /default.aspx id=1;exec+xp_cmdshell 443 - 203.0.113.77 Mozilla/5.0 500 0 0 15`,
	`1,2026/10/22 10:15:01,0011,THREAT,vulnerability,2049,2026/10/22 10:15:01,198.51.100.50,10.0.0.9,0.0.0.0,0.0.0.0,rule1,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,log,2026/10/22 10:15:01,1,1,51234,80,0,0,0x0,tcp,reset-both,"Apache Struts RCE(30000)",code-execution,critical`,
}

// 变异：截断、翻转字节、插入引号括号、无效 UTF-8、超长字段、重复片段。
func mutate(r *rand.Rand, s string) string {
	b := []byte(s)
	for k := 0; k < 1+r.Intn(4); k++ {
		if len(b) == 0 {
			b = append(b, '"')
		}
		i := r.Intn(len(b))
		switch r.Intn(9) {
		case 0:
			b = b[:i]
		case 1:
			b[i] = byte(r.Intn(256))
		case 2:
			c := r.Intn(8)
			b = append(b[:i], append([]byte(`"[]{}<>%`)[c:c+1], b[i:]...)...)
		case 3:
			b = append(b[:i], append([]byte{0xff, 0xfe, 0xc3}, b[i:]...)...)
		case 4:
			b = append(b[:i], append([]byte(strings.Repeat("A%25", 2000+r.Intn(4000))), b[i:]...)...)
		case 5:
			j := i + r.Intn(len(b)-i+1)
			b = append(b[:j], append(append([]byte{}, b[i:j]...), b[j:]...)...)
		case 6:
			b = append(b[:i], b[min(len(b), i+1+r.Intn(20)):]...)
		case 7:
			b = append(b[:i], append([]byte(" = , ; | : / \\ \t"), b[i:]...)...)
		case 8:
			b = append(b[:i], append([]byte("%u0027%2527&#x27;/**/"), b[i:]...)...)
		}
	}
	return string(b)
}

// 解析 → 检测 → 入库全流程对畸形输入不能 panic 或卡死（此处不经过 recover 保护，异常会直接使测试失败）。
func TestRobustAgainstMalformedLogs(t *testing.T) {
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	beh := detect.NewBehavior(cfg.Detect.Thresholds)
	st := store.New(5000, 1000, 5, time.Hour)
	rip := NewRealIP(config.RealIPConfig{TrustedProxies: []string{"10.0.0.0/8"}, Headers: []string{"x_forwarded_for", "forwarded"}})
	r := rand.New(rand.NewSource(42))
	n := 60000
	if testing.Short() {
		n = 5000
	}
	start := time.Now()
	parsed := 0
	for i := 0; i < n; i++ {
		p, _ := parser.NewAuto("auto", "")
		// 先喂一条正常样本锁定格式，再喂变异样本，覆盖“已识别格式后遇到畸形行”的路径
		seed := robustSeeds[r.Intn(len(robustSeeds))]
		p.Parse(seed)
		line := mutate(r, seed)
		if strings.HasPrefix(line, "#Fields:") {
			p.Directive(line)
		}
		ev, ok := p.Parse(line)
		if !ok {
			continue
		}
		parsed++
		hits := eng.Inspect(ev)
		if h := rip.Apply(ev); h != nil {
			hits = append(hits, *h)
		}
		hits = append(hits, beh.Observe(ev)...)
		st.Record(ev, hits)
	}
	if parsed == 0 {
		t.Fatal("变异样本应有一部分仍可解析")
	}
	// 结果查询同样不能异常
	st.Overview()
	st.MapData(model.SevLow)
	st.Surface()
	st.Attackers(store.AttackerQuery{Limit: 50})
	if d := time.Since(start); d > 60*time.Second {
		t.Fatalf("处理 %d 条畸形日志耗时 %v，可能存在性能退化（如正则回溯）", n, d)
	}
	t.Logf("%d 条变异日志，其中 %d 条仍被解析，耗时 %v", n, parsed, time.Since(start).Round(time.Millisecond))
}
