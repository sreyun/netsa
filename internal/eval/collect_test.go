package eval

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 脱敏：内网地址一致映射、回环与云元数据地址保留；指定的域名与网段替换；口令令牌类参数、邮箱、手机号、身份证号、JWT 替换；
// 参数值本身是攻击载荷时保留，脱敏后仍能触发同样的检测。
func TestAnonymizer(t *testing.T) {
	a, err := NewAnonymizer([]string{"corp.example.org", "43.242.97.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	u := a.URI("/fetch?url=http://192.168.1.20/admin&b=http://192.168.1.20/x&c=127.0.0.1&d=169.254.169.254&e=8.8.8.8&f=43.242.97.40")
	if strings.Contains(u, "192.168.1.20") || strings.Count(u, "10.250.0.2") != 2 || !strings.Contains(u, "127.0.0.1") ||
		!strings.Contains(u, "169.254.169.254") || !strings.Contains(u, "8.8.8.8") || !strings.Contains(u, "198.51.100.1") {
		t.Fatalf("地址脱敏: %s", u)
	}
	u = a.URI("/login?user=bob&password=S3cret!x&token=abc123&next=/home")
	if strings.Contains(u, "S3cret") || strings.Contains(u, "abc123") || !strings.Contains(u, "password=REDACTED") || !strings.Contains(u, "next=/home") {
		t.Fatalf("口令与令牌: %s", u)
	}
	if u := a.URI("/login?password=' or 1=1--"); !strings.Contains(u, "or 1=1") {
		t.Fatalf("参数值是攻击载荷时应保留: %s", u)
	}
	u = a.Text("https://app.corp.example.org/u?mail=alice@corp.example.org&tel=13812345678&id=11010119900101123X&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc")
	for _, bad := range []string{"corp.example.org", "alice", "13812345678", "11010119900101123X", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(u, bad) {
			t.Fatalf("%s 应被替换: %s", bad, u)
		}
	}
	if _, err := NewAnonymizer([]string{"10.0.0.0/33"}); err == nil {
		t.Fatal("无效网段应报错")
	}
}

// 从现场日志挑选样本：攻击与正常请求都保留，同一请求形态只留几条；生成的语料按自己的期望重新评测全部符合，
// 写出后可以被 eval 读回。
func TestCollector(t *testing.T) {
	c, err := NewCollector(CollectOptions{MaxCases: 100, PerShape: 2, Hide: []string{"shop.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	add := func(method, uri string, status int, bytes int64) {
		c.Add(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.9", Host: "shop.example.org", Method: method, URI: uri, Status: status, Bytes: bytes,
			UA: "Mozilla/5.0", Time: now})
	}
	for i := range 50 {
		add("GET", "/product/"+strconv.Itoa(i)+"?ref=home", 200, 3000+int64(i)) // 同一形态：只留 2 条
	}
	add("GET", "/search?q=shoes", 200, 2500)
	add("GET", "/news?id=-1%20union%20select%201,user(),3--", 200, 2300)
	add("GET", "/view?file=../../../../etc/passwd", 404, 120)
	add("GET", "/view?file=../../../../etc/shadow", 404, 120)
	add("GET", "/view?file=../../../../etc/hosts", 404, 120)                                             // 同一规则、同一形态：只留 2 条
	c.Add(&model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.9", DstIP: "10.0.0.1", DstPort: 22}) // 不是 Web 日志
	if c.Seen != 55 {
		t.Fatalf("应读取 55 条 Web 请求: %d", c.Seen)
	}
	cases, rep, err := c.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 6 || rep.Violations != 0 { // 商品页 2 条、搜索 1 条、SQL 注入 1 条、目录穿越 2 条
		t.Fatalf("样本数 / 一致性: %d %d", len(cases), rep.Violations)
	}
	attacks := 0
	for _, cs := range cases {
		if cs.Label == "attack" {
			attacks++
			if !strings.HasPrefix(cs.Expect, "=") || cs.Group == "real" {
				t.Errorf("攻击样本应写明期望等级与规则: %+v", cs)
			}
		}
	}
	if attacks != 3 {
		t.Fatalf("攻击样本应为 3 条: %d", attacks)
	}
	var buf bytes.Buffer
	if err := WriteCorpus(&buf, cases, "test.log", c.Seen, c.Hits); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "shop.example.org") {
		t.Fatal("指定的域名应被替换")
	}
	back, err := Parse(&buf)
	if err != nil || len(back) != len(cases) {
		t.Fatalf("读回: %v %d", err, len(back))
	}
	if rep, err := Run(back); err != nil || rep.Violations != 0 {
		t.Fatalf("读回后评测应全部符合: %v %+v", err, rep)
	}
}
