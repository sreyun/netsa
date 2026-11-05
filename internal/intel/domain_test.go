package intel

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 域名情报的过滤：公共平台本身、平台基础设施、内网后缀、公共后缀、本单位域名都不生效。
func TestNormDomain(t *testing.T) {
	allow := map[string]bool{"corp-example.com": true}
	for in, want := range map[string]string{
		"Evil-C2.Example.NET.":         "evil-c2.example.net",
		"*.bad.example.org":            "bad.example.org",
		"raw.githubusercontent.com":    "", // 平台基础设施
		"github.com":                   "", // 平台本身
		"www.dropbox.com":              "",
		"attacker-page.github.io":      "attacker-page.github.io", // 平台上属于个人的子域名照常生效
		"x.y.workers.dev":              "x.y.workers.dev",
		"printer.local":                "",
		"com.cn":                       "",
		"localhost":                    "",
		"203.0.113.9":                  "",
		"bad_host!.example.com":        "",
		"mail.corp-example.com":        "", // 本单位域名
		strings.Repeat("a", 64) + ".x": "",
	} {
		if got := normDomain(in, allow); got != want {
			t.Errorf("normDomain(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 文本情报：IP、网段、域名、URL 与 hosts 文件格式混在一起时都能识别；域名按上级域名匹配。
func TestDomainFeeds(t *testing.T) {
	s := newEntrySet("混合情报", nil)
	parseText(s, []byte(strings.Join([]string{
		"# 注释",
		"203.0.113.10",
		"198.51.100.0/24",
		"evil-c2.example.net",
		"https://drop.example.org/payload.bin",
		"http://203.0.113.11:8080/x",
		"0.0.0.0 blackhole.example.com",
		"127.0.0.1 localhost",
		"github.com",
		"10.0.0.1",
	}, "\n")))
	if len(s.l.addrs) != 2 || s.l.count != 1 || len(s.l.domains) != 3 {
		t.Fatalf("addrs=%v nets=%d domains=%v", s.l.addrs, s.l.count, s.l.domains)
	}
	if s.skipped != 3 { // localhost、github.com、10.0.0.1
		t.Fatalf("丢弃 %d 条", s.skipped)
	}
	db := &DB{lists: []*list{s.l}}
	for name, want := range map[string]bool{
		"evil-c2.example.net": true, "a.b.evil-c2.example.net": true, "example.net": false,
		"DROP.example.org.": true, "blackhole.example.com": true, "example.com": false, "github.com": false, "": false,
	} {
		if got := len(db.MatchDomain(name)) > 0; got != want {
			t.Errorf("%q: 命中 %v，期望 %v", name, got, want)
		}
	}
	// STIX 与 MISP 中的域名、URL
	st := newEntrySet("x", nil)
	if err := parseSTIX(st, []byte(`{"type":"bundle","objects":[
	 {"type":"indicator","pattern":"[domain-name:value = 'c2.example.net'] OR [url:value = 'http://dl.example.org/a']"},
	 {"type":"domain-name","value":"phish.example.com"}]}`), 0, now0); err != nil {
		t.Fatal(err)
	}
	if len(st.l.domains) != 3 {
		t.Fatalf("STIX 域名: %v", st.l.domains)
	}
	ms := newEntrySet("x", nil)
	if err := parseMISP(ms, []byte(`{"response":{"Attribute":[
	 {"type":"domain","value":"c2.example.net","to_ids":true},
	 {"type":"hostname","value":"h.example.net","to_ids":true},
	 {"type":"domain|ip","value":"d.example.net|203.0.113.20","to_ids":true},
	 {"type":"url","value":"https://u.example.net/x","to_ids":true},
	 {"type":"domain","value":"skip.example.net","to_ids":false}]}}`)); err != nil {
		t.Fatal(err)
	}
	if len(ms.l.domains) != 4 || len(ms.l.addrs) != 1 {
		t.Fatalf("MISP: domains=%v addrs=%v", ms.l.domains, ms.l.addrs)
	}
}

// 缓存写入后重新读取，域名不丢失；本单位域名在加载时过滤。
func TestDomainCacheRoundTrip(t *testing.T) {
	s := newEntrySet("x", nil)
	parseText(s, []byte("evil.example.net\n203.0.113.1\nmail.own.example.com\n"))
	path := t.TempDir() + "/x.txt"
	if err := writeFeedCache(path, s.l); err != nil {
		t.Fatal(err)
	}
	db := &DB{allow: map[string]bool{"own.example.com": true}}
	l, err := readList("x", strings.NewReader(mustRead(t, path)), db.allow, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.domains["evil.example.net"]; !ok || len(l.domains) != 1 || len(l.addrs) != 1 {
		t.Fatalf("domains=%v addrs=%v", l.domains, l.addrs)
	}
}

var now0 = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func BenchmarkMatchDomainMiss(b *testing.B) {
	s := newEntrySet("大型域名情报", nil)
	for i := 0; i < 100000; i++ {
		s.addDomain("host" + strconv.Itoa(i) + ".bad-example.net")
	}
	db := &DB{lists: []*list{s.l}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.MatchDomain("img.cdn.normal-site.example.com")
	}
}
