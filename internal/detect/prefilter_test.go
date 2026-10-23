package detect

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"

	"netsa/internal/demo"
	"netsa/internal/model"
	"netsa/internal/parser"
)

func fmtCNF(cnf [][]string) string {
	var parts []string
	for _, c := range cnf {
		c = append([]string(nil), c...)
		sort.Strings(c)
		parts = append(parts, strings.Join(c, "|"))
	}
	sort.Strings(parts)
	return strings.Join(parts, " & ")
}

func TestRequiredSubstrings(t *testing.T) {
	cases := map[string]string{
		`\bunion\s+select`: "\tselect|\nselect|\fselect|\rselect| select & union",
		`(foo|barbaz)`:     "barbaz|foo",
		`a?bc`:             "abc|bc",
		`(x|y*)z`:          "z",
		`\.(php|jsp)\?`:    ".jsp?|.php?",
		`.*`:               "",
		`(foo|.*)`:         "",
	}
	for pat, want := range cases {
		if got := fmtCNF(buildPrefilter(pat, syntax.Perl)); got != want {
			t.Errorf("%s =>\n  %q\nwant\n  %q", pat, got, want)
		}
	}
	// 引号与关键字同时作为必要条件
	got := buildPrefilter(`['"]\s*(and|or)\b`, syntax.Perl)
	if len(got) != 2 {
		t.Errorf("应同时要求引号与关键字两个子句: %q", got)
	}
}

func hitKeys(hits []model.Hit) string {
	var ks []string
	for _, h := range hits {
		ks = append(ks, h.RuleID+"|"+h.Evidence+"|"+h.Result)
	}
	sort.Strings(ks)
	return strings.Join(ks, "\n")
}

// 预过滤不得改变检测结果：在演示流量与攻击载荷语料上与逐条执行正则的结果完全一致。
func TestPrefilterEquivalence(t *testing.T) {
	fast, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := NewEngine("", 1)
	withNeed := 0
	for _, r := range ref.rules {
		if r.need != nil {
			withNeed++
		}
		r.need = nil
	}
	t.Logf("可预过滤规则 %d/%d", withNeed, len(ref.rules))
	if withNeed < len(ref.rules)*3/4 {
		t.Errorf("可预过滤的规则过少: %d/%d", withNeed, len(ref.rules))
	}

	dir := t.TempDir()
	if err := demo.Generate(dir, 1, 6, 7); err != nil {
		t.Fatal(err)
	}
	p, _ := parser.NewAuto("auto", "")
	var events []*model.Event
	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	for _, f := range files {
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if ev, ok := p.Parse(sc.Text()); ok {
				events = append(events, ev)
			}
		}
		fh.Close()
	}
	extra := []string{"/?q=%3CsCrIpT%3E", "/a?id=1%2527%2520UnIoN%2520sElEcT", "/x?f=....//....//etc/passwd", "/?${jndi:ldap://x}",
		"/cgi-bin/%2e%2e/%2e%2e/bin/sh", "/index.php?s=/index/\\think\\app/invokefunction", "/a?x={{7*7}}", "/a?u=gopher://127.0.0.1:6379/_"}
	for _, u := range extra {
		events = append(events, &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: u, Status: 200, Bytes: 10, UA: "Mozilla/5.0 () { :; }; /bin/bash"})
	}
	diff := 0
	for _, ev := range events {
		if a, b := hitKeys(fast.Inspect(ev)), hitKeys(ref.Inspect(ev)); a != b {
			diff++
			if diff <= 5 {
				t.Errorf("结果不一致 %s\n预过滤: %s\n参考: %s", ev.URI, a, b)
			}
		}
	}
	if len(events) < 1000 {
		t.Fatalf("语料过少: %d", len(events))
	}
	t.Logf("比对 %d 个事件，不一致 %d", len(events), diff)
}
