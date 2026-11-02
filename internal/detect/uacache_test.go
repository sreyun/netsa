package detect

import (
	"strconv"
	"sync"
	"testing"

	"netsa/internal/model"
)

// UA 规则结果缓存：命中与证据与不缓存时完全一致；与单次请求相关的条件（方法、响应结果）仍逐次判断；
// 并发安全，条目数有上限。
func TestUACacheEquivalent(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	evs := []*model.Event{
		{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: "/", Status: 200, UA: "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"},
		{Kind: model.KindWeb, SrcIP: "198.51.100.1", Method: "GET", URI: "/?id=1%20union%20select%201", Status: 403, UA: "sqlmap/1.8#stable (https://sqlmap.org)"},
		{Kind: model.KindWeb, SrcIP: "198.51.100.2", Method: "GET", URI: "/", Status: 200, UA: "python-requests/2.32.3"},
		{Kind: model.KindWeb, SrcIP: "198.51.100.3", Method: "GET", URI: "/", Status: 200, UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0"},
		{Kind: model.KindWeb, SrcIP: "198.51.100.4", Method: "GET", URI: "/", Status: 200, UA: "Mozilla/5.0 zgrab/0.x censys"},
	}
	key := func(hits []model.Hit) string {
		s := ""
		for _, h := range hits {
			s += h.RuleID + "|" + h.Evidence + "|" + h.Severity.String() + ";"
		}
		return s
	}
	// 基准：每次都用新引擎（缓存为空）
	want := make([]string, len(evs))
	for i, ev := range evs {
		fresh, _ := NewEngine("", 1)
		want[i] = key(fresh.Inspect(ev))
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 50; round++ {
				for i, ev := range evs {
					if got := key(e.Inspect(ev)); got != want[i] {
						t.Errorf("事件 %d 缓存结果不一致:\n got %s\nwant %s", i, got, want[i])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	if want[0] == "" || want[3] != "" {
		t.Fatalf("基准结果异常: %q / %q", want[0], want[3])
	}
	// 条目数有上限：大量随机 UA 只会导致缓存换新，不会无限增长
	for i := 0; i < uaCacheMax+100; i++ {
		e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.9", Method: "GET", URI: "/", Status: 200, UA: "bot-" + strconv.Itoa(i)})
	}
	if n := e.uac.n.Load(); n > uaCacheMax {
		t.Fatalf("缓存条目应有上限: %d", n)
	}
}
