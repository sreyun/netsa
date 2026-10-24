package intel

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestMatchPrefixes(t *testing.T) {
	l := parseList("演示情报", strings.NewReader(`# 注释
203.0.113.66
198.51.100.0/24   ; 行尾注释
10.8.0.0/16
2001:db8:bad::/48
192.0.2.7/32
bad-line
`))
	db := &DB{lists: []*list{l}, tor: map[netip.Addr]bool{}}
	for ip, want := range map[string]bool{
		"203.0.113.66": true, "203.0.113.67": false, "198.51.100.200": true, "198.51.101.1": false,
		"10.8.255.1": true, "10.9.0.1": false, "2001:db8:bad:1::5": true, "2001:db8:bad0::1": false,
		"::ffff:198.51.100.9": true, "192.0.2.7": true, "not-an-ip": false,
	} {
		if got := len(db.Match(ip)) > 0; got != want {
			t.Errorf("%s: 命中 %v，期望 %v", ip, got, want)
		}
	}
	if l.count != 3 || len(l.addrs) != 2 {
		t.Fatalf("网段 %d 个、IP %d 个", l.count, len(l.addrs))
	}
}

// 大型情报库（数千条网段）中查询的耗时与网段数量无关。
func BenchmarkMatchLargeList(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "%d.%d.%d.0/%d\n", 1+i%200, i/200, i%250, 16+i%9)
	}
	db := &DB{lists: []*list{parseList("大型情报", strings.NewReader(sb.String()))}, tor: map[netip.Addr]bool{}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.Match("223.5.5.5")
	}
}
