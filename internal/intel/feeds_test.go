package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"netsa/internal/config"
)

func TestEntrySetRejectsUnsafe(t *testing.T) {
	s := newEntrySet("x")
	for _, v := range []string{"0.0.0.0/0", "1.0.0.0/4", "::/0", "2001::/16", "10.0.0.1", "192.168.0.0/16", "127.0.0.1", "169.254.169.254", "224.0.0.1", "fe80::1", "fc00::/7", "not-ip", "0.0.0.0"} {
		s.add(v)
	}
	if s.size() != 0 || s.skipped != 13 {
		t.Fatalf("不安全的条目应全部丢弃: size=%d skipped=%d", s.size(), s.skipped)
	}
	for _, v := range []string{"203.0.113.9", "198.51.100.0/24", "2001:db8::1", "::ffff:203.0.113.10", "8.0.0.0/8"} {
		s.add(v)
	}
	if len(s.l.addrs) != 3 || s.l.count != 2 {
		t.Fatalf("addrs=%v nets=%d", s.l.addrs, s.l.count)
	}
}

func TestParseSTIX(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	bundle := `{"type":"bundle","objects":[
	 {"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.1']","confidence":90},
	 {"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.2'] OR [ipv6-addr:value = '2001:db8::2']"},
	 {"type":"indicator","pattern":"[ipv4-addr:value IN ('203.0.113.3', '203.0.113.4')]"},
	 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.0/24']"},
	 {"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.5']","revoked":true},
	 {"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.6']","valid_until":"2026-01-01T00:00:00Z"},
	 {"type":"indicator","pattern":"[domain-name:value = 'evil.example']"},
	 {"type":"ipv4-addr","value":"203.0.113.7"},
	 {"type":"malware","name":"x"}]}`
	s := newEntrySet("x")
	if err := parseSTIX(s, []byte(bundle), 0, now); err != nil {
		t.Fatal(err)
	}
	if len(s.l.addrs) != 6 || s.l.count != 1 {
		t.Fatalf("addrs=%v nets=%d", s.l.addrs, s.l.count)
	}
	// 最低可信度：没有声明可信度的指标也不算
	s2 := newEntrySet("x")
	parseSTIX(s2, []byte(bundle), 80, now)
	if len(s2.l.addrs) != 2 { // 203.0.113.1 与 ipv4-addr 对象
		t.Fatalf("可信度过滤: %v", s2.l.addrs)
	}
	if err := parseSTIX(newEntrySet("x"), []byte("{"), 0, now); err == nil {
		t.Fatal("无效 JSON 应报错")
	}
	if err := parseSTIX(newEntrySet("x"), []byte(`{"type":"indicator"}`), 0, now); err == nil {
		t.Fatal("不是 bundle 应报错")
	}
}

func TestParseMISP(t *testing.T) {
	s := newEntrySet("x")
	err := parseMISP(s, []byte(`{"response":{"Attribute":[
	 {"type":"ip-src","value":"203.0.113.1","to_ids":true},
	 {"type":"ip-dst|port","value":"203.0.113.2|443","to_ids":true},
	 {"type":"ip-dst","value":"203.0.113.3","to_ids":false},
	 {"type":"domain","value":"evil.example","to_ids":true},
	 {"type":"ip-src","value":"10.0.0.1","to_ids":true}]}}`))
	if err != nil || len(s.l.addrs) != 2 || s.skipped != 1 {
		t.Fatalf("addrs=%v skipped=%d err=%v", s.l.addrs, s.skipped, err)
	}
}

func waitFeed(t *testing.T, db *DB, name string, ok func(FeedStatus) bool) FeedStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range db.FeedStatuses() {
			if st.Name == name && ok(st) {
				return st
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("情报源 %s 未达到预期状态: %+v", name, db.FeedStatuses())
	return FeedStatus{}
}

// 拉取、分页、鉴权、缓存：情报服务不可用时继续使用旧数据，重启后从缓存恢复。
func TestFeedsEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var auth, accept string
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/taxii"):
			mu.Lock()
			auth, accept = r.Header.Get("Authorization"), r.Header.Get("Accept")
			mu.Unlock()
			if r.URL.Query().Get("next") == "" {
				json.NewEncoder(w).Encode(map[string]any{"more": true, "next": "p2", "objects": []map[string]any{{"type": "ipv4-addr", "value": "203.0.113.1"}}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"objects": []map[string]any{{"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.2']"}}})
		case r.URL.Path == "/attributes/restSearch":
			if r.Header.Get("Authorization") != "misp-key" || r.Method != http.MethodPost {
				w.WriteHeader(403)
				return
			}
			w.Write([]byte(`{"response":{"Attribute":[{"type":"ip-src","value":"203.0.113.3","to_ids":true}]}}`))
		case r.URL.Path == "/list.txt":
			w.Write([]byte("# 注释\n203.0.113.4 # 说明\n198.51.100.0/24\n0.0.0.0/0\n"))
		case r.URL.Path == "/bundle":
			w.Write([]byte(`{"type":"bundle","objects":[{"type":"ipv4-addr","value":"203.0.113.5"}]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("T_TAXII", "tok")
	t.Setenv("T_MISP", "misp-key")
	dir := filepath.Join(t.TempDir(), "feeds")
	cfgs := []config.IntelFeedConfig{
		{Name: "taxii", Type: "taxii", URL: srv.URL + "/taxii/collections/1/objects/", TokenEnv: "T_TAXII", Interval: 20 * time.Millisecond},
		{Name: "misp", Type: "misp", URL: srv.URL, TokenEnv: "T_MISP"},
		{Name: "text", Type: "text", URL: srv.URL + "/list.txt"},
		{Name: "stix", Type: "stix", URL: srv.URL + "/bundle"},
	}
	db, _ := Load(config.IntelConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	db.StartFeeds(ctx, cfgs, dir)
	if st := waitFeed(t, db, "taxii", func(s FeedStatus) bool { return s.Addrs == 2 }); st.LastError != "" {
		t.Fatalf("%+v", st)
	}
	waitFeed(t, db, "misp", func(s FeedStatus) bool { return s.Addrs == 1 })
	if st := waitFeed(t, db, "text", func(s FeedStatus) bool { return s.Addrs == 1 }); st.Nets != 1 || st.Skipped != 1 {
		t.Fatalf("text: %+v", st)
	}
	waitFeed(t, db, "stix", func(s FeedStatus) bool { return s.Addrs == 1 })
	mu.Lock()
	gotAuth, gotAccept := auth, accept
	mu.Unlock()
	if gotAuth != "Bearer tok" || gotAccept != taxiiAccept {
		t.Fatalf("TAXII 请求头: %q %q", gotAuth, gotAccept)
	}
	for ip, want := range map[string]string{"203.0.113.1": "taxii", "203.0.113.3": "misp", "198.51.100.9": "text", "203.0.113.5": "stix"} {
		if got := db.Match(ip); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %v，期望 %s", ip, got, want)
		}
	}
	if got := db.Match("8.8.8.8"); len(got) != 0 {
		t.Errorf("0.0.0.0/0 不能生效: %v", got)
	}
	// 服务不可用：保留旧数据并记录错误
	fail.Store(true)
	waitFeed(t, db, "taxii", func(s FeedStatus) bool { return s.LastError != "" })
	if got := db.Match("203.0.113.1"); len(got) != 1 {
		t.Fatalf("更新失败时应保留旧数据: %v", got)
	}
	cancel()
	// 重启：服务仍不可用，从缓存恢复
	db2, _ := Load(config.IntelConfig{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	db2.StartFeeds(ctx2, cfgs[:1], dir)
	if got := db2.Match("203.0.113.2"); len(got) != 1 {
		t.Fatalf("重启后应从缓存恢复: %v", got)
	}
}
