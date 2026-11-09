package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"netsa/internal/model"
)

func readable(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\x01\x03\x0e\x1d")
}

// 新记录的二进制请求按协议说明；旧快照中保存的原始字节在载入时整理，同一站点的同类探测合并为一个目标。
func TestBinaryTargetsReadable(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	probe := hit("proto-nonhttp", "协议异常", model.PhaseRecon, model.SevLow, model.ResultFailed)
	const ip = "198.51.100.80"
	for i, raw := range []string{"\x16\x03\x01\x02\x00", "\x03\x00\x00*%\xe0Cookie: mstshash=nmap", "\x00\x00\x00\x1d\xd5\xa1", "\x00\x0e8\x9d\x8b\x00"} {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", URI: raw, Status: 400, Time: now.Add(time.Duration(i) * time.Second)}, []model.Hit{probe})
	}
	s.mu.Lock()
	p := s.ips[ip]
	for k := range p.Targets {
		if !readable(k) {
			t.Fatalf("新记录的目标仍含原始字节: %q", k)
		}
	}
	if p.Targets["mg.example.com （非 HTTP 请求：二进制数据）"] != 2 || len(p.Targets) != 3 {
		t.Fatalf("同类二进制探测应合并: %v", p.Targets)
	}
	// 模拟旧版本保存的原始字节
	p.Targets["mg.example.com \x00#9b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"] = 5
	p.Targets["mg.example.com \x00\x00\x00\x1d\xd5\xa1\xc3"] = 3
	inc := s.incidents[s.incByKey[ip]]
	inc.Targets["mg.example.com <policy-file-request/>\x00"] = 1
	for _, a := range s.alerts {
		if a != nil && a.SrcIP == ip {
			a.Target = "mg.example.com \x16\x03\x01\x02"
		}
	}
	s.mu.Unlock()

	path := filepath.Join(t.TempDir(), "snap.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore()
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	s2.mu.RLock()
	defer s2.mu.RUnlock()
	p2 := s2.ips[ip]
	if p2.Targets["mg.example.com （非 HTTP 请求：DNS 查询（TCP））"] != 5 || p2.Targets["mg.example.com （非 HTTP 请求：二进制数据）"] != 5 {
		t.Fatalf("载入时应整理并合并: %v", p2.Targets)
	}
	for k := range s2.incidents[s2.incByKey[ip]].Targets {
		if !readable(k) {
			t.Fatalf("事件目标未整理: %q", k)
		}
	}
	for _, a := range s2.alerts {
		if a != nil && !readable(a.Target) {
			t.Fatalf("告警目标未整理: %q", a.Target)
		}
	}
	for _, tr := range s2.chains {
		for _, st := range tr.Steps {
			if !readable(st.Target) {
				t.Fatalf("链路步骤目标未整理: %q", st.Target)
			}
		}
	}
}
