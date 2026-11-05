package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/intel"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 内网主机解析情报标记的域名：按情报类别定级，远控域名列为疑似失陷主机；解析失败的降一级；公共平台不受情报影响。
func TestDomainIntelDNS(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	db, err := intel.Load(config.IntelConfig{DomainAllowlist: []string{"own.example.com"}, Blocklists: []config.BlocklistConfig{
		{Name: "远控域名", Kind: "c2", Path: write("c2.txt", "c2.example.net\nraw.githubusercontent.com\nportal.own.example.com\n")},
		{Name: "钓鱼域名", Kind: "phishing", Path: write("ph.txt", "0.0.0.0 login-verify.example.org\n")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(1000, 1000, 100, 7*24*time.Hour)
	got := map[string]*model.Alert{}
	p := &Pipeline{Engine: eng, Store: st, Intel: db, OnAlert: func(a *model.Alert) { got[a.SrcIP] = a }}
	in := make(chan []*model.Event, 1)
	done := p.Run(context.Background(), in, 1)
	q := func(src, name, rcode string) *model.Event {
		return &model.Event{Kind: model.KindDNS, SrcIP: src, Host: name, QType: "A", RCode: rcode, Time: time.Now()}
	}
	in <- []*model.Event{
		q("10.0.0.5", "a.c2.example.net", "NOERROR"),
		q("10.0.0.6", "login-verify.example.org", "NOERROR"),
		q("10.0.0.7", "c2.example.net", "NXDOMAIN"),
		q("10.0.0.8", "raw.githubusercontent.com", "NOERROR"),
		q("10.0.0.9", "portal.own.example.com", "NOERROR"),
	}
	close(in)
	<-done
	for ip, want := range map[string]struct {
		cat string
		sev model.Severity
	}{
		"10.0.0.5": {store.CatC2, model.SevHigh},
		"10.0.0.6": {store.CatPhishing, model.SevMedium},
		"10.0.0.7": {store.CatC2, model.SevMedium},
	} {
		a := got[ip]
		if a == nil || a.RuleID != "intel-dns" || a.Category != want.cat || a.Severity != want.sev {
			t.Errorf("%s: %+v，期望 %s %s", ip, a, want.cat, want.sev)
		}
	}
	for _, ip := range []string{"10.0.0.8", "10.0.0.9"} {
		if a := got[ip]; a != nil {
			t.Errorf("%s 不应告警（公共平台 / 本单位域名）: %+v", ip, a)
		}
	}
	found := false
	for _, c := range st.CompromisedAssets() {
		found = found || c.Asset == "10.0.0.5"
	}
	if !found {
		t.Fatal("解析远控域名的主机应列为疑似失陷")
	}
	if d := st.Incident(got["10.0.0.5"].IncidentID); d == nil || strings.Join(d.Feeds, ",") != "远控域名" {
		t.Fatalf("事件应记录情报源: %+v", d)
	}
}
