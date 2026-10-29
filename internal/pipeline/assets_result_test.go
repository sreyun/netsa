package pipeline

import (
	"context"
	"testing"
	"time"

	"netsa/internal/assets"
	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 目标确实存在被利用的 CVE 时，只有响应没有表明失败的才改判为疑似成功：
// 利用路径返回 404（文件不存在）说明利用没有生效，不能因为「目标有该漏洞」就升为严重。
func TestAssetCVEFailedNotSuccess(t *testing.T) {
	as, err := assets.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAsset(assets.Asset{Hosts: []string{"oa.example.com"}, Name: "OA", Importance: assets.LevelCore}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.ImportVulns([]assets.Vuln{{Host: "oa.example.com", CVE: []string{"CVE-2017-12615"}, Name: "Tomcat PUT 任意文件上传",
		Severity: model.SevHigh}}, []int{1}, false, "test"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		status int
		result string
		sev    model.Severity
	}{
		{404, model.ResultFailed, model.SevHigh},
		{201, model.ResultSuccess, model.SevCritical},
	} {
		eng, _ := detect.NewEngine("", 1)
		st := store.New(1000, 1000, 100, 7*24*time.Hour)
		p := &Pipeline{Engine: eng, Store: st, Assets: as}
		in := make(chan []*model.Event, 1)
		done := p.Run(context.Background(), in, 1)
		in <- []*model.Event{{Time: time.Now(), Kind: model.KindWeb, SrcIP: "203.0.113.90", Host: "oa.example.com", Method: "PUT",
			URI: "/shell.jsp/", Status: c.status, Bytes: 10}}
		close(in)
		<-done
		var got *model.Alert
		for _, a := range st.Alerts(store.AlertQuery{Limit: 10}) {
			if a.RuleID == "cve-put-upload" {
				got = a
			}
		}
		if got == nil || got.Result != c.result || got.Severity != c.sev {
			t.Fatalf("响应 %d: %+v", c.status, got)
		}
	}
}
