package detect

import (
	"strings"
	"testing"

	"netsa/internal/model"
)

// 后端响应码复核：请求没有转发到后端时载荷没有被处理；后端 5xx 被改写成 200 时为后端异常；敏感文件不受影响。
func TestUpstreamReview(t *testing.T) {
	e, _ := NewEngine("", 1)
	insp := func(uri string, up int) []model.Hit {
		return e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.example.com", Method: "GET", URI: uri, Status: 200, Bytes: 5000, UA: "Mozilla/5.0", Upstream: up})
	}
	find := func(hits []model.Hit, cat string) *model.Hit {
		for i := range hits {
			if hits[i].Category == cat {
				return &hits[i]
			}
		}
		return nil
	}
	if h := find(insp("/download?file=../../../../etc/passwd", 0), CatTraversal); h == nil || h.Result != model.ResultSuccess {
		t.Fatalf("没有记录后端状态时维持原研判: %+v", h)
	}
	if h := find(insp("/download?file=../../../../etc/passwd", -1), CatTraversal); h == nil || h.Result != model.ResultPassed || !strings.Contains(h.Evidence, "没有转发到后端") {
		t.Fatalf("没有转发到后端: %+v", h)
	}
	if h := find(insp("/download?file=../../../../etc/passwd", 502), CatTraversal); h == nil || h.Result != model.ResultError {
		t.Fatalf("后端 5xx: %+v", h)
	}
	if h := find(insp("/.env", -1), CatSensitive); h == nil || h.Result != model.ResultSuccess {
		t.Fatalf("nginx 直接返回的敏感文件正是泄露: %+v", h)
	}
}
