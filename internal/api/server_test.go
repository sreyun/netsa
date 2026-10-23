package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/ingest"
	"netsa/internal/model"
	"netsa/internal/pipeline"
	"netsa/internal/store"
)

func testServer(t *testing.T, user, pass string) (*Server, *store.Store) {
	t.Helper()
	cfg := config.Default()
	cfg.Server.Username, cfg.Server.Password = user, pass
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	gaz, err := geo.LoadGazetteer(os.DirFS("../../web/static"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(1000, 1000, 5, time.Hour)
	res := geo.NewResolver(geo.Options{Gazetteer: gaz})
	st.GeoLookup = res.Lookup
	pipe := &pipeline.Pipeline{Engine: eng, Store: st}
	s := &Server{Cfg: cfg, Store: st, Ingest: ingest.NewManager(1), Pipeline: pipe, Geo: res, Engine: eng,
		Static: os.DirFS("../../web/static"), Version: "test", Broker: NewBroker()}
	return s, st
}

func get(h http.Handler, path string, auth ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if len(auth) == 2 {
		req.SetBasicAuth(auth[0], auth[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthAndHealth(t *testing.T) {
	s, _ := testServer(t, "admin", "secret")
	h := s.Handler()
	if rec := get(h, "/healthz"); rec.Code != 200 {
		t.Fatalf("健康检查不应需要认证: %d", rec.Code)
	}
	if rec := get(h, "/api/overview"); rec.Code != 401 {
		t.Fatalf("未认证访问 API 应返回 401: %d", rec.Code)
	}
	if rec := get(h, "/api/overview", "admin", "wrong"); rec.Code != 401 {
		t.Fatalf("错误口令应返回 401: %d", rec.Code)
	}
	rec := get(h, "/api/overview", "admin", "secret")
	if rec.Code != 200 || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("认证后应可访问且带安全响应头: %d", rec.Code)
	}
	if rec := get(h, "/", "admin", "secret"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "网络安全态势感知平台") {
		t.Fatalf("首页: %d", rec.Code)
	}
	if rec := get(h, "/vendor/china/guangdong.json", "admin", "secret"); rec.Code != 200 {
		t.Fatalf("省级地图: %d", rec.Code)
	}
}

func TestMetaMapAndExport(t *testing.T) {
	s, st := testServer(t, "", "")
	h := s.Handler()
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.20", Method: "GET", URI: "/x", Status: 403, Time: time.Now()},
		[]model.Hit{{RuleID: "r", Name: "r", Category: "SQL注入", Severity: model.SevCritical, Phase: model.PhaseExploit, Result: model.ResultBlocked}})

	var meta map[string]any
	json.Unmarshal(get(h, "/api/meta").Body.Bytes(), &meta)
	if maps, _ := meta["china_maps"].(map[string]any); len(maps) != 34 {
		t.Fatalf("meta 中省级地图索引异常: %v", meta["china_maps"])
	}
	if rec := get(h, "/api/map"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"points"`) {
		t.Fatalf("地图接口: %d %s", rec.Code, rec.Body.String())
	}
	rec := get(h, "/api/export/blocklist?format=csv&level=high")
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(rec.Body.String(), "\xEF\xBB\xBF")))
	rows, err := r.ReadAll()
	if err != nil || len(rows) != 2 || rows[1][0] != "198.51.100.20" {
		t.Fatalf("CSV 导出异常: %v %v", err, rows)
	}
	if rec := get(h, "/api/export/blocklist?format=iptables&level=high"); !strings.Contains(rec.Body.String(), "iptables -C INPUT -s 198.51.100.20 -j DROP") {
		t.Fatalf("iptables 导出应幂等: %s", rec.Body.String())
	}
	if rec := get(h, "/api/ip/203.0.113.250"); rec.Code != 404 {
		t.Fatalf("不存在的 IP 应返回 404: %d", rec.Code)
	}
	if rec := get(h, "/api/attackers?limit=999999"); rec.Code != 200 {
		t.Fatalf("超大 limit 应被限制而非报错: %d", rec.Code)
	}
}

// 服务模式下取消 ctx 后流水线应立即退出，而不是等待输入通道关闭。
func TestPipelineStopsOnCancel(t *testing.T) {
	s, _ := testServer(t, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan []*model.Event)
	done := s.Pipeline.Run(ctx, in, 2)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消后流水线未退出")
	}
}
