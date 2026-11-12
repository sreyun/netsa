package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"netsa/internal/backup"
	"netsa/internal/ingest"
)

// 备机同步：带令牌下载主机的状态备份并恢复到本机状态目录；令牌错误时不改动本机状态；健康检查区分主机不可用。
func TestStandbySync(t *testing.T) {
	primary := t.TempDir()
	os.WriteFile(filepath.Join(primary, "s.json.gz"), []byte("snapshot-v1"), 0o600)
	os.WriteFile(filepath.Join(primary, "users.json"), []byte(`{"users":[]}`), 0o600)
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			if down.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte(`{"status":"ok"}`))
		case "/api/admin/backup":
			if r.Header.Get("Authorization") != "Bearer good" || r.URL.Query().Get("standby") != "1" {
				http.Error(w, `{"error":"未登录"}`, http.StatusUnauthorized)
				return
			}
			backup.Create(w, primary, backup.Options{Version: "test"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	local := filepath.Join(t.TempDir(), "state")
	ctx := context.Background()
	if !standbyHealthy(ctx, srv.Client(), srv.URL) {
		t.Fatal("主机正常时健康检查应通过")
	}
	if _, err := standbySync(ctx, srv.Client(), srv.URL, "bad", local); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("令牌错误应返回主机的拒绝: %v", err)
	}
	if _, err := os.Stat(filepath.Join(local, "s.json.gz")); err == nil {
		t.Fatal("令牌错误时不应写入本机状态")
	}
	n, err := standbySync(ctx, srv.Client(), srv.URL, "good", local)
	if err != nil || n != 2 {
		t.Fatalf("同步: %d %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(local, "s.json.gz")); string(b) != "snapshot-v1" {
		t.Fatalf("应恢复主机的快照: %q", b)
	}
	// 主机状态变化后再次同步：本机随之更新，下载的临时文件不残留
	os.WriteFile(filepath.Join(primary, "s.json.gz"), []byte("snapshot-v2"), 0o600)
	if _, err := standbySync(ctx, srv.Client(), srv.URL, "good", local); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(local, "s.json.gz")); string(b) != "snapshot-v2" {
		t.Fatalf("应更新为主机的新状态: %q", b)
	}
	if _, err := os.Stat(filepath.Join(local, ".standby-download.tmp")); err == nil {
		t.Fatal("下载的临时文件应删除")
	}
	// 读取断点：主机的断点同步过来后标记为来自主机（接管后只在读同一个文件时使用）；
	// 主机没有断点文件时，删掉本机以前做主机时留下的过时断点
	stale := filepath.Join(local, ingest.CheckpointFile)
	os.WriteFile(stale, []byte(`{"/var/log/a.log":{"offset":5,"prefix_len":3,"prefix":"x"}}`), 0o600)
	if _, err := standbySync(ctx, srv.Client(), srv.URL, "good", local); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("主机没有断点文件时应删除本机过时的断点")
	}
	os.WriteFile(filepath.Join(primary, ingest.CheckpointFile), []byte(`{"/var/log/a.log":{"offset":9,"prefix_len":3,"prefix":"y"}}`), 0o600)
	if _, err := standbySync(ctx, srv.Client(), srv.URL, "good", local); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(stale); !strings.Contains(string(b), `"foreign": true`) || !strings.Contains(string(b), `"offset": 9`) {
		t.Fatalf("同步来的断点应标记为来自主机: %s", b)
	}
	down.Store(true)
	if standbyHealthy(ctx, srv.Client(), srv.URL) {
		t.Fatal("主机返回 503 时健康检查应失败")
	}
	srv.Close()
	if standbyHealthy(ctx, srv.Client(), srv.URL) {
		t.Fatal("主机不可达时健康检查应失败")
	}
}
