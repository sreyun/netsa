package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/model"
)

func writeSnapshotFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// 更新版本写入的快照必须被拒绝，且原文件要备份，避免被下一次保存覆盖。
func TestSnapshotTooNewIsBackedUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	writeSnapshotFile(t, path, `{"version":99,"alerts":[],"profiles":{}}`)

	s := New(10, 10, 10, time.Hour)
	err := s.Load(path)
	if !errors.Is(err, ErrSnapshotTooNew) {
		t.Fatalf("应返回 ErrSnapshotTooNew: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("过新快照应被改名，而不是留在原处等待覆盖")
	}
	if _, err := os.Stat(path + ".v99.bak"); err != nil {
		t.Fatalf("应保留备份文件: %v", err)
	}
}

// 损坏（截断）的快照同样要备份后报错。
func TestSnapshotCorruptIsBackedUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writeSnapshotFile(t, path, `{"version":2,"profiles":{`)

	s := New(10, 10, 10, time.Hour)
	if err := s.Load(path); err == nil {
		t.Fatal("截断的快照应报错")
	}
	if _, err := os.Stat(path + ".corrupt.bak"); err != nil {
		t.Fatalf("损坏的快照应保留备份: %v", err)
	}
}

// v1 快照（事件只有告警计数）加载后按命中 = 告警回填，并补齐每规则告警数。
func TestSnapshotV1Migration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	writeSnapshotFile(t, path, `{
	  "version": 1,
	  "alerts": [],
	  "profiles": {},
	  "incidents": {
	    "1": {"id":1,"key":"203.0.113.9","severity":"high","status":"open","alerts":3,
	          "rules":{"fw-riskport":3},"targets":{"43.242.97.40:1433/tcp":3},
	          "categories":{"高危服务探测":3},"phases":{"recon":3},
	          "first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z",
	          "created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z","due":"2026-01-02T00:00:00Z"}
	  }
	}`)

	s := New(10, 10, 10, time.Hour)
	if err := s.Load(path); err != nil {
		t.Fatalf("v1 快照应可加载: %v", err)
	}
	d := s.Incident(1)
	if d == nil {
		t.Fatal("事件未恢复")
	}
	if d.Alerts != 3 || d.Hits != 3 || d.Muted != 0 {
		t.Fatalf("迁移后命中/告警应一致: alerts=%d hits=%d muted=%d", d.Alerts, d.Hits, d.Muted)
	}
	if len(d.Rules) != 1 || d.Rules[0].Value != 3 || d.Rules[0].Alerts != 3 {
		t.Fatalf("每规则告警数未补齐: %+v", d.Rules)
	}
}

// 新写入的快照必须带当前版本号，便于下次加载时判断兼容性。
func TestSnapshotWritesCurrentVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := New(10, 10, 10, time.Hour)
	s.Record(&model.Event{Time: time.Now(), Kind: model.KindFirewall, SrcIP: "203.0.113.9",
		DstIP: "43.242.97.40", DstPort: 1433, Proto: "tcp", Action: model.ActionAllow}, nil)
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		t.Fatal(err)
	}
	if head.Version != snapshotVersion {
		t.Fatalf("快照版本应为 %d，实际 %d", snapshotVersion, head.Version)
	}
	// 重新加载应成功
	if err := New(10, 10, 10, time.Hour).Load(path); err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
}
