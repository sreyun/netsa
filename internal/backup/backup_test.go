package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeState(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	src := t.TempDir()
	writeState(t, src, map[string]string{
		"state.json.gz": "snapshot", "users.json": "{}", "audit/2026.log": "chain", "empty.json": "",
		"rawlog/a.gz": "raw", "x.tmp": "temp", "backups/old.tar.gz": "old",
	})
	var buf bytes.Buffer
	m, err := Create(&buf, src, Options{Version: "1.7.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 4 || m.Version != "1.7.0" {
		t.Fatalf("默认不包含原始日志、临时文件和旧备份: %v", m.Files)
	}
	dst := t.TempDir()
	got, err := Restore(bytes.NewReader(buf.Bytes()), dst, false)
	if err != nil || got.Version != "1.7.0" {
		t.Fatalf("恢复: %v %+v", err, got)
	}
	for rel, want := range map[string]string{"state.json.gz": "snapshot", "audit/2026.log": "chain", "empty.json": ""} {
		b, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil || string(b) != want {
			t.Errorf("%s: %q %v", rel, b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, restoreTmp)); !os.IsNotExist(err) {
		t.Error("应清理临时目录")
	}
	// 目录不是空的：必须确认覆盖
	if _, err := Restore(bytes.NewReader(buf.Bytes()), dst, false); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("非空目录应拒绝: %v", err)
	}
	writeState(t, dst, map[string]string{"users.json": "changed", "keep.json": "keep"})
	if _, err := Restore(bytes.NewReader(buf.Bytes()), dst, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "users.json")); string(b) != "{}" {
		t.Errorf("应覆盖: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "keep.json")); string(b) != "keep" {
		t.Errorf("备份中没有的文件保持不变: %s", b)
	}
	// 包含原始日志
	buf.Reset()
	if m, err := Create(&buf, src, Options{RawLog: true}); err != nil || m.Files["rawlog/a.gz"] == "" {
		t.Fatalf("应包含原始日志: %v %v", err, m)
	}
}

func TestCreateEmptyDir(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Create(&buf, t.TempDir(), Options{}); err == nil {
		t.Fatal("空目录不应生成备份")
	}
}

// 构造任意内容的备份，用于验证恢复时的校验。
func craft(t *testing.T, entries []tar.Header, bodies []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := range entries {
		h := entries[i]
		h.Size, h.Mode = int64(len(bodies[i])), 0o600
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(bodies[i])); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestRestoreRejectsBadArchives(t *testing.T) {
	sum := "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" // foo
	manifest := func(files string) string { return `{"version":"x","files":{` + files + `}}` }
	for _, c := range []struct {
		name    string
		headers []tar.Header
		bodies  []string
	}{
		{"路径穿越", []tar.Header{{Name: "../evil"}, {Name: manifestName}}, []string{"foo", manifest(`"../evil":"` + sum + `"`)}},
		{"绝对路径", []tar.Header{{Name: "/etc/evil"}, {Name: manifestName}}, []string{"foo", manifest(`"/etc/evil":"` + sum + `"`)}},
		{"反斜杠", []tar.Header{{Name: `a\..\..\evil`}, {Name: manifestName}}, []string{"foo", manifest("")}},
		{"软链接", []tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, {Name: manifestName}}, []string{"", manifest("")}},
		{"内容被改动", []tar.Header{{Name: "a"}, {Name: manifestName}}, []string{"bar", manifest(`"a":"` + sum + `"`)}},
		{"缺少文件", []tar.Header{{Name: manifestName}}, []string{manifest(`"a":"` + sum + `"`)}},
		{"多出文件", []tar.Header{{Name: "a"}, {Name: "b"}, {Name: manifestName}}, []string{"foo", "foo", manifest(`"a":"` + sum + `"`)}},
		{"没有清单", []tar.Header{{Name: "a"}}, []string{"foo"}},
	} {
		dst := t.TempDir()
		if _, err := Restore(bytes.NewReader(craft(t, c.headers, c.bodies)), dst, false); err == nil {
			t.Errorf("%s 应被拒绝", c.name)
		}
		if entries, _ := os.ReadDir(dst); len(entries) != 0 {
			t.Errorf("%s 不应写入任何文件: %v", c.name, entries)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil")); err == nil {
			t.Fatalf("%s 写到了目录外", c.name)
		}
	}
	if _, err := Restore(strings.NewReader("not gzip"), t.TempDir(), false); err == nil {
		t.Error("非 gzip 应被拒绝")
	}
}

func TestCreateFileAndRotate(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	writeState(t, src, map[string]string{"a.json": "1"})
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		if _, err := CreateFile(filepath.Join(out, ScheduledName(base.Add(time.Duration(i)*time.Hour))), src, Options{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Rotate(out, 2); err != nil {
		t.Fatal(err)
	}
	list, _ := filepath.Glob(filepath.Join(out, "netsa-*.tar.gz"))
	if len(list) != 2 || !strings.Contains(list[1], "030000") {
		t.Fatalf("只保留最新的 2 个: %v", list)
	}
}

// 增量快照紧挨着排在它的完整快照之前读取：两次读取之间恰好完整保存时，拿到的是旧增量快照（恢复时基准对不上被忽略）
// 与新的完整快照，而不是旧的完整快照与对不上的新增量快照。
func TestBackupOrderDeltaFirst(t *testing.T) {
	src := t.TempDir()
	writeState(t, src, map[string]string{"state.json": "base", "state.json.delta": "delta", "state.json.journal": "j", "ai.json": "{}", "users.json": "{}"})
	var buf bytes.Buffer
	if _, err := Create(&buf, src, Options{}); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var order []string
	for {
		hd, err := tr.Next()
		if err != nil {
			break
		}
		order = append(order, hd.Name)
	}
	want := []string{"ai.json", "state.json.delta", "state.json", "state.json.journal", "users.json", manifestName}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("备份顺序: %v，应为 %v", order, want)
	}
}
