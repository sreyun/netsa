package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/auth"
)

func TestTrail(t *testing.T) {
	dir := t.TempDir()
	tr, err := Open(dir, 180)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 30, 10, 0, 0, 0, time.Local)
	for i := 0; i < 6; i++ {
		tr.now = func() time.Time { return base.Add(time.Duration(i) * 24 * time.Hour) } // 跨月：8 月 2 条、9 月 4 条
		tr.AppendAudit(auth.Record{User: "admin", IP: "10.0.0.1", Action: "处置安全事件", Detail: "事件 #" + string(rune('1'+i)) + "，含“中文”", OK: true})
	}
	tr.AppendAudit(auth.Record{Time: base.Add(7 * 24 * time.Hour), User: "eve", IP: "198.51.100.7", OK: false, Reason: "密码错误"})
	if v := tr.Verify(); !v.OK || v.Entries != 7 || v.Files != 2 || v.LastSeq != 7 {
		t.Fatalf("校验: %+v", v)
	}
	if got := tr.Search(Query{Action: "login"}); len(got) != 1 || got[0].User != "eve" {
		t.Fatalf("检索登录: %+v", got)
	}
	if got := tr.Search(Query{Failed: true}); len(got) != 1 {
		t.Fatal("检索失败记录")
	}
	if got := tr.Search(Query{Search: "#3", Limit: 10}); len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("关键字: %+v", got)
	}
	// 重新打开：序号与哈希链延续，内存缓存恢复
	tr2, _ := Open(dir, 180)
	tr2.AppendAudit(auth.Record{User: "admin", Action: "导出原始日志", OK: true})
	if v := tr2.Verify(); !v.OK || v.LastSeq != 8 {
		t.Fatalf("重启后链应延续: %+v", v)
	}
	if got := tr2.Search(Query{Limit: 100}); len(got) != 8 || got[0].Seq != 8 {
		t.Fatalf("重启后检索: %d", len(got))
	}
	// 导出 CSV（防公式注入）
	tr2.AppendAudit(auth.Record{User: "=cmd|' /C calc'!A0", Action: "登记资产", OK: true})
	var buf bytes.Buffer
	if err := tr2.Export(&buf, Query{Limit: 100}, "csv", time.Local); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.HasPrefix(out, "\ufeff序号") || !strings.Contains(out, "'=cmd") || strings.Count(out, "\n") != 10 {
		t.Fatalf("导出: %q", out)
	}

	// 篡改：修改一条记录的内容
	f := filepath.Join(dir, "audit-202609.jsonl")
	b, _ := os.ReadFile(f)
	os.WriteFile(f, []byte(strings.Replace(string(b), "事件 #4", "事件 #9", 1)), 0o640)
	if v := tr2.Verify(); v.OK || !strings.Contains(strings.Join(v.Problems, ";"), "被修改") {
		t.Fatalf("应发现记录被修改: %+v", v)
	}
	os.WriteFile(f, b, 0o640)
	// 删除一条记录
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(f, []byte(strings.Join(append(lines[:1:1], lines[2:]...), "")), 0o640)
	if v := tr2.Verify(); v.OK || !strings.Contains(strings.Join(v.Problems, ";"), "缺失") {
		t.Fatalf("应发现记录被删除: %+v", v)
	}
	os.WriteFile(f, b, 0o640)

	// 留存清理：8 月文件超过留存期后删除，锚点保证校验仍然通过
	tr2.retention = 40 // 截止 9 月 15 日：8 月整月过期，9 月仍在留存期内
	tr2.now = func() time.Time { return time.Date(2026, 10, 25, 0, 0, 0, 0, time.Local) }
	tr2.mu.Lock()
	tr2.cleanupLocked()
	tr2.mu.Unlock()
	if _, err := os.Stat(filepath.Join(dir, "audit-202608.jsonl")); !os.IsNotExist(err) {
		t.Fatal("超过留存期的文件应被删除")
	}
	if v := tr2.Verify(); !v.OK || !v.Anchored || v.FirstSeq != 3 {
		t.Fatalf("清理后从锚点校验: %+v", v)
	}
	if st := tr2.Stats(); st.Entries != 9 || st.Retention != 40 {
		t.Fatalf("概况: %+v", st)
	}
}
