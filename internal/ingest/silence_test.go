package ingest

import (
	"testing"
	"time"
)

func TestCheckSilence(t *testing.T) {
	m := NewManager(1)
	m.DefaultSilence = 30 * time.Minute
	a, _ := m.add("nginx:access.log", "/var/log/nginx/access.log", "auto", "", "")
	b, _ := m.add("nginx:access.log.1", "/var/log/nginx/access.log.1", "auto", "", "")
	q, _ := m.add("quiet", "/var/log/quiet.log", "auto", "", "")
	off, _ := m.add("batch.log", "/tmp/batch.log", "auto", "", "") // 离线分析：不参与断流检测
	for _, s := range []*source{a, b} {
		s.group, s.silence = "nginx", -1
		s.setStatus("tailing", "")
	}
	q.group, q.silence = "quiet", 0 // 单独关闭
	q.setStatus("tailing", "")
	off.setStatus("reading", "")
	a.lines.Store(10)
	q.lines.Store(10)
	now := time.Now()
	if n := m.CheckSilence(now); len(n) != 0 {
		t.Fatalf("首次检查只记录基线: %+v", n)
	}
	// 通配符匹配的多个文件合并判断：轮转后的旧文件不再增长不算断流
	a.lines.Add(5)
	if n := m.CheckSilence(now.Add(time.Minute)); len(n) != 0 {
		t.Fatalf("有新日志: %+v", n)
	}
	n := m.CheckSilence(now.Add(32 * time.Minute))
	if len(n) != 1 || n[0].Kind != "silent" || n[0].Source != "nginx" || n[0].Silence != 30*time.Minute {
		t.Fatalf("断流: %+v", n)
	}
	if n := m.CheckSilence(now.Add(40 * time.Minute)); len(n) != 0 {
		t.Fatal("断流通知不应重复")
	}
	var st Stat
	for _, s := range m.Stats() {
		if s.Name == "nginx:access.log" {
			st = s
		}
	}
	if !st.Silent || st.Silence != "30 分钟" {
		t.Fatalf("状态页: %+v", st)
	}
	// 恢复，同时解析失败率过高
	a.lines.Add(200)
	a.failed.Add(150)
	n = m.CheckSilence(now.Add(41 * time.Minute))
	if len(n) != 2 || n[0].Kind != "recovered" || n[1].Kind != "parse_errors" {
		t.Fatalf("恢复与解析异常: %+v", n)
	}
	a.lines.Add(200)
	a.failed.Add(150)
	if n := m.CheckSilence(now.Add(42 * time.Minute)); len(n) != 0 {
		t.Fatalf("解析异常告警有间隔: %+v", n)
	}
}
