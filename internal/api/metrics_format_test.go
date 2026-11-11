package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netsa/internal/config"
)

func TestPromWriterGroupsAndDedups(t *testing.T) {
	p := newPromWriter()
	p.metric("a_total", "counter", "A", 1, "source", "ssh")
	p.metric("b", "gauge", "B", 2)
	p.metric("a_total", "counter", "A", 3, "source", "ufw")
	p.metric("a_total", "counter", "A", 9, "source", "ssh") // 标签完全相同：只保留第一条
	p.metric("c", "gauge", "C", 1, "note", `x"y`)
	want := "# HELP a_total A\n# TYPE a_total counter\na_total{source=\"ssh\"} 1\na_total{source=\"ufw\"} 3\n" +
		"# HELP b B\n# TYPE b gauge\nb 2\n" +
		"# HELP c C\n# TYPE c gauge\n" + `c{note="x\"y"} 1` + "\n"
	if got := string(p.bytes()); got != want {
		t.Fatalf("输出:\n%s\n应为:\n%s", got, want)
	}
}

// checkExposition 检查 Prometheus 文本格式：同一指标的行连在一起、没有重复的序列。
func checkExposition(t *testing.T, body string) {
	t.Helper()
	done := map[string]bool{} // 已经结束输出的指标
	series := map[string]bool{}
	cur := ""
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		name := ""
		switch {
		case strings.HasPrefix(line, "# HELP "), strings.HasPrefix(line, "# TYPE "):
			name = strings.Fields(line)[2]
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		default:
			key := line[:strings.LastIndexByte(line, ' ')]
			if series[key] {
				t.Errorf("重复的序列: %s", key)
			}
			series[key] = true
			name = key
			if i := strings.IndexByte(key, '{'); i >= 0 {
				name = key[:i]
			}
		}
		if name != cur {
			if done[name] {
				t.Errorf("指标 %s 的行没有连在一起", name)
			}
			if cur != "" {
				done[cur] = true
			}
			cur = name
		}
	}
	if len(series) == 0 {
		t.Fatal("没有任何样本")
	}
}

// 同名同类型的数据源（默认配置里 ssh 有两个候选路径）合并为一条序列，行数相加。
func TestMetricsNoDuplicateSeries(t *testing.T) {
	s, _ := testServer(t, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	var paths []string
	for _, f := range []string{"auth.log", "secure"} {
		path := filepath.Join(dir, f)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if err := s.Ingest.StartSource(ctx, config.SourceConfig{Name: "ssh", Type: "auth", Paths: paths}); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Ingest.Stats()); n != 2 {
		t.Fatalf("两个路径应各有一条数据源状态，得到 %d", n)
	}
	body := get(s.Handler(), "/metrics").Body.String()
	checkExposition(t, body)
	if n := strings.Count(body, `netsa_source_lines_total{source="ssh",type="auth"}`); n != 1 {
		t.Fatalf("同名数据源应合并为一条序列，得到 %d 条:\n%s", n, body)
	}
}
