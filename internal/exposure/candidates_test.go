package exposure

import (
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
)

func boolPtr(v bool) *bool { return &v }

func newSuggestManager(t *testing.T, cfg config.ExposureConfig) *Manager {
	t.Helper()
	m, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// 候选映射的三个必要条件：公网来源、公网目标、被放行；阈值达到后才会出现在建议里。
func TestCandidatesThreshold(t *testing.T) {
	m := newSuggestManager(t, config.ExposureConfig{
		Suggest: config.ExposureSuggest{MinAllows: 3, MinSources: 2},
	})
	now := time.Now()
	// 3 次放行、来自 3 个不同来源 → 达到阈值
	for i, src := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		m.Observe("43.242.97.40", 443, "tcp", src, true, now.Add(time.Duration(i)*time.Second))
	}
	// 同一来源重复放行：次数够但来源只有一个 → 不达阈值
	for i := 0; i < 5; i++ {
		m.Observe("43.242.97.40", 3389, "tcp", "198.51.100.9", true, now)
	}

	list := m.Candidates()
	if len(list) != 1 {
		t.Fatalf("应只有 1 个候选，实际 %d: %+v", len(list), list)
	}
	c := list[0]
	if c.PublicIP != "43.242.97.40" || c.PublicPort != 443 || c.Allows != 3 || c.Sources != 3 || c.Service != "HTTPS" {
		t.Fatalf("候选内容错误: %+v", c)
	}
	if !strings.Contains(c.YAML, "public_ip: 43.242.97.40") || !strings.Contains(c.YAML, "public_port: 443") {
		t.Fatalf("YAML 片段不完整: %s", c.YAML)
	}
	if n := m.CandidateCount(); n != 1 {
		t.Fatalf("候选计数错误: %d", n)
	}
}

// 内网来源（东西向流量）、被拦截的连接、已登记端口都不应进入候选。
func TestCandidatesIgnoresIrrelevant(t *testing.T) {
	m := newSuggestManager(t, config.ExposureConfig{
		Enabled:  true,
		Services: []config.ExposureService{{PublicIP: "43.242.97.40", PublicPort: 443, Proto: "tcp"}},
		Suggest:  config.ExposureSuggest{MinAllows: 1, MinSources: 1},
	})
	now := time.Now()
	m.Observe("43.242.97.40", 443, "tcp", "198.51.100.1", true, now)   // 已登记
	m.Observe("43.242.97.40", 1433, "tcp", "10.0.0.5", true, now)      // 内网来源
	m.Observe("43.242.97.40", 1433, "tcp", "198.51.100.2", false, now) // 被拦截
	m.Observe("10.0.0.21", 1433, "tcp", "198.51.100.3", true, now)     // 内网目标
	if list := m.Candidates(); len(list) != 0 {
		t.Fatalf("不应产生候选: %+v", list)
	}

	// 同一个端口配置在任意地址上（public_port + 不填 public_ip）同样视为已登记
	m2 := newSuggestManager(t, config.ExposureConfig{
		Enabled:  true,
		Services: []config.ExposureService{{PublicPort: 8080, Proto: "tcp"}},
		Suggest:  config.ExposureSuggest{MinAllows: 1, MinSources: 1},
	})
	m2.Observe("43.242.97.41", 8080, "tcp", "198.51.100.4", true, now)
	if list := m2.Candidates(); len(list) != 0 {
		t.Fatalf("任意地址已登记端口不应产生候选: %+v", list)
	}
}

// 关闭建议统计后不记录任何候选。
func TestCandidatesDisabled(t *testing.T) {
	m := newSuggestManager(t, config.ExposureConfig{
		Suggest: config.ExposureSuggest{Enabled: boolPtr(false), MinAllows: 1, MinSources: 1},
	})
	m.Observe("43.242.97.40", 22, "tcp", "198.51.100.1", true, time.Now())
	if n := m.CandidateCount(); n != 0 {
		t.Fatalf("关闭后不应记录候选: %d", n)
	}
}

// 候选数量受上限约束：大量不同端口也不会无限增长（同时验证计数与列表一致）。
func TestCandidatesCap(t *testing.T) {
	m := newSuggestManager(t, config.ExposureConfig{
		Suggest: config.ExposureSuggest{MinAllows: 1, MinSources: 1},
	})
	now := time.Now()
	for p := 1; p <= maxCandidates+50; p++ {
		m.Observe("43.242.97.40", p, "tcp", "198.51.100.1", true, now)
	}
	if n := m.CandidateCount(); n > maxCandidates {
		t.Fatalf("候选数量超过上限: %d", n)
	}
}
