package store

import (
	"path/filepath"
	"testing"
	"time"

	"netsa/internal/model"
)

func profLevel(t *testing.T, s *Store, ip string) (model.Severity, float64) {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.ips[ip]
	if p == nil {
		t.Fatalf("%s 没有画像", ip)
	}
	return p.Level, p.Score
}

func hasRule(list []KV, name string) bool {
	for _, kv := range list {
		if kv.Name == name {
			return true
		}
	}
	return false
}

// 停用的自学习观察规则被判定为误报（业务轮询）：它的命中不再抬高攻击源的评分与等级，也不进入总览排行；
// 原始命中保留，重新启用后恢复计入。
func TestExcludedRuleNotScored(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	const emp, atk = "198.51.100.50", "198.51.100.60"
	web := func(ip, uri string, i int) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "GET", URI: uri, Status: 200, Time: now.Add(time.Duration(i) * time.Second)}
	}
	learned := hit("learn-4b5c24a2", "未知攻击（自学习）", model.PhaseExploit, model.SevMedium, model.ResultUnknown)
	learned.Name = "自学习发现的攻击请求"
	for i := 0; i < 300; i++ { // 员工出口地址的轮询，被观察规则命中了几百次
		s.Record(web(emp, "/uaa/api/ht/sid", i), []model.Hit{learned})
	}
	s.Record(web(emp, "/.env", 400), []model.Hit{hit("bhv-dirscan", "目录扫描", model.PhaseRecon, model.SevLow, model.ResultUnknown)})
	s.Record(web(atk, "/uaa/api/ht/sid", 1), []model.Hit{learned})
	s.Record(web(atk, "/?id=1'+union+select", 2), []model.Hit{hit("sqli-union", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultUnknown)})

	before, _ := profLevel(t, s, emp)
	atkBefore, atkScore := profLevel(t, s, atk)
	if before != model.SevMedium || atkBefore != model.SevHigh {
		t.Fatalf("前提: 员工 %v，攻击者 %v", before, atkBefore)
	}
	if o := s.Overview(); !hasRule(o.TopRules, "自学习发现的攻击请求") {
		t.Fatalf("停用前应在高频规则中: %+v", o.TopRules)
	}

	if n := s.Retract("learn-4b5c24a2", "", "观察规则已停用"); n == 0 {
		t.Fatal("应同时修正事件")
	}
	after, score := profLevel(t, s, emp)
	if after != model.SevLow || score >= 25 {
		t.Fatalf("剔除误报命中后员工出口应只剩目录扫描（低危），实际 %v %.1f", after, score)
	}
	if lv, sc := profLevel(t, s, atk); lv != model.SevHigh || sc > atkScore {
		t.Fatalf("其他攻击源按其余命中计分: %v %.1f", lv, sc)
	}
	o := s.Overview()
	if hasRule(o.TopRules, "自学习发现的攻击请求") {
		t.Fatalf("停用的误报规则不应进入高频规则: %+v", o.TopRules)
	}
	if hasRule(o.Categories, "未知攻击（自学习）") {
		t.Fatalf("全部命中来自停用规则的攻击类型不应进入排行: %+v", o.Categories)
	}
	if o.LevelCounts["medium"] != 0 || o.LevelCounts["high"] != 1 {
		t.Fatalf("等级分布应随之更新: %+v", o.LevelCounts)
	}
	s.mu.RLock()
	raw := s.ips[emp].Rules["learn-4b5c24a2"]
	s.mu.RUnlock()
	if raw != 300 {
		t.Fatalf("原始命中应保留: %d", raw)
	}
	if s.ExcludeRule("learn-4b5c24a2", true) != 0 {
		t.Fatal("重复停用应无变化")
	}

	// 快照恢复后状态库重新收到停用通知（自学习启动时补做回溯），按快照中的规则类型剔除
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore()
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	if lv, _ := profLevel(t, s2, emp); lv != model.SevMedium {
		t.Fatalf("载入后、补做回溯前按原始命中计分: %v", lv)
	}
	s2.Retract("learn-4b5c24a2", "", "观察规则已停用")
	if lv, _ := profLevel(t, s2, emp); lv != model.SevLow {
		t.Fatalf("补做回溯后应剔除: %v", lv)
	}

	// 管理员重新启用：恢复计入
	s.Restore("learn-4b5c24a2", "", "管理员重新启用了观察规则")
	if lv, _ := profLevel(t, s, emp); lv != model.SevMedium {
		t.Fatalf("重新启用后应恢复: %v", lv)
	}
	if o := s.Overview(); !hasRule(o.TopRules, "自学习发现的攻击请求") || o.LevelCounts["medium"] != 1 {
		t.Fatalf("重新启用后排行与分布应恢复: %+v %+v", o.TopRules, o.LevelCounts)
	}
}

// 告警全部淘汰、快照里也没有记录的自学习规则：按固定的类型与阶段剔除。
func TestExcludeLearnedRuleWithoutMeta(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	learned := hit("learn-0000beef", "未知攻击（自学习）", model.PhaseExploit, model.SevMedium, model.ResultUnknown)
	for i := 0; i < 20; i++ {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.70", Host: "a.example.com", Method: "GET", URI: "/poll", Status: 200, Time: now.Add(time.Duration(i) * time.Second)}, []model.Hit{learned})
	}
	s.mu.Lock()
	delete(s.ruleMeta, "learn-0000beef")
	s.mu.Unlock()
	if s.ExcludeRule("learn-0000beef", true) != 1 {
		t.Fatal("应调整该攻击源的等级")
	}
	if lv, sc := profLevel(t, s, "198.51.100.70"); lv != model.SevInfo || sc != 0 {
		t.Fatalf("只有误报命中的来源评分应归零: %v %.1f", lv, sc)
	}
}
