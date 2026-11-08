package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

func incOf(t *testing.T, s *Store, ip string) *Incident {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc := s.incidents[s.incByKey[ip]]
	if inc == nil {
		t.Fatalf("%s 没有事件", ip)
	}
	c := *inc
	return &c
}

// 自学习纠错回溯：观察规则停用后，它生成的告警不再计入事件等级；全部来自该规则的事件标为误报；
// 只凭模型判断确认的来源被撤销后，因此升级过一级的告警按原等级计算。
func TestRetractCorrectsIncidents(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	web := func(ip, uri string) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "GET", URI: uri, Status: 200, Time: now}
	}
	learned := hit("learn-4b5c24a2", "未知攻击（自学习）", model.PhaseExploit, model.SevMedium, model.ResultUnknown)
	// A：观察规则的告警 + 一条低危的目录扫描
	s.Record(web("198.51.100.7", "/uaa/api/ht/sid"), []model.Hit{learned})
	s.Record(web("198.51.100.7", "/.env"), []model.Hit{hit("bhv-dirscan", "目录扫描", model.PhaseRecon, model.SevLow, model.ResultUnknown)})
	// B：只有观察规则的告警
	s.Record(web("198.51.100.8", "/uaa/api/ht/sid"), []model.Hit{learned})
	// C：因来源被自动确认为攻击源而升级过一级的告警
	esc := hit("sens-vcs", "敏感文件探测", model.PhaseRecon, model.SevMedium, model.ResultFailed)
	esc.Evidence += "；自学习：该来源已被自动确认为攻击源（模型 m 以 95% 置信度判为攻击（事件 #1）），等级上调一级"
	esc.Learned = 1
	s.Record(web("198.51.100.9", "/.git/HEAD"), []model.Hit{esc})

	a, b, c := incOf(t, s, "198.51.100.7"), incOf(t, s, "198.51.100.8"), incOf(t, s, "198.51.100.9")
	if n := s.Retract("learn-4b5c24a2", "", "观察规则已停用"); n != 2 {
		t.Fatalf("应修正 A、B 两个事件，实际 %d", n)
	}
	a2, b2 := incOf(t, s, "198.51.100.7"), incOf(t, s, "198.51.100.8")
	if a2.Severity >= a.Severity || !a2.active() || !strings.Contains(a2.Notes[len(a2.Notes)-1].Action, "自学习纠错：观察规则已停用") {
		t.Fatalf("A 的等级应按保留的告警下调: %v → %v %+v", a.Severity, a2.Severity, a2.Notes)
	}
	if b2.Status != IncFalsePositive || b2.ClosedSev != b.Severity {
		t.Fatalf("B 的告警全部撤销，应标为误报: %+v", b2)
	}
	if s.Retract("learn-4b5c24a2", "", "观察规则已停用") != 0 {
		t.Fatal("重复撤销不应再次调整")
	}
	s.mu.RLock()
	marked := 0
	for _, al := range s.alerts {
		if al != nil && al.RuleID == "learn-4b5c24a2" && al.Retracted != "" {
			marked++
		}
	}
	s.mu.RUnlock()
	if marked != 2 {
		t.Fatalf("观察规则的告警应标记为已撤销: %d", marked)
	}

	if n := s.Retract("", "198.51.100.9", "撤销了自动确认（站点常客）"); n != 1 {
		t.Fatalf("应修正 C，实际 %d", n)
	}
	if c2 := incOf(t, s, "198.51.100.9"); c2.Severity != c.Severity-1 || c2.Due.After(c.Due.Add(time.Hour*24*365)) {
		t.Fatalf("C 的升级应撤销: %v → %v", c.Severity, c2.Severity)
	}
	// 分析员确认过的升级（曾被分析员确认为攻击）不受影响
	man := hit("sens-vcs", "敏感文件探测", model.PhaseRecon, model.SevMedium, model.ResultFailed)
	man.Evidence += "；自学习：该来源曾被分析员确认为攻击（事件 #7），等级上调一级"
	man.Learned = 1
	s.Record(web("198.51.100.10", "/.git/HEAD"), []model.Hit{man})
	if s.Retract("", "198.51.100.10", "x") != 0 {
		t.Fatal("分析员确认的升级不应被自动撤销")
	}
}

// 自动归档：只有侦察 / 口令尝试、没有疑似成功、中危及以下、无人处理过、3 天没有活动的事件归档为已处置；
// 同一来源之后再出现作为新事件。
func TestAutoArchive(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	old := now.Add(-4 * 24 * time.Hour)
	ev := func(ip, uri string, at time.Time) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "GET", URI: uri, Status: 404, Time: at}
	}
	recon := hit("bhv-dirscan", "目录扫描", model.PhaseRecon, model.SevMedium, model.ResultFailed)
	s.Record(ev("198.51.100.20", "/a", old), []model.Hit{recon})                                                                               // 归档
	s.Record(ev("198.51.100.21", "/b?id=1'", old), []model.Hit{hit("sqli", "SQL注入", model.PhaseExploit, model.SevMedium, model.ResultFailed)}) // 越过了侦察
	s.Record(ev("198.51.100.22", "/c", now.Add(-time.Hour)), []model.Hit{recon})                                                               // 仍在活动
	s.Record(ev("198.51.100.23", "/d", old), []model.Hit{recon})                                                                               // 有人处理过
	s.Record(ev("198.51.100.24", "/e", old), []model.Hit{hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevHigh, model.ResultUnknown)})   // 高危
	if _, err := s.UpdateIncidents([]uint64{incOf(t, s, "198.51.100.23").ID}, "alice", IncidentUpdate{Note: "在看"}); err != nil {
		t.Fatal(err)
	}
	first := incOf(t, s, "198.51.100.20")
	list := s.AutoArchive(now, 72*time.Hour)
	if len(list) != 1 || list[0].Key != "198.51.100.20" || list[0].Status != IncResolved {
		t.Fatalf("应只归档 198.51.100.20: %+v", list)
	}
	if got := incOf(t, s, "198.51.100.20"); !strings.Contains(got.Notes[len(got.Notes)-1].Action, "自动归档") || got.Notes[len(got.Notes)-1].User != "自学习" {
		t.Fatalf("应写明归档原因: %+v", got.Notes)
	}
	if len(s.AutoArchive(now, 72*time.Hour)) != 0 {
		t.Fatal("已归档的事件不应重复归档")
	}
	s.Record(ev("198.51.100.20", "/again", now), []model.Hit{recon})
	if again := incOf(t, s, "198.51.100.20"); again.ID == first.ID || !again.active() {
		t.Fatalf("归档后再出现应作为新事件: %d → %d", first.ID, again.ID)
	}
	if s.AutoArchive(now, 0) != nil {
		t.Fatal("天数为 0 时不归档")
	}
}

// 回溯修正与读者并发：事件详情、攻击源详情返回的告警在解锁后序列化，回溯只能写副本，不能改写共享的告警对象（-race 下验证）。
func TestRetractConcurrentReaders(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := range 50 {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.70", Host: "mg.example.com", Method: "GET", URI: "/uaa/api/ht/sid?i=" + itoa(i), Status: 200, Time: now},
			[]model.Hit{hit("learn-race", "未知攻击（自学习）", model.PhaseExploit, model.SevMedium, model.ResultUnknown)})
	}
	id := incOf(t, s, "198.51.100.70").ID
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			if d := s.Incident(id); d != nil {
				if _, err := json.Marshal(d); err != nil {
					t.Error(err)
				}
			}
			if p := s.IPDetail("198.51.100.70"); p != nil {
				_, _ = json.Marshal(p)
			}
		}
	}()
	for range 3 {
		s.Retract("learn-race", "", "观察规则已停用")
	}
	<-done
	if d := s.Incident(id); d == nil || len(d.AlertList) == 0 || d.AlertList[0].Retracted == "" {
		t.Fatal("事件详情中的告警应标记为已撤销")
	}
}

// 线上实例：员工浏览器的 SockJS 实时通道（/websocket/{server}/{session}/xhr_send）一分钟 600 次被判为高危 CC，
// 事件 #355 因此一直是高危。启动时修正：这类旧告警整条撤销、事件重新定级；普通接口上的 CC 照常保留。
func TestRetractLegacyCC(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	web := func(ip, uri string) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: ip, Host: "mg.example.com", Method: "POST", URI: uri, Status: 200, Time: now}
	}
	s.Record(web("101.231.58.190", "/websocket/783/vpqq4rcl/xhr_send?t=1793873532511"), []model.Hit{hit("bhv-cc", "CC攻击", model.PhaseImpact, model.SevHigh, model.ResultUnknown)})
	s.Record(web("101.231.58.190", "/x"), []model.Hit{hit("bhv-dirscan", "目录扫描", model.PhaseRecon, model.SevMedium, model.ResultFailed)})
	s.Record(web("198.51.100.80", "/search?q=1"), []model.Hit{hit("bhv-cc", "CC攻击", model.PhaseImpact, model.SevHigh, model.ResultUnknown)})
	before := incOf(t, s, "101.231.58.190").Severity
	if n := s.RetractLegacyCC(); n != 1 {
		t.Fatalf("应只修正长连接上的旧 CC: %d", n)
	}
	if got := incOf(t, s, "101.231.58.190").Severity; got >= before {
		t.Fatalf("事件应重新定级: %v → %v", before, got)
	}
	if incOf(t, s, "198.51.100.80").Severity != model.SevHigh {
		t.Fatal("普通接口上的 CC 不应撤销")
	}
	if s.RetractLegacyCC() != 0 {
		t.Fatal("应幂等")
	}
}
