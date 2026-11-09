package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netsa/internal/geo"
	"netsa/internal/model"
)

func fwOut(src, dst string, port int, t time.Time) *model.Event {
	return &model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Action: model.ActionAllow, Time: t}
}

// 内部对外：只记录有攻击或异常判定的连接（外连恶意地址、对外扫描等），正常的出站访问与外部对内的攻击不记录；
// 地图按地点汇总并给出飞线终点；快照恢复后保留；在线溯源完成后更新归属地。
func TestOutboundTargets(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	c2 := hit("intel-c2", "外连威胁情报地址", model.PhasePersistence, model.SevCritical, model.ResultUnknown)
	scan := hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevMedium, model.ResultUnknown)

	res := s.Record(fwOut("10.0.0.31", "45.33.12.122", 443, now), []model.Hit{c2})
	if res.NewOutbound != "45.33.12.122" {
		t.Fatalf("新的外部目标应返回以便在线溯源: %+v", res)
	}
	if res := s.Record(fwOut("10.0.0.31", "45.33.12.122", 443, now.Add(time.Minute)), []model.Hit{c2}); res.NewOutbound != "" {
		t.Fatal("已记录的目标不再重复溯源")
	}
	s.Record(fwOut("10.0.0.45", "45.33.12.122", 8443, now.Add(2*time.Minute)), []model.Hit{scan})
	s.Record(fwOut("10.0.0.46", "104.152.52.7", 22, now), []model.Hit{scan})
	// 不记录：正常出站访问、外部对内的攻击、内网之间、只打标签的命中
	s.Record(fwOut("10.0.0.31", "8.8.8.8", 53, now), nil)
	s.Record(fwOut("45.79.7.213", "10.0.0.5", 22, now), []model.Hit{scan})
	s.Record(fwOut("10.0.0.31", "10.0.0.32", 445, now), []model.Hit{scan})
	tag := hit("ua-script", "脚本客户端", model.PhaseRecon, model.SevLow, model.ResultUnknown)
	tag.TagOnly = true
	s.Record(fwOut("10.0.0.31", "1.1.1.1", 443, now), []model.Hit{tag})

	m := s.MapData(model.SevInfo)
	if m.OutTotal != 2 || len(m.Outbound) != 1 { // 测试定位把两个地址都放在“美国”同一地点
		t.Fatalf("外部目标: total=%d points=%d", m.OutTotal, len(m.Outbound))
	}
	o := m.Outbound[0]
	if o.Targets != 2 || o.Hosts != 3 || o.Level != model.SevHigh || o.Hits != 4 || !o.hasCoord() { // 严重需要成功证据，按高危计
		t.Fatalf("按地点汇总: %+v", o)
	}
	if top := o.Items[0]; top.IP != "45.33.12.122" || top.Hits != 3 || top.Level != model.SevHigh || len(top.Hosts) != 2 || top.Category != "外连威胁情报地址" {
		t.Fatalf("目标明细（等级高的在前）: %+v", top)
	}
	if m2 := s.MapData(model.SevHigh); len(m2.Outbound) != 1 || m2.OutTotal != 1 {
		t.Fatalf("按等级过滤: %+v", m2)
	}

	// 在线溯源完成：归属地更新
	s.UpdateGeo("104.152.52.7", &geo.Info{IP: "104.152.52.7", Country: "德国", CountryCode: "DE", City: "法兰克福", WorldName: "Germany", Lat: 50.1, Lon: 8.7, HasCoord: true, CoordSource: "ip-api"})
	if m := s.MapData(model.SevInfo); len(m.Outbound) != 2 {
		t.Fatalf("溯源后应分成两个地点: %d", len(m.Outbound))
	}

	path := filepath.Join(t.TempDir(), "snap.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore()
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	if m := s2.MapData(model.SevInfo); m.OutTotal != 2 || len(m.Outbound) != 2 {
		t.Fatalf("快照恢复后应保留: %+v", m)
	}
	// 超过保留期没有再出现的目标清理掉
	s2.mu.Lock()
	s2.pruneOutboundLocked(now.Add(outboundTTL + 2*time.Hour))
	n := len(s2.outbound)
	s2.mu.Unlock()
	if n != 0 {
		t.Fatalf("过期目标应清理: %d", n)
	}
}

func (o *MapOutbound) hasCoord() bool { return o.Lat != 0 || o.Lon != 0 }

// 外部目标数达到上限时淘汰最久没有再出现的。
func TestOutboundEviction(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	scan := hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevMedium, model.ResultUnknown)
	for i := 0; i < maxOutbound+20; i++ {
		dst := "45." + itoa(i/250) + "." + itoa(i%250) + ".9"
		s.Record(fwOut("10.0.0.31", dst, 443, now.Add(time.Duration(i)*time.Second)), []model.Hit{scan})
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.outbound) != maxOutbound || s.outbound["45.0.0.9"] != nil || s.outbound["45.2.19.9"] == nil {
		t.Fatalf("应淘汰最早的目标: %d", len(s.outbound))
	}
}

// 来自日志的显示内容（证据、User-Agent、标签说明、X-Forwarded-For）写入时转义控制字符；末尾的 NUL 去掉。
func TestLogTextEscaped(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	h := hit("sqli-union", "SQL注入", model.PhaseExploit, model.SevHigh, model.ResultUnknown)
	h.Evidence = "union select\x00\x01 from users\x00"
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.30", Host: "a.example.com", Method: "GET", URI: "/?id=1",
		Status: 200, UA: "curl\x07/8\xff", XFF: "1.2.3.4\x00", PeerIP: "10.0.0.2", Time: now}, []model.Hit{h})
	s.mu.Lock()
	p := s.ips["198.51.100.30"]
	p.setTag("脚本/自动化客户端", "python\x1b[31m")
	s.mu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := p.Recent[len(p.Recent)-1]
	if a.Evidence != `union select\x00\x01 from users` || a.UA != `curl\x07/8\xff` {
		t.Fatalf("告警: %q %q", a.Evidence, a.UA)
	}
	for k := range p.UAs {
		if k != `curl\x07/8\xff` {
			t.Fatalf("UA 统计: %q", k)
		}
	}
	if p.LastXFF != "1.2.3.4" || p.Tags["脚本/自动化客户端"] != `python\x1b[31m` {
		t.Fatalf("XFF / 标签: %q %q", p.LastXFF, p.Tags["脚本/自动化客户端"])
	}
	if strings.ContainsAny(a.Evidence+a.UA, "\x00\x01\x07\x1b") {
		t.Fatal("不应残留控制字符")
	}
}
