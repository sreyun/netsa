package pipeline

import (
	"context"
	"testing"
	"time"

	"netsa/internal/assets"
	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/exposure"
	"netsa/internal/model"
	"netsa/internal/store"
)

// runOnce 构造一条最小流水线并处理一批事件。
func runOnce(t *testing.T, exp *exposure.Manager, evs []*model.Event) (*store.Store, *Pipeline) {
	t.Helper()
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(1000, 1000, 100, 7*24*time.Hour)
	p := &Pipeline{Engine: eng, Behavior: detect.NewBehavior(config.Default().Detect.Thresholds), Store: st, Exposure: exp}
	in := make(chan []*model.Event, 1)
	done := p.Run(context.Background(), in, 1)
	in <- evs
	close(in)
	<-done
	return st, p
}

func fwEvent(dst string, port int, action string) *model.Event {
	return &model.Event{Time: time.Now(), Kind: model.KindFirewall, SrcIP: "121.207.52.4",
		DstIP: dst, DstPort: port, Proto: "tcp", Action: action, Source: "fw"}
}

func TestExposureGateFiltersUnmappedProbe(t *testing.T) {
	exp, err := exposure.Load(config.ExposureConfig{
		Enabled: true,
		Services: []config.ExposureService{
			{PublicIP: "43.242.97.40", PublicPort: 1433, Proto: "tcp", Name: "业务库"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 未做映射的另一台主机上的 1433：探测命中降级为仅打标签，不产生告警
	st, _ := runOnce(t, exp, []*model.Event{fwEvent("43.242.97.41", 1433, model.ActionAllow)})
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) != 0 {
		t.Fatalf("未发布端口不应产生告警: %+v", got)
	}
	if exp.Muted() != 1 {
		t.Fatalf("应记录一次被过滤的探测，实际 %d", exp.Muted())
	}
	// 只打标签：画像存在但攻击计数为 0
	if p := st.Profile("121.207.52.4"); p == nil || p.Attacks != 0 || len(p.Tags) == 0 {
		t.Fatalf("应仅打标签: %+v", p)
	}

	// 已映射的 1433：照常告警
	st2, _ := runOnce(t, exp, []*model.Event{fwEvent("43.242.97.40", 1433, model.ActionAllow)})
	if got := st2.Alerts(store.AlertQuery{Limit: 10}); len(got) == 0 {
		t.Fatal("已发布端口应正常告警")
	}
}

func TestExposureGateKeepsInternalTargets(t *testing.T) {
	exp, _ := exposure.Load(config.ExposureConfig{Enabled: true})
	// 目标是内网地址：已经过 DNAT 或东西向流量，按真实暴露处理，不受清单限制
	st, _ := runOnce(t, exp, []*model.Event{fwEvent("10.0.0.21", 1433, model.ActionAllow)})
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) == 0 {
		t.Fatal("内网目标不应被过滤")
	}
	if exp.Muted() != 0 {
		t.Fatalf("内网目标不应计入过滤: %d", exp.Muted())
	}
}

func TestExposureGateKeepsScanBehaviour(t *testing.T) {
	exp, _ := exposure.Load(config.ExposureConfig{Enabled: true})
	// 大量未映射端口上的探测仍应触发端口扫描行为告警（反映攻击者行为，与端口是否开放无关）
	var evs []*model.Event
	for p := 1000; p < 1040; p++ {
		evs = append(evs, fwEvent("43.242.97.40", p, model.ActionDeny))
	}
	st, _ := runOnce(t, exp, evs)
	found := false
	for _, a := range st.Alerts(store.AlertQuery{Limit: 100}) {
		if a.Category == detect.CatPortScan {
			found = true
		}
	}
	if !found {
		t.Fatal("端口扫描行为不应被未发布端口过滤")
	}
}

func TestExposureDisabledKeepsAlerts(t *testing.T) {
	exp, _ := exposure.Load(config.ExposureConfig{}) // 默认关闭
	st, _ := runOnce(t, exp, []*model.Event{fwEvent("43.242.97.40", 1433, model.ActionAllow)})
	if got := st.Alerts(store.AlertQuery{Limit: 10}); len(got) == 0 {
		t.Fatal("未启用时行为不应改变")
	}
}

// TestExposureMapsTargetToInternalAsset 校验 DNAT 映射会把公网目标还原为内网地址，
// 使攻击事件能关联到内网资产与漏洞（否则资产台账里只有 10.x 地址，永远匹配不到）。
func TestExposureMapsTargetToInternalAsset(t *testing.T) {
	as, err := assets.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAsset(assets.Asset{IP: "10.0.0.21", Name: "业务库", Importance: assets.LevelCore}); err != nil {
		t.Fatal(err)
	}
	exp, _ := exposure.Load(config.ExposureConfig{Enabled: true, Services: []config.ExposureService{
		{PublicIP: "43.242.97.40", PublicPort: 1433, PrivateIP: "10.0.0.21", PrivatePort: 1433, Proto: "tcp", Name: "业务库"},
	}})
	eng, _ := detect.NewEngine("", 1)
	st := store.New(1000, 1000, 100, 7*24*time.Hour)
	p := &Pipeline{Engine: eng, Store: st, Exposure: exp, Assets: as}
	in := make(chan []*model.Event, 1)
	done := p.Run(context.Background(), in, 1)
	in <- []*model.Event{fwEvent("43.242.97.40", 1433, model.ActionAllow)}
	close(in)
	<-done

	alerts := st.Alerts(store.AlertQuery{Limit: 10})
	if len(alerts) == 0 {
		t.Fatal("已映射端口应告警")
	}
	if alerts[0].Asset != "业务库" || alerts[0].AssetLevel != assets.LevelCore {
		t.Fatalf("应关联到映射后的内网资产: %+v", alerts[0])
	}
}

// 候选映射：流水线把「外部来源访问公网端口且被放行」的防火墙事件交给 exposure 统计，
// 内网来源与出站流量不计入（它们不能证明本地端口对外发布）。
func TestExposureObservesCandidates(t *testing.T) {
	exp, err := exposure.Load(config.ExposureConfig{
		Suggest: config.ExposureSuggest{MinAllows: 1, MinSources: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng, _ := detect.NewEngine("", 1)
	st := store.New(1000, 1000, 100, time.Hour)
	p := &Pipeline{Engine: eng, Store: st, Exposure: exp}
	in := make(chan []*model.Event, 1)
	done := p.Run(context.Background(), in, 1)
	ev := fwEvent("43.242.97.40", 8443, model.ActionAllow) // 来源 121.207.52.4（公网）
	ev2 := fwEvent("43.242.97.40", 8443, model.ActionAllow)
	ev2.SrcIP = "10.0.0.9" // 内网来源：东西向流量，不计入候选
	ev3 := fwEvent("43.242.97.40", 22, model.ActionDeny)
	in <- []*model.Event{ev, ev2, ev3}
	close(in)
	<-done

	list := exp.Candidates()
	if len(list) != 1 || list[0].PublicPort != 8443 || list[0].Allows != 1 {
		t.Fatalf("应只记录 1 条公网来源的放行连接: %+v", list)
	}
}
