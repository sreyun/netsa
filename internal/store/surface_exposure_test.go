package store

import (
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// TestSurfaceIgnoresUnpublishedPort 校验攻击面的「服务暴露」判定同样以 DNAT 映射为前提：
// 默认策略放行过一次探测，不代表该端口真的对外提供了服务。
func TestSurfaceIgnoresUnpublishedPort(t *testing.T) {
	s := New(1000, 1000, 100, time.Hour)
	s.PortPublished = func(ip string, port int, proto string) bool { return port == 443 }

	fire := func(port int) {
		s.Record(&model.Event{Time: time.Now(), Kind: model.KindFirewall, SrcIP: "203.0.113.9",
			DstIP: "43.242.97.40", DstPort: port, Proto: "tcp", Action: model.ActionAllow}, nil)
	}

	fire(1433) // 未映射：只计入被探测端口
	rep := s.Surface()
	if len(rep.Services) != 0 {
		t.Fatalf("未映射端口不应登记为对外服务: %+v", rep.Services)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("未映射端口不应产生服务暴露风险: %+v", rep.Findings)
	}
	found := false
	for _, kv := range rep.TopPorts {
		if strings.HasPrefix(kv.Name, "1433/") {
			found = true
		}
	}
	if !found {
		t.Fatal("未映射端口仍应计入被探测端口统计")
	}

	fire(443) // 已映射：登记为对外服务并标记暴露
	rep = s.Surface()
	if len(rep.Services) != 1 || !rep.Services[0].Exposed {
		t.Fatalf("已映射端口应登记为对外服务: %+v", rep.Services)
	}
}

// TestSurfaceWithoutExposureKeepsBehaviour 未配置映射表时保持原有行为。
func TestSurfaceWithoutExposureKeepsBehaviour(t *testing.T) {
	s := New(1000, 1000, 100, time.Hour)
	s.Record(&model.Event{Time: time.Now(), Kind: model.KindFirewall, SrcIP: "203.0.113.9",
		DstIP: "43.242.97.40", DstPort: 1433, Proto: "tcp", Action: model.ActionAllow}, nil)
	if rep := s.Surface(); len(rep.Services) != 1 {
		t.Fatalf("未配置映射表时应保持原有判定: %+v", rep.Services)
	}
}

// 通用后台入口（/admin、/manage、/dashboard）在可访问时同样属于对外暴露的管理面：
// 特征规则只处理「探测」这一侧，暴露面必须由响应状态判定，否则降低探测等级后会漏掉真正的暴露。
func TestSurfaceClassifiesAdminEntry(t *testing.T) {
	s := New(1000, 1000, 100, time.Hour)
	record := func(uri string, status int) {
		s.Record(&model.Event{Time: time.Now(), Kind: model.KindWeb, SrcIP: "203.0.113.20", Host: "a.com",
			Method: "GET", URI: uri, Status: status, Bytes: 800}, nil)
	}
	record("/admin/login", 200)
	record("/manage/", 302)
	record("/dashboard", 200)
	record("/admin/phpinfo.php", 404) // 不存在：不登记为暴露

	rep := s.Surface()
	want := map[string]bool{"/admin/login": true, "/manage/": true, "/dashboard": true}
	found := 0
	for _, ep := range rep.Endpoints {
		if ep.Host == "-" {
			continue
		}
		if ep.Sensitive == "" {
			continue
		}
		if strings.Contains(ep.Path, "phpinfo") {
			t.Fatalf("404 的后台路径不应登记为敏感资源: %+v", ep)
		}
		if want[ep.Path] {
			found++
			if ep.Severity < model.SevMedium {
				t.Errorf("%s 暴露的后台入口等级过低: %s", ep.Path, ep.Severity)
			}
		}
	}
	if found != len(want) {
		t.Fatalf("应识别 %d 个后台入口，实际 %d: %+v", len(want), found, rep.Endpoints)
	}
}
