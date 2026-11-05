package detect

import (
	"testing"

	"netsa/internal/model"
	"netsa/internal/risk"
)

// 检测产生的每个分类都要在等级裁决中有底线：分类名对不上时，底线与“观察即证据”都不生效
// （曾经 DNS 带外探测的分类名与裁决表不一致，严重被封顶成高危）。
func TestCategoriesKnownToRisk(t *testing.T) {
	for _, c := range []string{
		CatSQLi, CatXSS, CatTraversal, CatCmdExec, CatExpr, CatSSRF, CatXXE, CatDeser, CatWebShell, CatCVE, CatSensitive,
		CatAdminProbe, CatScanner, CatMapping, CatAutomation, CatProtocol, CatCC, CatDirScan, CatBruteForce, CatPortScan,
		CatHostSweep, CatFlood, CatIoT, CatRiskService, CatIntel, CatSpoof, CatCrawl, CatBeacon, CatDestroy,
		CatDNSTunnel, CatDGA, CatOOB, CatMining, CatDynDNS, CatHostEvent, CatAccount, CatVulnEndpoint, CatExfil, CatDownload, CatLateral,
	} {
		h := model.Hit{Category: c, Severity: model.SevInfo, Result: model.ResultUnknown}
		risk.Finalize(&h)
		if h.Severity == model.SevInfo {
			t.Errorf("分类 %q 在等级裁决中没有底线", c)
		}
	}
	oob := dnsHit("a1b2c3.dnslog.cn")
	if len(oob) == 0 || oob[0].RuleID != "dns-oob" {
		t.Fatalf("%+v", oob)
	}
	risk.Finalize(&oob[0])
	if oob[0].Severity != model.SevCritical {
		t.Fatalf("内网主机解析带外探测平台域名应为严重: %s", oob[0].Severity)
	}
}

func dnsHit(name string) []model.Hit {
	return inspectDNS(&model.Event{Kind: model.KindDNS, SrcIP: "10.0.0.5", Host: name, QType: "A"})
}
