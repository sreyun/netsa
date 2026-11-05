package pipeline

import (
	"strings"

	"netsa/internal/detect"
	"netsa/internal/intel"
	"netsa/internal/model"
	"netsa/internal/store"
)

// 域名情报：内网主机解析情报源标记的域名。等级按情报类别：
//   - 远控（c2）：主机正在联系控制端，失陷迹象，高危；
//   - 矿池（mining）：挖矿，高危；
//   - 恶意软件投递（malware）、通用黑名单：主机可能下载了恶意文件，中危；
//   - 钓鱼（phishing）：有人访问了钓鱼网站，中危；
//   - 攻击来源（attacker）：低危提示。
// 域名没有解析成功（NXDOMAIN）时降一级：连接多半没有建立。

// domainIntelHit 检查 DNS 查询是否命中域名情报。
func (p *Pipeline) domainIntelHit(ev *model.Event) (model.Hit, bool) {
	if p.Intel == nil || ev.Kind != model.KindDNS || ev.Host == "" {
		return model.Hit{}, false
	}
	names := p.Intel.MatchDomain(ev.Host)
	if len(names) == 0 {
		return model.Hit{}, false
	}
	kind, rank := intel.KindAttacker, -1
	for _, n := range names {
		if k := p.Intel.KindOf(n); domainRank[k] > rank {
			kind, rank = k, domainRank[k]
		}
	}
	h := model.Hit{RuleID: "intel-dns", Phase: model.PhasePersistence, Result: model.ResultAllowed, Feeds: names}
	switch kind {
	case intel.KindC2:
		h.Name, h.Category, h.Severity = "解析情报标记的远控域名（疑似失陷）", store.CatC2, model.SevHigh
	case intel.KindMining:
		h.Name, h.Category, h.Severity = "解析情报标记的矿池域名（疑似挖矿）", store.CatMining, model.SevHigh
	case intel.KindPhishing:
		h.Name, h.Category, h.Severity = "解析情报标记的钓鱼网站域名", store.CatPhishing, model.SevMedium
	case intel.KindAttacker:
		h.Name, h.Category, h.Severity = "解析情报标记的攻击来源域名", store.CatMalDomain, model.SevLow
	default:
		h.Name, h.Category, h.Severity = "解析情报标记的恶意域名", store.CatMalDomain, model.SevMedium
	}
	h.Evidence = ev.SrcIP + " 查询 " + detect.Printable(ev.Host, 120) + "，命中 " + strings.Join(names, "、")
	if strings.EqualFold(ev.RCode, "NXDOMAIN") {
		if h.Severity > model.SevLow {
			h.Severity--
		}
		h.Result = model.ResultFailed
		h.Evidence += "（域名没有解析成功，连接多半没有建立）"
	}
	return h, true
}

// domainRank 是情报类别的严重程度：同一域名命中多个情报时按最严重的类别处理。
var domainRank = map[string]int{intel.KindC2: 5, intel.KindMining: 4, intel.KindMalware: 3, intel.KindDefault: 2, intel.KindPhishing: 1, intel.KindAttacker: 0}
