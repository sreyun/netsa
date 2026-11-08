package api

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"netsa/internal/model"
	"netsa/internal/store"
)

// 全局搜索：顶栏的搜索框（Ctrl+K）输入 IP、事件编号、资产、站点、规则、攻击类型等任意关键字，
// 按类别各返回少量匹配项，点击直达对应详情。只汇总只读角色本来就能查看的内容。

const (
	searchPerGroup = 6
	searchMaxRunes = 100
)

type searchItem struct {
	Type  string `json:"type"`            // ip / incident / chain / asset / campaign / rule
	Key   string `json:"key"`             // 打开详情用的标识（IP、事件编号、链路标识、资产编号、规则编号）
	Title string `json:"title"`           // 主标题
	Sub   string `json:"sub,omitempty"`   // 副标题（归属地、状态、类别等）
	Level string `json:"level,omitempty"` // 等级（critical / high / medium / low / info），用于着色
}

type searchGroup struct {
	Type  string       `json:"type"`
	Label string       `json:"label"`
	Total int          `json:"total"` // 匹配总数（items 只含前几项）
	Items []searchItem `json:"items"`
}

type searchResult struct {
	Query  string        `json:"query"`
	Groups []searchGroup `json:"groups"`
}

// search 处理 GET /api/search?q=。
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(q) > searchMaxRunes {
		writeError(w, http.StatusBadRequest, "关键字过长")
		return
	}
	writeJSON(w, s.searchAll(q))
}

func (s *Server) searchAll(q string) searchResult {
	res := searchResult{Query: q, Groups: []searchGroup{}}
	if q == "" {
		return res
	}
	add := func(g searchGroup) {
		if g.Total > 0 {
			res.Groups = append(res.Groups, g)
		}
	}
	lower := strings.ToLower(q)

	// 事件编号：#123 或纯数字直接定位；同时也按关键字搜索事件
	inc := searchGroup{Type: "incident", Label: "安全事件"}
	if id, ok := incidentNumber(q); ok {
		if d := s.Store.Incident(id); d != nil {
			inc.Items = append(inc.Items, incidentItem(d.IncidentView))
			inc.Total++
		}
	}
	if strings.HasPrefix(q, "#") { // 明确写了 #编号：只要这一个事件
		add(inc)
		return res
	}
	list, total, _ := s.Store.Incidents(store.IncidentQuery{Search: q, Limit: searchPerGroup})
	for _, v := range list {
		if len(inc.Items) >= searchPerGroup {
			break
		}
		if len(inc.Items) > 0 && inc.Items[0].Key == strconv.FormatUint(v.ID, 10) {
			continue // 编号精确命中的事件已在第一项
		}
		inc.Items = append(inc.Items, incidentItem(v))
	}
	inc.Total = max(inc.Total, total)

	// 攻击源：IP 前缀、归属地、运营商、攻击类型、标签
	ips := searchGroup{Type: "ip", Label: "攻击源"}
	key := q
	if a, err := netip.ParseAddr(q); err == nil {
		key = a.Unmap().WithZone("").String()
	}
	atk, n := s.Store.Attackers(store.AttackerQuery{Search: key, Sort: "score", Limit: searchPerGroup})
	for _, a := range atk {
		sub := a.Location
		if len(a.Categories) > 0 {
			sub = joinNonEmpty(" · ", sub, strings.Join(firstN(a.Categories, 3), "、"))
		}
		ips.Items = append(ips.Items, searchItem{Type: "ip", Key: a.IP, Title: a.IP, Sub: sub, Level: a.Level.String()})
	}
	ips.Total = n

	// 资产攻击链路：台账资产、站点域名、主机地址
	ch := searchGroup{Type: "chain", Label: "资产攻击链路"}
	if cl := s.Store.ChainList(store.ChainQuery{Search: q, Limit: searchPerGroup}); cl != nil {
		for _, c := range cl.Chains {
			sub := stageName(c.Depth)
			if c.Confidence != "" {
				sub = joinNonEmpty(" · ", "疑似失陷", sub)
			}
			ch.Items = append(ch.Items, searchItem{Type: "chain", Key: c.Key, Title: c.Name, Sub: sub, Level: c.Severity.String()})
		}
		ch.Total = cl.Total
	}

	// 资产台账
	as := searchGroup{Type: "asset", Label: "资产台账"}
	if s.Assets != nil {
		al := s.Assets.Assets(q, "")
		for _, a := range firstN(al, searchPerGroup) {
			as.Items = append(as.Items, searchItem{Type: "asset", Key: a.ID, Title: a.Name,
				Sub: joinNonEmpty(" · ", a.IP, strings.Join(firstN(a.Hosts, 2), "、"), a.ImportanceLabel, a.Owner)})
		}
		as.Total = len(al)
	}

	// 攻击活动：成员地址、工具、网段、带外回连标识
	cp := searchGroup{Type: "campaign", Label: "攻击活动"}
	var camps []*store.Campaign
	if rep := s.Store.Campaigns(); rep != nil {
		camps = rep.Campaigns
	}
	for _, c := range camps {
		if !campaignMatch(c, lower) {
			continue
		}
		cp.Total++
		if len(cp.Items) < searchPerGroup {
			cp.Items = append(cp.Items, searchItem{Type: "campaign", Key: c.ID, Title: "攻击活动 " + c.ID,
				Sub: joinNonEmpty(" · ", strconv.Itoa(c.Size)+" 个地址", strings.Join(firstN(c.Tools, 2), "、"), strings.Join(firstN(c.Categories, 2), "、")), Level: c.Level.String()})
		}
	}

	// 检测规则：编号、名称、攻击类型
	ru := searchGroup{Type: "rule", Label: "检测规则"}
	for _, r := range s.engine().Rules() {
		if !strings.Contains(strings.ToLower(r.ID+" "+r.Name+" "+r.Category), lower) {
			continue
		}
		ru.Total++
		if len(ru.Items) < searchPerGroup {
			ru.Items = append(ru.Items, searchItem{Type: "rule", Key: r.ID, Title: r.Name, Sub: joinNonEmpty(" · ", r.ID, r.Category), Level: model.ParseSeverity(r.Severity).String()})
		}
	}

	// 精确命中的类别排在前面：输入的是 IP 时攻击源优先，是编号时事件优先
	groups := []searchGroup{ips, inc, ch, as, cp, ru}
	if _, ok := incidentNumber(q); ok {
		groups[0], groups[1] = groups[1], groups[0]
	}
	for _, g := range groups {
		add(g)
	}
	return res
}

// incidentNumber 识别事件编号写法：#123、123。
func incidentNumber(q string) (uint64, bool) {
	q = strings.TrimPrefix(q, "#")
	if q == "" || len(q) > 12 {
		return 0, false
	}
	id, err := strconv.ParseUint(q, 10, 64)
	return id, err == nil && id > 0
}

// stageName 返回攻击链路阶段的中文名称（推进到哪一步）。
func stageName(id string) string {
	for _, st := range store.ChainStages {
		if st.ID == id {
			return "推进到" + st.Name
		}
	}
	return id
}

func incidentItem(v store.IncidentView) searchItem {
	status := store.IncidentStatusLabel[v.Status]
	if v.Overdue {
		status += "（已超时）"
	}
	return searchItem{Type: "incident", Key: strconv.FormatUint(v.ID, 10), Title: "#" + strconv.FormatUint(v.ID, 10) + " " + v.Title,
		Sub: joinNonEmpty(" · ", status, v.Key, v.Location), Level: v.Severity.String()}
}

func campaignMatch(c *store.Campaign, lower string) bool {
	if strings.Contains(strings.ToLower(c.ID), lower) {
		return true
	}
	for _, m := range c.Members {
		if strings.Contains(m.IP, lower) {
			return true
		}
	}
	for _, list := range [][]string{c.Tools, c.ASNs, c.OAST, c.Decoys, c.Categories, c.Targets} {
		for _, v := range list {
			if strings.Contains(strings.ToLower(v), lower) {
				return true
			}
		}
	}
	for _, n := range c.Nets {
		if strings.Contains(n.Net, lower) {
			return true
		}
	}
	return false
}

func joinNonEmpty(sep string, parts ...string) string {
	out := parts[:0:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}
