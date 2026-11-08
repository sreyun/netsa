package api

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 全局搜索：IP、事件编号、规则、攻击类型按类别分组；#编号只返回该事件；关键字过长拒绝。
func TestGlobalSearch(t *testing.T) {
	s, st := testServer(t, "", "")
	h := s.Handler()
	now := time.Now()
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.20", Host: "shop.example.com", Method: "GET", URI: "/x?id=1'", Status: 403, Time: now},
		[]model.Hit{{RuleID: "sqli-union", Name: "UNION联合查询注入", Category: "SQL注入", Severity: model.SevHigh, Phase: model.PhaseExploit, Result: model.ResultBlocked}})
	st.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.21", Host: "shop.example.com", Method: "GET", URI: "/.env", Status: 404, Time: now},
		[]model.Hit{{RuleID: "sens-env", Name: "敏感文件探测", Category: "敏感文件", Severity: model.SevMedium, Phase: model.PhaseRecon, Result: model.ResultFailed}})

	search := func(q string) searchResult {
		t.Helper()
		rec := get(h, "/api/search?q="+q)
		if rec.Code != 200 {
			t.Fatalf("搜索 %q: %d %s", q, rec.Code, rec.Body.String())
		}
		var r searchResult
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	group := func(r searchResult, typ string) *searchGroup {
		for i := range r.Groups {
			if r.Groups[i].Type == typ {
				return &r.Groups[i]
			}
		}
		return nil
	}

	if r := search(""); len(r.Groups) != 0 {
		t.Fatalf("空关键字不返回结果: %+v", r)
	}
	r := search("198.51.100.20")
	if r.Groups[0].Type != "ip" || r.Groups[0].Items[0].Key != "198.51.100.20" || r.Groups[0].Items[0].Level != "high" {
		t.Fatalf("输入 IP 时攻击源排在最前: %+v", r.Groups)
	}
	inc := group(r, "incident")
	if inc == nil || inc.Total != 1 || !strings.HasPrefix(inc.Items[0].Title, "#") {
		t.Fatalf("应找到该来源的事件: %+v", inc)
	}
	id := inc.Items[0].Key

	r = search("%23" + id) // #编号
	if len(r.Groups) != 1 || r.Groups[0].Type != "incident" || r.Groups[0].Total != 1 || r.Groups[0].Items[0].Key != id {
		t.Fatalf("#编号只返回该事件: %+v", r.Groups)
	}
	if r = search("%23999999"); len(r.Groups) != 0 {
		t.Fatalf("不存在的编号: %+v", r.Groups)
	}
	if n, _ := strconv.Atoi(id); n > 0 {
		if r = search(id); r.Groups[0].Type != "incident" {
			t.Fatalf("纯数字时事件排在最前: %+v", r.Groups)
		}
	}

	r = search("sql") // 攻击类型：攻击源、事件、规则（不区分大小写）
	if g := group(r, "ip"); g == nil || g.Total != 1 {
		t.Fatalf("按攻击类型找到攻击源: %+v", r.Groups)
	}
	if g := group(r, "rule"); g == nil || g.Total == 0 || len(g.Items) > searchPerGroup {
		t.Fatalf("按攻击类型找到规则（每组最多 %d 项）: %+v", searchPerGroup, g)
	}
	if r = search("shop.example"); group(r, "chain") == nil {
		t.Fatalf("按站点找到资产攻击链路: %+v", r.Groups)
	}
	if r = search("no-such-thing-xyz"); len(r.Groups) != 0 {
		t.Fatalf("没有匹配: %+v", r.Groups)
	}
	if rec := get(h, "/api/search?q="+strings.Repeat("a", 101)); rec.Code != 400 {
		t.Fatalf("关键字过长应拒绝: %d", rec.Code)
	}
}
