package store

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/model"
	"netsa/internal/risk"
)

// 资产攻击链路：以被攻击的资产（站点、主机、资产台账中的资产）为中心，把侦察、利用、突破、植入、控制、横向、
// 窃取、影响按时间串起来，每一步注明证据、来源与 ATT&CK 技术。
//
//   - 入库时按资产增量记录（命中口径，含按规则节流未生成告警的命中），不依赖保留的告警条数，随快照持久化；
//   - 一次命中可能落在两个资产上：被攻击的目标（站点、目的地址），以及发起连接的内网资产自身
//     （外连远控、DNS 带外 / 隧道是被控制，向其他内网主机发起扫描、暴力破解是横向）；
//   - 同一资产的不同标识在查询时合并：资产台账中精确登记的同一资产、Web 日志记录的服务器地址、
//     服务器回连的地址正是攻击该站点的来源或攻击载荷中写明的回连地址；
//   - 分析员把来源的事件标为误报后，该来源的步骤不再计入阶段与失陷研判（页面仍显示并注明）。

// 资产攻击链路的阶段（按攻击推进的顺序）。
const (
	stRecon = iota
	stExploit
	stBreach
	stPersist
	stControl
	stLateral
	stCollect
	stImpact
	stageN
)

// StageDef 是资产攻击链路的一个阶段。
type StageDef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// ChainStages 按攻击推进的顺序列出资产攻击链路的阶段。
var ChainStages = [stageN]StageDef{
	{"recon", "侦察", "端口扫描、主机探测、目录与漏洞扫描、敏感文件探测"},
	{"exploit", "利用", "漏洞利用、注入、暴力破解等攻击尝试"},
	{"breach", "突破", "攻击成功研判、暴力破解后登录成功、Web 进程执行系统命令、账号盗用"},
	{"persist", "植入", "WebShell 交互与落地、载荷下载、自启动项、新建账号、加入管理员组、清除日志"},
	{"control", "控制", "回连攻击者、反弹 Shell、外连远控 / 矿池、恶意 TLS 指纹、DNS 带外回连 / 隧道 / DGA"},
	{"lateral", "横向", "以该资产为来源向其他内网主机发起的扫描、探测、暴力破解与管理连接，凭证窃取"},
	{"collect", "窃取", "接口遍历、批量爬取、外发流量与下载量突增"},
	{"impact", "影响", "CC、拒绝服务（含带宽型 DDoS）、破坏性攻击、删除卷影副本"},
}

func stageIndex(id string) int {
	for i, d := range ChainStages {
		if d.ID == id {
			return i
		}
	}
	return -1
}

const (
	chainMaxTracks  = 3000
	chainMaxSteps   = 150 // 单个资产标识记录的步骤上限
	chainMaxRecon   = 20  // 其中侦察步骤的上限：互联网背景扫描的来源很多，只保留前若干个，其余只计入阶段统计
	chainMaxPeers   = 200
	chainMaxServers = 8
	chainMaxAliases = 8
	chainRetention  = 30 * 24 * time.Hour
	chainViewSteps  = 300 // 详情中返回的步骤上限
	chainListMax    = 500
	callbackLinkWin = 2 * time.Hour  // 服务器连接攻击来源：攻击之后多久内的连接参与合并
	payloadLinkWin  = 24 * time.Hour // 服务器连接攻击载荷中的回连地址：载荷可能由计划任务稍后执行
	chainSlack      = 2 * time.Minute
)

// 外部地址在资产链路中的角色（位）。
const (
	peerAttacker uint8 = 1 << iota // 对该资产发起过利用及以上的攻击
	peerPayload                    // 出现在针对该资产的攻击载荷中
)

// chainPeer 是与资产相关的外部地址，用于把之后回连这些地址的服务器与被攻击的站点串起来。
type chainPeer struct {
	Role  uint8 `json:"role"`
	First int64 `json:"first"` // Unix 秒
	Last  int64 `json:"last"`
}

// stageStat 是资产在一个阶段的累计（含超出步骤上限、未单独记录的命中）。
type stageStat struct {
	First int64          `json:"f,omitempty"` // Unix 秒
	Last  int64          `json:"l,omitempty"`
	Hits  int64          `json:"n,omitempty"`
	Sev   model.Severity `json:"s,omitempty"`
}

// chainStep 是链路中的一步：同一阶段、同一攻击类型、同一来源（与对端）的命中合并为一步。
type chainStep struct {
	Stage    int            `json:"stage"`
	Category string         `json:"category"`
	Rule     string         `json:"rule"`
	Name     string         `json:"name"`
	Src      string         `json:"src"`            // 攻击来源；资产自身发起的步骤（控制、横向）为资产地址
	Peer     string         `json:"peer,omitempty"` // 资产自身发起的步骤的对端：外连目的、查询的域名、横向的目标
	Target   string         `json:"target,omitempty"`
	Evidence string         `json:"evidence,omitempty"` // 最有说服力的一次命中的证据
	Severity model.Severity `json:"severity"`
	Result   string         `json:"result,omitempty"`
	Proven   bool           `json:"proven,omitempty"`
	First    time.Time      `json:"first"`
	Last     time.Time      `json:"last"`
	Count    int64          `json:"count"`
	Alert    uint64         `json:"alert,omitempty"`    // 首条告警
	Incident uint64         `json:"incident,omitempty"` // 最近一次命中所属的事件（分析员的结论以它为准）
}

// stepKey 是步骤的合并键（结构体作为 map 键，查找时不拼接字符串、不分配内存）。
type stepKey struct {
	stage          int
	cat, src, peer string
}

func (st *chainStep) key() stepKey { return stepKey{st.Stage, st.Category, st.Src, st.Peer} }

// chainKey 是资产标识的键：类型 + 标识。
type chainKey struct{ kind, key string }

// rank 用于挑选一步的代表性命中：有证据的成功 > 成功 > 等级高。
func hitRank(sev model.Severity, result string, proven bool) int {
	r := int(sev) * 4
	if result == model.ResultSuccess {
		r += 2
		if proven {
			r++
		}
	}
	return r
}

// chainTrack 是一个资产标识（站点域名、主机地址、台账资产）的攻击链路记录。
type chainTrack struct {
	Key       string                `json:"key"`
	Kind      string                `json:"kind"`            // asset：台账中精确登记的资产；site：站点；host：主机
	Asset     string                `json:"asset,omitempty"` // 按网段 / 通配域名覆盖到的台账资产
	Level     string                `json:"level,omitempty"`
	Owner     string                `json:"owner,omitempty"`
	FirstSeen time.Time             `json:"first_seen"`
	LastSeen  time.Time             `json:"last_seen"`
	Hits      int64                 `json:"hits"`
	Stages    [stageN]stageStat     `json:"stages"`
	Steps     []*chainStep          `json:"steps"`
	Dropped   int64                 `json:"dropped,omitempty"` // 超出步骤上限、未单独记录的命中
	Aliases   []string              `json:"aliases,omitempty"` // 同一资产的其他标识：台账资产被访问时的域名与地址、DNAT 前的公网地址
	Servers   []string              `json:"servers,omitempty"` // Web 日志记录的服务器内网地址
	Peers     map[string]*chainPeer `json:"peers,omitempty"`

	idx   map[stepKey]*chainStep // 步骤键 → 步骤（不持久化，加载后重建）
	recon int                    // 侦察步骤数
}

func (tr *chainTrack) reindex() {
	tr.idx = make(map[stepKey]*chainStep, len(tr.Steps))
	tr.recon = 0
	steps := tr.Steps[:0]
	for _, st := range tr.Steps {
		if st == nil || st.Stage < 0 || st.Stage >= stageN {
			continue
		}
		steps = append(steps, st)
		tr.idx[st.key()] = st
		if st.Stage == stRecon {
			tr.recon++
		}
	}
	tr.Steps = steps
}

// depth 是资产推进到的最深阶段（只有侦察为 0）。
func (tr *chainTrack) depth() int {
	for i := stageN - 1; i > 0; i-- {
		if tr.Stages[i].Hits > 0 {
			return i
		}
	}
	return 0
}

func addUnique(list []string, v string, limit int) []string {
	if v == "" || len(list) >= limit {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func (tr *chainTrack) addPeer(ip string, role uint8, t time.Time) {
	if ip == "" {
		return
	}
	u := t.Unix()
	p := tr.Peers[ip]
	if p == nil {
		if len(tr.Peers) >= chainMaxPeers {
			return
		}
		if tr.Peers == nil {
			tr.Peers = map[string]*chainPeer{}
		}
		p = &chainPeer{First: u, Last: u}
		tr.Peers[ip] = p
	}
	p.Role |= role
	p.First, p.Last = min(p.First, u), max(p.Last, u)
}

// makeRoom 判断能否为新步骤腾出位置：侦察步骤有单独的上限；步骤满了时淘汰命中最少的一条侦察步骤给更深的阶段让位。
func (tr *chainTrack) makeRoom(stage int) bool {
	if stage == stRecon {
		return tr.recon < chainMaxRecon && len(tr.Steps) < chainMaxSteps
	}
	if len(tr.Steps) < chainMaxSteps {
		return true
	}
	victim := -1
	for i, x := range tr.Steps {
		if x.Stage == stRecon && (victim < 0 || x.Count < tr.Steps[victim].Count) {
			victim = i
		}
	}
	if victim < 0 {
		return false
	}
	v := tr.Steps[victim]
	delete(tr.idx, v.key())
	tr.Dropped += v.Count
	tr.Steps = append(tr.Steps[:victim], tr.Steps[victim+1:]...)
	tr.recon--
	return true
}

// chainSide 是一次命中所涉及的资产标识（值类型：每条攻击事件都要计算，不在堆上分配）。
type chainSide struct {
	ok                             bool
	key, kind, asset, level, owner string
	aliases                        [3]string // 同一资产的其他标识：台账资产被访问时的地址与域名、DNAT 前的公网地址、主机名
}

func (c *chainSide) addAlias(a string) {
	for i := range c.aliases {
		if c.aliases[i] == "" || c.aliases[i] == a {
			c.aliases[i] = a
			return
		}
	}
}

// chainRoles 是一个事件在资产攻击链路中的角色，每个事件只计算一次。
type chainRoles struct {
	done   bool
	target chainSide // 被攻击的资产
	actor  chainSide // 发起连接的内网资产自身（外连、DNS 查询、横向）
	egress bool      // actor 访问的是外部（外连、DNS 查询），否则为横向
	peer   string    // actor 的对端
	server string    // Web 日志记录的服务器内网地址
	// srcInternal 表示来源是内网地址（判断一次，记录每条命中时复用）
	srcInternal bool
}

// AssetOf 由资产台账提供；为 nil 时只按地址与域名区分资产。见 Store.AssetOf。

// chainHost 归一化站点域名：小写、去掉端口与末尾的点。
func chainHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || h == "-" || h == "_" {
		return ""
	}
	if strings.HasPrefix(h, "[") { // [::1]:8080
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[:i], ":") {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if len(h) > 120 {
		h = truncate(h, 120)
	}
	return h
}

// isIPLiteral 判断站点名是不是地址。先按首字符排除域名：解析失败时 netip 会分配错误对象，每条 Web 攻击都要判断一次
func isIPLiteral(s string) bool {
	if s == "" || (s[0] < '0' || s[0] > '9') && strings.IndexByte(s, ':') < 0 {
		return false
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// side 返回资产标识：台账中精确登记的资产按资产名称合并；按网段 / 通配域名覆盖到的仍按地址或站点区分。
func (s *Store) side(ref *model.AssetRef, ip, host string) chainSide {
	if ref == nil && s.AssetOf != nil && (ip != "" || host != "") {
		ref = s.AssetOf(ip, host)
	}
	var c chainSide
	switch {
	case ref != nil && ref.Name != "" && !ref.Group:
		c.key, c.kind = ref.Name, "asset"
		c.addAlias(host)
		c.addAlias(ip)
	case host != "":
		c.key, c.kind = host, "site"
	case ip != "":
		c.key, c.kind = ip, "host"
	default:
		return c
	}
	c.ok = true
	if ref != nil {
		c.level, c.owner = ref.Level, ref.Owner
		if ref.Group {
			c.asset = ref.Name
		}
	}
	return c
}

// chainRolesOf 判断事件涉及的资产（调用方持写锁）。
func (s *Store) chainRolesOf(ev *model.Event) chainRoles {
	r := chainRoles{done: true}
	src := ev.SrcIP
	srcInternal := src != "" && geo.IsPrivate(src)
	r.srcInternal = srcInternal
	switch {
	case ev.Kind == model.KindDNS:
		// DNS 查询：主体是发起查询的内网主机（流水线按查询的域名匹配资产，这里不采用）
		r.actor, r.egress, r.peer = s.side(nil, src, ""), true, regDomainOr(ev.Host)
		return r
	case ev.Kind == model.KindFirewall && (ev.Outbound || srcInternal && ev.DstIP != "" && !geo.IsPrivate(ev.DstIP)):
		var ref *model.AssetRef
		if ev.Outbound {
			ref = ev.Asset // 出站流量由流水线按发起方匹配资产
		}
		r.actor, r.egress, r.peer = s.side(ref, src, ""), true, ev.DstIP
		return r
	case ev.SubjectHost:
		// 主机自身的事件（清除日志、加入管理员组）：上报日志的主机就是资产
		ip, host := src, ""
		if ip == "" {
			host = chainHost(ev.Host)
		}
		r.target = hostSide(s.side(nil, ip, host))
		if r.target.ok && ev.Host != "" && ip != "" {
			r.target.addAlias(chainHost(ev.Host))
		}
		return r
	}
	switch ev.Kind {
	case model.KindWeb:
		host := chainHost(ev.Host)
		if detect.FakeSiteHost(host) {
			host = "" // 虚构的 Host 头（OAST、nip.io、云元数据地址）：记在实际收到请求的服务器或日志源上
		}
		server := ""
		switch {
		case ev.NatDstIP != "" && geo.IsPrivate(ev.NatDstIP):
			server = ev.NatDstIP
		case ev.DstIP != "" && geo.IsPrivate(ev.DstIP):
			server = ev.DstIP
		}
		switch {
		case host == "" && ev.DstIP != "":
			r.target = s.side(ev.Asset, ev.DstIP, "")
		case host == "":
			name := "未知站点"
			if ev.Source != "" {
				name = "日志源 " + ev.Source
			}
			r.target = s.side(ev.Asset, "", name)
		case isIPLiteral(host):
			r.target = s.side(ev.Asset, host, "") // 直接用地址访问：与防火墙日志中的目的地址是同一台主机
		default:
			r.target = s.side(ev.Asset, server, host)
			r.server = server
		}
	case model.KindAuth:
		ip, host := ev.DstIP, ""
		if ip == "" {
			host = chainHost(ev.Host) // 上报日志的主机名
		}
		r.target = hostSide(s.side(ev.Asset, ip, host))
	default:
		ip := ev.DstIP
		if ev.NatDstIP != "" && ev.NatDstIP != ev.DstIP && geo.IsPrivate(ev.NatDstIP) {
			ip = ev.NatDstIP // DNAT 之后的服务器才是被攻击的资产
		}
		r.target = s.side(ev.Asset, ip, "")
		if r.target.ok && ip != ev.DstIP {
			r.target.addAlias(ev.DstIP)
		}
	}
	// 内网主机向其他内网主机发起的扫描、暴力破解是它自身的横向移动。Web 攻击的来源可能是未还原真实地址的
	// 反向代理，不作为横向记录（目标站点仍记录这次攻击）
	if srcInternal && r.target.ok && r.target.key != src && (ev.Kind == model.KindFirewall || ev.Kind == model.KindAuth) {
		r.actor, r.peer = s.side(nil, src, ""), r.target.key
	}
	return r
}

// hostSide 把以主机名标识的资产记为主机（认证日志、主机事件中的主机名不是站点）。
func hostSide(c chainSide) chainSide {
	if c.ok && c.kind == "site" {
		c.kind = "host"
	}
	return c
}

func regDomainOr(h string) string {
	h = chainHost(h)
	if d := regDomain(h); d != "" {
		return d
	}
	return h
}

// 资产被控制的迹象：外连远控 / 矿池 / 恶意软件投递地址、周期性外连、攻击后回连、安全设备报出的恶意软件与远控、
// DNS 带外回连 / 隧道 / DGA / 动态域名。钓鱼网站与“攻击来源”类情报只说明有人访问过，不计入链路
var controlCats = map[string]bool{
	CatC2: true, CatBeacon: true, CatCallback: true, CatMalware: true, CatMalDomain: true, CatMining: true,
	"DNS隧道": true, "带外探测回连": true, "DGA域名": true, "动态域名/内网穿透": true,
}

// volumeCats 是只凭连接 / 请求数量判断的攻击类型。
var volumeCats = map[string]bool{"洪水攻击": true, "CC攻击": true}

// lateralReconCats 是侦察性质的攻击类型：内网主机发起时可能是运维人员或漏洞扫描器。
var lateralReconCats = map[string]bool{"端口扫描": true, "主机探测": true, "高危服务探测": true, "扫描器": true, "网络空间测绘": true,
	"协议异常": true, "自动化工具": true, "目录扫描": true, "管理后台探测": true}

// hostStages 是主机侧证据（进程日志、流量日志中的文件、账号盗用）所处的阶段。
var hostStages = map[string]int{
	"主机命令执行": stBreach, "反弹Shell": stControl, "凭证窃取": stLateral, "可疑命令": stPersist, "持久化": stPersist, "痕迹清除": stPersist,
	"账号盗用": stBreach, "载荷下载": stPersist, "恶意文件": stPersist,
}

// targetStage 返回命中在被攻击资产链路中的阶段。
func targetStage(h *model.Hit) int {
	switch h.Category {
	case "账号异常", "主机安全事件":
		return stPersist
	}
	if st, ok := hostStages[h.Category]; ok {
		return st
	}
	switch h.Phase {
	case model.PhaseImpact:
		return stImpact
	case model.PhaseCollection:
		return stCollect
	}
	if h.Result == model.ResultSuccess {
		if h.Category == "WebShell后门" {
			return stPersist // 与后门脚本发生了交互
		}
		return stBreach
	}
	if h.Phase == model.PhaseRecon {
		return stRecon
	}
	return stExploit
}

// actorStage 返回资产自身发起的命中所处的阶段，第二个返回值为 false 表示不计入链路。
func (r *chainRoles) actorStage(h *model.Hit) (int, bool) {
	if !r.egress {
		if volumeCats[h.Category] || h.Phase == model.PhaseImpact {
			// 连接量类命中（洪泛、CC）说明不了发起方在横向移动：反向代理回源、监控探活、内部扫描器都会这样，
			// 只记在被访问的一侧
			return 0, false
		}
		return stLateral, true
	}
	switch {
	case h.Category == "载荷下载" || h.Category == "恶意文件":
		return stPersist, true // 资产自己下载的攻击载荷
	case controlCats[h.Category]:
		return stControl, true
	case h.Phase == model.PhaseCollection:
		return stCollect, true
	case h.Phase == model.PhaseImpact:
		return stImpact, true
	}
	return 0, false
}

// chainTrackLocked 返回资产标识的记录，不存在时创建（调用方持写锁）。
func (s *Store) chainTrackLocked(c *chainSide, t time.Time) *chainTrack {
	if s.chains == nil {
		s.chains = map[chainKey]*chainTrack{}
	}
	k := chainKey{c.kind, c.key}
	tr := s.chains[k]
	if tr == nil {
		if len(s.chains) >= chainMaxTracks {
			s.evictChainsLocked()
		}
		tr = &chainTrack{Key: c.key, Kind: c.kind, FirstSeen: t, LastSeen: t, idx: map[stepKey]*chainStep{}}
		s.chains[k] = tr
	}
	if c.level != "" {
		tr.Level, tr.Owner = c.level, c.owner
	}
	if c.asset != "" {
		tr.Asset = c.asset
	}
	for _, a := range c.aliases {
		if a != "" && a != c.key {
			tr.Aliases = addUnique(tr.Aliases, a, chainMaxAliases)
		}
	}
	return tr
}

// chainHitLocked 把一次命中记入资产攻击链路（调用方持写锁）。t 为统计用时间（已排除未来 / 远古的异常时间），
// alert 为生成的告警编号（被节流时为 0），inc 为所属事件。
func (s *Store) chainHitLocked(ev *model.Event, h *model.Hit, r *chainRoles, t time.Time, alert, inc uint64) {
	if c := &r.target; c.ok {
		st := targetStage(h)
		tr := s.chainTrackLocked(c, t)
		tr.step(st, h, ev, ev.SrcIP, "", t, alert, inc)
		if r.server != "" {
			tr.Servers = addUnique(tr.Servers, r.server, chainMaxServers)
		}
		if st >= stExploit && st <= stPersist && ev.SrcIP != "" && !r.srcInternal {
			tr.addPeer(ev.SrcIP, peerAttacker, t)
			for _, a := range ev.PayloadAddrs {
				tr.addPeer(a, peerPayload, t)
			}
		}
	}
	if c := &r.actor; c.ok {
		if st, ok := r.actorStage(h); ok {
			s.chainTrackLocked(c, t).step(st, h, ev, ev.SrcIP, r.peer, t, alert, inc)
		}
	}
}

// step 累计一步（调用方持写锁）。已有的步骤只更新计数与时间，不分配内存。
func (tr *chainTrack) step(stage int, h *model.Hit, ev *model.Event, src, peer string, t time.Time, alert, inc uint64) {
	tr.Hits++
	if t.Before(tr.FirstSeen) {
		tr.FirstSeen = t
	}
	if t.After(tr.LastSeen) {
		tr.LastSeen = t
	}
	u := t.Unix()
	ss := &tr.Stages[stage]
	if ss.Hits == 0 || u < ss.First {
		ss.First = u
	}
	ss.Last = max(ss.Last, u)
	ss.Hits++
	ss.Sev = max(ss.Sev, h.Severity)

	if tr.idx == nil {
		tr.reindex()
	}
	k := stepKey{stage, h.Category, src, truncate(peer, 120)}
	st := tr.idx[k]
	if st == nil {
		if !tr.makeRoom(stage) {
			tr.Dropped++
			return
		}
		st = &chainStep{Stage: stage, Category: h.Category, Src: src, Peer: k.peer, First: t, Last: t, Rule: h.RuleID, Name: h.Name,
			Severity: h.Severity, Result: h.Result, Proven: h.Proven, Evidence: truncate(h.Evidence, 300), Target: truncate(ev.Target(), 200)}
		tr.Steps = append(tr.Steps, st)
		tr.idx[k] = st
		if stage == stRecon {
			tr.recon++
		}
	}
	st.Count++
	if t.Before(st.First) {
		st.First = t
	}
	if t.After(st.Last) {
		st.Last = t
	}
	if hitRank(h.Severity, h.Result, h.Proven) > hitRank(st.Severity, st.Result, st.Proven) {
		st.Rule, st.Name, st.Severity, st.Result = h.RuleID, h.Name, h.Severity, h.Result
		st.Proven = st.Proven || h.Proven
		st.Evidence, st.Target = truncate(h.Evidence, 300), truncate(ev.Target(), 200)
		if alert != 0 {
			st.Alert = alert
		}
	}
	if st.Alert == 0 {
		st.Alert = alert
	}
	if inc != 0 {
		st.Incident = inc
	}
}

// evictChainsLocked 资产标识数达到上限时淘汰一成：先淘汰只有侦察的，再按最后活动时间从早到晚（调用方持写锁）。
func (s *Store) evictChainsLocked() {
	type cand struct {
		k     chainKey
		depth int
		last  time.Time
	}
	list := make([]cand, 0, len(s.chains))
	for k, tr := range s.chains {
		list = append(list, cand{k, tr.depth(), tr.LastSeen})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].depth != list[j].depth {
			return list[i].depth < list[j].depth
		}
		return list[i].last.Before(list[j].last)
	})
	for _, c := range list[:max(1, len(list)/10)] {
		delete(s.chains, c.k)
	}
}

// pruneChainsLocked 清理超过保留期没有新命中的资产记录（调用方持写锁）。
func (s *Store) pruneChainsLocked(now time.Time) {
	cut := now.Add(-chainRetention)
	for k, tr := range s.chains {
		if tr.LastSeen.Before(cut) {
			delete(s.chains, k)
		}
	}
}

// ---------------- 查询 ----------------

// ChainTech 是一步对应的 ATT&CK 技术。
type ChainTech struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ChainStepView 是链路中的一步。
type ChainStepView struct {
	Stage      string         `json:"stage"`
	StageName  string         `json:"stage_name"`
	Asset      string         `json:"asset"` // 所在的资产标识
	Category   string         `json:"category"`
	Rule       string         `json:"rule"`
	Name       string         `json:"name"`
	Src        string         `json:"src"`
	SrcLabel   string         `json:"src_label,omitempty"` // 来源的归属地；内网地址为“内网主机”
	Internal   bool           `json:"internal,omitempty"`  // 来源为内网地址
	Self       bool           `json:"self,omitempty"`      // 资产自身发起（控制、横向）
	Peer       string         `json:"peer,omitempty"`
	Target     string         `json:"target,omitempty"`
	Evidence   string         `json:"evidence,omitempty"`
	Severity   model.Severity `json:"severity"`
	Result     string         `json:"result,omitempty"`
	Proven     bool           `json:"proven,omitempty"`
	First      time.Time      `json:"first"`
	Last       time.Time      `json:"last"`
	Count      int64          `json:"count"`
	Techniques []ChainTech    `json:"techniques,omitempty"`
	Alert      uint64         `json:"alert,omitempty"`
	Incident   uint64         `json:"incident,omitempty"`
	Dismissed  bool           `json:"dismissed,omitempty"` // 来源的事件已被标为误报：不计入阶段与失陷研判
	Weak       string         `json:"weak,omitempty"`      // 只是需核实的迹象（原因）：照常显示，不计入阶段与失陷研判
}

// counted 判断一步是否计入阶段与研判。
func (v *ChainStepView) counted() bool { return !v.Dismissed && v.Weak == "" }

// ChainStageView 是链路中的一个阶段。
type ChainStageView struct {
	StageDef
	Reached    bool           `json:"reached"`
	Weak       bool           `json:"weak,omitempty"` // 只有需核实的迹象
	First      time.Time      `json:"first,omitempty"`
	Last       time.Time      `json:"last,omitempty"`
	Hits       int64          `json:"hits"`
	Severity   model.Severity `json:"severity"`
	Sources    int            `json:"sources"`
	Techniques []ChainTech    `json:"techniques,omitempty"`
}

// ChainSource 是攻击该资产的一个来源。
type ChainSource struct {
	IP       string         `json:"ip"`
	Location string         `json:"location,omitempty"`
	Internal bool           `json:"internal,omitempty"`
	Stages   []string       `json:"stages"`
	Hits     int64          `json:"hits"`
	Severity model.Severity `json:"severity"`
	Score    float64        `json:"score"`
	First    time.Time      `json:"first"`
	Last     time.Time      `json:"last"`
}

// ChainMember 是合并到同一链路的一个资产标识。
type ChainMember struct {
	Key       string    `json:"key"`
	Kind      string    `json:"kind"`
	Asset     string    `json:"asset,omitempty"`
	Hits      int64     `json:"hits"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ChainLink 是两个资产标识合并的依据。
type ChainLink struct {
	A      string `json:"a"`
	B      string `json:"b"`
	Reason string `json:"reason"`
}

// ChainSummary 是资产攻击链路列表中的一项。
type ChainSummary struct {
	Key        string         `json:"key"` // 查询详情用的标识
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Asset      string         `json:"asset,omitempty"`
	Level      string         `json:"level,omitempty"`
	Owner      string         `json:"owner,omitempty"`
	Members    []string       `json:"members"`
	Reached    []string       `json:"reached"`
	Weak       []string       `json:"weak,omitempty"` // 只有需核实的迹象、未计入的阶段
	Depth      string         `json:"depth"`
	Severity   model.Severity `json:"severity"`
	Confidence string         `json:"confidence,omitempty"` // 失陷研判：high / medium，空为未见失陷迹象
	Hits       int64          `json:"hits"`
	Sources    int            `json:"sources"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Verdict    string         `json:"verdict"`
	// InternalOnly 表示越过侦察的攻击来源全部是内网地址（常是内部漏洞扫描）
	InternalOnly bool `json:"internal_only,omitempty"`
}

// AssetChain 是一个资产的完整攻击链路。
type AssetChain struct {
	ChainSummary
	Stages     []ChainStageView `json:"stages"`
	Path       []ChainStepView  `json:"path"`  // 关键路径：每个阶段最有代表性的一步
	Steps      []ChainStepView  `json:"steps"` // 时间线（按首次出现的时间）
	StepsTotal int              `json:"steps_total"`
	SourceList []ChainSource    `json:"source_list"`
	MemberInfo []ChainMember    `json:"member_info"`
	Links      []ChainLink      `json:"links,omitempty"`
	Advice     []string         `json:"advice"`
	Dropped    int64            `json:"dropped,omitempty"`
}

// ChainList 是资产攻击链路列表。
type ChainList struct {
	Stages      []StageDef     `json:"stage_defs"`
	Chains      []ChainSummary `json:"chains"`
	Total       int            `json:"total"`   // 符合条件的资产数
	Tracked     int            `json:"tracked"` // 记录的资产标识数
	Counts      map[string]int `json:"counts"`  // 推进到各阶段的资产数（全部资产）
	Compromised map[string]int `json:"compromised"`
}

// ChainQuery 是资产攻击链路的查询条件。
type ChainQuery struct {
	Search      string
	Stage       string // 至少推进到该阶段之后（如 exploit：越过侦察）
	Compromised bool   // 只看研判为失陷的
	Limit       int
}

// chainGroup 是合并后的一个资产。
type chainGroup struct {
	tracks []*chainTrack
	links  []ChainLink
}

// chainIndex 是查询时构建的合并结果。
type chainIndex struct {
	list   []*chainTrack
	byID   map[string]int // 资产标识（含别名）→ list 下标
	groups []*chainGroup
	of     []int // list 下标 → groups 下标
}

// weakLocked 返回一步只是“需核实的迹象”的原因，不是时返回空。这样的步骤照常显示并注明原因，但不计入阶段、推进深度
// 与失陷研判：与疑似失陷资产的口径一致（只凭规律外连不列为失陷主机），否则内网里定时调用接口、监控探活的主机都会被
// 标成疑似失陷，反向代理、内部扫描器的大量连接也会被当成横向移动与拒绝服务。查询时判断，已记录的历史数据同样适用
// （调用方持读锁）。
func (s *Store) weakLocked(g *chainGroup, st *chainStep) string {
	switch st.Stage {
	case stControl:
		switch {
		case st.Category == CatBeacon && st.Severity < model.SevHigh && !g.strongPeer(st.Peer):
			// 规律外连的对端正是命中情报的远控地址时，是佐证而不是需核实的迹象
			return "只有规律外连：软件更新、监控探活、定时调用接口同样等间隔，需在主机上核实发起连接的进程"
		case st.Severity < model.SevMedium:
			return "低危迹象（如解析动态域名、定时 ping）：正常软件也会这样，需结合主机核实"
		}
	case stLateral:
		switch {
		case volumeCats[st.Category]:
			return "只是连接量多：反向代理回源、监控探活同样频繁，说明不了横向移动"
		case st.Severity < model.SevHigh && (lateralReconCats[st.Category] || st.Rule == "bhv-fwbrute"):
			return "内网扫描或连接次数：运维人员与漏洞扫描器同样会这样做，需核实发起方；是授权扫描的请登记"
		}
	case stImpact:
		switch {
		case volumeCats[st.Category] && st.Src != "" && (geo.IsPrivate(st.Src) || g.isSelf(st.Src)):
			return "来源是内网地址：多为反向代理、负载均衡、监控或内部扫描器的连接，不是拒绝服务"
		case st.Rule == "bhv-flood" && s.scannerLocked(st.Src):
			return "来源是端口扫描器：旧版本把高速扫描误判为流量洪泛"
		case st.Rule == "bhv-flood" && webTarget(st.Target) && s.webClientLocked(st.Src):
			return "该来源同时在 Web 日志中正常访问站点：防火墙只看得到连接数，是否为攻击以 Web 日志的 CC 检测为准"
		case st.Rule == "bhv-timeout" && longLivedTarget(st.Target):
			return "长连接（WebSocket / SockJS / SSE）本来就一直挂着：旧版本把页面的不断重连误判为慢请求攻击"
		}
	case stBreach, stPersist:
		if !st.Proven && st.Result == model.ResultSuccess && risk.ResponseProvable(st.Category) && !s.surf.successKept(st.Category, st.Target) {
			if st.Category == "敏感文件探测" {
				return "攻击面中没有对应的敏感资源暴露：响应是站点的兜底页面，并没有取到文件"
			}
			return "攻击成功研判已撤销：响应是站点的兜底页面，或来源已被标为误报 / 授权扫描"
		}
	}
	return ""
}

// strongPeer 判断资产是否以高危以上的非规律外连（命中情报的远控、恶意软件）连接过该对端。
func (g *chainGroup) strongPeer(peer string) bool {
	if peer == "" {
		return false
	}
	for _, tr := range g.tracks {
		for _, st := range tr.Steps {
			if st.Stage == stControl && st.Peer == peer && st.Category != CatBeacon && st.Severity >= model.SevHigh {
				return true
			}
		}
	}
	return false
}

// webTarget 判断防火墙步骤的目标（地址:端口/协议）是否为 Web 端口。
func webTarget(target string) bool {
	_, rest, ok := strings.Cut(target, ":")
	if !ok {
		return false
	}
	port, _, _ := strings.Cut(rest, "/")
	switch port {
	case "80", "443", "8080", "8443", "8000", "8888":
		return true
	}
	return false
}

// webClientLocked 判断来源是否主要是正常的 Web 访问：Web 请求不少于 50 次，攻击命中不到一半（调用方持读锁）。
func (s *Store) webClientLocked(ip string) bool {
	p := s.ips[ip]
	return p != nil && p.WebReqs >= 50 && p.Attacks*2 < p.WebReqs
}

// longLivedTarget 判断 Web 步骤的目标（站点 + 空格 + URI）是否为长连接接口。
func longLivedTarget(target string) bool {
	_, uri, ok := strings.Cut(target, " ")
	return ok && detect.LongLivedURI(uri)
}

// scannerLocked 判断来源是否做过端口扫描或主机探测（调用方持读锁）。
func (s *Store) scannerLocked(ip string) bool {
	p := s.ips[ip]
	return p != nil && (p.Rules["bhv-portscan"] > 0 || p.Rules["bhv-hostsweep"] > 0)
}

// fakeGroup 判断合并后的资产是否全部是虚构的站点（Host 头里的 OAST、nip.io 等，旧版本按站点记录过）。
func (g *chainGroup) fakeGroup() bool {
	for _, tr := range g.tracks {
		if !fakeSite(tr) {
			return false
		}
	}
	return true
}

// fakeSite 判断资产标识是不是虚构的站点名。没有 Host 头时按日志源记录的“日志源 nginx”“未知站点”不是虚构的。
func fakeSite(tr *chainTrack) bool {
	return tr.Kind == "site" && tr.Key != "未知站点" && !strings.HasPrefix(tr.Key, "日志源 ") && detect.FakeSiteHost(tr.Key)
}

func kindRank(k string) int {
	switch k {
	case "asset":
		return 0
	case "site":
		return 1
	}
	return 2
}

// dismissedLocked 判断一步的来源事件是否已被分析员标为误报（调用方持读锁）。
func (s *Store) dismissedLocked(st *chainStep) bool {
	if st.Incident == 0 {
		return false
	}
	inc := s.incidents[st.Incident]
	return inc != nil && inc.Status == IncFalsePositive
}

// chainIndexLocked 把同一资产的不同标识合并（调用方持读锁）。
func (s *Store) chainIndexLocked() *chainIndex {
	ix := &chainIndex{byID: map[string]int{}}
	for _, tr := range s.chains {
		ix.list = append(ix.list, tr)
	}
	sort.Slice(ix.list, func(i, j int) bool {
		a, b := ix.list[i], ix.list[j]
		if kindRank(a.Kind) != kindRank(b.Kind) {
			return kindRank(a.Kind) < kindRank(b.Kind)
		}
		return a.Key < b.Key
	})
	for i, tr := range ix.list {
		if _, ok := ix.byID[tr.Key]; !ok {
			ix.byID[tr.Key] = i
		}
	}
	for i, tr := range ix.list { // 别名优先级低于真实标识
		for _, a := range tr.Aliases {
			if _, ok := ix.byID[a]; !ok {
				ix.byID[a] = i
			}
		}
	}
	parent := make([]int, len(ix.list))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	var links []struct {
		a, b int
		why  string
	}
	join := func(a, b int, why string) {
		if a == b {
			return
		}
		if ra, rb := find(a), find(b); ra != rb {
			parent[rb] = ra
		}
		links = append(links, struct {
			a, b int
			why  string
		}{a, b, why})
	}
	// 0. 同一资产的其他标识（台账资产被访问时的地址与域名、DNAT 前的公网地址）另有记录：如登记台账之前的数据
	for i, tr := range ix.list {
		for _, a := range tr.Aliases {
			for _, k := range [...]chainKey{{"host", a}, {"site", a}} {
				if o := s.chains[k]; o != nil {
					if j, ok := ix.byID[o.Key]; ok {
						join(i, j, a+" 是 "+tr.Key+" 的地址或域名")
					}
				}
			}
		}
	}
	// 1. Web 日志记录的服务器地址
	for i, tr := range ix.list {
		for _, srv := range tr.Servers {
			if j, ok := ix.byID[srv]; ok {
				join(i, j, "Web 日志记录的服务器地址为 "+srv)
			}
		}
	}
	// 2. 服务器回连的地址是攻击该站点的来源，或出现在针对该站点的攻击载荷中
	peerOf := map[string][]int{}
	for i, tr := range ix.list {
		for p := range tr.Peers {
			peerOf[p] = append(peerOf[p], i)
		}
	}
	for i, tr := range ix.list {
		for _, st := range tr.Steps {
			if st.Stage != stControl || st.Peer == "" || st.Severity < model.SevHigh || s.dismissedLocked(st) {
				continue
			}
			type cand struct {
				j       int
				payload bool
				last    int64
			}
			var cs []cand
			at := st.First.Unix()
			for _, j := range peerOf[st.Peer] {
				p := ix.list[j].Peers[st.Peer]
				if j == i || p == nil {
					continue
				}
				slack := int64(chainSlack / time.Second)
				switch {
				case p.Role&peerPayload != 0 && at >= p.First-slack && at <= p.Last+int64(payloadLinkWin/time.Second):
					cs = append(cs, cand{j, true, p.Last})
				case p.Role&peerAttacker != 0 && at >= p.First-slack && at <= p.Last+int64(callbackLinkWin/time.Second):
					cs = append(cs, cand{j, false, p.Last})
				}
			}
			if len(cs) > 3 {
				// 同一来源攻击过很多资产：只合并回连之前最近被它攻击的那一个
				sort.Slice(cs, func(a, b int) bool { return cs[a].last > cs[b].last })
				cs = cs[:1]
			}
			for _, c := range cs {
				why := "服务器回连的 " + st.Peer + " 对该站点发起过攻击"
				if c.payload {
					why = "服务器回连的 " + st.Peer + " 出现在针对该站点的攻击载荷中"
				}
				join(c.j, i, why)
			}
		}
	}
	root := map[int]int{}
	ix.of = make([]int, len(ix.list))
	for i := range ix.list {
		r := find(i)
		g, ok := root[r]
		if !ok {
			g = len(ix.groups)
			root[r] = g
			ix.groups = append(ix.groups, &chainGroup{})
		}
		ix.groups[g].tracks = append(ix.groups[g].tracks, ix.list[i])
		ix.of[i] = g
	}
	seen := map[string]bool{}
	for _, l := range links {
		a, b := ix.list[l.a].Key, ix.list[l.b].Key
		k := a + "|" + b + "|" + l.why
		if seen[k] {
			continue
		}
		seen[k] = true
		g := ix.groups[ix.of[l.a]]
		if len(g.links) < 20 {
			g.links = append(g.links, ChainLink{A: a, B: b, Reason: l.why})
		}
	}
	return ix
}

// chainEval 是一个资产的阶段与研判。
type chainEval struct {
	reached [stageN]bool
	weak    [stageN]bool // 出现过需核实的迹象（不计入阶段与研判）
	// internalOnly 表示越过侦察的攻击来源全部是内网地址（常是内部漏洞扫描、安全测试）
	internalOnly bool
	sev          [stageN]model.Severity
	hits         [stageN]int64
	first        [stageN]time.Time
	last         [stageN]time.Time
	srcs         map[string]uint16 // 攻击来源（不含资产自身）→ 出现过的阶段（位）
	conf         string
	maxSev       model.Severity
	depth        int
	hitsAll      int64
	firstT       time.Time
	lastT        time.Time
}

func (s *Store) evalLocked(g *chainGroup) *chainEval {
	e := &chainEval{srcs: map[string]uint16{}}
	var steps [stageN]int
	strong := false        // 单独即可判定失陷的证据
	var kinds [stageN]bool // 出现过的失陷迹象种类
	atkInt, atkExt := false, false
	for _, tr := range g.tracks {
		e.hitsAll += tr.Hits
		if e.firstT.IsZero() || tr.FirstSeen.Before(e.firstT) {
			e.firstT = tr.FirstSeen
		}
		if tr.LastSeen.After(e.lastT) {
			e.lastT = tr.LastSeen
		}
		for i := range tr.Stages {
			ss := tr.Stages[i]
			if ss.Hits == 0 {
				continue
			}
			e.hits[i] += ss.Hits
			if f := time.Unix(ss.First, 0); e.first[i].IsZero() || f.Before(e.first[i]) {
				e.first[i] = f
			}
			if l := time.Unix(ss.Last, 0); l.After(e.last[i]) {
				e.last[i] = l
			}
		}
		for _, st := range tr.Steps {
			steps[st.Stage]++
			if s.dismissedLocked(st) {
				continue
			}
			i := st.Stage
			if s.weakLocked(g, st) != "" {
				e.weak[i] = true
				continue
			}
			e.reached[i] = true
			e.sev[i] = max(e.sev[i], st.Severity)
			if st.Src != "" && !g.isSelf(st.Src) {
				e.srcs[st.Src] |= 1 << i
				if i >= stExploit && st.Category != "横向移动" { // 横向移动是另一台失陷主机发起的，不是内部扫描
					if geo.IsPrivate(st.Src) {
						atkInt = true
					} else {
						atkExt = true
					}
				}
			}
			// 与疑似失陷资产的口径一致：Web 只有带证据的命令执行、WebShell 等成功才单独判定；主机外连远控、
			// 安全设备报出恶意软件（高危以上）、暴力破解后登录成功、清除日志 / 加入管理员组单独判定
			switch i {
			case stBreach:
				strong = strong || st.Proven && highImpact[st.Category] || st.Rule == "auth-brute-ok"
				// 敏感文件确实可以下载是已验证的暴露面，不说明服务器已被控制（与疑似失陷资产的口径一致）
				kinds[i] = kinds[i] || st.Category != "敏感文件探测" || st.Proven
			case stPersist:
				strong = strong || st.Proven || st.Severity >= model.SevHigh && st.Category != "WebShell后门"
				kinds[i] = true
			case stControl:
				strong = strong || st.Severity >= model.SevHigh
				kinds[i] = kinds[i] || st.Severity >= model.SevMedium
			case stLateral:
				// 内网扫描可能来自运维人员或漏洞扫描器，只有大范围的才算一种迹象
				kinds[i] = kinds[i] || st.Severity >= model.SevHigh
			}
		}
	}
	// 阶段的步骤全部因上限未单独记录时，以累计为准
	for i := range e.reached {
		if steps[i] == 0 && e.hits[i] > 0 {
			e.reached[i] = true
			for _, tr := range g.tracks {
				e.sev[i] = max(e.sev[i], tr.Stages[i].Sev)
			}
		}
		if e.reached[i] {
			e.maxSev = max(e.maxSev, e.sev[i])
			if i > 0 {
				e.depth = i
			}
		}
	}
	n := 0
	for _, k := range kinds {
		if k {
			n++
		}
	}
	switch {
	case strong || n >= 2:
		e.conf = "high"
	case n == 1:
		e.conf = "medium"
	}
	e.internalOnly = atkInt && !atkExt && e.conf == "" // 已有失陷迹象时不提示登记授权扫描
	return e
}

// isSelf 判断地址是不是资产自身的标识（资产自身发起的步骤、主机自身的事件不算攻击来源）。
func (g *chainGroup) isSelf(ip string) bool {
	for _, tr := range g.tracks {
		if tr.Key == ip {
			return true
		}
		for _, a := range tr.Aliases {
			if a == ip {
				return true
			}
		}
	}
	return false
}

// stageSources 返回在该阶段出现过的攻击来源数。
func (e *chainEval) stageSources(i int) int {
	n := 0
	for _, b := range e.srcs {
		if b&(1<<i) != 0 {
			n++
		}
	}
	return n
}

// title 返回合并后资产的名称：台账资产 > 站点 > 主机，同类按命中多的。
func (g *chainGroup) title() *chainTrack {
	rank := func(tr *chainTrack) int {
		if fakeSite(tr) {
			return 3 // 虚构的站点名（旧版本按 Host 头记录）排在服务器地址之后
		}
		return kindRank(tr.Kind)
	}
	best := g.tracks[0]
	for _, tr := range g.tracks[1:] {
		if rank(tr) < rank(best) || rank(tr) == rank(best) && tr.Hits > best.Hits {
			best = tr
		}
	}
	return best
}

func stagePath(e *chainEval) string {
	var names []string
	for i, r := range e.reached {
		if r {
			names = append(names, ChainStages[i].Name)
		}
	}
	return strings.Join(names, " → ")
}

func (s *Store) summaryLocked(g *chainGroup, e *chainEval) ChainSummary {
	t := g.title()
	sm := ChainSummary{Key: t.Key, Name: t.Key, Kind: t.Kind, Asset: t.Asset, Severity: e.maxSev, Confidence: e.conf,
		Hits: e.hitsAll, Sources: len(e.srcs), FirstSeen: e.firstT, LastSeen: e.lastT, Reached: []string{}, Depth: ChainStages[e.depth].ID}
	for _, tr := range g.tracks {
		sm.Members = append(sm.Members, tr.Key)
		if assetRank(tr.Level) > assetRank(sm.Level) {
			sm.Level, sm.Owner = tr.Level, tr.Owner
		}
		if sm.Asset == "" {
			sm.Asset = tr.Asset
		}
	}
	var weak []string
	for i, r := range e.reached {
		if r {
			sm.Reached = append(sm.Reached, ChainStages[i].ID)
		} else if e.weak[i] {
			sm.Weak = append(sm.Weak, ChainStages[i].ID)
			weak = append(weak, ChainStages[i].Name)
		}
	}
	path := stagePath(e)
	deep := ChainStages[e.depth].Name
	switch {
	case e.conf == "high":
		sm.Verdict = "攻击已推进到「" + deep + "」阶段（" + path + "），研判为已失陷（高置信），需立即处置"
	case e.conf == "medium":
		sm.Verdict = "攻击已推进到「" + deep + "」阶段（" + path + "），疑似失陷，需结合主机核实"
	case e.depth == 0 && e.reached[stRecon]:
		sm.Verdict = "只有侦察：被扫描探测，未见进一步攻击"
	case e.depth == 0 && len(weak) > 0:
		sm.Verdict = "未见攻击推进：只有需核实的迹象（" + strings.Join(weak, "、") + "），不判为失陷"
		weak = nil
	case e.depth == 0:
		sm.Verdict = "命中均已被标为误报"
	case e.reached[stBreach]: // 没有失陷迹象的突破只有敏感文件可下载
		sm.Verdict = "攻击推进到「" + deep + "」阶段（" + path + "），有敏感资源可被访问，未见失陷迹象"
	default:
		sm.Verdict = "攻击推进到「" + deep + "」阶段（" + path + "），未见攻击成功或失陷迹象"
	}
	if len(weak) > 0 {
		sm.Verdict += "；「" + strings.Join(weak, "、") + "」只有需核实的迹象，不计入"
	}
	if e.internalOnly && e.depth >= stExploit {
		sm.InternalOnly = true
		sm.Verdict += "；越过侦察的攻击都来自内网地址，如是内部漏洞扫描请登记为授权扫描"
	}
	return sm
}

// ChainList 返回资产攻击链路列表：按失陷研判、推进深度、等级、最近活动排序。只为返回的这一页生成摘要。
func (s *Store) ChainList(q ChainQuery) *ChainList {
	if q.Limit <= 0 || q.Limit > chainListMax {
		q.Limit = 100
	}
	search := strings.ToLower(strings.TrimSpace(q.Search))
	minStage := stageIndex(q.Stage)
	s.mu.RLock()
	defer s.mu.RUnlock()
	ix := s.chainIndexLocked()
	out := &ChainList{Stages: ChainStages[:], Chains: []ChainSummary{}, Tracked: len(ix.list),
		Counts: map[string]int{}, Compromised: map[string]int{"high": 0, "medium": 0}}
	type item struct {
		g   *chainGroup
		e   *chainEval
		key string
	}
	items := make([]item, 0, len(ix.groups))
	for _, g := range ix.groups {
		if g.fakeGroup() {
			out.Tracked -= len(g.tracks)
			continue // 只有虚构站点名的记录（旧版本按 Host 头记录）：不是资产
		}
		e := s.evalLocked(g)
		for i, r := range e.reached {
			if r {
				out.Counts[ChainStages[i].ID]++
			}
		}
		if e.conf != "" {
			out.Compromised[e.conf]++
		}
		if minStage > 0 && e.depth < minStage || q.Compromised && e.conf == "" || search != "" && !chainMatch(g, search) {
			continue
		}
		items = append(items, item{g, e, g.title().Key})
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if ca, cb := confRank(a.e.conf), confRank(b.e.conf); ca != cb {
			return ca > cb
		}
		if a.e.depth != b.e.depth {
			return a.e.depth > b.e.depth
		}
		if a.e.maxSev != b.e.maxSev {
			return a.e.maxSev > b.e.maxSev
		}
		if !a.e.lastT.Equal(b.e.lastT) {
			return a.e.lastT.After(b.e.lastT)
		}
		return a.key < b.key
	})
	out.Total = len(items)
	for i := 0; i < len(items) && i < q.Limit; i++ {
		out.Chains = append(out.Chains, s.summaryLocked(items[i].g, items[i].e))
	}
	return out
}

func confRank(c string) int {
	switch c {
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}

func chainMatch(g *chainGroup, q string) bool {
	for _, tr := range g.tracks {
		if strings.Contains(strings.ToLower(tr.Key), q) || strings.Contains(strings.ToLower(tr.Asset), q) {
			return true
		}
		for _, a := range tr.Aliases {
			if strings.Contains(strings.ToLower(a), q) {
				return true
			}
		}
	}
	return false
}

// resolve 按资产标识查找：精确、别名、站点域名归一化后，以及“站点/路径”形式的攻击面资产。
func (ix *chainIndex) resolve(id string) (int, bool) {
	id = strings.TrimSpace(id)
	if i, ok := ix.byID[id]; ok {
		return i, true
	}
	h := id
	if k := strings.IndexAny(h, "/ "); k > 0 {
		h = h[:k]
	}
	if i, ok := ix.byID[chainHost(h)]; ok {
		return i, true
	}
	return 0, false
}

func techsOf(cat string) []ChainTech {
	var out []ChainTech
	for _, id := range categoryTechniques[cat] {
		if t, ok := techniques[id]; ok {
			out = append(out, ChainTech{ID: t.ID, Name: t.Name})
		}
	}
	return out
}

// AssetChain 返回资产的完整攻击链路，id 可以是资产名称、站点域名或主机地址；不存在时返回 nil。
func (s *Store) AssetChain(id string) *AssetChain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ix := s.chainIndexLocked()
	i, ok := ix.resolve(id)
	if !ok {
		return nil
	}
	g := ix.groups[ix.of[i]]
	e := s.evalLocked(g)
	c := &AssetChain{ChainSummary: s.summaryLocked(g, e), Links: g.links, Advice: []string{}}
	self := map[string]bool{}
	for _, tr := range g.tracks {
		self[tr.Key] = true
		for _, a := range tr.Aliases {
			self[a] = true
		}
		c.MemberInfo = append(c.MemberInfo, ChainMember{Key: tr.Key, Kind: tr.Kind, Asset: tr.Asset, Hits: tr.Hits, FirstSeen: tr.FirstSeen, LastSeen: tr.LastSeen})
		c.Dropped += tr.Dropped
	}
	sort.Slice(c.MemberInfo, func(a, b int) bool { return c.MemberInfo[a].Hits > c.MemberInfo[b].Hits })

	// 步骤
	type ref struct {
		tr *chainTrack
		st *chainStep
	}
	var all []ref
	for _, tr := range g.tracks {
		for _, st := range tr.Steps {
			all = append(all, ref{tr, st})
		}
	}
	c.StepsTotal = len(all)
	if len(all) > chainViewSteps {
		// 步骤很多时优先保留更深的阶段，侦察按命中次数保留
		sort.Slice(all, func(a, b int) bool {
			x, y := all[a].st, all[b].st
			if (x.Stage == stRecon) != (y.Stage == stRecon) {
				return x.Stage != stRecon
			}
			if x.Severity != y.Severity {
				return x.Severity > y.Severity
			}
			return x.Count > y.Count
		})
		all = all[:chainViewSteps]
	}
	view := func(r ref) ChainStepView {
		st := r.st
		v := ChainStepView{Stage: ChainStages[st.Stage].ID, StageName: ChainStages[st.Stage].Name, Asset: r.tr.Key, Category: st.Category,
			Rule: st.Rule, Name: st.Name, Src: st.Src, Peer: st.Peer, Target: st.Target, Evidence: st.Evidence, Severity: st.Severity,
			Result: st.Result, Proven: st.Proven, First: st.First, Last: st.Last, Count: st.Count, Techniques: techsOf(st.Category),
			Alert: st.Alert, Incident: st.Incident, Dismissed: s.dismissedLocked(st)}
		if !v.Dismissed {
			v.Weak = s.weakLocked(g, st)
		}
		v.Self = self[st.Src] || st.Peer != "" && (st.Stage == stControl || st.Stage == stLateral)
		if st.Src == "" {
			v.SrcLabel = noSourceLabel // 设备只记录了目的地址的多源洪泛
		} else if geo.IsPrivate(st.Src) {
			v.Internal, v.SrcLabel = true, "内网主机"
		} else if p := s.ips[st.Src]; p != nil && p.Geo != nil {
			v.SrcLabel = p.Geo.Location()
		}
		return v
	}
	for _, r := range all {
		c.Steps = append(c.Steps, view(r))
	}
	sort.SliceStable(c.Steps, func(a, b int) bool {
		if !c.Steps[a].First.Equal(c.Steps[b].First) {
			return c.Steps[a].First.Before(c.Steps[b].First)
		}
		return stageIndex(c.Steps[a].Stage) < stageIndex(c.Steps[b].Stage)
	})

	// 阶段
	for i := 0; i < stageN; i++ {
		sv := ChainStageView{StageDef: ChainStages[i], Reached: e.reached[i], Weak: e.weak[i] && !e.reached[i], Hits: e.hits[i], Severity: e.sev[i], Sources: e.stageSources(i)}
		if e.hits[i] > 0 {
			sv.First, sv.Last = e.first[i], e.last[i]
		}
		seenT := map[string]bool{}
		for _, v := range c.Steps {
			if v.Stage != sv.ID || v.Dismissed {
				continue
			}
			for _, t := range v.Techniques {
				if !seenT[t.ID] && len(sv.Techniques) < 6 {
					seenT[t.ID] = true
					sv.Techniques = append(sv.Techniques, t)
				}
			}
		}
		c.Stages = append(c.Stages, sv)
	}

	// 关键路径：每个推进到的阶段选一步。主要攻击者优先：服务器回连的正是它、或回连地址写在它的攻击载荷中，
	// 其次是突破、植入成功的来源；其他阶段也优先选它们的步骤，串起一次完整的入侵
	var ctrl []string
	for _, v := range c.Steps {
		if v.counted() && v.Stage == "control" && v.Peer != "" {
			ctrl = append(ctrl, v.Peer)
		}
	}
	key, prime := map[string]bool{}, map[string]bool{}
	for _, v := range c.Steps {
		if !v.counted() || v.Self {
			continue
		}
		if v.Stage == "breach" || v.Stage == "persist" {
			key[v.Src] = true
		}
		for _, p := range ctrl {
			if v.Src == p || v.Stage != "recon" && strings.Contains(v.Target, p) {
				prime[v.Src] = true
			}
		}
	}
	better := func(a, b *ChainStepView) bool { // a 是否比 b 更适合作为该阶段的代表
		if pa, pb := prime[a.Src] && !a.Self, prime[b.Src] && !b.Self; pa != pb {
			return pa
		}
		if ka, kb := key[a.Src] && !a.Self, key[b.Src] && !b.Self; ka != kb {
			return ka
		}
		if ra, rb := hitRank(a.Severity, a.Result, a.Proven), hitRank(b.Severity, b.Result, b.Proven); ra != rb {
			return ra > rb
		}
		return a.First.Before(b.First)
	}
	for i := 0; i < stageN; i++ {
		var best *ChainStepView
		for k := range c.Steps {
			v := &c.Steps[k]
			if v.Stage == ChainStages[i].ID && v.counted() && (best == nil || better(v, best)) {
				best = v
			}
		}
		if best != nil {
			c.Path = append(c.Path, *best)
		}
	}
	sort.SliceStable(c.Path, func(a, b int) bool { return stageIndex(c.Path[a].Stage) < stageIndex(c.Path[b].Stage) })

	// 攻击来源
	srcs := map[string]*ChainSource{}
	for _, v := range c.Steps {
		if v.Self || !v.counted() || v.Src == "" {
			continue
		}
		x := srcs[v.Src]
		if x == nil {
			x = &ChainSource{IP: v.Src, Internal: v.Internal, First: v.First, Last: v.Last, Location: v.SrcLabel}
			if p := s.ips[v.Src]; p != nil {
				x.Score = p.Score
			}
			srcs[v.Src] = x
		}
		x.Hits += v.Count
		x.Severity = max(x.Severity, v.Severity)
		if v.First.Before(x.First) {
			x.First = v.First
		}
		if v.Last.After(x.Last) {
			x.Last = v.Last
		}
		x.Stages = addUnique(x.Stages, v.Stage, stageN)
	}
	for _, x := range srcs {
		sort.Slice(x.Stages, func(a, b int) bool { return stageIndex(x.Stages[a]) < stageIndex(x.Stages[b]) })
		c.SourceList = append(c.SourceList, *x)
	}
	sort.Slice(c.SourceList, func(a, b int) bool {
		x, y := c.SourceList[a], c.SourceList[b]
		if dx, dy := stageIndex(x.Stages[len(x.Stages)-1]), stageIndex(y.Stages[len(y.Stages)-1]); dx != dy {
			return dx > dy
		}
		if x.Severity != y.Severity {
			return x.Severity > y.Severity
		}
		return x.Hits > y.Hits
	})
	if len(c.SourceList) > 50 {
		c.SourceList = c.SourceList[:50]
	}
	c.Advice = chainAdvice(c, e)
	return c
}

// chainAdvice 按推进到的阶段给出处置建议。
func chainAdvice(c *AssetChain, e *chainEval) []string {
	var out []string
	hosts, peers, laterals, breachTargets := []string{}, []string{}, []string{}, []string{}
	for _, m := range c.MemberInfo {
		if m.Kind == "host" {
			hosts = addUnique(hosts, m.Key, 3)
		}
	}
	var attackers, weak, weakHosts []string
	for _, v := range c.Steps {
		if v.Dismissed {
			continue
		}
		if v.Weak != "" {
			weak = addUnique(weak, "「"+v.StageName+"」"+v.Name+"："+v.Weak, 4)
			if v.Self {
				weakHosts = addUnique(weakHosts, v.Src, 3)
			}
			continue
		}
		switch v.Stage {
		case "control":
			peers = addUnique(peers, v.Peer, 5)
			hosts = addUnique(hosts, v.Src, 3)
		case "lateral":
			laterals = addUnique(laterals, v.Peer, 5)
			hosts = addUnique(hosts, v.Src, 3)
		case "breach", "persist":
			breachTargets = addUnique(breachTargets, v.Target, 3)
		}
	}
	for _, x := range c.SourceList {
		if !x.Internal && stageIndex(x.Stages[len(x.Stages)-1]) >= stExploit {
			attackers = addUnique(attackers, x.IP, 5)
		}
	}
	who := c.Name
	if len(hosts) > 0 {
		who = strings.Join(hosts, "、")
	}
	// 只有横向（内网暴力破解等）、没有失陷迹象时不要求隔离：先核实发起方
	if e.reached[stControl] || e.reached[stLateral] && e.conf != "" || e.conf == "high" {
		out = append(out, "立即隔离 "+who+"（断开外网或迁移到隔离区），保全内存与日志后再排查，避免攻击者察觉后清理痕迹")
	}
	if e.reached[stControl] && len(peers) > 0 {
		out = append(out, "排查 "+who+" 上连接 "+strings.Join(peers, "、")+" 的进程、计划任务、自启动项与新增账号；在出口防火墙与 DNS 封禁这些地址 / 域名")
	}
	if e.reached[stLateral] && len(laterals) > 0 {
		out = append(out, "核查被横向访问的内网主机 "+strings.Join(laterals, "、")+" 的登录记录与新增进程，按同样的方法排查是否已被控制")
	}
	if e.reached[stPersist] {
		out = append(out, "清除 WebShell 与后门账号：核对网站目录中新增、修改的脚本文件与系统账号，修改相关账号口令")
	}
	if e.reached[stBreach] {
		t := ""
		if len(breachTargets) > 0 {
			t = "（" + strings.Join(breachTargets, "；") + "）"
		}
		out = append(out, "确认被成功利用的接口"+t+"对应的漏洞并修复，回溯成功请求前后的原始日志确认攻击者的后续操作")
	}
	if e.reached[stCollect] {
		out = append(out, "评估被遍历、爬取的接口涉及的数据范围，补充越权校验与访问频率限制；涉及个人信息时按要求评估是否需要报告")
	}
	if e.reached[stImpact] {
		out = append(out, "对受影响的服务开启限流、人机校验或接入抗 D 服务，确认业务是否已恢复")
	}
	if len(attackers) > 0 {
		out = append(out, "封禁对该资产发起利用的来源 "+strings.Join(attackers, "、")+"，并在攻击活动中查看是否有同一攻击者的其他地址")
	}
	if c.InternalOnly {
		out = append(out, "越过侦察的攻击都来自内网地址：如是内部漏洞扫描或安全测试，在「授权扫描」中登记扫描器地址与时间窗口，之后不再告警、不计入链路；不是的话按内网主机失陷排查发起方")
	}
	if len(weak) > 0 {
		w := ""
		if len(weakHosts) > 0 {
			w = "（在 " + strings.Join(weakHosts, "、") + " 上）"
		}
		out = append(out, "需核实"+w+"："+strings.Join(weak, "；")+"。确认是正常业务后把对应事件标为误报（自学习据此校准同类告警），无法解释时再按失陷排查")
	}
	if len(out) == 0 {
		out = append(out, "只有侦察：确认暴露的端口与路径确有必要对外开放，关闭不必要的服务；被频繁探测的敏感路径在 WAF 中加入拦截")
	}
	return out
}

// chainTracks 返回全部资产标识的记录（快照保存用，调用方持读锁）。
func (s *Store) chainTracks() []*chainTrack {
	out := make([]*chainTrack, 0, len(s.chains))
	for _, tr := range s.chains {
		out = append(out, tr)
	}
	return out
}
