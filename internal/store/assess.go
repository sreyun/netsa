package store

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"netsa/internal/model"
)

// Visibility 是评估“日志与检测覆盖”所需的部署信息，由 API 层根据配置与运行状态提供。
type Visibility struct {
	ParseRate     float64 // 日志解析成功率（0~1），没有日志时为 1
	PreciseGeo    bool    // 已配置 MaxMind 或在线溯源（精确坐标与 ASN）
	Intel         int     // 已配置的威胁情报源数（黑名单文件、Tor 出口节点列表）
	Robots        int     // 已启用的告警推送机器人
	Archive       bool    // 已启用告警长期归档
	AuthEnabled   bool    // 已开启登录认证
	HTTPS         bool    // 以 HTTPS 提供服务
	AllowNetworks bool    // 已限制管理访问来源
}

// Metric 是评估维度中的一项指标。
type Metric struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Level string `json:"level,omitempty"` // good / warn / risk
}

// Check 是可见性评估中的一项检查。
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Weight int    `json:"weight"`
	Advice string `json:"advice,omitempty"`
}

// Dimension 是一个评估维度。
type Dimension struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	Weight  int      `json:"weight"`
	Score   int      `json:"score"` // 0~100，越高越安全；-1 表示缺少数据无法评估
	Level   string   `json:"level"` // good / warn / risk / na
	Summary string   `json:"summary"`
	Metrics []Metric `json:"metrics"`
	Advice  []string `json:"advice"`
	Checks  []Check  `json:"checks,omitempty"`
}

// Drill 描述处置建议对应的明细位置（前端据此跳转并带上筛选条件）。
type Drill struct {
	Tab    string            `json:"tab"` // attackers / alerts / surface / sources / ip
	Params map[string]string `json:"params,omitempty"`
	Label  string            `json:"label,omitempty"`
}

// Action 是一条处置建议。
type Action struct {
	Priority  string   `json:"priority"` // P0 紧急 / P1 高 / P2 中 / P3 低
	Dimension string   `json:"dimension"`
	Title     string   `json:"title"`
	Reason    string   `json:"reason"`
	Steps     []string `json:"steps"`
	Drill     *Drill   `json:"drill,omitempty"`
}

// Assessment 是安全防护评估结果。
type Assessment struct {
	Score       int            `json:"score"`       // 0~100，越高越安全
	Grade       string         `json:"grade"`       // A~E
	GradeLabel  string         `json:"grade_label"` // 优秀 / 良好 / 一般 / 较差 / 危险
	Verdict     string         `json:"verdict"`     // 一句话结论
	Dimensions  []*Dimension   `json:"dimensions"`
	Actions     []*Action      `json:"actions"`
	ActionCount map[string]int `json:"action_count"`
	Compromised []*Compromised `json:"compromised"`
	Matrix      *AttackMatrix  `json:"matrix"`
	History     []ScorePoint   `json:"history"` // 评分趋势（每小时一次，最近 30 天）
	From        time.Time      `json:"from"`
	To          time.Time      `json:"to"`
	GeneratedAt time.Time      `json:"generated_at"`
}

// assessData 是在读锁内收集的评估所需数据。
type assessData struct {
	totals                                     Totals
	from, to                                   time.Time
	comp                                       []*Compromised
	exposure                                   []*Finding // 敏感资源暴露、服务暴露
	services                                   []*Service // 对公网开放的服务
	endpoints, probedPorts                     int
	exploitBlocked, exploitPassed              int64
	passedCats                                 []KV // 未被拦截的漏洞利用类攻击（按类型）
	brute, bruteHits, bruteSuccess             int64
	activeHigh, intelHits, scanners, ccSources int
	portScanners                               int
	threatIndex                                float64
	matrix                                     *AttackMatrix
}

func (s *Store) collectAssessLocked() *assessData {
	d := &assessData{totals: s.totals, from: s.minTime, to: s.maxTime, comp: s.compromisedLocked(),
		endpoints: len(s.surf.Endpoints), probedPorts: len(s.surf.Ports), exploitBlocked: s.surf.ExploitBlocked, exploitPassed: s.surf.ExploitPassed,
		bruteHits: s.categories["暴力破解"]}
	for _, f := range s.surf.Findings {
		switch {
		case f.Category == "敏感资源暴露" || f.Category == "服务暴露":
			c := *f
			d.exposure = append(d.exposure, &c)
		case f.Category == "攻击成功研判" && strings.Contains(f.Title, "暴力破解"):
			d.bruteSuccess++
		}
	}
	sort.Slice(d.exposure, func(i, j int) bool {
		if d.exposure[i].Severity != d.exposure[j].Severity {
			return d.exposure[i].Severity > d.exposure[j].Severity
		}
		return d.exposure[i].Count > d.exposure[j].Count
	})
	for _, sv := range s.surf.Services {
		if sv.Exposed && sv.Risk >= model.SevMedium {
			c := *sv
			d.services = append(d.services, &c)
		}
	}
	sort.Slice(d.services, func(i, j int) bool { return d.services[i].Risk > d.services[j].Risk })
	recentCut := s.maxTime.Add(-time.Hour)
	// 一次遍历画像同时完成各项计数与 ATT&CK 矩阵累计；每个画像只遍历自身的攻击类型，不按名称逐个查表
	var acc matrixAcc
	for _, p := range s.ips {
		if !isAttacker(p) {
			continue
		}
		if p.LastSeen.After(recentCut) && p.Level >= model.SevHigh {
			d.activeHigh++
		}
		if len(p.Intel) > 0 {
			d.intelHits++
		}
		var brute, scan, cc, port bool
		for cat := range p.Categories {
			switch cat {
			case "暴力破解":
				brute = true
			case "扫描器", "网络空间测绘", "目录扫描":
				scan = true
			case "CC攻击", "洪水攻击":
				cc = true
			case "端口扫描", "主机探测", "高危服务探测":
				port = true
			}
			acc.category(cat, p.CatSev[cat])
		}
		acc.done()
		d.brute += int64(b2i(brute))
		d.scanners += b2i(scan)
		d.ccSources += b2i(cc)
		d.portScanners += b2i(port)
	}
	d.matrix = s.buildMatrixLocked(&acc)
	var weighted float64
	cut := recentCut.Unix() / 60
	for k, b := range s.buckets {
		if k >= cut {
			weighted += bucketWeight(b)
		}
	}
	d.threatIndex = threatIndex(weighted)
	// 未被拦截的漏洞利用类告警按攻击类型统计（用于给出虚拟补丁建议）
	passed := map[string]int64{}
	for _, a := range s.alerts {
		if a.Phase != model.PhaseRecon && (a.Result == model.ResultPassed || a.Result == model.ResultSuccess || a.Result == model.ResultError) {
			passed[a.Category]++
		}
	}
	d.passedCats = topN(passed, 3, ident)
	return d
}

// Assess 进行安全防护评估：从失陷风险、暴露面、Web 防护、凭证安全、边界防护、威胁活跃度、
// 日志与检测覆盖七个维度打分，给出总评与按优先级排序的处置建议。
func (s *Store) Assess(v Visibility) *Assessment {
	s.mu.RLock()
	d := s.collectAssessLocked()
	history := append([]ScorePoint{}, s.scores...)
	s.mu.RUnlock()

	a := &Assessment{Compromised: d.comp, Matrix: d.matrix, From: d.from, To: d.to, GeneratedAt: time.Now(), ActionCount: map[string]int{}, History: history}
	if a.Compromised == nil {
		a.Compromised = []*Compromised{}
	}
	a.Dimensions = []*Dimension{d.compromise(), d.exposureDim(), d.webDefense(), d.credential(), d.perimeter(), d.threat(), d.visibility(v)}
	total, weight := 0, 0
	for _, dim := range a.Dimensions {
		if dim.Score >= 0 {
			total += dim.Score * dim.Weight
			weight += dim.Weight
		}
		dim.Level = levelOf(dim.Score)
	}
	if weight > 0 {
		a.Score = int(math.Round(float64(total) / float64(weight)))
	}
	// 一票否决：存在高置信失陷时总评不高于“危险”，存在疑似失陷或严重暴露面时不高于“较差”
	high, med := countConfidence(d.comp)
	critExposure := countSev(d.exposure, model.SevCritical) + countServices(d.services, model.SevCritical)
	switch {
	case high > 0:
		a.Score = min(a.Score, 35)
	case med > 0 || critExposure > 0:
		a.Score = min(a.Score, 59)
	}
	a.Grade, a.GradeLabel = grade(a.Score)
	a.Actions = d.actions(v, a.Dimensions)
	for _, act := range a.Actions {
		a.ActionCount[act.Priority]++
	}
	switch {
	case high > 0:
		a.Verdict = fmt.Sprintf("发现 %d 个高置信疑似失陷资产，安全状况危险，请立即按 P0 建议启动应急响应", high)
	case med > 0:
		a.Verdict = fmt.Sprintf("发现 %d 个疑似攻击成功的资产，需尽快核查确认是否已失陷", med)
	case critExposure > 0:
		a.Verdict = fmt.Sprintf("未发现失陷迹象，但存在 %d 项严重暴露面，攻击者可直接利用，请优先处置", critExposure)
	case a.ActionCount["P1"] > 0:
		a.Verdict = fmt.Sprintf("未发现失陷迹象，有 %d 项高优先级加固建议待处置", a.ActionCount["P1"])
	case a.Score >= 90:
		a.Verdict = "未发现失陷迹象与严重暴露面，整体防护状况良好，请保持监测"
	default:
		a.Verdict = "未发现失陷迹象，按建议持续加固可进一步降低风险"
	}
	return a
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func levelOf(score int) string {
	switch {
	case score < 0:
		return "na"
	case score >= 80:
		return "good"
	case score >= 60:
		return "warn"
	}
	return "risk"
}

func grade(score int) (string, string) {
	switch {
	case score >= 90:
		return "A", "优秀"
	case score >= 75:
		return "B", "良好"
	case score >= 60:
		return "C", "一般"
	case score >= 40:
		return "D", "较差"
	}
	return "E", "危险"
}

func clamp100(v float64) int { return int(math.Round(math.Max(0, math.Min(100, v)))) }

func countConfidence(cs []*Compromised) (high, med int) {
	for _, c := range cs {
		if c.Confidence == "high" {
			high++
		} else {
			med++
		}
	}
	return
}

func countSev(fs []*Finding, sev model.Severity) int {
	n := 0
	for _, f := range fs {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func countServices(ss []*Service, sev model.Severity) int {
	n := 0
	for _, s := range ss {
		if s.Risk == sev {
			n++
		}
	}
	return n
}

func metricLevel(bad bool, warn bool) string {
	switch {
	case bad:
		return "risk"
	case warn:
		return "warn"
	}
	return "good"
}

func num(n int64) string { return fmt.Sprintf("%d", n) }

// ---------------- 各维度 ----------------

func (d *assessData) compromise() *Dimension {
	high, med := countConfidence(d.comp)
	hosts := 0
	for _, c := range d.comp {
		if c.Kind == "host" {
			hosts++
		}
	}
	dim := &Dimension{Key: "compromise", Name: "失陷风险", Weight: 25, Score: clamp100(100 - 45*float64(high) - 20*float64(med)),
		Metrics: []Metric{
			{"疑似失陷资产", num(int64(len(d.comp))), metricLevel(high > 0, med > 0)},
			{"其中高置信", num(int64(high)), metricLevel(high > 0, false)},
			{"外连恶意地址的主机", num(int64(hosts)), metricLevel(hosts > 0, false)},
			{"疑似攻击成功", num(d.totals.Success) + " 次", metricLevel(false, d.totals.Success > 0)},
		}}
	switch {
	case high > 0:
		dim.Summary = fmt.Sprintf("发现 %d 个高置信疑似失陷资产（WebShell 交互、命令执行成功或外连恶意地址），需立即应急响应", high)
		dim.Advice = []string{"立即隔离受影响的主机或下线受影响的服务，保留日志、内存与磁盘镜像用于取证",
			"排查 Web 目录中近期新增 / 修改的脚本、异常进程、计划任务、自启动项与新增账号",
			"修复被利用的漏洞后再恢复服务，并轮换服务器、数据库与应用的全部凭证"}
	case med > 0:
		dim.Summary = fmt.Sprintf("发现 %d 个资产存在疑似攻击成功的记录，需核查是否真实成功", med)
		dim.Advice = []string{"根据告警证据复核对应接口的响应内容与服务器日志，确认攻击是否成功",
			"对确认存在漏洞的接口尽快修复，修复前通过 WAF 规则临时拦截"}
	default:
		dim.Summary = "未发现攻击成功或外连恶意地址等失陷迹象"
		dim.Advice = []string{"保持监测；建议配置威胁情报以启用内网主机外连恶意地址检测"}
	}
	return dim
}

func (d *assessData) exposureDim() *Dimension {
	penalty := map[model.Severity]float64{model.SevCritical: 30, model.SevHigh: 15, model.SevMedium: 6, model.SevLow: 2}
	score := 100.0
	sens, svc, admin := 0, 0, 0
	for _, f := range d.exposure {
		score -= penalty[f.Severity]
		if f.Category == "服务暴露" {
			svc++
		} else {
			sens++
			if strings.Contains(f.Title, "管理后台") {
				admin++
			}
		}
	}
	crit := countSev(d.exposure, model.SevCritical)
	dim := &Dimension{Key: "exposure", Name: "暴露面", Weight: 20, Score: clamp100(score),
		Metrics: []Metric{
			{"敏感资源可公开访问", num(int64(sens)), metricLevel(crit > 0, sens > 0)},
			{"高危服务对公网开放", num(int64(svc)), metricLevel(countServices(d.services, model.SevCritical) > 0, svc > 0)},
			{"管理后台对外暴露", num(int64(admin)), metricLevel(false, admin > 0)},
			{"Web 资产入口", num(int64(d.endpoints)), ""},
		}}
	if len(d.exposure) == 0 {
		dim.Summary = "未发现敏感资源泄露或高危服务对公网开放"
		dim.Advice = []string{"定期复核攻击面分析中的 Web 资产与网络服务清单，及时下线不再使用的入口"}
		return dim
	}
	dim.Summary = fmt.Sprintf("发现 %d 项暴露面风险（严重 %d 项），攻击者无需漏洞即可获取敏感信息或直接访问内部服务", len(d.exposure), crit)
	seen := map[string]bool{}
	for _, f := range d.exposure {
		if !seen[f.Remediation] && len(dim.Advice) < 4 {
			seen[f.Remediation] = true
			dim.Advice = append(dim.Advice, f.Title+"："+f.Remediation)
		}
	}
	return dim
}

func (d *assessData) webDefense() *Dimension {
	dim := &Dimension{Key: "web", Name: "Web 防护", Weight: 15}
	if d.totals.Web == 0 {
		dim.Score, dim.Summary = -1, "未接入 Web 访问日志，无法评估 Web 防护能力"
		dim.Advice = []string{"接入 nginx / Apache / IIS 等 Web 服务器的访问日志"}
		return dim
	}
	total := d.exploitBlocked + d.exploitPassed
	webSucc := int64(0)
	for _, c := range d.comp {
		if c.Kind == "web" {
			webSucc++
		}
	}
	rate := 1.0
	if total > 0 {
		rate = float64(d.exploitBlocked) / float64(total)
	}
	dim.Metrics = []Metric{
		{"漏洞利用类请求", num(total) + " 次", ""},
		{"拦截率", fmt.Sprintf("%.1f%%", rate*100), metricLevel(total >= 20 && rate < 0.5, total >= 20 && rate < 0.8)},
		{"未拦截", num(d.exploitPassed) + " 次", metricLevel(false, d.exploitPassed > 0)},
		{"攻击成功的 Web 资产", num(webSucc), metricLevel(webSucc > 0, false)},
	}
	if total < 20 {
		dim.Score = clamp100(90 - 15*float64(webSucc))
		dim.Summary = fmt.Sprintf("漏洞利用类请求较少（%d 次），暂不足以准确评估拦截效果", total)
		dim.Advice = []string{"持续观察；建议在 Web 服务器前部署 WAF 并开启拦截模式"}
		return dim
	}
	dim.Score = clamp100(rate*100 - 15*float64(webSucc))
	dim.Summary = fmt.Sprintf("漏洞利用类请求 %d 次，拦截率 %.1f%%", total, rate*100)
	if rate < 0.8 {
		dim.Summary += "，大量攻击请求直接到达后端应用"
		dim.Advice = append(dim.Advice, "部署 WAF（ModSecurity + OWASP CRS、云 WAF 或网关 WAF）并开启拦截模式，而非仅检测")
		if len(d.passedCats) > 0 {
			var names []string
			for _, kv := range d.passedCats {
				names = append(names, kv.Name)
			}
			dim.Advice = append(dim.Advice, "针对未拦截最多的攻击类型（"+strings.Join(names, "、")+"）添加虚拟补丁规则")
		}
	}
	dim.Advice = append(dim.Advice, "及时升级存在已知漏洞的中间件、框架与 OA 系统，关闭不使用的功能模块")
	return dim
}

func (d *assessData) credential() *Dimension {
	dim := &Dimension{Key: "credential", Name: "凭证安全", Weight: 10,
		Score: clamp100(100 - math.Min(45, 5*float64(d.brute)) - math.Min(50, 25*float64(d.bruteSuccess))),
		Metrics: []Metric{
			{"暴力破解来源", num(int64(d.brute)), metricLevel(false, d.brute > 0)},
			{"暴力破解尝试", num(d.bruteHits) + " 次", ""},
			{"疑似破解成功", num(d.bruteSuccess), metricLevel(d.bruteSuccess > 0, false)},
		}}
	switch {
	case d.bruteSuccess > 0:
		dim.Summary = fmt.Sprintf("发现 %d 处疑似暴力破解成功，相关账号可能已被攻破", d.bruteSuccess)
	case d.brute > 0:
		dim.Summary = fmt.Sprintf("%d 个来源在暴力破解登录口令，暂未发现破解成功", d.brute)
	default:
		dim.Summary = "未发现暴力破解行为"
		dim.Advice = []string{"保持登录失败锁定与强口令策略"}
		return dim
	}
	dim.Advice = []string{"登录接口启用失败锁定、图形验证码与多因素认证（MFA）",
		"在 nginx 中对登录接口限速：limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m; 并在登录 location 中 limit_req zone=login burst=5 nodelay;",
		"SSH / RDP 禁止对公网开放，改用 VPN 或堡垒机；SSH 关闭口令登录（PasswordAuthentication no）"}
	if d.bruteSuccess > 0 {
		dim.Advice = append([]string{"立即重置疑似被破解账号的口令，核查其登录记录与操作日志"}, dim.Advice...)
	}
	return dim
}

func (d *assessData) perimeter() *Dimension {
	dim := &Dimension{Key: "perimeter", Name: "边界防护", Weight: 10}
	if d.totals.Firewall == 0 {
		dim.Score, dim.Summary = -1, "未接入防火墙 / 网络设备日志，无法评估网络边界"
		dim.Advice = []string{"将防火墙、安全网关或主机防火墙日志通过 syslog 发送到本平台（默认 5514 端口）"}
		return dim
	}
	crit, high := countServices(d.services, model.SevCritical), countServices(d.services, model.SevHigh)
	medium := len(d.services) - crit - high
	dim.Score = clamp100(100 - 30*float64(crit) - 15*float64(high) - 5*float64(medium) - math.Min(15, float64(d.portScanners)/2))
	dim.Metrics = []Metric{
		{"对公网开放的高危服务", num(int64(len(d.services))), metricLevel(crit > 0, len(d.services) > 0)},
		{"端口扫描 / 主机探测来源", num(int64(d.portScanners)), metricLevel(false, d.portScanners >= 10)},
		{"被探测端口", num(int64(d.probedPorts)), ""},
	}
	if len(d.services) > 0 {
		var names []string
		for _, sv := range d.services {
			if len(names) < 5 {
				names = append(names, fmt.Sprintf("%s(%d)", sv.Name, sv.Port))
			}
		}
		dim.Summary = fmt.Sprintf("%d 个高危服务对公网开放：%s", len(d.services), strings.Join(names, "、"))
		dim.Advice = []string{"入站默认拒绝，只放行确需对外提供的端口（通常仅 80/443）",
			"数据库、缓存、远程管理等端口仅允许内网或白名单访问，并启用认证", "通过 VPN / 堡垒机进行运维，不直接暴露管理端口"}
	} else {
		dim.Summary = "未发现高危服务对公网开放"
		dim.Advice = []string{"保持入站默认拒绝策略，定期复核防火墙放行规则"}
	}
	return dim
}

func (d *assessData) threat() *Dimension {
	dim := &Dimension{Key: "threat", Name: "威胁活跃度", Weight: 10,
		Score: clamp100(100 - d.threatIndex*0.5 - math.Min(30, 2*float64(d.activeHigh)) - math.Min(10, float64(d.intelHits))),
		Metrics: []Metric{
			{"威胁指数（近 60 分钟）", fmt.Sprintf("%.0f", d.threatIndex), metricLevel(d.threatIndex >= 80, d.threatIndex >= 35)},
			{"活跃的高危攻击源", num(int64(d.activeHigh)), metricLevel(d.activeHigh >= 10, d.activeHigh > 0)},
			{"威胁情报命中", num(int64(d.intelHits)), metricLevel(false, d.intelHits > 0)},
			{"扫描器 / 测绘来源", num(int64(d.scanners)), ""},
		}}
	dim.Summary = fmt.Sprintf("近 60 分钟威胁指数 %.0f，%d 个高危以上攻击源仍在活动", d.threatIndex, d.activeHigh)
	if d.activeHigh > 0 {
		dim.Advice = append(dim.Advice, "在“数据源 → 导出”中导出高危及以上攻击源的封禁列表，下发到防火墙 / WAF")
	}
	dim.Advice = append(dim.Advice, "订阅威胁情报黑名单（intel.blocklists），提前拦截已知恶意来源")
	return dim
}

func (d *assessData) visibility(v Visibility) *Dimension {
	checks := []Check{
		{"已接入 Web 访问日志", d.totals.Web > 0, 20, "接入 nginx / Apache / IIS 访问日志，覆盖 Web 攻击检测"},
		{"已接入防火墙 / 网络设备日志", d.totals.Firewall > 0, 20, "通过 syslog 接入防火墙日志，覆盖端口扫描、暴力破解与服务暴露面"},
		{"日志解析成功率 ≥ 98%", v.ParseRate >= 0.98, 10, fmt.Sprintf("当前解析成功率 %.1f%%，在“数据源”页查看失败样例并配置对应的日志格式", v.ParseRate*100)},
		{"已配置威胁情报", v.Intel > 0, 10, "配置 intel.blocklists 或 Tor 出口节点列表，启用情报命中与内网主机外连恶意地址检测"},
		{"已配置精确定位（MaxMind / 在线溯源）", v.PreciseGeo, 10, "放入 MaxMind GeoLite2 数据库或开启 geo.online，获得精确坐标与 ASN"},
		{"已启用告警推送", v.Robots > 0, 10, "在“告警推送”页添加钉钉 / 企业微信 / 飞书机器人，高危事件第一时间通知值班人员"},
		{"已启用告警长期归档", v.Archive, 10, "配置 archive.dsn 接入 PostgreSQL，长期留存告警以满足合规与追溯需要"},
		{"平台访问已加固（登录 + HTTPS 或来源限制）", v.AuthEnabled && (v.HTTPS || v.AllowNetworks), 10, "开启 HTTPS（server.tls_cert）或用 server.allow_networks 限制管理访问来源"},
	}
	dim := &Dimension{Key: "visibility", Name: "日志与检测覆盖", Weight: 10, Checks: checks}
	ok := 0
	for _, c := range checks {
		if c.OK {
			dim.Score += c.Weight
			ok++
		} else {
			dim.Advice = append(dim.Advice, c.Advice)
		}
	}
	dim.Summary = fmt.Sprintf("%d / %d 项检查通过", ok, len(checks))
	dim.Metrics = []Metric{{"检查通过", fmt.Sprintf("%d / %d", ok, len(checks)), metricLevel(ok < len(checks)/2, ok < len(checks))}}
	return dim
}

// ---------------- 处置建议 ----------------

func pathOf(asset string) string {
	if i := strings.Index(asset, "/"); i >= 0 {
		return asset[i:]
	}
	return asset
}

func (d *assessData) actions(v Visibility, dims []*Dimension) []*Action {
	var out []*Action
	add := func(a *Action) { out = append(out, a) }
	ips := func(list []string) string {
		if len(list) == 0 {
			return ""
		}
		if len(list) > 5 {
			return strings.Join(list[:5], "、") + " 等"
		}
		return strings.Join(list, "、")
	}
	// 失陷：高置信 P0，其余 P1
	n := 0
	for _, c := range d.comp {
		if n >= 8 {
			break
		}
		n++
		act := &Action{Priority: "P1", Dimension: "compromise", Reason: c.Indicators[0]}
		if c.Confidence == "high" {
			act.Priority = "P0"
		}
		if c.Kind == "host" {
			act.Title = "应急处置疑似失陷主机：" + c.Asset
			act.Steps = []string{"立即将主机 " + c.Asset + " 断网隔离（保留现场，不要直接重装）",
				"排查恶意进程、自启动项、计划任务、可疑账号与近期新增文件", "在出口防火墙封禁外连地址：" + ips(c.IPs),
				"检查同网段其他主机是否存在相同外连，确认入侵途径后修复并轮换凭证"}
			act.Drill = &Drill{Tab: "ip", Params: map[string]string{"ip": c.Asset}, Label: "查看主机详情"}
		} else {
			if c.Confidence == "high" {
				act.Title = "应急处置疑似失陷资产：" + c.Asset
			} else {
				act.Title = "核查疑似攻击成功：" + c.Asset
			}
			act.Steps = []string{"复核告警证据与服务器日志，确认攻击是否成功", c.Advice,
				"修复漏洞前通过 WAF 规则临时拦截该接口的攻击载荷"}
			if c.Confidence == "high" {
				act.Steps = append([]string{"立即下线或隔离受影响服务，保留访问日志与服务器镜像用于取证"}, act.Steps...)
			}
			if len(c.IPs) > 0 {
				act.Steps = append(act.Steps, "封禁攻击来源："+ips(c.IPs))
			}
			act.Drill = &Drill{Tab: "alerts", Params: map[string]string{"q": pathOf(c.Asset)}, Label: "查看相关告警"}
		}
		add(act)
	}
	// 暴露面：按发现标题归并，严重 P0、高危 P1、其余 P2
	type group struct {
		f      *Finding
		assets []string
	}
	var groups []*group
	byTitle := map[string]*group{}
	for _, f := range d.exposure {
		if f.Category == "服务暴露" {
			continue
		}
		g := byTitle[f.Title]
		if g == nil {
			g = &group{f: f}
			byTitle[f.Title] = g
			groups = append(groups, g)
		}
		g.assets = append(g.assets, f.Asset)
	}
	for _, g := range groups {
		p := map[model.Severity]string{model.SevCritical: "P0", model.SevHigh: "P1"}[g.f.Severity]
		if p == "" {
			p = "P2"
		}
		steps := []string{g.f.Remediation}
		if g.f.Severity >= model.SevHigh {
			steps = append(steps, "检查访问日志确认是否已被下载；涉及的密钥、口令与令牌需全部轮换")
		}
		add(&Action{Priority: p, Dimension: "exposure", Title: fmt.Sprintf("处置%s（%d 处）", g.f.Title, len(g.assets)),
			Reason: "可公开访问：" + ips(g.assets), Steps: steps, Drill: &Drill{Tab: "surface", Label: "查看攻击面分析"}})
	}
	// 对公网开放的高危服务
	for _, sev := range []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium} {
		var names []string
		for _, sv := range d.services {
			if sv.Risk == sev {
				names = append(names, fmt.Sprintf("%s(%s:%d)", sv.Name, sv.DstIP, sv.Port))
			}
		}
		if len(names) == 0 {
			continue
		}
		p := map[model.Severity]string{model.SevCritical: "P0", model.SevHigh: "P1", model.SevMedium: "P2"}[sev]
		add(&Action{Priority: p, Dimension: "perimeter", Title: fmt.Sprintf("限制对公网开放的%s风险服务（%d 个）", sev.Label(), len(names)),
			Reason: "防火墙放行了来自公网的连接：" + ips(names),
			Steps: []string{"在安全组 / 防火墙中将这些端口限制为内网或白名单访问", "服务仅监听内网地址，并启用认证（如 Redis requirepass、Elasticsearch 安全认证）",
				"运维访问改用 VPN 或堡垒机"}, Drill: &Drill{Tab: "surface", Label: "查看网络服务暴露面"}})
	}
	// 活跃的高危攻击源
	if d.activeHigh > 0 {
		add(&Action{Priority: "P1", Dimension: "threat", Title: fmt.Sprintf("封禁仍在活动的高危攻击源（%d 个）", d.activeHigh),
			Reason: "近 60 分钟内仍有高危及以上攻击源在发起攻击",
			Steps: []string{"在“数据源 → 导出”中选择“高危及以上”，导出 nginx / iptables / ipset / firewalld / Windows 防火墙封禁列表并下发",
				"同一网段出现多个攻击源时可按网段封禁（见 IP 详情中的同源关联分析）", "封禁后持续观察是否更换地址继续攻击"},
			Drill: &Drill{Tab: "attackers", Params: map[string]string{"level": "high", "sort": "last"}, Label: "查看高危攻击源"}})
	}
	// 暴力破解
	if d.brute > 0 {
		p := "P2"
		if d.bruteSuccess > 0 {
			p = "P1"
		}
		cred := dimByKey(dims, "credential")
		add(&Action{Priority: p, Dimension: "credential", Title: "加固登录入口，防御暴力破解", Reason: cred.Summary, Steps: cred.Advice,
			Drill: &Drill{Tab: "attackers", Params: map[string]string{"category": "暴力破解"}, Label: "查看暴力破解来源"}})
	}
	// Web 防护
	if total := d.exploitBlocked + d.exploitPassed; total >= 20 {
		rate := float64(d.exploitBlocked) / float64(total)
		if rate < 0.8 {
			p := "P2"
			if rate < 0.5 {
				p = "P1"
			}
			web := dimByKey(dims, "web")
			add(&Action{Priority: p, Dimension: "web", Title: "提升 Web 攻击拦截能力", Reason: web.Summary, Steps: web.Advice,
				Drill: &Drill{Tab: "alerts", Params: map[string]string{"result": "passed"}, Label: "查看未拦截的攻击"}})
		}
	}
	// CC / 洪水攻击
	if d.ccSources > 0 {
		add(&Action{Priority: "P2", Dimension: "threat", Title: "配置访问频率限制，缓解 CC / 洪水攻击", Reason: fmt.Sprintf("%d 个来源发起高频请求或流量洪泛", d.ccSources),
			Steps: []string{"nginx 中配置 limit_req（按 IP 限制请求速率）与 limit_conn（限制并发连接）",
				"对动态接口与搜索接口单独设置更严格的频率限制", "流量较大时接入 CDN / 高防服务"},
			Drill: &Drill{Tab: "attackers", Params: map[string]string{"category": "CC攻击"}, Label: "查看 CC 攻击来源"}})
	}
	// 扫描与测绘
	if d.scanners >= 5 {
		add(&Action{Priority: "P3", Dimension: "threat", Title: "减少指纹信息暴露，降低被批量扫描命中的概率",
			Reason: fmt.Sprintf("%d 个扫描器 / 网络空间测绘来源在探测资产", d.scanners),
			Steps:  []string{"nginx 中设置 server_tokens off;，隐藏 X-Powered-By 等版本信息", "在 WAF 中拦截常见扫描器的 User-Agent 与目录字典", "删除默认页面、示例程序与未使用的入口"},
			Drill:  &Drill{Tab: "attackers", Params: map[string]string{"category": "扫描器"}, Label: "查看扫描来源"}})
	}
	// 可见性
	for _, c := range dimByKey(dims, "visibility").Checks {
		if !c.OK {
			p := "P3"
			if c.Weight >= 20 {
				p = "P2"
			}
			add(&Action{Priority: p, Dimension: "visibility", Title: "补齐检测覆盖：" + strings.TrimPrefix(c.Name, "已"), Reason: "该项检查未通过，相关攻击无法被发现或追溯",
				Steps: []string{c.Advice}, Drill: &Drill{Tab: "sources", Label: "查看数据源"}})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	if out == nil {
		out = []*Action{}
	}
	return out
}

func dimByKey(dims []*Dimension, key string) *Dimension {
	for _, d := range dims {
		if d.Key == key {
			return d
		}
	}
	return &Dimension{}
}
