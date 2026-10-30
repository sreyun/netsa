// Package api 提供态势感知 REST API、SSE 实时告警流与前端静态资源。
package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netsa/internal/ai"
	"netsa/internal/alert"
	"netsa/internal/archive"
	"netsa/internal/assets"
	"netsa/internal/audit"
	"netsa/internal/auth"
	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/exposure"
	"netsa/internal/geo"
	"netsa/internal/ingest"
	"netsa/internal/learn"
	"netsa/internal/model"
	"netsa/internal/pipeline"
	"netsa/internal/rawlog"
	"netsa/internal/store"
	"netsa/internal/suppress"
)

// HTTP 服务的读写超时。处理时间可能超过该时长的接口（实时告警流、历史告警导出）需自行调整连接期限：
// 设置 ReadTimeout 后，服务端在请求读完后检测连接关闭的后台读取也受该期限约束，超时会取消请求上下文。
const (
	ReadTimeout  = 30 * time.Second
	WriteTimeout = 2 * time.Minute
)

// extendDeadline 为长时间运行的请求调整连接读写期限（d 为 0 表示不限制）。不支持的 ResponseWriter（如测试中的录制器）忽略。
func extendDeadline(w http.ResponseWriter, d time.Duration) {
	var t time.Time
	if d > 0 {
		t = time.Now().Add(d)
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(t)
	_ = rc.SetWriteDeadline(t)
}

// Server 是 HTTP 服务。
type Server struct {
	Cfg      *config.Config
	Store    *store.Store
	Ingest   *ingest.Manager
	Pipeline *pipeline.Pipeline
	Geo      *geo.Resolver
	Engine   *detect.Engine
	RDAP     *geo.RDAPClient // 为 nil 表示禁用
	Static   fs.FS
	Version  string
	Broker   *Broker
	Notifier *alert.Notifier
	Auth     *auth.Manager     // 为 nil 表示未开启登录
	Archive  *archive.Archive  // 为 nil 表示未启用告警归档
	Suppress *suppress.Manager // 误报抑制规则
	RawLog   *rawlog.Store     // 原始日志留存，为 nil 表示未启用
	Assets   *assets.Manager   // 资产与漏洞
	Exposure *exposure.Manager // 对外发布服务清单（DNAT 映射），为 nil 表示未启用
	Learn    *learn.Learner    // 自学习（研判反馈、平台行为基线、合规自检），可为空
	AI       *ai.Client        // 可选的外部大模型（研判参考），未启用时为 nil
	Trail    *audit.Trail      // 防篡改审计链

	started    time.Time
	rdapSem    chan struct{}
	cache      *respCache
	hashSem    chan struct{}   // 限制同时进行的密码哈希计算
	lastComp   time.Time       // 上次合规自检（只在后台任务中访问）
	lastVerify string          // 上次审计链自检的日期
	aiBusy     atomic.Bool     // 自动研判进行中
	aiDone     map[uint64]bool // 已自动研判的事件（只在后台任务中访问）
	archHealth archiveHealth
	sched      reportSchedule
}

func (s *Server) Handler() http.Handler {
	s.started = time.Now()
	s.rdapSem = make(chan struct{}, 4)
	s.cache = newRespCache()
	s.hashSem = make(chan struct{}, 4)
	if s.Auth != nil && s.Trail != nil {
		// 审计链外包一层自学习：学习平台账号的行为基线，发现异常登录、批量导出与高危变更时告警
		var sink auth.AuditSink = s.Trail
		if s.Learn != nil {
			sink = &learn.Sink{Next: s.Trail, L: s.Learn, Notify: s.PlatformAnomaly}
		}
		s.Auth.SetAuditSink(sink)
	}
	if s.Notifier == nil {
		s.Notifier, _ = alert.New(config.AlertConfig{}, "")
	}
	// 聚合类接口短时缓存：多个大屏并发刷新时每个周期只计算一次
	cached := s.cache.wrap
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/meta", s.meta)
	mux.HandleFunc("GET /api/overview", cached(2*time.Second, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Store.Overview()) }))
	mux.HandleFunc("GET /api/timeline", cached(2*time.Second, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Store.Timeline(clamp(qint(r, "minutes", 60), 1, 31*24*60)))
	}))
	mux.HandleFunc("GET /api/attackers", cached(time.Second, s.attackers))
	mux.HandleFunc("GET /api/ip/{ip}", cached(2*time.Second, s.ipDetail)) // 含同源关联分析，短时缓存避免重复全量比对
	mux.HandleFunc("GET /api/ip/{ip}/rdap", s.rdap)
	mux.HandleFunc("GET /api/alerts", cached(time.Second, s.alerts))
	mux.HandleFunc("GET /api/alerts/summary", cached(2*time.Second, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Store.AlertSummary()) }))
	mux.HandleFunc("GET /api/map", cached(3*time.Second, func(w http.ResponseWriter, r *http.Request) {
		res := s.Store.MapData(model.ParseSeverity(r.URL.Query().Get("level")))
		writeJSON(w, map[string]any{"home": s.Cfg.Home, "data": res})
	}))
	mux.HandleFunc("GET /api/surface", cached(3*time.Second, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Store.Surface()) }))
	mux.HandleFunc("GET /api/assessment", cached(3*time.Second, s.assessment))
	mux.HandleFunc("GET /api/sources", s.sources)
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Engine.Rules()) })
	mux.HandleFunc("GET /api/rules/stats", func(w http.ResponseWriter, r *http.Request) {
		total, hit, hits := s.ruleStats()
		writeJSON(w, map[string]any{"total": total, "hit": hit, "hits": hits})
	})
	mux.HandleFunc("GET /api/exposure", s.exposureInfo)
	mux.HandleFunc("GET /api/learn", s.learnReport)
	mux.HandleFunc("POST /api/learn/suggestions/{id}/{action}", s.learnSuggestion)
	mux.HandleFunc("POST /api/learn/rules/{rule}/{action}", s.learnPin)
	mux.HandleFunc("GET /api/stream", func(w http.ResponseWriter, r *http.Request) { s.Broker.Serve(w, r, s.sessionAlive(r)) })
	mux.HandleFunc("GET /api/export/blocklist", s.blocklist)
	mux.HandleFunc("GET /api/report", s.report)
	// 历史告警（PostgreSQL 归档）
	mux.HandleFunc("GET /api/archive/status", s.archiveStatus)
	mux.HandleFunc("GET /api/archive/alerts", s.archiveAlerts)
	mux.HandleFunc("GET /api/archive/stats", s.archiveStats)
	mux.HandleFunc("GET /api/archive/export", s.archiveExport)
	// 登录与账号管理
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("GET /api/auth/session", s.authSession)
	mux.HandleFunc("POST /api/auth/logout", s.authLogout)
	mux.HandleFunc("POST /api/auth/password", s.authPassword)
	mux.HandleFunc("GET /api/auth/users", s.authUsers)
	mux.HandleFunc("POST /api/auth/users", s.authUserCreate)
	mux.HandleFunc("PUT /api/auth/users/{name}", s.authUserUpdate)
	mux.HandleFunc("DELETE /api/auth/users/{name}", s.authUserDelete)
	mux.HandleFunc("GET /api/auth/audit", s.authAudit)
	mux.HandleFunc("POST /api/auth/login/2fa", s.authLogin2FA)
	mux.HandleFunc("POST /api/auth/2fa/setup", s.auth2FASetup)
	mux.HandleFunc("POST /api/auth/2fa/enable", s.auth2FAEnable)
	mux.HandleFunc("POST /api/auth/2fa/disable", s.auth2FADisable)
	mux.HandleFunc("GET /api/auth/tokens", s.authTokens)
	mux.HandleFunc("POST /api/auth/tokens", s.authTokenCreate)
	mux.HandleFunc("DELETE /api/auth/tokens/{id}", s.authTokenDelete)
	// 告警推送机器人管理
	mux.HandleFunc("GET /api/incidents", s.incidents)
	mux.HandleFunc("GET /api/incidents/assignees", s.incidentAssignees)
	mux.HandleFunc("GET /api/incidents/{id}", s.incident)
	mux.HandleFunc("POST /api/incidents/bulk", s.incidentUpdate)
	mux.HandleFunc("POST /api/incidents/{id}", s.incidentUpdate)
	mux.HandleFunc("POST /api/incidents/{id}/ai", s.incidentAI)
	mux.HandleFunc("GET /metrics", s.cache.wrap(5*time.Second, s.metrics))
	mux.HandleFunc("GET /api/assets", s.assetList)
	mux.HandleFunc("GET /api/assets/template", s.assetTemplate)
	mux.HandleFunc("GET /api/assets/{id}", s.assetDetail)
	mux.HandleFunc("POST /api/assets", s.assetCreate)
	mux.HandleFunc("POST /api/assets/import", s.assetImport)
	mux.HandleFunc("PUT /api/assets/{id}", s.assetUpdate)
	mux.HandleFunc("DELETE /api/assets/{id}", s.assetDelete)
	mux.HandleFunc("GET /api/vulns", s.vulnList)
	mux.HandleFunc("PUT /api/vulns/{id}", s.vulnUpdate)
	mux.HandleFunc("DELETE /api/vulns/{id}", s.vulnDelete)
	mux.HandleFunc("GET /api/reports/periodic", s.periodicReport)
	mux.HandleFunc("GET /api/compliance/mlps", s.compliance)
	mux.HandleFunc("POST /api/reports/email", s.reportEmail)
	mux.HandleFunc("GET /api/audit", s.auditSearch)
	mux.HandleFunc("GET /api/audit/export", s.auditExport)
	mux.HandleFunc("POST /api/audit/verify", s.auditVerify)
	mux.HandleFunc("GET /api/rawlog/status", s.rawlogStatus)
	mux.HandleFunc("GET /api/rawlog/search", s.rawlogSearch)
	mux.HandleFunc("GET /api/rawlog/export", s.rawlogExport)
	mux.HandleFunc("POST /api/rawlog/verify", s.rawlogVerify)
	mux.HandleFunc("GET /api/syslog/senders", s.syslogSenders)
	mux.HandleFunc("POST /api/syslog/senders", s.senderCreate)
	mux.HandleFunc("PUT /api/syslog/senders/{id}", s.senderUpdate)
	mux.HandleFunc("DELETE /api/syslog/senders/{id}", s.senderDelete)
	mux.HandleFunc("PUT /api/syslog/policy", s.senderPolicy)
	mux.HandleFunc("GET /api/suppressions", s.suppressions)
	mux.HandleFunc("POST /api/suppressions", s.suppressionCreate)
	mux.HandleFunc("DELETE /api/suppressions/{id}", s.suppressionDelete)

	mux.HandleFunc("GET /api/alert/robots", s.alertInfo)
	mux.HandleFunc("POST /api/alert/robots", s.robotCreate)
	mux.HandleFunc("PUT /api/alert/robots/{id}", s.robotUpdate)
	mux.HandleFunc("DELETE /api/alert/robots/{id}", s.robotDelete)
	mux.HandleFunc("POST /api/alert/robots/{id}/test", s.robotTest)
	mux.HandleFunc("POST /api/alert/robots/{id}/report", s.sendReport)
	mux.HandleFunc("POST /api/alert/test", s.robotTest)
	// 性能剖析接口（仅管理员，需 server.pprof 开启）：排查 CPU、内存与协程问题时按需打开。
	// 必须带方法注册：Go 1.22 起 ServeMux 会判定「不限方法的 /debug/pprof/」与「GET /」互相冲突
	// （前者方法更宽、后者路径更泛），启动时直接 panic。
	if s.Cfg != nil && s.Cfg.Server.Pprof {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("POST /debug/pprof/symbol", pprof.Symbol) // symbolize 支持批量 POST
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}
	if s.Static != nil {
		files := http.FileServer(http.FS(s.Static))
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/vendor/") {
				w.Header().Set("Cache-Control", "public, max-age=604800")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
		}))
	}

	root := http.NewServeMux()
	// 健康检查不需要认证，供 Docker / 负载均衡探活
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "uptime": time.Since(s.started).Round(time.Second).String(), "processed": s.Pipeline.Processed()})
	})
	root.Handle("/", s.allowNetworks(s.authenticate(sameOrigin(mux))))
	return securityHeaders(gzipHandler(root))
}

// securityHeaders 设置安全响应头：页面只加载自身资源，日志中的攻击载荷即使被渲染也无法执行脚本。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func qint(r *http.Request, key string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil {
		return v
	}
	return def
}

// qtime 解析查询参数中的时间：Unix 秒或 RFC3339，无效时返回零值（不限制）。
func qtime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n < 1<<40 {
		return time.Unix(n, 0)
	}
	t, _ := time.Parse(time.RFC3339, v)
	return t
}

// displayTimezone 返回页面展示时间所用的 IANA 时区名：配置项 timezone，未配置时取进程的 TZ 环境变量
// （容器镜像默认 Asia/Shanghai）；都没有时返回空，页面使用浏览器本地时区。
func (s *Server) displayTimezone() string {
	if s.Cfg.Timezone != "" {
		return s.Cfg.Timezone
	}
	if tz := os.Getenv("TZ"); tz != "" && !strings.HasPrefix(tz, ":") {
		if _, err := time.LoadLocation(tz); err == nil {
			return tz
		}
	}
	return ""
}

// now 返回配置时区下的当前时间（导出文件名、文件头中的时间）。
func (s *Server) now() time.Time {
	if loc, err := s.Cfg.Location(); err == nil {
		return time.Now().In(loc)
	}
	return time.Now()
}

func clamp(v, lo, hi int) int {
	return min(max(v, lo), hi)
}

// ruleStats 统计已加载规则数、本次运行有命中的规则数，以及每条规则的命中次数。
func (s *Server) ruleStats() (total, hit int, hits map[string]int64) {
	rules := s.Engine.Rules()
	hits = s.Store.RuleHits()
	for _, r := range rules {
		if hits[r.ID] > 0 {
			hit++
		}
	}
	return len(rules), hit, hits
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	ruleTotal, ruleHit, _ := s.ruleStats()
	writeJSON(w, map[string]any{
		"version": s.Version, "home": s.Cfg.Home, "started": s.started, "timezone": s.displayTimezone(),
		"time_correction": s.Cfg.TimeCorrection != "off", "archive": s.Archive != nil,
		"geo_providers": s.Geo.ProviderNames(), "rdap": s.RDAP != nil, "rules": ruleTotal, "rules_hit": ruleHit,
		"china_maps": s.Geo.Gazetteer().ChinaMaps(),
		"intranet":   geo.ExtraInternalNetworks(),
		"exposure":   s.Exposure.Enforcing(), "exposure_rules": s.Exposure.Count(), "exposure_muted": s.Exposure.Muted(),
		"exposure_candidates": s.Exposure.CandidateCount(),
		"proxies":             s.proxyPeers(),
		"exposure_reach":      s.Exposure.ReachCheck(), "exposure_unreached": s.Exposure.Unreached(), "exposure_learned": s.Exposure.LearnedCount(), "learn": s.Learn != nil, "ai": s.AI.Status(), "exposure_policies": topPolicies(s.Exposure.Policies(), 5),
		"require_2fa": s.Cfg.Server.Require2FA, "rawlog": s.RawLog != nil, "assets": s.Assets != nil, "audit": s.Trail != nil,
		"syslog": s.Cfg.Syslog.Enabled, "suppress": s.Suppress != nil, "auth": s.Auth != nil,
	})
}

func (s *Server) attackers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, total := s.Store.Attackers(store.AttackerQuery{
		MinLevel: model.ParseSeverity(q.Get("level")), Search: q.Get("q"), Sort: q.Get("sort"),
		Limit: clamp(qint(r, "limit", 50), 1, 1000), Offset: max(qint(r, "offset", 0), 0),
		Country: q.Get("country"), City: q.Get("city"), NetType: q.Get("net_type"), ISP: q.Get("isp"), World: q.Get("world"),
		Province: q.Get("province"), CityMap: q.Get("city_map"), Place: q.Get("place"), Category: q.Get("category"), Phase: q.Get("phase"),
		Technique: q.Get("technique"),
	})
	if list == nil {
		list = []store.AttackerSummary{}
	}
	writeJSON(w, map[string]any{"total": total, "items": list})
}

// canonIP 把查询参数中的 IP 规范化为入库时的写法（IPv4 映射地址、IPv6 大小写与零压缩、区域标识），
// 否则 2001:DB8::1、::ffff:203.0.113.5 这类等价写法查不到已有的画像与告警；无法解析时原样返回。
func canonIP(s string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return s
}

func (s *Server) ipDetail(w http.ResponseWriter, r *http.Request) {
	d := s.Store.IPDetail(canonIP(r.PathValue("ip")))
	if d == nil {
		writeError(w, http.StatusNotFound, "未找到该 IP 的记录")
		return
	}
	writeJSON(w, d)
}

func (s *Server) rdap(w http.ResponseWriter, r *http.Request) {
	if s.RDAP == nil {
		writeError(w, http.StatusForbidden, "RDAP 查询未启用（geo.online.rdap）")
		return
	}
	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil || geo.IsNonPublic(addr) || !addr.IsGlobalUnicast() {
		writeError(w, http.StatusBadRequest, "仅支持公网 IP")
		return
	}
	select {
	case s.rdapSem <- struct{}{}:
		defer func() { <-s.rdapSem }()
	default:
		writeError(w, http.StatusTooManyRequests, "RDAP 查询过于频繁，请稍后重试")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	info, err := s.RDAP.Lookup(ctx, addr.Unmap().String())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, info)
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, _ := strconv.ParseUint(q.Get("since"), 10, 64)
	list := s.Store.Alerts(store.AlertQuery{
		MinSeverity: model.ParseSeverity(q.Get("severity")), Category: q.Get("category"), IP: canonIP(q.Get("ip")),
		Result: q.Get("result"), Kind: q.Get("kind"), Search: q.Get("q"), SinceID: since,
		Limit: clamp(qint(r, "limit", 200), 1, 2000),
		Phase: q.Get("phase"), Target: q.Get("target"), From: qtime(q.Get("from")), To: qtime(q.Get("to")), Technique: q.Get("technique"),
		Asset: q.Get("asset"), Incident: incidentParam(q.Get("incident")),
	})
	if list == nil {
		list = []*model.Alert{}
	}
	writeJSON(w, list)
}

func (s *Server) sources(w http.ResponseWriter, r *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	writeJSON(w, map[string]any{
		"sources": s.Ingest.Stats(), "processed": s.Pipeline.Processed(), "geo_providers": s.Geo.ProviderNames(),
		"geo_pending": s.Geo.QueueLen(), "rules": len(s.Engine.Rules()), "syslog": s.Cfg.Syslog, "silence": silenceText(s.Ingest.DefaultSilence),
		"runtime": map[string]any{
			"uptime": time.Since(s.started).Round(time.Second).String(), "goroutines": runtime.NumGoroutine(),
			"heap_mb": ms.HeapAlloc >> 20, "sys_mb": ms.Sys >> 20, "go": runtime.Version(),
		},
	})
}

// blocklist 导出封禁列表：txt / nginx / iptables / ipset / firewalld / windows / csv。
func (s *Server) blocklist(w http.ResponseWriter, r *http.Request) {
	lvl := r.URL.Query().Get("level")
	if lvl == "" {
		lvl = "high"
	}
	list := s.Store.Blocklist(model.ParseSeverity(lvl))
	format := r.URL.Query().Get("format")
	s.audit(r, "导出封禁列表", "格式 "+format+" 等级>="+lvl+" 共 "+strconv.Itoa(len(list))+" 个 IP", nil)
	ext := map[string]string{"nginx": "conf", "csv": "csv", "windows": "bat", "iptables": "sh", "ipset": "sh", "firewalld": "sh"}[format]
	if ext == "" {
		format, ext = "txt", "txt"
	}
	w.Header().Set("Content-Disposition", "attachment; filename=netsa-blocklist-"+lvl+"."+ext)

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Write([]byte("\xEF\xBB\xBF")) // UTF-8 BOM，便于 Excel 正确识别中文
		cw := csv.NewWriter(w)
		cw.Write([]string{"ip", "score", "level", "attacks", "location", "isp", "asn", "net_type", "categories", "first_seen", "last_seen"})
		for _, a := range list {
			cw.Write(csvSafe([]string{a.IP, strconv.FormatFloat(a.Score, 'f', 0, 64), a.Level.Label(), strconv.FormatInt(a.Attacks, 10),
				a.Location, a.ISP, strconv.FormatUint(uint64(a.ASN), 10), a.NetType, strings.Join(a.Categories, "/"),
				a.FirstSeen.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339)}))
		}
		cw.Flush()
		return
	}

	var b strings.Builder
	comment := "#"
	if format == "windows" {
		comment = "REM"
	}
	if format != "txt" {
		fmt.Fprintf(&b, "%s netsa 封禁列表 生成时间 %s 等级>=%s 共 %d 个IP\n", comment, s.now().Format("2006-01-02 15:04:05"), lvl, len(list))
	}
	switch format {
	case "ipset":
		b.WriteString("ipset create netsa_blacklist hash:net -exist\nipset create netsa_blacklist6 hash:net family inet6 -exist\n")
	case "iptables", "firewalld":
		b.WriteString("set -e\n")
	}
	for _, a := range list {
		// 注释中只保留安全字符，避免地名中的特殊字符影响脚本
		note := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '`' || r == '$' || r == '\'' || r == '"' || r == ';' || r == '&' || r == '|' {
				return ' '
			}
			return r
		}, a.Location+" "+strings.Join(a.Categories, "/"))
		v6 := strings.Contains(a.IP, ":")
		switch format {
		case "nginx":
			fmt.Fprintf(&b, "deny %s; # score=%.0f %s\n", a.IP, a.Score, note)
		case "iptables":
			cmd := "iptables"
			if v6 {
				cmd = "ip6tables"
			}
			fmt.Fprintf(&b, "%s -C INPUT -s %s -j DROP 2>/dev/null || %s -I INPUT -s %s -j DROP # %s\n", cmd, a.IP, cmd, a.IP, note)
		case "ipset":
			set := "netsa_blacklist"
			if v6 {
				set = "netsa_blacklist6"
			}
			fmt.Fprintf(&b, "ipset add %s %s -exist\n", set, a.IP)
		case "firewalld":
			fam := "ipv4"
			if v6 {
				fam = "ipv6"
			}
			fmt.Fprintf(&b, "firewall-cmd --permanent --add-rich-rule='rule family=\"%s\" source address=\"%s\" drop'\n", fam, a.IP)
		case "windows":
			fmt.Fprintf(&b, "netsh advfirewall firewall add rule name=\"netsa-block-%s\" dir=in action=block remoteip=%s\n", a.IP, a.IP)
		default:
			b.WriteString(a.IP + "\n")
		}
	}
	switch format {
	case "ipset":
		b.WriteString("iptables -C INPUT -m set --match-set netsa_blacklist src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set netsa_blacklist src -j DROP\n")
		b.WriteString("ip6tables -C INPUT -m set --match-set netsa_blacklist6 src -j DROP 2>/dev/null || ip6tables -I INPUT -m set --match-set netsa_blacklist6 src -j DROP\n")
	case "firewalld":
		b.WriteString("firewall-cmd --reload\n")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b.String()))
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	s.audit(r, "下载分析报告", "", nil)
	w.Header().Set("Content-Disposition", "attachment; filename=netsa-report-"+s.now().Format("20060102-150405")+".json")
	rep := Report(s.Store, 200)
	rep["assessment"] = s.Store.Assess(s.visibility(r))
	writeJSON(w, rep)
}

// csvSafe 防止 CSV 公式注入：以 = + - @ 制表符或回车开头的单元格（运营商、地名等可能来自第三方数据）
// 在 Excel 中会被当作公式执行，在前面加单引号使其按文本显示。
func csvSafe(row []string) []string {
	for i, v := range row {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			row[i] = "'" + v
		}
	}
	return row
}

// Report 生成完整的 JSON 分析报告。
func Report(st *store.Store, topAttackers int) map[string]any {
	attackers, total := st.Attackers(store.AttackerQuery{Sort: "score", Limit: topAttackers})
	return map[string]any{
		"generated_at": time.Now(), "overview": st.Overview(), "attackers_total": total,
		"attackers": attackers, "surface": st.Surface(), "timeline": st.Timeline(24 * 60), "map": st.MapData(model.SevLow),
	}
}

// Broker 将告警通过 SSE 推送给浏览器，限速 50 条/秒，超出部分丢弃（前端会定时补拉）。
type Broker struct {
	mu     sync.Mutex
	subs   map[chan []byte]struct{}
	tokens float64
	last   time.Time
	// PingEvery 是心跳间隔（默认 20 秒），同时也是检查登录会话是否仍然有效的周期
	PingEvery time.Duration
}

func NewBroker() *Broker { return &Broker{subs: map[chan []byte]struct{}{}} }

func (b *Broker) Publish(a *model.Alert) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subs) == 0 {
		return
	}
	now := time.Now()
	b.tokens = min(b.tokens+now.Sub(b.last).Seconds()*50, 50)
	b.last = now
	if b.tokens < 1 {
		return
	}
	b.tokens--
	msg, _ := json.Marshal(a)
	for ch := range b.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) { b.Serve(w, r, nil) }

// Serve 推送实时告警流。alive 不为空时每次心跳检查登录会话是否仍然有效：
// 退出登录、修改密码、删除账号或调整角色后，已建立的长连接也会在 20 秒内断开，不会继续收到告警。
func (b *Broker) Serve(w http.ResponseWriter, r *http.Request, alive func() bool) {
	extendDeadline(w, 0) // 长连接：不受服务的读写超时限制（连接断开由心跳与会话复核发现）
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	b.mu.Lock()
	if len(b.subs) >= 256 {
		b.mu.Unlock()
		http.Error(w, "too many subscribers", http.StatusServiceUnavailable)
		return
	}
	ch := make(chan []byte, 64)
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	fmt.Fprint(w, "retry: 5000\n: connected\n\n")
	fl.Flush()
	every := b.PingEvery
	if every <= 0 {
		every = 20 * time.Second
	}
	ping := time.NewTicker(every)
	defer ping.Stop()
	// 长连接不设整体期限，但每次写入限时：客户端不再读取（网络卡死、恶意慢读）时发送缓冲区写满，
	// 没有写期限的写入会永久阻塞，连接与订阅名额（上限 256）就再也不会释放
	rc := http.NewResponseController(w)
	send := func(format string, args ...any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			if !send("event: alert\ndata: %s\n\n", msg) {
				return
			}
		case <-ping.C:
			if alive != nil && !alive() {
				return
			}
			if !send(": ping\n\n") {
				return
			}
		}
	}
}

// sseWriteTimeout 是实时告警流单次写入的最长时间。
const sseWriteTimeout = 30 * time.Second
