// Package api 提供态势感知 REST API、SSE 实时告警流与前端静态资源。
package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"netsa/internal/alert"
	"netsa/internal/auth"
	"netsa/internal/config"
	"netsa/internal/detect"
	"netsa/internal/geo"
	"netsa/internal/ingest"
	"netsa/internal/model"
	"netsa/internal/pipeline"
	"netsa/internal/store"
)

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
	Auth     *auth.Manager // 为 nil 表示未开启登录

	started time.Time
	rdapSem chan struct{}
	cache   *respCache
	hashSem chan struct{} // 限制同时进行的密码哈希计算
}

func (s *Server) Handler() http.Handler {
	s.started = time.Now()
	s.rdapSem = make(chan struct{}, 4)
	s.cache = newRespCache()
	s.hashSem = make(chan struct{}, 4)
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
	mux.HandleFunc("GET /api/ip/{ip}", s.ipDetail)
	mux.HandleFunc("GET /api/ip/{ip}/rdap", s.rdap)
	mux.HandleFunc("GET /api/alerts", cached(time.Second, s.alerts))
	mux.HandleFunc("GET /api/alerts/summary", cached(2*time.Second, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Store.AlertSummary()) }))
	mux.HandleFunc("GET /api/map", cached(3*time.Second, func(w http.ResponseWriter, r *http.Request) {
		res := s.Store.MapData(model.ParseSeverity(r.URL.Query().Get("level")))
		writeJSON(w, map[string]any{"home": s.Cfg.Home, "data": res})
	}))
	mux.HandleFunc("GET /api/surface", cached(3*time.Second, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Store.Surface()) }))
	mux.HandleFunc("GET /api/sources", s.sources)
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Engine.Rules()) })
	mux.HandleFunc("GET /api/stream", s.Broker.ServeHTTP)
	mux.HandleFunc("GET /api/export/blocklist", s.blocklist)
	mux.HandleFunc("GET /api/report", s.report)
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
	// 告警推送机器人管理
	mux.HandleFunc("GET /api/alert/robots", s.alertInfo)
	mux.HandleFunc("POST /api/alert/robots", s.robotCreate)
	mux.HandleFunc("PUT /api/alert/robots/{id}", s.robotUpdate)
	mux.HandleFunc("DELETE /api/alert/robots/{id}", s.robotDelete)
	mux.HandleFunc("POST /api/alert/robots/{id}/test", s.robotTest)
	mux.HandleFunc("POST /api/alert/test", s.robotTest)
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
	root.Handle("/", s.authenticate(sameOrigin(mux)))
	return securityHeaders(gzipHandler(root))
}

// securityHeaders 设置安全响应头：页面只加载自身资源，日志中的攻击载荷即使被渲染也无法执行脚本。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
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

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"version": s.Version, "home": s.Cfg.Home, "started": s.started, "timezone": s.displayTimezone(),
		"time_correction": s.Cfg.TimeCorrection != "off",
		"geo_providers":   s.Geo.ProviderNames(), "rdap": s.RDAP != nil, "rules": len(s.Engine.Rules()),
		"china_maps": s.Geo.Gazetteer().ChinaMaps(),
	})
}

func (s *Server) attackers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, total := s.Store.Attackers(store.AttackerQuery{
		MinLevel: model.ParseSeverity(q.Get("level")), Search: q.Get("q"), Sort: q.Get("sort"),
		Limit: clamp(qint(r, "limit", 50), 1, 1000), Offset: max(qint(r, "offset", 0), 0),
	})
	if list == nil {
		list = []store.AttackerSummary{}
	}
	writeJSON(w, map[string]any{"total": total, "items": list})
}

func (s *Server) ipDetail(w http.ResponseWriter, r *http.Request) {
	d := s.Store.IPDetail(r.PathValue("ip"))
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
	if err != nil || geo.IsPrivate(addr.String()) || !addr.IsGlobalUnicast() {
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
		MinSeverity: model.ParseSeverity(q.Get("severity")), Category: q.Get("category"), IP: q.Get("ip"),
		Result: q.Get("result"), Kind: q.Get("kind"), Search: q.Get("q"), SinceID: since,
		Limit: clamp(qint(r, "limit", 200), 1, 2000),
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
		"geo_pending": s.Geo.QueueLen(), "rules": len(s.Engine.Rules()), "syslog": s.Cfg.Syslog,
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
			cw.Write([]string{a.IP, strconv.FormatFloat(a.Score, 'f', 0, 64), a.Level.Label(), strconv.FormatInt(a.Attacks, 10),
				a.Location, a.ISP, strconv.FormatUint(uint64(a.ASN), 10), a.NetType, strings.Join(a.Categories, "/"),
				a.FirstSeen.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339)})
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
	w.Header().Set("Content-Disposition", "attachment; filename=netsa-report-"+s.now().Format("20060102-150405")+".json")
	writeJSON(w, Report(s.Store, 200))
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

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "event: alert\ndata: %s\n\n", msg)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}
