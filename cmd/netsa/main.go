// netsa —— 基于 nginx / 防火墙日志的网络安全态势感知与攻击面分析系统。
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	_ "time/tzdata" // 内嵌时区数据，精简容器镜像中也能使用 timezone 配置

	"netsa/internal/alert"
	"netsa/internal/api"
	"netsa/internal/archive"
	"netsa/internal/assets"
	"netsa/internal/audit"
	"netsa/internal/auth"
	"netsa/internal/config"
	"netsa/internal/demo"
	"netsa/internal/detect"
	"netsa/internal/exposure"
	"netsa/internal/geo"
	"netsa/internal/ingest"
	"netsa/internal/intel"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/pipeline"
	"netsa/internal/rawlog"
	"netsa/internal/store"
	"netsa/internal/suppress"
	"netsa/web"
)

// version 是构建版本号。默认值用于本地构建；镜像构建通过
// -ldflags "-X main.version=<tag>" 注入，`netsa version` 与 /api/meta 都会显示注入后的值。
var version = "1.6.4"

func usage() {
	fmt.Fprintf(os.Stderr, `netsa %s —— 网络安全态势感知与攻击面分析系统

用法:
  netsa serve    -c config.yaml                 启动实时态势感知服务（文件跟踪 + syslog + Web 大屏）
  netsa analyze  [选项] <日志文件...>            离线分析日志（自动识别格式，支持通配符与 .gz）
  netsa simulate -o demo-logs [-live]            生成演示日志
  netsa rules    [-rules custom.yaml]            列出检测规则
  netsa passwd   -c config.yaml -u admin         重置登录密码（忘记密码时使用）
  netsa hash-password                           生成密码哈希（用于配置文件 server.password）
  netsa version

运行 "netsa <命令> -h" 查看各命令选项。
`, version)
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "analyze":
		err = cmdAnalyze(os.Args[2:])
	case "simulate":
		err = cmdSimulate(os.Args[2:])
	case "rules":
		err = cmdRules(os.Args[2:])
	case "passwd":
		err = cmdPasswd(os.Args[2:])
	case "hash-password":
		err = cmdHashPassword(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("netsa", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("错误: %v", err)
	}
}

// app 是装配好的系统组件。
type app struct {
	cfg      *config.Config
	geo      *geo.Resolver
	intel    *intel.DB
	engine   *detect.Engine
	store    *store.Store
	notifier *alert.Notifier
	broker   *api.Broker
	pipe     *pipeline.Pipeline
	ingest   *ingest.Manager
	rdap     *geo.RDAPClient
	archive  *archive.Archive  // 可选的 PostgreSQL 告警归档
	suppress *suppress.Manager // 误报抑制规则
	raw      *rawlog.Store     // 原始日志留存
	assets   *assets.Manager   // 资产与漏洞
	exposure *exposure.Manager // 对外发布服务清单（DNAT 映射）
	api      *api.Server
}

func build(cfg *config.Config) (*app, error) {
	a := &app{cfg: cfg}
	loc, err := cfg.Location()
	if err != nil {
		return nil, err
	}
	parser.Location = loc
	alert.Location = loc // 告警消息中的时间按同一时区展示
	// 内网 / 保留网段：内置 RFC1918 与保留段 + 配置 geo.intranet + 本机网卡自动探测。
	// 这些地址不查询任何定位库，避免把内网误用的公网段（如 172.168.100.0/24）解析成境外地址。
	nets := append([]string(nil), cfg.Geo.Intranet...)
	if cfg.Geo.AutoDetectIntranet() {
		nets = append(nets, geo.DetectLocalNetworks()...)
	}
	effective, invalid := geo.SetInternalNetworks(nets)
	if len(invalid) > 0 {
		log.Printf("[geo] 忽略无法解析的内网网段: %s", strings.Join(invalid, ", "))
	}
	if len(effective) > 0 {
		log.Printf("[geo] 额外内网网段（按内网呈现、不查询定位库）: %s", strings.Join(effective, ", "))
	}
	gaz, err := geo.LoadGazetteer(staticFS(cfg))
	if err != nil {
		return nil, fmt.Errorf("加载地图地名库失败: %w", err)
	}
	var providers []geo.Provider
	i2r, err := geo.OpenIP2Region(cfg.Geo.IP2RegionV4, cfg.Geo.IP2RegionV6)
	if err != nil {
		return nil, fmt.Errorf("加载 ip2region 失败: %w", err)
	}
	if i2r != nil {
		providers = append(providers, i2r)
	}
	mm, err := geo.OpenMaxMind(cfg.Geo.MaxMindCity, cfg.Geo.MaxMindASN)
	if err != nil {
		return nil, fmt.Errorf("加载 MaxMind 失败: %w", err)
	}
	if mm != nil {
		providers = append(providers, mm)
	}
	opt := geo.Options{
		Providers: providers, ReverseDNS: cfg.Geo.ReverseDNS, CacheSize: cfg.Geo.CacheSize,
		HomeLat: cfg.Home.Lat, HomeLon: cfg.Home.Lon, Gazetteer: gaz, Custom: geo.NewCustom(cfg.Geo.Custom),
	}
	if cfg.Geo.Online.Enabled {
		opt.Online = geo.NewIPAPI(cfg.Geo.Online.URL, cfg.Geo.Online.Lang)
	}
	a.geo = geo.NewResolver(opt)
	log.Printf("[geo] 定位数据源: %s", strings.Join(a.geo.ProviderNames(), ", "))
	if n := opt.Custom.Len(); n > 0 {
		log.Printf("[geo] 自定义网段: %d 条", n)
	}
	if !anyReady(providers) {
		log.Printf("[geo] 警告: 未找到离线定位库，IP 归属地只能依赖在线查询（库文件就绪后将自动加载）")
	}
	if cfg.Geo.Online.RDAP {
		a.rdap = geo.NewRDAPClient()
	}

	if a.intel, err = intel.Load(cfg.Intel); err != nil {
		return nil, err
	}
	if a.engine, err = detect.NewEngine(cfg.Detect.RulesFile, cfg.Detect.SuccessMinBytes); err != nil {
		return nil, err
	}
	a.store = store.New(cfg.Storage.MaxIPs, cfg.Storage.MaxAlerts, cfg.Detect.AlertsPerRule, cfg.Storage.Retention)
	a.store.SetLocation(loc)
	a.store.GeoLookup = a.geo.Lookup
	a.store.IntelMatch = a.intel.Match
	if a.notifier, err = alert.New(cfg.Alert, robotsFile(cfg)); err != nil {
		return nil, err
	}
	if a.suppress, err = suppress.Load(dataFile(cfg, "", "suppressions.json")); err != nil {
		return nil, err
	}
	if a.assets, err = assets.Load(dataFile(cfg, "", "assets.json")); err != nil {
		return nil, err
	}
	if a.exposure, err = exposure.Load(cfg.Exposure); err != nil {
		return nil, err
	}
	a.store.PortPublished = a.exposure.Published
	if a.exposure.Enforcing() {
		log.Printf("[exposure] 对外发布服务清单已启用：%d 条映射、%d 个兜底端口；未发布端口上的端口探测与暴力破解只打标签，不产生告警",
			a.exposure.Count(), len(cfg.Exposure.AllowedPorts))
	}
	a.broker = api.NewBroker()
	a.pipe = &pipeline.Pipeline{
		Engine: a.engine, Behavior: detect.NewBehavior(cfg.Detect.Thresholds), Store: a.store, Geo: a.geo,
		RealIP: pipeline.NewRealIP(cfg.RealIP), Notifier: a.notifier,
		EnrichLevel: model.ParseSeverity(cfg.Geo.EnrichLevel), OnAlert: a.onAlert, Suppress: a.suppress, Assets: a.assets,
		Exposure: a.exposure,
	}
	a.pipe.SetWhitelist(cfg.Detect.Whitelist)
	a.geo.OnUpdate = a.pipe.OnGeoUpdate
	a.ingest = ingest.NewManager(20000)
	silence, _ := config.ParseSilence(cfg.Alert.SourceSilence, 0)
	a.ingest.DefaultSilence = silence
	if a.ingest.Senders, err = ingest.NewSenders(cfg.Syslog, dataFile(cfg, cfg.Syslog.SendersFile, "syslog-senders.json"), silence); err != nil {
		return nil, err
	}
	a.ingest.AutoTime = cfg.TimeCorrection != "off"
	if dsn := archiveDSN(cfg); dsn != "" {
		host, _ := os.Hostname()
		ar, err := archive.Open(context.Background(), archive.Options{
			DSN: dsn, RetentionYears: cfg.Archive.RetentionYears, BatchSize: cfg.Archive.BatchSize, FlushInterval: cfg.Archive.FlushInterval,
			QueueSize: cfg.Archive.QueueSize, Instance: host, Location: loc,
		})
		if err != nil {
			return nil, err
		}
		a.archive = ar
		log.Printf("[archive] 告警归档已启用：%s（后台连接中）", ar.Server())
	}
	if rc := cfg.RawLog; rc.Enabled {
		dir := dataFile(cfg, rc.Dir, "rawlog")
		if dir == "" {
			dir = filepath.Join("data", "rawlog")
		}
		rl, err := rawlog.Open(context.Background(), rawlog.Options{Dir: dir, RetentionDays: rc.RetentionDays, MaxBytes: int64(rc.MaxSizeGB * (1 << 30)),
			AttacksOnly: rc.AttacksOnly, Location: loc})
		if err != nil {
			return nil, err
		}
		a.raw, a.pipe.Raw = rl, rl
		log.Printf("[rawlog] 原始日志留存已启用：%s（留存 %d 天）", dir, rc.RetentionDays)
	}
	return a, nil
}

func (a *app) server(listen string) (*http.Server, error) {
	s := &api.Server{
		Cfg: a.cfg, Store: a.store, Ingest: a.ingest, Pipeline: a.pipe, Geo: a.geo, Engine: a.engine,
		RDAP: a.rdap, Static: staticFS(a.cfg), Version: version, Broker: a.broker, Notifier: a.notifier,
		Archive: a.archive, Suppress: a.suppress, RawLog: a.raw, Assets: a.assets, Exposure: a.exposure,
	}
	a.api = s
	dir := dataFile(a.cfg, a.cfg.Audit.Dir, "audit")
	if dir == "" {
		dir = filepath.Join("data", "audit")
	}
	trail, err := audit.Open(dir, a.cfg.Audit.RetentionDays)
	if err != nil {
		return nil, err
	}
	s.Trail = trail
	if a.cfg.Server.AuthEnabled() {
		m, initial, err := auth.New(auth.Options{
			Audit:      trail,
			ConfigUser: a.cfg.Server.Username, ConfigPassword: a.cfg.Server.Password, File: usersFile(a.cfg),
			TTL: a.cfg.Server.SessionTTL, InitialAdmin: os.Getenv("NETSA_ADMIN_PASSWORD"), Require2FA: a.cfg.Server.Require2FA,
		})
		if err != nil {
			return nil, fmt.Errorf("初始化登录账号失败: %w", err)
		}
		s.Auth = m
		if initial != "" {
			log.Printf("[auth] ==================================================")
			log.Printf("[auth] 已创建管理员账号 admin，初始密码: %s", initial)
			log.Printf("[auth] 首次登录后须修改密码；忘记密码可执行 netsa passwd -u admin 重置")
			log.Printf("[auth] ==================================================")
		}
		if usersFile(a.cfg) == "" {
			log.Printf("[auth] 警告: 未配置 storage.snapshot 或 server.users_file，账号只保存在内存中，重启后需重新登录")
		}
	} else {
		log.Printf("[auth] 警告: 已关闭登录认证（server.auth: false），任何能访问该端口的人都可以查看和修改配置")
	}
	if a.cfg.Server.Pprof {
		log.Printf("[api] 性能剖析已开启：/debug/pprof/（仅管理员），排障结束后请关闭 server.pprof")
	}
	// 读取请求（含请求体）与写出响应都限时，防止慢速发送请求体 / 慢速读取响应的连接长期占用资源；
	// 实时告警流与历史告警导出在处理时用 http.ResponseController 单独解除 / 延长期限。
	return &http.Server{
		Addr: listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: api.ReadTimeout, WriteTimeout: api.WriteTimeout,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}, nil
}

// listen 启动 HTTP 或 HTTPS 服务（配置了证书时）。
func (a *app) listen(srv *http.Server) error {
	if c := a.cfg.Server; c.TLSCert != "" {
		return srv.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	}
	return srv.ListenAndServe()
}

func (a *app) scheme() string {
	if a.cfg.Server.TLSCert != "" {
		return "https"
	}
	return "http"
}

// archiveDSN 返回告警归档的数据库连接串：环境变量 NETSA_ARCHIVE_DSN 优先（避免口令写入配置文件），其次 archive.dsn。
func archiveDSN(cfg *config.Config) string {
	if v := strings.TrimSpace(os.Getenv("NETSA_ARCHIVE_DSN")); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.Archive.DSN)
}

// onAlert 把告警推送到大屏实时流，并投递到归档（未启用时忽略）。
func (a *app) onAlert(al *model.Alert) {
	a.broker.Publish(al)
	a.archive.Add(al)
}

// usersFile 返回账号文件位置：server.users_file，或 storage.snapshot 所在目录。
func usersFile(cfg *config.Config) string {
	if cfg.Server.UsersFile != "" {
		return cfg.Server.UsersFile
	}
	if cfg.Storage.Snapshot != "" {
		return filepath.Join(filepath.Dir(cfg.Storage.Snapshot), "users.json")
	}
	return ""
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("c", "configs/config.yaml", "配置文件")
	listen := fs.String("listen", "", "监听地址（覆盖配置）")
	webDir := fs.String("web", "", "从该目录加载前端页面（覆盖 server.web_dir，用于定制或开发界面）")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Server.Listen = *listen
	}
	if *webDir != "" {
		cfg.Server.WebDir = *webDir
	}
	a, err := build(cfg)
	if err != nil {
		return err
	}
	if err := a.store.Load(cfg.Storage.Snapshot); err != nil {
		log.Printf("[store] 加载快照失败（将从空状态开始）: %v", err)
	}
	// 快照中的定位结果可能来自旧版定位库或旧的自定义网段，按当前库重新定位
	if n := a.store.RefreshGeo(a.geo.Relocate); n > 0 {
		log.Printf("[geo] 已按当前定位库更新 %d 个历史攻击源的归属地", n)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.geo.Start(ctx)
	go a.reloadGeo(ctx, *cfgPath)
	go a.notifier.Run(ctx)
	a.intel.StartTor(ctx, cfg.Intel.TorExitURL)
	done := a.pipe.Run(ctx, a.ingest.Out, 0)

	for _, src := range cfg.Sources {
		if err := a.ingest.StartSource(ctx, src); err != nil {
			return fmt.Errorf("数据源 %s: %w", src.Name, err)
		}
		log.Printf("[ingest] 数据源 %s (%s): %s", src.Name, src.Type, strings.Join(src.Paths, ", "))
	}
	if err := a.ingest.StartSyslog(ctx, cfg.Syslog); err != nil {
		return fmt.Errorf("启动 syslog 失败: %w", err)
	}

	srv, err := a.server(cfg.Server.Listen)
	if err != nil {
		return err
	}
	go a.api.RunBackground(ctx) // 每小时记录安全评分，每日推送安全日报
	go func() {
		log.Printf("[web] 态势感知大屏: %s://%s", a.scheme(), displayAddr(cfg.Server.Listen))
		if err := a.listen(srv); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[web] %v", err)
			stop()
		}
	}()

	tick := time.NewTicker(cfg.Storage.Interval)
	defer tick.Stop()
	candLogged := 0 // 已提示过的候选映射数量，避免每次维护重复打印
	for {
		select {
		case <-tick.C:
			a.store.Maintain()
			// 候选映射提示：只在新发现时打印一次摘要，详细清单（含可粘贴的 YAML）在 /api/exposure
			if n := a.exposure.CandidateCount(); n > candLogged {
				candLogged = n
				if list := a.exposure.Candidates(); len(list) > 0 {
					c := list[0]
					log.Printf("[exposure] 发现 %d 个疑似对外映射（示例 %s:%d，已放行 %d 次、%d 个来源）；"+
						"确认后写入 exposure.services，详见 GET /api/exposure", n, c.PublicIP, c.PublicPort, c.Allows, c.Sources)
				}
			}
			if err := a.store.Save(cfg.Storage.Snapshot); err != nil {
				log.Printf("[store] 保存快照失败: %v", err)
			}
			if err := a.suppress.Flush(); err != nil {
				log.Printf("[suppress] %v", err)
			}
			if err := a.ingest.Senders.Flush(); err != nil {
				log.Printf("[syslog] %v", err)
			}
		case <-ctx.Done():
			log.Printf("正在退出...")
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			srv.Shutdown(shutdown)
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
			a.archive.Close(10 * time.Second) // 写完归档队列中剩余的告警
			a.raw.Close(10 * time.Second)
			a.suppress.Flush()
			a.ingest.Senders.Flush()
			if err := a.store.Save(cfg.Storage.Snapshot); err != nil {
				log.Printf("[store] 保存快照失败: %v", err)
			}
			return nil
		}
	}
}

// reloadGeo 按 geo.reload_interval 检查定位库文件与配置中的自定义网段，有变化时热更新，
// 并刷新所有攻击源画像的归属地，无需重启服务。
func (a *app) reloadGeo(ctx context.Context, cfgPath string) {
	if a.cfg.Geo.ReloadInterval <= 0 {
		return
	}
	custom := a.cfg.Geo.Custom
	tick := time.NewTicker(a.cfg.Geo.ReloadInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		changed, err := a.geo.Reload()
		if err != nil {
			log.Printf("[geo] 重新加载定位库失败（继续使用旧库）: %v", err)
		}
		if cfg, err := config.Load(cfgPath); err != nil {
			log.Printf("[geo] 读取配置失败，自定义网段保持不变: %v", err)
		} else if !reflect.DeepEqual(cfg.Geo.Custom, custom) {
			custom = cfg.Geo.Custom
			c := geo.NewCustom(custom)
			a.geo.SetCustom(c)
			changed = append(changed, fmt.Sprintf("custom(%d)", c.Len()))
		}
		if len(changed) == 0 {
			continue
		}
		n := a.store.RefreshGeo(a.geo.Relocate)
		log.Printf("[geo] 定位库已热更新: %s，%d 个攻击源归属地发生变化", strings.Join(changed, ", "), n)
	}
}

// robotsFile 返回界面添加的告警机器人的保存位置：alert.robots_file，或 storage.snapshot 所在目录。
func robotsFile(cfg *config.Config) string {
	return dataFile(cfg, cfg.Alert.RobotsFile, "alert-robots.json")
}

// dataFile 返回运行数据文件路径：显式配置优先，否则与状态快照放在同一目录；两者都没有时只保存在内存中。
func dataFile(cfg *config.Config, explicit, name string) string {
	if explicit != "" {
		return explicit
	}
	if cfg.Storage.Snapshot != "" {
		return filepath.Join(filepath.Dir(cfg.Storage.Snapshot), name)
	}
	return ""
}

// anyReady 判断是否至少有一个离线定位库已加载。
func anyReady(ps []geo.Provider) bool {
	for _, p := range ps {
		if rd, ok := p.(geo.Readier); !ok || rd.Ready() {
			return true
		}
	}
	return false
}

func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "localhost" + listen
	}
	return listen
}

// expandArgs 展开通配符（Windows 命令行不会自动展开）。
func expandArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.ContainsAny(a, "*?[") {
			m, _ := filepath.Glob(a)
			out = append(out, m...)
		} else {
			out = append(out, a)
		}
	}
	return out
}

func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	cfgPath := fs.String("c", "", "配置文件（可选，用于定位库路径、可信代理、规则等）")
	typ := fs.String("type", "auto", "日志类型: auto | nginx | firewall | 具体解析器名")
	logFormat := fs.String("format", "", "自定义 nginx log_format 字符串")
	host := fs.String("host", "", "站点名（日志中无 $host 时使用）")
	out := fs.String("o", "", "输出 JSON 报告路径")
	online := fs.Bool("online", false, "启用在线溯源（ip-api + rDNS），会将攻击 IP 发送至第三方接口")
	wait := fs.Duration("wait", 60*time.Second, "在线溯源最长等待时间")
	listen := fs.String("listen", "", "分析完成后启动 Web 大屏，例如 :8080")
	top := fs.Int("top", 20, "控制台输出的攻击者数量")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法: netsa analyze [选项] <日志文件...>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	files := expandArgs(fs.Args())
	if len(files) == 0 {
		fs.Usage()
		return errors.New("未指定日志文件")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	cfg.Geo.Online.Enabled = *online
	if !*online {
		cfg.Geo.ReverseDNS = false
	}
	a, err := build(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.geo.Start(ctx)

	start := time.Now()
	done := a.pipe.Run(ctx, a.ingest.Out, 0)
	for _, f := range files {
		if err := a.ingest.ReadFile(ctx, f, *typ, *logFormat, *host); err != nil {
			log.Printf("跳过 %s: %v", f, err)
		}
	}
	go func() {
		a.ingest.Wait()
		close(a.ingest.Out)
	}()
	<-done
	elapsed := time.Since(start)
	if a.archive != nil { // 离线分析同样归档（可用于把历史日志补录到归档库）
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := a.archive.WaitReady(c); err != nil {
			log.Printf("[archive] 归档数据库不可用，本次分析结果未归档")
		}
		cancel()
		a.archive.Close(2 * time.Minute)
		w, d := a.archive.Counts()
		log.Printf("[archive] 已归档 %d 条告警（丢弃 %d 条）", w, d)
	}

	if *online {
		deadline := time.Now().Add(*wait)
		log.Printf("[geo] 等待在线溯源完成（最长 %s）...", *wait)
		for time.Now().Before(deadline) && a.geo.QueueLen() > 0 && ctx.Err() == nil {
			time.Sleep(500 * time.Millisecond)
		}
		time.Sleep(5 * time.Second) // 等待最后一批请求返回
	}

	printReport(a, files, elapsed, *top)
	if *out != "" {
		b, _ := json.MarshalIndent(api.Report(a.store, 500), "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			return err
		}
		fmt.Printf("\nJSON 报告已写入 %s\n", *out)
	}
	if *listen != "" {
		srv, err := a.server(*listen)
		if err != nil {
			return err
		}
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		fmt.Printf("\nWeb 大屏: %s://%s  (Ctrl+C 退出)\n", a.scheme(), displayAddr(*listen))
		if err := a.listen(srv); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func printReport(a *app, files []string, elapsed time.Duration, top int) {
	o := a.store.Overview()
	fmt.Println()
	fmt.Println("==================== 数据源 ====================")
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "文件\t识别格式\t行数\t解析成功\t失败")
	for _, s := range a.ingest.Stats() {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\n", s.Path, s.Detected, s.Lines, s.Parsed, s.Failed)
	}
	tw.Flush()
	rate := float64(o.Totals.Events) / max(elapsed.Seconds(), 0.001)
	fmt.Printf("耗时 %s，处理 %d 条事件（%.0f 条/秒）\n", elapsed.Round(time.Millisecond), o.Totals.Events, rate)

	fmt.Println()
	fmt.Println("==================== 态势总览 ====================")
	fmt.Printf("时间范围: %s ~ %s\n", o.From.In(parser.Location).Format("2006-01-02 15:04:05"), o.To.In(parser.Location).Format("2006-01-02 15:04:05"))
	fmt.Printf("Web 请求 %d | 防火墙事件 %d | 独立来源 IP %d | 攻击 IP %d\n", o.Totals.Web, o.Totals.Firewall, o.UniqueIPs, o.Attackers)
	fmt.Printf("攻击事件 %d | 已拦截 %d (%.1f%%) | 疑似成功 %d | 攻击面风险指数 %d/100\n",
		o.Totals.Attacks, o.Totals.Blocked, o.BlockRate, o.Totals.Success, o.SurfaceScore)
	fmt.Printf("攻击源等级: 严重 %d / 高危 %d / 中危 %d / 低危 %d\n",
		o.LevelCounts["critical"], o.LevelCounts["high"], o.LevelCounts["medium"], o.LevelCounts["low"])

	fmt.Println()
	fmt.Println("---- 攻击类型分布 ----")
	for i, kv := range o.Categories {
		if i >= 15 {
			break
		}
		fmt.Printf("  %-22s %d\n", kv.Name, kv.Value)
	}
	if len(o.TopCountries) > 0 {
		fmt.Println("---- 攻击来源国家/地区 ----")
		var parts []string
		for _, kv := range o.TopCountries {
			parts = append(parts, fmt.Sprintf("%s(%d)", kv.Name, kv.Value))
		}
		fmt.Println("  " + strings.Join(parts, "  "))
	}

	fmt.Println()
	fmt.Printf("==================== 攻击源 TOP %d ====================\n", top)
	list, _ := a.store.Attackers(store.AttackerQuery{Sort: "score", Limit: top})
	tw = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\t评分\t等级\t攻击次数\t归属地\t网络类型\t置信度\t攻击类型")
	for _, s := range list {
		ip := s.IP
		if s.ViaProxy {
			ip += "(经代理)"
		}
		fmt.Fprintf(tw, "%s\t%.0f\t%s\t%d\t%s\t%s\t%s\t%s\n", ip, s.Score, s.Level.Label(), s.Attacks,
			s.Location, s.NetType, s.Confidence, strings.Join(s.Categories, ","))
	}
	tw.Flush()

	sf := a.store.Surface()
	fmt.Println()
	fmt.Println("==================== 攻击面风险发现 ====================")
	if len(sf.Findings) == 0 {
		fmt.Println("  未发现明显暴露面风险")
	}
	for i, f := range sf.Findings {
		if i >= 15 {
			fmt.Printf("  ... 共 %d 项\n", len(sf.Findings))
			break
		}
		fmt.Printf("  [%s] %s — %s\n      证据: %s\n      建议: %s\n", f.Severity.Label(), f.Title, f.Asset, f.Evidence, f.Remediation)
	}
	if len(sf.Tech) > 0 {
		var parts []string
		for _, kv := range sf.Tech {
			parts = append(parts, kv.Name)
		}
		fmt.Println("识别到的技术栈: " + strings.Join(parts, ", "))
	}
	exposed := 0
	for _, s := range sf.Services {
		if s.Exposed {
			exposed++
		}
	}
	fmt.Printf("观测到网络服务 %d 个（对公网放行 %d 个），Web 入口 %d 个\n", len(sf.Services), exposed, sf.EndpointTotal)
}

func cmdSimulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	dir := fs.String("o", "demo-logs", "输出目录")
	hours := fs.Int("hours", 6, "生成多少小时的历史日志")
	intensity := fs.Int("intensity", 4, "流量强度")
	live := fs.Bool("live", false, "生成历史日志后持续追加实时日志")
	interval := fs.Duration("interval", 2*time.Second, "实时模式追加间隔")
	seed := fs.Int64("seed", 20261022, "随机种子")
	fs.Parse(args)

	if *hours > 0 {
		if err := demo.Generate(*dir, *hours, *intensity, *seed); err != nil {
			return err
		}
		fmt.Printf("已生成 %d 小时演示日志到 %s/ (access.log, ufw.log, fortigate.log, auth.log, dns.log)\n", *hours, *dir)
	}
	if !*live {
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("实时模式：每 %s 追加一批日志，Ctrl+C 结束\n", *interval)
	return demo.Live(ctx, *dir, *interval, *intensity, *seed)
}

func cmdRules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	file := fs.String("rules", "", "自定义规则文件")
	fs.Parse(args)
	rules, err := detect.LoadRules(*file)
	if err != nil {
		return err
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Category < rules[j].Category })
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\t分类\t等级\t名称")
	for _, r := range rules {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Category, r.Severity, r.Name)
	}
	tw.Flush()
	fmt.Printf("共 %d 条特征规则（另有 CC/目录扫描/暴力破解/端口扫描/主机探测/洪水等行为检测）\n", len(rules))
	return nil
}

// staticFS 返回前端资源：配置了 server.web_dir 时使用磁盘目录，否则使用编译内嵌的资源。
func staticFS(cfg *config.Config) fs.FS {
	if cfg.Server.WebDir != "" {
		return os.DirFS(cfg.Server.WebDir)
	}
	return web.Static()
}

// readPassword 从参数或标准输入读取密码（标准输入读取一行，便于脚本调用）。
func readPassword(flagValue, prompt string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("未读取到密码")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	cfgPath := fs.String("c", "configs/config.yaml", "配置文件（用于定位账号文件）")
	user := fs.String("u", "admin", "用户名（不存在时以管理员身份创建）")
	pass := fs.String("p", "", "新密码（不指定时从标准输入读取）")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	file := usersFile(cfg)
	if file == "" {
		return fmt.Errorf("配置中未设置 storage.snapshot 或 server.users_file，账号只保存在内存中，重启服务即会重新生成初始密码")
	}
	pw, err := readPassword(*pass, "新密码: ")
	if err != nil {
		return err
	}
	if err := auth.SetPassword(file, *user, pw); err != nil {
		return err
	}
	fmt.Printf("账号 %s 的密码已更新（%s），该账号已登录的会话全部失效；运行中的服务会自动加载新密码。\n", *user, file)
	return nil
}

func cmdHashPassword(args []string) error {
	fs := flag.NewFlagSet("hash-password", flag.ExitOnError)
	pass := fs.String("p", "", "密码（不指定时从标准输入读取）")
	fs.Parse(args)
	pw, err := readPassword(*pass, "密码: ")
	if err != nil {
		return err
	}
	if err := auth.CheckStrength("", pw); err != nil {
		return err
	}
	fmt.Println(auth.HashPassword(pw))
	return nil
}
