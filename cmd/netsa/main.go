// netsa —— 基于 nginx / 防火墙日志的网络安全态势感知与攻击面分析系统。
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
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

	"gopkg.in/yaml.v3"

	"netsa/internal/ai"
	"netsa/internal/alert"
	"netsa/internal/api"
	"netsa/internal/archive"
	"netsa/internal/assets"
	"netsa/internal/audit"
	"netsa/internal/auth"
	"netsa/internal/authscan"
	"netsa/internal/backup"
	"netsa/internal/block"
	"netsa/internal/config"
	"netsa/internal/deception"
	"netsa/internal/demo"
	"netsa/internal/detect"
	"netsa/internal/eval"
	"netsa/internal/exposure"
	"netsa/internal/forward"
	"netsa/internal/geo"
	"netsa/internal/ingest"
	"netsa/internal/intel"
	"netsa/internal/learn"
	"netsa/internal/model"
	"netsa/internal/parser"
	"netsa/internal/pipeline"
	"netsa/internal/playbook"
	"netsa/internal/rawlog"
	"netsa/internal/rulemgr"
	"netsa/internal/sso"
	"netsa/internal/store"
	"netsa/internal/suppress"
	"netsa/web"
)

// version 是构建版本号。默认值用于本地构建；镜像构建通过
// -ldflags "-X main.version=<tag>" 注入，`netsa version` 与 /api/meta 都会显示注入后的值。
var version = "1.10.4"

func usage() {
	fmt.Fprintf(os.Stderr, `netsa %s —— 网络安全态势感知与攻击面分析系统

用法:
  netsa serve    -c config.yaml                 启动实时态势感知服务（文件跟踪 + syslog + Web 大屏）
  netsa analyze  [选项] <日志文件...>            离线分析日志（自动识别格式，支持通配符与 .gz）
  netsa simulate -o demo-logs [-live]            生成演示日志
  netsa rules    [-rules custom.yaml]            列出检测规则
  netsa rulepack keygen|sign                     生成规则包密钥、签名规则包
  netsa eval     [-corpus samples.tsv] [-v]      用带标注的样本评测检出率与误报
  netsa backup   -c config.yaml -o backup.tar.gz 备份状态目录（可在运行时执行）
  netsa restore  -c config.yaml -i backup.tar.gz 恢复状态目录（需先停止服务）
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
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "restore":
		err = cmdRestore(os.Args[2:])
	case "rulepack":
		err = cmdRulePack(os.Args[2:])
	case "eval":
		err = cmdEval(os.Args[2:])
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
	cfg       *config.Config
	geo       *geo.Resolver
	intel     *intel.DB
	engine    *detect.Engine
	store     *store.Store
	notifier  *alert.Notifier
	broker    *api.Broker
	pipe      *pipeline.Pipeline
	ingest    *ingest.Manager
	rdap      *geo.RDAPClient
	archive   *archive.Archive   // 可选的 PostgreSQL 告警归档
	suppress  *suppress.Manager  // 误报抑制规则
	authscan  *authscan.Manager  // 授权扫描登记
	deception *deception.Manager // 诱饵
	raw       *rawlog.Store      // 原始日志留存
	assets    *assets.Manager    // 资产与漏洞
	exposure  *exposure.Manager  // 对外发布服务清单（DNAT 映射）
	learn     *learn.Learner     // 自学习（研判反馈、平台行为基线、合规自检）
	rules     *rulemgr.Manager
	forward   *forward.Forwarder
	block     *block.Manager
	playbooks *playbook.Engine
	api       *api.Server
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
	// 页面维护的规则与内置规则一起构建引擎；变更后热更新流水线
	a.rules, err = rulemgr.New(rulemgr.Options{Path: dataFile(cfg, "", "rules-managed.json"), RulesFile: cfg.Detect.RulesFile, MinBytes: cfg.Detect.SuccessMinBytes,
		Keys: cfg.Detect.RulePackKeys, OnChange: func(e *detect.Engine) { a.pipe.SetEngine(e) }})
	if err != nil {
		return nil, err
	}
	a.engine = a.rules.Engine()
	a.store = store.New(cfg.Storage.MaxIPs, cfg.Storage.MaxAlerts, cfg.Detect.AlertsPerRule, cfg.Storage.Retention)
	a.store.SetLocation(loc)
	a.store.GeoLookup = a.geo.Lookup
	a.store.IntelMatch = a.intel.Match
	a.store.IntelKind = a.intel.KindOf
	if a.notifier, err = alert.New(cfg.Alert, robotsFile(cfg)); err != nil {
		return nil, err
	}
	if a.suppress, err = suppress.Load(dataFile(cfg, "", "suppressions.json")); err != nil {
		return nil, err
	}
	if a.authscan, err = authscan.Load(dataFile(cfg, "", "authscans.json")); err != nil {
		return nil, err
	}
	if a.deception, err = deception.Load(cfg.Deception, dataFile(cfg, cfg.Deception.File, "deception.json")); err != nil {
		return nil, err
	}
	if a.assets, err = assets.Load(dataFile(cfg, "", "assets.json")); err != nil {
		return nil, err
	}
	a.store.AssetOf = a.assets.Find // 资产攻击链路按台账合并同一资产的地址与域名
	if a.exposure, err = exposure.Load(cfg.Exposure); err != nil {
		return nil, err
	}
	a.store.PortPublished = a.exposure.Published
	if a.learn, err = learn.Load(learn.Options{Path: dataFile(cfg, "", "learn.json"), Calibrate: cfg.Learn.CalibrateOn(),
		MinVerdicts: cfg.Learn.MinVerdicts, MaxPrecision: cfg.Learn.MaxPrecision, Sentinel: cfg.Learn.SentinelOn(), Compliance: cfg.Learn.ComplianceOn(),
		Escalate: cfg.Learn.EscalateOn(), EscalateDays: cfg.Learn.EscalateDays, WindowDays: cfg.Learn.WindowDays}); err != nil {
		return nil, err
	}
	a.learn.PriorAttacks = a.store.AttackCount // 业务接口学习只用此前没有攻击记录的访客
	a.store.Calibrate = a.learn.Calibrate      // 状态库生成的情报命中同样按情报源的准确率校准
	a.store.OASTLinks = a.learn.OASTLinks      // 同一 OAST 关联标识的来源归入同一攻击活动
	a.store.DecoyLinks = a.deception.Links     // 使用同一诱饵线索、诱饵账号的来源互相关联
	if added := geo.AddInternalNetworks(a.learn.LearnedNets()); len(added) > 0 {
		log.Printf("[learn] 载入自动识别的内网网段: %s", strings.Join(added, ", "))
	}
	if a.exposure.Enforcing() {
		log.Printf("[exposure] 对外发布服务清单已启用：%d 条映射、%d 个兜底端口；未发布端口上的端口探测与暴力破解只打标签，不产生告警",
			a.exposure.Count(), len(cfg.Exposure.AllowedPorts))
	}
	a.broker = api.NewBroker()
	a.pipe = &pipeline.Pipeline{
		Engine: a.engine, Behavior: a.behavior(cfg), Store: a.store, Geo: a.geo, Intel: a.intel,
		RealIP: pipeline.NewRealIP(cfg.RealIP), Notifier: a.notifier,
		EnrichLevel: model.ParseSeverity(cfg.Geo.EnrichLevel), OnAlert: a.onAlert, Suppress: a.suppress, AuthScan: a.authscan, Deception: a.deception, Assets: a.assets,
		Exposure: a.exposure, Learn: a.learn,
	}
	// 自学习识别出新的内网网段：已有攻击源按新网段重新定位（不再显示为境外）
	a.pipe.OnIntranetLearned = func(string) {
		go func() {
			if n := a.store.RefreshGeo(a.geo.Relocate); n > 0 {
				log.Printf("[geo] 按自动识别的内网网段更新了 %d 个攻击源的归属地", n)
			}
		}()
	}
	a.pipe.SetWhitelist(cfg.Detect.Whitelist)
	if a.forward, err = forward.New(cfg.Forward, version); err != nil {
		return nil, err
	}
	token := ""
	if cfg.Block.WebhookTokenEnv != "" {
		token = os.Getenv(cfg.Block.WebhookTokenEnv)
	}
	if a.block, err = block.New(block.Options{Cfg: cfg.Block, Path: dataFile(cfg, "", "block.json"), IsPrivate: geo.IsPrivate, Whitelist: cfg.Detect.Whitelist, Token: token,
		Audit: func(user, msg string) { a.auditLog(user, "联动封禁", msg) }}); err != nil {
		return nil, err
	}
	var blockFn playbook.BlockFunc
	if a.block != nil {
		blockFn = func(ip, reason string, incident uint64, user string) error {
			_, err := a.block.Request(ip, reason, 0, incident, user)
			return err
		}
	}
	if a.playbooks, err = playbook.New(cfg.Playbooks, cfg.Tickets, a.store, blockFn); err != nil {
		return nil, err
	}
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
		Archive: a.archive, Suppress: a.suppress, AuthScan: a.authscan, Deception: a.deception, RawLog: a.raw, Assets: a.assets, Exposure: a.exposure, Learn: a.learn, AI: ai.New(a.cfg.AI, os.Getenv),
	}
	// 外部模型在 Web 管理页面（自学习 → 外部模型）配置，保存在状态目录的 ai.json；
	// 界面从未保存过时沿用配置文件 ai 段与环境变量中的密钥
	if loaded, err := s.AI.SetPath(dataFile(a.cfg, "", "ai.json")); err != nil {
		log.Printf("[ai] %v", err)
	} else if loaded {
		log.Printf("[ai] 已加载界面保存的外部模型配置（%s）", dataFile(a.cfg, "", "ai.json"))
	}
	if st := s.AI.Status(); st.Enabled {
		log.Printf("[ai] 已接入外部模型 %s（%s）：发送前脱敏 %v，自动研判高危事件 %v，每小时最多 %d 次；模型结论仅供参考，不作为自学习样本", st.Model, st.Endpoint, st.Desensitize, st.AutoTriage, st.MaxPerHour)
		if !st.KeySet {
			log.Printf("[ai] 提示：未设置模型密钥，按无密钥方式调用（适用于内网部署的模型）")
		}
	}
	s.OIDC = sso.NewOIDC(a.cfg.Server.OIDC)
	s.Rules, s.Block, s.Forward, s.Playbooks, s.Intel = a.rules, a.block, a.forward, a.playbooks, a.intel
	s.StateDir, _ = stateDir(a.cfg)
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
	// 自学习：进化日志写入审计链
	a.learn.OnChange = func(c learn.Change) {
		trail.AppendAudit(auth.Record{Time: c.Time, User: c.User, Action: "自学习", Detail: c.Detail, OK: true})
	}
	if a.cfg.Server.AuthEnabled() {
		m, initial, err := auth.New(auth.Options{
			Audit:      trail, // 自学习的审计包装在 api.Server.Handler 中安装
			ConfigUser: a.cfg.Server.Username, ConfigPassword: a.cfg.Server.Password, File: usersFile(a.cfg),
			TTL: a.cfg.Server.SessionTTL, InitialAdmin: os.Getenv("NETSA_ADMIN_PASSWORD"), Require2FA: a.cfg.Server.Require2FA,
		})
		if err != nil {
			return nil, fmt.Errorf("初始化登录账号失败: %w", err)
		}
		s.Auth = m
		ldapAuth, err := sso.NewLDAP(a.cfg.Server.LDAP)
		if err != nil {
			return nil, err
		}
		if ldapAuth != nil {
			m.SetExternalAuth(ldapAuth.Authenticate)
			log.Printf("[auth] 已启用 LDAP 登录: %s", a.cfg.Server.LDAP.URL)
		}
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
	a.forward.Send(al)
	a.playbooks.OnAlert(al)
}

// auditLog 把后台模块的操作写入审计链。
func (a *app) auditLog(user, action, detail string) {
	if a.api != nil && a.api.Trail != nil {
		a.api.Trail.AppendAudit(auth.Record{Time: time.Now(), User: user, Action: action, Detail: detail, OK: true})
	}
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
	defer a.store.CloseJournal()
	if err := a.store.Load(cfg.Storage.Snapshot); err != nil {
		log.Printf("[store] 加载快照失败（将从空状态开始）: %v", err)
	}
	// 快照之后的处置记录（进程异常退出时快照里没有）从预写日志恢复
	if p := cfg.Storage.Snapshot; p != "" {
		if n, err := a.store.OpenIncidentJournal(p + ".journal"); err != nil {
			log.Printf("[store] 打开处置记录日志失败: %v", err)
		} else if n > 0 {
			log.Printf("[store] 已从处置记录日志恢复 %d 次事件变更", n)
		}
	}
	// 快照中的定位结果可能来自旧版定位库或旧的自定义网段，按当前库重新定位
	if n := a.store.RefreshGeo(a.geo.Relocate); n > 0 {
		log.Printf("[geo] 已按当前定位库更新 %d 个历史攻击源的归属地", n)
	}
	// 恢复上次运行自动识别的对外服务（只在实时服务中恢复，离线分析不受历史状态影响）
	if err := a.exposure.SetPath(dataFile(cfg, "", "exposure-learned.json"), time.Now()); err != nil {
		log.Printf("[exposure] 恢复自动识别的对外服务失败（将重新识别）: %v", err)
	} else if n := a.exposure.LearnedCount(); n > 0 {
		log.Printf("[exposure] 已恢复 %d 个自动识别的对外服务", n)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.geo.Start(ctx)
	go a.reloadGeo(ctx, *cfgPath)
	go a.notifier.Run(ctx)
	a.intel.StartTor(ctx, cfg.Intel.TorExitURL)
	a.intel.StartFeeds(ctx, cfg.Intel.Feeds, dataFile(cfg, "", "intel-feeds"))
	a.forward.Start(ctx)
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
	if err := a.ingest.StartFlow(ctx, cfg.Flow); err != nil {
		return fmt.Errorf("启动流量采集失败: %w", err)
	}

	srv, err := a.server(cfg.Server.Listen)
	if err != nil {
		return err
	}
	securityHints(cfg)
	go a.api.RunBackground(ctx) // 每小时记录安全评分，每日推送安全日报
	go a.runBackups(ctx)
	go a.block.Run(ctx)
	go a.playbooks.Run(ctx)
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
			if err := a.authscan.Flush(); err != nil {
				log.Printf("[authscan] %v", err)
			}
			if err := a.deception.Flush(); err != nil {
				log.Printf("[deception] %v", err)
			}
			if err := a.ingest.Senders.Flush(); err != nil {
				log.Printf("[syslog] %v", err)
			}
			if err := a.exposure.Flush(); err != nil {
				log.Printf("[exposure] %v", err)
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
			a.authscan.Flush()
			a.deception.Flush()
			if err := a.learn.Save(); err != nil {
				log.Printf("[learn] 保存学习状态失败: %v", err)
			}
			a.ingest.Senders.Flush()
			if err := a.exposure.Flush(); err != nil {
				log.Printf("[exposure] %v", err)
			}
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
		fmt.Printf("已生成 %d 小时演示日志到 %s/ (access.log, ufw.log, fortigate.log, auth.log, dns.log, process.log)\n", *hours, *dir)
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

// cmdEval 用带标注的样本跑完整检测流水线，输出检出率与误报。不符合期望等级时返回错误，便于接入 CI。
func cmdEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	file := fs.String("corpus", "", "样本文件（默认使用内置样本，格式见 internal/eval/corpus/web.tsv）")
	verbose := fs.Bool("v", false, "列出不符合期望等级的样本")
	asJSON := fs.Bool("json", false, "输出 JSON")
	fs.Parse(args)
	cases, err := eval.Builtin()
	if *file != "" {
		cases, err = eval.LoadFile(*file)
	}
	if err != nil {
		return err
	}
	rep, err := eval.Run(cases)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		rep.Write(os.Stdout, *verbose)
	}
	if rep.Violations > 0 {
		return fmt.Errorf("%d 条样本不符合期望等级", rep.Violations)
	}
	return nil
}

// stateDir 返回状态目录：事件快照所在的目录，其余状态文件都放在这里。
func stateDir(cfg *config.Config) (string, error) {
	if cfg.Storage.Snapshot == "" {
		return "", errors.New("配置中没有 storage.snapshot，无法确定状态目录")
	}
	return filepath.Dir(cfg.Storage.Snapshot), nil
}

// cmdBackup 备份状态目录。
func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("c", "configs/config.yaml", "配置文件")
	out := fs.String("o", "", "备份文件（默认按时间命名，放在当前目录）")
	raw := fs.Bool("rawlog", false, "同时备份原始日志（可能很大）")
	fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	dir, err := stateDir(cfg)
	if err != nil {
		return err
	}
	if *out == "" {
		*out = backup.ScheduledName(time.Now())
	}
	m, err := backup.CreateFile(*out, dir, backup.Options{Version: version, RawLog: *raw})
	if err != nil {
		return err
	}
	fmt.Printf("已备份 %d 个文件到 %s。备份中有密码哈希和模型密钥，请妥善保管。\n", len(m.Files), *out)
	return nil
}

// cmdRestore 恢复状态目录。
func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	cfgPath := fs.String("c", "configs/config.yaml", "配置文件")
	in := fs.String("i", "", "备份文件")
	force := fs.Bool("force", false, "状态目录不是空的时覆盖其中的文件")
	fs.Parse(args)
	if *in == "" {
		return errors.New("请用 -i 指定备份文件")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	dir, err := stateDir(cfg)
	if err != nil {
		return err
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := backup.Restore(f, dir, *force)
	if err != nil {
		return err
	}
	fmt.Printf("已恢复 %d 个文件到 %s（备份版本 %s，生成于 %s）。\n", len(m.Files), dir, m.Version, m.Created.Format("2006-01-02 15:04:05"))
	if m.Version != version {
		fmt.Printf("提示：当前程序版本是 %s，与备份版本不同。低版本程序读取高版本快照可能失败，请使用相同或更高的版本。\n", version)
	}
	return nil
}

// runBackups 按 storage.backup_dir 定时备份。失败只记录日志并写入指标，不影响服务。
func (a *app) runBackups(ctx context.Context) {
	dir := a.cfg.Storage.BackupDir
	state, err := stateDir(a.cfg)
	if dir == "" || err != nil {
		return
	}
	interval := a.cfg.Storage.BackupInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	keep := a.cfg.Storage.BackupKeep
	if keep <= 0 {
		keep = 7
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m, err := backup.CreateFile(filepath.Join(dir, backup.ScheduledName(time.Now())), state, backup.Options{Version: version})
			if err != nil {
				log.Printf("[backup] 定时备份失败: %v", err)
				continue
			}
			log.Printf("[backup] 已备份 %d 个文件到 %s", len(m.Files), dir)
			if err := backup.Rotate(dir, keep); err != nil {
				log.Printf("[backup] 清理旧备份失败: %v", err)
			}
		}
	}
}

// securityHints 启动时提示不安全的部署方式，方便在交付时发现。
func securityHints(cfg *config.Config) {
	if cfg.Server.TLSCert == "" {
		log.Printf("[security] 提示：管理页面未启用 HTTPS（server.tls_cert）；生产环境请配置证书或放在 HTTPS 反向代理之后")
	}
	if cfg.Syslog.Enabled && !cfg.Syslog.Allowlist {
		log.Printf("[security] 提示：syslog 未开启发送端白名单（syslog.allowlist）；任何能访问该端口的主机都可以写入日志")
	}
}

// cmdRulePack 生成规则包密钥、签名规则包。私钥只在签发规则包的机器上使用，不需要放到部署环境。
func cmdRulePack(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: netsa rulepack keygen -o pack.key | netsa rulepack sign -key pack.key -in rules.yaml -name 名称 -serial 序号 -o pack.json")
	}
	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("rulepack keygen", flag.ExitOnError)
		out := fs.String("o", "", "私钥文件")
		fs.Parse(args[1:])
		if *out == "" {
			return errors.New("请用 -o 指定私钥文件")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("创建私钥文件（不会覆盖已有文件）: %w", err)
		}
		defer f.Close()
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err != nil {
			return err
		}
		fmt.Printf("私钥已保存到 %s，请妥善保管。\n把公钥写入 detect.rule_pack_keys：\n%s\n", *out, base64.StdEncoding.EncodeToString(pub))
		return nil
	case "sign":
		fs := flag.NewFlagSet("rulepack sign", flag.ExitOnError)
		keyFile := fs.String("key", "", "私钥文件")
		in := fs.String("in", "", "规则文件（YAML，格式同 detect.rules_file）")
		name := fs.String("name", "", "规则包名称")
		serial := fs.Int64("serial", 0, "序号，必须比已安装的版本大")
		out := fs.String("o", "", "输出文件")
		fs.Parse(args[1:])
		if *keyFile == "" || *in == "" || *name == "" || *serial <= 0 || *out == "" {
			return errors.New("请指定 -key、-in、-name、-serial 和 -o")
		}
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != ed25519.PrivateKeySize {
			return errors.New("私钥文件无效")
		}
		data, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		var file detect.RulesFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("解析规则文件: %w", err)
		}
		if len(file.Rules) == 0 {
			return errors.New("规则文件中没有规则")
		}
		// 签名前确认每条规则都能编译，避免发布一个所有部署都装不上的规则包
		if _, err := detect.NewEngineWith("", file.Rules, 1); err != nil {
			return err
		}
		p := rulemgr.Pack{Name: *name, Serial: *serial, Rules: file.Rules}
		if err := rulemgr.Sign(&p, ed25519.PrivateKey(key)); err != nil {
			return err
		}
		body, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return err
		}
		fmt.Printf("已生成规则包 %s：%d 条规则，序号 %d\n", *out, len(p.Rules), p.Serial)
		return nil
	}
	return fmt.Errorf("未知子命令 %q", args[0])
}

// behavior 创建行为检测：账号盗用按定位库判断登录地点（与状态库使用同一份定位，不发起在线查询）。
func (a *app) behavior(cfg *config.Config) *detect.Behavior {
	b := detect.NewBehavior(cfg.Detect.Thresholds)
	b.Geo = a.geo.Lookup
	return b
}
