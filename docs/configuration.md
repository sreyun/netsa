# 配置参考

[← 返回 README](../README.md)

常用配置项与运行注意事项，完整说明见 [configs/config.yaml](../configs/config.yaml)。

## 常用配置项

配置采用严格解析，拼写错误的配置项会在启动时报错。

| 配置项 | 说明 |
| --- | --- |
| `timezone` | 不带时区的日志时间所用时区，例如 `Asia/Shanghai`；也是页面与告警消息的展示时区 |
| `time_correction` | `auto`（默认）自动校正实时日志的整时区偏差，`off` 关闭 |
| `server.auth` | 登录认证，默认开启 |
| `server.username/password` | 配置文件中的管理员账号（可选，只读）；`password` 可用 `netsa hash-password` 生成的哈希 |
| `server.users_file` / `session_ttl` | 账号文件位置 / 登录有效期（默认 12h，自动续期） |
| `server.tls_cert` / `tls_key` | 直接提供 HTTPS |
| `server.allow_networks` | 只允许这些来源网段访问大屏与 API（本机与 `/healthz` 不受限）；反向代理之后需配合 `real_ip.trusted_proxies` |
| `server.require_2fa` | 强制所有界面账号绑定身份验证器（双因素认证） |
| `syslog.tls` / `tls_cert` / `tls_key` / `tls_client_ca` | syslog over TLS 监听与证书；配置客户端 CA 时要求双向认证 |
| `syslog.allowlist` / `senders` / `rate_limit` | 发送端白名单（`true` 时界面不能关闭）/ 配置文件登记的发送端（名称、分组、`allow` / `block`、断流阈值）/ 单发送端每秒日志上限 |
| `alert.source_silence` / `sources[].silence` | 数据源断流告警的默认阈值（默认 30m，`off` 关闭）/ 单个数据源的阈值 |
| `rawlog.*` | 原始日志留存：`enabled`、`dir`、`retention_days`（默认 180）、`max_size_gb`、`attacks_only` |
| `audit.dir` / `retention_days` | 防篡改审计链的目录与留存天数（默认 180） |
| `report.recipients` / `weekly` / `monthly` / `smtp.*` | 周报 / 月报的收件人、发送时间（如 `mon 09:00`、`1 09:00`）与发信服务器 |
| `intel.blocklists` / `tor_exit_url` | 威胁情报：命中的来源告警，内网主机外连其中地址判为疑似失陷 |
| `alert.base_url` / `dedup_window` | 告警消息中的大屏链接 / 推送去重窗口 |
| `alert.report_time` | 每日安全日报推送时间（HH:MM，按 `timezone`，默认 09:00，`off` 关闭）；机器人需勾选“接收每日安全日报” |
| `detect.thresholds` | 行为检测阈值：CC、目录扫描、暴力破解、端口扫描、主机探测、洪泛，以及分布式暴力破解（`dist_window`、`dist_brute_*`）、分布式 CC（`dist_cc_*`）、多源 DDoS（`ddos_events`、`ddos_sources`）、接口遍历（`enum_*`）、周期性外连（`beacon_conns`）、主机认证（`auth_failures`、`auth_users`）、DNS（`dns_nxdomain`、`dns_subdomains`） |
| `alert.webhooks` | 配置文件方式的告警机器人：`type`、`url`、`secret`（加签）、`levels`（多选 medium / high / critical） |
| `server.web_dir` / `serve -web` | 从磁盘目录加载前端页面，用于定制界面 |
| `detect.whitelist` | 自有监控、扫描器等白名单，只统计流量不检测 |
| `detect.rules_file` | 自定义规则；与内置规则 ID 相同时覆盖内置规则，`disable` 可禁用内置规则，`methods` 可限定 HTTP 方法 |
| `real_ip.trusted_proxies` / `trusted_presets` | 可信代理网段；`trusted_presets: [cloudflare]` 使用内置的 Cloudflare 回源网段 |
| `real_ip.auto_learn` | 反向代理自动识别（默认开启）：内网 / 本机地址持续携带 X-Forwarded-For 且客户端分散时自动按可信代理还原；公网节点只提示 |
| `real_ip.headers` | 按优先级尝试的客户端地址头：`cf_connecting_ip`、`true_client_ip`、`ali_cdn_real_ip`、`x_client_ip`、`x_real_ip`、`x_forwarded_for`、`forwarded` |
| `real_ip.cdn_only` | 源站只应经 CDN 访问时开启，公网直连标记为“绕过 CDN 直连源站” |
| `geo.online.enabled` | 在线溯源开关（会把攻击 IP 发送到 ip-api.com） |
| `geo.enrich_level` | 达到该等级的攻击 IP 才做在线查询与反向 DNS |
| `geo.custom` | 自定义网段位置（内网办公区、分支机构、VPN 地址池等） |
| `geo.intranet` | 内网网段：RFC1918 之外、但实际用在内网的公网地址段（如 `172.168.100.0/24`）；命中后不查询定位库、不参与境外着色 |
| `geo.detect_local_networks` | 启动时自动把本机网卡网段并入内网（默认 `true`）；主机本身位于公网段时建议关闭 |
| `exposure.enabled` | 开启“未做 DNAT 映射的端口探测”过滤（默认关闭）；开启后未发布端口上的探测与端口级暴力破解只打标签 |
| `exposure.services` / `allowed_ports` | DNAT 精确映射（公网 IP:端口 → 内网 IP:端口）/ 兜底端口白名单 |
| `exposure.reach_check` | 会话证据研判（默认开启）：防火墙放行但日志表明未到达服务（目的安全域仍为外网、会话结束时目标无应答）的端口探测只打标签 |
| `exposure.suggest` | 候选映射统计（`min_allows` / `min_sources`）：从放行连接反推可能漏登记的映射，只提示不生效 |
| `geo.reload_interval` | 定位库与自定义网段的热更新检查周期，`0` 关闭 |
| `storage.snapshot` | 状态快照路径（`.gz` 结尾自动压缩） |
| `archive.dsn` / `NETSA_ARCHIVE_DSN` | 可选的 PostgreSQL 告警归档连接串，不配置则不启用 |
| `archive.retention_years` | 归档保留周期（年）：`0` 永久保留（默认）；`N` 至少保留最近 N 年，更早的月分区整表删除 |
| `archive.batch_size` / `flush_interval` / `queue_size` | 每批写入条数（1000）/ 最长等待（2s）/ 内存队列容量（10 万） |

## 运行注意事项

- 开启在线溯源时，攻击 IP（不含正常访客）会被发送至 ip-api.com；内网隔离或合规要求不允许外发时请关闭 `geo.online.enabled`，此时由 ip2region + 区划地名库提供城市级离线定位。ip-api 免费接口为 HTTP、限速 15 批/分钟，程序已自动限速。
- 对于所有路径都返回 200 的单页应用（SPA），平台学到首页的响应大小后会自动识别兜底页面，不再判为“疑似成功”；学到之前最高判为高危，可将结果作为线索复核；扫描器的随机路径不会被登记为 Web 资产。
- 页面启用了 CSP、X-Frame-Options、Permissions-Policy、跨源隔离（COOP/CORP）等安全响应头，HTTPS 下启用 HSTS；日志中的攻击载荷仅作为文本展示；所有写操作校验同源（防 CSRF），请求体限制大小；导出的 CSV 对以 = + - @ 开头的单元格做转义，防止在 Excel 中触发公式注入；快照、账号、机器人配置文件权限均为 0600。
- 健壮性：单条畸形日志触发的解析 / 检测异常只跳过该条，不影响服务；画像数与行为检测窗口均有硬上限（大量伪造源地址的扫描不会耗尽内存）；未来时间的异常日志不会污染统计窗口；syslog TCP 支持 octet-counting 帧并限制并发连接与空闲时长；文件轮转后会继续读取旧文件中延迟写入的日志。
- 快照：每个 `storage.interval` 保存一次，画像分批编码、压缩与写盘在锁外进行（6 万个攻击源保存约 0.6 秒，期间日志入库最长等待约 30ms），重启后自动恢复并按当前评分规则重新计算等级。
- 快照带版本号（当前 `v2`，对应事件「命中 / 告警」双计数）：读取旧版本会自动迁移；读到**更新版本**或损坏的文件时拒绝加载，并把原文件改名为 `<快照>.v<N>.bak` / `<快照>.corrupt.bak` 保留，绝不被空状态覆盖。升级后如需回滚，请一并回滚快照或手工保留备份。
- 连接超时：读取请求（含请求体）限时 30 秒、写出响应限时 2 分钟，防止慢速连接长期占用资源；实时告警流与历史告警导出单独放宽。
- 性能：解析与检测由多个 worker 并行、按批（256 条）传递，聚合入库一次加锁处理一批。开发机（i7-10700，16 线程）端到端约 46 万条/秒，正常请求检测约 3µs/条（`go test -bench . ./internal/pipeline`）；正常访客只保存轻量画像，行为检测窗口有容量上限。
- 聚合接口不扫描全量画像：总览（国家/省份/城市/运营商/网络类型/目标/近 1 小时）与安全评估（情报命中、暴力破解/扫描/CC/端口来源数、ATT&CK 矩阵的攻击源数与最高等级）都在画像新增、攻击类型增加、等级变化、归属地更新与淘汰时增量维护，读取只做小规模拷贝。5 万攻击源下 `Overview` 约 6µs、`Assess` 约 0.1ms，避免长事务持锁阻塞日志入库；一致性由 `store/aggregate_test.go` 与全量扫描逐项对账。
