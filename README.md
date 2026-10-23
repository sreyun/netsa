# netsa —— 网络安全态势感知与攻击面分析系统

基于 Go 实现，以 **nginx 访问日志** 和 **防火墙日志** 为数据源，自动识别日志格式，完成攻击检测、攻击源溯源定位、威胁评分、态势可视化与攻击面分析。单个二进制、无外部依赖（前端、地图数据与离线定位库均已内置），支持 Docker Compose 一键部署与内网离线运行。

## 功能

| 模块 | 能力 |
| --- | --- |
| 日志采集 | 实时跟踪文件（通配符、自动发现新文件、logrotate 重命名与 copytruncate 轮转、超长行截断）、批量分析（支持 `.gz`）、Syslog UDP/TCP 接收（RFC3164/5424/6587） |
| 格式自动识别 | **Web**：nginx/Apache combined、main（带 XFF）、vhost_combined、JSON（nginx `escape=json`、Caddy、Traefik）、IIS W3C（按 `#Fields` 指令解析）、任意自定义 `log_format`（可直接粘贴 nginx.conf 中的多行写法）<br>**防火墙**：iptables/UFW/firewalld/nftables 内核日志、pfSense/OPNsense filterlog、Windows 防火墙、Cisco ASA/FTD、Palo Alto（TRAFFIC/THREAT CSV）、FortiGate/华为 USG/H3C/深信服/山石等 key=value、JSON 防火墙日志<br>**IDS/IPS**：Suricata EVE JSON、Snort fast alert，以及 FortiGate IPS/UTM 等设备威胁日志（攻击名称映射到攻击分类与等级） |
| 攻击检测 | 69 条特征规则（SQL 注入、XSS、目录穿越/文件包含、命令/代码执行、Log4Shell/OGNL/SpEL/SSTI、SSRF、XXE、反序列化、WebShell、ThinkPHP/WebLogic/Confluence/Exchange/F5/GPON/海康等已知漏洞、国产 OA、敏感文件探测、扫描器/测绘引擎指纹……）+ 行为检测（CC、目录枚举、Web/SSH/RDP 暴力破解及**破解成功研判**、端口扫描、主机横向探测、流量洪泛）<br>多轮 URL 解码、`%u` 编码、HTML 实体、SQL 注释混淆归一化，抵抗常见绕过；Aho-Corasick 多模式预筛 + 由正则语法树推导的必要关键词条件，正常请求无需执行正则 |
| 结果研判 | 依据响应码/响应体大小判断 **已拦截 / 失败 / 服务异常 / 疑似成功 / 未拦截**；仅对 SQL 注入、命令执行、敏感文件等能由响应判断成功的攻击给出“疑似成功”并升级风险 |
| 攻击源溯源 | **真实 IP 还原**：可信代理（含 Cloudflare 内置网段）+ 多种客户端地址头（CF-Connecting-IP、True-Client-IP、Ali-CDN-Real-IP、X-Real-IP、X-Forwarded-For、RFC 7239 Forwarded）右向左解析，识别 XFF 伪造与**绕过 CDN 直连源站**<br>**多源定位**：ip2region（国内到城市+运营商）、MaxMind GeoLite2（经纬度+精度半径+ASN）、ip-api 在线库（经纬度、代理/IDC/移动网络标记）、反向 DNS、**区划地名库**（离线换算城市/省/国家中心坐标）、**自定义网段**（内网办公区/分支机构/VPN 地址池定位到具体地点）；**交叉比对给出置信度**；定位库**热更新**；按需 **RDAP/WHOIS** 查询网段归属与滥用投诉邮箱；识别 IDC/云主机、代理/VPN、Tor、网络空间测绘机构 |
| 威胁画像 | 每个 IP 的威胁评分（0-100）、等级、攻击链阶段（侦察→凭证→利用→后门→影响）、命中规则、攻击目标、端口、UA、最近告警、处置命令；**同源关联分析**：按网段、ASN、工具指纹、攻击手法、攻击目标、扫描端口、测绘机构与时间等线索找出疑似同一攻击者/团伙的其他 IP |
| 攻击面分析 | 自动梳理 Web 入口与网络服务暴露面；发现源码/密钥/备份/配置泄露、调试与管理接口暴露、高危端口对公网放行、疑似被攻破接口、WAF 缺失；识别技术栈；输出处置建议与风险指数 |
| 态势大屏 | **世界 / 中国双视图攻击地图**：城市级标注、国家/省份热力着色、点击省份下钻到地市、点击地点查看该地攻击源列表、实时飞线与告警闪烁、刷新时保留缩放视角、命中自定义网段的内网攻击源以菱形标注；威胁指数、攻击类型/阶段/来源城市/网络类型分布、趋势、实时告警推送（SSE）、全屏大屏模式；统一栅格布局，各面板在常规与全屏下均对齐填满 |
| 处置联动 | 导出封禁列表（txt / nginx deny / 幂等 iptables / ipset / firewalld / Windows / CSV）、Webhook 告警（钉钉 / 企业微信 / 飞书 / 通用 JSON，自动去重限速）、JSON 分析报告 |

## 快速开始（Docker Compose）

```bash
# 演示环境：模拟器持续生成日志，netsa 实时分析，浏览器打开 http://localhost:8080
docker compose -f docker-compose.demo.yml up -d --build

# 生产部署：读取宿主机 /var/log/nginx 与 /var/log 下的防火墙日志，并在 5514 端口接收 syslog
docker compose up -d --build
docker compose logs -f netsa
```

- 国内网络构建镜像较慢时：`GOPROXY=https://goproxy.cn,direct docker compose up -d --build`
- 修改 [configs/docker.yaml](configs/docker.yaml) 后执行 `docker compose restart netsa` 生效（配置以只读方式挂载）。
- 态势数据保存在数据卷 `netsa-state`（`/app/state`），容器重建后自动恢复。
- 容器以非 root 用户（uid 10001）运行，并加入 `adm` 组（gid 4）以读取 nginx 日志；若宿主机日志权限不同，调整 `group_add` 或日志文件权限。
- 日志必须以**目录**方式挂载：logrotate 轮转会创建新文件，单文件挂载会一直指向旧文件。
- 若需在告警中看到网络设备的真实源地址（多设备共用 syslog 端口时），可将服务改为 `network_mode: host`。
- 健康检查：`GET /healthz`（不需要认证）。

## 本地运行

```bash
# 编译（需要 Go 1.22+；纯 Go 实现，无 CGO）
go build -o bin/netsa ./cmd/netsa

# 生成 6 小时演示日志并启动，浏览器打开 http://localhost:8080
./bin/netsa simulate -o demo-logs -hours 6
./bin/netsa serve -c configs/demo.yaml

# 可选：另开终端持续追加实时日志
./bin/netsa simulate -o demo-logs -hours 0 -live
```

离线分析已有日志（自动识别格式，Windows 下通配符由程序自行展开）：

```bash
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -online -listen :8080 access.log      # 启用在线溯源，并在分析后打开大屏
./bin/netsa analyze -format '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $host' access.log
```

交叉编译 Linux 版本：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/netsa-linux-amd64 ./cmd/netsa
```

## 架构

```
 nginx 日志 ─┐                                         ┌─ 特征规则（并行 worker）
 防火墙日志 ─┼─ 采集(tail/批量/syslog) ─ 格式自动识别 ─ 真实IP还原 ─┤
 syslog ────┘                                         └─ 行为检测（时间窗口，内存有上限）
                                                                │
             ┌───────────── 状态库（攻击者画像 / 告警 / 时间序列 / 攻击面）──── 快照持久化
             │                       │
   多源溯源定位（离线同步 + 在线/rDNS 异步 + 区划地名库）    Webhook 告警 / SSE 推送
             │
        REST API + 内嵌 Web 大屏（世界/中国/省级地图）
```

```
cmd/netsa/            命令行入口（serve / analyze / simulate / rules）
internal/parser/      日志解析与格式自动识别（nginx、log_format 编译、各类防火墙、syslog 头）
internal/detect/      URL 归一化、特征规则、结果研判、行为检测
internal/pipeline/    处理流水线、真实 IP 还原、通知去重
internal/geo/         多源定位融合、ip2region / MaxMind / ip-api、区划地名库、RDAP
internal/intel/       本地黑名单、Tor 出口、rDNS 测绘机构识别
internal/store/       攻击者画像与评分、告警、时间序列、地图聚合、攻击面、快照
internal/ingest/      文件跟踪、批量读取、syslog 接收
internal/api/         REST API、SSE、封禁列表导出、安全响应头
web/static/           前端大屏（ECharts、世界地图、中国省级/地市级地图已内置，可离线使用）
data/                 离线定位库（ip2region；MaxMind 可放入此目录）
configs/              config.yaml（本机）、docker.yaml（容器）、demo.yaml（演示）、规则示例
```

## 接入日志

### nginx

默认 `main` / `combined` 格式即可直接识别。站点位于 CDN/负载均衡之后时，务必记录 `$http_x_forwarded_for`，并把 CDN 回源网段加入 `real_ip.trusted_proxies`；多站点建议记录 `$host`：

```nginx
log_format netsa '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_x_forwarded_for" $request_time $host';
access_log /var/log/nginx/access.log netsa;
```

自定义格式时把上面的 `log_format` 原样（可多行）粘贴到数据源的 `log_format` 字段；JSON 格式（`escape=json`）自动识别。远程 nginx 也可直接发送 syslog：`access_log syslog:server=netsa服务器IP:5514,tag=nginx netsa;`

使用 Cloudflare 等 CDN 时，可额外记录 CDN 提供的客户端地址头（如 `"$http_cf_connecting_ip"`，JSON 格式字段名为 `http_cf_connecting_ip`），并配置：

```yaml
real_ip:
  trusted_presets: [cloudflare]                 # 内置 Cloudflare 回源网段
  headers: [cf_connecting_ip, x_forwarded_for]  # 按优先级尝试
  cdn_only: true                                # 源站只应经 CDN 访问：公网直连会告警“绕过 CDN 直连源站”
```

只有请求确实来自可信代理时才采信这些请求头，攻击者直连源站时伪造的 X-Forwarded-For 不会改变攻击源，且会被标记为“伪造 X-Forwarded-For”。

### 其他 Web 服务器

- **Apache**：默认 combined 格式直接识别。
- **IIS**：W3C 扩展日志（`u_ex*.log`），按文件中的 `#Fields:` 指令自动映射字段，建议勾选 `X-Forwarded-For` 自定义字段。
- **Caddy / Traefik**：JSON 访问日志直接识别（Caddy `request.remote_ip`、`request.headers`；Traefik `ClientHost`、`RequestPath` 等）。

### 防火墙

- **UFW**：`ufw logging medium`，日志 `/var/log/ufw.log`
- **firewalld**：`firewall-cmd --set-log-denied=all`，日志位于 `kern.log`（Debian/Ubuntu）或 `messages`（RHEL）
- **iptables**：在 DROP 前加 `iptables -A INPUT -j LOG --log-prefix "[IPTABLES DROP] "`（前缀含 DROP/REJECT/ACCEPT 等关键字用于判断动作）
- **网络设备**（FortiGate、华为、H3C、Cisco ASA、Palo Alto、pfSense 等）：syslog 发送到 `netsa服务器:5514`（UDP/TCP），并开启策略允许/拒绝日志；FortiGate/Palo Alto 的 IPS/威胁日志会直接按攻击名称归类
- **Windows**：`netsh advfirewall set allprofiles logging droppedconnections enable`，日志 `%windir%\system32\LogFiles\Firewall\pfirewall.log`
- **Suricata**：跟踪 `eve.json`，`alert` 事件按签名映射为攻击；建议在 `suricata.yaml` 中为 netsa 单独输出一个只含 `alert` 类型的 eve 文件，减少无关事件
- **Snort**：跟踪 fast 格式的 `alert` 文件，或通过 syslog 发送

接入后在大屏 **数据源** 页查看自动识别的格式、解析成功/失败数与失败样例。注意 `timezone` 需与日志产生方一致（syslog 等日志不含时区）。

## 攻击源溯源定位

| 数据源 | 精度与用途 | 获取方式 |
| --- | --- | --- |
| ip2region（已内置） | 国内地址精确到城市 + 运营商；境外到省/州 | `data/ip2region_v4.xdb`、`data/ip2region_v6.xdb`，可从 ip2region 项目更新 |
| 区划地名库（已内置） | 只有地名时换算为城市/省/国家中心坐标，离线也能在地图上落到具体城市 | 来自内置的 ECharts 世界/中国/省级地图数据 |
| MaxMind GeoLite2 | 经纬度 + 精度半径 + ASN，境外地址更准 | maxmind.com 免费注册下载 `GeoLite2-City.mmdb`、`GeoLite2-ASN.mmdb` 放入 `data/`（容器挂载到 `/app/data/`） |
| ip-api 在线库 | 经纬度、ASN、代理/IDC/移动网络标记、反向解析 | `geo.online.enabled`，只对达到 `enrich_level` 的攻击 IP 查询，失败自动重试 |
| 反向 DNS | 识别 Shodan/Censys 等测绘机构、搜索引擎爬虫 | `geo.reverse_dns` |
| RDAP/WHOIS | 网段归属组织、CIDR、滥用投诉邮箱 | IP 详情页按需查询 |

- **融合策略**：国内地址优先 ip2region，境外地址优先 MaxMind/在线库；各数据源国家判定不一致时，位置字段只采用与最终国家一致的数据源；坐标所属城市与采信城市不一致时改用采信城市的中心点，保证地图标注与归属地一致。
- **坐标标识**：地图上实心点为数据源给出的精确坐标，空心点为按区划中心换算的近似位置；IP 详情中注明坐标来源。
- **置信度**：多个数据源城市级一致或 MaxMind 精度半径 ≤ 20km 为“高”；单一数据源到城市为“中”；只有国家或国家冲突为“低”，并给出说明。
- **能力边界**：IP 定位只能到城市/机房级，无法定位到具体个人；攻击者常借助云主机、代理、VPN、Tor 或被控“肉鸡”发起攻击，系统会标注这些情况，溯源结论需结合 RDAP 归属、攻击手法与时间线综合研判。

### 内网攻击源与自定义网段

内网地址不在任何公共定位库中。通过 `geo.custom` 把办公网、分支机构、VPN 地址池、合作方出口等网段标注到具体地点后，内网横向攻击、失陷主机外联扫描等也能在地图上落到对应办公地点（菱形标注），IP 详情中显示所属网段名称：

```yaml
geo:
  custom:
    - { cidr: 10.10.0.0/16, name: 北京总部办公网, country: 中国, province: 北京市, city: 北京市 }
    - { cidr: 10.20.0.0/16, name: 上海研发中心, country: 中国, province: 上海市, city: 上海市, lat: 31.2304, lon: 121.4737 }
    - { cidr: 172.16.100.0/24, name: VPN 地址池, country: 中国, province: 广东省, city: 深圳市, isp: SSL VPN }
```

- 按**最长前缀**匹配，优先级高于所有定位库；也可用于公网网段（如合作方专线出口），此时运营商、ASN 等字段仍取自定位库。
- 未填写 `lat/lon` 时按省/市名称换算区划中心；未命中任何自定义网段的内网地址统一归入“内网”，坐标取 `home`（受保护资产所在地），不参与国家/省份着色。

### 定位库热更新

`geo.reload_interval`（默认 `10m`，`0` 关闭）周期检查 ip2region / MaxMind 库文件的修改时间与大小，文件被替换后在后台重新加载，并按新库刷新所有攻击源（包括从快照恢复的历史攻击源）的归属地；同时重新读取配置文件中的 `geo.custom`，增删网段无需重启。

- 更新库文件时请先写临时文件再 `mv` 覆盖；刚修改不足 3 秒的文件会留到下一轮再加载，避免读到未复制完的文件。
- 新库加载失败时继续使用旧库并记录日志；启动时库文件尚不存在也没关系，文件就绪后会自动加载。
- 服务启动加载快照后也会按当前库重新定位一次，已完成的在线溯源与 rDNS 结果会被保留，不会重复查询。

### 同源关联分析

IP 详情页的“同源关联分析”在全部攻击源中查找与当前 IP 疑似同源的地址，按线索加权给出 0-100 的关联度：

| 线索 | 说明 |
| --- | --- |
| 同网段 | 同一 /24（IPv6 为 /48）权重最高，同一 /16（IPv6 /32）为辅助线索 |
| 工具指纹 | 共用非浏览器 User-Agent（sqlmap、nuclei、自研脚本等）；curl、Go-http-client 等被大量攻击源共用的通用 UA 降权；共用罕见的浏览器 UA 也计入 |
| 攻击手法 | 命中规则集合的 Jaccard 相似度，共同目标路径数，防火墙扫描端口组合相似度 |
| 基础设施 | 同一 IDC/云厂商 ASN、反向解析同属一个域名、同属一家测绘机构、同属一个自定义网段 |
| 时间 | 已有其他线索时，首次出现时间相差 10 分钟以内作为佐证 |

- 同 ASN 属于弱线索：大型云厂商/运营商下的攻击源很多，单凭 ASN 不会列出关联。
- 关联度 ≥ 60 视为强关联（疑似同一攻击者或团伙），处置建议中会提示一并封禁；同网段攻击源较多时提示按网段封禁。
- 规则集合用位图指纹按位运算精确比对，候选只保留前 30 名，比对过程几乎不分配内存；全量比对分批进行，每批 4096 个攻击源后释放读锁，不会阻塞日志写入。基准测试（i7-10700）中 2 万攻击源单次约 10ms，20 万攻击源约 150ms。

## 威胁评分模型

- 按攻击分类累计：分类权重（低 5 / 中 12 / 高 25 / 严重 45）×（1 + log2(次数)/3，最多 2 倍），侦察类 ×0.6
- 疑似攻击成功 +20；跨越多个攻击阶段每多一个阶段 +10；命中威胁情报 +30；上限 100
- 等级：≥80 严重、≥50 高危、≥25 中危、>0 低危；命中高危/严重规则时等级不低于其下一级
- 威胁指数：最近 60 分钟按严重程度加权的攻击量，经指数饱和映射到 0-100

## 配置要点

完整说明见 [configs/config.yaml](configs/config.yaml)。配置采用严格解析，拼写错误的配置项会在启动时报错。

| 配置项 | 说明 |
| --- | --- |
| `timezone` | 不带时区的日志时间所用时区，例如 `Asia/Shanghai` |
| `server.username/password` | HTTP Basic 认证（公网部署务必开启） |
| `server.web_dir` / `serve -web` | 从磁盘目录加载前端页面，用于定制界面 |
| `detect.whitelist` | 自有监控、扫描器等白名单，只统计流量不检测 |
| `detect.rules_file` | 自定义规则；与内置规则 ID 相同时覆盖内置规则，`disable` 可禁用内置规则，`methods` 可限定 HTTP 方法 |
| `real_ip.trusted_proxies` / `trusted_presets` | 可信代理网段；`trusted_presets: [cloudflare]` 使用内置的 Cloudflare 回源网段 |
| `real_ip.headers` | 按优先级尝试的客户端地址头：`cf_connecting_ip`、`true_client_ip`、`ali_cdn_real_ip`、`x_client_ip`、`x_real_ip`、`x_forwarded_for`、`forwarded` |
| `real_ip.cdn_only` | 源站只应经 CDN 访问时开启，公网直连标记为“绕过 CDN 直连源站” |
| `geo.online.enabled` | 在线溯源开关（会把攻击 IP 发送到 ip-api.com） |
| `geo.enrich_level` | 达到该等级的攻击 IP 才做在线查询与反向 DNS |
| `geo.custom` | 自定义网段位置（内网办公区、分支机构、VPN 地址池等） |
| `geo.reload_interval` | 定位库与自定义网段的热更新检查周期，`0` 关闭 |
| `storage.snapshot` | 状态快照路径（`.gz` 结尾自动压缩） |

## API

| 接口 | 说明 |
| --- | --- |
| `GET /healthz` | 健康检查（无需认证） |
| `GET /api/meta` | 版本、定位数据源、省级地图索引 |
| `GET /api/overview` | 态势总览（KPI、分布、城市排行、威胁指数） |
| `GET /api/timeline?minutes=360` | 趋势数据 |
| `GET /api/map?level=` | 地图数据：城市级地点（含攻击源列表）、国家与省份着色统计 |
| `GET /api/attackers?level=&q=&sort=&limit=&offset=` | 攻击源列表 |
| `GET /api/ip/{ip}` / `GET /api/ip/{ip}/rdap` | IP 溯源详情（含 `related` 同源关联分析）/ WHOIS 注册信息 |
| `GET /api/alerts?severity=&category=&result=&kind=&ip=&q=` | 告警查询 |
| `GET /api/surface` | 攻击面分析 |
| `GET /api/sources` / `GET /api/rules` | 数据源与运行状态 / 规则列表 |
| `GET /api/stream` | SSE 实时告警流 |
| `GET /api/export/blocklist?format=nginx&level=high` | 导出封禁列表 |
| `GET /api/report` | 完整 JSON 报告 |

## 注意事项

- 开启在线溯源时，攻击 IP（不含正常访客）会被发送至 ip-api.com；内网隔离或合规要求不允许外发时请关闭 `geo.online.enabled`，此时由 ip2region + 区划地名库提供城市级离线定位。ip-api 免费接口为 HTTP、限速 15 批/分钟，程序已自动限速。
- 对于所有路径都返回 200 的单页应用（SPA），敏感文件探测可能被误判为“疑似成功”，可调整 `detect.success_min_bytes` 或将结果作为线索复核；扫描器的随机路径不会被登记为 Web 资产。
- 页面启用了 CSP 等安全响应头，日志中的攻击载荷仅作为文本展示。
- 性能：解析与检测由多个 worker 并行、按批（256 条）传递，聚合入库一次加锁处理一批。开发机（i7-10700，16 线程）端到端基准测试约 40 万条/秒以上，正常请求检测约 3.5µs/条（`go test -bench . ./internal/pipeline`）；正常访客只保存轻量画像，行为检测窗口有容量上限。
