# netsa —— 网络安全态势感知与攻击面分析系统

基于 Go 实现，以 **nginx 访问日志**、**防火墙 / IDS 日志**、**主机认证日志** 与 **DNS 日志** 为数据源，自动识别日志格式，完成攻击检测、攻击源溯源定位、威胁评分、态势可视化与攻击面分析，并提供事件处置、误报抑制、资产与漏洞关联、原始日志留存、周报月报与等保合规等安全运营能力。单个二进制、无外部依赖（前端、地图数据与离线定位库均已内置；可选接入 PostgreSQL 长期归档告警），支持 Docker Compose 一键部署与内网离线运行。

## 功能

| 模块 | 能力 |
| --- | --- |
| 日志采集 | 实时跟踪文件（通配符、自动发现新文件、logrotate 重命名与 copytruncate 轮转、超长行截断）、批量分析（支持 `.gz`）、Syslog UDP/TCP 接收（RFC3164/5424/6587）、**Syslog over TLS（RFC 5425，可双向认证）**；**syslog 发送端识别、登记、分组、白名单 / 阻止与限速**；数据源与发送端**断流告警** |
| 格式自动识别 | **Web**：nginx/Apache combined、main（带 XFF）、vhost_combined、JSON（nginx `escape=json`、Caddy、Traefik）、IIS W3C（按 `#Fields` 指令解析）、任意自定义 `log_format`（可直接粘贴 nginx.conf 中的多行写法）<br>**防火墙**：iptables/UFW/firewalld/nftables 内核日志、pfSense/OPNsense filterlog、Windows 防火墙、Cisco ASA/FTD、Palo Alto（TRAFFIC/THREAT CSV）、FortiGate/华为 USG/H3C/深信服/山石等 key=value、JSON 防火墙日志<br>**IDS/IPS**：Suricata EVE JSON、Snort fast alert，以及 FortiGate IPS/UTM 等设备威胁日志（攻击名称映射到攻击分类与等级）<br>**主机 / VPN 认证**：Linux auth.log / secure、Windows 安全事件（NXLog / Winlogbeat / Snare）、FortiGate / Cisco / OpenVPN VPN 登录、SQL Server 登录<br>**DNS**：BIND、dnsmasq、CoreDNS、Windows DNS、Zeek、Suricata DNS |
| 攻击检测 | 69 条特征规则（SQL 注入、XSS、目录穿越/文件包含、命令/代码执行、Log4Shell/OGNL/SpEL/SSTI、SSRF、XXE、反序列化、WebShell、ThinkPHP/WebLogic/Confluence/Exchange/F5/GPON/海康等已知漏洞、国产 OA、敏感文件探测、扫描器/测绘引擎指纹……）+ 行为检测（CC、目录枚举、Web/SSH/RDP 暴力破解及**破解成功研判**、**分布式暴力破解 / 撞库**（大量来源各尝试少量几次）、**接口遍历 / 批量爬取**（按 ID 遍历用户、订单等对象）、端口扫描、主机横向探测、流量洪泛）<br>**主机与 DNS**：SSH / RDP / VPN 暴力破解、密码喷洒、**破解成功（账号失陷）**、日志被清除、新建账号 / 提权、服务与计划任务持久化；DNSLog 带外回连、DNS 隧道、DGA 与 NXDOMAIN 风暴、矿池与动态域名<br>多轮 URL 解码、`%u` 编码、HTML 实体、SQL 注释混淆归一化，抵抗常见绕过；Aho-Corasick 多模式预筛 + 由正则语法树推导的必要关键词条件，正常请求无需执行正则 |
| 结果研判 | 依据响应码/响应体大小判断 **已拦截 / 失败 / 服务异常 / 疑似成功 / 未拦截**；仅对 SQL 注入、命令执行、敏感文件等能由响应判断成功的攻击给出“疑似成功”并升级风险 |
| 攻击源溯源 | **真实 IP 还原**：可信代理（含 Cloudflare 内置网段）+ 多种客户端地址头（CF-Connecting-IP、True-Client-IP、Ali-CDN-Real-IP、X-Real-IP、X-Forwarded-For、RFC 7239 Forwarded）右向左解析，识别 XFF 伪造与**绕过 CDN 直连源站**<br>**多源定位**：ip2region（国内到城市+运营商）、MaxMind GeoLite2（经纬度+精度半径+ASN）、ip-api 在线库（经纬度、代理/IDC/移动网络标记）、反向 DNS、**区划地名库**（离线换算城市/省/国家中心坐标）、**自定义网段**（内网办公区/分支机构/VPN 地址池定位到具体地点）；**交叉比对给出置信度**；定位库**热更新**；按需 **RDAP/WHOIS** 查询网段归属与滥用投诉邮箱；识别 IDC/云主机、代理/VPN、Tor、网络空间测绘机构 |
| 威胁画像 | 每个 IP 的威胁评分（0-100）、等级、攻击链阶段（侦察→凭证→利用→后门→影响）、命中规则、攻击目标、端口、UA、最近告警、处置命令；**同源关联分析**：按网段、ASN、工具指纹、攻击手法、攻击目标、扫描端口、测绘机构与时间等线索找出疑似同一攻击者/团伙的其他 IP |
| 攻击面分析 | 自动梳理 Web 入口与网络服务暴露面；发现源码/密钥/备份/配置泄露、调试与管理接口暴露、高危端口对公网放行、疑似被攻破接口、WAF 缺失；识别技术栈；输出处置建议与风险指数 |
| 态势大屏 | **世界 / 中国双视图攻击地图**：城市级标注、国家/省份热力着色、点击省份下钻到地市、点击地点查看该地攻击源列表、实时飞线与告警闪烁、刷新时保留缩放视角、命中自定义网段的内网攻击源以菱形标注；威胁指数、攻击类型/阶段/来源城市/网络类型分布、趋势、实时告警推送（SSE）、全屏大屏模式；统一栅格布局，各面板在常规与全屏下均对齐填满<br>**全面下钻**：KPI 卡片、威胁指数、攻击类型、攻击链阶段、趋势图任意时间点、来源国家 / 城市 / 网络类型、被攻击目标、地图上的国家 / 省份 / 地市 / 地点均可点击，直接列出对应的攻击源或告警（条目数量与图表一致），并可一键转到归档库查询更早的告警 |
| 安全评估 | 从**失陷风险、暴露面、Web 防护、凭证安全、边界防护、威胁活跃度、日志与检测覆盖**七个维度打分，给出 A~E 总评与一句话结论；自动生成 **P0~P3 分级处置建议**（含具体操作步骤与 nginx / 防火墙配置示例），一键下钻到相关告警、攻击源或资产；**失陷研判**汇总疑似失陷的 Web 资产与主机；**MITRE ATT&CK 战术 / 技术矩阵**展示攻击手法分布与检测覆盖；支持打印 / 导出 PDF 评估报告 |
| 失陷检测 | **内网主机外连威胁情报地址**（木马回连 C2、挖矿、数据外传）判定为疑似失陷，放行为严重、拦截为高危；安全设备报出的内网主机恶意软件 / 远控通信同样记为失陷迹象；**无需情报的 C2 心跳检测**：内网主机按固定间隔（1 分钟~1 小时，波动不超过 12%）反复连接同一外部地址，判定为疑似失陷（中置信）；攻击成功研判按资产合并并给出置信度（WebShell 交互、命令执行成功或多种成功迹象为高置信） |
| 处置联动 | 导出封禁列表（txt / nginx deny / 幂等 iptables / ipset / firewalld / Windows / CSV）、JSON 分析报告 |
| 告警推送 | **钉钉 / 企业微信 / 飞书群机器人**（及通用 JSON Webhook）：每个机器人可**多选推送等级（中危 / 高危 / 严重）**，在大屏中添加、测试、启停；支持加签；去重、合并、按平台限速，超出部分汇总推送不丢失；附“查看溯源详情”链接 |
| 登录与权限 | 专业安全平台风格的登录页（动态点阵地球与攻击轨迹），账号密码登录（PBKDF2 哈希），**管理员 / 运营分析员 / 只读**三种角色，**双因素认证（TOTP 动态口令 + 一次性恢复码，可强制开启）**，**API 令牌**（Bearer，可设权限与有效期，含仅监控指标权限），首次登录强制修改初始密码，登录失败锁定，会话自动续期，可选 HTTPS |
| 事件处置 | 告警按来源自动聚合为**安全事件**：待处理 / 处置中 / 已处置 / 误报 / 忽略，指派负责人、处置记录、批量处置，按等级与资产重要性计算**处置时限并推送超时提醒**；**误报抑制**规则（规则 + 类型 + 来源 + 目标组合、有效期、命中计数） |
| 资产与漏洞 | 导入 CMDB 资产（负责人、部门、业务重要性、等保级别）与漏洞扫描结果（Nessus / OpenVAS / 绿盟等 CSV）；告警标注目标资产，**攻击利用的 CVE 在目标上存在时升级为严重并研判为疑似成功** |
| 原始日志留存 | 按小时压缩留存（默认 180 天），按时间 / IP / 关键字检索、查看告警前后的原始日志、取证导出，**SHA-256 哈希链防篡改**校验 |
| 报表与合规 | **周报 / 月报**（可打印为 PDF，定时邮件发送）、**等保 2.0（第三级）合规检查报告**（逐项判定、证据与整改建议）、**防篡改审计链**（登录、配置变更、处置、检索与导出，可校验、导出 CSV / JSONL）、Prometheus **`/metrics`** 监控指标 |
| 告警归档（可选） | 配置 PostgreSQL 后告警**异步批量写入、按月自动分区**，长期留存；按**时间 / IP / 网段 / 规则 / 等级 / 类型 / 关键字**检索历史告警，统计 TOP 来源与规则、每日趋势，导出 CSV；不配置时保持单二进制无依赖部署 |
| 时间与时区 | 日志时间按 `timezone` 解析，**实时日志整时区偏差自动校正**（如设备按 UTC 记录导致慢 8 小时），页面与告警消息统一按配置时区展示 |

## 快速开始（Docker Compose）

```bash
# 演示环境：模拟器持续生成日志，netsa 实时分析，浏览器打开 http://localhost:8080
docker compose -f docker-compose.demo.yml up -d --build

# 生产部署：读取宿主机 /var/log/nginx 与 /var/log 下的防火墙日志，并在 5514 端口接收 syslog
docker compose up -d --build
docker compose logs -f netsa
```

- **登录**：演示环境账号 `admin` / `Netsa@demo2026`（见 [configs/demo.yaml](configs/demo.yaml)）。生产部署首次启动会自动创建管理员 `admin` 并在日志中输出初始密码：`docker compose logs netsa | grep 初始密码`，首次登录后须修改；也可在 `docker-compose.yml` 中通过 `NETSA_ADMIN_PASSWORD` 指定。
- 国内网络构建镜像较慢时：`GOPROXY=https://goproxy.cn,direct docker compose up -d --build`
- 修改 [configs/docker.yaml](configs/docker.yaml) 后执行 `docker compose restart netsa` 生效（配置以只读方式挂载）。
- 态势数据保存在数据卷 `netsa-state`（`/app/state`），容器重建后自动恢复。
- 容器以非 root 用户（uid 10001）运行，并加入 `adm` 组（gid 4）以读取 nginx 日志；若宿主机日志权限不同，调整 `group_add` 或日志文件权限。
- 日志必须以**目录**方式挂载：logrotate 轮转会创建新文件，单文件挂载会一直指向旧文件。
- 若需在告警中看到网络设备的真实源地址（多设备共用 syslog 端口时），可将服务改为 `network_mode: host`。
- 健康检查：`GET /healthz`（不需要认证）。

### 镜像构建与发布（华为云 SWR）

创建 tag 后，[.github/workflows/docker.yml](.github/workflows/docker.yml) 自动构建多架构镜像并推送到华为云容器镜像服务（SWR）；登录凭证由 AK/SK 现场推导，无需在控制台生成长期登录密文。

| 触发 | 行为 |
|---|---|
| 创建 tag `v1.6.4` | 构建 + 启动自检 + 推送：`1.6.4`、`1.6`、`1`、`latest`、`sha-xxxxxxx` |
| 创建预发布 tag `v1.6.4-rc1` | 只推 `1.6.4-rc1`、`sha-xxxxxxx`，不动 `latest` / `1.6` / `1` |
| 推送 `master` / Pull Request | 不构建镜像（质量门禁由 `ci` 工作流负责） |
| 手动触发（workflow_dispatch） | 填写要发布的 tag 与是否更新 `latest`；按该 tag 检出源码，版本与内容严格对应 |

发布流程：

```bash
git tag v1.6.4 && git push origin v1.6.4
```

需要在仓库 **Settings → Secrets and variables → Actions** 配置两个 Secret：

| Secret | 说明 |
|---|---|
| `HW_ACCESS_KEY` | 华为云访问密钥 AK（对应 IAM 用户需具备 SWR 推送权限） |
| `HW_SECRET_KEY` | 华为云秘密密钥 SK |

SWR 登录凭证的推导方式（工作流内自动完成）：用户名为 `{region}@{AK}`，密码为 `HMAC-SHA256(key=SK, data=AK)` 的十六进制，即

```bash
printf '%s' "$AK" | openssl dgst -binary -sha256 -hmac "$SK" | od -An -vtx1 | tr -d ' \n'
```

可选 Variables（不配置则用默认值）：

| Variable | 默认值 | 说明 |
|---|---|---|
| `SWR_REGISTRY` | `swr.cn-east-3.myhuaweicloud.com` | 仓库域名，区域需与组织一致 |
| `SWR_NAMESPACE` | `sreyun` | SWR 组织名（需先在控制台创建） |
| `IMAGE_NAME` | `netsa` | 镜像名 |
| `GOPROXY` | `https://goproxy.cn,direct` | 构建时的 Go 模块代理 |

```bash
docker pull swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:1.6.4
docker run -d --name netsa -p 8080:8080 -p 5514:5514/udp -v netsa-state:/app/state \
  swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:1.6.4
```

- **版本随 tag 注入**：构建时通过 `-ldflags "-X main.version=<tag>"` 写入二进制，`netsa version` 与 `/api/meta` 显示的就是发布版本；本地 `docker compose build` 不传该参数，仍使用源码中的默认版本。
- **推送前自检**：先用 amd64 构建并实际运行 `netsa rules` / `netsa version`，确认二进制可执行、规则可加载、版本与 tag 一致后才推送多架构镜像。

质量门禁由 [.github/workflows/ci.yml](.github/workflows/ci.yml) 负责：`gofmt`、`go vet`、前端语法检查，以及两轮测试——`go test -race -short ./...` 验证并发正确性（race 检测会让用例慢 5~10 倍，故走降级规模），`go test ./...` 以完整规模验证性能退化类断言。
- **SWR 介质类型**：使用 `outputs: type=registry,oci-mediatypes=false` 并关闭 provenance / SBOM 附件，避免仓库里出现 `unknown/unknown` 架构条目导致拉取时选错架构。
- 镜像以非 root（uid 10001）运行，配置内置在 `/app/configs`，状态目录为 `/app/state`（建议挂载数据卷）。

## 本地运行

```bash
# 编译（需要 Go 1.23+；纯 Go 实现，无 CGO）
go build -o bin/netsa ./cmd/netsa

# 生成 6 小时演示日志并启动，浏览器打开 http://localhost:8080（账号 admin / Netsa@demo2026）
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
   多源溯源定位（离线同步 + 在线/rDNS 异步 + 区划地名库）    Webhook 告警 / SSE 推送 / PostgreSQL 归档（可选）
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
internal/auth/        登录账号、PBKDF2 密码哈希、签名会话、登录失败锁定与审计
internal/archive/     可选的 PostgreSQL 告警归档（异步 COPY 批量写入、按月分区、历史查询）
internal/alert/       钉钉 / 企业微信 / 飞书 / Webhook 告警推送（多选等级、合并、限速、加签）
internal/safe/        异常保护（单条畸形数据不影响服务）
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

### 未做 DNAT 映射的端口探测

互联网背景扫描会持续探测 1433、6379、3389 等端口，防火墙通常只是按默认策略**记录并放行**。如果这些端口并没有做 DNAT 映射，探测不可能到达任何服务，但每一条日志都会被记成一次“高危服务端口探测”，把真正的风险信号淹没。

开启 `exposure` 后，目标为**公网地址**、端口未列入清单的端口探测与端口级暴力破解会降级为**仅打标签**：不生成告警、不计入威胁评分与攻击统计，但仍保留在画像标签和攻击面的“被探测端口”统计中，可事后回溯。

```yaml
exposure:
  enabled: true
  allowed_ports: [80, 443]        # 兜底：拿不到精确 NAT 表时（云负载均衡 / 上级防火墙转发）
  services:                       # 精确映射：公网 IP:端口 → 内网 IP:端口
    - { public_ip: 43.242.97.40, public_port: 1433, private_ip: 10.0.0.21, private_port: 1433, proto: tcp, name: 业务库 }
    - { public_ip: 43.242.97.40, public_port: 443,  private_ip: 10.0.0.10, private_port: 443,  proto: tcp, name: 官网 }
```

- 目标为**内网地址**时不做判断（说明已过 DNAT 或属东西向流量），按真实暴露处理。
- **攻击面评估同源**：未映射端口上被放行的探测只计入「被探测端口」，不会登记为「对公网开放的服务」，也不参与暴露面扣分；填写了 `private_ip` 的映射会用于把公网目标还原为内网资产，从而正常关联资产台账与漏洞。
- IPS/IDS/WAF 已明确判定的威胁、端口扫描、主机探测与洪水告警**不受影响**——它们反映的是攻击者行为，与端口是否开放无关。
- 大屏 **数据源 → 溯源与检测能力** 显示开关状态、映射条数与已过滤次数，`GET /api/exposure` 返回清单；启动日志同样会打印。

**候选映射（免手工维护）**：清单靠手填，新上线服务或更换公网 IP 后容易漏登，过滤于是「该拦的没拦、该放的被降级」。程序会从防火墙日志反推候选——只统计**外部来源访问公网地址端口且被放行**的连接（内网来源是东西向流量、出站连接的目标是外部服务，都不算），按两条信号判定：累计放行次数与不同来源数（真实服务持续收到连接且来源分散，关闭端口只有零星探测）。

```yaml
exposure:
  suggest:
    enabled: true      # 默认开启，只生成建议
    min_allows: 20
    min_sources: 3
```

- 候选只作提示，**不会自动生效**：误判为已发布会让真实攻击不再告警，必须人工确认。
- `GET /api/exposure` 的 `candidates` 字段给出放行次数、来源数，以及可直接粘贴到 `exposure.services` 的 YAML（内网地址留作注释，按实际 DNAT 填写）。
- 新发现候选时启动日志之外的维护周期会打印一条摘要（仅数量增加时打印，不重复刷屏）；大屏能力面板显示「发现 N 个疑似对外映射」。

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

#### 使用公网地址段的内网（`geo.intranet`）

RFC1918 私有段只覆盖 `10/8`、`172.16/12`、`192.168/16`，而很多单位实际把 **`172.168.100.0/24`、`172.168.200.0/24`** 这类已被分配为公网的地址段用在内网。若不声明，定位库会按其公网注册信息返回“美国”等境外归属地，攻击源被画到境外地图上，封禁列表的国内/境外判断也会出错。把这类网段列入 `geo.intranet` 后，一律按内网呈现且不查询任何定位库：

```yaml
geo:
  intranet:
    - 172.168.100.0/24
    - 172.168.200.0/24
  detect_local_networks: true   # 启动时自动把本机网卡所在网段并入内网（默认开启）
```

- 内置始终生效：RFC1918、CGNAT（`100.64/10`）、回环、链路本地、IPv6 ULA，以及 `0.0.0.0/8`、`240.0.0.0/4` 等保留段（标注为“保留地址”）。
- 该判定在**全系统统一**：定位着色、出站/横向流量判断、CDN 绕过判断、RDAP 查询过滤都使用同一份网段集合。
- 部署在公网地址段主机上时建议 `detect_local_networks: false`，避免把该段的真实攻击者误判为内网；**数据源** 页会列出当前生效的额外内网网段。

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

## 威胁等级判定

一条命中从产生到入库会经过多个环节（特征规则、设备告警、资产漏洞关联、响应复核），每个环节都可能影响等级。为避免「各环节各自加减」导致同类事件等级不一致，最终等级统一由 `internal/risk` 裁决，规则里声明的 `severity` 只作为**建议值**。

**判定优先级（从高到低，后一步在前一步结果上收敛）**

1. **分类底线**：低于该分类最低等级的声明一律抬升。防止规则写错（把 SQL 注入写成 low）或自定义规则随手填 info 导致高危信号永久漏报。
2. **成功升级**：响应可判定成功的利用类攻击直接升为「严重」；敏感文件可访问只到「高危」（证明暴露，不证明失陷）。
3. **严重级准入**：只有「成功利用」「未拦截的利用类」「失陷迹象（带外、恶意外连、远控、挖矿、主机事件）」可以达到严重。
4. **结果封顶**：已拦截 / 请求失败 / 后端异常的命中**最高只到高危**——没有成功就不构成严重。
5. **标签降级**：`tag_only` 规则只打标签，不超过低危，不参与告警分级。
6. **复核回落**：命中被正常响应基线复核为「未成功」时，等级回落到高危封顶。

**分类底线（节选）**

| 底线 | 分类 |
|---|---|
| 严重 | 带外探测（DNSLog 回连，漏洞已被触发的直接证据） |
| 高危 | SQL 注入、命令/代码执行、表达式注入、反序列化、WebShell、已知漏洞利用、目录穿越/文件包含、XXE、SSRF、恶意外连、恶意软件/远控、挖矿 |
| 中危 | XSS、敏感文件探测、管理后台探测、暴力破解、账号与权限、主机安全事件、CC/洪水攻击、可疑外连、DNS 隧道 |
| 低危 | 扫描器、网络空间测绘、目录扫描、端口扫描、主机探测、高危服务探测、IoT 僵尸网络、自动化工具、协议异常、DGA/动态域名、威胁情报、IP 伪造 |

扫描器类保持低危，避免互联网背景扫描抬高整体风险；`高风险端口探测` 同样只到低危（是否告警由 `exposure` 决定）。

**各等级的处理流程与边界**

| 等级 | 告警与推送 | 事件处置时限 | 失陷研判 | 典型边界 |
|---|---|---|---|---|
| 严重 | 默认推送；进入 P0 处置建议 | 1 小时（核心资产不变） | 计入高置信失陷 | 仅在成功利用或失陷迹象时出现；**已拦截的利用尝试不会达到严重** |
| 高危 | 默认推送 | 4 小时（核心资产按严重） | 未拦截的利用类按疑似失陷统计 | 已拦截的已知漏洞利用、扫描器批量命中、暴力破解成功前的攻击 |
| 中危 | 不推送（按机器人配置） | 24 小时 | 仅作为线索 | 放行的端口探测、单次可疑外连（心跳）、敏感文件探测未取到内容 |
| 低危 | 只记录 | 72 小时 | 否 | 已拦截的扫描、高危端口探测、标签类观察 |
| 信息 | 只记录 / 只打标签 | 7 天 | 否 | `tag_only` 规则、空 UA 等弱特征 |

**误报与异常防护**

- **规则加载即校验**：`severity` 拼写错误直接启动失败（不再静默降级为 info）；低于分类底线的声明会被纠正并打印日志。
- **响应复核**：攻击请求的响应大小与该接口正常基线一致（变异系数 ≤10%、偏差 ≤5%）时改判为「未成功」，等级随之回落。
- **资产关联不越权**：目标确有针对性的未修复漏洞时，未拦截的命中按成功处理；已拦截的仍只到高危。
- **严重级佐证**：单条「严重」告警若既无成功命中、也无失陷迹象类分类，攻击源等级只按高危封顶，避免一条误判把 IP 抬到严重。
- **设备告警**：按设备自身等级映射；无法识别时按高危（设备已判定为威胁），已拦截的封顶高危。
- **可观测**：`netsa_severity_adjusted_total{from,to}` 统计等级被自动调整的次数——持续出现 `critical→high` 说明规则把未成功的利用写成了严重；`GET /api/rules/stats` 给出每条规则的命中次数，长期 0 命中的规则需核对是否误配（分类拼写错误时启动日志也会列出）。
- **暴露面与探测分级解耦**：后台/端口「探测」按低危记录，是否真正暴露由响应状态判定——`2xx/3xx` 的 `/admin`、`/manage`、`/dashboard` 等通用后台入口会作为「管理后台/运维入口对外暴露」进入安全评估（中危），不会因为降低探测等级而漏掉真实暴露面。

## 威胁评分模型

- 按攻击分类累计：分类权重（低 5 / 中 12 / 高 25 / 严重 45）×（1 + log2(次数)/3，最多 2 倍），侦察类 ×0.6
- 疑似攻击成功 +20；跨越多个攻击阶段每多一个阶段 +10；命中威胁情报 +30；上限 100
- 等级：≥80 严重、≥50 高危、≥25 中危、>0 低危；**攻击源等级不低于其触发过的最高告警等级**（评分同步抬升到该等级下限），告警事件中出现高危的 IP 必然计入“高危以上攻击源”。严重级还需佐证：没有成功命中、也没有失陷迹象分类时，单条严重告警只按高危封顶
- 威胁指数：最近 60 分钟按严重程度加权的攻击量，经指数饱和映射到 0-100
- 两类等级的区别：**告警 / 攻击事件**按单次攻击的规则等级统计（总览“攻击事件”下方的严重 / 高危 / 中危）；**攻击源**按 IP 的综合威胁等级统计（总览“高危以上攻击源”）。同时触发高危与严重告警的 IP 计为严重攻击源。

## 登录与账号

- 登录认证默认开启。未在配置文件中设置 `server.username/password` 时，首次启动自动创建管理员 `admin`，**初始密码输出在启动日志中**，首次登录后必须修改；也可用环境变量 `NETSA_ADMIN_PASSWORD` 指定初始密码。
- 角色：**管理员**可管理账号、告警推送、资产、syslog 发送端等配置；**运营分析员**可处置事件、标记误报、修改漏洞状态、检索与导出原始日志，不能修改系统配置；**只读**账号只能查看态势、告警与事件，适合值班大屏。账号在大屏“系统管理”页面添加，新账号与重置密码后的账号首次登录须修改密码。
- 密码使用 PBKDF2-HMAC-SHA256（60 万次迭代、随机盐）存储在 `users.json`（权限 0600，默认与快照同目录）；密码至少 8 位且包含字母、数字、符号中的两类。
- 会话：HttpOnly + SameSite Cookie，签名令牌重启后仍有效，有访问时自动续期（`server.session_ttl`，默认 12 小时），自登录起最长 30 天；修改密码、角色变化、删除账号或退出登录后立即失效。
- **双因素认证**：用户在右上角菜单“双因素认证”中扫码绑定身份验证器（Microsoft / Google Authenticator、阿里云、腾讯身份验证器等，TOTP 6 位 30 秒），获得 8 个一次性恢复码；之后登录需在密码之后输入动态口令（同一口令不能重放，验证失败同样计入登录锁定），开启后不能再用 HTTP Basic 认证绕过。`server.require_2fa: true` 时所有界面账号须先绑定才能使用；管理员可为丢失手机的用户重置。
- 防暴力破解：同一账号同一来源连续失败 5 次锁定 15 分钟（不影响管理员从其他地址登录）；同一来源尝试多个账号失败 20 次锁定该来源；同一账号来自所有来源失败 50 次锁定该账号。账号不存在与密码错误返回相同提示与耗时。所有登录尝试记录在“系统管理 → 登录记录”。
- **操作审计**：登录（含失败与锁定）、退出、修改密码、双因素认证、账号与令牌管理、告警推送与发送端配置、事件处置、误报抑制、资产导入、原始日志检索与导出、报告生成与发送等，均记录操作人、来源 IP、时间与结果。记录按月写入 `audit/` 目录的 **SHA-256 哈希链**文件（`audit.retention_days`，默认 180 天），在“系统管理 → 操作审计”中检索、校验完整性、导出 CSV / JSONL；任何修改、删除、插入都会使校验失败，按留存策略清理旧记录时保留锚点，不会误报为篡改。
- 忘记密码：在服务器上执行 `netsa passwd -c configs/config.yaml -u admin`（容器：`docker compose exec netsa /app/netsa passwd -c /app/configs/docker.yaml -u admin -p '新密码'`），运行中的服务自动生效。
- 脚本与第三方系统建议使用 **API 令牌**（见“监控指标与 API 令牌”）；也可使用 HTTP Basic 认证（开启双因素的账号除外）：`curl -u admin:密码 http://服务器:8080/api/export/blocklist?format=txt`。
- HTTPS：设置 `server.tls_cert` / `server.tls_key` 直接提供 HTTPS（并启用 HSTS），或部署在 HTTPS 反向代理之后。
- 仅在可信内网或由前置统一认证网关负责认证时，才设置 `server.auth: false` 关闭登录。

## 告警推送（钉钉 / 企业微信 / 飞书）

在大屏 **告警推送** 页面点击“添加机器人”，选择类型、粘贴群机器人的 Webhook 地址、勾选推送等级（**中危 / 高危 / 严重，可多选**），点“发送测试消息”确认后保存即可。

| 平台 | 获取 Webhook | 安全设置 |
| --- | --- | --- |
| 钉钉 | 群设置 → 机器人 → 添加机器人 → 自定义 | 选“加签”时填写密钥（SEC 开头）；选“自定义关键词”时填写 `告警` |
| 企业微信 | 群右上角 … → 添加群机器人 | 无需额外设置 |
| 飞书 | 群设置 → 群机器人 → 添加机器人 → 自定义机器人 | 开启“签名校验”时填写密钥；开启“自定义关键词”时填写 `告警` |

- **推送内容**：告警事件的规则名称、等级、研判结果（疑似成功会特别标注）、来源 IP 与归属地、攻击目标、攻击证据与威胁评分；以及攻击源因多次攻击累积导致的威胁等级升级。配置 `alert.base_url` 后附带“查看溯源详情”链接，点击直接打开该 IP 的溯源详情。
- **降噪**：同一 IP、同一规则、同一研判结果在 `alert.dedup_window`（默认 10 分钟）内只推送一次；2 秒内的多条告警合并为一条消息；钉钉 / 企业微信每个机器人每分钟最多 18 条、飞书 60 条，超出部分汇总为“另有 N 条”推送，不会静默丢失；网络错误或平台限流时自动重试。
- **安全**：日志中的攻击载荷与链接已转义，不会在群聊中渲染为可点击的链接或图片；界面只允许填写官方机器人地址（防止借服务端访问任意地址），Webhook 令牌与密钥不会回显到页面；机器人配置保存在 `alert-robots.json`（权限 0600）。
- 私有化部署的机器人或通用 JSON Webhook（对接 SOAR、工单系统）请在配置文件 `alert.webhooks` 中配置，示例见 [configs/config.yaml](configs/config.yaml)。

## 安全评估与失陷研判

大屏 **安全评估** 页面综合全部数据给出当前防护状况的评估与处置建议：

| 维度 | 权重 | 评估内容 |
| --- | --- | --- |
| 失陷风险 | 25 | 疑似失陷资产（攻击成功研判、外连恶意地址、设备报出的内网恶意软件），按置信度扣分 |
| 暴露面 | 20 | 敏感资源可公开访问（源码仓库、密钥、备份、配置、调试接口、管理后台）、高危服务对公网开放 |
| Web 防护 | 15 | 漏洞利用类请求的拦截率、攻击成功的 Web 资产 |
| 凭证安全 | 10 | 暴力破解来源与疑似破解成功 |
| 边界防护 | 10 | 对公网开放的高危服务、端口扫描来源（未接入防火墙日志时不参与评分） |
| 威胁活跃度 | 10 | 近 60 分钟威胁指数、仍在活动的高危攻击源、情报命中 |
| 日志与检测覆盖 | 10 | Web / 防火墙日志接入、解析成功率、威胁情报、精确定位、告警推送、长期归档、平台访问加固 |

- **总评**：按权重加权平均，存在高置信失陷时总评不高于 35 分（E 危险），存在疑似失陷或严重暴露面时不高于 59 分。
- **处置建议**：P0 紧急（应急处置失陷资产、删除泄露的敏感资源、关闭对公网开放的严重风险服务）、P1 高（核查疑似成功、封禁活跃的高危攻击源、加固登录口、提升 WAF 拦截能力）、P2 中、P3 低（补齐检测覆盖、减少指纹暴露），每条附操作步骤，点击即可查看相关告警、攻击源或资产。
- **失陷研判**：同一资产的多种成功迹象合并展示，附攻击来源 / 外连地址与处置建议。
- **外连恶意地址检测**：配置 `intel.blocklists` 后，防火墙日志中内网主机（或本机出站流量）连接列表中地址的行为会产生“外连威胁情报地址（疑似失陷）”告警，并推送到告警机器人、写入归档。演示环境自带一份演示情报（[configs/demo-intel.txt](configs/demo-intel.txt)），模拟日志中的 10.0.0.31 会周期性外连。
- **ATT&CK 矩阵**：各攻击类型映射到 MITRE ATT&CK 技术（如 SQL 注入 → T1190、WebShell → T1505.003、暴力破解 → T1110、外连 → T1071），矩阵按命中量着色，点击技术查看对应告警；IP 溯源详情中列出该攻击源使用过的技术。
- **研判准确性**：Log4j / SSRF / XXE / 反序列化等盲打类攻击无法从响应码判断是否成功，返回 2xx 时研判为“未拦截”而非“疑似成功”；对 SQL 注入、目录穿越、已知漏洞利用等，若攻击请求的响应与该接口正常访问时的响应大小一致（接口响应大小稳定且偏差在 5% 以内），说明返回的仍是正常页面，改判为“未拦截”。内网主机访问公网的出站流量不做扫描 / 洪泛 / 暴力破解判定，也不计入服务暴露面，避免把正常上网当成攻击。
- **评分趋势**：每小时记录一次安全评分（随快照保存，保留 30 天），展示整改效果。
- **安全日报**：每天 `alert.report_time`（默认 09:00，`off` 关闭）向勾选了“接收每日安全日报”的机器人推送安全评分与结论、近 24 小时攻击量及环比、活动 / 新增 / 高危攻击源、疑似失陷资产、主要攻击类型与攻击源、P0 / P1 优先处置事项；在“告警推送”页可对任一机器人点击“发送日报”立即发送。
- **新增行为检测**：分布式暴力破解（`dist_window` 内同一登录接口失败登录 ≥ `dist_brute_logins` 次且来自 ≥ `dist_brute_ips` 个来源，401 / 403 / 429 计为失败）、接口遍历 / 批量爬取（`enum_window` 内同一来源对同一接口请求 ≥ `enum_ids` 个不同 ID 并成功返回，涉及用户 / 订单 / 账户等接口为高危，搜索引擎爬虫除外，归入新增的“数据窃取”攻击阶段与 ATT&CK 收集战术）、周期性外连（`beacon_conns` 次连接）。
- 总览顶部的 **态势研判** 条给出一句话结论与近 1 小时攻击量环比、新增攻击源、活跃高危攻击源、疑似成功攻击、疑似失陷资产与安全评分，均可点击下钻。

## 安全运营：事件处置与误报抑制

告警是检测的产物，**事件**是处置的单位。同一来源在一段时间内的告警自动合并为一个安全事件（超过 24 小时没有新告警，或上一个事件已处置后再出现，归入新事件），在大屏 **事件处置** 页统一处置：

- **处置状态**：待处理 → 处置中 → 已处置 / 误报 / 忽略；可指派负责人（管理员或运营分析员）、填写处置说明，**关闭事件必须填写说明**，处置过程（状态变化、指派、备注）全程记录。支持批量处置、只看我负责的、只看超时。
- **处置时限（SLA）**：严重 1 小时、高危 4 小时、中危 24 小时、低危 72 小时；**涉及核心资产时按高一级计算**；事件等级升高时时限相应缩短。超时未关闭的事件推送提醒到告警机器人（每个事件提醒一次，较多时合并为一条），导航栏显示待处置 / 超时数。
- **自动重开**：标记为误报 / 忽略的事件之后出现更高等级的告警时自动重新打开，并在处置记录中注明原因。
- **误报抑制**：在告警列表或事件详情中对误报的告警点击“标记误报”，按 **检测规则、攻击类型、来源 IP / 网段、目标路径** 的组合生成抑制规则（可设有效期，可选同时把所属事件标记为误报）。命中抑制规则的攻击不产生告警、不计入攻击统计与威胁评分，只累计抑制次数用于审计；只按攻击类型抑制等范围过大的规则会被拒绝。
- 告警、事件接口支持 API 令牌调用，便于对接 SOAR、工单系统自动处置（`POST /api/incidents/bulk`）。

## Syslog 发送端管理与数据源健康

在 **数据源 → Syslog 发送端** 中查看每个发送 syslog 的设备（源 IP）：

- **发送端画像**：设备自报的主机名（经中继转发时区分设备）、TLS 客户端证书、协议（UDP / TCP / TLS）、识别出的日志格式、日志量与近 5 分钟速率、解析失败数与失败样例、时区校正、最近接收时间；每个发送端独立识别格式与时区，互不干扰。
- **登记与分组**：按 IP 或网段登记设备名称、分组（防火墙 / WAF / 服务器 / VPN …）与断流阈值；告警的“数据来源”显示为设备名称。分组汇总在线、断流、被拒绝的设备数与日志速率。
- **白名单与阻止**：开启 **发送端白名单** 后只接收已登记（允许）的发送端，其余来源的 UDP 数据报直接丢弃、TCP / TLS 连接在读取前立即断开，被拒绝的来源按 IP 计数并推送“未授权的 syslog 发送端”通知（同一来源 6 小时一次，伪造源地址的洪泛不会刷屏）。开启时可一键把近 24 小时活跃的发送端登记为允许，避免误断；白名单为空时不允许开启。“阻止”规则在任何模式下都拒绝该来源。也可在配置文件 `syslog.senders` 中登记（只读）、`syslog.allowlist: true` 强制开启。
- **防伪造与防洪泛**：UDP 源地址可被伪造，对完整性要求高的设备建议使用 **TLS（RFC 5425）**，配置 `syslog.tls_client_ca` 后要求客户端证书（双向认证）；`syslog.rate_limit` 限制单个发送端的日志速率，异常设备不会挤占处理能力；发送端画像数有上限，伪造的大量来源不会挤掉已登记的设备。
- **断流告警**：跟踪中的日志文件、syslog 监听与登记的发送端超过阈值（`alert.source_silence`，默认 30 分钟；可按数据源 / 发送端单独设置）没有新日志时推送“数据源断流”告警，恢复后再推送一次；一分钟内解析失败率超过一半（日志格式被修改）、告警归档连续写入失败或队列溢出时同样推送。断流状态显示在数据源页面。

## 主机认证日志与 DNS 日志

| 类型 | 支持的格式 | 检测 |
| --- | --- | --- |
| 主机 / VPN 认证（`type: auth`） | Linux `auth.log` / `secure`（sshd、PAM、useradd、usermod）、Windows 安全事件（NXLog / Winlogbeat JSON、Snare 及中英文事件文本，4624 / 4625 / 4740 / 4720 / 4728 / 4732 / 4756 / 1102 / 4697 / 7045 / 4698 / 4771 / 4776）、FortiGate SSL VPN 与管理登录、Cisco ASA AAA / AnyConnect、OpenVPN、SQL Server 登录 | 暴力破解（`auth_failures`）、密码喷洒 / 账号枚举（`auth_users` 个不同账号）、**多次失败后登录成功（账号疑似失陷）**、公网 IP 直接登录特权账号、安全日志被清除、新建账号、加入管理员组、新安装服务 / 计划任务 |
| DNS（`type: dns`） | BIND querylog、dnsmasq、CoreDNS、Windows DNS 调试日志、Zeek `dns.log`、Suricata eve.json（`event_type: dns`）及 JSON DNS 日志 | **DNSLog 带外回连**（内网主机解析 dnslog.cn、ceye.io、oast.* 等，说明盲打的 RCE / SSRF / Log4j 已被触发）、矿池域名（挖矿木马）、DNS 隧道（超长高熵子域名、同一主域名下大量不同子域名）、DGA 随机域名与 NXDOMAIN 风暴、动态域名 / 内网穿透服务 |

DNS 与主机事件的主体是**内网主机本身**（判断其是否失陷），不受 `detect.whitelist` 影响；命中后计入“失陷研判”与 ATT&CK 矩阵（T1071.004、T1568.002、T1496、T1070.001、T1136、T1098 等）。认证日志也可经 syslog 接收，没有远程来源的主机事件（如日志被清除）以发送日志的设备为主体。

## 原始日志留存与检索

开启 `rawlog.enabled` 后，解析后的日志按事件时间分小时压缩存放（`<dir>/YYYYMMDD/HH.log.gz`），写入在独立协程中进行（约 0.2µs/条，零分配），不影响实时检测：

- **检索**：在 **日志检索** 页按时间范围、IP（来源或目的）、关键字、数据源、只看攻击检索；每个分段附带 IP 布隆过滤器，按 IP 检索时跳过不包含该 IP 的分段。告警列表、事件详情、IP 溯源详情中可一键查看**告警前后 5 分钟的原始日志**。检索与导出需要运营分析员以上权限（原始日志可能包含 Cookie、令牌等敏感信息），并记入审计。
- **取证导出**：按条件导出原始日志（按时间先后，最多 5000 条）。
- **防篡改**：分段关闭时计算 SHA-256 并写入哈希链清单（`manifest.jsonl`），在页面中可校验分段是否被修改、留存期内的分段是否被删除，以及清单本身是否被改动。
- **留存**：默认 180 天（满足《网络安全法》日志留存不少于六个月的要求），可设置总容量上限；只想留存攻击事件时开启 `attacks_only`。
- **异常时间戳**：比当前时间晚 1 小时以上的日志（发送端时钟错误或伪造）按接收时间归档，原文不变；早于留存期限的日志不写入（在留存状态中计数）；时间戳在大量不同小时间来回跳动时，每分钟最多新开 30 个历史分段，其余按接收时间归档，避免分段反复开关。

## 资产与漏洞

在 **资产漏洞** 页导入资产台账与漏洞扫描结果（CSV，UTF-8，按列名自动识别中英文表头，可下载模板），也可逐个登记：

- **资产**：IP / 网段、域名（支持 `*.example.com`）、名称、负责人、部门、**业务重要性（核心 / 重要 / 一般）**、等保级别、环境、标签。导入方式可选合并（按 IP 更新）或替换。
- **漏洞**：兼容 Nessus、OpenVAS、绿盟等扫描器导出的 CSV（IP / Host、Port、CVE、Name / 漏洞名称、Risk / 风险等级 / CVSS…），信息类结果自动跳过；“替换”方式以本次扫描为准，上次存在而本次未出现的漏洞标记为已修复。漏洞状态可由运营分析员修改（未修复 / 已修复 / 风险接受）。
- **关联**：攻击事件按目的 IP 或站点域名标注目标资产（告警、推送消息、事件中显示资产名称、重要性与负责人）；**攻击利用的 CVE 在目标资产上存在且未修复时升级为严重，未被拦截时判定为疑似成功**；攻击类型或组件（SQL 注入、反序列化、Struts、WebLogic、Log4j…）与目标上的高危漏洞一致时等级提升一级；涉及核心资产的事件处置时限按高一级计算。

## 周报 / 月报与等保合规

- **周报 / 月报**：在 **报表合规** 页查看近 7 天 / 上周 / 近 30 天 / 上月的报告：自动生成的结论、攻击趋势与环比、攻击类型 / 攻击源 / 国家 TOP、事件处置统计（新建、关闭、误报、平均处置时长、按时处置率）、疑似失陷资产、资产与漏洞概况、优先处置建议、防护能力评估、数据源运行情况。点击“打开打印版”在浏览器中打印或另存为 PDF。系统按天汇总统计（随快照保存 400 天），报告不受 `storage.retention` 限制。
- **定时邮件**：配置 `report.smtp` 与 `report.recipients` 后，每周一（`report.weekly`）发送上周周报、每月 1 日（`report.monthly`）发送上月月报，报告同时作为 HTML 附件；支持 SSL / STARTTLS，口令可用环境变量 `NETSA_SMTP_PASSWORD` 提供。
- **等保 2.0 合规检查**（管理员）：依据 GB/T 22239-2019 第三级，对安全区域边界（入侵防范、恶意代码防范、安全审计）、安全计算环境（身份鉴别、访问控制、安全审计、入侵防范）、安全管理中心（审计管理、集中管控）、安全运维管理（资产管理、漏洞和风险管理、安全事件处置）及《网络安全法》日志留存要求，逐项给出 **符合 / 部分符合 / 不符合** 的判定、平台证据与整改建议，可打印为 PDF。该报告基于平台可观测的技术证据，供日常自查与整改跟踪，不能替代测评机构的正式测评。

## 监控指标与 API 令牌

- **API 令牌**：管理员在“系统管理 → API 令牌”中为账号创建令牌（`nsa_` 开头，只显示一次，服务端只保存哈希），权限可选只读 / 运营分析员 / 管理员 / **仅监控指标**，不超过所属账号的权限，可设有效期、随时吊销，记录最近使用时间与来源。调用：`curl -H "Authorization: Bearer nsa_…" http://服务器:8080/api/incidents?status=active`。
- **Prometheus 指标**：`GET /metrics`（会话、Basic 认证或令牌，推荐“仅监控指标”令牌），包含各数据源的日志量 / 解析失败 / 断流状态 / 最新日志时间、syslog 发送端（在线、断流、被拒绝、限速丢弃）、攻击与告警（按等级）、攻击源数、安全评分、事件（按状态、超时数）、误报抑制、告警推送（成功 / 失败 / 排队）、告警归档与原始日志留存、Go 运行时等。
- **背压与丢弃可见**：`netsa_pipeline_queue_depth` / `_capacity`（入库跟不上时队列长度会贴近容量）、`netsa_rawlog_dropped_total`、`netsa_archive_dropped_total`、`netsa_exposure_muted_total`、`netsa_alert_robot_queued`。这几项是「静默丢数据」的直接信号，建议配置告警。
- **缓存与去重可见**：`netsa_response_cache_entries` / `_hits_total` / `_misses_total`（聚合接口缓存改为 LRU，条目数长期贴近上限说明查询参数组合过多）、`netsa_notify_dedup_entries`（告警去重表规模，随去重窗口自然回收）。
- **性能剖析**：`server.pprof: true` 后开放 `/debug/pprof/`（**仅管理员**，默认关闭）。用于排查 CPU / 内存 / 协程问题，例如：
  ```bash
  go tool pprof -top "http://管理员:密码@服务器:8080/debug/pprof/profile?seconds=30"
  go tool pprof -top "http://管理员:密码@服务器:8080/debug/pprof/heap"
  ```
  剖析会带来额外开销，排障结束后请关闭。

## 告警归档（可选，PostgreSQL）

默认所有数据保存在内存并定期快照，内存中只保留最近的告警（`storage.max_alerts`）。需要**长期留存、按条件检索历史告警或满足日志留存合规要求**时，可接入 PostgreSQL（11 及以上，推荐 15+）：

```yaml
archive:
  dsn: postgres://netsa:密码@127.0.0.1:5432/netsa?sslmode=disable
  retention_years: 0      # 保留周期（年）：0 永久保留（默认），N 表示至少保留最近 N 年
```

也可使用环境变量 `NETSA_ARCHIVE_DSN`（优先于配置文件，避免口令写入配置）。Docker Compose 部署可直接启用自带的 PostgreSQL：

```bash
# .env（两处密码相同）
POSTGRES_PASSWORD=强密码
NETSA_ARCHIVE_DSN=postgres://netsa:强密码@postgres:5432/netsa?sslmode=disable
```

```bash
docker compose --profile archive up -d
```

- **准备数据库**：只需一个普通账号（无需超级用户）和它拥有的数据库，例如 `CREATE ROLE netsa LOGIN PASSWORD '…'; CREATE DATABASE netsa OWNER netsa;`。表结构与分区由 netsa 自动创建与维护。
- **写入**：告警进入内存队列，后台按批（默认 1000 条或 2 秒）用 COPY 写入，不影响实时分析（开发机本地 PostgreSQL 实测 3 个实例并发写入约 6 万条/秒）。
- **幂等去重**：每条告警按内容（时间、来源、规则、目标、证据等）与出现序号计算指纹，同一份日志被重复分析（`from_beginning: true` 时重启、`netsa analyze` 重复补录同一批日志）时，内容相同的告警只归档一次，跳过的数量显示在“数据源 → 告警归档”中；同一秒内内容完全相同的多次真实攻击仍全部保留。多个数据源并发读取时，个别行为检测类告警（如扫描、暴力破解）的触发时刻会随事件交错顺序略有差异，这类告警可能再次写入。数据库暂不可用时 netsa 照常启动与分析，告警在队列中缓冲（默认 10 万条）并自动重连写入，队列满时丢弃并计数；退出时写完队列中剩余的告警。攻击载荷中的 NUL 字节与非法 UTF-8 会被清理，不会导致整批写入失败。
- **分区**：表 `netsa_alerts` 按 `timezone` 的自然月分区（`netsa_alerts_p202610` …），自动提前创建下月分区；默认**永久保留**；设置 `retention_years: N` 后至少保留最近 N 年（N×12 个完整月加当月，满足日志留存不少于六个月的合规要求），更早的月分区每小时检查并整表删除，清理耗时与数据量无关。永久保留时请关注“数据源 → 告警归档”中各分区的占用空间，按磁盘容量规划保留周期。多台 netsa 可共用一个数据库（写入实例名区分来源，建表与建分区由咨询锁串行化）。
- **查询**：大屏“告警事件 → 历史告警（归档库）”按时间范围、来源 IP / 网段（IPv4 / IPv6 CIDR）、规则 ID 或名称、等级、攻击类型、研判结果、日志来源、关键字（目标 URL / 载荷 / 规则名称）检索，展示统计（各等级数量、TOP 10 来源 IP 与规则、每日趋势），可导出 CSV（最多 20 万条，记入审计日志）；IP 溯源详情中可一键查看该 IP 的全部历史告警。所有查询参数化执行，限制并发与超时，防止拖垮数据库。
- **离线分析**：`netsa analyze` 同样会把分析出的告警写入归档，可用于把历史日志补录到归档库。
- **状态**：“数据源”页面显示连接状态、已写入 / 队列 / 丢弃数量、最近错误与各分区的行数和占用空间（`GET /api/archive/status`）。

## 时间与时区

- 不带时区信息的日志时间（传统 syslog、FortiGate、Cisco ASA、华为、Palo Alto、Snort、Windows 防火墙等）按 `timezone` 解析；IIS W3C 日志按标准以 UTC 解析；nginx、Suricata、RFC 5424 等带时区的时间按其自身时区。
- **自动校正**（`time_correction: auto`，默认开启）：对实时日志（已追上文件末尾后新写入的行、syslog 各发送端分别统计）比较日志时间与接收时间，若持续相差某个整时区（例如服务器或设备按 UTC 记录，而 `timezone` 为 Asia/Shanghai，时间慢 8 小时），自动校正并在“数据源”页面显示“时区已自动校正 +8 小时”。历史日志回放、设备断网后集中补发的日志不会触发校正；日志产生方改为正确时区后校正自动撤销。建议仍将日志产生方的时区设置一致。
- 页面、告警推送消息与导出文件中的时间统一按 `timezone`（未配置时按服务进程的 `TZ`）展示，与查看页面的电脑所在时区无关。

## 配置要点

完整说明见 [configs/config.yaml](configs/config.yaml)。配置采用严格解析，拼写错误的配置项会在启动时报错。

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
| `detect.thresholds` | 行为检测阈值：CC、目录扫描、暴力破解、端口扫描、主机探测、洪泛，以及分布式暴力破解（`dist_*`）、接口遍历（`enum_*`）、周期性外连（`beacon_conns`）、主机认证（`auth_failures`、`auth_users`）、DNS（`dns_nxdomain`、`dns_subdomains`） |
| `alert.webhooks` | 配置文件方式的告警机器人：`type`、`url`、`secret`（加签）、`levels`（多选 medium / high / critical） |
| `server.web_dir` / `serve -web` | 从磁盘目录加载前端页面，用于定制界面 |
| `detect.whitelist` | 自有监控、扫描器等白名单，只统计流量不检测 |
| `detect.rules_file` | 自定义规则；与内置规则 ID 相同时覆盖内置规则，`disable` 可禁用内置规则，`methods` 可限定 HTTP 方法 |
| `real_ip.trusted_proxies` / `trusted_presets` | 可信代理网段；`trusted_presets: [cloudflare]` 使用内置的 Cloudflare 回源网段 |
| `real_ip.headers` | 按优先级尝试的客户端地址头：`cf_connecting_ip`、`true_client_ip`、`ali_cdn_real_ip`、`x_client_ip`、`x_real_ip`、`x_forwarded_for`、`forwarded` |
| `real_ip.cdn_only` | 源站只应经 CDN 访问时开启，公网直连标记为“绕过 CDN 直连源站” |
| `geo.online.enabled` | 在线溯源开关（会把攻击 IP 发送到 ip-api.com） |
| `geo.enrich_level` | 达到该等级的攻击 IP 才做在线查询与反向 DNS |
| `geo.custom` | 自定义网段位置（内网办公区、分支机构、VPN 地址池等） |
| `geo.intranet` | 内网网段：RFC1918 之外、但实际用在内网的公网地址段（如 `172.168.100.0/24`）；命中后不查询定位库、不参与境外着色 |
| `geo.detect_local_networks` | 启动时自动把本机网卡网段并入内网（默认 `true`）；主机本身位于公网段时建议关闭 |
| `exposure.enabled` | 开启“未做 DNAT 映射的端口探测”过滤（默认关闭）；开启后未发布端口上的探测与端口级暴力破解只打标签 |
| `exposure.services` / `allowed_ports` | DNAT 精确映射（公网 IP:端口 → 内网 IP:端口）/ 兜底端口白名单 |
| `exposure.suggest` | 候选映射统计（`min_allows` / `min_sources`）：从放行连接反推可能漏登记的映射，只提示不生效 |
| `geo.reload_interval` | 定位库与自定义网段的热更新检查周期，`0` 关闭 |
| `storage.snapshot` | 状态快照路径（`.gz` 结尾自动压缩） |
| `archive.dsn` / `NETSA_ARCHIVE_DSN` | 可选的 PostgreSQL 告警归档连接串，不配置则不启用 |
| `archive.retention_years` | 归档保留周期（年）：`0` 永久保留（默认）；`N` 至少保留最近 N 年，更早的月分区整表删除 |
| `archive.batch_size` / `flush_interval` / `queue_size` | 每批写入条数（1000）/ 最长等待（2s）/ 内存队列容量（10 万） |

## API

| 接口 | 说明 |
| --- | --- |
| `GET /healthz` | 健康检查（无需认证） |
| `GET /metrics` | Prometheus 指标（会话、Basic 或 API 令牌；“仅监控指标”令牌只能访问此接口） |
| `POST /api/auth/login/2fa` | 双因素认证的第二步：`{"challenge":"…","code":"123456"}`（`/api/auth/login` 返回 `need_2fa` 与一次性挑战时使用） |
| `POST /api/auth/2fa/setup` / `enable` / `disable` | 绑定身份验证器（返回密钥、otpauth 链接与二维码）/ 验证启用（返回恢复码）/ 关闭 |
| `GET/POST /api/auth/tokens`、`DELETE /api/auth/tokens/{id}` | API 令牌管理（管理员） |
| `GET /api/audit?from=&to=&user=&action=&q=&failed=1`、`GET /api/audit/export?format=csv|jsonl`、`POST /api/audit/verify` | 操作审计检索 / 导出 / 哈希链校验（管理员） |
| `GET /api/incidents?status=active|closed|open…&severity=&assignee=me&overdue=1&q=` | 安全事件列表与各状态数量（含 `alerts` 告警条数与 `hits` 命中次数） |
| `GET /api/exposure` | 对外发布服务清单（DNAT 映射）、兜底端口与已过滤的探测次数 |
| `GET /api/incidents/{id}`、`POST /api/incidents/{id}`、`POST /api/incidents/bulk` | 事件详情 / 处置（`status`、`assignee`、`note`；批量时附 `ids`，运营分析员以上）、`GET /api/incidents/assignees` 可指派的负责人 |
| `GET/POST /api/suppressions`、`DELETE /api/suppressions/{id}` | 误报抑制规则（写操作需运营分析员以上） |
| `GET /api/syslog/senders`、`POST /api/syslog/senders`、`PUT/DELETE /api/syslog/senders/{id}`、`PUT /api/syslog/policy` | syslog 发送端画像、登记与白名单开关（写操作需管理员） |
| `GET /api/rawlog/search?from=&to=&ip=&q=&source=&attacks=1&limit=`、`GET /api/rawlog/export?…`、`GET /api/rawlog/status`、`POST /api/rawlog/verify` | 原始日志检索 / 导出（运营分析员以上）/ 留存状态 / 完整性校验（管理员） |
| `GET/POST /api/assets`、`PUT/DELETE /api/assets/{id}`、`POST /api/assets/import?type=assets|vulns&mode=merge|replace`、`GET /api/assets/template?type=` | 资产台账与导入（请求体为 CSV） |
| `GET /api/vulns?status=&severity=&q=&ip=`、`PUT /api/vulns/{id}`、`DELETE /api/vulns/{id}` | 漏洞列表与状态修改 |
| `GET /api/reports/periodic?period=week|month&range=recent|last&format=html`、`POST /api/reports/email` | 周报 / 月报（JSON 或可打印 HTML）/ 立即发送邮件（管理员） |
| `GET /api/compliance/mlps?format=html` | 等保 2.0 合规检查报告（管理员） |
| `POST /api/auth/login` / `POST /api/auth/logout` / `GET /api/auth/session` | 登录 / 退出 / 当前会话（其余接口均需登录，或使用 HTTP Basic 认证） |
| `POST /api/auth/password` | 修改自己的密码 |
| `GET/POST /api/auth/users`、`PUT/DELETE /api/auth/users/{name}`、`GET /api/auth/audit` | 账号管理与登录记录（管理员） |
| `POST /api/alert/robots/{id}/report` | 立即向该机器人发送安全日报（管理员） |
| `GET/POST /api/alert/robots`、`PUT/DELETE /api/alert/robots/{id}`、`POST /api/alert/robots/{id}/test` | 告警推送机器人管理与测试（写操作需管理员） |
| `GET /api/alerts/summary` | 告警条数与攻击命中次数的分等级统计 |
| `GET /api/meta` | 版本、定位数据源、省级地图索引 |
| `GET /api/overview` | 态势总览（KPI、分布、城市排行、威胁指数） |
| `GET /api/timeline?minutes=360` | 趋势数据 |
| `GET /api/map?level=` | 地图数据：城市级地点（含攻击源列表）、国家与省份着色统计 |
| `GET /api/attackers?level=&q=&sort=&limit=&offset=` | 攻击源列表；下钻条件 `country`、`city`、`net_type`、`isp`、`world`、`province`、`city_map`、`place`、`category`、`phase`、`technique`（ATT&CK 技术编号） |
| `GET /api/ip/{ip}` / `GET /api/ip/{ip}/rdap` | IP 溯源详情（含 `related` 同源关联分析）/ WHOIS 注册信息 |
| `GET /api/alerts?severity=&category=&result=&kind=&ip=&q=` | 告警查询；下钻条件 `phase`、`target`、`from` / `to`（Unix 秒或 RFC3339）、`technique`、`asset`（目标资产）、`incident`（所属事件） |
| `GET /api/surface` | 攻击面分析 |
| `GET /api/assessment` | 安全评估：七个维度评分与总评、P0~P3 处置建议、疑似失陷资产、ATT&CK 矩阵（`GET /api/report` 中同样包含） |
| `GET /api/sources` / `GET /api/rules` | 数据源与运行状态 / 规则列表（等级为最终生效值） |
| `GET /api/rules/stats` | 规则命中统计：已加载条数、本次运行有命中的条数、每条规则命中次数（用于发现长期未触发的规则） |
| `GET /api/stream` | SSE 实时告警流 |
| `GET /api/export/blocklist?format=nginx&level=high` | 导出封禁列表 |
| `GET /api/report` | 完整 JSON 报告 |
| `GET /api/archive/status` | 告警归档状态与分区信息 |
| `GET /api/archive/alerts?from=&to=&ip=&rule=&severity=&category=&result=&kind=&q=&limit=&offset=` | 历史告警查询（`ip` 可为 CIDR；时间为 RFC3339 或 `2006-01-02T15:04`，按 `timezone` 解析，默认最近 7 天） |
| `GET /api/archive/stats?…` / `GET /api/archive/export?…` | 历史告警统计 / 导出 CSV（参数同上） |

## 注意事项

- 开启在线溯源时，攻击 IP（不含正常访客）会被发送至 ip-api.com；内网隔离或合规要求不允许外发时请关闭 `geo.online.enabled`，此时由 ip2region + 区划地名库提供城市级离线定位。ip-api 免费接口为 HTTP、限速 15 批/分钟，程序已自动限速。
- 对于所有路径都返回 200 的单页应用（SPA），敏感文件探测可能被误判为“疑似成功”，可调整 `detect.success_min_bytes` 或将结果作为线索复核；扫描器的随机路径不会被登记为 Web 资产。
- 页面启用了 CSP、X-Frame-Options、Permissions-Policy、跨源隔离（COOP/CORP）等安全响应头，HTTPS 下启用 HSTS；日志中的攻击载荷仅作为文本展示；所有写操作校验同源（防 CSRF），请求体限制大小；导出的 CSV 对以 = + - @ 开头的单元格做转义，防止在 Excel 中触发公式注入；快照、账号、机器人配置文件权限均为 0600。
- 健壮性：单条畸形日志触发的解析 / 检测异常只跳过该条，不影响服务；画像数与行为检测窗口均有硬上限（大量伪造源地址的扫描不会耗尽内存）；未来时间的异常日志不会污染统计窗口；syslog TCP 支持 octet-counting 帧并限制并发连接与空闲时长；文件轮转后会继续读取旧文件中延迟写入的日志。
- 快照：每个 `storage.interval` 保存一次，画像分批编码、压缩与写盘在锁外进行（6 万个攻击源保存约 0.6 秒，期间日志入库最长等待约 30ms），重启后自动恢复并按当前评分规则重新计算等级。
- 快照带版本号（当前 `v2`，对应事件「命中 / 告警」双计数）：读取旧版本会自动迁移；读到**更新版本**或损坏的文件时拒绝加载，并把原文件改名为 `<快照>.v<N>.bak` / `<快照>.corrupt.bak` 保留，绝不被空状态覆盖。升级后如需回滚，请一并回滚快照或手工保留备份。
- 连接超时：读取请求（含请求体）限时 30 秒、写出响应限时 2 分钟，防止慢速连接长期占用资源；实时告警流与历史告警导出单独放宽。
- 性能：解析与检测由多个 worker 并行、按批（256 条）传递，聚合入库一次加锁处理一批。开发机（i7-10700，16 线程）端到端基准测试约 40 万条/秒以上，正常请求检测约 3.5µs/条（`go test -bench . ./internal/pipeline`）；正常访客只保存轻量画像，行为检测窗口有容量上限。
- 聚合接口不扫描全量画像：总览（国家/省份/城市/运营商/网络类型/目标/近 1 小时）与安全评估（情报命中、暴力破解/扫描/CC/端口来源数、ATT&CK 矩阵的攻击源数与最高等级）都在画像新增、攻击类型增加、等级变化、归属地更新与淘汰时增量维护，读取只做小规模拷贝。5 万攻击源下 `Overview` 由 29ms 降至约 6µs、`Assess` 由 22ms 降至约 0.1ms，避免长事务持锁阻塞日志入库；一致性由 `store/aggregate_test.go` 与全量扫描逐项对账。
