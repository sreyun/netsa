<div align="center">

# netsa

**开源的网络安全态势感知与攻击面分析平台**

把 nginx、防火墙 / IDS、主机认证与 DNS 日志，变成可溯源、可处置、会持续学习的安全态势。<br>
单个二进制，开箱即用，支持内网离线运行。

[![CI](https://github.com/sreyun/netsa/actions/workflows/ci.yml/badge.svg)](https://github.com/sreyun/netsa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/sreyun/netsa?label=release)](https://github.com/sreyun/netsa/tags)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

**简体中文** · [English](docs/i18n/README.en.md) · [繁體中文](docs/i18n/README.zh-TW.md) · [日本語](docs/i18n/README.ja.md) · [한국어](docs/i18n/README.ko.md) · [Español](docs/i18n/README.es.md) · [Français](docs/i18n/README.fr.md) · [Deutsch](docs/i18n/README.de.md) · [Русский](docs/i18n/README.ru.md)

[快速开始](#快速开始) · [界面预览](#界面预览) · [核心能力](#核心能力) · [工作原理](#工作原理) · [支持的日志](#支持的日志) · [文档](#文档)

</div>

![态势总览：攻击地图、实时告警与威胁指数](docs/images/overview.png)

## 为什么是 netsa

- **零依赖，一键部署**：Go 单二进制，前端、世界与中国省市地图、离线定位库全部内置，不需要 Elasticsearch、Kafka 或数据库。Docker 镜像同时提供 amd64 与 arm64，关闭在线溯源后可在隔离网络中完全离线运行。
- **日志不用先适配**：自动识别 40 余种格式，覆盖 nginx / Tengine / OpenResty / APISIX / Kong / Apache / IIS / Caddy、ModSecurity 等 WAF、iptables、华为、H3C、FortiGate、Palo Alto、Suricata、Linux 与 Windows 认证、主流 DNS，以及 Docker、Filebeat 等采集器的包装格式。
- **检测准，告警可信**：81 条特征规则（部分改编自 OWASP CRS）、libinjection 语法分析加行为检测，用响应、会话证据和资产漏洞复核“表面成功”。等级由统一裁决决定：已拦截的攻击不会被标成“严重”，真正利用成功的不会被漏掉。
- **认得国产 OA 和中间件**：内置 261 条漏洞接口签名，覆盖致远、泛微、用友、通达、蓝凌、万户 OA，帆软、亿赛通、若依、Nacos、APISIX、Nginx UI，以及深信服、锐捷、海康、大华等 43 个国产产品，告警直接注明产品与 CVE / CNVD 编号；正常业务在用的漏洞接口自动学习，不会一直刷告警。
- **情报在准不在多**：IP 与域名情报（STIX / TAXII / MISP / 文本列表），按远控、恶意软件、钓鱼、矿池、攻击来源分类定级，自动过滤被滥用的公共平台；每个情报源的准确率按分析员结论自动统计，长期误报的自动降级。
- **防火墙与 Web 日志联动**：Web 攻击之后内网主机连接攻击者、或连接攻击载荷里写着的回连地址，直接判为失陷迹象；载荷中的地址被连接即证明载荷已被执行。
- **能溯源到城市，能关联到团伙**：还原 CDN 与代理背后的真实 IP，识别 XFF 伪造和绕过 CDN 直连；多源定位交叉比对并给出置信度；同源关联分析找出疑似同一攻击者的其他 IP。
- **越用越准**：从分析员的处置结论中学习，反复误报的规则和接口自动降级，已确认的攻击者再次出现自动升级；不需要人工整理白名单，自动从正常流量学习每个参数平时的取值、被动识别每个站点使用的产品与前端框架，搜索框里的普通文字、站点上根本不存在的产品的漏洞探测不再刷出高危。AI 研判同时支持 OpenAI 与 Anthropic 接口，内网 vLLM、云端模型都能接入，自动适配模型差异，并用分析员的结论评估模型可信度。
- **安全运营闭环**：事件聚合与处置时限、误报抑制、钉钉 / 企业微信 / 飞书推送、资产漏洞关联、原始日志留存与取证、周报月报、等保 2.0 自查、防篡改审计链。
- **单机就够快**：开发机（i7-10700，16 线程）端到端约 46 万条/秒；Aho-Corasick 预筛让正常请求基本不必执行正则，检测约 3µs/条。

## 快速开始

### 一条命令体验（自带模拟攻击日志）

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose -f docker-compose.demo.yml up -d --build
```

浏览器打开 <http://localhost:8080>，账号 `admin`，密码 `Netsa@demo2026`。模拟器会持续生成攻击日志，大屏实时更新。

### 生产部署

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
docker compose pull
docker compose up -d
```

- 访问 `http://<服务器IP>:8080`，初始密码在日志中：`docker compose logs netsa | grep 初始密码`，首次登录后须修改。
- 默认读取宿主机 `/var/log/nginx` 与 `/var/log`；网络设备的 syslog 发送到 `<服务器IP>:5514`（UDP / TCP）。
- 需要固定版本、修改端口或启用告警归档时，先执行 `cp .env.example .env` 再按注释修改。
- Windows PowerShell 5.1 不支持 `&&` 和 `grep`：请逐行执行命令，并用 `Select-String` 代替 `grep`。

升级回滚、内网离线部署和常见问题见[部署指南](docs/deployment.md)。

### 不部署，直接分析已有日志

```bash
go build -o bin/netsa ./cmd/netsa
./bin/netsa analyze /var/log/nginx/access.log* /var/log/ufw.log -o report.json
./bin/netsa analyze -listen :8080 access.log    # 分析后打开大屏
```

## 界面预览

| 安全评估与处置建议 | 攻击面分析 |
|---|---|
| ![安全评估](docs/images/assess.png) | ![攻击面分析](docs/images/surface.png) |
| **事件处置与处置时限** | **自学习与自动校准** |
| ![事件处置](docs/images/incidents.png) | ![自学习](docs/images/learn.png) |

截图来自内置模拟器生成的演示数据，其中的 IP 与站点均为模拟，可用上面的演示环境自行体验。

## 核心能力

| 模块 | 能力 |
|---|---|
| [日志采集](docs/log-sources.md) | 实时跟踪文件（通配符、logrotate 轮转）、批量分析（含 `.gz`）、Syslog UDP / TCP / TLS（可双向认证）；发送端识别、白名单、限速与断流告警 |
| [攻击检测](docs/detection.md) | SQL 注入、XSS、命令执行、Log4Shell、SSRF、XXE、反序列化、WebShell、已知漏洞利用等特征规则，部分命令、代码、Java 类规则改编自 OWASP CRS；[libinjection 语法分析](docs/detection.md#语法分析libinjection)复核注入命中并补上正则漏掉的变形；[国产 OA、中间件漏洞接口签名](docs/detection.md#国产-oa中间件漏洞接口签名)（254 条，41 个产品）；CC、暴力破解、撞库、接口遍历、端口扫描等行为检测；多轮解码对抗常见绕过 |
| [结果研判](docs/detection.md#研判复核用证据排除表面成功) | 按响应与会话证据区分已拦截、失败、未拦截、疑似成功；排除单页应用兜底页、统一错误页、未到达服务的“放行”等表面现象 |
| [主机与 DNS 检测](docs/log-sources.md#主机认证日志与-dns-日志) | SSH / RDP / VPN 暴力破解与破解成功、密码喷洒、日志被清除、新建账号与提权；DNSLog 带外回连、DNS 隧道、DGA、矿池域名，以及情报标记的远控、恶意软件、钓鱼域名 |
| [攻击源溯源](docs/traceability.md) | 融合 ip2region、MaxMind、ip-api、rDNS、RDAP / WHOIS，支持内网自定义网段定位；同源关联按网段、工具指纹、攻击手法找出疑似同一团伙 |
| [态势大屏](docs/deployment.md#演示环境) | 世界 / 中国双视图攻击地图，可下钻到省和地市；实时飞线与告警推送；KPI、趋势、分布图均可点击下钻到攻击源或告警 |
| [攻击面分析](docs/log-sources.md#未做-dnat-映射的端口探测) | 梳理对外服务，发现源码、密钥、备份泄露与管理接口暴露；结合 DNAT 映射与防火墙会话证据，过滤打不到任何服务的背景扫描 |
| [安全评估与失陷研判](docs/detection.md#安全评估与失陷研判) | 七个维度打分并给出 A~E 总评与 P0~P3 处置建议；内网主机外连情报地址、C2 心跳检测；[防火墙与 Web 日志联动](docs/detection.md#防火墙与-web-日志联动被攻击后回连)发现被攻击后回连攻击者的主机；MITRE ATT&CK 矩阵 |
| [自学习与 AI 研判](docs/self-learning.md) | 规则级、目标级与威胁情报源准确率自动校准、确认攻击源复现升级、学习窗口，策略可在页面调整；从日志自动学习内网网段、攻击源、攻击活动、[参数正常取值与站点产品](docs/self-learning.md#参数的正常取值与站点产品)；AI 研判支持 OpenAI / Anthropic 接口与 vLLM，自动适配模型差异，附带本单位相似案例，并统计模型与分析员结论的一致率 |
| [事件处置与推送](docs/operations.md#事件处置与误报抑制) | 告警自动聚合为事件，支持指派、处置时限与超时提醒；误报抑制；[钉钉 / 企业微信 / 飞书推送](docs/operations.md#告警推送钉钉--企业微信--飞书)，去重、合并、限速；导出 nginx、iptables、ipset 等封禁列表 |
| [留存、合规与审计](docs/operations.md#原始日志留存与检索) | 原始日志按小时压缩留存，哈希链防篡改；[PostgreSQL 长期归档](docs/operations.md#告警归档可选postgresql)（可选）；周报月报、等保 2.0 自查；[三种角色、双因素认证与防篡改审计链](docs/operations.md#登录账号与审计)；Prometheus 指标 |

## 工作原理

```text
日志源      nginx · 防火墙 / IDS · 主机认证 · DNS · 容器与采集器
   │        文件跟踪 / 批量分析 / Syslog（UDP · TCP · TLS）
   ▼
格式识别    每个数据源、每个发送端独立识别格式与时区
   ▼
真实 IP     按可信代理还原来源，标记 XFF 伪造与绕过 CDN
   ▼
威胁检测    特征规则（AC 预筛 + 正则）+ 语法分析（libinjection）+ 行为检测（时间窗口，内存有上限）
   ▼
证据过滤    会话证据与 DNAT 映射排除未到达服务的探测，应用误报抑制
   ▼
学习校准    参数正常取值、站点产品复核命中；按分析员结论下调反复误报的命中，升级已确认攻击源（learn）
   ▼
联动分析    防火墙出站连接关联此前的 Web 攻击：被攻击后回连攻击者或载荷中的回连地址
   ▼
等级裁决    分类底线、成功升级、结果封顶，统一决定最终等级（risk）
   ▼
状态库      攻击者画像 · 告警 · 安全事件 · 攻击面 · 时间序列 · 快照持久化
   │
   ├── Web 大屏与 REST API（SSE 实时推送）
   ├── 钉钉 / 企业微信 / 飞书 / Webhook
   ├── 原始日志留存 · PostgreSQL 归档（可选）
   └── AI 研判（可选，结论写入事件处置记录）
```

几个关键设计：

- **等级只在一处裁决**：规则声明的等级只是建议值，避免各环节各自加减造成同类事件等级不一致。详见[威胁等级判定](docs/detection.md#威胁等级判定)。
- **证据优先于表象**：防火墙“放行”、响应 200、多次失败后登录成功，都要再用会话、响应基线和账号线索复核。
- **学习有边界**：规则校准只从人的结论学习，自动调整每次最多一级，利用成功仍判严重；从正常流量学到的参数取值与站点产品，要两个相互独立的依据同时成立才降级（参数平时就是普通文字 + 语法分析不构成注入；站点没有该产品 + 请求没有成功），只降到低危、不隐藏告警；会隐藏告警的误报抑制必须人工采纳。AI 结论不作为学习样本，也不会自动处置。
- **压力下不失控**：解析与检测并行、按批入库，画像数和检测窗口都有硬上限，单条畸形日志不影响服务；队列积压和丢弃都有监控指标。

## 支持的日志

| 类型 | 格式 |
|---|---|
| **Web** | nginx / Tengine / OpenResty / Apache（combined、main、vhost）、任意自定义 `log_format`、nginx JSON、APISIX、Kong、Nginx Proxy Manager、Caddy、Traefik、Elastic ECS、IIS W3C |
| **WAF** | nginx / Tengine / OpenResty 错误日志中的 ModSecurity、naxsi 拦截与限流，ModSecurity JSON 审计日志，OpenResty Lua WAF |
| **防火墙** | iptables、UFW、firewalld、nftables、pfSense / OPNsense、Windows 防火墙、Cisco ASA / FTD、Palo Alto、FortiGate、华为 USG、H3C、深信服、山石 |
| **IDS / IPS** | Suricata EVE JSON、Snort fast alert、FortiGate IPS / UTM 等设备威胁日志 |
| **主机与 VPN 认证** | Linux `auth.log` / `secure`、Windows 安全事件（NXLog、Winlogbeat、Snare）、FortiGate / Cisco / OpenVPN、SQL Server 登录 |
| **DNS** | BIND、dnsmasq、CoreDNS、Windows DNS、Zeek、Suricata DNS |
| **容器与采集器** | Docker json-file、Fluent Bit / Fluentd、Filebeat / Logstash / Vector、containerd / CRI-O，自动拆开后识别原始日志 |

接入方法见[日志接入](docs/log-sources.md)；接入后在大屏“数据源”页查看识别结果和解析失败样例。

## 文档

| 文档 | 内容 |
|---|---|
| [部署指南](docs/deployment.md) | 生产部署、`.env` 变量、升级回滚、内网离线、演示环境、从源码运行 |
| [日志接入](docs/log-sources.md) | Web、防火墙、认证、DNS 接入，syslog 发送端管理，时区，DNAT 与会话证据 |
| [检测与研判](docs/detection.md) | 威胁等级判定、研判复核、威胁评分、安全评估与失陷研判 |
| [攻击源溯源](docs/traceability.md) | 多源定位、内网网段、定位库热更新、同源关联分析 |
| [自学习与 AI 研判](docs/self-learning.md) | 自动生效的范围与边界、行为基线、合规自检、外部模型配置与模型适配 |
| [安全运营](docs/operations.md) | 事件处置、告警推送、原始日志、资产漏洞、报表合规、账号审计、监控指标、告警归档 |
| [配置参考](docs/configuration.md) | 常用配置项与运行注意事项 |
| [API](docs/api.md) | REST 接口一览 |
| [对接外部系统](docs/integrations.md) | LDAP / OIDC 单点登录、SIEM 转发、联动封禁、工单与处置剧本、STIX / TAXII / MISP 与文本情报（IP、域名，情报类别）、Sigma 与签名规则包 |
| [开发与发布](docs/development.md) | 本地测试、代码结构、镜像构建与发布 |
| [更新记录](docs/CHANGELOG.md) | 影响使用的变化 |

## 开发

需要 Go 1.25 及以上（发布版本使用 Go 1.27 构建），纯 Go 实现，无 CGO。

```bash
go build -o bin/netsa ./cmd/netsa
gofmt -l internal cmd     # 必须没有输出
go vet ./...
go test ./...
```

竞态测试依赖 C 编译器，本机没有 gcc 时可以在容器里运行：

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.27-alpine sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
```

代码结构和发布流程见[开发与发布](docs/development.md)。

## 参与贡献

欢迎提交 Issue 和 Pull Request，尤其欢迎：

- 新的日志格式样例（请先脱敏），以及识别失败或解析错误的反馈；
- 新的检测规则，以及带样例的误报、漏报报告；
- 文档改进和实际部署经验。

提交代码前请先通过上面的检查，CI 还会运行竞态测试和 `govulncheck`。

如果 netsa 对你有帮助，请点一个 **Star**，让更多需要它的人看到。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 发布：可以自由地用于商业目的、修改与再分发，只需保留版权声明、许可文本与 [NOTICE](NOTICE) 文件。

- 软件按「现状」提供，不附带任何明示或暗示的担保；
- 许可不授予商标使用权，`netsa` 名称与标识不包含在授权范围内；
- 第三方依赖遵循各自许可，完整列表见 `go.mod` 与 `go.sum`；部分检测规则改编自 [OWASP Core Rule Set](https://coreruleset.org)（Apache-2.0），国产 OA、中间件漏洞接口签名提取自 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)（MIT），见 [NOTICE](NOTICE)。

规则与情报订阅、部署交付、等保测评支撑等商业服务由维护方另行提供，不影响开源版依据 Apache-2.0 的使用权利。
