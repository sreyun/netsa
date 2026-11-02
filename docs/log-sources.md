# 日志接入

[← 返回 README](../README.md)

各类日志的接入方式、自动识别规则、syslog 发送端管理与时区处理。

## nginx

默认 `main` / `combined` 格式即可直接识别。站点位于 CDN/负载均衡之后时，务必记录 `$http_x_forwarded_for`，并把 CDN 回源网段加入 `real_ip.trusted_proxies`；多站点建议记录 `$host`：

```nginx
log_format netsa '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_x_forwarded_for" $request_time $host';
access_log /var/log/nginx/access.log netsa;
```

自定义格式时把上面的 `log_format` 原样（可多行）粘贴到数据源的 `log_format` 字段；JSON 格式自动识别。远程 nginx 也可直接发送 syslog：`access_log syslog:server=netsa服务器IP:5514,tag=nginx netsa;`

**JSON 格式**：字段名不限顺序、不区分大小写，嵌套对象自动展开，常见写法均可识别（来源 `remote_addr` / `client_ip`，请求 `request` 整行或 `request_method` + `request_uri` + `args`，状态码字符串或数字，时间 `time_iso8601` / `time_local` / `@timestamp` / `msec`）。推荐加上 `escape=json`：

```nginx
log_format netsa_json escape=json '{"time_iso8601":"$time_iso8601","remote_addr":"$remote_addr","request":"$request",'
  '"status":"$status","body_bytes_sent":"$body_bytes_sent","http_referer":"$http_referer","http_user_agent":"$http_user_agent",'
  '"http_x_forwarded_for":"$http_x_forwarded_for","request_time":"$request_time","host":"$host"}';
access_log /var/log/nginx/access.json netsa_json;
```

- 未加 `escape=json` 时，nginx 会把值中的引号、反斜杠、中文写成 `\x22`、`\x5C`、`\xE4…`，整行不是合法 JSON。netsa 会先还原再解析，带引号、尖括号、中文的请求（往往正是 XSS、注入）不会被当成解析失败丢弃。
- **Elastic ECS 字段**（`source.ip`、`url.original`、`user_agent.original`、`http.response.status_code` 等）按完整路径取值。`url.original` 与 `user_agent.original` 这类末级同名的字段不会互相覆盖。

**容器与采集器转发**：日志被容器运行时或采集器再包一层时自动拆开，按里面的原始日志识别格式（文本与 JSON 均可）。原始日志留存保存的是包装内的原文，数据源 / 发送端列表中显示为“nginx（log 字段包装）”等：

| 包装 | 示例 |
|---|---|
| Docker json-file、Fluent Bit、Fluentd | `{"log":"<原始日志>\n","stream":"stdout","time":"…"}` |
| Filebeat、Logstash、Vector 等 | `{"message":"<原始日志>", "host":{…}, …}`（最多拆两层，如采集器转发的 Docker 日志） |
| containerd / CRI-O（Kubernetes） | `2026-10-26T10:00:00.123456789+08:00 stdout F <原始日志>` |

**反向代理自动识别（默认开启）**：站点放在负载均衡 / 反向代理之后、但没有配置 `real_ip.trusted_proxies` 时，所有攻击都会记到负载均衡上。netsa 会统计直连地址：

- **内网或本机地址**：持续携带 `X-Forwarded-For`，且其中出现 8 个以上不同的公网客户端时，自动按可信代理还原真实攻击源。
- **公网地址**：只提示“疑似未配置的 CDN / 代理节点”，确认后再加入 `trusted_proxies`。公网来源可以任意伪造请求头，不会自动信任。

识别结果显示在 **数据源 → 溯源与检测能力**。关闭：`real_ip.auto_learn: false`。平台自身登录接口的来源判断不受影响，仍只信任配置的可信代理。

使用 Cloudflare 等 CDN 时，可额外记录 CDN 提供的客户端地址头（如 `"$http_cf_connecting_ip"`，JSON 格式字段名为 `http_cf_connecting_ip`），并配置：

```yaml
real_ip:
  trusted_presets: [cloudflare]                 # 内置 Cloudflare 回源网段
  headers: [cf_connecting_ip, x_forwarded_for]  # 按优先级尝试
  cdn_only: true                                # 源站只应经 CDN 访问：公网直连会告警“绕过 CDN 直连源站”
```

只有请求确实来自可信代理时才采信这些请求头，攻击者直连源站时伪造的 X-Forwarded-For 不会改变攻击源，且会被标记为“伪造 X-Forwarded-For”。

## 其他 Web 服务器

- **Apache**：默认 combined 格式直接识别。
- **IIS**：W3C 扩展日志（`u_ex*.log`），按文件中的 `#Fields:` 指令自动映射字段，建议勾选 `X-Forwarded-For` 自定义字段。
- **Caddy / Traefik**：JSON 访问日志直接识别（Caddy `request.remote_ip`、`request.headers`；Traefik `ClientHost`、`RequestPath` 等）。

## 防火墙与 IDS

- **UFW**：`ufw logging medium`，日志 `/var/log/ufw.log`
- **firewalld**：`firewall-cmd --set-log-denied=all`，日志位于 `kern.log`（Debian/Ubuntu）或 `messages`（RHEL）
- **iptables**：在 DROP 前加 `iptables -A INPUT -j LOG --log-prefix "[IPTABLES DROP] "`（前缀含 DROP/REJECT/ACCEPT 等关键字用于判断动作）
- **网络设备**（FortiGate、华为、H3C、Cisco ASA、Palo Alto、pfSense 等）：syslog 发送到 `netsa服务器:5514`（UDP/TCP），并开启策略允许/拒绝日志；FortiGate/Palo Alto 的 IPS/威胁日志会直接按攻击名称归类
- **Windows**：`netsh advfirewall set allprofiles logging droppedconnections enable`，日志 `%windir%\system32\LogFiles\Firewall\pfirewall.log`
- **Suricata**：跟踪 `eve.json`，`alert` 事件按签名映射为攻击；建议在 `suricata.yaml` 中为 netsa 单独输出一个只含 `alert` 类型的 eve 文件，减少无关事件
- **Snort**：跟踪 fast 格式的 `alert` 文件，或通过 syslog 发送

接入后在大屏 **数据源** 页查看自动识别的格式、解析成功/失败数与失败样例。注意 `timezone` 需与日志产生方一致（syslog 等日志不含时区）。

## 主机认证日志与 DNS 日志

| 类型 | 支持的格式 | 检测 |
| --- | --- | --- |
| 主机 / VPN 认证（`type: auth`） | Linux `auth.log` / `secure`（sshd、PAM、useradd、usermod）、Windows 安全事件（NXLog / Winlogbeat JSON、Snare 及中英文事件文本，4624 / 4625 / 4740 / 4720 / 4728 / 4732 / 4756 / 1102 / 4697 / 7045 / 4698 / 4771 / 4776）、FortiGate SSL VPN 与管理登录、Cisco ASA AAA / AnyConnect、OpenVPN、SQL Server 登录 | 暴力破解（`auth_failures`）、密码喷洒 / 账号枚举（`auth_users` 个不同账号）、**多次失败后登录成功（账号疑似失陷）**、公网 IP 直接登录特权账号、安全日志被清除、新建账号、加入管理员组、新安装服务 / 计划任务 |
| DNS（`type: dns`） | BIND querylog、dnsmasq、CoreDNS、Windows DNS 调试日志、Zeek `dns.log`、Suricata eve.json（`event_type: dns`）及 JSON DNS 日志 | **DNSLog 带外回连**（内网主机解析 dnslog.cn、ceye.io、oast.* 等，说明盲打的 RCE / SSRF / Log4j 已被触发）、矿池域名（挖矿木马）、DNS 隧道（超长高熵子域名、同一主域名下大量不同子域名）、DGA 随机域名与 NXDOMAIN 风暴、动态域名 / 内网穿透服务 |

DNS 与主机事件的主体是**内网主机本身**（判断其是否失陷），不受 `detect.whitelist` 影响；命中后计入“失陷研判”与 ATT&CK 矩阵（T1071.004、T1568.002、T1496、T1070.001、T1136、T1098 等）。认证日志也可经 syslog 接收，没有远程来源的主机事件（如日志被清除）以发送日志的设备为主体。

## Syslog 发送端管理与数据源健康

在 **数据源 → Syslog 发送端** 中查看每个发送 syslog 的设备（源 IP）：

- **发送端画像**：设备自报的主机名（经中继转发时区分设备）、TLS 客户端证书、协议（UDP / TCP / TLS）、识别出的日志格式、日志量与近 5 分钟速率、解析失败数与失败样例、时区校正、最近接收时间；每个发送端独立识别格式与时区，互不干扰。
- **登记与分组**：按 IP 或网段登记设备名称、分组（防火墙 / WAF / 服务器 / VPN …）与断流阈值；告警的“数据来源”显示为设备名称。分组汇总在线、断流、被拒绝的设备数与日志速率。
- **白名单与阻止**：开启 **发送端白名单** 后只接收已登记（允许）的发送端，其余来源的 UDP 数据报直接丢弃、TCP / TLS 连接在读取前立即断开，被拒绝的来源按 IP 计数并推送“未授权的 syslog 发送端”通知（同一来源 6 小时一次，伪造源地址的洪泛不会刷屏）。开启时可一键把近 24 小时活跃的发送端登记为允许，避免误断；白名单为空时不允许开启。“阻止”规则在任何模式下都拒绝该来源。也可在配置文件 `syslog.senders` 中登记（只读）、`syslog.allowlist: true` 强制开启。
- **防伪造与防洪泛**：UDP 源地址可被伪造，对完整性要求高的设备建议使用 **TLS（RFC 5425）**，配置 `syslog.tls_client_ca` 后要求客户端证书（双向认证）；`syslog.rate_limit` 限制单个发送端的日志速率，异常设备不会挤占处理能力；发送端画像数有上限，伪造的大量来源不会挤掉已登记的设备。
- **断流告警**：跟踪中的日志文件、syslog 监听与登记的发送端超过阈值（`alert.source_silence`，默认 30 分钟；可按数据源 / 发送端单独设置）没有新日志时推送“数据源断流”告警，恢复后再推送一次；一分钟内解析失败率超过一半（日志格式被修改）、告警归档连续写入失败或队列溢出时同样推送。断流状态显示在数据源页面。

## 时间与时区

- 不带时区信息的日志时间（传统 syslog、FortiGate、Cisco ASA、华为、Palo Alto、Snort、Windows 防火墙等）按 `timezone` 解析；IIS W3C 日志按标准以 UTC 解析；nginx、Suricata、RFC 5424 等带时区的时间按其自身时区。
- **自动校正**（`time_correction: auto`，默认开启）：对实时日志（已追上文件末尾后新写入的行、syslog 各发送端分别统计）比较日志时间与接收时间，若持续相差某个整时区（例如服务器或设备按 UTC 记录，而 `timezone` 为 Asia/Shanghai，时间慢 8 小时），自动校正并在“数据源”页面显示“时区已自动校正 +8 小时”。历史日志回放、设备断网后集中补发的日志不会触发校正；日志产生方改为正确时区后校正自动撤销。建议仍将日志产生方的时区设置一致。
- 页面、告警推送消息与导出文件中的时间统一按 `timezone`（未配置时按服务进程的 `TZ`）展示，与查看页面的电脑所在时区无关。

## 未做 DNAT 映射的端口探测

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

**会话证据研判（默认开启，无需维护清单）**：防火墙“放行”不等于探测到达了服务。netsa 读取防火墙日志自身记录的会话证据，判断一次放行的外部访问是否真正建立了通信。即使 `exposure.enabled: false` 也生效：

| 日志中的证据 | 判断 | 处理 |
|---|---|---|
| 源 / 目的安全域相同或目的为外网域（华为 `source-zone=untrust, destination-zone=untrust`） | 报文没有转发到任何内部安全域 | 端口探测只打标签，不告警 |
| 会话结束时目标无应答（华为会话日志 `RcvPkts=0`、FortiGate `rcvdpkt=0`、Palo Alto end 日志收包数为 0） | 没有建立通信 | 只打标签，不告警 |
| DNAT 后为内网地址（FortiGate `trandisp=dnat tranip`、华为 `DestinationNatIP`、Palo Alto NAT 目的地址等），或转发到内部安全域（`destination-zone=dmz`） | 确实到达了内部服务 | 保持告警并注明证据，不再按手工清单过滤；DNAT 后地址直接用于关联资产台账 |
| 目的安全域为 `local`，端口不是设备服务（如 37215、2323、5432） | 打到防火墙自身未提供服务的端口 | 只打标签，不告警；按策略汇总为“可疑放行策略”（local 安全域策略过宽）。ICMP 等无端口协议（ping 防火墙）由设备自身应答，不按此判断 |
| 目的安全域为 `local`，端口是设备的管理 / VPN 服务（SSH、Telnet、HTTP(S)、SNMP、NETCONF、IKE、L2TP、SSL VPN；可用 `exposure.device_ports` 追加） | 打到防火墙自身的服务 | 单次探测只打标签；管理服务对公网放行记为攻击面风险“防火墙管理服务对公网放行”（Telnet / HTTP / SNMP 为高危，SSH / HTTPS / NETCONF 为中危，VPN 不计）；针对该端口的暴力破解照常告警 |
| 日志没有上述字段 | 无法判断 | 按 `exposure.enabled` / `services` 判断 |

- **可疑放行策略**：被放行却没到达任何服务的外部流量会按“策略 + 安全域”汇总，显示在 **数据源 → 溯源与检测能力** 和 `GET /api/exposure` 的 `policies` 中。例如外部探测命中出站策略「允许本地上外网」（untrust → untrust），通常是该策略的源安全域或源地址配得过宽，建议限定为内网安全域。
- 这类放行不计入候选映射，避免把打到防火墙上的背景扫描误报成“疑似对外映射”。
- 为什么不主动连接探测端口：netsa 位于内网，探测自己的公网地址依赖回流 NAT；而且很多端口只对特定来源开放，内部测得的结果和攻击者看到的不一致。一旦误判为“不通”，真实攻击就不会再告警。用防火墙自身记录的会话证据更可靠，也不会对生产网络产生额外流量。
- 华为建议同时开启会话日志（会话结束时输出收发包计数）。策略匹配日志（`POLICYPERMIT`）只有安全域，没有应答计数。
- 关闭：`exposure.reach_check: false`。指标 `netsa_exposure_unreached_total`。
