# API

[← 返回 README](../README.md)

所有接口均需登录（会话、HTTP Basic 或 API 令牌），另有说明的除外。

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
| `GET /api/incidents/{id}/evidence` | 一键取证包（zip）：事件详情、时间线、来源画像、资产攻击链路、归档告警、原始日志与 SHA-256 哈希清单（运营分析员以上，写入审计） |
| `GET /api/block`、`POST /api/block` | 封禁记录、提交封禁申请（运营分析员以上） |
| `POST /api/block/{id}/approve`、`reject`、`release` | 审批、驳回、解除封禁（管理员） |
| `GET /api/block/edl` | 生效中的封禁地址（纯文本，每行一个），供防火墙拉取 |
| `GET /api/rules/managed`、`POST /api/rules/managed`、`DELETE /api/rules/managed/{id}` | 页面维护的规则 |
| `POST /api/rules/test` | 用样本试运行规则（不保存） |
| `POST /api/rules/packs`、`DELETE /api/rules/packs/{name}` | 安装、卸载签名规则包 |
| `POST /api/rules/sigma` | 转换 Sigma 规则（`{"yaml":"…","apply":false}`，`apply` 为 true 时导入） |
| `GET /api/integrations` | 外部系统对接状态（管理员） |
| `GET /api/admin/backup` | 下载状态备份（管理员） |
| `GET /api/auth/oidc/start`、`GET /api/auth/oidc/callback` | 单点登录 |
| `POST /api/incidents/ai-batch` | 把事件加入后台研判队列（`{"ids":[…]}`，最多 500 个，运营分析员以上） |
| `POST /api/incidents/{id}/ai` | 对事件执行 AI 研判，结论写入处置记录（运营分析员以上） |
| `GET /api/learn`、`POST /api/learn/suggestions/{id}/apply|dismiss`、`POST /api/learn/rules/{rule}/pin|unpin`、`PUT /api/learn/policy` | 自学习状态（规则 / 目标级校准、确认攻击源、自动生效次数、模型一致率、建议、进化日志；`report.attack` 为从日志学到的攻击行为，`report.profile` 为参数正常取值、站点产品与已认定的业务接口）、采纳或忽略建议、锁定规则与修改策略（管理员） |
| `GET /api/ai/settings`、`PUT /api/ai/settings`、`POST /api/ai/test`、`POST /api/ai/models` | 外部模型配置（协议、地址、名称、密钥、启用；响应不含密钥）、连接测试与读取模型列表（管理员） |
| `GET/POST /api/suppressions`、`DELETE /api/suppressions/{id}` | 误报抑制规则（写操作需运营分析员以上） |
| `GET/POST /api/authscans`、`POST /api/authscans/{id}/end`、`DELETE /api/authscans/{id}` | 授权扫描登记：扫描源（地址或网段）、起止时间（`start` / `end`，RFC3339 或按展示时区的 `2006-01-02T15:04`；不填结束时间时可用 `hours`）、说明；期间只记录不告警，返回期间的事件数、命中数、攻击类型与目标（写操作需运营分析员以上） |
| `GET /api/deception`、`POST /api/deception`、`DELETE /api/deception/{id}` | 诱饵：诱饵列表（类型、值、说明、命中次数、来源数，`config` 为配置文件中的诱饵）、命中过诱饵的来源（`attackers`）与使用同一线索 / 账号的来源（`links`）；登记 `{"kind":"path|token|account|host","value":"…","note":"…"}`（写操作需运营分析员以上，配置文件中的诱饵不能在页面删除） |
| `GET /api/syslog/senders`、`POST /api/syslog/senders`、`PUT/DELETE /api/syslog/senders/{id}`、`PUT /api/syslog/policy` | syslog 发送端画像、登记与白名单开关（写操作需管理员） |
| `GET /api/rawlog/search?from=&to=&ip=&q=&source=&attacks=1&limit=&clip=&cursor=`、`GET /api/rawlog/export?…`、`GET /api/rawlog/status`、`POST /api/rawlog/verify` | 原始日志检索 / 导出（运营分析员以上）/ 留存状态 / 完整性校验（管理员）。检索结果中的 `next` 传给 `cursor` 取下一页；`clip` 限制每条返回的字节数 |
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
| `GET /api/campaigns` | 攻击活动：多个攻击源之间的强关联归并的活动，含成员、关联依据、来源网段、OAST 关联标识（`oast`）与建议封禁网段（缓存 1 分钟） |
| `GET /api/search?q=` | 全局搜索：按攻击源、安全事件、资产攻击链路、资产台账、攻击活动、检测规则分组，每组 `total` 为匹配总数、`items` 为前 6 项（`type`、`key`、`title`、`sub`、`level`）；`#12` 只返回编号为 12 的事件。关键字最长 100 个字符，结果缓存 1 秒 |
| `GET /api/chains?q=&stage=&compromised=1&limit=` | 资产攻击链路列表：每个资产推进到的阶段（`reached`）、最深阶段、失陷研判（`confidence`：high / medium）、合并的标识与结论；`stage` 只看推进到该阶段之后的（如 `exploit` 表示越过侦察），`limit` 默认 100、最多 500 |
| `GET /api/chains/detail?asset=` | 一个资产的完整攻击链路：八个阶段的统计与 ATT&CK 技术、关键路径、时间线（每一步的来源、目标、证据、告警与事件编号）、攻击来源、合并依据与处置建议；`asset` 可以是台账资产名称、站点域名或主机地址 |
| `GET /api/alerts?severity=&category=&result=&kind=&ip=&q=` | 告警查询；下钻条件 `phase`、`target`、`from` / `to`（Unix 秒或 RFC3339）、`technique`、`asset`（目标资产）、`incident`（所属事件） |
| `GET /api/surface` | 攻击面分析 |
| `GET /api/assessment` | 安全评估：七个维度评分与总评、P0~P3 处置建议、疑似失陷资产、ATT&CK 矩阵（`GET /api/report` 中同样包含） |
| `GET /api/sources` / `GET /api/rules` | 数据源与运行状态 / 规则列表（等级为最终生效值） |
| `GET /api/rules/stats` | 规则命中统计：已加载条数、本次运行有命中的条数、每条规则命中次数（用于发现长期未触发的规则） |
| `GET /api/stream` | SSE 实时告警流 |
| `GET /api/export/blocklist?format=nginx&level=high` | 导出封禁列表：`txt`、`nginx`（nginx / Tengine / OpenResty / Nginx UI）、`iptables`、`ipset`、`firewalld`、`windows`、`csv`、`apisix`、`kong`（ip-restriction 插件 JSON）；`level` 为 `low` / `medium` / `high`（默认）/ `critical`，写错时返回 400 |
| `GET /api/report` | 完整 JSON 报告 |
| `GET /api/archive/status` | 告警归档状态与分区信息 |
| `GET /api/archive/alerts?from=&to=&ip=&rule=&severity=&category=&result=&kind=&q=&limit=&offset=` | 历史告警查询（`ip` 可为 CIDR；时间为 RFC3339 或 `2006-01-02T15:04`，按 `timezone` 解析，默认最近 7 天） |
| `GET /api/archive/stats?…` / `GET /api/archive/export?…` | 历史告警统计 / 导出 CSV（参数同上） |
