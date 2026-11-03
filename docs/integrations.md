# 对接外部系统

[← 返回 README](../README.md)

单点登录、SIEM 转发、联动封禁、工单与处置剧本、在线情报、规则运营。这些都是可选的，默认关闭；配置写在 `config.yaml`，修改后重启生效。“系统管理 → 对接状态”可以确认配置是否生效，每一项的运行情况也有对应的监控指标。

密钥和令牌都只从环境变量读取，不写进配置文件。

## 单点登录

### LDAP / Active Directory

配置后，登录页的账号密码会先按本地账号校验，本地账号不存在时再查目录服务。

```yaml
server:
  ldap:
    url: ldaps://ldap.example.com:636     # 也可以用 ldap:// 加 start_tls: true
    ca_file: /app/configs/ldap-ca.pem     # 内部 CA 证书（可选）
    bind_dn: cn=netsa,ou=services,dc=example,dc=com
    bind_password_env: NETSA_LDAP_PASSWORD
    base_dn: dc=example,dc=com
    user_filter: "(|(uid=%s)(sAMAccountName=%s))"  # 默认值，%s 是转义后的用户名
    group_attr: memberOf                  # 默认值
    admin_groups: ["soc-admins"]          # 可以写组的 CN，也可以写完整 DN
    analyst_groups: ["soc"]
    viewer_groups: ["staff"]
    default_role: ""                      # 匹配不到组时的角色；留空表示拒绝登录
```

### OpenID Connect

登录页会显示单点登录按钮。支持 Keycloak、Authing、Okta、Azure AD 等符合标准的身份提供方（授权码流程 + PKCE，ID Token 使用 RS256 或 ES256）。

```yaml
server:
  oidc:
    issuer: https://idp.example.com/realms/soc
    client_id: netsa
    client_secret_env: NETSA_OIDC_SECRET
    redirect_url: https://soc.example.com/api/auth/oidc/callback  # 在身份提供方中登记同样的地址
    display_name: 企业单点登录             # 登录页按钮上的文字
    role_claim: groups                    # 默认值
    admin_groups: ["soc-admins"]
    analyst_groups: ["soc"]
    default_role: viewer
```

### 组映射

组可以写短名（`soc-admins`），也可以写完整的 DN 或路径（`/部门/soc-admins`）。写短名时，任何位置的同名组都算匹配；目录或身份提供方里有多个同名组时，请写完整的 DN 或路径。

- **Keycloak**：默认不发组，需要在客户端的 Client scopes 中添加 `Group Membership` 映射，令牌声明名填 `groups`，并打开“添加到 ID 令牌”。“完整组路径”开或关都能识别。
- **OpenLDAP**：需要启用 `memberOf` 模块，否则用户条目上没有组属性。
- **Active Directory**：`memberOf` 只包含直接所属的组，嵌套组里的成员不会被识别。

账号通过认证但映射不到角色时，日志会记录收到的组。`收到的组: []` 表示身份提供方或目录没有发组，要检查上面的配置，而不是平台的 `admin_groups`。

### 边界

- **账号创建**：外部账号首次登录时自动创建，每次登录按组更新角色；角色降低时立即吊销已签发的会话。
- **账号名不区分大小写**：外部账号名统一为小写，`Alice` 和 `alice` 是同一个账号。
- **本地账号优先**：外部身份不能接管同名的本地账号（只差大小写的也一样），避免目录服务里的同名账号变成本地管理员。保留一个本地管理员，身份提供方故障时仍能登录。
- **默认角色**：不能设为管理员。
- **离职处理**：会话在 `server.session_ttl`（默认 12 小时）内继续有效。需要立即阻止时，在“系统管理”中删除该账号。
- **双因素认证**：外部账号的双因素认证由身份提供方负责，`server.require_2fa` 只约束本地账号。

## SIEM 转发

把告警转发到 Splunk、QRadar、ArcSight、Elastic、奇安信、安恒等平台。

```yaml
forward:
  - name: splunk
    address: siem.example.com:6514
    protocol: tls       # tls（默认）/ tcp / udp
    format: cef         # cef（默认）/ json / rfc5424
    min_level: medium   # 最低转发等级，默认 low
    ca_file: /app/configs/siem-ca.pem
```

- 转发不影响检测：每个目标有独立的队列（1 万条），目标不可用时自动重连，队列满时丢弃并计入 `netsa_forward_dropped_total`。
- 消息一行一条。日志内容由攻击者控制，所有格式都做了转义，换行和分隔符不能伪造出额外的日志。
- TCP 重连时可能重复发送一条消息，CEF 的消息编号和 JSON 的 `id` 可用于去重。
- CEF 字段：`src`、`request`、`requestMethod`、`requestClientApplication`、`cat`、`outcome`、`msg`，`cn1` 响应码、`cn2` 事件编号、`cs1` 攻击阶段、`cs2` 是否有证据证明成功、`cs3` 资产、`cs4` 漏洞。

## 联动封禁

分析员或剧本提交申请，管理员审批后生效，到期自动解除。

```yaml
block:
  enabled: true
  default_ttl: 24h
  max_ttl: 720h
  protect:              # 永不封禁的地址或网段：业务出口、合作方、监控
    - 203.0.113.0/24
  allow_self_approve: false   # 只有一位管理员时才打开
  webhook_url: ""             # 可选：生效和解除时推送
  webhook_token_env: NETSA_BLOCK_TOKEN
```

### 接入防火墙

**外部动态列表（推荐）**：防火墙定时拉取生效名单，FortiGate 的 External Block List、Palo Alto 的 External Dynamic List 等都支持。创建一个只读 API 令牌，地址填：

```
https://soc.example.com/api/block/edl
```

请求头 `Authorization: Bearer <令牌>`，响应是每行一个 IP 的纯文本。平台不需要防火墙的管理权限，封禁范围也完全由防火墙的策略决定。

**Webhook**：配置 `webhook_url` 后，生效和解除时推送 `{"action":"block|unblock","id":1,"ip":"…","reason":"…","expires":"…"}`，失败重试 3 次。适合接自动化平台，再由它调用防火墙接口。平台没有内置某个厂商防火墙的管理接口。

### 边界

- 内网和保留地址、`protect` 和 `detect.whitelist` 中的地址都不能封禁，审批时会重新检查。
- 只能封禁单个 IP，不能封禁网段。
- 申请人不能批准自己的申请，除非打开 `allow_self_approve`。
- 每条封禁都有有效期，到期后立刻从名单中移除。
- 申请、审批、解除、到期都写入审计链。

## 工单与处置剧本

事件满足条件时自动执行一次。剧本只做可逆、需要人继续跟进的动作：不会关闭事件，封禁也只是提交申请。

```yaml
tickets:
  - name: jira
    url: https://jira.example.com/rest/api/2/issue
    token_env: NETSA_JIRA_TOKEN      # 以 Authorization: Bearer 发送
    id_field: key                    # 响应中工单编号的字段，支持 a.b 路径
    body: |
      {"fields":{"project":{"key":"SEC"},"issuetype":{"name":"Task"},
       "summary":{{json .Title}},
       "description":{{json (printf "来源 %s，等级 %s，目标 %v" .Source .Severity .Targets)}}}}

playbooks:
  - name: WebShell 应急
    when:
      min_level: critical
      categories: ["WebShell后门"]
      proven: true                   # 只匹配有证据证明成功的事件
    assign: oncall                   # 指派负责人（已有负责人时不覆盖）
    status: investigating            # 只能是 investigating
    note: |
      1. 隔离目标主机
      2. 排查上传目录和近期新增的脚本
      3. 核对访问日志中的同源请求
    ticket: jira
    request_block: true              # 提交封禁申请（需要启用 block）
```

- 请求体模板是 Go text/template，可用字段：`ID`、`Title`、`Source`、`Location`、`Severity`、`Status`、`Categories`、`Targets`、`Assets`、`Created`、`Proven`。这些内容来自日志，字符串请用 `{{json .Title}}` 转义。
- 不填 `body` 时发送包含上述字段的 JSON。
- `when` 中未填写的条件不限制。事件等级后来升高时会重新判断，同一剧本对同一事件只执行一次，执行记录写在处置记录里，重启后不会重复执行。
- 工单创建失败时，原因写入处置记录，其他动作照常执行，不会反复重试。

## 在线情报

```yaml
intel:
  feeds:
    - name: 行业情报
      type: taxii      # stix / taxii / misp / text
      url: https://taxii.example.com/api/collections/abc/objects/
      token_env: NETSA_TAXII_TOKEN
      interval: 1h
      min_confidence: 70
    - name: MISP
      type: misp
      url: https://misp.example.com
      token_env: NETSA_MISP_KEY
```

- **支持的内容**：STIX 2.x 指标模式和 `ipv4-addr` / `ipv6-addr` 对象中的 IP；MISP 中 `to_ids` 的 `ip-src`、`ip-dst`；`text` 是每行一个 IP 或网段。域名和哈希类指标目前不使用。
- **防投毒**：内网和保留地址、短于 /8（IPv6 /32）的网段都丢弃，页面显示丢弃数量。一条错误的 `0.0.0.0/0` 不会把所有流量都标记为恶意。
- **可用性**：拉取失败时继续使用旧数据；结果缓存在状态目录，重启后立即可用。STIX 中已撤销、已过期的指标不生效。

## 规则运营

“系统管理 → 规则运营”可以添加、修改规则，保存前可以用样本试运行。保存后立即生效，不需要重启。

- 表达式是 RE2 正则，不支持回溯和环视，也因此不会出现正则回溯导致的性能问题。匹配的是解码、转小写后的文本。
- 托管规则不能使用内置规则的 ID。要覆盖内置规则，请在 `detect.rules_file` 的规则文件中设置，它是可以审查的配置。
- 规则保存时先构建新引擎，成功才切换，一条错误的规则不影响正在运行的检测。

### 导入 Sigma

上传 Sigma 规则文件（可以包含多条），先预览，确认后导入。只转换能准确表达的部分：

- **支持**：`logsource.category` 为 `webserver` 或 `proxy`；URI、路径、UA、Referer 字段；`contains`、`startswith`、`endswith`、`re` 修饰符，通配符；单个选择条件、`1 of selection*`、关键字列表；`cs-method`。
- **跳过并说明原因**：多个字段同时满足、`not` 排除条件、`contains|all`、环视正则、其他日志类型。悄悄去掉条件会让一条精确的规则变成误报来源，所以不做近似转换。
- `sc-status` 条件被忽略，响应结果由平台统一研判。

### 签名规则包

用于向多个部署统一分发规则。规则包用 ed25519 签名，只接受 `detect.rule_pack_keys` 中的公钥；序号必须递增，防止回滚；任何一条规则无效时整包都不生效。

```bash
netsa rulepack keygen -o pack.key           # 输出公钥，写入 detect.rule_pack_keys
```

```bash
netsa rulepack sign -key pack.key -in rules.yaml -name acme -serial 1 -o acme-1.json
```

在“规则运营 → 安装规则包”中上传 `acme-1.json`。规则包中的规则只能通过更新规则包修改。

## 尚未支持

高可用（双活或主备）、多租户、Kafka 输出、域名和哈希类情报、面向具体厂商防火墙的管理接口、授权管理。界面目前只有中文。
