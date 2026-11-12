# 开发与发布

[← 返回 README](../README.md)

本地开发、测试、代码结构，以及镜像构建与发布流程。

## 开发与测试

提交前按 CI 的顺序在本地检查：

```bash
gofmt -l internal cmd          # 必须没有输出
go vet ./...
go test ./...                  # 完整规模，约 1 分钟
go test -race -short ./...     # 需要 CGO 与 C 编译器（gcc）
```

- `-race` 依赖 CGO。本机没有 gcc 时（例如 Windows），可以在容器里执行：

  ```bash
  docker run --rm -v "$PWD":/src -w /src -e GOPROXY=https://goproxy.cn,direct golang:1.27-alpine \
    sh -c 'apk add --no-cache gcc musl-dev && CGO_ENABLED=1 go test -race -short ./...'
  ```

- 依赖与标准库的已知漏洞（CI 同样执行，发现代码可达的漏洞即失败）：

  ```bash
  go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
  ```

- 改动规则或定级后跑一遍评测（`go test ./internal/eval` 已包含在测试中，门槛不达标时 CI 失败）：

  ```bash
  go run ./cmd/netsa eval -v
  ```

  样本在 `internal/eval/corpus/web.tsv`，每条标注“正常 / 攻击”和期望等级。内置样本是手工构造的回归基线，不代表真实流量的准确率。新增样本时先运行一次、记下结果再调整规则，否则样本就失去了验证作用。

- 用现场日志做回归：`netsa corpus` 从真实的 Web 日志中按请求形态挑选样本（攻击按规则与形态、正常请求按形态各保留几条），脱敏后写成同样格式的语料，标注与期望等级取当前版本的检测结果：

  ```bash
  netsa corpus -o real.tsv -hide example.org,43.242.97.0/24 /var/log/nginx/access.log*
  netsa eval -corpus real.tsv -v      # 之后每个版本跑一遍，不符合期望的样本就是这次改动带来的变化
  ```

  脱敏只替换不影响攻击写法的内容：内网地址映射到 10.250.0.0/16（同一地址始终映射到同一个），`-hide` 指定的域名换成 example.com、网段内的地址换成 198.51.100.0/24，口令与令牌类参数（值本身是攻击载荷时保留）、邮箱、手机号、身份证号、JWT 替换；回环、云元数据地址与其他公网地址保留。标注不是人工结论，作为准确率依据前请复核第一列。语料文件仍是现场数据，权限为 0600，不要提交到代码仓库。

- 满规模测量（默认跳过，约 3 分钟）：建立指定数量的攻击源画像，测量完整 / 增量快照的保存与恢复、各查询的耗时、与每种查询或保存单独并发时日志入库每批的最长耗时，以及全部并发时入库等待写锁的时间。改动状态库的锁、快照或查询后跑一遍，对比前后的数字：

  ```bash
  NETSA_SCALE=200000 go test -run TestScale -v -timeout 20m ./internal/store
  ```

- 前端回归（登录、事件处置、封禁审批、规则运营，以及所有页面渲染攻击者控制的内容时不产生 XSS）用 Playwright，CI 同样执行：

  ```bash
  cd test/e2e && npm ci && npx playwright install chromium && npx playwright test
  ```

  测试实例的状态保存在 `test/e2e/.e2e-state`，重复运行前先删除它，否则上一次留下的事件会影响断言。下载不了 Playwright 自带的浏览器时，可以用 `NETSA_E2E_CHROME` 指定本机的 Chrome，用 `NETSA_E2E_BIN` 指定已编译的程序（Windows 上请写绝对路径）。

- 权限矩阵：`internal/api/authz_matrix_test.go` 列出了每条路由需要的角色。新增路由时这个测试会失败，请确认谁应该能访问后再加进去。

- 测试用例中的中文名称请写成结构体字段（`[]struct{ name string; … }`），不要用作 map 的键：gofmt 按字符数对齐 map 的值，编辑器里看起来错位，手工对齐后 `gofmt -l` 就会失败。
- 前端为原生 JavaScript，CI 只做语法检查：`for f in web/static/*.js; do node --check "$f"; done`。

### 状态库的锁

状态库（`internal/store`）用一把读写锁保护全部内存状态，没有按画像、告警、事件、攻击面分成多把锁：一条日志入库时要同时更新画像、分钟桶、汇总、事件、资产链路与攻击面，它们之间有一致性约束（例如事件的等级来自告警，排行来自画像），拆成多把锁就要规定加锁顺序、处理跨域的中间状态，快照也不再是同一时刻的。实测的争用来自单次持锁过长，而不是锁的数量，因此做法是缩短每次持锁：

- 入库每 32 条事件持一次写锁（`recordChunk`），段间查询可以插入；
- 扫描全部画像的查询先复制画像数组（`profileList`），再每 1024 个持一次读锁；事件搜索分批筛选、排序在锁外；
- 快照分段编码，画像每 64 个持一次读锁；完整快照每 15 分钟一次，其余时候只写改动过的画像（`delta.go`）。

新增的查询如果要遍历全部画像或事件，请沿用分批的写法，并用满规模测量确认入库等待没有变长。改动画像的新路径要调用 `markDirty`，否则这个改动只在下一次完整快照时保存（`TestDeltaSnapshot*` 覆盖了现有的路径）。

## 代码结构

```
cmd/netsa/            命令行入口（serve / analyze / simulate / rules / passwd / hash-password / version）
internal/parser/      日志解析与格式自动识别（nginx、log_format 编译、各类防火墙、IDS、认证、DNS、syslog 头）
internal/detect/      URL 归一化、特征规则、libinjection 语法分析、国产 OA 漏洞接口签名、结果研判、行为检测
internal/risk/        威胁等级统一裁决（攻击分类底线、拦截与成功的等级上限）
internal/pipeline/    处理流水线、真实 IP 还原（含反向代理自动识别）、DNAT 暴露面过滤、资产关联
internal/exposure/    对外发布服务清单、会话证据研判（是否到达服务）、候选映射与可疑放行策略
internal/geo/         多源定位融合、ip2region / MaxMind / ip-api、区划地名库、内网网段、RDAP
internal/intel/       本地黑名单、Tor 出口、rDNS 测绘机构识别
internal/store/       攻击者画像与评分、告警、安全事件、时间序列、地图聚合、攻击面、安全评估、快照
internal/ingest/      文件跟踪、批量读取、syslog 接收（UDP / TCP / TLS）、发送端管理
internal/rawlog/      原始日志留存（按小时压缩、哈希链防篡改、检索与导出）
internal/suppress/    误报抑制规则
internal/assets/      资产台账与漏洞导入、攻击与漏洞关联
internal/learn/       自学习：研判反馈校准（规则级 / 目标级）、攻击行为、参数正常取值、站点产品、业务接口、模型一致率评估、平台账号行为基线、持续合规自检
internal/ai/          可选的外部大模型研判（Web 页面配置、OpenAI 兼容接口、发送前脱敏、调用限额）
internal/api/         REST API、SSE、封禁列表导出、报表与等保合规、安全响应头
internal/auth/        登录账号、PBKDF2 密码哈希、签名会话、双因素认证、API 令牌、登录失败锁定
internal/audit/       防篡改审计链（哈希链、校验与导出）
internal/archive/     可选的 PostgreSQL 告警归档（异步 COPY 批量写入、按月分区、历史查询）
internal/alert/       钉钉 / 企业微信 / 飞书 / Webhook 告警推送（多选等级、合并、限速、加签）
internal/mailer/      SMTP 发信（周报、月报、合规报告）
internal/qr/          二维码生成（绑定身份验证器）
internal/demo/        演示日志生成器（simulate 命令）
internal/eval/        带标注样本的检出率与误报评测（eval 命令）
internal/backup/      状态目录的备份与恢复
internal/sso/         LDAP 与 OpenID Connect 登录
internal/forward/     SIEM 转发（CEF / JSON / RFC 5424）
internal/block/       联动封禁（申请、审批、到期解除）
tools/vulnpaths/      从 nuclei-templates 生成国产 OA、中间件漏洞接口签名（见检测说明）
internal/playbook/    处置剧本与工单对接
internal/rulemgr/     页面维护的规则、签名规则包、Sigma 转换
internal/config/      配置加载、默认值与校验
internal/model/       流水线公共数据结构
internal/safe/        异常保护（单条畸形数据不影响服务）
web/static/           前端大屏（ECharts、世界地图、中国省级/地市级地图已内置，可离线使用）
data/                 离线定位库（ip2region；MaxMind 可放入此目录）
configs/              config.yaml（本机）、docker.yaml（容器）、demo.yaml（演示）、规则示例
docs/                 使用与开发文档（images/ 为 README 截图，i18n/ 为多语言 README）
```

## 镜像构建与发布（华为云 SWR）

创建 tag 后，[.github/workflows/docker.yml](../.github/workflows/docker.yml) 自动构建多架构镜像并推送到华为云容器镜像服务（SWR）；登录凭证由 AK/SK 现场推导，无需在控制台生成长期登录密文。

| 触发 | 行为 |
|---|---|
| 创建 tag `v1.14.0` | 构建 + 启动自检 + 推送：`1.14.0`、`1.14`、`1`、`latest`、`sha-xxxxxxx` |
| 创建预发布 tag `v1.14.0-rc1` | 只推 `1.14.0-rc1`、`sha-xxxxxxx`，不动 `latest` / `1.14` / `1` |
| 推送 `master` / Pull Request | 不构建镜像（质量门禁由 `ci` 工作流负责） |
| 手动触发（workflow_dispatch） | 填写要发布的 tag 与是否更新 `latest`；按该 tag 检出源码，版本与内容严格对应 |

发布流程：

```bash
git tag v1.14.0
git push origin v1.14.0
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
docker pull swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:1.14.0
docker run -d --name netsa -p 8080:8080 -p 5514:5514/udp -v netsa-state:/app/state \
  swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:1.14.0
```

- **版本随 tag 注入**：构建时通过 `-ldflags "-X main.version=<tag>"` 写入二进制，`netsa version` 与 `/api/meta` 显示的就是发布版本；本地 `docker build` 不传该参数，仍使用源码中的默认版本。
- **推送前自检**：先用 amd64 构建并实际运行 `netsa rules` / `netsa version`，确认二进制可执行、规则可加载、版本与 tag 一致后才推送多架构镜像。
- **SWR 介质类型**：使用 `outputs: type=registry,oci-mediatypes=false` 并关闭 provenance / SBOM 附件，避免仓库里出现 `unknown/unknown` 架构条目导致拉取时选错架构。
- 镜像以非 root（uid 10001）运行，配置内置在 `/app/configs`，状态目录为 `/app/state`（建议挂载数据卷）。

质量门禁由 [.github/workflows/ci.yml](../.github/workflows/ci.yml) 负责：`gofmt`、`go vet`、前端语法检查，以及两轮测试——`go test -race -short ./...` 验证并发正确性（race 检测会让用例慢 5~10 倍，故走降级规模），`go test ./...` 以完整规模验证性能退化类断言，最后用 `govulncheck` 检查依赖与标准库中代码可达的已知漏洞。任何一步失败，后面的步骤都会被跳过，提交前请先在本地执行[开发与测试](#开发与测试)中的检查。
