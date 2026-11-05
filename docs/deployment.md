# 部署指南

[← 返回 README](../README.md)

镜像发布在华为云容器镜像服务（SWR），同时提供 amd64 与 arm64，服务器上无需安装 Go、无需编译：

| 镜像 | 用途 |
|---|---|
| `swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:latest` | netsa 主程序（默认）；也可使用版本号标签，如 `:1.7.10` |
| `swr.cn-east-3.myhuaweicloud.com/sreyun/pgvector:pg18` | 可选的告警归档数据库（PostgreSQL 18），只在启用归档时拉取 |

## 生产部署（Docker Compose）

```bash
git clone https://github.com/sreyun/netsa.git
cd netsa
cp .env.example .env        # 可选：固定版本、初始密码、端口、告警归档（说明见文件内注释）
docker compose pull
docker compose up -d
docker compose logs -f netsa
```

默认读取宿主机 `/var/log/nginx` 与 `/var/log` 下的 Web、防火墙与认证日志，并在 5514 端口（UDP / TCP）接收 syslog。

- **登录**：浏览器访问 `http://<服务器IP>:8080`。首次启动自动创建管理员 `admin`，初始密码输出在日志中（`docker compose logs netsa | grep 初始密码`），首次登录后须修改；也可在 `.env` 中用 `NETSA_ADMIN_PASSWORD` 指定。
- **接入日志**：网络设备的 syslog 发送到 `<服务器IP>:5514`；本机日志的路径在 [configs/docker.yaml](../configs/docker.yaml) 的 `sources` 中配置，详见[日志接入](log-sources.md)。
- **修改配置**：编辑 [configs/docker.yaml](../configs/docker.yaml) 后执行 `docker compose restart netsa`（配置以只读方式挂载）。
- **只需要两个文件**：不想克隆整个仓库时，把 `docker-compose.yml` 与 `configs/docker.yaml` 按原有相对路径放到同一目录即可。配置文件必须存在，否则 Docker 会创建同名空目录，容器无法启动。
- **数据持久化**：态势数据、账号、学习状态、原始日志与审计链保存在数据卷 `netsa-state`（容器内 `/app/state`），重建或升级容器后自动恢复。
- **健康检查**：`GET /healthz`（无需认证），compose 已配置容器健康检查。

### `.env` 变量

均为可选，未设置时使用 `docker-compose.yml` 中的默认值：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `NETSA_IMAGE` | `…/sreyun/netsa:latest` | netsa 镜像；生产环境建议固定版本号，内网可改为私有仓库地址 |
| `PG_IMAGE` | `…/sreyun/pgvector:pg18` | 告警归档数据库镜像 |
| `NETSA_HTTP_PORT` | `8080` | 宿主机上的 Web 端口（容器内固定 8080） |
| `NETSA_SYSLOG_PORT` | `5514` | 宿主机上的 syslog 端口，UDP 与 TCP 同时映射 |
| `NETSA_ADMIN_PASSWORD` | 随机生成 | 首次启动时管理员 `admin` 的初始密码 |
| `POSTGRES_PASSWORD` | — | 自带 PostgreSQL 的密码（启用归档时必填） |
| `NETSA_ARCHIVE_DSN` | — | 告警归档连接串，设置后启用归档 |
| `NETSA_SMTP_PASSWORD` | — | 周报 / 月报发信口令 |

外部大模型的地址、名称与密钥在页面“自学习 → 外部模型”中配置，无需写入 `.env`。

### 常见问题

- **端口被占用**：启动时报 `Bind for 0.0.0.0:8080 failed: port is already allocated`，说明宿主机上已有程序（例如同机运行的[演示环境](#演示环境)）占用了该端口。在 `.env` 中设置 `NETSA_HTTP_PORT=8081`（syslog 端口冲突时设置 `NETSA_SYSLOG_PORT`），重新执行 `docker compose up -d`。
- **读不到 nginx 日志**：容器以非 root 用户（uid 10001）运行，并加入 `adm` 组（gid 4）读取日志；宿主机权限不同时调整 `group_add` 或日志文件权限。日志必须**以目录方式挂载**——logrotate 轮转会创建新文件，单文件挂载会一直指向旧文件。
- **多台设备共用 syslog 端口**：需要按设备真实地址区分发送端时，可把服务改为 `network_mode: host`，避免端口映射环节改写源地址。
- **Windows 上试用**：Windows PowerShell 5.1 不支持 `&&`，请逐行执行命令；`cp` 改用 `Copy-Item .env.example .env`，查看初始密码用 `docker compose logs netsa | Select-String 初始密码`。Docker Desktop 中没有 `/var/log/nginx`，可通过 syslog 发送日志，或直接使用[演示环境](#演示环境)。
- **长期留存告警**：按[告警归档](operations.md#告警归档可选postgresql)在 `.env` 中设置数据库密码后执行 `docker compose --profile archive up -d`。

## 升级与回滚

```bash
# 升级前备份数据卷（数据卷名为「项目名_卷名」，即 netsa_netsa-state）
docker run --rm --user 0 --entrypoint tar -v netsa_netsa-state:/state -v "$PWD":/backup \
  swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:latest czf /backup/netsa-state-$(date +%Y%m%d).tgz -C /state .

# 使用 latest 时直接拉取最新版本；固定版本时先修改 .env 中 NETSA_IMAGE 的版本号
docker compose pull
docker compose up -d
```

- `docker compose up -d` 不会更新本地已有的 `latest`，升级时需要先执行 `docker compose pull`。
- 回滚时把 `NETSA_IMAGE` 改回旧版本号。新版本写入的状态快照旧版本可能拒绝读取（会改名保留，不会被覆盖），因此先停止服务、用升级前的备份覆盖数据卷，再启动：

  ```bash
  docker compose down
  docker run --rm --user 0 --entrypoint tar -v netsa_netsa-state:/state -v "$PWD":/backup \
    swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:latest xzf /backup/netsa-state-20261102.tgz -C /state
  docker compose up -d
  ```

## 内网 / 离线部署

服务器不能访问 SWR 时，在能联网的机器上导出镜像，拷贝到服务器后导入：

```bash
# 联网机器：按服务器架构拉取（arm64 服务器用 --platform linux/arm64），不启用归档可不拉取 pgvector
docker pull --platform linux/amd64 swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:1.7.10
docker pull --platform linux/amd64 swr.cn-east-3.myhuaweicloud.com/sreyun/pgvector:pg18
docker save -o netsa-images.tar swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:1.7.10 \
  swr.cn-east-3.myhuaweicloud.com/sreyun/pgvector:pg18

# 服务器：导入后直接启动（不要执行 docker compose pull），.env 中写入相同的镜像标签
docker load -i netsa-images.tar
echo 'NETSA_IMAGE=swr.cn-east-3.myhuaweicloud.com/sreyun/netsa:1.7.10' >> .env
docker compose up -d
```

- 也可以把镜像推送到内网私有仓库，再把 `NETSA_IMAGE` / `PG_IMAGE` 改为私有仓库地址。
- 隔离网络中请在 [configs/docker.yaml](../configs/docker.yaml) 中关闭在线溯源 `geo.online.enabled: false`，由内置的 ip2region 与区划地名库提供离线定位。

## 备份与恢复

状态目录里有事件与处置记录、账号、学习结果、审计链和页面上的配置。备份里有密码哈希和模型密钥，请限制访问。

```bash
docker compose exec netsa /app/netsa backup -c /app/configs/docker.yaml -o /app/state/backups/manual.tar.gz
```

- 可以在服务运行时备份。默认不包含原始日志，需要时加 `-rawlog`。
- 定时备份：配置 `storage.backup_dir`、`backup_interval`（默认 24h）、`backup_keep`（默认保留 7 个）。
- 管理员也可以在“系统管理 → 对接状态”中下载备份，下载行为写入审计。

恢复前先停止服务，否则退出时的快照会覆盖恢复的内容：

```bash
docker compose stop netsa
```

```bash
docker compose run --rm netsa restore -c /app/configs/docker.yaml -i /app/state/backups/manual.tar.gz -force
```

```bash
docker compose start netsa
```

恢复前会校验备份中每个文件的 SHA-256，校验不通过时不会改动任何文件。请定期演练恢复，并使用相同或更高版本的程序读取备份。

## 数据可靠性

- **处置记录**：分析员和模型对事件的每次修改都先写入预写日志并落盘，进程异常退出（断电、`kill -9`、内存不足）后重放，不会丢失。
- **其他状态**：快照默认每分钟保存一次（`storage.interval`），异常退出时最多丢失这段时间内新产生的告警和统计。需要长期留存和更高可靠性时启用 PostgreSQL 告警归档和原始日志留存。
- **高可用**：目前是单实例部署，没有主备切换。

## 容器加固

`docker-compose.yml` 默认去掉全部 Linux 能力、禁止提权、根文件系统只读，只有状态卷和 `/tmp` 可写，并限制内存（`NETSA_MEM_LIMIT`，默认 4g；`NETSA_GOMEMLIMIT` 默认 3400MiB，请设为前者的 85% 左右）和进程数。达到 `storage.max_ips` 上限（默认 20 万）后，存活堆约 1.5 GB，峰值约为其两倍。新增挂载目录时使用卷，不要去掉 `read_only`。

启动日志中的 `[security]` 提示列出了需要在生产环境处理的项目：配置 HTTPS（或放在 HTTPS 反向代理之后）、开启 syslog 发送端白名单。

## 演示环境

```bash
# 模拟器持续生成攻击日志，netsa 实时分析，浏览器打开 http://localhost:8080（账号 admin / Netsa@demo2026）
docker compose -f docker-compose.demo.yml up -d --build
# 停止并清除演示数据
docker compose -f docker-compose.demo.yml down -v
```

演示环境从源码构建镜像（默认使用 `goproxy.cn` 下载 Go 依赖），账号见 [configs/demo.yaml](../configs/demo.yaml)。

## 从源码构建镜像

```bash
# 海外网络加 --build-arg GOPROXY=https://proxy.golang.org,direct；
# 基础镜像拉取慢时加 --build-arg BASE_REGISTRY=docker.m.daocloud.io
docker build -t netsa:dev .
```

在 `.env` 中写入 `NETSA_IMAGE=netsa:dev` 后执行 `docker compose up -d`。

## 不用 Docker 运行

```bash
# 编译（需要 Go 1.25+；纯 Go 实现，无 CGO）
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
./bin/netsa analyze -online -listen :8080 access.log      # 启用在线溯源，分析后打开大屏
./bin/netsa analyze -format '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $host' access.log
```

交叉编译 Linux 版本：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/netsa-linux-amd64 ./cmd/netsa
```
