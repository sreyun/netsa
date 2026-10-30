# 不使用外部 frontend 镜像：内网 / 镜像仓库受限环境下无需额外拉取 dockerfile 镜像

# 基础镜像仓库可在构建时替换（国内可用镜像站加速），例如
#   --build-arg BASE_REGISTRY=docker.m.daocloud.io
ARG BASE_REGISTRY=docker.io

# ---------- 构建阶段 ----------
# Go 工具链须使用仍在维护期内的版本：标准库（net/http、crypto/tls、crypto/x509 等）的安全修复只进入受支持的版本，
# 用已停止维护的版本编译，二进制会带上已公开的漏洞（可用 govulncheck ./... 检查）
FROM ${BASE_REGISTRY}/library/golang:1.27-alpine AS build
# 默认使用国内代理；海外环境可 --build-arg GOPROXY=https://proxy.golang.org,direct 覆盖
ARG GOPROXY=https://goproxy.cn,direct
# 版本号由 CI 传入（tag 名，去掉前缀 v）；不传时使用源码中的默认值
ARG VERSION=""
ENV GOPROXY=${GOPROXY} CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
# 只在传了 VERSION 时注入，保证本地 / compose 构建的行为与之前一致
RUN ver="${VERSION#v}" && \
    go build -trimpath -ldflags "-s -w ${ver:+-X main.version=${ver}}" -o /out/netsa ./cmd/netsa

# ---------- 运行阶段 ----------
# 运行镜像同样使用仍在维护期内的 Alpine 版本（3.20 已于 2026-04 停止维护，不再提供安全更新）
FROM ${BASE_REGISTRY}/library/alpine:3.23
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 netsa \
 && adduser -S -D -H -u 10001 -G netsa netsa \
 && mkdir -p /app/state /app/demo-logs /logs \
 && chown netsa:netsa /app/state /app/demo-logs
WORKDIR /app
COPY --from=build /out/netsa /app/netsa
COPY configs /app/configs
# 离线定位库（ip2region），MaxMind 库可在运行时挂载到 /app/data
COPY data/ip2region_v4.xdb data/ip2region_v6.xdb /app/data/
ENV TZ=Asia/Shanghai
USER netsa
# 8080: Web 大屏 / API；5514: syslog 接收（UDP + TCP）
EXPOSE 8080 5514/udp 5514/tcp
VOLUME ["/app/state"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/app/netsa"]
CMD ["serve", "-c", "/app/configs/docker.yaml"]
