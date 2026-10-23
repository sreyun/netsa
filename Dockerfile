# syntax=docker/dockerfile:1

# ---------- 构建阶段 ----------
FROM golang:1.23-alpine AS build
# 国内网络可通过 --build-arg GOPROXY=https://goproxy.cn,direct 加速
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN go build -trimpath -ldflags "-s -w" -o /out/netsa ./cmd/netsa

# ---------- 运行阶段 ----------
FROM alpine:3.20
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
