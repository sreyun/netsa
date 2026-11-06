#!/usr/bin/env bash
# 把 go test 日志中的失败原因写成 GitHub Actions 注解：失败用例、断言所在行、panic 与第一个数据竞争报告。
# 注解在运行页面与 API 中不登录也能看到，排查 CI 失败不必下载完整日志。
# 用法：annotate-test-log.sh <日志文件> <标题>
set -u
log="$1"
title="${2:-go test}"
grep -E -- '--- FAIL|^FAIL[[:space:]]|panic:|_test\.go:[0-9]+:' "$log" | head -8 | while IFS= read -r line; do
  printf '::error title=%s::%s\n' "$title" "$(printf '%s' "$line" | sed 's/%/%25/g')"
done
race=$(awk '/WARNING: DATA RACE/{f=1} f{print; if (++n >= 60) exit}' "$log")
if [ -n "$race" ]; then
  body=$(printf '%s\n' "$race" | sed 's/%/%25/g' | awk 'BEGIN{ORS="%0A"} {print}')
  printf '::error title=%s 数据竞争::%s\n' "$title" "$body"
fi
