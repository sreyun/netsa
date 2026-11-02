# 安全策略

## 报告漏洞

请不要在公开 Issue 中披露安全漏洞。通过 GitHub 的 [Private vulnerability reporting](https://github.com/sreyun/netsa/security/advisories/new) 私下提交，并尽量包含：

- 受影响的版本（`netsa version`）与部署方式；
- 复现步骤或概念验证；
- 可能造成的影响。

## 支持范围

只为最新发布的版本提供安全修复，请尽量升级到最新版本。

## 部署建议

- 通过 HTTPS 访问管理页面（`server.tls_cert` 或反向代理），不要把管理端口直接暴露到公网。
- 保持登录认证开启，为管理员启用双因素认证。
- 开启 syslog 发送端白名单；对完整性要求高的设备使用 TLS 发送日志。
- 连接公网模型服务时保持发送前脱敏开启。

详见[部署指南](../docs/deployment.md)与[安全运营](../docs/operations.md)。
