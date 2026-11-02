// @ts-check
const { defineConfig } = require('@playwright/test');

const port = process.env.NETSA_E2E_PORT || '18099';

module.exports = defineConfig({
  testDir: '.',
  timeout: 60_000,
  workers: 1, // 用例按顺序操作同一个实例
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    screenshot: 'only-on-failure',
    // 没有 Playwright 自带的浏览器时（如内网环境）可以指定系统里的 Chromium
    launchOptions: process.env.NETSA_E2E_CHROME ? { executablePath: process.env.NETSA_E2E_CHROME, args: ['--no-sandbox'] } : {},
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  webServer: {
    command: process.env.NETSA_E2E_BIN
      ? `${process.env.NETSA_E2E_BIN} serve -c e2e.yaml -web ${process.env.NETSA_E2E_WEB || '../../web/static'}`
      : 'go run ../../cmd/netsa serve -c e2e.yaml -web ../../web/static',
    url: `http://127.0.0.1:${port}/healthz`,
    timeout: 180_000,
    reuseExistingServer: false,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
