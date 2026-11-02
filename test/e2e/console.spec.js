// @ts-check
const { test, expect } = require('@playwright/test');
const net = require('net');

const ADMIN = { username: 'admin', password: 'E2e-admin-pass-1' };
const SYSLOG = { host: '127.0.0.1', port: 15599 };

// 日志内容由攻击者控制，页面把它们当作纯文本显示。载荷覆盖 HTML 标签、属性、URL 和模板的常见逃逸方式。
const MARK = 'netsaxss';
const PAYLOADS = [
  `/s?q=<img src=x onerror="window.${MARK}=1">`,
  `/s?q="><svg onload=window.${MARK}=1>`,
  `/s?q='><script>window.${MARK}=1</script>`,
  `/a"onmouseover="window.${MARK}=1".php?cmd=id`,
  `/x?u=javascript:window.${MARK}=1`,
  `/<details open ontoggle=window.${MARK}=1>`,
  '/${alert(1)}`-alert(1)-`',
];

function sendLogs(lines) {
  return new Promise((resolve, reject) => {
    const c = net.connect(SYSLOG, () => {
      c.end(lines.join('\n') + '\n', resolve);
    });
    c.on('error', reject);
  });
}

function logLine(ip, method, path, status, bytes, ua, host) {
  const now = new Date();
  const mon = now.toLocaleString('en-US', { month: 'short' });
  const body = JSON.stringify({
    time_iso8601: now.toISOString(), remote_addr: ip, request: `${method} ${path} HTTP/1.1`, status, body_bytes_sent: bytes,
    http_user_agent: ua, host, http_referer: path,
  });
  const clock = now.toTimeString().slice(0, 8);
  return `<190>${mon} ${String(now.getDate()).padStart(2, ' ')} ${clock} web nginx: ${body}`;
}

async function login(page, user = ADMIN) {
  await page.goto('/login.html');
  await page.fill('#username', user.username);
  await page.fill('#password', user.password);
  await page.click('#loginBtn');
  await page.waitForURL((u) => !u.pathname.includes('login'));
  await expect(page.locator('#tabs')).toBeVisible();
}

// 收集页面里所有说明发生了注入的迹象。CSP 会阻止内联脚本执行，所以不能只看脚本有没有运行，
// 还要看攻击者的标签或事件属性有没有进入 DOM、有没有触发 CSP 违规。
async function watch(page) {
  const issues = [];
  page.on('dialog', (d) => { issues.push(`弹窗: ${d.message()}`); d.dismiss().catch(() => {}); });
  page.on('pageerror', (e) => issues.push(`脚本错误: ${e.message}`));
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  return issues;
}

async function checkNoInjection(page, where, issues) {
  const r = await page.evaluate((mark) => ({
    ran: Boolean(window[mark]),
    csp: window.__csp || [],
    handlers: [...document.querySelectorAll('*')].filter((el) => [...el.attributes].some((a) => /^on/i.test(a.name) && a.value.includes(mark))).map((el) => el.outerHTML.slice(0, 120)),
    images: [...document.querySelectorAll('img[src="x"], script:not([src])')].map((el) => el.outerHTML.slice(0, 120)),
    links: [...document.querySelectorAll('a[href^="javascript:"]')].map((el) => el.outerHTML.slice(0, 120)),
  }), MARK);
  expect.soft(r.ran, `${where}: 载荷被执行`).toBe(false);
  expect.soft(r.handlers, `${where}: 事件属性进入 DOM`).toEqual([]);
  expect.soft(r.images, `${where}: 攻击者的标签进入 DOM`).toEqual([]);
  expect.soft(r.links, `${where}: javascript: 链接进入 DOM`).toEqual([]);
  expect.soft(r.csp, `${where}: CSP 违规`).toEqual([]);
  expect.soft(issues, `${where}: 页面错误`).toEqual([]);
}

const TABS = ['overview', 'attackers', 'alerts', 'rawlog', 'surface', 'incidents', 'assess', 'assets', 'reports', 'learn', 'notify', 'system', 'sources'];

async function openTab(page, tab) {
  await page.evaluate((t) => { location.hash = `#tab=${t}`; }, tab);
  await page.waitForTimeout(700);
}

test.describe.configure({ mode: 'serial' });

test('登录失败有提示，未登录不能访问接口', async ({ page, request }) => {
  const rec = await request.get('/api/overview');
  expect(rec.status()).toBe(401);
  await page.goto('/');
  await page.waitForURL(/login/);
  await page.fill('#username', 'admin');
  await page.fill('#password', 'wrong-password');
  await page.click('#loginBtn');
  await expect(page.locator('#loginMsg')).not.toBeEmpty();
  await expect(page).toHaveURL(/login/);
});

test('安全响应头', async ({ request }) => {
  const r = await request.get('/login.html');
  const h = r.headers();
  expect(h['content-security-policy']).toContain("script-src 'self'");
  expect(h['x-frame-options']).toBe('DENY');
  expect(h['x-content-type-options']).toBe('nosniff');
});

test('写入攻击日志后，定级符合证据', async ({ page }) => {
  await login(page);
  const ua = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0';
  const seed = [];
  for (let i = 1; i <= 20; i++) {
    seed.push(logLine(`198.51.100.${i}`, 'GET', '/', 200, 5120, ua, 'app.test'));
    seed.push(logLine(`198.51.100.${i}`, 'GET', '/item', 200, 3000, ua, 'app.test'));
  }
  await sendLogs(seed);
  await page.waitForTimeout(1500);
  const lines = PAYLOADS.map((p, i) => logLine(`203.0.113.${i + 10}`, 'GET', p, 200, 1000 + i, `<img src=x onerror="window.${MARK}=1">`, 'app.test'));
  lines.push(logLine('203.0.113.50', 'GET', '/item?id=1+union+select+1,2,3--', 200, 3000, ua, 'app.test')); // 与接口基线一致
  lines.push(logLine('203.0.113.51', 'GET', '/item?id=1+union+select+user(),2', 200, 30000, ua, 'app.test')); // 明显大于基线
  await sendLogs(lines);
  await expect.poll(async () => {
    const r = await page.request.get('/api/incidents?status=active&q=203.0.113.51');
    return (await r.json()).incidents?.[0]?.severity;
  }, { timeout: 15_000 }).toBe('critical');
  const same = await (await page.request.get('/api/incidents?status=active&q=203.0.113.50')).json();
  expect(same.incidents[0].severity).toBe('high');
});

test('所有页面渲染攻击者控制的内容都不会产生注入', async ({ page }) => {
  const issues = await watch(page);
  await login(page);
  for (const tab of TABS) {
    await openTab(page, tab);
    await checkNoInjection(page, tab, issues);
  }
  // 确认载荷确实显示在页面上（作为文字）：否则上面的检查没有意义
  await openTab(page, 'alerts');
  await expect(page.locator('#tab-alerts')).toContainText('onerror');
  // 事件详情、告警详情和攻击源详情
  const list = await (await page.request.get('/api/incidents?status=active&limit=20')).json();
  const xss = list.incidents.filter((i) => i.key.startsWith('203.0.113.1'));
  expect(xss.length).toBeGreaterThan(0);
  for (const i of xss.slice(0, 7)) {
    await page.evaluate((id) => { location.hash = `#tab=incidents&incident=${id}`; }, i.id);
    await page.waitForSelector('#incModal:not([hidden])');
    await page.waitForTimeout(300);
    await checkNoInjection(page, `事件 #${i.id}`, issues);
    await page.keyboard.press('Escape');
    await page.evaluate(() => { location.hash = '#tab=overview'; });
    await page.waitForTimeout(200);
    await page.evaluate((ip) => { location.hash = `#ip=${ip}`; }, i.key);
    await page.waitForTimeout(600);
    await checkNoInjection(page, `攻击源 ${i.key}`, issues);
    await page.keyboard.press('Escape');
  }
});

test('处置事件：写入记录、状态变化，刷新后保留', async ({ page }) => {
  await login(page);
  const list = await (await page.request.get('/api/incidents?status=active&q=203.0.113.50')).json();
  const id = list.incidents[0].id;
  const rec = await page.request.post(`/api/incidents/${id}`, { data: { status: 'false_positive', note: 'E2E：确认是授权扫描' } });
  expect(rec.ok()).toBeTruthy();
  await page.evaluate((i) => { location.hash = `#tab=incidents&incident=${i}`; }, id);
  await expect(page.locator('#incBody')).toContainText('E2E：确认是授权扫描');
  await page.reload();
  await expect(page.locator('#incBody')).toContainText('E2E：确认是授权扫描');
});

test('封禁：申请、审批、下发名单、解除', async ({ page }) => {
  await login(page);
  const bad = await page.request.post('/api/block', { data: { ip: '10.1.2.3', reason: 'x' } });
  expect(bad.status()).toBe(400);
  const rec = await page.request.post('/api/block', { data: { ip: '203.0.113.51', reason: 'E2E 封禁 <b>原因</b>', ttl_hours: 1 } });
  expect(rec.ok()).toBeTruthy();
  const { id } = await rec.json();
  await openTab(page, 'incidents');
  await expect(page.locator('#blockPanel')).toBeVisible();
  // 原因按纯文本显示
  await expect(page.locator('#blockTable')).toContainText('<b>原因</b>');
  await expect(page.locator('#blockTable b')).toHaveCount(0);
  expect(await (await page.request.get('/api/block/edl')).text()).toBe('\n');
  await page.locator(`[data-bk="approve"][data-id="${id}"]`).click();
  await expect(page.locator(`[data-bk="release"][data-id="${id}"]`)).toBeVisible();
  expect(await (await page.request.get('/api/block/edl')).text()).toBe('203.0.113.51\n');
  page.once('dialog', (d) => d.accept('E2E 解除'));
  await page.locator(`[data-bk="release"][data-id="${id}"]`).click();
  await expect(page.locator(`[data-bk="release"][data-id="${id}"]`)).toHaveCount(0);
  expect(await (await page.request.get('/api/block/edl')).text()).toBe('\n');
});

test('规则运营：添加规则后立即命中', async ({ page }) => {
  await login(page);
  await openTab(page, 'system');
  await expect(page.locator('#ruleTable')).toContainText('还没有自定义规则');
  const answers = ['e2e-rule', 'E2E 规则', 'e2e-unique-marker', 'uri', 'medium', '', ''];
  const onDialog = (d) => d.accept(answers.shift() ?? '');
  page.on('dialog', onDialog);
  await page.click('#ruleAdd');
  await expect(page.locator('#ruleTable')).toContainText('e2e-rule');
  page.off('dialog', onDialog);
  await sendLogs([logLine('203.0.113.60', 'GET', '/e2e-unique-marker', 404, 100, 'Mozilla/5.0', 'app.test')]);
  await expect.poll(async () => {
    const r = await page.request.get('/api/incidents?status=active&q=203.0.113.60');
    const list = (await r.json()).incidents || [];
    if (!list.length) return '';
    const d = await page.request.get(`/api/incidents/${list[0].id}`);
    return JSON.stringify((await d.json()).rules);
  }, { timeout: 15_000 }).toContain('e2e-rule');
  const del = await page.request.delete('/api/rules/managed/e2e-rule');
  expect(del.ok()).toBeTruthy();
  await expect(page.locator('#intTable')).toContainText('定时备份');
});

test('只读账号看不到管理功能，也不能调用', async ({ page, browser }) => {
  await login(page);
  const create = await page.request.post('/api/auth/users', { data: { name: 'e2e-viewer', role: 'viewer', password: 'E2e-viewer-init-1' } });
  expect(create.ok()).toBeTruthy();
  const ctx = await browser.newContext({ baseURL: page.url().replace(/\/[^/]*$/, '') });
  const viewer = await ctx.newPage();
  const login1 = await viewer.request.post('/api/auth/login', { data: { username: 'e2e-viewer', password: 'E2e-viewer-init-1' } });
  expect(login1.ok()).toBeTruthy();
  const change = await viewer.request.post('/api/auth/password', { data: { current: 'E2e-viewer-init-1', new: 'E2e-viewer-pass-22' } });
  expect(change.ok()).toBeTruthy();
  await viewer.goto('/');
  await expect(viewer.locator('#tabs')).toBeVisible();
  await expect(viewer.locator('#tabSystem')).toBeHidden();
  expect((await viewer.request.get('/api/auth/users')).status()).toBe(403);
  expect((await viewer.request.post('/api/block', { data: { ip: '203.0.113.9', reason: 'x' } })).status()).toBe(403);
  expect((await viewer.request.get('/api/admin/backup')).status()).toBe(403);
  await ctx.close();
});

test('跨站写请求被拒绝', async ({ page }) => {
  await login(page);
  const r = await page.request.post('/api/block', { data: { ip: '203.0.113.9', reason: 'x' }, headers: { Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site' } });
  expect(r.status()).toBe(403);
});
