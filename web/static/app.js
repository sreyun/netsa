'use strict';

// ---------------- 工具 ----------------
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
// 日志中的攻击载荷（如 <script>）必须转义后再插入页面
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const LV = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
const LV_COLOR = { critical: '#ff4d4f', high: '#ff7a45', medium: '#ffc53d', low: '#40a9ff', info: '#8c9ab8' };
const LEVELS = ['critical', 'high', 'medium', 'low', 'info'];
const PHASE = { recon: '侦察扫描', credential: '凭证攻击', exploit: '漏洞利用', persistence: '后门控制', impact: '拒绝服务' };
const PHASES = ['recon', 'credential', 'exploit', 'persistence', 'impact'];
const RESULT = { blocked: '已拦截', failed: '失败', error: '服务异常', success: '疑似成功', passed: '未拦截', allowed: '防火墙放行', unknown: '未知' };
const CONF = { high: '高', medium: '中', low: '低' };
const SRC = { custom: '自定义网段', ip2region: 'ip2region 离线库', maxmind: 'MaxMind GeoLite2', 'ip-api': 'ip-api 在线库', private: '内网地址', rdns: '反向 DNS', gazetteer: '区划地名库（离线城市定位）' };
const TEXT = '#a9b8db';
const GRID_LINE = 'rgba(80,110,170,.18)';

const api = async (path, method = 'GET', body) => {
  const opt = { method, headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  let r;
  try {
    r = await fetch(path, opt);
  } catch (e) {
    setOffline(true); // 网络中断或服务重启：提示并由定时刷新自动重试
    throw e;
  }
  setOffline(false);
  if (!r.ok) {
    const text = await r.text();
    let msg = text || r.statusText;
    let code = '';
    try {
      const j = JSON.parse(text);
      msg = j.error || msg;
      code = j.code || '';
    } catch (_) { /* 非 JSON 错误 */ }
    if (r.status === 401) goLogin(); // 登录已过期或被管理员注销
    else if (code === 'must_change_password') openPasswordForm(true);
    const err = new Error(msg);
    err.status = r.status;
    err.code = code;
    throw err;
  }
  return r.json();
};

function setOffline(on) {
  const b = document.getElementById('connBanner');
  if (b && b.hidden === on) b.hidden = !on;
}

// 对话框：打开时记住原焦点、Tab 键在对话框内循环，关闭后焦点回到打开前的元素
const focusables = 'a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select, textarea, [tabindex]:not([tabindex="-1"])';
const openDialog = () => [...document.querySelectorAll('.modal-mask')].find((m) => !m.hidden)
  || (document.getElementById('drawer').classList.contains('open') ? document.getElementById('drawer') : null);
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Tab') return;
  const dlg = openDialog();
  if (!dlg) return;
  const items = [...dlg.querySelectorAll(focusables)].filter((el) => el.offsetParent !== null);
  if (!items.length) return;
  const first = items[0], last = items[items.length - 1];
  if (!dlg.contains(document.activeElement)) { first.focus(); e.preventDefault(); return; }
  if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
  else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
});
// 记录对话框之外最近获得焦点的元素（打开对话框的按钮），对话框关闭后把焦点还给它
let lastOutside = null;
// rememberFocus 在打开对话框前调用，同步记录当前焦点（不依赖 focusin 事件）
function rememberFocus() {
  const a = document.activeElement;
  if (a && a !== document.body && !a.closest('.modal-mask')) lastOutside = a;
}
document.addEventListener('focusin', (e) => { if (!e.target.closest('.modal-mask')) lastOutside = e.target; });
new MutationObserver((muts) => {
  for (const m of muts) {
    // 只处理对话框关闭；提示条等元素的显隐不能改变焦点
    if (m.target.classList.contains('modal-mask') && m.target.hidden && lastOutside && document.contains(lastOutside)) lastOutside.focus();
  }
}).observe(document.body, { subtree: true, attributes: true, attributeFilter: ['hidden'] });

// 跳转登录页（保留 #ip=… 等页面内定位，登录后回到原处）
let leaving = false;
function goLogin() {
  if (leaving) return;
  leaving = true;
  location.href = '/login.html' + location.hash;
}

// 当前登录账号；未开启登录认证时为管理员
let me = { user: '', role: 'admin', auth: false, must_change: false };
const isAdmin = () => me.role === 'admin';
let meta = { china_maps: {}, geo_providers: [] };
const num = (n) => (n ?? 0).toLocaleString('zh-CN');
const zero = (t) => !t || t.startsWith('0001');
const pad = (n) => String(n).padStart(2, '0');
// 时间统一按服务端配置的 timezone 展示（未配置时用浏览器本地时区）：值班电脑的系统时区设置不同
// （例如跳板机为 UTC）时，页面上的时间也与日志、告警推送保持一致，不会出现相差 8 小时的情况。
let tzFmt = null;
function setDisplayTimezone(tz) {
  tzFmt = null;
  if (!tz) return;
  try {
    tzFmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch (_) { /* 浏览器不认识该时区时退回本地时区 */ }
}
// timeParts 返回指定时刻在展示时区下的年月日时分秒（均为两位数字符串，年为四位）。
function timeParts(d) {
  if (!tzFmt) {
    return { y: String(d.getFullYear()), mo: pad(d.getMonth() + 1), d: pad(d.getDate()), h: pad(d.getHours()), mi: pad(d.getMinutes()), s: pad(d.getSeconds()) };
  }
  const o = {};
  for (const p of tzFmt.formatToParts(d)) o[p.type] = p.value;
  return { y: o.year, mo: o.month, d: o.day, h: o.hour === '24' ? '00' : o.hour, mi: o.minute, s: o.second };
}
const fmtTime = (t) => {
  if (zero(t)) return '-';
  const p = timeParts(new Date(t));
  return `${p.y}-${p.mo}-${p.d} ${p.h}:${p.mi}:${p.s}`;
};
const fmtShort = (t) => (zero(t) ? '-' : fmtTime(t).slice(5));
const badge = (lv) => `<span class="badge lv-${esc(lv)} bg-${esc(lv)}">${esc(LV[lv] || lv)}</span>`;
const resTag = (r) => `<span class="res-${esc(r)} nowrap">${esc(RESULT[r] || r)}</span>`;
const scoreBar = (s, lv) => `<span class="scorebar"><i style="width:${Math.min(100, s)}%;background:${LV_COLOR[lv] || '#888'}"></i></span><b>${Math.round(s)}</b>`;
const ipLink = (ip) => `<span class="ip clickable" data-ip="${esc(ip)}">${esc(ip)}</span>`;
const empty = (cols, text = '暂无数据') => `<tr><td colspan="${cols}" class="empty">${esc(text)}</td></tr>`;
const sortedEntries = (obj, n) => Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, n);
// fmtDur 把 Go 的时长字符串（如 10m0s）转为中文
const fmtDur = (s) => {
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(s || '');
  if (!m) return s || '';
  return [m[1] && `${m[1]} 小时`, +m[2] ? `${m[2]} 分钟` : '', +m[3] ? `${m[3]} 秒` : ''].filter(Boolean).join('') || s;
};

// ---------------- 图表 ----------------
const charts = {};
// 图表实例创建后的一次性初始化（事件绑定等），实例重建时会重新执行
const chartSetup = {};
const isVisible = (el) => !!el && el.offsetWidth > 0 && el.offsetHeight > 0;
// 图表容器尺寸变化（面板被拉伸、窗口缩放、切换标签页）时自动重绘，保证图表始终填满面板
const chartObserver = new ResizeObserver((entries) => {
  for (const e of entries) {
    const c = echarts.getInstanceByDom(e.target);
    if (c && e.contentRect.width > 0 && e.contentRect.height > 0) c.resize();
  }
});
// 隐藏标签页中的容器宽高为 0：此时 resize 会把画布缩成 0 高度，地图飞线拖尾绘制 0 尺寸画布时抛出异常，
// 实例会卡在 ECharts 内部处理流程中，之后所有 setOption / resize 都被拒绝，表现为切回后地图空白。
// 因此只对可见图表 resize，并在取用实例时检查健康状态，异常实例直接重建。
function resizeCharts() {
  for (const c of Object.values(charts)) {
    if (isVisible(c.getDom())) c.resize();
  }
}
function chartHealthy(c) {
  if (c.isDisposed()) return false;
  const el = c.getDom();
  if (!isVisible(el)) return true; // 隐藏时无法判断，等可见后再检查
  if (c.__flagInMainProcess) return false; // 渲染异常后残留的内部标记（正常情况下调用方取实例时必为 false）
  const cv = el.querySelector('canvas');
  return !cv || (cv.offsetWidth > 0 && cv.offsetHeight > 0);
}
function chart(id) {
  let c = charts[id];
  if (c && !chartHealthy(c)) {
    console.warn(`图表 ${id} 状态异常，已重建`);
    chartObserver.unobserve(c.getDom());
    try { c.dispose(); } catch (_) { /* 异常实例可能无法正常释放 */ }
    c = null;
  }
  if (!c) {
    const el = document.getElementById(id);
    c = charts[id] = echarts.init(el, null, { renderer: 'canvas' });
    chartObserver.observe(el);
    chartSetup[id]?.(c);
  }
  return c;
}
const baseTooltip = { backgroundColor: 'rgba(8,16,34,.95)', borderColor: '#2b4a80', textStyle: { color: '#d6e2ff', fontSize: 12 } };

// 可下钻图表的提示信息末尾附加操作说明
const hintLine = (t) => (t ? `<br/><span style="color:#7d8db3">${esc(t)}</span>` : '');
const HINT = hintLine('点击查看明细');

function barChart(id, items, color, horizontal = true, hint = '') {
  const names = items.map((i) => i.name).reverse();
  const vals = items.map((i) => i.value).reverse();
  const cat = { type: 'category', data: names, triggerEvent: !!hint, axisLabel: { color: TEXT, fontSize: 11, width: 110, overflow: 'truncate' }, axisLine: { lineStyle: { color: GRID_LINE } }, axisTick: { show: false } };
  const val = { type: 'value', axisLabel: { color: TEXT, fontSize: 10 }, splitLine: { lineStyle: { color: GRID_LINE } } };
  chart(id).setOption({
    tooltip: { ...baseTooltip, trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (ps) => `${esc(ps[0].name)}：${num(ps[0].value)}${hintLine(hint)}` },
    grid: { left: 8, right: 30, top: 6, bottom: 4, containLabel: true },
    xAxis: horizontal ? val : cat, yAxis: horizontal ? cat : val,
    series: [{
      type: 'bar', data: vals, barMaxWidth: 14,
      itemStyle: { borderRadius: horizontal ? [0, 3, 3, 0] : [3, 3, 0, 0], color: new echarts.graphic.LinearGradient(0, 0, horizontal ? 1 : 0, horizontal ? 0 : 1, [{ offset: 0, color: color[0] }, { offset: 1, color: color[1] }]) },
      label: { show: horizontal, position: 'right', color: TEXT, fontSize: 10 },
    }],
  }, true);
}

function gauge(id, value, title) {
  chart(id).setOption({
    series: [{
      type: 'gauge', startAngle: 210, endAngle: -30, min: 0, max: 100, radius: '92%', center: ['50%', '58%'],
      progress: { show: true, width: 12, itemStyle: { color: value >= 80 ? LV_COLOR.critical : value >= 60 ? LV_COLOR.high : value >= 35 ? LV_COLOR.medium : value >= 10 ? LV_COLOR.low : '#52c41a' } },
      axisLine: { lineStyle: { width: 12, color: [[1, 'rgba(60,90,150,.3)']] } },
      axisTick: { show: false }, splitLine: { length: 8, lineStyle: { color: '#2b4a80', width: 2 } },
      axisLabel: { color: TEXT, fontSize: 10, distance: 16 }, pointer: { width: 4, itemStyle: { color: '#8fe9ff' } },
      anchor: { show: true, size: 8, itemStyle: { color: '#8fe9ff' } },
      title: { color: TEXT, fontSize: 12, offsetCenter: [0, '72%'] },
      detail: { valueAnimation: true, fontSize: 28, fontWeight: 700, color: '#fff', offsetCenter: [0, '38%'], formatter: '{value}' },
      data: [{ value, name: title }],
    }],
  }, true);
}

function pie(id, items, rose = false, hint = '') {
  chart(id).setOption({
    tooltip: { ...baseTooltip, trigger: 'item', formatter: (x) => `${esc(x.name)}<br/>${num(x.value)} (${x.percent}%)${hintLine(hint)}` },
    legend: { type: 'scroll', orient: 'vertical', right: 0, top: 'middle', textStyle: { color: TEXT, fontSize: 11 }, itemWidth: 10, itemHeight: 10, pageTextStyle: { color: TEXT } },
    color: ['#3a8bff', '#36cfc9', '#ff7a45', '#ffc53d', '#ff4d4f', '#9254de', '#73d13d', '#f759ab', '#40a9ff', '#ffa940', '#5cdbd3', '#adc6ff'],
    series: [{
      type: 'pie', radius: rose ? ['15%', '78%'] : ['45%', '72%'], center: ['34%', '50%'], roseType: rose ? 'radius' : false,
      itemStyle: { borderColor: '#0b1428', borderWidth: 2 }, label: { show: false }, data: items,
    }],
  }, true);
}

// ---------------- 顶栏 ----------------
setInterval(() => { $('#clock').textContent = fmtTime(new Date().toISOString()); }, 1000);

let currentTab = 'overview';
$$('#tabs button').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));
function switchTab(tab) {
  currentTab = tab;
  $$('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  $$('.tab').forEach((s) => s.classList.toggle('active', s.id === 'tab-' + tab));
  loaders[tab]?.();
  // 等浏览器完成新标签页的布局后再校正尺寸；只处理可见图表，隐藏的图表保持原尺寸
  requestAnimationFrame(() => requestAnimationFrame(resizeCharts));
}

// ---------------- 下钻 ----------------
// 态势总览中的 KPI、图表、排行与地图均可点击，跳转到攻击源或告警列表并带上筛选条件；
// 条件显示在列表上方的“下钻条件”栏中，可一键清除或返回态势总览。
const drillState = { attackers: null, alerts: null };
// drillTo 打开目标列表。params 为附加到接口的筛选参数，label 为条件说明，native 为列表自带的筛选控件取值。
function drillTo(tab, { params = {}, label = '', native = {} } = {}) {
  if (tab === 'attackers') {
    $('#atkSearch').value = '';
    $('#atkLevel').value = native.level || '';
    $('#atkSort').value = native.sort || 'score';
    atkOffset = 0;
    drillState.attackers = label ? { params, label } : null;
  } else if (tab === 'alerts') {
    setAlertMode('live');
    fillAlertFilters();
    $('#alSearch').value = '';
    $('#alSev').value = native.severity || '';
    $('#alCat').value = native.category || '';
    $('#alResult').value = native.result || '';
    $('#alKind').value = native.kind || '';
    drillState.alerts = label ? { params, label } : null;
  }
  renderDrillBars();
  closeDrawer();
  switchTab(tab);
  window.scrollTo({ top: 0 });
}
function renderDrillBars() {
  for (const [tab, id] of [['attackers', '#atkDrill'], ['alerts', '#alDrill']]) {
    const d = drillState[tab];
    const bar = $(id);
    bar.hidden = !d;
    if (!d) continue;
    const hist = tab === 'alerts' && meta.archive ? '<button type="button" class="btn" data-drill="history" title="按相同条件在 PostgreSQL 归档中查询更早的告警">在归档库中查询</button>' : '';
    bar.innerHTML = `<span class="drill-ico">⤵</span><span>下钻条件：<b>${esc(d.label)}</b></span><span class="spacer"></span>${hist}`
      + `<button type="button" class="btn" data-drill="back">← 返回态势总览</button><button type="button" class="btn" data-drill="clear">✕ 清除条件</button>`;
  }
}
const drillParams = (tab) => (drillState[tab] ? drillState[tab].params : {});
['#atkDrill', '#alDrill'].forEach((id) => $(id).addEventListener('click', (e) => {
  const b = e.target.closest('[data-drill]');
  if (!b) return;
  const tab = id === '#atkDrill' ? 'attackers' : 'alerts';
  if (b.dataset.drill === 'back') { switchTab('overview'); return; }
  if (b.dataset.drill === 'history') { openHistoryFromDrill(); return; }
  drillState[tab] = null;
  renderDrillBars();
  if (tab === 'attackers') { atkOffset = 0; loadAttackers().catch(console.error); } else loadAlerts().catch(console.error);
}));
// data-go="标签页:参数" 的元素（KPI 卡片、面板标题中的“全部 ›”链接）点击后跳转
document.addEventListener('click', (e) => {
  const k = e.target.closest('[data-go]');
  if (!k) return;
  const [tab, arg] = k.dataset.go.split(':');
  if (tab === 'attackers') drillTo('attackers', { native: { level: arg } });
  else if (tab === 'alerts') drillTo('alerts', { native: { result: arg } });
  else switchTab(tab);
});
const fmtHM = (sec) => { const p = timeParts(new Date(sec * 1000)); return `${p.mo}-${p.d} ${p.h}:${p.mi}`; };

// IP 点击统一打开溯源详情
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-ip]');
  if (el) openIP(el.dataset.ip);
});

// ---------------- 态势总览 ----------------
let lastOverview = null;
async function loadOverview() {
  const o = await api('/api/overview');
  lastOverview = o;
  const lc = o.level_counts || {};
  const t = o.totals;
  const sc = o.sev_counts || {};
  // 两类“等级”含义不同：攻击事件按单次攻击的告警等级统计；攻击源按 IP 的综合威胁等级统计
  // （不低于其触发过的最高告警等级）。一个同时触发高危与严重告警的 IP 计为严重攻击源。
  const kpis = [
    ['总事件', num(t.events), `Web ${num(t.web)} · 防火墙 ${num(t.firewall)}`, '#8fe9ff', '点击查看各日志数据源的采集与解析情况', 'sources:'],
    ['攻击事件', num(t.attacks), `严重 ${num(sc.critical || 0)} · 高危 ${num(sc.high || 0)} · 中危 ${num(sc.medium || 0)}`, LV_COLOR.high,
      `按告警等级统计的攻击命中次数：严重 ${num(sc.critical || 0)} · 高危 ${num(sc.high || 0)} · 中危 ${num(sc.medium || 0)} · 低危 ${num(sc.low || 0)}；近 1 小时 ${num(o.recent.attacks)} 次`, 'alerts:'],
    ['攻击源 IP', num(o.attackers), `独立来源 ${num(o.unique_ips)} · 近 1 小时活跃 ${num(o.recent.attackers)}`, '#ffc53d', '', 'attackers:'],
    ['高危以上攻击源', num((lc.critical || 0) + (lc.high || 0)), `严重 ${lc.critical || 0} · 高危 ${lc.high || 0}`, LV_COLOR.critical,
      `按攻击源 IP 的综合威胁等级统计：严重 ${lc.critical || 0} · 高危 ${lc.high || 0} · 中危 ${lc.medium || 0} · 低危 ${lc.low || 0}。触发过高危告警的 IP 至少为高危`, 'attackers:high'],
    ['攻击拦截率', `${o.block_rate}%`, `已拦截 ${num(t.blocked)}`, '#52c41a', `已拦截 ${num(t.blocked)} 次，点击查看已拦截的告警`, 'alerts:blocked'],
    ['疑似成功攻击', num(t.success), '需优先排查是否失陷', t.success > 0 ? LV_COLOR.critical : '#52c41a', '', 'alerts:success'],
    ['攻击面风险指数', `${o.surface_score}`, `风险发现 ${num(o.findings)} 项`,
      o.surface_score >= 60 ? LV_COLOR.critical : o.surface_score >= 30 ? LV_COLOR.high : o.surface_score > 0 ? LV_COLOR.medium : '#52c41a', '', 'surface:'],
    ['攻击来源地域', num(o.country_count), `国家/地区 · 城市 ${num(o.city_count)}`, '#8fe9ff', '点击查看全部攻击源（可在下方“来源国家/地区”“攻击来源城市”图表中点击具体地域）', 'attackers:'],
  ];
  $('#kpis').innerHTML = kpis.map(([l, v, s, c, tip, go]) => `<div class="kpi${go ? ' clickable' : ''}"${go ? ` data-go="${go}"` : ''} title="${esc(tip || s)}"><div class="label">${l}</div><div class="value" style="color:${c}">${v}</div><div class="sub">${esc(s)}</div></div>`).join('');
  const tb = $('#threatBadge');
  tb.innerHTML = `威胁等级 <b>${esc(LV[o.threat_level] === '信息' ? '安全' : LV[o.threat_level])}</b> · ${o.threat_index}`;
  tb.style.color = LV_COLOR[o.threat_level] || '#52c41a';
  tb.style.borderColor = tb.style.color;
  $('#rangeText').textContent = zero(o.from) ? '' : `${fmtShort(o.from)} ~ ${fmtShort(o.to)}`;

  gauge('cGauge', o.threat_index, '近 60 分钟 · 点击查看告警');
  pie('cCategory', (o.categories || []).slice(0, 12), false, '点击查看该类型告警');
  const ph = o.phases || {};
  chart('cPhase').setOption({
    tooltip: { ...baseTooltip, trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (ps) => `${esc(ps[0].name)}：${num(ps[0].value)} 次${HINT}` },
    grid: { left: 8, right: 30, top: 6, bottom: 4, containLabel: true },
    xAxis: { type: 'value', axisLabel: { color: TEXT, fontSize: 10 }, splitLine: { lineStyle: { color: GRID_LINE } } },
    yAxis: { type: 'category', inverse: true, triggerEvent: true, data: PHASES.map((p) => PHASE[p]), axisLabel: { color: TEXT }, axisTick: { show: false }, axisLine: { lineStyle: { color: GRID_LINE } } },
    series: [{ type: 'bar', barMaxWidth: 14, label: { show: true, position: 'right', color: TEXT, fontSize: 10 },
      data: PHASES.map((p, i) => ({ value: ph[p] || 0, itemStyle: { color: ['#40a9ff', '#ffc53d', '#ff7a45', '#ff4d4f', '#9254de'][i], borderRadius: [0, 3, 3, 0] } })) }],
  }, true);
  barChart('cCountry', (o.top_countries || []).slice(0, 10), ['#1d4fa8', '#3a8bff'], true, '点击查看该地区攻击源');
  barChart('cCity', (o.top_cities || []).slice(0, 10), ['#126e6a', '#36cfc9'], true, '点击查看该城市攻击源');
  pie('cNetType', o.top_net_types || [], false, '点击查看该类型攻击源');
  $('#topTargets').innerHTML = (o.top_targets || []).length
    ? `<colgroup><col><col style="width:72px"></colgroup><thead><tr><th>目标</th><th class="num">次数</th></tr></thead><tbody>${o.top_targets.map((k) => `<tr class="clickable" data-target="${esc(k.name)}" title="${esc(k.name)}&#10;点击查看攻击该目标的告警"><td class="mono">${esc(k.name)}</td><td class="num">${num(k.value)}</td></tr>`).join('')}</tbody>`
    : empty(2);
}
$('#topTargets').addEventListener('click', (e) => {
  const tr = e.target.closest('[data-target]');
  if (tr) drillTo('alerts', { params: { target: tr.dataset.target }, label: `被攻击目标 = ${tr.dataset.target}` });
});

// 总览图表的下钻：图表实例创建时绑定（实例重建后自动恢复）。条目名称即筛选值，与总览统计口径一致。
const onPick = (c, fn) => c.on('click', (x) => {
  // 系列条目与坐标轴标签（triggerEvent）都可点击
  const name = x.componentType === 'yAxis' || x.componentType === 'xAxis' ? x.value : x.name;
  if (name) fn(name, x);
});
chartSetup.cCategory = (c) => onPick(c, (name) => drillTo('alerts', { native: { category: name } }));
chartSetup.cPhase = (c) => onPick(c, (name) => {
  const ph = PHASES.find((p) => PHASE[p] === name);
  if (ph) drillTo('alerts', { params: { phase: ph }, label: `攻击链阶段 = ${name}` });
});
chartSetup.cCountry = (c) => onPick(c, (name) => drillTo('attackers', { params: { country: name }, label: `来源国家/地区 = ${name}` }));
chartSetup.cCity = (c) => onPick(c, (name) => drillTo('attackers', { params: { city: name }, label: `攻击来源城市 = ${name}` }));
chartSetup.cNetType = (c) => onPick(c, (name) => drillTo('attackers', { params: { net_type: name }, label: `攻击源网络类型 = ${name}` }));
// 威胁指数：点击仪表盘查看近 60 分钟（以最新日志时间为准）的告警
chartSetup.cGauge = (c) => c.getZr().on('click', () => {
  if (!lastOverview || zero(lastOverview.to)) return;
  const to = Math.floor(new Date(lastOverview.to).getTime() / 1000) + 1;
  drillTo('alerts', { params: { from: to - 3600, to }, label: `近 60 分钟（${fmtHM(to - 3600)} ~ ${fmtHM(to)}）` });
});

let trendMinutes = 360;
$$('#trendRange button').forEach((b) => b.addEventListener('click', () => {
  trendMinutes = +b.dataset.m;
  $$('#trendRange button').forEach((x) => x.classList.toggle('active', x === b));
  loadTrend();
}));
let trendData = [];
// 趋势图：点击任意时间点查看该时段的告警（按图表的时间粒度）
chartSetup.cTrend = (c) => c.getZr().on('click', (e) => {
  if (!trendData.length || !c.containPixel({ gridIndex: 0 }, [e.offsetX, e.offsetY])) return;
  const idx = Math.round(c.convertFromPixel({ xAxisIndex: 0 }, e.offsetX));
  const b = trendData[idx];
  if (!b) return;
  const step = trendData.length > 1 ? trendData[1].t - trendData[0].t : 60;
  drillTo('alerts', { params: { from: b.t, to: b.t + step }, label: `时间段 ${fmtHM(b.t)} ~ ${fmtHM(b.t + step)}（攻击 ${num(b.attacks)} 次）` });
});
async function loadTrend() {
  const data = (await api(`/api/timeline?minutes=${trendMinutes}`)) || [];
  trendData = data;
  const x = data.map((b) => {
    const d = new Date(b.t * 1000);
    const p = timeParts(d);
    return trendMinutes > 1440 ? `${p.mo}-${p.d} ${p.h}:${p.mi}` : `${p.h}:${p.mi}`;
  });
  const area = (c) => ({ color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: c + '66' }, { offset: 1, color: c + '00' }]) });
  chart('cTrend').setOption({
    tooltip: {
      ...baseTooltip, trigger: 'axis',
      formatter: (ps) => `${esc(ps[0].axisValue)}<br/>${ps.map((p) => `${p.marker}${esc(p.seriesName)}：${num(p.value)}`).join('<br/>')}${hintLine('点击查看该时段告警')}`,
    },
    // 图例单独占一行，坐标轴名称放在其下方，避免与右侧轴名“攻击”重叠
    legend: { top: 0, right: 0, textStyle: { color: TEXT, fontSize: 11 }, itemWidth: 12, itemHeight: 8, itemGap: 14 },
    grid: { left: 8, right: 8, top: 44, bottom: 4, containLabel: true },
    xAxis: { type: 'category', data: x, axisLabel: { color: TEXT, fontSize: 10 }, axisLine: { lineStyle: { color: GRID_LINE } } },
    yAxis: [
      { type: 'value', name: '流量', nameGap: 10, nameTextStyle: { color: TEXT, fontSize: 10 }, axisLabel: { color: TEXT, fontSize: 10 }, splitLine: { lineStyle: { color: GRID_LINE } } },
      { type: 'value', name: '攻击', nameGap: 10, nameTextStyle: { color: TEXT, fontSize: 10 }, axisLabel: { color: TEXT, fontSize: 10 }, splitLine: { show: false } },
    ],
    series: [
      { name: 'Web 请求', type: 'line', smooth: true, showSymbol: false, data: data.map((b) => b.web), lineStyle: { width: 1.5, color: '#3a8bff' }, itemStyle: { color: '#3a8bff' }, areaStyle: area('#3a8bff') },
      { name: '防火墙事件', type: 'line', smooth: true, showSymbol: false, data: data.map((b) => b.fw), lineStyle: { width: 1.5, color: '#36cfc9' }, itemStyle: { color: '#36cfc9' } },
      { name: '攻击事件', type: 'bar', yAxisIndex: 1, data: data.map((b) => b.attacks), itemStyle: { color: '#ff7a45' }, barMaxWidth: 6 },
      { name: '高危/严重', type: 'line', yAxisIndex: 1, smooth: true, showSymbol: false, data: data.map((b) => b.sev[3] + b.sev[4]), lineStyle: { width: 1.5, color: '#ff4d4f' }, itemStyle: { color: '#ff4d4f' } },
    ],
  }, true);
}

// ---------------- 攻击来源地图 ----------------
// 视图：world（世界）/ china（中国）/ china + province（省级下钻，地市着色）。
// 刷新时只替换系列数据，保留用户的缩放与平移；切换视图或点击“重置”时恢复默认视角。
const COORD = {
  maxmind: '精确坐标（MaxMind）', 'ip-api': '精确坐标（在线库）', custom: '自定义网段坐标', private: '内网（资产所在地）',
  city: '城市中心（近似）', province: '省级中心（近似）', country: '国家中心（近似）',
};
const isExact = (s) => s === 'maxmind' || s === 'ip-api' || s === 'custom';
const mapCtl = { view: 'world', province: null, data: null, home: null, maps: {}, flashes: [], rendered: false };
try { mapCtl.view = localStorage.getItem('netsa.mapView') === 'china' ? 'china' : 'world'; } catch (_) { /* 隐私模式 */ }

function registerMap(name, url) {
  if (!mapCtl.maps[name]) {
    mapCtl.maps[name] = fetch(url)
      .then((r) => { if (!r.ok) throw new Error(`加载地图 ${url} 失败`); return r.json(); })
      .then((geo) => echarts.registerMap(name, geo))
      .catch((e) => { delete mapCtl.maps[name]; throw e; });
  }
  return mapCtl.maps[name];
}
const mapName = () => (mapCtl.view === 'world' ? 'world' : mapCtl.province ? 'prov:' + mapCtl.province : 'china');
const inChina = (lon, lat) => lon > 73 && lon < 136 && lat > 3 && lat < 54;
const placeShort = (p) => p.label || p.city || p.province || p.country || '未知';
// 内网攻击源（命中自定义网段）用菱形标注，与外部来源区分
const pointSymbol = (p) => (p.internal ? 'diamond' : isExact(p.coord_source) ? 'circle' : 'emptyCircle');

function visiblePoints() {
  const pts = (mapCtl.data && mapCtl.data.points) || [];
  if (mapCtl.view === 'world') return pts;
  if (!mapCtl.province) return pts.filter((p) => p.world_name === 'China');
  return pts.filter((p) => p.province_map === mapCtl.province);
}

function regionData() {
  const d = mapCtl.data || {};
  if (mapCtl.view === 'world') return (d.countries || []).map((r) => ({ name: r.map_name, label: r.name, value: r.attacks, attackers: r.attackers }));
  if (!mapCtl.province) return (d.provinces || []).map((r) => ({ name: r.map_name, label: r.name, value: r.attacks, attackers: r.attackers }));
  const agg = {};
  for (const p of visiblePoints()) {
    if (!p.city_map) continue;
    const r = (agg[p.city_map] = agg[p.city_map] || { name: p.city_map, label: p.city_map, value: 0, attackers: 0 });
    r.value += p.attacks;
    r.attackers += p.attackers;
  }
  return Object.values(agg);
}

async function loadMap() {
  const m = await api('/api/map');
  mapCtl.data = m.data;
  mapCtl.home = m.home;
  await renderMap(!mapCtl.rendered);
}

function pointTip(p) {
  return `<b>${esc(p.name || placeShort(p))}</b><br/>攻击源 ${p.attackers} 个 · 攻击 ${num(p.attacks)} 次<br/>最高等级 <span style="color:${LV_COLOR[p.level]}">${LV[p.level]}</span>`
    + (p.internal ? '<br/><span style="color:#ffd666">内网攻击源 · 自定义网段</span>' : '')
    + `<br/><span style="color:#7d8db3">${esc(COORD[p.coord_source] || '')} · 点击查看攻击源</span>`;
}

async function renderMap(reset) {
  // 地图所在标签页隐藏时不渲染（容器尺寸为 0），切回态势总览时由 loadMap 补上
  if (!isVisible($('#cMap'))) {
    mapCtl.deferredReset = mapCtl.deferredReset || reset;
    return;
  }
  // 实例刚创建或已损坏需重建时，按首次渲染处理（设置初始视角）
  reset = reset || mapCtl.deferredReset || !charts.cMap || !chartHealthy(charts.cMap);
  mapCtl.deferredReset = false;
  const name = mapName();
  try {
    if (name === 'world') await registerMap('world', '/vendor/world.json');
    else if (name === 'china') await registerMap('china', '/vendor/china/china.json');
    else await registerMap(name, `/vendor/china/${encodeURIComponent(meta.china_maps[mapCtl.province])}.json`);
  } catch (e) {
    $('#mapNote').textContent = e.message;
    return;
  }
  // 加载地图数据期间用户可能已切换到其他标签页
  if (!isVisible($('#cMap'))) {
    mapCtl.deferredReset = mapCtl.deferredReset || reset;
    return;
  }
  const home = mapCtl.home || { lat: 0, lon: 0, name: '' };
  const homeXY = [home.lon, home.lat];
  const homeVisible = mapCtl.view === 'world' || inChina(home.lon, home.lat);
  const pts = visiblePoints().slice(0, 400);
  const regions = regionData();
  const maxV = Math.max(1, ...regions.map((r) => r.value));
  const maxA = Math.max(1, ...pts.map((p) => p.attacks));
  const size = (a) => 7 + 18 * Math.sqrt(a / maxA);
  const labelN = mapCtl.view === 'world' ? 16 : 30;
  const geo = {
    map: name, roam: true, scaleLimit: { min: 0.8, max: 40 },
    label: { show: mapCtl.view !== 'world', color: 'rgba(170,195,240,.55)', fontSize: 10 },
    itemStyle: { areaColor: '#10244a', borderColor: '#2b4a80', borderWidth: 0.7 },
    emphasis: { label: { show: true, color: '#fff' }, itemStyle: { areaColor: '#25508f' } },
    select: { disabled: true },
  };
  if (reset && mapCtl.view === 'world') Object.assign(geo, { center: [30, 22], zoom: 1.2 });
  const option = {
    tooltip: { ...baseTooltip, trigger: 'item' },
    visualMap: {
      type: 'continuous', seriesIndex: 0, min: 0, max: maxV, show: regions.length > 0, right: 10, bottom: 10,
      itemWidth: 10, itemHeight: 90, text: ['攻击多', '少'], textStyle: { color: TEXT, fontSize: 10 }, calculable: false,
      inRange: { color: ['#173566', '#1f5fae', '#c89a1c', '#e8532f'] },
    },
    geo,
    series: [
      {
        type: 'map', geoIndex: 0, data: regions,
        tooltip: {
          formatter: (x) => (x.data
            ? `<b>${esc(x.data.label || x.name)}</b><br/>攻击源 ${x.data.attackers} 个 · 攻击 ${num(x.data.value)} 次`
              + hintLine(mapCtl.view === 'world' ? (x.name === 'China' ? '点击切换到中国地图' : '点击查看该国家/地区的攻击源')
                : !mapCtl.province ? (meta.china_maps?.[x.name] ? '点击查看地市分布' : '点击查看该省攻击源') : '点击查看该地市的攻击源')
            : esc(x.name)),
        },
      },
      {
        type: 'lines', coordinateSystem: 'geo', zlevel: 1, silent: true,
        effect: { show: true, period: 4, trailLength: 0.35, symbol: 'arrow', symbolSize: 5 },
        lineStyle: { width: 1, opacity: 0.45, curveness: 0.25 },
        data: homeVisible ? pts.slice(0, 150).map((p) => ({ coords: [[p.lon, p.lat], homeXY], lineStyle: { color: LV_COLOR[p.level] } })) : [],
      },
      {
        type: 'effectScatter', coordinateSystem: 'geo', zlevel: 2, rippleEffect: { scale: 3, brushType: 'stroke' },
        labelLayout: { hideOverlap: true },
        data: pts.map((p, i) => ({
          name: placeShort(p), value: [p.lon, p.lat, p.attacks], p,
          symbol: pointSymbol(p), symbolSize: size(p.attacks),
          itemStyle: { color: LV_COLOR[p.level] },
          label: {
            show: i < labelN, formatter: placeShort(p) + (p.attackers > 1 ? ` ×${p.attackers}` : ''),
            position: 'right', distance: 6, color: '#e6f0ff', fontSize: 11, textBorderColor: '#06101f', textBorderWidth: 2,
          },
        })),
        tooltip: { formatter: (x) => pointTip(x.data.p) },
      },
      {
        type: 'effectScatter', coordinateSystem: 'geo', zlevel: 3, silent: true, rippleEffect: { scale: 6, brushType: 'fill' },
        data: mapCtl.flashes.map((f) => ({ value: [f.lon, f.lat], symbolSize: 8, itemStyle: { color: LV_COLOR[f.severity] } })),
      },
      {
        type: 'scatter', coordinateSystem: 'geo', zlevel: 4, symbol: 'pin', symbolSize: 30, itemStyle: { color: '#36cfc9' },
        label: { show: true, formatter: home.name, position: 'top', color: '#8fe9ff', fontSize: 12 },
        data: homeVisible ? [{ name: home.name, value: homeXY }] : [],
        tooltip: { formatter: () => `受保护资产：${esc(home.name)}` },
      },
    ],
  };
  // 切换视图时先清空画布：飞线拖尾使用独立图层，不清空会残留上一个视图的轨迹
  if (reset) chart('cMap').clear();
  chart('cMap').setOption(option, reset ? { notMerge: true } : { replaceMerge: ['series'] });
  mapCtl.rendered = true;
  updateMapChrome(pts, regions);
}

function updateMapChrome(pts, regions) {
  const d = mapCtl.data || {};
  const exact = pts.filter((p) => isExact(p.coord_source)).length;
  const attackers = pts.reduce((s, p) => s + p.attackers, 0);
  let stats;
  if (mapCtl.view === 'world') stats = `来源国家/地区<b>${(d.countries || []).length}</b> 地点<b>${pts.length}</b> 攻击源<b>${attackers}</b>`;
  else if (!mapCtl.province) stats = `国内来源省份<b>${(d.provinces || []).length}</b> 城市<b>${pts.length}</b> 攻击源<b>${attackers}</b>`;
  else stats = `${esc(mapCtl.province)} 来源地市<b>${regions.length}</b> 攻击源<b>${attackers}</b>`;
  if (pts.length) stats += `<br/>精确坐标占比<b>${Math.round((exact * 100) / pts.length)}%</b>`;
  $('#mapStats').innerHTML = stats;
  const notes = [];
  if (d.no_coord > 0) notes.push(`${d.no_coord} 个攻击源无法定位（未配置自定义网段的内网地址或定位库中无记录）`);
  if (pts.some((p) => p.internal)) notes.push('菱形为命中自定义网段的内网攻击源');
  if (pts.length && exact < pts.length) notes.push('空心点为按城市/省份/国家中心换算的近似位置，配置 MaxMind 或开启在线溯源可获得精确坐标');
  $('#mapNote').textContent = notes.join('；');
  $('#mapCrumb').innerHTML = mapCtl.view === 'china' && mapCtl.province
    ? `<button type="button" id="crumbBack">中国</button> › <b>${esc(mapCtl.province)}</b> <button type="button" id="crumbList" title="列出该省全部攻击源">攻击源列表 ›</button>`
    : mapCtl.view === 'china' ? '<button type="button" id="crumbList" title="列出国内全部攻击源">国内攻击源列表 ›</button>' : '';
  const back = $('#crumbBack');
  if (back) back.onclick = () => { mapCtl.province = null; hidePop(); renderMap(true); };
  const list = $('#crumbList');
  if (list) {
    list.onclick = () => (mapCtl.province
      ? drillTo('attackers', { params: { province: mapCtl.province }, label: `来源省份 = ${mapCtl.province}` })
      : drillTo('attackers', { params: { world: 'China' }, label: '来源国家/地区 = 中国' }));
  }
  $$('#mapView button').forEach((b) => b.classList.toggle('active', b.dataset.v === mapCtl.view));
}

function hidePop() { $('#mapPop').hidden = true; }
function showPop(p) {
  const pop = $('#mapPop');
  const ips = p.ips || [];
  pop.innerHTML = `<div class="pt">${badge(p.level)} ${esc(p.name || placeShort(p))}<span class="x" id="popClose">✕</span></div>
    <div class="meta">${esc(COORD[p.coord_source] || '')} · ${(+p.lat).toFixed(3)}, ${(+p.lon).toFixed(3)}<br/>攻击源 ${p.attackers} 个 · 攻击 ${num(p.attacks)} 次</div>
    <table>${ips.map((x) => `<tr class="clickable" data-ip="${esc(x.ip)}"><td class="ip">${esc(x.ip)}</td><td>${badge(x.level)}</td><td>${Math.round(x.score)}</td><td class="muted">${esc(x.isp || '')}</td></tr>`).join('')}</table>
    <div class="pop-foot">${p.attackers > ips.length ? `<span class="muted">仅显示威胁评分最高的 ${ips.length} 个</span>` : '<span></span>'}<button type="button" class="more" id="popAll">查看该地全部攻击源 ›</button></div>`;
  pop.hidden = false;
  $('#popClose').onclick = hidePop;
  $('#popAll').onclick = () => { hidePop(); drillTo('attackers', { params: { place: p.key }, label: `攻击来源地点 = ${p.name || placeShort(p)}` }); };
}

function switchMapView(v) {
  mapCtl.view = v;
  mapCtl.province = null;
  try { localStorage.setItem('netsa.mapView', v); } catch (_) { /* 隐私模式 */ }
  hidePop();
  renderMap(true);
}

// 地图点击事件随实例创建绑定，实例重建后自动恢复
chartSetup.cMap = (c) => c.on('click', (x) => {
  if (x.seriesType === 'effectScatter' && x.data && x.data.p) { showPop(x.data.p); return; }
  if (x.seriesType !== 'map' || !x.data) return; // 没有攻击来源的区域不下钻
  const label = x.data.label || x.name;
  if (mapCtl.view === 'world') {
    if (x.name === 'China') switchMapView('china');
    else drillTo('attackers', { params: { world: x.name }, label: `来源国家/地区 = ${label}` });
    return;
  }
  if (!mapCtl.province) {
    if (meta.china_maps && meta.china_maps[x.name]) {
      mapCtl.province = x.name;
      hidePop();
      renderMap(true);
    } else drillTo('attackers', { params: { province: x.name }, label: `来源省份 = ${label}` });
    return;
  }
  drillTo('attackers', { params: { province: mapCtl.province, city_map: x.name }, label: `来源地市 = ${mapCtl.province} ${label}` });
});
function initMapEvents() {
  $$('#mapView button').forEach((b) => b.addEventListener('click', () => switchMapView(b.dataset.v)));
  $('#mapReset').addEventListener('click', () => { hidePop(); renderMap(true); });
}

async function loadTopAttackers() {
  const r = await api('/api/attackers?limit=10');
  $('#topAttackers').innerHTML = r.items.length
    ? `<colgroup><col style="width:36%"><col><col style="width:112px"></colgroup><thead><tr><th>IP</th><th>归属地</th><th class="num">评分</th></tr></thead><tbody>${r.items.map((a) => {
      const loc = [a.country, a.province, a.city].filter(Boolean).filter((v, i, x) => x.indexOf(v) === i).join(' ');
      return `<tr class="clickable" data-ip="${esc(a.ip)}"><td class="ip" title="${esc(a.ip)}">${esc(a.ip)}</td><td title="${esc(loc)}">${esc(loc)}</td><td class="num">${scoreBar(a.score, a.level)}</td></tr>`;
    }).join('')}</tbody>`
    : empty(3);
}

// 实时告警
let feedSeen = 0;
function feedItem(a) {
  return `<li data-ip="${esc(a.src_ip)}" title="${esc(a.name)}：${esc(a.target)}"><span class="lv">${badge(a.severity)}</span>`
    + `<span class="title">${esc(a.name)}</span><span class="time">${esc(fmtShort(a.time).slice(6))}</span>`
    + `<div class="row2"><span class="ip">${esc(a.src_ip)}</span> ${esc(a.location || '')} → ${esc(a.target)}</div></li>`;
}
async function loadFeed() {
  const list = await api('/api/alerts?limit=40&severity=low');
  $('#feed').innerHTML = list.map(feedItem).join('') || '<li class="empty">暂无告警</li>';
}
// 用户向下翻看告警时，新告警插入顶部不应把正在阅读的内容挤走：保持滚动位置并提示新告警数量。
let feedUnseen = 0;
function pushFeed(a) {
  if (a.severity === 'info') return;
  const ul = $('#feed');
  if (ul.firstElementChild?.classList.contains('empty')) ul.innerHTML = '';
  const reading = ul.scrollTop > 4;
  ul.insertAdjacentHTML('afterbegin', feedItem(a));
  if (reading) {
    ul.scrollTop += ul.firstElementChild.offsetHeight;
    feedUnseen++;
    const pill = $('#feedNew');
    pill.textContent = `↑ ${feedUnseen} 条新告警`;
    pill.hidden = false;
  }
  while (ul.children.length > 80) ul.lastElementChild.remove();
  feedSeen++;
  $('#feedCount').textContent = `本次会话推送 ${feedSeen} 条`;
  if (a.lat || a.lon) {
    mapCtl.flashes.push({ lat: a.lat, lon: a.lon, severity: a.severity, t: Date.now() });
    if (currentTab === 'overview') throttledMap();
  }
}
let mapTimer = null;
function throttledMap() {
  if (mapTimer || !mapCtl.rendered) return;
  mapTimer = setTimeout(() => {
    mapTimer = null;
    mapCtl.flashes = mapCtl.flashes.filter((f) => Date.now() - f.t < 6000).slice(-30);
    renderMap(false).catch(console.error);
  }, 800);
}

function resetFeedUnseen() {
  feedUnseen = 0;
  $('#feedNew').hidden = true;
}
$('#feedNew').addEventListener('click', () => { $('#feed').scrollTo({ top: 0, behavior: 'smooth' }); resetFeedUnseen(); });
$('#feed').addEventListener('scroll', () => { if ($('#feed').scrollTop <= 4) resetFeedUnseen(); }, { passive: true });

function connectStream() {
  const es = new EventSource('/api/stream');
  es.onopen = () => $('#liveDot').classList.add('on');
  es.onerror = () => $('#liveDot').classList.remove('on');
  es.addEventListener('alert', (e) => { try { pushFeed(JSON.parse(e.data)); } catch (_) { /* ignore */ } });
}

// ---------------- 攻击溯源 ----------------
let atkOffset = 0;
const ATK_PAGE = 50;
async function loadAttackers() {
  const q = new URLSearchParams({ ...drillParams('attackers'), q: $('#atkSearch').value, level: $('#atkLevel').value, sort: $('#atkSort').value, limit: ATK_PAGE, offset: atkOffset });
  const r = await api('/api/attackers?' + q);
  $('#atkTotal').textContent = `共 ${num(r.total)} 个攻击源`;
  const rows = r.items.map((a) => `<tr class="clickable" data-ip="${esc(a.ip)}">
    <td class="nowrap">${ipLink(a.ip)}<div class="cell-chips">${a.via_proxy ? '<span class="chip">经代理还原</span>' : ''}${(a.intel || []).length ? '<span class="chip warn">情报命中</span>' : ''}</div></td>
    <td class="nowrap">${scoreBar(a.score, a.level)}</td><td class="nowrap">${badge(a.level)}</td>
    <td><div class="clamp2" title="${esc(a.location || '')}">${esc(a.location || '未知')}</div></td>
    <td class="nowrap">${a.asn ? 'AS' + a.asn : '-'}</td>
    <td class="nowrap">${esc(a.net_type || '-')}</td>
    <td class="nowrap">${esc(CONF[a.confidence] || '-')}</td>
    <td><div class="cell-chips wide">${(a.categories || []).map((c) => `<span class="chip">${esc(c)}</span>`).join('')}</div></td>
    <td><div class="cell-chips">${(a.phases || []).map((p) => `<span class="chip">${esc(PHASE[p] || p)}</span>`).join('')}</div></td>
    <td class="num">${num(a.attacks)}${a.successes ? `<div class="res-success" style="font-size:11px">${a.successes} 次疑似成功</div>` : ''}</td>
    <td class="nowrap muted">${esc(fmtShort(a.last_seen))}</td></tr>`).join('');
  $('#atkTable').innerHTML = `<thead><tr><th>来源 IP</th><th>威胁评分</th><th>等级</th><th>归属地 / 运营商</th><th>ASN</th><th>网络类型</th><th>定位置信度</th><th>攻击类型</th><th>攻击阶段</th><th class="num">攻击次数</th><th>最近活动</th></tr></thead><tbody>${rows || empty(11)}</tbody>`;
  const pages = Math.max(1, Math.ceil(r.total / ATK_PAGE));
  const page = Math.floor(atkOffset / ATK_PAGE) + 1;
  $('#atkPager').innerHTML = `<button type="button" class="btn" id="atkPrev" ${page <= 1 ? 'disabled' : ''}>上一页</button><span class="muted">${page} / ${pages}</span><button type="button" class="btn" id="atkNext" ${page >= pages ? 'disabled' : ''}>下一页</button>`;
  $('#atkPrev').onclick = () => { atkOffset = Math.max(0, atkOffset - ATK_PAGE); loadAttackers(); };
  $('#atkNext').onclick = () => { atkOffset += ATK_PAGE; loadAttackers(); };
}
let atkDebounce;
$('#atkSearch').addEventListener('input', () => { clearTimeout(atkDebounce); atkDebounce = setTimeout(() => { atkOffset = 0; loadAttackers(); }, 300); });
['#atkLevel', '#atkSort'].forEach((s) => $(s).addEventListener('change', () => { atkOffset = 0; loadAttackers(); }));

// ---------------- 告警事件 ----------------
function fillAlertFilters() {
  const cat = $('#alCat');
  if (cat.options.length <= 1 && lastOverview) {
    (lastOverview.categories || []).forEach((c) => cat.add(new Option(c.name, c.name)));
  }
  const res = $('#alResult');
  if (res.options.length <= 1) Object.entries(RESULT).forEach(([k, v]) => res.add(new Option(v, k)));
}
async function loadAlerts() {
  fillAlertFilters();
  const q = new URLSearchParams({ ...drillParams('alerts'), q: $('#alSearch').value, severity: $('#alSev').value, category: $('#alCat').value, result: $('#alResult').value, kind: $('#alKind').value, limit: 300 });
  const [list, sum] = await Promise.all([api('/api/alerts?' + q), api('/api/alerts/summary')]);
  const rt = sum.retained || {}, hits = sum.hits || {};
  $('#alSummary').innerHTML = `当前保留告警 <b>${num(sum.retained_total)}</b> 条（严重 ${num(rt.critical || 0)} · 高危 ${num(rt.high || 0)} · 中危 ${num(rt.medium || 0)} · 低危 ${num(rt.low || 0)}），`
    + `攻击命中共 <b>${num(sum.hits_total)}</b> 次（严重 ${num(hits.critical || 0)} · 高危 ${num(hits.high || 0)} · 中危 ${num(hits.medium || 0)}）。`
    + `<span class="muted">同一 IP 同一规则 ${esc(fmtDur(sum.window))}内最多记录 ${sum.per_rule} 条告警，其余重复命中只累加计数；最多保留最近 ${num(sum.max_alerts)} 条。当前列表最多显示 300 条。</span>`;
  const rows = list.map((a) => `<tr>
    <td class="nowrap muted">${esc(fmtShort(a.time))}</td><td>${badge(a.severity)}</td>
    <td><b>${esc(a.name)}</b><div class="muted">${esc(a.category)} · ${esc(PHASE[a.phase] || a.phase)}</div></td>
    <td>${ipLink(a.src_ip)}<div class="muted">${esc(a.location || '')}</div></td>
    <td class="mono">${a.method ? esc(a.method) + ' ' : ''}${esc(a.target)}${a.status ? ` <span class="muted">[${a.status}]</span>` : ''}</td>
    <td>${resTag(a.result)}</td><td class="evidence">${esc(a.evidence)}</td></tr>`).join('');
  const none = drillState.alerts && meta.archive ? '内存中没有符合条件的告警（只保留最近的告警），可点击上方“在归档库中查询”查看更早的告警' : '暂无符合条件的告警';
  $('#alTable').innerHTML = `<thead><tr><th>时间</th><th>等级</th><th>攻击类型</th><th>来源</th><th>目标</th><th>结果研判</th><th>证据 / 载荷</th></tr></thead><tbody>${rows || empty(7, none)}</tbody>`;
}
let alDebounce;
$('#alSearch').addEventListener('input', () => { clearTimeout(alDebounce); alDebounce = setTimeout(loadAlerts, 300); });
['#alSev', '#alCat', '#alResult', '#alKind'].forEach((s) => $(s).addEventListener('change', loadAlerts));

// ---------------- 历史告警（PostgreSQL 归档，可选） ----------------
let alMode = 'live';
const HS_PAGE = 100;
const hs = { offset: 0, key: '', stats: null, inited: false, seq: 0 };
// toInput 把时刻转换为 datetime-local 控件的值（按展示时区，与服务端解析时区一致）
const toInput = (d) => { const p = timeParts(d); return `${p.y}-${p.mo}-${p.d}T${p.h}:${p.mi}`; };
function setAlertMode(m) {
  alMode = m === 'history' && meta.archive ? 'history' : 'live';
  $$('#alMode button').forEach((b) => { b.classList.toggle('active', b.dataset.m === alMode); b.setAttribute('aria-selected', b.dataset.m === alMode); });
  $('#alLive').hidden = alMode !== 'live';
  $('#alHistory').hidden = alMode !== 'history';
  $('#alModeHint').textContent = alMode === 'live'
    ? '内存中最近的告警，实时更新'
    : '归档在 PostgreSQL 中的全部告警，可按时间、IP / 网段、规则等条件检索与导出';
}
$$('#alMode button').forEach((b) => b.addEventListener('click', () => {
  setAlertMode(b.dataset.m);
  loaders.alerts();
}));
function hsRange(days) {
  $$('#hsRange button').forEach((b) => b.classList.toggle('active', b.dataset.d === String(days)));
  $('#hsTo').value = '';
  $('#hsFrom').value = days === 'all' ? '' : toInput(new Date(Date.now() - days * 86400e3));
}
function fillHistFilters() {
  const cat = $('#hsCat');
  if (cat.options.length <= 1 && lastOverview) (lastOverview.categories || []).forEach((c) => cat.add(new Option(c.name, c.name)));
  const res = $('#hsResult');
  if (res.options.length <= 1) Object.entries(RESULT).forEach(([k, v]) => res.add(new Option(v, k)));
  const ph = $('#hsPhase');
  if (ph.options.length <= 1) PHASES.forEach((p) => ph.add(new Option(PHASE[p], p)));
  if (!hs.inited) { hs.inited = true; hsRange(7); }
}
// openHistoryFromDrill 按实时告警的下钻条件在归档库中查询（时间段、阶段、目标与列表自带的筛选项）
function openHistoryFromDrill() {
  fillHistFilters();
  const p = drillParams('alerts');
  $('#hsIP').value = '';
  $('#hsRule').value = '';
  $('#hsQ').value = p.target || $('#alSearch').value.trim();
  $('#hsPhase').value = p.phase || '';
  $('#hsSev').value = $('#alSev').value;
  $('#hsCat').value = $('#alCat').value;
  $('#hsResult').value = $('#alResult').value;
  $('#hsKind').value = $('#alKind').value;
  if (p.from) {
    $$('#hsRange button').forEach((b) => b.classList.remove('active'));
    $('#hsFrom').value = toInput(new Date(p.from * 1000));
    // datetime-local 精确到分钟：结束时间向上取整，避免漏掉该分钟内的告警
    $('#hsTo').value = p.to ? toInput(new Date(Math.ceil(p.to / 60) * 60000)) : '';
  } else hsRange(30);
  setAlertMode('history');
  loadHistory(true);
}
function hsParams() {
  const p = new URLSearchParams();
  const from = $('#hsFrom').value;
  // “全部”：从很早的时间开始查询（服务端未指定开始时间时默认最近 7 天）
  p.set('from', from || '2000-01-01T00:00');
  if ($('#hsTo').value) p.set('to', $('#hsTo').value);
  for (const [k, id] of [['ip', '#hsIP'], ['rule', '#hsRule'], ['q', '#hsQ'], ['severity', '#hsSev'], ['category', '#hsCat'], ['result', '#hsResult'], ['kind', '#hsKind'], ['phase', '#hsPhase']]) {
    const v = $(id).value.trim();
    if (v) p.set(k, v);
  }
  return p;
}
// hsCheck 在提交前校验输入，错误时提示并返回 false
function hsCheck() {
  const ip = $('#hsIP').value.trim();
  const bad = ip && !/^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(ip);
  $('#hsIP').classList.toggle('invalid', !!bad);
  const from = $('#hsFrom').value, to = $('#hsTo').value;
  let msg = bad ? 'IP 或网段格式无效，例如 203.0.113.7、10.0.0.0/8、2001:db8::/32' : '';
  if (!msg && from && to && to <= from) msg = '结束时间必须晚于开始时间';
  $('#hsMsg').textContent = msg;
  return !msg;
}
async function loadHistory(reset) {
  fillHistFilters();
  if (!hsCheck()) return;
  const p = hsParams();
  const key = p.toString();
  if (reset || key !== hs.key) hs.offset = 0;
  const needStats = key !== hs.key || !hs.stats || reset;
  hs.key = key;
  const seq = ++hs.seq; // 只渲染最后一次查询的结果，避免慢查询覆盖新结果
  $('#hsSubmit').setAttribute('disabled', '');
  $('#hsCount').textContent = '查询中…';
  try {
    const page = new URLSearchParams(p);
    page.set('limit', HS_PAGE);
    page.set('offset', hs.offset);
    const [list, st] = await Promise.all([api('/api/archive/alerts?' + page), needStats ? api('/api/archive/stats?' + p) : hs.stats]);
    if (seq !== hs.seq) return;
    hs.stats = st;
    $('#hsMsg').textContent = '';
    renderHistStats(st, p);
    renderHistTable(list);
  } catch (e) {
    if (seq !== hs.seq) return;
    hs.key = ''; // 失败后重新查询时刷新统计
    $('#hsCount').textContent = '';
    $('#hsMsg').textContent = e.code === 'archive_unavailable' ? '归档数据库暂不可用：' + e.message : e.message;
    if (e.code === 'archive_disabled') { meta.archive = false; $('#alModeBar').hidden = true; setAlertMode('live'); }
  } finally {
    if (seq === hs.seq) $('#hsSubmit').removeAttribute('disabled');
  }
}
function renderHistStats(st, p) {
  const sev = st.by_severity || {};
  const from = p.get('from').startsWith('2000-') ? '全部' : p.get('from').replace('T', ' ');
  $('#hsRangeText').textContent = `${from} ~ ${(p.get('to') || '现在').replace('T', ' ')}`;
  const chips = (items, attr, fmt) => (items || []).map((x) => `<span class="chip clickable" ${attr}="${esc(x.name)}" title="点击按此筛选">${fmt(x)}</span>`).join('') || '<span class="muted">-</span>';
  $('#hsSummary').innerHTML = st.total
    ? `<div><span class="hs-total">${num(st.total)}</span>条告警
        <span class="muted">${esc(fmtTime(st.first_seen))} ~ ${esc(fmtTime(st.last_seen))}</span></div>
      <div class="hs-sev">${['critical', 'high', 'medium', 'low', 'info'].filter((l) => sev[l]).map((l) => `<span>${badge(l)} <b>${num(sev[l])}</b></span>`).join('')}</div>
      <div class="hs-sub">来源 IP TOP 10</div><div>${chips(st.top_ips, 'data-hip', (x) => `${esc(x.name)}${x.label ? ` <span class="muted">${esc(x.label)}</span>` : ''} · ${num(x.count)}`)}</div>
      <div class="hs-sub">命中规则 TOP 10</div><div>${chips(st.top_rules, 'data-hrule', (x) => `${esc(x.label || x.name)} · ${num(x.count)}`)}</div>`
    : '<div class="empty">该条件下没有历史告警</div>';
  const days = st.trend || [];
  hs.trend = days;
  hs.bucket = st.bucket;
  $('#hsTrendUnit').textContent = { hour: '按小时', day: '按天', month: '按月' }[st.bucket] || '';
  chart('cHsDay').setOption({
    tooltip: { ...baseTooltip, trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (ps) => `${esc(days[ps[0].dataIndex]?.name || '')}：${num(ps[0].value)} 条${hintLine('点击缩小到该时段')}` },
    grid: { left: 8, right: 16, top: 12, bottom: 4, containLabel: true },
    xAxis: { type: 'category', triggerEvent: true, data: days.map((d) => (st.bucket === 'month' ? d.name : d.name.slice(5))), axisLabel: { color: TEXT, fontSize: 10 }, axisLine: { lineStyle: { color: GRID_LINE } }, axisTick: { show: false } },
    yAxis: { type: 'value', minInterval: 1, axisLabel: { color: TEXT, fontSize: 10 }, splitLine: { lineStyle: { color: GRID_LINE } } },
    series: [{ type: 'bar', name: '告警数', data: days.map((d) => d.count), barMaxWidth: 18,
      itemStyle: { borderRadius: [3, 3, 0, 0], color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: '#36cfc9' }, { offset: 1, color: '#1d4f8f' }]) } }],
    graphic: days.length ? [] : [{ type: 'text', left: 'center', top: 'middle', style: { text: '暂无数据', fill: TEXT, fontSize: 12 } }],
  }, true);
}
// 历史趋势图：点击某个时段，把查询时间范围缩小到该小时 / 天 / 月
chartSetup.cHsDay = (c) => c.on('click', (x) => {
  const d = hs.trend?.[x.dataIndex ?? (x.componentType === 'xAxis' ? hs.trend.findIndex((t) => t.name.endsWith(x.value)) : -1)];
  if (!d) return;
  const m = /^(\d{4})-(\d{2})(?:-(\d{2})(?: (\d{2}))?)?/.exec(d.name);
  if (!m) return;
  // 时段名称是展示时区下的本地时间，用 UTC 运算避免浏览器时区影响
  const start = Date.UTC(+m[1], +m[2] - 1, +(m[3] || 1), +(m[4] || 0));
  const e = new Date(start);
  if (hs.bucket === 'hour') e.setUTCHours(e.getUTCHours() + 1);
  else if (hs.bucket === 'month') e.setUTCMonth(e.getUTCMonth() + 1);
  else e.setUTCDate(e.getUTCDate() + 1);
  const fmt = (t) => new Date(t).toISOString().slice(0, 16);
  $('#hsFrom').value = fmt(start);
  $('#hsTo').value = fmt(e.getTime());
  $$('#hsRange button').forEach((b) => b.classList.remove('active'));
  loadHistory(true);
});
function renderHistTable(list) {
  const items = list.items || [];
  const rows = items.map((a) => `<tr>
    <td class="nowrap muted">${esc(fmtTime(a.time))}${a.instance ? `<div style="font-size:11px">${esc(a.instance)}</div>` : ''}</td><td>${badge(a.severity)}</td>
    <td><b>${esc(a.name)}</b><div class="muted">${esc(a.category || '-')}${a.phase ? ' · ' + esc(PHASE[a.phase] || a.phase) : ''}</div><div class="muted mono rule-id">${esc(a.rule_id)}</div></td>
    <td>${ipLink(a.src_ip)}<div class="muted">${esc(a.location || '')}</div></td>
    <td class="mono">${a.method ? esc(a.method) + ' ' : ''}${esc(a.target || '-')}${a.status ? ` <span class="muted">[${a.status}]</span>` : ''}</td>
    <td>${a.result ? resTag(a.result) : '-'}</td><td class="evidence">${esc(a.evidence || '')}</td></tr>`).join('');
  $('#hsTable').innerHTML = `<thead><tr><th>时间</th><th>等级</th><th>攻击类型 / 规则</th><th>来源</th><th>目标</th><th>结果研判</th><th>证据 / 载荷</th></tr></thead><tbody>${rows || empty(7, '没有符合条件的历史告警')}</tbody>`;
  const page = Math.floor(hs.offset / HS_PAGE) + 1;
  const total = hs.stats?.total ?? 0;
  const pages = Math.max(1, Math.ceil(Math.min(total, 100000 + HS_PAGE) / HS_PAGE));
  $('#hsCount').textContent = items.length ? `第 ${num(hs.offset + 1)} ~ ${num(hs.offset + items.length)} 条，共 ${num(total)} 条` : '';
  $('#hsPager').innerHTML = `<button type="button" class="btn" id="hsPrev" ${page <= 1 ? 'disabled' : ''}>上一页</button><span class="muted">${page} / ${num(pages)}</span>`
    + `<button type="button" class="btn" id="hsNext" ${list.has_more && hs.offset + HS_PAGE <= 100000 ? '' : 'disabled'}>下一页</button>`;
  $('#hsPrev').onclick = () => { hs.offset = Math.max(0, hs.offset - HS_PAGE); loadHistory(false); };
  $('#hsNext').onclick = () => { hs.offset += HS_PAGE; loadHistory(false); };
}
$('#hsForm').addEventListener('submit', (e) => { e.preventDefault(); loadHistory(true); });
$$('#hsRange button').forEach((b) => b.addEventListener('click', () => { hsRange(b.dataset.d === 'all' ? 'all' : +b.dataset.d); loadHistory(true); }));
['#hsFrom', '#hsTo'].forEach((s) => $(s).addEventListener('change', () => $$('#hsRange button').forEach((b) => b.classList.remove('active'))));
['#hsSev', '#hsCat', '#hsResult', '#hsKind', '#hsPhase'].forEach((s) => $(s).addEventListener('change', () => loadHistory(true)));
$('#hsIP').addEventListener('input', () => { $('#hsIP').classList.remove('invalid'); });
$('#hsReset').addEventListener('click', () => {
  ['#hsIP', '#hsRule', '#hsQ', '#hsSev', '#hsCat', '#hsResult', '#hsKind', '#hsPhase'].forEach((s) => { $(s).value = ''; });
  hsRange(7);
  loadHistory(true);
});
$('#hsSummary').addEventListener('click', (e) => {
  const c = e.target.closest('[data-hip],[data-hrule]');
  if (!c) return;
  if (c.dataset.hip) $('#hsIP').value = c.dataset.hip;
  else $('#hsRule').value = c.dataset.hrule;
  loadHistory(true);
});
$('#hsExport').addEventListener('click', () => {
  if (!hsCheck()) return;
  const total = hs.stats?.total ?? 0;
  if (total > 200000 && !confirm(`符合条件的告警共 ${num(total)} 条，单次最多导出最近的 20 万条。继续导出？`)) return;
  const a = document.createElement('a');
  a.href = '/api/archive/export?' + hsParams();
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
});
// openHistory 从 IP 详情等处跳转到历史告警并按 IP 查询最近 90 天
function openHistory(ip) {
  fillHistFilters();
  ['#hsRule', '#hsQ', '#hsSev', '#hsCat', '#hsResult', '#hsKind', '#hsPhase'].forEach((s) => { $(s).value = ''; });
  $('#hsIP').value = ip;
  hsRange(90);
  setAlertMode('history');
  closeDrawer();
  switchTab('alerts');
}

// ---------------- 攻击面分析 ----------------
async function loadSurface() {
  const s = await api('/api/surface');
  gauge('cSurfaceGauge', s.score, '风险指数');
  pie('cWaf', [{ name: '已拦截', value: s.exploit_blocked, itemStyle: { color: '#52c41a' } }, { name: '未拦截/到达后端', value: s.exploit_passed, itemStyle: { color: '#ff7a45' } }]);
  barChart('cPorts', (s.top_ports || []).slice(0, 10), ['#7a2a2a', '#ff4d4f']);
  $('#techChips').innerHTML = ((s.tech || []).map((t) => `<span class="chip">${esc(t.name)} · ${t.value}</span>`).join('') || '<span class="muted">暂无</span>')
    + '<br>' + (s.hosts || []).map((h) => `<span class="chip">站点 ${esc(h.name)} · ${num(h.value)} 次</span>`).join('');
  const sc = s.severity_count || {};
  $('#findingCount').textContent = `共 ${(s.findings || []).length} 项 · 严重 ${sc.critical || 0} · 高危 ${sc.high || 0} · 中危 ${sc.medium || 0}`;
  $('#findings').innerHTML = (s.findings || []).slice(0, 120).map((f) => `<div class="finding" style="border-left-color:${LV_COLOR[f.severity]}">
      <div class="ft">${badge(f.severity)}<span>${esc(f.title)}</span><span class="spacer"></span><span class="muted">${esc(f.category)} · ${num(f.count)} 次</span></div>
      <div class="asset">${esc(f.asset)}</div><div class="ev">${esc(f.evidence)}</div>
      <div class="fix">处置建议：${esc(f.remediation)}</div>
      <div class="muted" style="font-size:11px">${esc(fmtShort(f.first_seen))} ~ ${esc(fmtShort(f.last_seen))}</div></div>`).join('') || '<div class="empty">未发现明显暴露面风险</div>';
  $('#svcTable').innerHTML = `<thead><tr><th>目标</th><th>服务</th><th>风险</th><th>公网放行</th><th class="num">放行/拦截</th><th class="num">来源数</th><th>最近</th></tr></thead><tbody>${
    (s.services || []).map((v) => `<tr><td class="mono">${esc(v.dst_ip || '*')}:${v.port}/${esc(v.proto)}</td><td>${esc(v.name)}</td><td>${badge(v.risk)}</td>
      <td>${v.exposed ? '<span class="res-success">是</span>' : '<span class="muted">否</span>'}</td><td class="num">${num(v.allowed)} / ${num(v.denied)}</td>
      <td class="num">${num(v.sources)}</td><td class="muted nowrap">${esc(fmtShort(v.last_seen))}</td></tr>`).join('') || empty(7)}</tbody>`;
  $('#epTable').innerHTML = `<thead><tr><th>站点</th><th>路径</th><th>方法</th><th class="num">访问</th><th class="num">攻击</th><th class="num">攻击者</th><th>状态码</th><th>标记</th></tr></thead><tbody>${
    (s.endpoints || []).map((e) => `<tr><td>${esc(e.host)}</td><td class="mono">${esc(e.path)}</td><td class="nowrap">${esc(Object.keys(e.methods || {}).join(','))}</td>
      <td class="num">${num(e.hits)}</td><td class="num">${e.attacks ? `<span class="lv-high">${num(e.attacks)}</span>` : 0}</td><td class="num">${num(e.attackers)}</td>
      <td class="nowrap muted">${esc(sortedEntries(e.status, 3).map(([k, v]) => `${k}:${v}`).join(' '))}</td>
      <td>${e.sensitive ? `<span class="chip warn">${esc(e.sensitive)}</span>` : ''}${(e.tech || []).map((t) => `<span class="chip">${esc(t)}</span>`).join('')}</td></tr>`).join('') || empty(8)}</tbody>`;
}

// ---------------- 数据源 ----------------
const SRC_STATUS = { tailing: '实时跟踪', reading: '读取中', done: '已完成', waiting: '等待文件', listening: '监听中', error: '错误', starting: '启动中' };
async function loadSources() {
  const r = await api('/api/sources');
  const rt = r.runtime || {};
  $('#procCount').textContent = `已处理 ${num(r.processed)} 条事件 · 运行 ${rt.uptime || '-'} · 内存 ${rt.heap_mb ?? '-'} MB · 待溯源 ${r.geo_pending ?? 0}`;
  $('#srcTable').innerHTML = `<thead><tr><th>名称</th><th>路径/地址</th><th>配置类型</th><th>自动识别格式</th><th>状态</th><th class="num">行数</th><th class="num">解析成功</th><th class="num">失败</th><th>最近事件时间</th><th>最近失败样例</th></tr></thead><tbody>${
    (r.sources || []).map((s) => `<tr><td>${esc(s.name)}</td><td class="mono">${esc(s.path)}</td><td>${esc(s.type)}</td><td><span class="chip">${esc(s.detected || '-')}</span></td>
      <td>${esc(SRC_STATUS[s.status] || s.status)}${s.last_error ? `<div class="lv-high" style="font-size:11px">${esc(s.last_error)}</div>` : ''}${s.time_offset
        ? `<div class="lv-medium" style="font-size:11px" title="日志时间与实际时间相差整时区，已自动校正。通常是日志产生方（服务器 / 设备）按 UTC 等其他时区记录，而 timezone 配置为 ${esc(meta.timezone || '本地时区')}。可将日志产生方的时区改为一致，或忽略（已自动校正）。">时区已自动校正 ${esc(s.time_offset)}</div>` : ''}</td>
      <td class="num">${num(s.lines)}</td><td class="num">${num(s.parsed)}</td><td class="num">${s.failed ? `<span class="lv-medium">${num(s.failed)}</span>` : 0}</td>
      <td class="nowrap muted">${esc(fmtShort(s.last_event))}</td><td class="evidence">${esc(s.sample_failed || '')}</td></tr>`).join('') || empty(10, '未配置数据源')}</tbody>`;
  const sl = r.syslog || {};
  $('#caps').innerHTML = `<div class="kv">
    <div class="k">IP 溯源数据源</div><div>${(meta.geo_providers || []).map((p) => `<span class="chip">${esc(SRC[p] || p)}</span>`).join('') || '<span class="lv-high">未配置</span>'}</div>
    <div class="k">WHOIS / RDAP</div><div>${meta.rdap ? '已启用（IP 详情中按需查询）' : '未启用'}</div>
    <div class="k">特征规则</div><div>${meta.rules} 条 + 行为检测（CC / 目录扫描 / 暴力破解 / 端口扫描 / 主机探测 / 洪水）</div>
    <div class="k">时区</div><div>${esc(meta.timezone || '服务器本地时区')}${meta.time_correction ? ' · <span class="muted">实时日志与实际时间相差整时区时自动校正（time_correction: auto）</span>' : ' · <span class="muted">未开启时区自动校正</span>'}</div>
    <div class="k">Syslog 接收</div><div>${sl.enabled ? `UDP ${esc(sl.udp || '-')} · TCP ${esc(sl.tcp || '-')}` : '未启用'}</div>
    <div class="k">告警归档</div><div>${meta.archive ? 'PostgreSQL（历史告警可在“告警事件 → 历史告警”中查询与导出）' : '未启用 <span class="muted">（配置 archive.dsn 后可长期留存与检索历史告警）</span>'}</div>
    <div class="k">支持的日志格式</div><div>nginx/Apache combined、main(XFF)、vhost、JSON、自定义 log_format；iptables/UFW/firewalld、pfSense/OPNsense、Windows 防火墙、Cisco ASA、FortiGate/华为/H3C/深信服等 key=value、JSON 防火墙日志</div>
    <div class="k">日志时区</div><div>${esc(meta.timezone || '系统时区')}</div>
    <div class="k">版本</div><div>netsa ${esc(meta.version)} · ${esc(rt.go || '')} · 启动于 ${esc(fmtTime(meta.started))}</div></div>`;
  if (meta.archive) await loadArchiveStatus();
}
const fmtBytes = (b) => (b >= 1 << 30 ? (b / (1 << 30)).toFixed(2) + ' GB' : b >= 1 << 20 ? (b / (1 << 20)).toFixed(1) + ' MB' : Math.round(b / 1024) + ' KB');
async function loadArchiveStatus() {
  const st = await api('/api/archive/status');
  $('#arcPanel').hidden = false;
  const conn = st.connected ? '<span class="nt-on">● 已连接</span>' : '<span class="lv-high">● 未连接（后台自动重试，期间告警在内存队列中缓冲）</span>';
  $('#arcSummary').textContent = `${st.server || ''} · 保留 ${st.retention_months < 0 ? '永久' : st.retention_months + ' 个月'}`;
  const errRecent = st.last_error && !zero(st.last_error_at) && (zero(st.last_write) || st.last_error_at > st.last_write);
  const parts = (st.partitions || []).map((p) => `<tr><td class="mono">${esc(p.name)}</td>
    <td class="nowrap">${p.default ? '<span class="muted">默认分区（超出月分区范围的数据）</span>' : `${esc(fmtTime(p.from).slice(0, 10))} ~ ${esc(fmtTime(p.to).slice(0, 10))}`}</td>
    <td class="num">${num(p.rows)}</td><td class="num">${esc(fmtBytes(p.bytes))}</td></tr>`).join('');
  $('#arcBody').innerHTML = `<div class="arc-grid"><div class="kv">
      <div class="k">连接状态</div><div>${conn}</div>
      <div class="k">已写入</div><div>${num(st.written)} 条 <span class="muted">（本次启动以来）</span></div>
      <div class="k">待写入队列</div><div>${num(st.queued)} 条</div>
      <div class="k">丢弃</div><div>${st.dropped ? `<span class="lv-high">${num(st.dropped)} 条</span> <span class="muted">（队列满或数据无法写入）</span>` : '0'}</div>
      <div class="k">重复跳过</div><div>${num(st.duplicates)} 条 <span class="muted">（同一份日志被重复分析时，已归档的告警不会重复写入）</span></div>
      <div class="k">超出保留期</div><div>${num(st.expired)} 条 <span class="muted">（早于保留期的告警不写入）</span></div>
      <div class="k">写入失败批次</div><div>${st.failed_batches ? `<span class="lv-medium">${num(st.failed_batches)}</span>（已自动重试）` : '0'}</div>
      <div class="k">最近写入</div><div>${esc(fmtTime(st.last_write))}</div>
      ${st.last_error ? `<div class="k">最近错误</div><div class="${errRecent ? 'arc-err' : 'muted'}">${esc(fmtTime(st.last_error_at))} ${esc(st.last_error)}${errRecent ? '' : '（已恢复）'}</div>` : ''}
    </div>
    <div class="scroll"><table class="table"><thead><tr><th>分区</th><th>时间范围</th><th class="num">行数（估算）</th><th class="num">占用空间</th></tr></thead><tbody>${parts || empty(4, st.connected ? '暂无分区' : '未连接')}</tbody></table></div></div>`;
}
$$('.exports .btn[data-fmt]').forEach((b) => b.addEventListener('click', () => {
  window.location.href = `/api/export/blocklist?format=${b.dataset.fmt}&level=${$('#blLevel').value}`;
}));

// ---------------- IP 溯源详情 ----------------
const drawer = $('#drawer');
const mask = $('#drawerMask');
let miniChart = null;
function closeDrawer() { drawer.classList.remove('open'); mask.classList.remove('open'); }
$('#drawerClose').onclick = closeDrawer;
mask.onclick = closeDrawer;
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!$('#pwModal').hidden) { if (!pwForced) closePasswordForm(); return; }
  if (!$('#userModal').hidden) { closeUserForm(); return; }
  if (!$('#ntModal').hidden) closeRobotForm();
  else closeDrawer();
});

async function openIP(ip) {
  let d;
  try { d = await api('/api/ip/' + encodeURIComponent(ip)); } catch (e) { return; }
  const s = d.summary;
  const p = d.profile;
  const g = p.geo || {};
  drawer.classList.add('open');
  mask.classList.add('open');
  const tags = Object.keys(p.tags || {}).map((t) => `<span class="chip">${esc(t)}</span>`).join('');
  const intel = (p.intel || []).map((t) => `<span class="chip warn">情报: ${esc(t)}</span>`).join('');
  $('#drawerTitle').innerHTML = `<div class="ipbig">${esc(ip)} ${badge(s.level)} <span style="font-size:14px">威胁评分 <b style="color:${LV_COLOR[s.level]}">${Math.round(s.score)}</b></span></div><div>${intel}${tags}</div>`;

  const loc = [g.country, g.province, g.city, g.district].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(' / ') || '未知';
  const coord = g.has_coord
    ? `${(+g.lat || 0).toFixed(4)}, ${(+g.lon || 0).toFixed(4)}${g.accuracy_km ? ` (±${g.accuracy_km} km)` : ''} <span class="muted">${esc(COORD[g.coord_source] || '')}</span>`
    : '<span class="muted">无（定位库中无该地址）</span>';
  const proxies = Object.keys(p.proxies || {});
  const sources = (g.sources || []).map((r) => `<tr><td>${esc(SRC[r.source] || r.source)}</td><td>${esc(r.country)}${r.country_code ? ` (${esc(r.country_code)})` : ''}</td><td>${esc(r.province || '-')}</td><td>${esc(r.city || '-')}${r.district ? ' ' + esc(r.district) : ''}</td><td>${esc(r.isp || r.as_org || '-')}</td><td>${r.asn ? 'AS' + r.asn : '-'}</td><td class="mono">${r.lat || r.lon ? `${r.lat.toFixed(3)}, ${r.lon.toFixed(3)}` : '-'}</td></tr>`).join('');

  const chainSteps = PHASES.map((ph) => {
    const c = (d.chain || []).find((x) => x.phase === ph);
    return `<div class="step ${c ? 'on' : ''}"><div>${PHASE[ph]}</div><div class="n">${c ? num(c.count) : 0}</div><div class="t">${c ? esc(fmtShort(c.first)) : '未出现'}</div></div>`;
  }).join('');
  const rules = (d.rules || []).map((r) => `<tr><td>${esc(r.name)}<div class="muted mono">${esc(r.id)}</div></td><td>${badge(r.severity)}</td><td>${num(r.count)}</td></tr>`).join('');
  const targets = sortedEntries(p.targets, 15).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${num(v)}</td></tr>`).join('');
  const ports = sortedEntries(p.ports, 30).map(([k, v]) => `<span class="chip">${esc(k)} × ${v}</span>`).join('');
  const status = sortedEntries(p.status, 10).map(([k, v]) => `<span class="chip">${esc(k)} × ${v}</span>`).join('');
  const uas = sortedEntries(p.uas, 8).map(([k, v]) => `<div class="mono">${esc(k)} <span class="muted">× ${v}</span></div>`).join('');
  const recent = (p.recent || []).slice().reverse().map((a) => `<tr><td class="nowrap muted">${esc(fmtShort(a.time))}</td><td>${badge(a.severity)} ${esc(a.name)}</td><td>${resTag(a.result)}</td><td class="mono">${esc(a.target)}</td><td class="evidence">${esc(a.evidence)}</td></tr>`).join('');

  const v6 = ip.includes(':');
  const advice = [];
  if (s.successes > 0) advice.push('存在疑似成功的攻击，请优先排查被攻击资产是否已失陷（检查进程、计划任务、WebShell 与异常外连）。');
  if ((s.categories || []).includes('暴力破解')) advice.push('存在暴力破解行为：检查相关账号登录记录，启用登录失败锁定与多因素认证。');
  if (g.hosting) advice.push('来源为 IDC/云主机，通常为被控肉鸡或攻击者租用的 VPS，可向其云厂商提交滥用投诉（见 WHOIS 中的 abuse 邮箱）。');
  if (g.proxy) advice.push('来源被标记为代理/VPN 出口，攻击者真实位置可能在其后方，需结合其他线索综合研判。');
  if (proxies.length) advice.push(`该 IP 经 ${proxies.join('、')} 转发，已根据 X-Forwarded-For 还原真实来源，封禁请在 CDN/WAF 或应用层基于真实 IP 进行。`);
  const rel = d.related;
  if (rel && rel.strong > 0) advice.push(`发现 ${rel.strong} 个强关联攻击源（疑似同一攻击者或团伙），建议与该 IP 一并处置。`);
  if (rel && rel.subnet_count >= 2) advice.push(`同网段 ${rel.subnet} 内另有 ${rel.subnet_count} 个攻击源，可考虑按网段封禁。`);
  advice.push(s.level === 'critical' || s.level === 'high' ? '建议立即封禁，并持续关注同网段/同 ASN 的关联攻击。' : '建议加入观察名单，若持续出现攻击行为再进行封禁。');
  const relRows = (rel?.related || []).map((r) => `<tr class="clickable" data-ip="${esc(r.ip)}"><td class="ip nowrap">${esc(r.ip)}</td>`
    + `<td class="nowrap">${scoreBar(r.score, r.score >= 60 ? 'high' : 'medium')}</td><td>${badge(r.level)}</td>`
    + `<td class="reasons">${r.reasons.map((x) => `<span class="chip">${esc(x)}</span>`).join('')}</td><td class="muted">${esc(r.location || '')}</td></tr>`).join('');
  const relHTML = rel ? `
    <h4>同源关联分析 <span class="muted" style="font-weight:400">比对 ${num(rel.scanned)} 个攻击源</span></h4>
    <div class="kv">
      <div class="k">所在网段</div><div><span class="mono">${esc(rel.subnet || '-')}</span> <span class="muted">同网段攻击源 ${num(rel.subnet_count)} 个</span></div>
      <div class="k">自治系统</div><div>${rel.asn ? `AS${rel.asn} <span class="muted">同 ASN 攻击源 ${num(rel.asn_count)} 个</span>` : '-'}</div>
      <div class="k">关联结论</div><div>${rel.strong
        ? `<b style="color:${LV_COLOR.high}">${rel.strong} 个强关联攻击源，疑似同一攻击者或团伙</b>`
        : relRows ? `${num(rel.total)} 个弱关联攻击源，需结合其他线索研判` : '未发现同源攻击者'}${rel.total > rel.related.length ? ` <span class="muted">（共 ${num(rel.total)} 个，列出关联度最高的 ${rel.related.length} 个）</span>` : ''}</div>
    </div>
    ${relRows ? `<div class="scroll"><table class="table"><thead><tr><th>IP</th><th>关联度</th><th>等级</th><th>关联依据</th><th>归属地</th></tr></thead><tbody>${relRows}</tbody></table></div>` : ''}` : '';

  $('#drawerBody').innerHTML = `
    <h4>溯源定位</h4>
    <div class="kv">
      ${g.label ? `<div class="k">所属网段</div><div><span class="chip warn">${esc(g.label)}</span>${g.private ? ' <span class="muted">内网攻击源</span>' : ''}</div>` : ''}
      <div class="k">归属地</div><div><b>${esc(loc)}</b></div>
      <div class="k">运营商</div><div>${esc(g.isp || '-')}</div>
      <div class="k">自治系统</div><div>${g.asn ? `AS${g.asn} ${esc(g.as_org || '')}` : '-'}</div>
      <div class="k">网络类型</div><div>${esc(g.net_type || '-')}</div>
      <div class="k">经纬度</div><div>${coord}</div>
      <div class="k">时区</div><div>${esc(g.timezone || '-')}</div>
      <div class="k">反向解析</div><div class="mono">${esc(g.rdns || '-')}</div>
      <div class="k">定位置信度</div><div>${esc(CONF[g.confidence] || '-')}${g.enriched ? '' : ' <span class="muted">（仅离线库，等级达到阈值后自动进行在线深度溯源）</span>'}</div>
      ${proxies.length ? `<div class="k">转发链路</div><div>经 <span class="mono">${esc(proxies.join(', '))}</span> 转发<div class="mono muted">X-Forwarded-For: ${esc(p.last_xff || '')}</div></div>` : ''}
    </div>
    ${(g.notes || []).map((n) => `<div class="note">• ${esc(n)}</div>`).join('')}
    <h4>多源定位比对</h4>
    <table class="table"><thead><tr><th>数据源</th><th>国家</th><th>省/州</th><th>城市</th><th>运营商/组织</th><th>ASN</th><th>坐标</th></tr></thead><tbody>${sources || empty(7)}</tbody></table>
    ${g.has_coord ? '<div class="chart mini-map" id="cMiniMap"></div>' : ''}
    <div style="margin-top:8px"><button type="button" class="btn" id="rdapBtn">查询 WHOIS / RDAP 注册信息</button></div>
    <div id="rdapBox"></div>

    <h4>攻击画像</h4>
    <div class="kv">
      <div class="k">首次出现</div><div>${esc(fmtTime(p.first_seen))}</div>
      <div class="k">最近活动</div><div>${esc(fmtTime(p.last_seen))}</div>
      <div class="k">事件统计</div><div>总计 ${num(p.events)} · Web 请求 ${num(p.web_reqs)} · 防火墙 ${num(p.fw_events)}（拒绝 ${num(p.denied)}）</div>
      <div class="k">攻击统计</div><div>攻击 ${num(p.attacks)} 次 · <span class="res-success">疑似成功 ${num(p.successes)}</span> · 结果分布 ${sortedEntries(p.results, 6).map(([k, v]) => `${esc(RESULT[k] || k)} ${v}`).join(' / ')}</div>
    </div>
    <h4>攻击链</h4><div class="chain">${chainSteps}</div>
    <h4>命中规则</h4><table class="table"><thead><tr><th>规则</th><th>等级</th><th>次数</th></tr></thead><tbody>${rules || empty(3)}</tbody></table>
    <h4>攻击目标 TOP</h4><table class="table"><thead><tr><th>目标</th><th>次数</th></tr></thead><tbody>${targets || empty(2)}</tbody></table>
    ${ports ? `<h4>探测端口</h4><div class="chips">${ports}</div>` : ''}
    ${status ? `<h4>响应状态码</h4><div class="chips">${status}</div>` : ''}
    ${uas ? `<h4>User-Agent</h4>${uas}` : ''}
    <h4>最近告警${meta.archive ? ' <button type="button" class="btn" id="hsFromIP" style="margin-left:8px;font-weight:400">查看全部历史告警（归档库）</button>' : ''}</h4><div class="scroll"><table class="table"><thead><tr><th>时间</th><th>规则</th><th>结果</th><th>目标</th><th>证据</th></tr></thead><tbody>${recent || empty(5)}</tbody></table></div>
    ${relHTML}
    <h4>处置建议</h4>
    ${advice.map((a) => `<div class="note" style="color:#b7eb8f">• ${esc(a)}</div>`).join('')}
    <pre class="cmd"># Linux iptables
${v6 ? 'ip6tables' : 'iptables'} -I INPUT -s ${esc(ip)} -j DROP
# nginx
deny ${esc(ip)};
# firewalld
firewall-cmd --permanent --add-rich-rule='rule family="${v6 ? 'ipv6' : 'ipv4'}" source address="${esc(ip)}" drop' &amp;&amp; firewall-cmd --reload
# Windows
netsh advfirewall firewall add rule name="netsa-block-${esc(ip)}" dir=in action=block remoteip=${esc(ip)}</pre>`;

  if (miniChart) { miniChart.dispose(); miniChart = null; }
  if (g.has_coord) {
    // 国内地址使用中国地图（含省界与省名），境外使用世界地图
    const cn = g.world_name === 'China';
    try {
      await (cn ? registerMap('china', '/vendor/china/china.json') : registerMap('world', '/vendor/world.json'));
      miniChart = echarts.init($('#cMiniMap'));
      miniChart.setOption({
        geo: {
          map: cn ? 'china' : 'world', roam: true, center: [g.lon, g.lat], zoom: cn ? 3 : 5, silent: true,
          label: { show: cn, color: 'rgba(170,195,240,.6)', fontSize: 10 }, itemStyle: { areaColor: '#10244a', borderColor: '#2b4a80' },
        },
        series: [{
          type: 'effectScatter', coordinateSystem: 'geo', symbol: isExact(g.coord_source) ? 'circle' : 'emptyCircle',
          data: [{ value: [g.lon, g.lat], label: { show: true, formatter: g.label || g.city || g.province || g.country || '', position: 'right', color: '#fff' } }],
          symbolSize: 12, itemStyle: { color: LV_COLOR[s.level] }, rippleEffect: { scale: 4 },
        }],
      });
    } catch (e) { console.error(e); }
  }
  if ($('#hsFromIP')) $('#hsFromIP').onclick = () => openHistory(ip);
  $('#rdapBtn').onclick = async () => {
    const box = $('#rdapBox');
    box.innerHTML = '<div class="muted">查询中...</div>';
    try {
      const r = await api('/api/ip/' + encodeURIComponent(ip) + '/rdap');
      box.innerHTML = `<div class="kv" style="margin-top:8px">
        <div class="k">网络名称</div><div>${esc(r.name || '-')} <span class="muted">${esc(r.handle || '')}</span></div>
        <div class="k">地址范围</div><div class="mono">${esc(r.range)}</div>
        <div class="k">CIDR</div><div class="mono">${esc((r.cidr || []).join(', ') || '-')}</div>
        <div class="k">注册国家</div><div>${esc(r.country || '-')}</div>
        <div class="k">所属组织</div><div>${esc(r.org || '-')}</div>
        <div class="k">滥用投诉</div><div class="mono">${esc((r.abuse_email || []).join(', ') || '-')}</div>
        <div class="k">注册/更新</div><div>${esc(r.registered || '-')} / ${esc(r.updated || '-')}</div>
        <div class="k">描述</div><div>${esc((r.description || []).join(' '))}</div>
        <div class="k">数据来源</div><div>${esc(r.source)}</div></div>`;
    } catch (e) {
      box.innerHTML = `<div class="note">查询失败：${esc(e.message)}</div>`;
    }
  };
}

// ---------------- 告警推送 ----------------
const NT_TYPES = {
  dingtalk: {
    label: '钉钉', secret: true, ph: 'https://oapi.dingtalk.com/robot/send?access_token=…',
    help: '钉钉群 → 群设置 → 机器人 → 添加机器人 → 自定义，复制 Webhook 地址。安全设置选择「加签」时填写上方密钥；选择「自定义关键词」时填写“告警”。',
  },
  wecom: {
    label: '企业微信', secret: false, ph: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…',
    help: '企业微信群 → 右上角「…」→ 添加群机器人 → 新创建一个机器人，复制 Webhook 地址。企业微信机器人没有加签设置。',
  },
  feishu: {
    label: '飞书', secret: true, ph: 'https://open.feishu.cn/open-apis/bot/v2/hook/…',
    help: '飞书群 → 设置 → 群机器人 → 添加机器人 → 自定义机器人，复制 Webhook 地址。安全设置开启「签名校验」时填写上方密钥；开启「自定义关键词」时填写“告警”。',
  },
};
const ntState = { info: null, editing: null, type: 'dingtalk' };
const levelChips = (levels) => ['critical', 'high', 'medium'].filter((l) => (levels || []).includes(l)).map(badge).join(' ');

async function loadNotify() {
  const info = await api('/api/alert/robots');
  ntState.info = info;
  const on = info.robots.filter((r) => r.enabled).length;
  $('#ntCount').textContent = info.robots.length ? `共 ${info.robots.length} 个 · 启用 ${on} 个` : '';
  const rows = info.robots.map((r) => {
    const st = r.stats || {};
    const failing = !zero(st.last_error_at) && (zero(st.last_ok) || st.last_error_at > st.last_ok);
    const status = (r.enabled ? '<span class="nt-on">● 启用</span>' : '<span class="muted">○ 停用</span>')
      + (failing ? `<div class="nt-err" title="${esc(st.last_error)}">最近失败：${esc(st.last_error)}</div>` : '');
    const stats = `消息 ${num(st.messages || 0)} · 告警 ${num(st.events || 0)}${st.failed ? ` · <span class="nt-err-inline">失败 ${num(st.failed)}</span>` : ''}`
      + `<div class="muted">${zero(st.last_ok) ? '尚未成功推送' : '最近成功 ' + esc(fmtShort(st.last_ok))}${st.suppressed ? ` · 合并 ${num(st.suppressed)} 条` : ''}${st.queued ? ` · 待发送 ${st.queued}` : ''}</div>`;
    const ui = r.source === 'ui';
    const acts = !isAdmin() ? '<span class="muted">只读</span>' : `<button class="btn" data-act="test" data-id="${esc(r.id)}">测试</button>`
      + (ui ? ` <button class="btn" data-act="toggle" data-id="${esc(r.id)}">${r.enabled ? '停用' : '启用'}</button>`
        + ` <button class="btn" data-act="edit" data-id="${esc(r.id)}">编辑</button>`
        + ` <button class="btn danger" data-act="del" data-id="${esc(r.id)}">删除</button>`
        : ' <span class="chip" title="来自配置文件 alert.webhooks，请在配置文件中修改">配置文件</span>');
    return `<tr><td><b>${esc(r.name)}</b>${r.has_secret ? '<div class="muted">已启用加签</div>' : ''}</td>
      <td class="nowrap">${esc(r.type_label)}</td><td class="nowrap">${levelChips(r.levels)}</td>
      <td class="mono nt-url" title="${esc(r.url)}">${esc(r.url)}</td><td>${status}</td><td>${stats}</td><td class="nowrap num">${acts}</td></tr>`;
  }).join('');
  $('#ntTable').innerHTML = '<thead><tr><th>名称</th><th>类型</th><th>推送等级</th><th>Webhook</th><th>状态</th><th>推送统计</th><th class="num">操作</th></tr></thead>'
    + `<tbody>${rows || '<tr><td colspan="7" class="empty">尚未添加告警推送机器人，点击右上角「添加机器人」开始配置</td></tr>'}</tbody>`;
  const notes = [info.persist
    ? `界面中添加的机器人保存在 <span class="mono">${esc(info.file)}</span>（含 Webhook 令牌，文件权限 0600）。`
    : '<span class="nt-warn">未配置 storage.snapshot 或 alert.robots_file：界面中添加的机器人只保存在内存中，服务重启后需重新添加。</span>'];
  if (!info.base_url) notes.push('在配置文件中设置 <span class="mono">alert.base_url</span>（大屏访问地址）后，告警消息将附带“查看溯源详情”链接。');
  $('#ntNote').innerHTML = notes.join('<br>');
  $('#ntRules').innerHTML = `<ul>
    <li><b>推送内容</b>：等级在所选范围内的告警事件，包括规则名称、研判结果（疑似成功会特别标注）、来源 IP 与归属地、攻击目标、攻击证据与威胁评分；以及攻击源因多次攻击累积导致的威胁等级升级。</li>
    <li><b>去重</b>：同一 IP、同一规则、同一研判结果在 ${esc(fmtDur(info.dedup_window))}内只推送一次（<span class="mono">alert.dedup_window</span>）。</li>
    <li><b>合并</b>：2 秒内的多条告警合并为一条消息，最多逐条列出 10 条。</li>
    <li><b>限速</b>：钉钉、企业微信每个机器人每分钟最多 18 条，飞书 60 条（低于平台限制）；超出部分在下一条消息中汇总为“另有 N 条”，不会静默丢失。</li>
    <li><b>失败重试</b>：网络错误或平台限流时 10 秒后自动重试一次；失败原因显示在机器人状态中。</li>
    <li><b>安全</b>：日志中的攻击载荷与链接已做转义，不会在群聊中显示为可点击的链接或图片；界面只允许填写钉钉、企业微信、飞书的官方 Webhook 地址，令牌与密钥不会回显到页面。</li>
  </ul>`;
  $('#ntHistory').innerHTML = `<thead><tr><th>时间</th><th>机器人</th><th>内容</th><th>结果</th></tr></thead><tbody>${info.history.map((h) => `<tr>
    <td class="nowrap muted">${esc(fmtShort(h.time))}</td><td class="nowrap">${esc(h.robot)}</td><td>${esc(h.title)}${h.events > 1 ? ` <span class="muted">(${h.events} 条)</span>` : ''}</td>
    <td>${h.ok ? '<span class="nt-on">成功</span>' : `<span class="nt-err-inline">失败</span><div class="muted">${esc(h.error)}</div>`}</td></tr>`).join('') || empty(4, '暂无推送记录')}</tbody>`;
}

function ntSetType(t) {
  ntState.type = t;
  const cfg = NT_TYPES[t];
  $$('#ntType button').forEach((b) => b.classList.toggle('active', b.dataset.t === t));
  $('#ntSecretRow').hidden = !cfg.secret;
  $('#ntHelp').textContent = cfg.help;
  const ed = ntState.editing;
  $('#ntUrl').placeholder = ed ? `已保存：${ed.url}（不修改请留空）` : cfg.ph;
  $('#ntUrlHint').textContent = ed ? '' : `只能填写${cfg.label}官方机器人地址；私有化部署等其他地址请在配置文件 alert.webhooks 中配置。`;
}

function ntMsg(text, ok) {
  const m = $('#ntMsg');
  m.textContent = text || '';
  m.className = 'form-msg' + (text ? (ok ? ' ok' : ' err') : '');
}

function openRobotForm(r) {
  rememberFocus();
  ntState.editing = r || null;
  $('#ntFormTitle').textContent = r ? `编辑机器人 · ${r.name}` : '添加告警推送机器人';
  $('#ntName').value = r ? r.name : '';
  $('#ntUrl').value = '';
  $('#ntSecret').value = '';
  $('#ntSecret').placeholder = r && r.has_secret ? '已设置（不修改请留空）' : '机器人安全设置选择“加签”时填写，以 SEC 开头';
  $('#ntClearRow').hidden = !(r && r.has_secret);
  $('#ntClear').checked = false;
  const levels = r ? r.levels : ['critical', 'high'];
  $$('#ntLevels input').forEach((c) => { c.checked = levels.includes(c.value); });
  $('#ntEnabled').checked = r ? r.enabled : true;
  $$('#ntType button').forEach((b) => { b.disabled = !!r; }); // 编辑时不能更改类型
  ntSetType(r ? r.type : 'dingtalk');
  ntMsg('');
  $('#ntModal').hidden = false;
  $('#ntName').focus();
}

function closeRobotForm() {
  $('#ntModal').hidden = true;
  ntState.editing = null;
}

function ntCollect() {
  return {
    name: $('#ntName').value.trim(), type: ntState.type, url: $('#ntUrl').value.trim(),
    secret: NT_TYPES[ntState.type].secret ? $('#ntSecret').value.trim() : '', clear_secret: $('#ntClear').checked,
    levels: $$('#ntLevels input').filter((c) => c.checked).map((c) => c.value), enabled: $('#ntEnabled').checked,
  };
}

function ntCheck(f) {
  if (!f.levels.length) return '请至少选择一个推送等级';
  if (!ntState.editing && !f.url) return '请填写 Webhook 地址';
  return '';
}

async function ntBusy(btn, fn) {
  btn.disabled = true;
  try { await fn(); } finally { btn.disabled = false; }
}

$('#ntAdd').addEventListener('click', () => openRobotForm(null));
$('#ntClose').addEventListener('click', closeRobotForm);
$('#ntCancel').addEventListener('click', closeRobotForm);
$('#ntModal').addEventListener('mousedown', (e) => { if (e.target.id === 'ntModal') closeRobotForm(); });
$$('#ntType button').forEach((b) => b.addEventListener('click', () => ntSetType(b.dataset.t)));
$('#ntForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = ntCollect();
  const bad = ntCheck(f);
  if (bad) { ntMsg(bad); return; }
  ntBusy($('#ntSave'), async () => {
    try {
      const ed = ntState.editing;
      const r = ed ? await api('/api/alert/robots/' + encodeURIComponent(ed.id), 'PUT', f) : await api('/api/alert/robots', 'POST', f);
      if (r.warning) alert('配置已生效，但' + r.warning);
      closeRobotForm();
      loadNotify().catch(console.error);
    } catch (err) { ntMsg(err.message); }
  });
});
$('#ntTest').addEventListener('click', () => {
  const f = ntCollect();
  const bad = ntCheck(f);
  if (bad) { ntMsg(bad); return; }
  ntMsg('正在发送测试消息…', true);
  ntBusy($('#ntTest'), async () => {
    try {
      const ed = ntState.editing;
      const r = await api(ed ? `/api/alert/robots/${encodeURIComponent(ed.id)}/test` : '/api/alert/test', 'POST', f);
      ntMsg(r.ok ? '测试消息已发送，请在群中查看。' : '发送失败：' + r.error, r.ok);
      loadNotify().catch(console.error);
    } catch (err) { ntMsg(err.message); }
  });
});
$('#ntTable').addEventListener('click', async (e) => {
  const b = e.target.closest('button[data-act]');
  const r = b && ntState.info.robots.find((x) => x.id === b.dataset.id);
  if (!r) return;
  const path = '/api/alert/robots/' + encodeURIComponent(r.id);
  try {
    switch (b.dataset.act) {
      case 'edit':
        openRobotForm(r);
        return;
      case 'test':
        await ntBusy(b, async () => {
          const res = await api(path + '/test', 'POST');
          alert(res.ok ? `测试消息已发送到「${r.name}」，请在群中查看。` : `发送到「${r.name}」失败：${res.error}`);
        });
        break;
      case 'toggle':
        await api(path, 'PUT', { name: r.name, type: r.type, levels: r.levels, enabled: !r.enabled });
        break;
      case 'del':
        if (!confirm(`确定删除机器人「${r.name}」？删除后将不再向该群推送告警。`)) return;
        await api(path, 'DELETE');
        break;
      default:
        return;
    }
  } catch (err) { alert(err.message); }
  loadNotify().catch(console.error);
});

// ---------------- 账号与登录 ----------------
const ROLE = { admin: '管理员', viewer: '只读' };

function renderUserMenu() {
  if (!me.auth) return; // 未开启登录认证
  $('#userMenu').hidden = false;
  $('#userName').textContent = me.user;
  $('#userRole').textContent = ROLE[me.role] || me.role;
  $('#tabSystem').hidden = !isAdmin();
  $('#ntAdd').hidden = !isAdmin();
}

function toggleUserDrop(open) {
  const d = $('#userDrop');
  d.hidden = open === undefined ? !d.hidden : !open;
  $('#userBtn').setAttribute('aria-expanded', String(!d.hidden));
}
$('#userBtn').addEventListener('click', (e) => { e.stopPropagation(); toggleUserDrop(); });
document.addEventListener('click', (e) => { if (!e.target.closest('#userMenu')) toggleUserDrop(false); });
$('#menuPassword').addEventListener('click', () => { toggleUserDrop(false); openPasswordForm(false); });
$('#menuLogout').addEventListener('click', async () => {
  toggleUserDrop(false);
  try { await api('/api/auth/logout', 'POST'); } catch (_) { /* 已过期也直接回到登录页 */ }
  leaving = true;
  location.href = '/login.html';
});

// 修改密码；forced 为 true 时（初始密码 / 管理员重置后）不可关闭，修改成功后重新加载页面
let pwForced = false;
function openPasswordForm(forced) {
  if (!$('#pwModal').hidden && pwForced) return;
  rememberFocus();
  pwForced = !!forced;
  $('#pwTitle').textContent = forced ? '请设置新密码' : '修改密码';
  $('#pwForce').hidden = !forced;
  $('#pwClose').hidden = forced;
  $('#pwCancel').hidden = forced;
  $('#pwUser').value = me.user;
  ['#pwCurrent', '#pwNew', '#pwNew2'].forEach((s) => { $(s).value = ''; });
  $('#pwMsg').textContent = '';
  $('#pwMsg').className = 'form-msg';
  $('#pwModal').hidden = false;
  $('#pwCurrent').focus();
}
function closePasswordForm() { $('#pwModal').hidden = true; }
$('#pwClose').addEventListener('click', closePasswordForm);
$('#pwCancel').addEventListener('click', closePasswordForm);
$('#pwForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const cur = $('#pwCurrent').value;
  const next = $('#pwNew').value;
  const msg = (t, ok) => { $('#pwMsg').textContent = t; $('#pwMsg').className = 'form-msg ' + (ok ? 'ok' : 'err'); };
  if (!cur || !next) { msg('请填写当前密码与新密码'); return; }
  if (next !== $('#pwNew2').value) { msg('两次输入的新密码不一致'); return; }
  ntBusy($('#pwSave'), async () => {
    try {
      await api('/api/auth/password', 'POST', { current: cur, new: next });
      if (pwForced) { location.reload(); return; }
      msg('密码已修改，其他设备上的登录已失效', true);
      setTimeout(closePasswordForm, 1200);
    } catch (err) { msg(err.message); }
  });
});

// 系统管理：账号与登录记录（仅管理员）
let users = [];
async function loadSystem() {
  if (!isAdmin()) return;
  const [u, audit] = await Promise.all([api('/api/auth/users'), api('/api/auth/audit?limit=100')]);
  users = u.users || [];
  const admins = users.filter((x) => x.role === 'admin').length;
  $('#userCount').textContent = `共 ${users.length} 个 · 管理员 ${admins} 个`;
  $('#userTable').innerHTML = `<thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>最近登录</th><th>密码修改</th><th>创建时间</th><th class="num">操作</th></tr></thead><tbody>${users.map((x) => {
    const cfg = x.source === 'config';
    const self = x.name === u.me;
    const acts = cfg ? '<span class="chip" title="来自配置文件 server.username，请在配置文件中修改">配置文件</span>'
      : `<button class="btn" data-uact="reset" data-name="${esc(x.name)}">重置密码</button>`
        + ` <button class="btn" data-uact="role" data-name="${esc(x.name)}">${x.role === 'admin' ? '设为只读' : '设为管理员'}</button>`
        + ` <button class="btn danger" data-uact="del" data-name="${esc(x.name)}">删除</button>`;
    return `<tr><td><b>${esc(x.name)}</b>${self ? ' <span class="muted">（当前账号）</span>' : ''}</td>
      <td>${x.role === 'admin' ? '<span class="chip warn">管理员</span>' : '<span class="chip">只读</span>'}</td>
      <td>${x.must_change ? '<span class="nt-warn">待修改初始密码</span>' : '<span class="nt-on">正常</span>'}</td>
      <td class="nowrap muted">${esc(fmtShort(x.last_login))}</td><td class="nowrap muted">${esc(fmtShort(x.changed))}</td>
      <td class="nowrap muted">${esc(fmtShort(x.created))}</td><td class="nowrap num">${acts}</td></tr>`;
  }).join('')}</tbody>`;
  $('#auditTable').innerHTML = `<thead><tr><th>时间</th><th>账号</th><th>来源 IP</th><th>操作</th><th>结果</th><th>详情 / 客户端</th></tr></thead><tbody>${audit.map((a) => `<tr>
    <td class="nowrap muted">${esc(fmtShort(a.time))}</td><td>${esc(a.user)}</td><td class="mono">${esc(a.ip)}</td>
    <td class="nowrap">${esc(a.action || '登录')}</td>
    <td>${a.ok ? '<span class="nt-on">成功</span>' : `<span class="nt-err-inline">失败</span> <span class="muted">${esc(a.reason || '')}</span>`}</td>
    <td class="muted evidence">${esc(a.detail || a.agent || '')}</td></tr>`).join('') || empty(6, '暂无记录')}</tbody>`;
}

// 账号表单：mode 为 create（新增）或 reset（重置密码）
let ufMode = 'create';
let ufName = '';
let ufRole = 'viewer';
function setUfRole(r) {
  ufRole = r;
  $$('#ufRole button').forEach((b) => b.classList.toggle('active', b.dataset.r === r));
}
function openUserForm(mode, name) {
  rememberFocus();
  ufMode = mode;
  ufName = name || '';
  $('#userFormTitle').textContent = mode === 'create' ? '添加账号' : `重置密码 · ${name}`;
  $('#ufName').value = ufName;
  $('#ufName').disabled = mode !== 'create';
  $('#ufRole').parentElement.hidden = mode !== 'create';
  $('#ufPwLabel').textContent = mode === 'create' ? '初始密码' : '新密码';
  $('#ufHint').textContent = mode === 'create'
    ? '用户首次登录后须修改密码。至少 8 位，包含字母、数字、符号中的至少两类。'
    : '重置后该账号已登录的会话立即失效，下次登录须修改密码。';
  $('#ufPw').value = '';
  $('#ufMsg').textContent = '';
  setUfRole('viewer');
  $('#userModal').hidden = false;
  (mode === 'create' ? $('#ufName') : $('#ufPw')).focus();
}
function closeUserForm() { $('#userModal').hidden = true; }
$('#userAdd').addEventListener('click', () => openUserForm('create'));
$('#userClose').addEventListener('click', closeUserForm);
$('#userCancel').addEventListener('click', closeUserForm);
$$('#ufRole button').forEach((b) => b.addEventListener('click', () => setUfRole(b.dataset.r)));
$('#userForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const pw = $('#ufPw').value;
  const msg = (t) => { $('#ufMsg').textContent = t; $('#ufMsg').className = 'form-msg err'; };
  if (ufMode === 'create' && !$('#ufName').value.trim()) { msg('请填写用户名'); return; }
  if (!pw) { msg('请填写密码'); return; }
  ntBusy($('#userSave'), async () => {
    try {
      if (ufMode === 'create') await api('/api/auth/users', 'POST', { name: $('#ufName').value.trim(), role: ufRole, password: pw });
      else await api('/api/auth/users/' + encodeURIComponent(ufName), 'PUT', { password: pw });
      closeUserForm();
      loadSystem().catch(console.error);
    } catch (err) { msg(err.message); }
  });
});
$('#userTable').addEventListener('click', async (e) => {
  const b = e.target.closest('button[data-uact]');
  if (!b) return;
  const name = b.dataset.name;
  const u = users.find((x) => x.name === name);
  if (!u) return;
  const path = '/api/auth/users/' + encodeURIComponent(name);
  try {
    if (b.dataset.uact === 'reset') { openUserForm('reset', name); return; }
    if (b.dataset.uact === 'role') {
      const role = u.role === 'admin' ? 'viewer' : 'admin';
      if (!confirm(`确定将「${name}」设为${ROLE[role]}？该账号需重新登录后生效。`)) return;
      await api(path, 'PUT', { role });
    }
    if (b.dataset.uact === 'del') {
      if (!confirm(`确定删除账号「${name}」？其已登录的会话将立即失效。`)) return;
      await api(path, 'DELETE');
      if (name === me.user) { goLogin(); return; }
    }
  } catch (err) { alert(err.message); }
  loadSystem().catch(console.error);
});

// ---------------- 调度 ----------------
const loaders = {
  overview: () => Promise.all([loadOverview(), loadTrend(), loadMap(), loadTopAttackers()]).catch(console.error),
  attackers: () => loadAttackers().catch(console.error),
  alerts: () => (alMode === 'history' ? loadHistory(false) : loadAlerts()).catch(console.error),
  surface: () => loadSurface().catch(console.error),
  notify: () => loadNotify().catch(console.error),
  system: () => loadSystem().catch(console.error),
  sources: () => loadSources().catch(console.error),
};

$('#fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen().catch(() => {});
});
document.addEventListener('fullscreenchange', () => setTimeout(resizeCharts, 200));

(async function init() {
  // 先确认登录状态：未登录时 api() 会跳转登录页；使用初始密码时先强制修改密码
  try {
    const s = await api('/api/auth/session');
    if (!s.authenticated) { goLogin(); return; }
    me = { user: s.user, role: s.role, auth: s.auth_enabled, must_change: s.must_change };
  } catch (_) { return; }
  renderUserMenu();
  if (me.must_change) { openPasswordForm(true); return; }
  try { meta = await api('/api/meta'); } catch (e) { console.error(e); }
  setDisplayTimezone(meta.timezone);
  $('#alModeBar').hidden = !meta.archive;
  $('#clock').title = meta.timezone ? `时区：${meta.timezone}（与服务端配置一致）` : '时区：浏览器本地时区';
  initMapEvents();
  loaders.overview();
  loadFeed().catch(console.error);
  connectStream();
  openFromHash();
})();

// 告警消息中的“查看溯源详情”链接形如 /#ip=1.2.3.4，打开后直接显示该 IP 的溯源详情
function openFromHash() {
  const m = /^#ip=(.+)$/.exec(location.hash);
  if (!m) return;
  let ip = '';
  try { ip = decodeURIComponent(m[1]); } catch (_) { return; }
  if (/^[0-9a-fA-F.:]{2,45}$/.test(ip)) openIP(ip);
}
window.addEventListener('hashchange', openFromHash);

setInterval(() => {
  if (document.hidden) return;
  if (currentTab === 'overview') {
    loadOverview().catch(console.error);
    loadTrend().catch(console.error);
    loadTopAttackers().catch(console.error);
  } else if (currentTab === 'alerts' && alMode === 'live' && $('#alAuto').checked) {
    loadAlerts().catch(console.error);
  } else if (currentTab === 'notify' && $('#ntModal').hidden) {
    loadNotify().catch(console.error);
  } else if (currentTab === 'sources') {
    loadSources().catch(console.error);
  }
}, 5000);
setInterval(() => { if (!document.hidden && currentTab === 'overview') loadMap().catch(console.error); }, 15000);
