'use strict';
// AI 使用（风险管理 → AI 使用）：内网终端使用了哪些 AI 服务、用了多少、上传了多少数据，以及目录之外的疑似 AI 服务与 AI 接口。
// 与 app.js / ops.js 共用全局工具（$、api、esc、num、chart、segInit、openModal 等），在它们之后加载。

OPS_MODALS.push('auCatModal', 'auSvcModal', 'auSubjModal');
const au = { range: '7d', data: null, service: '', catalog: null, labels: { category: {}, region: {}, policy: {}, endpoint: {} } };
const auBytes = (b) => (!b ? '0' : b >= 1 << 30 ? (b / (1 << 30)).toFixed(2) + ' GB' : b >= 1 << 20 ? (b / (1 << 20)).toFixed(1) + ' MB' : b >= 1024 ? Math.round(b / 1024) + ' KB' : b + ' B');
const auPol = (p) => `<span class="au-pol ${esc(p || 'unset')}">${esc(au.labels.policy[p || ''] || '未设定')}</span>`;
const auRegion = (r) => `<span class="au-region ${esc(r)}">${esc(au.labels.region[r || ''] || '未知')}</span>`;
const auCat = (c) => esc(au.labels.category[c] || c);
const auSvc = (id) => (au.data?.report.services || []).find((s) => s.id === id);
const auSvcName = (id) => auSvc(id)?.name || id;
const auSince = (t) => (zero(t) ? '-' : esc(fmtShort(t)));

segInit('#auRange', (b) => { au.range = b.dataset.r; loadAIUse().catch(console.error); });
$('#auSearch').addEventListener('input', () => renderAUTables());
$('#auPolicy').addEventListener('change', () => renderAUTables());
$('#auExport').addEventListener('click', () => {
  window.open('/api/aiuse/export?' + new URLSearchParams({ range: au.range }), '_blank', 'noopener');
});

async function loadAIUse() {
  const r = await api('/api/aiuse?' + new URLSearchParams({ range: au.range }));
  if (!r.enabled) {
    au.data = null;
    $('#auNote').innerHTML = 'AI 使用统计未开启：在配置文件中设置 <code>ai_usage.enabled: true</code>（默认开启）后重启服务。';
    $('#auKpis').innerHTML = '';
    for (const id of ['auSvcTable', 'auSubjTable', 'auDeptTable', 'auCandTable', 'auEpTable']) $('#' + id).innerHTML = '';
    return;
  }
  au.data = r;
  au.labels = r.labels || au.labels;
  const rep = r.report;
  const t = rep.totals;
  const cv = rep.coverage || {};
  const notes = [];
  if (!cv.sni) notes.push('尚未接入 TLS 握手日志（如 Zeek ssl.log）：目前只按 DNS 查询统计，没有上传 / 下载量；不经过内网 DNS 的访问（DoH、浏览器内置解析）也看不到。');
  else if (!cv.bytes) notes.push('已接入 TLS 握手日志，但还没有会话日志（Zeek conn.log、防火墙会话日志）的字节数能归到 AI 服务，上传量暂不可用。');
  if (!r.assets) notes.push('在“资产漏洞”中按部门登记办公网段（如 10.1.10.0/24 → 研发部）或终端后，终端会显示使用者并按部门汇总。');
  if (cv.dropped) notes.push(`记录数达到上限（${num(cv.max_records)} 条），${num(cv.dropped)} 条没有记录，可调大 ai_usage.max_records。`);
  notes.push(`统计按域名识别，看不到对话内容；按天保留 ${num(cv.retention_days)} 天${cv.since ? `，最早记录 ${esc(cv.since)}` : ''}。目录中共 ${num(cv.services)} 个服务。`);
  $('#auNote').innerHTML = notes.map((n) => `<div>${n}</div>`).join('');
  const bytesTip = cv.bytes ? '' : ' title="需要 TLS 握手日志与会话日志"';
  $('#auKpis').innerHTML = `
    <div class="kpi"><span class="label">使用 AI 的终端</span><span class="value">${num(t.subjects)}</span><span class="sub">${esc(rep.from)} ~ ${esc(rep.to)}</span></div>
    <div class="kpi"><span class="label">AI 服务</span><span class="value">${num(t.services)}</span><span class="sub">新出现 ${num(t.new_services)}</span></div>
    <div class="kpi"><span class="label">使用境外服务的终端</span><span class="value ${t.overseas_subj ? 'lv-medium' : ''}">${num(t.overseas_subj)}</span><span class="sub"${bytesTip}>境外上传 ${cv.bytes ? auBytes(t.overseas_up) : '—'}</span></div>
    <div class="kpi"><span class="label">使用禁止类服务的终端</span><span class="value ${t.deny_subjects ? 'lv-critical' : ''}">${num(t.deny_subjects)}</span><span class="sub">策略在“服务目录”中设定</span></div>
    <div class="kpi"><span class="label">上传 / 下载</span><span class="value"${bytesTip}>${cv.bytes ? auBytes(t.up) : '—'}</span><span class="sub"${bytesTip}>下载 ${cv.bytes ? auBytes(t.down) : '—'}</span></div>
    <div class="kpi"><span class="label">被拦截的尝试</span><span class="value">${num(t.denied)}</span><span class="sub">DNS 拦截、握手未建立</span></div>`;
  renderAUCharts(rep, cv.bytes);
  renderAUTables();
}

function renderAUCharts(rep, bytes) {
  const days = rep.daily || [];
  const series = [{ name: '终端数', type: 'bar', data: days.map((d) => d.subjects), barMaxWidth: 18, itemStyle: { color: '#3a8bff', borderRadius: [3, 3, 0, 0] } }];
  if (bytes) {
    series.push({ name: '上传', type: 'line', yAxisIndex: 1, smooth: true, symbolSize: 5, data: days.map((d) => d.up), itemStyle: { color: '#36cfc9' } });
    series.push({ name: '境外上传', type: 'line', yAxisIndex: 1, smooth: true, symbolSize: 5, data: days.map((d) => d.overseas_up), itemStyle: { color: '#ff7a45' } });
  }
  const axis = { axisLabel: { color: TEXT, fontSize: 10 }, splitLine: { lineStyle: { color: GRID_LINE } } };
  chart('cAuTrend').setOption({
    tooltip: { ...baseTooltip, trigger: 'axis', formatter: (ps) => esc(ps[0].axisValue) + ps.map((p) => `<br/>${p.marker}${esc(p.seriesName)}：${p.seriesName === '终端数' ? num(p.value) : auBytes(p.value)}`).join('') },
    legend: { top: 0, right: 0, textStyle: { color: TEXT, fontSize: 11 }, itemWidth: 10, itemHeight: 10 },
    grid: { left: 8, right: 8, top: 28, bottom: 4, containLabel: true },
    xAxis: { type: 'category', data: days.map((d) => d.date.slice(5)), axisLabel: { color: TEXT, fontSize: 10 }, axisLine: { lineStyle: { color: GRID_LINE } }, axisTick: { show: false } },
    yAxis: [{ type: 'value', minInterval: 1, ...axis }, { type: 'value', show: bytes, ...axis, splitLine: { show: false }, axisLabel: { color: TEXT, fontSize: 10, formatter: (v) => auBytes(v) } }],
    series,
  }, true);
  barChart('cAuCat', (rep.categories || []).slice(0, 10).map((c) => ({ name: au.labels.category[c.name] || c.name, value: c.value })), ['#1f4b99', '#3a8bff']);
}

// auMatch 判断终端或服务是否符合筛选条件（关键字、策略、选中的服务）
function auPolicyOK(svc, pol) {
  if (!pol) return true;
  return pol === 'unset' ? !svc.policy : svc.policy === pol;
}
function renderAUTables() {
  if (!au.data) return;
  const rep = au.data.report;
  const kw = $('#auSearch').value.trim().toLowerCase();
  const pol = $('#auPolicy').value;
  const bytes = rep.coverage?.bytes;
  const svcs = (rep.services || []).filter((s) => auPolicyOK(s, pol) && (!kw || [s.name, s.vendor, s.id, ...(s.domains || [])].some((x) => (x || '').toLowerCase().includes(kw))
    || (rep.subjects || []).some((u) => u.services.includes(s.id) && [u.ip, u.asset, u.owner, u.dept].some((x) => (x || '').toLowerCase().includes(kw)))));
  $('#auSvcCount').textContent = `${num(svcs.length)} 个${au.service ? ' · 点击服务名可取消“仅看该服务”' : ' · 点击服务名只看使用它的终端'}`;
  $('#auSvcTable').innerHTML = `<thead><tr><th>服务</th><th>类别</th><th>所在地</th><th>策略</th><th class="num">终端</th><th class="num">DNS 查询</th><th class="num">连接</th><th class="num">上传</th><th class="num">下载</th><th class="num">被拦截</th><th>最近</th></tr></thead><tbody>${
    svcs.map((s) => `<tr${au.service === s.id ? ' class="sel"' : ''}>
      <td><b class="clickable" data-au-svc="${esc(s.id)}">${esc(s.name)}</b>${s.new ? ' <span class="chip warn" title="本期首次出现">新</span>' : ''}<div class="muted">${esc(s.vendor || '')}</div></td>
      <td class="nowrap">${auCat(s.category)}</td><td class="nowrap">${auRegion(s.region)}</td><td>${auPol(s.policy)}</td>
      <td class="num">${num(s.subjects)}</td><td class="num">${num(s.queries)}</td><td class="num">${num(s.conns)}</td>
      <td class="num">${bytes ? auBytes(s.up) : '—'}</td><td class="num">${bytes ? auBytes(s.down) : '—'}</td><td class="num">${s.denied ? num(s.denied) : '<span class="muted">0</span>'}</td>
      <td class="muted nowrap">${auSince(s.last)}</td></tr>`).join('') || empty(11, '所选范围内没有 AI 服务的使用记录')}</tbody>`;

  const svcOK = new Set(svcs.map((s) => s.id));
  const subj = (rep.subjects || []).filter((u) => (!au.service || u.services.includes(au.service))
    && (!pol || u.services.some((id) => auSvc(id) && auPolicyOK(auSvc(id), pol)))
    && (!kw ||[u.ip, u.asset, u.owner, u.dept].some((x) => (x || '').toLowerCase().includes(kw)) || u.services.some((id) => svcOK.has(id) && auSvcName(id).toLowerCase().includes(kw))));
  const more = rep.subjects_all > (rep.subjects || []).length ? `（共 ${num(rep.subjects_all)} 个，列出前 ${num(rep.subjects.length)} 个）` : '';
  $('#auSubjCount').innerHTML = `${num(subj.length)} 个${esc(more)}${au.service ? ` · 仅看 <b>${esc(auSvcName(au.service))}</b> <button type="button" class="more" data-au-svc="${esc(au.service)}">取消</button>` : ''}`;
  $('#auSubjTable').innerHTML = `<thead><tr><th>终端</th><th>使用者 / 部门</th><th>服务</th><th class="num">上传</th><th class="num">查询 / 连接</th><th>最近</th></tr></thead><tbody>${
    subj.slice(0, 500).map((u) => `<tr>
      <td class="mono nowrap"><span class="clickable" data-au-ip="${esc(u.ip)}">${esc(u.ip)}</span>${u.deny ? ' <span class="au-pol deny">禁止类</span>' : ''}</td>
      <td>${u.asset || u.owner ? `${esc(u.owner || u.asset)}${u.owner && u.asset ? `<div class="muted">${esc(u.asset)}</div>` : ''}` : '<span class="muted">未登记</span>'}${u.dept ? `<div class="muted">${esc(u.dept)}</div>` : ''}</td>
      <td><div class="cell-chips">${u.services.slice(0, 6).map((id) => { const s = auSvc(id); return `<span class="chip${s && s.policy === 'deny' ? ' warn' : ''}">${esc(auSvcName(id))}</span>`; }).join('')}${u.services.length > 6 ? `<span class="muted">等 ${u.services.length} 个</span>` : ''}</div></td>
      <td class="num">${bytes ? auBytes(u.up) : '—'}</td><td class="num nowrap">${num(u.queries)} / ${num(u.conns)}</td><td class="muted nowrap">${auSince(u.last)}</td></tr>`).join('') || empty(6, '没有符合条件的终端')}</tbody>`;

  $('#auDeptTable').innerHTML = `<thead><tr><th>部门</th><th class="num">使用 AI 的终端</th><th class="num">服务数</th><th class="num">禁止类</th><th class="num">上传</th></tr></thead><tbody>${
    (au.data.depts || []).filter((d) => !kw || d.dept.toLowerCase().includes(kw)).map((d) => `<tr><td>${d.dept === '未登记' ? '<span class="muted">未登记</span>' : `<span class="clickable" data-au-dept="${esc(d.dept)}">${esc(d.dept)}</span>`}</td>
      <td class="num">${num(d.subjects)}</td><td class="num">${num(d.services)}</td><td class="num">${d.deny ? `<span class="lv-critical">${num(d.deny)}</span>` : 0}</td><td class="num">${bytes ? auBytes(d.up) : '—'}</td></tr>`).join('') || empty(5)}</tbody>`;

  const admin = isAdmin();
  $('#auCandTable').innerHTML = `<thead><tr><th>域名</th><th>原因</th><th class="num">终端</th><th class="num">次数</th><th>最近</th><th></th></tr></thead><tbody>${
    (rep.candidates || []).map((c) => `<tr><td class="mono">${esc(c.domain)}${c.sample !== c.domain ? `<div class="muted">${esc(c.sample)}</div>` : ''}</td><td class="muted">${esc(c.reason)}</td>
      <td class="num">${num(c.clients)}</td><td class="num">${num(c.hits)}</td><td class="muted nowrap">${auSince(c.last)}</td>
      <td class="nowrap">${admin ? `<button type="button" class="btn" data-au-add="${esc(c.domain)}">登记</button> ` : ''}<button type="button" class="btn" data-au-ignore="${esc(c.domain)}">忽略</button></td></tr>`).join('')
      || empty(6, '暂无：DNS 查询或 TLS 握手中出现 openai、gpt、claude、llm 等特征词或 .ai 域名、又不在目录中时列在这里')}</tbody>`;

  $('#auEpTable').innerHTML = `<thead><tr><th>站点</th><th>接口</th><th>位置</th><th class="num">来源</th><th class="num">请求</th><th>最近</th></tr></thead><tbody>${
    (rep.endpoints || []).map((e) => `<tr><td class="mono">${esc(e.host)}${e.service ? `<div class="muted">${esc(auSvcName(e.service))}</div>` : ''}</td>
      <td>${esc(au.labels.endpoint[e.kind] || e.kind)}<div class="mono muted">${esc(e.path)}</div></td>
      <td class="nowrap">${e.internal ? '<span class="chip">内网服务</span>' : '<span class="chip">外部服务</span>'}${e.external ? `<div class="lv-medium" title="来自外网的来源数">外网来源 ${num(e.external)}</div>` : ''}</td>
      <td class="num">${num(e.clients)}</td><td class="num">${num(e.hits)}</td><td class="muted nowrap">${auSince(e.last)}</td></tr>`).join('')
      || empty(6, '暂无：Web 或流量日志中出现 /v1/chat/completions、/v1/messages、Ollama（11434 端口）等大模型接口时列在这里')}</tbody>`;
}

document.addEventListener('click', async (e) => {
  const sv = e.target.closest('[data-au-svc]');
  if (sv) { au.service = au.service === sv.dataset.auSvc ? '' : sv.dataset.auSvc; renderAUTables(); return; }
  const ip = e.target.closest('[data-au-ip]');
  if (ip) { openAUSubject(ip.dataset.auIp).catch((err) => alert(err.message)); return; }
  const dp = e.target.closest('[data-au-dept]');
  if (dp) { $('#auSearch').value = dp.dataset.auDept; renderAUTables(); return; }
  const ig = e.target.closest('[data-au-ignore]');
  if (ig) {
    try { await api('/api/aiuse/candidates/' + encodeURIComponent(ig.dataset.auIgnore) + '/ignore', 'POST'); loadAIUse().catch(console.error); } catch (err) { alert(err.message); }
    return;
  }
  const add = e.target.closest('[data-au-add]');
  if (add) { openAUServiceForm(add.dataset.auAdd); return; }
  const del = e.target.closest('[data-au-del]');
  if (del) {
    if (!confirm('删除该服务及其使用记录？')) return;
    try { await api('/api/aiuse/services/' + encodeURIComponent(del.dataset.auDel), 'DELETE'); await loadAUCatalog(); loadAIUse().catch(console.error); } catch (err) { setMsg('#auCatMsg', err.message); }
  }
});

async function openAUSubject(ip) {
  const r = await api('/api/aiuse?' + new URLSearchParams({ range: au.range, ip }));
  const rep = r.report;
  const u = (rep.subjects || [])[0] || { ip };
  const bytes = rep.coverage?.bytes;
  $('#auSubjTitle').textContent = `终端 ${ip} 的 AI 使用（${rep.from} ~ ${rep.to}）`;
  $('#auSubjInfo').innerHTML = `<div class="cell-chips">${u.asset ? `<span class="chip">资产 ${esc(u.asset)}</span>` : ''}${u.owner ? `<span class="chip">负责人 ${esc(u.owner)}</span>` : ''}${u.dept ? `<span class="chip">部门 ${esc(u.dept)}</span>` : ''}
    <span class="chip">服务 ${num((u.services || []).length)} 个</span>${bytes ? `<span class="chip">上传 ${auBytes(u.up)}</span><span class="chip">下载 ${auBytes(u.down)}</span>` : ''}${u.deny ? '<span class="au-pol deny">用过禁止类服务</span>' : ''}</div>`;
  const svcMap = Object.fromEntries((rep.services || []).map((s) => [s.id, s]));
  $('#auSubjDetail').innerHTML = `<thead><tr><th>日期</th><th>服务</th><th>策略</th><th class="num">DNS 查询</th><th class="num">连接</th><th class="num">被拦截</th><th class="num">上传</th><th class="num">下载</th><th>时段</th></tr></thead><tbody>${
    (rep.detail || []).map((d) => { const s = svcMap[d.service] || {}; return `<tr><td class="nowrap">${esc(d.date)}</td><td>${esc(d.name)} <span class="muted">${auRegion(s.region)}</span></td><td>${auPol(s.policy)}</td>
      <td class="num">${num(d.queries)}</td><td class="num">${num(d.conns)}</td><td class="num">${num(d.denied)}</td><td class="num">${bytes ? auBytes(d.up) : '—'}</td><td class="num">${bytes ? auBytes(d.down) : '—'}</td>
      <td class="muted nowrap">${esc(fmtTime(new Date(d.first * 1000).toISOString()).slice(11, 16))} ~ ${esc(fmtTime(new Date(d.last * 1000).toISOString()).slice(11, 16))}</td></tr>`; }).join('') || empty(9)}</tbody>`;
  openModal('auSubjModal');
}

// ---------------- 服务目录 ----------------
$('#auCatalog').addEventListener('click', async () => {
  setMsg('#auCatMsg', '');
  try { await loadAUCatalog(); openModal('auCatModal'); } catch (err) { alert(err.message); }
});
$('#auCatSearch').addEventListener('input', () => renderAUCatalog());
async function loadAUCatalog() {
  const r = await api('/api/aiuse/services');
  au.catalog = r.services || [];
  if (r.labels) au.labels = r.labels;
  renderAUCatalog();
}
const AU_SRC = { builtin: '内置', config: '配置文件', ui: '页面登记' };
function renderAUCatalog() {
  const kw = $('#auCatSearch').value.trim().toLowerCase();
  const admin = isAdmin();
  const list = (au.catalog || []).filter((s) => !kw || [s.name, s.vendor, s.id, ...(s.domains || [])].some((x) => (x || '').toLowerCase().includes(kw)));
  $('#auCatTable').innerHTML = `<thead><tr><th>服务</th><th>类别</th><th>所在地</th><th>域名</th><th class="num">近 30 天终端</th><th>策略</th><th>来源</th><th></th></tr></thead><tbody>${
    list.map((s) => `<tr><td><b>${esc(s.name)}</b><div class="muted">${esc(s.vendor || '')} · ${esc(s.id)}</div></td><td class="nowrap">${auCat(s.category)}</td><td class="nowrap">${auRegion(s.region)}</td>
      <td class="mono">${(s.domains || []).map(esc).join('<br>')}</td><td class="num">${num(s.subjects_30d)}</td>
      <td class="nowrap">${admin ? `<select data-au-pol="${esc(s.id)}" aria-label="${esc(s.name)} 的策略">${['', 'allow', 'restrict', 'deny'].map((p) => `<option value="${p}"${(s.policy || '') === p ? ' selected' : ''}>${esc(au.labels.policy[p] || '未设定')}</option>`).join('')}</select>` : auPol(s.policy)}
        ${s.policy_from === 'config' ? '<div class="muted">配置文件</div>' : s.policy_from === 'ui' ? '<div class="muted">页面设定</div>' : ''}</td>
      <td class="muted nowrap">${esc(AU_SRC[s.source] || s.source)}</td>
      <td>${admin && s.source === 'ui' ? `<button type="button" class="btn danger" data-au-del="${esc(s.id)}">删除</button>` : ''}</td></tr>`).join('') || empty(8)}</tbody>`;
}
$('#auCatTable').addEventListener('change', async (e) => {
  const sel = e.target.closest('[data-au-pol]');
  if (!sel) return;
  try {
    const s = await api('/api/aiuse/services/' + encodeURIComponent(sel.dataset.auPol), 'PUT', { policy: sel.value });
    setMsg('#auCatMsg', `${s.name} 的策略已设为“${au.labels.policy[s.policy || ''] || '未设定'}”`, true);
    await loadAUCatalog();
    loadAIUse().catch(console.error);
  } catch (err) { setMsg('#auCatMsg', err.message); }
});

// ---------------- 登记服务 ----------------
segInit('#auSvcRegion', () => {});
$('#auSvcAdd').addEventListener('click', () => openAUServiceForm(''));
function openAUServiceForm(domain) {
  $('#auSvcCat').innerHTML = Object.entries(au.labels.category || {}).map(([k, l]) => `<option value="${esc(k)}"${k === 'api' ? ' selected' : ''}>${esc(l)}</option>`).join('');
  $('#auSvcName').value = domain ? domain : '';
  $('#auSvcVendor').value = '';
  $('#auSvcPolicy').value = '';
  $('#auSvcDomains').value = domain || '';
  $('#auSvcNote').value = domain ? '由疑似 AI 服务登记' : '';
  segSet('#auSvcRegion', 'v', 'domestic');
  setMsg('#auSvcMsg', '');
  openModal('auSvcModal');
  $('#auSvcName').focus();
}
$('#auSvcForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    name: $('#auSvcName').value.trim(), vendor: $('#auSvcVendor').value.trim(), category: $('#auSvcCat').value, region: segVal('#auSvcRegion', 'v') || '',
    policy: $('#auSvcPolicy').value, domains: [$('#auSvcDomains').value], note: $('#auSvcNote').value.trim(),
  };
  if (!body.name) { setMsg('#auSvcMsg', '请填写名称'); return; }
  try {
    const s = await api('/api/aiuse/services', 'POST', body);
    closeModal('auSvcModal');
    if (!$('#auCatModal').hidden) await loadAUCatalog();
    loadAIUse().catch(console.error);
    setMsg('#auCatMsg', `已登记 ${s.name}，之后的访问计入统计`, true);
    if ($('#auCatModal').hidden) alert(`已登记 ${s.name}，之后的访问计入统计`);
  } catch (err) { setMsg('#auSvcMsg', err.message); }
});

loaders.aiuse = () => loadAIUse().catch(console.error);
