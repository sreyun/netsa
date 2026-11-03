'use strict';
// 安全运营功能：事件处置、误报抑制、syslog 发送端、原始日志检索、资产与漏洞、报表与合规、双因素认证、API 令牌、操作审计。
// 与 app.js 共用全局工具（$、api、esc、badge、fmtTime 等），在其之后加载。

// ---------------- 通用 ----------------
const STATUS = { open: '待处理', investigating: '处置中', resolved: '已处置', false_positive: '误报', ignored: '忽略' };
const OPS_MODALS = ['incModal', 'supModal', 'tfModal', 'tokModal', 'sndModal', 'assetModal', 'impModal', 'aiModal', 'lpModal'];
let tfForced = false;
function openModal(id) { rememberFocus(); $('#' + id).hidden = false; }
function closeModal(id) {
  if (id === 'tfModal' && tfForced) return; // 强制绑定双因素时不能关闭
  $('#' + id).hidden = true;
}
const anyModalOpen = () => [...OPS_MODALS, 'pwModal', 'userModal', 'ntModal'].some((id) => !$('#' + id).hidden);
document.addEventListener('click', (e) => {
  const c = e.target.closest('[data-close]');
  if (c) closeModal(c.dataset.close);
});
// 捕获阶段处理 Esc：先关闭最上层的运营对话框，不再关闭其下的溯源抽屉
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const id = [...OPS_MODALS].reverse().find((m) => !$('#' + m).hidden);
  if (!id) return;
  e.stopImmediatePropagation();
  closeModal(id);
}, true);
const setMsg = (sel, text, ok) => { const m = $(sel); m.textContent = text || ''; m.className = 'form-msg ' + (ok ? 'ok' : 'err'); };
// segInit 绑定分段按钮：点击时切换 active 并回调所选按钮
function segInit(sel, fn) {
  $$(sel + ' button').forEach((b) => b.addEventListener('click', () => {
    $$(sel + ' button').forEach((x) => x.classList.toggle('active', x === b));
    fn(b);
  }));
}
const segVal = (sel, key) => ($(sel + ' button.active') || {}).dataset?.[key];
const segSet = (sel, key, v) => $$(sel + ' button').forEach((b) => b.classList.toggle('active', b.dataset[key] === String(v)));
// fromInput 把 datetime-local 的值（按展示时区）转换为时刻，与 toInput 互逆
function fromInput(v) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(v || '');
  if (!m) return null;
  const want = Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5]);
  let t = want;
  for (let i = 0; i < 3; i++) {
    const p = timeParts(new Date(t));
    t += want - Date.UTC(+p.y, p.mo - 1, +p.d, +p.h, +p.mi);
  }
  return new Date(t);
}
const ago = (ms) => {
  const m = Math.round(Math.abs(ms) / 60000);
  if (m < 60) return `${m} 分钟`;
  if (m < 1440) return `${Math.floor(m / 60)} 小时${m % 60 ? ` ${m % 60} 分` : ''}`;
  return `${Math.floor(m / 1440)} 天${Math.floor((m % 1440) / 60) ? ` ${Math.floor((m % 1440) / 60)} 小时` : ''}`;
};
const statusChip = (s) => `<span class="st st-${esc(s)}">${esc(STATUS[s] || s)}</span>`;
const IMPC = (l) => (l ? `<span class="chip ${l === 'core' ? 'warn' : ''}">${esc(IMP[l] || l)}</span>` : '');

// ---------------- 事件处置 ----------------
const INC_PAGE = 50;
const inc = { offset: 0, list: [], sel: new Set(), cur: null, assignees: null };
async function loadAssignees() {
  if (inc.assignees) return inc.assignees;
  if (!canOperate()) return []; // 只读账号无权查看账号列表
  try { inc.assignees = await api('/api/incidents/assignees'); } catch (_) { inc.assignees = []; }
  return inc.assignees;
}
function incDue(i) {
  if (i.status !== 'open' && i.status !== 'investigating') return `<span class="muted">${esc(fmtShort(i.closed))} 关闭</span>`;
  const left = new Date(i.due) - Date.now();
  return left < 0 ? `<b class="lv-critical">超时 ${ago(left)}</b>` : `<span class="${left < 3600e3 ? 'lv-medium' : 'muted'}">剩余 ${ago(left)}</span>`;
}
function renderIncCounts(c) {
  $('#incCntActive').textContent = num(c.open + c.investigating);
  $('#incCntOpen').textContent = num(c.open);
  $('#incCntInv').textContent = num(c.investigating);
  $('#incCntClosed').textContent = num(c.resolved + c.false_positive + c.ignored);
  $('#incCntOverdue').textContent = c.overdue ? `（${num(c.overdue)}）` : '';
  const badgeEl = $('#incBadge');
  const n = c.overdue || c.open;
  badgeEl.hidden = !n;
  badgeEl.textContent = n > 99 ? '99+' : n;
  badgeEl.classList.toggle('hot', !!c.overdue);
  badgeEl.title = c.overdue ? `${c.overdue} 个事件超过处置时限` : `${c.open} 个事件待处理`;
}
async function loadIncidents() {
  const p = new URLSearchParams({ status: segVal('#incStatus', 's') ?? 'active', severity: $('#incSev').value, q: $('#incSearch').value.trim(), limit: INC_PAGE, offset: inc.offset });
  if ($('#incMine').checked) p.set('assignee', 'me');
  if ($('#incOverdue').checked) p.set('overdue', '1');
  const r = await api('/api/incidents?' + p);
  inc.list = r.incidents;
  renderIncCounts(r.counts);
  $('#incTotal').textContent = `共 ${num(r.total)} 个事件`;
  const ops = canOperate();
  const rows = r.incidents.map((i) => `<tr class="clickable${i.overdue ? ' row-hot' : ''}" data-inc="${i.id}">
    ${ops ? `<td class="chk"><input type="checkbox" data-sel="${i.id}" ${inc.sel.has(i.id) ? 'checked' : ''} aria-label="选择事件 #${i.id}"></td>` : ''}
    <td class="nowrap mono">#${i.id}</td>
    <td><b>${esc(i.title)}</b><div class="cell-chips">${(i.phases || []).map((ph) => `<span class="chip">${esc(PHASE[ph] || ph)}</span>`).join('')}${(i.assets || []).map((a) => `<span class="chip ${i.asset_level === 'core' ? 'warn' : ''}">资产 ${esc(a)}</span>`).join('')}</div></td>
    <td>${badge(i.severity)}${i.ai_from ? `<div class="muted" style="font-size:11px" title="模型判为疑似误报，等级已下调，待分析员确认">原${esc(SEV_LABEL[i.ai_from] || i.ai_from)} · AI 下调</div>` : ''}</td><td class="nowrap">${statusChip(i.status)}</td>
    <td class="nowrap">${esc(i.assignee || '-')}</td>
    <td class="num">${num(i.alerts)}${i.hits && i.hits !== i.alerts ? `<div class="muted" style="font-size:11px" title="同一规则在节流窗口内只记录前若干条告警，其余命中只计数">命中 ${num(i.hits)}</div>` : ''}${i.success ? `<div class="res-success" style="font-size:11px">${i.success} 次疑似成功</div>` : ''}</td>
    <td class="nowrap muted">${esc(fmtShort(i.first_seen))}<br>${esc(fmtShort(i.last_seen))}</td>
    <td class="nowrap">${incDue(i)}</td><td class="num">${i.notes || ''}</td></tr>`).join('');
  $('#incTable').innerHTML = `<thead><tr>${ops ? '<th class="chk"><input type="checkbox" id="incAll" aria-label="全选本页"></th>' : ''}<th>编号</th><th>事件</th><th>等级</th><th>状态</th><th>负责人</th><th class="num">告警</th><th>首次 / 最近</th><th>处置时限</th><th class="num">记录</th></tr></thead><tbody>${rows || empty(ops ? 10 : 9, '没有符合条件的事件')}</tbody>`;
  const pages = Math.max(1, Math.ceil(r.total / INC_PAGE));
  const page = Math.floor(inc.offset / INC_PAGE) + 1;
  $('#incPager').innerHTML = pages > 1 ? `<button type="button" class="btn" data-pg="-1" ${page <= 1 ? 'disabled' : ''}>上一页</button><span class="muted">${page} / ${pages}</span><button type="button" class="btn" data-pg="1" ${page >= pages ? 'disabled' : ''}>下一页</button>` : '';
  renderIncBulk();
  // 超时提醒链接：#tab=incidents&incident=12
  const want = +hashParams.get('incident');
  if (want) { hashParams.delete('incident'); openIncident(want); }
}
function renderIncBulk() {
  $('#incSel').textContent = inc.sel.size;
  $('#incBulk').hidden = !canOperate() || inc.sel.size === 0;
  $('#incBulkAI').hidden = !(meta.ai && meta.ai.enabled);
}
$('#incPager').addEventListener('click', (e) => {
  const b = e.target.closest('[data-pg]');
  if (!b) return;
  inc.offset = Math.max(0, inc.offset + +b.dataset.pg * INC_PAGE);
  loadIncidents().catch(console.error);
});
$('#incTable').addEventListener('click', (e) => {
  if (e.target.matches('input[type=checkbox]')) {
    if (e.target.id === 'incAll') {
      inc.list.forEach((i) => (e.target.checked ? inc.sel.add(i.id) : inc.sel.delete(i.id)));
      $$('#incTable input[data-sel]').forEach((c) => { c.checked = e.target.checked; });
    } else {
      const id = +e.target.dataset.sel;
      if (e.target.checked) inc.sel.add(id); else inc.sel.delete(id);
    }
    renderIncBulk();
    return;
  }
  if (e.target.closest('[data-ip]') || e.target.closest('td.chk')) return;
  const tr = e.target.closest('tr[data-inc]');
  if (tr) openIncident(+tr.dataset.inc);
});
segInit('#incStatus', () => { inc.offset = 0; inc.sel.clear(); loadIncidents().catch(console.error); });
['#incSev', '#incMine', '#incOverdue'].forEach((s) => $(s).addEventListener('change', () => { inc.offset = 0; loadIncidents().catch(console.error); }));
let incDebounce;
$('#incSearch').addEventListener('input', () => { clearTimeout(incDebounce); incDebounce = setTimeout(() => { inc.offset = 0; loadIncidents().catch(console.error); }, 300); });
$('#incBulk').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-bulk]');
  if (!b) return;
  const act = b.dataset.bulk;
  const ids = [...inc.sel];
  if (act === 'clear') { inc.sel.clear(); loadIncidents().catch(console.error); return; }
  if (act === 'ai') {
    try {
      const r = await api('/api/incidents/ai-batch', 'POST', { ids });
      alert(`已加入研判队列 ${r.queued} 个事件（队列中共 ${r.pending} 个）。后台每分钟最多研判 ${r.per_tick} 个，受每小时调用上限限制，结论写入各事件的处置记录。`);
      inc.sel.clear();
    } catch (err) { alert(err.message); }
    loadIncidents().catch(console.error);
    return;
  }
  const body = {};
  if (act === 'assign') {
    const names = (await loadAssignees()).map((a) => a.name);
    const who = prompt(`指派给（可选：${names.join('、') || '无可指派账号'}；留空取消指派）`, me.user);
    if (who === null) return;
    body.assignee = who.trim();
  } else {
    body.status = act;
    const closing = act !== 'investigating';
    const note = prompt(closing ? `将 ${ids.length} 个事件标记为“${STATUS[act]}”，请填写处置说明（必填）：` : `开始处置 ${ids.length} 个事件，可填写备注：`, '');
    if (note === null) return;
    if (closing && !note.trim()) { alert('关闭事件必须填写处置说明'); return; }
    body.note = note.trim();
    if (act === 'investigating' && !body.assignee) body.assignee = me.user || undefined;
  }
  try {
    await api('/api/incidents/bulk', 'POST', { ...body, ids });
    inc.sel.clear();
  } catch (err) { alert(err.message); }
  loadIncidents().catch(console.error);
});

async function openIncident(id) {
  let d;
  try { d = await api('/api/incidents/' + id); } catch (e) { alert(e.message); return; }
  inc.cur = d;
  if (currentTab !== 'incidents' && !$('#drawer').classList.contains('open')) { /* 从告警列表打开：保持当前页面 */ }
  $('#incTitle').innerHTML = `事件 #${d.id} ${badge(d.severity)} ${statusChip(d.status)}${d.overdue ? ' <b class="lv-critical">已超时</b>' : ''}`;
  const notes = (d.notes_list || []).slice().reverse().map((n) => `<li><span class="muted nowrap">${esc(fmtShort(n.time))}</span> <b>${esc(n.user)}</b>
    ${n.action ? `<span class="tl-act">${esc(n.action)}</span>` : ''}${n.text ? `<div class="tl-text">${esc(n.text)}</div>` : ''}</li>`).join('');
  const alerts = (d.alert_list || []).map((a, k) => `<tr><td class="nowrap muted">${esc(fmtShort(a.time))}</td><td>${badge(a.severity)} ${esc(a.name)}</td>
    <td class="mono">${a.method ? esc(a.method) + ' ' : ''}${esc(a.target)}${assetLine(a)}</td><td>${resTag(a.result, a.proven)}</td><td class="evidence">${esc(a.evidence)}</td>
    <td class="nowrap">${canOperate() ? `<button type="button" class="btn" data-ia="fp" data-k="${k}">标记误报</button>` : ''}${canOperate() && meta.rawlog ? ` <button type="button" class="btn" data-ia="raw" data-k="${k}">原始日志</button>` : ''}</td></tr>`).join('');
  $('#incBody').innerHTML = `
    <div class="inc-head"><b>${esc(d.title)}</b></div>
    <div class="kv">
      <div class="k">来源</div><div>${ipLink(d.key)} <span class="muted">${esc(d.location || '')}</span> <button type="button" class="btn sm" id="incBlock" hidden>申请封禁</button></div>
      <div class="k">时间</div><div>${esc(fmtTime(d.first_seen))} ~ ${esc(fmtTime(d.last_seen))}</div>
      <div class="k">告警</div><div>${num(d.alerts)} 条${d.muted ? ` <span class="muted">（累计命中 ${num(d.hits)} 次，其中 ${num(d.muted)} 次同类命中按规则节流未生成告警）</span>` : d.hits && d.hits !== d.alerts ? ` <span class="muted">（累计命中 ${num(d.hits)} 次）</span>` : ''}${d.success ? ` · <span class="res-success">疑似成功 ${d.success} 次</span>` : ''}</div>
      <div class="k">攻击类型</div><div>${(d.categories || []).map((c) => `<span class="chip">${esc(c)}</span>`).join('') || '-'}</div>
      <div class="k">攻击阶段</div><div>${(d.phases || []).map((p) => `<span class="chip">${esc(PHASE[p] || p)}</span>`).join('') || '-'}</div>
      ${(d.assets || []).length ? `<div class="k">涉及资产</div><div>${d.assets.map((a) => `<span class="chip">${esc(a)}</span>`).join('')} ${IMPC(d.asset_level)}</div>` : ''}
      ${d.ai_from ? `<div class="k">等级调整</div><div>模型判为疑似误报，由${esc(SEV_LABEL[d.ai_from] || d.ai_from)}下调一级，待分析员确认；出现成功利用或更高等级的告警时自动恢复${canOperate() ? ' <button type="button" class="btn" id="incRestoreAI">撤销下调</button>' : ''}</div>` : ''}
      <div class="k">负责人</div><div>${esc(d.assignee || '未指派')}</div>
      <div class="k">处置时限</div><div>${esc(fmtTime(d.due))}（${esc(fmtDur(d.sla))}，${d.asset_level === 'core' ? '涉及核心资产，时限按高一级计算' : '按事件等级计算'}）· ${incDue(d)}</div>
      <div class="k">命中规则</div><div>${(d.rules || []).map((r) => {
        const alerts = r.alerts == null ? r.value : r.alerts;
        const extra = alerts !== r.value ? ` / ${num(alerts)} 告警` : '';
        return `<span class="chip" title="命中 ${num(r.value)} 次，生成告警 ${num(alerts)} 条（同一规则在节流窗口内只记录前若干条）">${esc(r.name)} × ${num(r.value)} 命中${extra}</span>`;
      }).join('') || '-'}</div>
      <div class="k">攻击目标</div><div class="mono">${(d.targets || []).map((t) => `<div>${esc(t.name)} <span class="muted">× ${num(t.value)}</span></div>`).join('') || '-'}</div>
    </div>
    <h4>处置记录</h4><ul class="timeline">${notes || '<li class="muted">暂无处置记录</li>'}</ul>
    <h4>相关告警 <small>累计 ${num(d.alerts)} 条，当前内存保留最近 ${num((d.alert_list || []).length)} 条</small></h4>
    <div class="scroll"><table class="table"><thead><tr><th>时间</th><th>规则</th><th>目标</th><th>结果</th><th>证据</th><th></th></tr></thead><tbody>${alerts || empty(6, '告警已超出内存保留范围')}</tbody></table></div>`;
  // 处置栏
  const ass = await loadAssignees();
  $('#incSetAssignee').innerHTML = '<option value="__keep">负责人不变</option><option value="">取消指派</option>'
    + ass.map((a) => `<option value="${esc(a.name)}">${esc(a.name)}（${esc(ROLE[a.role] || a.role)}）</option>`).join('');
  if (!d.assignee && me.user && ass.some((a) => a.name === me.user)) $('#incSetAssignee').value = me.user;
  $('#incSetStatus').value = d.status === 'open' ? 'investigating' : '';
  $$('#incSetStatus option[value="open"]').forEach((o) => { o.hidden = d.status === 'open' || d.status === 'investigating'; });
  $('#incNote').value = '';
  setMsg('#incMsg', '');
  $('#incAI').hidden = !(meta.ai && meta.ai.enabled && canOperate());
  const blockBtn = $('#incBlock');
  if (blockBtn) blockBtn.hidden = !(meta.block && canOperate());
  $('#incAIBox').hidden = true;
  openModal('incModal');
}
const SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
$('#incBody').addEventListener('click', (e) => {
  if (e.target.id !== 'incRestoreAI') return;
  ntBusy(e.target, async () => {
    try {
      await api('/api/incidents/' + inc.cur.id, 'POST', { restore_ai: true });
      await openIncident(inc.cur.id);
      loadIncidents().catch(console.error);
    } catch (err) { setMsg('#incMsg', err.message); }
  });
});
// 申请封禁：提交后等待管理员审批
$('#incBody').addEventListener('click', async (e) => {
  if (e.target.id !== 'incBlock') return;
  const d = inc.cur;
  const reason = prompt(`申请封禁 ${d.key}，请填写原因（审批人会看到）：`, `事件 #${d.id} ${d.title}`);
  if (reason === null) return;
  const hours = prompt('封禁时长（小时），到期自动解除：', '24');
  if (hours === null) return;
  try {
    const it = await api('/api/block', 'POST', { ip: d.key, reason, ttl_hours: parseFloat(hours) || 0, incident_id: d.id });
    alert(it.status === 'active' ? `${it.ip} 已在封禁中` : `已提交封禁申请 #${it.id}，等待管理员审批`);
    loadBlockPanel().catch(console.error);
  } catch (err) { alert(err.message); }
});
// AI 研判：结论写入处置记录并在对话框中展示（模型输出按纯文本展示）
const AI_VERDICT = { attack: ['真实攻击', 'lv-high'], false_positive: ['疑似误报', 'nt-on'], uncertain: ['无法判断', 'muted'] };
$('#incAI').addEventListener('click', () => {
  const d = inc.cur;
  if (!d) return;
  ntBusy($('#incAI'), async () => {
    setMsg('#incMsg', '');
    try {
      const r = await api('/api/incidents/' + d.id + '/ai', 'POST', {});
      const v = r.verdict;
      const [label, cls] = AI_VERDICT[v.verdict] || AI_VERDICT.uncertain;
      await openIncident(d.id);
      const list = (xs) => (xs || []).map((x) => `<li>${esc(x)}</li>`).join('');
      $('#incAIBox').innerHTML = `<div><b>AI 研判</b> <span class="muted">${esc(v.model)} · 仅供参考，已写入处置记录</span></div>
        <div class="ai-verdict">${v.unparsed ? `<b class="lv-medium">未得到结论</b> · ${esc(v.summary)}` : `<b class="${cls}">${esc(label)}</b> 置信度 ${num(v.confidence)}% · ${esc(v.summary)}`}</div>
        ${v.downgraded ? `<div class="muted">事件等级已由${esc(v.downgraded)}下调一级，事件保持待处理，请分析员确认</div>` : ''}
        ${(v.reasons || []).length ? `<div class="muted">依据</div><ul>${list(v.reasons)}</ul>` : ''}
        ${(v.actions || []).length ? `<div class="muted">处置建议</div><ul>${list(v.actions)}</ul>` : ''}
        ${v.false_positive_hint ? `<div class="muted">抑制建议：${esc(v.false_positive_hint)}</div>` : ''}
        ${v.raw ? `<pre class="cmd">${esc(v.raw)}</pre>` : ''}`;
      $('#incAIBox').hidden = false;
    } catch (err) { setMsg('#incMsg', 'AI 研判失败：' + err.message); }
  });
});
$('#incBody').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-ia]');
  if (!b || !inc.cur) return;
  const a = inc.cur.alert_list[+b.dataset.k];
  if (b.dataset.ia === 'fp') openSuppress(a);
  else { closeModal('incModal'); openRawlogAround(a.src_ip, a.time); }
});
$('#incSave').addEventListener('click', () => {
  const d = inc.cur;
  if (!d) return;
  const body = { status: $('#incSetStatus').value, note: $('#incNote').value.trim() };
  const asg = $('#incSetAssignee').value;
  if (asg !== '__keep') body.assignee = asg;
  if (!body.status && body.assignee === undefined && !body.note) { setMsg('#incMsg', '请选择状态、负责人或填写处置说明'); return; }
  if (['resolved', 'false_positive', 'ignored'].includes(body.status) && !body.note) { setMsg('#incMsg', '关闭事件时请填写处置说明'); $('#incNote').focus(); return; }
  ntBusy($('#incSave'), async () => {
    try {
      await api('/api/incidents/' + d.id, 'POST', body);
      closeModal('incModal');
      if (currentTab === 'incidents') loadIncidents().catch(console.error);
      refreshIncBadge();
    } catch (err) { setMsg('#incMsg', err.message); }
  });
});
async function refreshIncBadge() {
  try { renderIncCounts((await api('/api/incidents?status=active&limit=1')).counts); } catch (_) { /* 无权限或离线 */ }
}

// ---------------- 误报抑制 ----------------
let supAlert = null;
// 从告警目标中取出路径部分（不含主机与查询参数），作为“目标包含”条件
function targetPath(a) {
  let t = a.target || '';
  if (a.kind === 'web') {
    const sp = t.indexOf(' ');
    if (sp >= 0) t = t.slice(sp + 1);
    t = t.split('?')[0];
  }
  return t.slice(0, 200);
}
function openSuppress(a) {
  supAlert = a;
  $('#supTitle').textContent = `标记误报 · ${a.name}`;
  $('#supRule').value = a.rule_id || '';
  $('#supCat').value = a.category || '';
  $('#supIP').value = a.src_ip || '';
  $('#supTarget').value = targetPath(a);
  $('#supUseRule').checked = true;
  $('#supUseCat').checked = false;
  $('#supUseIP').checked = false;
  $('#supUseTarget').checked = !!$('#supTarget').value;
  $('#supReason').value = '';
  segSet('#supDays', 'd', 30);
  $('#supIncRow').hidden = !a.incident_id;
  $('#supIncId').textContent = a.incident_id ? '#' + a.incident_id : '';
  setMsg('#supMsg', '');
  openModal('supModal');
  $('#supReason').focus();
}
segInit('#supDays', () => {});
$('#supForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const body = { reason: $('#supReason').value.trim(), days: +segVal('#supDays', 'd') };
  if ($('#supUseRule').checked) body.rule_id = $('#supRule').value.trim();
  if ($('#supUseCat').checked) body.category = $('#supCat').value.trim();
  if ($('#supUseIP').checked) body.ip = $('#supIP').value.trim();
  if ($('#supUseTarget').checked) body.target = $('#supTarget').value.trim();
  if (!body.reason) { setMsg('#supMsg', '请填写误报原因，便于日后审计'); $('#supReason').focus(); return; }
  ntBusy($('#supSave'), async () => {
    try {
      await api('/api/suppressions', 'POST', body);
      if (supAlert?.incident_id && !$('#supIncRow').hidden && $('#supInc').checked) {
        await api('/api/incidents/' + supAlert.incident_id, 'POST', { status: 'false_positive', note: '误报：' + body.reason }).catch(() => {});
      }
      closeModal('supModal');
      if (currentTab === 'incidents') loadIncidents().catch(console.error);
      loadSuppressions().catch(console.error);
    } catch (err) { setMsg('#supMsg', err.message); }
  });
});
async function loadSuppressions() {
  const r = await api('/api/suppressions');
  $('#supCount').textContent = `${(r.rules || []).length} 条 · 累计抑制 ${num(r.total)} 次命中`;
  const now = Date.now();
  const cond = (x) => [x.rule_id && `规则 <span class="mono">${esc(x.rule_id)}</span>`, x.category && `类型 ${esc(x.category)}`,
    x.ip && `来源 <span class="mono">${esc(x.ip)}</span>`, x.target && `目标包含 <span class="mono">${esc(x.target)}</span>`].filter(Boolean).join(' 且 ');
  $('#supTable').innerHTML = `<thead><tr><th>条件</th><th>原因</th><th>创建</th><th>有效期</th><th class="num">已抑制</th><th>最近命中</th><th></th></tr></thead><tbody>${(r.rules || []).map((x) => {
    const expired = !zero(x.expires) && new Date(x.expires) < now;
    return `<tr class="${expired ? 'muted' : ''}"><td>${cond(x)}</td><td>${esc(x.reason)}</td><td class="nowrap muted">${esc(x.creator)} · ${esc(fmtShort(x.created))}</td>
      <td class="nowrap">${zero(x.expires) ? '永久' : expired ? '<span class="nt-warn">已过期</span>' : esc(fmtShort(x.expires)) + ' 前'}</td>
      <td class="num">${num(x.hits)}</td><td class="nowrap muted">${esc(fmtShort(x.last_hit))}</td>
      <td class="num">${canOperate() ? `<button type="button" class="btn danger" data-sup="${esc(x.id)}">删除</button>` : ''}</td></tr>`;
  }).join('') || empty(7, '暂无抑制规则')}</tbody>`;
}
$('#supTable').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-sup]');
  if (!b || !confirm('确定删除该抑制规则？之后同类命中将重新产生告警。')) return;
  try { await api('/api/suppressions/' + encodeURIComponent(b.dataset.sup), 'DELETE'); } catch (err) { alert(err.message); }
  loadSuppressions().catch(console.error);
});

// ---------------- Syslog 发送端 ----------------
const SND_STATUS = { online: ['在线', 'nt-on'], idle: ['静默', 'muted'], silent: ['断流', 'lv-critical'], rejected: ['已拒绝', 'lv-high'], blocked: ['已阻止', 'lv-high'], offline: ['未上线', 'nt-warn'] };
const snd = { rep: null, editing: null, action: 'allow' };
const rateText = (r) => (r >= 1 ? r.toFixed(1) : r.toFixed(2));
async function loadSenders() {
  let r;
  try { r = await api('/api/syslog/senders'); } catch (_) { $('#sndPanel').hidden = true; return; }
  if (!r.report || (!r.enabled && !(r.report.senders || []).length && !(r.report.rules || []).length)) { $('#sndPanel').hidden = true; return; }
  $('#sndPanel').hidden = false;
  const rep = r.report;
  snd.rep = rep;
  const t = rep.totals;
  $('#sndSummary').textContent = `${num(t.senders)} 个发送端 · 在线 ${num(t.online)} · 断流 ${num(t.silent)} · 未登记 ${num(t.unregistered)} · 被拒绝的消息 ${num(t.rejected_messages)}${t.rate_limited ? ` · 限速丢弃 ${num(t.rate_limited)}` : ''}`;
  const allow = $('#sndAllow');
  allow.checked = rep.allowlist;
  allow.disabled = !isAdmin() || rep.forced;
  const lsn = r.listen || {};
  const listen = [lsn.udp && `UDP ${lsn.udp}`, lsn.tcp && `TCP ${lsn.tcp}`, lsn.tls && `TLS ${lsn.tls}${r.mutual_tls ? '（双向认证）' : ''}`].filter(Boolean).join(' · ');
  $('#sndMode').innerHTML = (rep.allowlist ? '<span class="nt-on">已开启：只接收已登记的发送端</span>' : '<span class="nt-warn">未开启：接收任何来源的日志</span>')
    + (rep.forced ? ' <span class="muted">（配置文件强制开启）</span>' : '')
    + ` <span class="muted">${esc(listen)}${rep.rate_limit ? ` · 单发送端 ≤ ${num(rep.rate_limit)} 条/秒` : ''} · 默认断流阈值 ${esc(rep.default_silence)}</span>`;
  const gsel = $('#sndGroup');
  const cur = gsel.value;
  gsel.innerHTML = '<option value="">全部分组</option>' + rep.groups.map((g) => `<option value="${esc(g.name)}">${esc(g.name)}（${g.senders}）</option>`).join('');
  gsel.value = rep.groups.some((g) => g.name === cur) ? cur : '';
  $('#sndGroupList').innerHTML = [...new Set(rep.rules.map((x) => x.group).filter(Boolean))].map((g) => `<option value="${esc(g)}">`).join('');
  $('#sndGroups').innerHTML = rep.groups.map((g) => `<button type="button" class="snd-group${gsel.value === g.name ? ' active' : ''}" data-g="${esc(g.name)}">
    <b>${esc(g.name)}</b><span>${g.senders} 个 · 在线 ${g.online}${g.silent ? ` · <i class="lv-critical">断流 ${g.silent}</i>` : ''}${g.rejected ? ` · <i class="lv-high">拒绝 ${g.rejected}</i>` : ''}</span>
    <span class="muted">${num(g.lines)} 行 · ${rateText(g.rate)} 条/秒</span></button>`).join('');
  renderSenders();
}
const senderGroupKey = (s) => s.group || (s.rule_id ? '未分组' : '未登记');
function renderSenders() {
  const rep = snd.rep;
  if (!rep) return;
  const g = $('#sndGroup').value;
  const st = $('#sndStatusSel').value;
  const list = rep.senders.filter((s) => (!g || senderGroupKey(s) === g) && (!st || (st === 'unregistered' ? !s.rule_id : s.status === st)));
  const admin = isAdmin();
  const actions = (s) => {
    if (!admin) return '';
    if (s.rule_id && !s.rule_id.startsWith('cfg-') && s.rule_cidr === s.ip) return `<button type="button" class="btn" data-snd="edit" data-id="${esc(s.rule_id)}">编辑</button>`;
    if (!s.rule_id || s.rule_cidr !== s.ip) return `<button type="button" class="btn" data-snd="reg" data-ip="${esc(s.ip)}">登记</button> <button type="button" class="btn danger" data-snd="block" data-ip="${esc(s.ip)}">阻止</button>`;
    return '';
  };
  $('#sndTable').innerHTML = `<thead><tr><th>发送端</th><th>设备 / 分组</th><th>状态</th><th>协议</th><th>识别格式</th><th class="num">日志</th><th class="num">解析失败</th><th class="num">速率（条/秒）</th><th class="num">拒绝 / 限速</th><th>最近接收</th><th></th></tr></thead><tbody>${list.map((s) => {
    const [lbl, cls] = SND_STATUS[s.status] || [s.status, ''];
    const ident = [s.hostname && `主机名 ${esc(s.hostname)}`, s.cert && `证书 ${esc(s.cert)}`].filter(Boolean).join('<br>');
    const fail = s.lines ? s.failed / s.lines : 0;
    return `<tr><td class="mono nowrap">${esc(s.ip)}${ident ? `<div class="muted" style="font-size:11px">${ident}</div>` : ''}</td>
      <td>${s.name ? `<b>${esc(s.name)}</b>` : '<span class="muted">未登记</span>'}${s.group ? ` <span class="chip">${esc(s.group)}</span>` : ''}${s.rule_cidr && s.rule_cidr !== s.ip ? `<div class="muted" style="font-size:11px">匹配 ${esc(s.rule_cidr)}</div>` : ''}</td>
      <td class="nowrap"><b class="${cls}">● ${esc(lbl)}</b>${s.silence && s.silence !== 'off' ? `<div class="muted" style="font-size:11px">断流阈值 ${esc(s.silence)}</div>` : ''}</td>
      <td class="nowrap">${(s.protocols || []).map((p) => `<span class="chip">${esc(p)}</span>`).join('')}</td>
      <td>${s.detected ? `<span class="chip">${esc(s.detected)}</span>` : '-'}${s.time_offset ? `<div class="lv-medium" style="font-size:11px">时区已校正 ${esc(s.time_offset)}</div>` : ''}</td>
      <td class="num">${num(s.lines)}</td>
      <td class="num">${s.failed ? `<span class="${fail > 0.2 ? 'lv-high' : 'lv-medium'}" title="${esc(s.sample_failed || '')}">${num(s.failed)}</span>` : 0}</td>
      <td class="num">${s.rate ? rateText(s.rate) : '-'}</td>
      <td class="num">${s.rejected || s.rate_limited ? `<span class="lv-high">${num(s.rejected)}</span> / ${num(s.rate_limited)}` : '-'}</td>
      <td class="nowrap muted">${esc(fmtShort(s.last_seen))}</td><td class="nowrap num">${actions(s)}</td></tr>`;
  }).join('') || empty(11, rep.senders.length ? '没有符合条件的发送端' : '尚未收到 syslog 日志')}</tbody>`;
  $('#sndRules').innerHTML = `<thead><tr><th>IP / 网段</th><th>名称</th><th>分组</th><th>动作</th><th>断流阈值</th><th>来源</th><th>备注</th><th></th></tr></thead><tbody>${rep.rules.map((x) => `<tr>
    <td class="mono">${esc(x.cidr)}</td><td>${esc(x.name || '-')}</td><td>${x.group ? `<span class="chip">${esc(x.group)}</span>` : '-'}</td>
    <td>${x.action === 'block' ? '<b class="lv-high">阻止</b>' : '<span class="nt-on">允许</span>'}</td><td>${esc(x.silence || '默认')}</td>
    <td>${x.source === 'config' ? '<span class="chip" title="来自配置文件 syslog.senders，请在配置文件中修改">配置文件</span>' : `<span class="muted">${esc(x.creator || '')} · ${esc(fmtShort(x.created))}</span>`}</td>
    <td class="muted">${esc(x.note || '')}</td>
    <td class="num">${admin && x.source !== 'config' ? `<button type="button" class="btn" data-snd="edit" data-id="${esc(x.id)}">编辑</button>` : ''}</td></tr>`).join('') || empty(8, '尚未登记发送端：点击“登记发送端”，或在上表中直接登记已出现的发送端')}</tbody>`;
}
function syncGroupChips() { $$('#sndGroups .snd-group').forEach((b) => b.classList.toggle('active', b.dataset.g === $('#sndGroup').value)); }
['#sndGroup', '#sndStatusSel'].forEach((s) => $(s).addEventListener('change', () => { syncGroupChips(); renderSenders(); }));
$('#sndGroups').addEventListener('click', (e) => {
  const b = e.target.closest('[data-g]');
  if (!b) return;
  $('#sndGroup').value = $('#sndGroup').value === b.dataset.g ? '' : b.dataset.g;
  syncGroupChips();
  renderSenders();
});
$('#sndAllow').addEventListener('change', async (e) => {
  const on = e.target.checked;
  let include = false;
  if (on) {
    const unreg = (snd.rep?.senders || []).filter((s) => !s.rule_id && s.parsed > 0).length;
    if (!confirm('开启后只接收已登记（允许）的发送端的日志，其余来源的数据报被丢弃、连接被断开。确定开启？')) { e.target.checked = false; return; }
    include = unreg > 0 && confirm(`当前有 ${unreg} 个未登记但正在发送日志的发送端。是否把近 24 小时内活跃的发送端自动登记为允许（分组“自动登记”）？\n选择“取消”则只保留已登记的发送端。`);
  } else if (!confirm('关闭后将接收任何来源的 syslog 日志（被“阻止”的发送端除外）。确定关闭？')) { e.target.checked = true; return; }
  try {
    const r = await api('/api/syslog/policy', 'PUT', { allowlist: on, include_active: include });
    if (r.added) alert(`已自动登记 ${r.added} 个活跃发送端`);
  } catch (err) { alert(err.message); }
  loadSenders().catch(console.error);
});
function openSender(rule, ip, action) {
  snd.editing = rule ? rule.id : null;
  $('#sndTitle').textContent = rule ? `编辑发送端 · ${rule.cidr}` : '登记发送端';
  $('#sndCIDR').value = rule ? rule.cidr : ip || '';
  $('#sndName').value = rule?.name || '';
  $('#sndGroupIn').value = rule?.group || '';
  $('#sndSilence').value = rule?.silence || '';
  $('#sndNote').value = rule?.note || '';
  snd.action = rule?.action || action || 'allow';
  segSet('#sndAction', 'a', snd.action);
  $('#sndDel').hidden = !rule;
  setMsg('#sndMsg', '');
  openModal('sndModal');
  (ip && !rule ? $('#sndName') : $('#sndCIDR')).focus();
}
segInit('#sndAction', (b) => { snd.action = b.dataset.a; });
$('#sndAdd').addEventListener('click', () => openSender(null));
['#sndTable', '#sndRules'].forEach((sel) => $(sel).addEventListener('click', async (e) => {
  const b = e.target.closest('[data-snd]');
  if (!b) return;
  if (b.dataset.snd === 'edit') { openSender(snd.rep.rules.find((x) => x.id === b.dataset.id)); return; }
  if (b.dataset.snd === 'reg') { openSender(null, b.dataset.ip, 'allow'); return; }
  if (b.dataset.snd === 'block' && confirm(`确定阻止 ${b.dataset.ip}？之后该来源发送的日志将被直接丢弃。`)) {
    try { await api('/api/syslog/senders', 'POST', { cidr: b.dataset.ip, action: 'block', note: '在发送端列表中阻止' }); } catch (err) { alert(err.message); }
    loadSenders().catch(console.error);
  }
}));
$('#sndForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const body = { cidr: $('#sndCIDR').value.trim(), name: $('#sndName').value.trim(), group: $('#sndGroupIn').value.trim(), action: snd.action, silence: $('#sndSilence').value.trim(), note: $('#sndNote').value.trim() };
  if (!body.cidr) { setMsg('#sndMsg', '请填写 IP 或网段'); return; }
  ntBusy($('#sndSave'), async () => {
    try {
      if (snd.editing) await api('/api/syslog/senders/' + encodeURIComponent(snd.editing), 'PUT', body);
      else await api('/api/syslog/senders', 'POST', body);
      closeModal('sndModal');
      loadSenders().catch(console.error);
    } catch (err) { setMsg('#sndMsg', err.message); }
  });
});
$('#sndDel').addEventListener('click', async () => {
  if (!snd.editing || !confirm('确定删除该登记？开启白名单时，该发送端的日志将被拒绝。')) return;
  try {
    await api('/api/syslog/senders/' + encodeURIComponent(snd.editing), 'DELETE');
    closeModal('sndModal');
  } catch (err) { setMsg('#sndMsg', err.message); return; }
  loadSenders().catch(console.error);
});

// ---------------- 原始日志检索 ----------------
let rlInited = false;
function rlRange(min) {
  segSet('#rlRange', 'm', min);
  $('#rlTo').value = '';
  $('#rlFrom').value = toInput(new Date(Date.now() - min * 60000));
}
segInit('#rlRange', (b) => rlRange(+b.dataset.m));
function rlParams(limit) {
  const p = new URLSearchParams();
  const from = fromInput($('#rlFrom').value);
  const to = $('#rlTo').value ? fromInput($('#rlTo').value) : new Date();
  if (from) p.set('from', Math.floor(from / 1000));
  if (to) p.set('to', Math.ceil(to / 1000) + ($('#rlTo').value ? 59 : 0)); // datetime-local 精确到分钟：包含结束时间所在的整分钟
  for (const [k, id] of [['ip', '#rlIP'], ['q', '#rlQ'], ['source', '#rlSource']]) {
    const v = $(id).value.trim();
    if (v) p.set(k, v);
  }
  if ($('#rlAttack').checked) p.set('attacks', '1');
  p.set('limit', limit);
  return p;
}
// 分页检索。检索条件在点“检索”时固定下来（结束时间留空时取当时的时间），翻页沿用同一组条件；
// 服务端按位置翻页，持续写入新日志时页面内容不会错位。
const rl = { query: '', cursors: [''], page: 0, size: 100, seq: 0 };
try { rl.size = +localStorage.getItem('netsa.rlSize') || 100; } catch (_) { /* 隐私模式 */ }
$('#rlSize').value = String(rl.size);
if (!$('#rlSize').value) { rl.size = 100; $('#rlSize').value = '100'; }
async function searchRawlog() {
  if (!meta.rawlog) return;
  const ip = $('#rlIP').value.trim();
  if (ip && !/^[0-9a-fA-F.:]+$/.test(ip)) { setMsg('#rlMsg', 'IP 格式不正确'); return; }
  setMsg('#rlMsg', '');
  const p = rlParams(rl.size);
  p.set('clip', 4096); // 超长行只显示开头，完整内容从导出获取
  rl.query = p.toString();
  rl.cursors = [''];
  rl.page = 0;
  await rlFetch();
}
async function rlFetch(scroll = false) {
  const seq = ++rl.seq;
  $('#rlInfo').textContent = '检索中…';
  $('#rlPrev').disabled = $('#rlNext').disabled = true;
  const cursor = rl.cursors[rl.page];
  try {
    const r = await api('/api/rawlog/search?' + rl.query + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''));
    if (seq !== rl.seq) return; // 期间又发起了新的检索或翻页
    rl.cursors.length = rl.page + 1;
    if (r.next) rl.cursors.push(r.next);
    const first = rl.page * rl.size;
    const range = r.records.length ? `第 ${num(first + 1)}-${num(first + r.records.length)} 条，` : '';
    // 找够一页后不再扫描更早的分段，这时总数只是下限
    const total = `${r.matched_all ? '共' : '至少'} ${num(first + r.matched)} 条`;
    const note = r.truncated && !(r.next && /^结果较多/.test(r.reason || '')) ? ' · ' + (r.reason || '结果不完整') : '';
    $('#rlInfo').textContent = `${range}${total} · 扫描 ${r.scanned}/${r.segments} 个分段 · ${fmtBytes(r.bytes)} · 耗时 ${r.took}${note}`;
    $('#rlTable').innerHTML = `<thead><tr><th>时间</th><th>数据源</th><th>来源 → 目的</th><th>原始日志</th></tr></thead><tbody>${r.records.map((x) => `<tr class="${x.attack ? 'row-attack' : ''}">
      <td class="nowrap muted">${esc(fmtTime(x.time))}</td><td class="nowrap">${esc(x.source)}</td>
      <td class="nowrap">${x.src_ip ? ipLink(x.src_ip) : '-'}${x.dst_ip ? ` <span class="muted">→ ${esc(x.dst_ip)}</span>` : ''}${x.attack ? ' <span class="chip warn">攻击</span>' : ''}</td>
      <td class="raw mono">${esc(x.raw)}${x.raw_len ? ` <span class="muted">…（共 ${fmtBytes(x.raw_len)}，导出可查看完整内容）</span>` : ''}</td></tr>`).join('') || empty(4, '没有符合条件的日志')}</tbody>`;
    $('#rlPageNo').textContent = rl.page || r.next ? `第 ${rl.page + 1} 页` : '';
    $('#rlPrev').disabled = rl.page === 0;
    $('#rlNext').disabled = !r.next;
    if (scroll) $('#rlTable').closest('.panel').scrollIntoView({ block: 'start' });
  } catch (err) {
    if (seq !== rl.seq) return;
    $('#rlInfo').textContent = '';
    setMsg('#rlMsg', err.message);
    $('#rlPrev').disabled = rl.page === 0;
  }
}
$('#rlPrev').addEventListener('click', () => { if (rl.page > 0) { rl.page--; rlFetch(true); } });
$('#rlNext').addEventListener('click', () => { if (rl.cursors[rl.page + 1]) { rl.page++; rlFetch(true); } });
$('#rlSize').addEventListener('change', () => {
  rl.size = +$('#rlSize').value;
  try { localStorage.setItem('netsa.rlSize', String(rl.size)); } catch (_) { /* 隐私模式 */ }
  if (rl.query) searchRawlog();
});
$('#rlForm').addEventListener('submit', (e) => { e.preventDefault(); searchRawlog(); });
$('#rlExport').addEventListener('click', () => { window.location.href = '/api/rawlog/export?' + rlParams(5000); });
async function loadRawlog() {
  if (!rlInited) { rlInited = true; rlRange(60); }
  if (!meta.rawlog) {
    $('#rlForm').hidden = true;
    $('#rlStatus').textContent = '';
    $('#rlStatusBody').innerHTML = '<div class="nt-help">未启用原始日志留存。在配置文件中设置 <code>rawlog.enabled: true</code>（默认留存 180 天，满足《网络安全法》日志留存不少于六个月的要求）后，可按时间、IP、关键字检索原始日志、查看告警前后的日志并导出取证。</div>';
    $('#rlTable').innerHTML = '';
    return;
  }
  const st = await api('/api/rawlog/status');
  $('#rlStatus').textContent = `留存 ${st.retention_days ? st.retention_days + ' 天' : '永久'}${st.max_bytes ? ` · 上限 ${fmtBytes(st.max_bytes)}` : ''} · 占用 ${fmtBytes(st.disk_bytes)}${st.attacks_only ? ' · 只留存攻击事件' : ''}`;
  $('#rlStatusBody').innerHTML = `<div class="kv">
    <div class="k">留存范围</div><div>${st.oldest ? `${esc(st.oldest)} ~ ${esc(st.newest)}（${st.days.length} 天）` : '暂无'}</div>
    <div class="k">本次启动以来</div><div>写入 ${num(st.written)} 条（原始 ${fmtBytes(st.bytes_in)}）${st.dropped ? ` · <span class="lv-high">丢弃 ${num(st.dropped)} 条</span>` : ''}${st.expired ? ` · <span class="muted">早于留存期限未写入 ${num(st.expired)} 条</span>` : ''}</div>
    ${st.last_error ? `<div class="k">最近错误</div><div class="arc-err">${esc(st.last_error)}</div>` : ''}
    <div class="k">防篡改</div><div>已关闭的分段以 SHA-256 登记到哈希链清单 ${isAdmin() ? '<button type="button" class="btn" id="rlVerify">校验完整性</button> <span id="rlVerifyMsg"></span>' : ''}</div></div>`;
  if ($('#rlVerify')) $('#rlVerify').onclick = () => ntBusy($('#rlVerify'), async () => {
    $('#rlVerifyMsg').textContent = '校验中…';
    try {
      const v = await api('/api/rawlog/verify', 'POST', {});
      $('#rlVerifyMsg').innerHTML = v.problems.length
        ? `<b class="lv-critical">发现 ${v.problems.length} 个问题</b><div class="arc-err">${v.problems.map(esc).join('<br>')}</div>`
        : `<span class="nt-on">✓ 通过</span> <span class="muted">校验 ${v.files} 个分段，哈希链 ${v.entries} 条${v.expired ? `，已按策略清理 ${v.expired} 个` : ''}${v.open ? `，${v.open} 个正在写入` : ''}</span>`;
    } catch (err) { $('#rlVerifyMsg').textContent = err.message; }
  });
}
// openRawlogAround 检索某个来源在某一时刻前后的原始日志（默认前后 5 分钟）
function openRawlogAround(ip, time, minutes = 5) {
  rlInited = true;
  const t = zero(time) ? Date.now() : new Date(time).getTime();
  $('#rlFrom').value = toInput(new Date(t - minutes * 60000));
  $('#rlTo').value = toInput(new Date(Math.min(t + minutes * 60000, Date.now())));
  $$('#rlRange button').forEach((b) => b.classList.remove('active'));
  $('#rlIP').value = ip || '';
  $('#rlQ').value = '';
  $('#rlSource').value = '';
  $('#rlAttack').checked = false;
  closeDrawer();
  switchTab('rawlog');
  searchRawlog();
}

// ---------------- 资产与漏洞 ----------------
const VSTATUS = { open: '未修复', fixed: '已修复', accepted: '风险接受' };
const av = { view: 'assets', list: [], editing: null, imp: 'normal', impType: 'assets', impMode: 'merge' };
segInit('#avView', (b) => { av.view = b.dataset.v; $('#avImp').hidden = av.view !== 'assets'; $('#avVStatus').hidden = av.view !== 'vulns'; loadAssets().catch(console.error); });
['#avImp', '#avVStatus'].forEach((s) => $(s).addEventListener('change', () => loadAssets().catch(console.error)));
let avDebounce;
$('#avSearch').addEventListener('input', () => { clearTimeout(avDebounce); avDebounce = setTimeout(() => loadAssets().catch(console.error), 300); });
const sevCounts = (m) => ['critical', 'high', 'medium', 'low'].filter((k) => m?.[k]).map((k) => `<span class="lv-${k}">${LV[k]} ${m[k]}</span>`).join(' ');
async function loadAssets() {
  if (!meta.assets) { $('#avTable').innerHTML = empty(1, '未启用资产管理'); return; }
  const q = $('#avSearch').value.trim();
  if (av.view === 'vulns') {
    const r = await api('/api/vulns?' + new URLSearchParams({ q, status: $('#avVStatus').value, limit: 1000 }));
    av.list = r.vulns;
    $('#avTable').innerHTML = `<thead><tr><th>等级</th><th>漏洞</th><th>目标</th><th>资产</th><th>组件</th><th>状态</th><th>发现 / 更新</th><th>修复建议</th></tr></thead><tbody>${r.vulns.map((v, i) => `<tr>
      <td>${badge(v.severity)}</td><td><b>${esc(v.name)}</b>${(v.cve || []).length ? `<div class="mono muted">${v.cve.map(esc).join(' ')}</div>` : ''}</td>
      <td class="mono nowrap">${esc(v.ip || v.host)}${v.port ? ':' + v.port : ''}</td>
      <td>${v.asset ? `${esc(v.asset)} ${IMPC(v.asset_importance)}${v.owner ? `<div class="muted">负责人 ${esc(v.owner)}</div>` : ''}` : '<span class="muted">未登记</span>'}</td>
      <td>${esc(v.product || '-')}</td>
      <td class="nowrap">${canOperate() ? `<select data-vi="${i}">${Object.entries(VSTATUS).map(([k, l]) => `<option value="${k}" ${k === v.status ? 'selected' : ''}>${l}</option>`).join('')}</select>` : esc(VSTATUS[v.status] || v.status)}</td>
      <td class="nowrap muted">${esc(fmtShort(v.found))}<br>${esc(fmtShort(v.updated))}</td><td class="evidence">${esc(v.solution || '')}</td></tr>`).join('') || empty(8, '没有符合条件的漏洞，可点击“导入 CSV”导入漏洞扫描结果')}</tbody>`;
    $('#avKpis').innerHTML = `<div class="kpi"><span class="label">漏洞</span><span class="value">${num(r.total)}</span><span class="sub">当前筛选条件下</span></div>`;
    return;
  }
  const r = await api('/api/assets?' + new URLSearchParams({ q, importance: $('#avImp').value }));
  av.list = r.assets;
  const s = r.summary;
  $('#avKpis').innerHTML = `
    <div class="kpi"><span class="label">资产</span><span class="value">${num(s.assets)}</span><span class="sub">核心 ${num(s.by_importance.core || 0)} · 重要 ${num(s.by_importance.important || 0)} · 一般 ${num(s.by_importance.normal || 0)}</span></div>
    <div class="kpi"><span class="label">未修复漏洞</span><span class="value ${s.open_vulns ? 'lv-high' : ''}">${num(s.open_vulns)}</span><span class="sub">${sevCounts(s.open_by_severity) || '无'}</span></div>
    <div class="kpi"><span class="label">核心资产高危漏洞</span><span class="value ${s.core_open_high ? 'lv-critical' : ''}">${num(s.core_open_high)}</span><span class="sub">需优先修复</span></div>
    <div class="kpi"><span class="label">已修复 / 风险接受</span><span class="value">${num(s.fixed)} / ${num(s.accepted)}</span><span class="sub">共 ${num(s.vulns)} 个漏洞</span></div>
    <div class="kpi"><span class="label">未填写负责人</span><span class="value ${s.no_owner ? 'lv-medium' : ''}">${num(s.no_owner)}</span><span class="sub">等保要求资产清单包含责任部门</span></div>`;
  const admin = isAdmin();
  $('#avTable').innerHTML = `<thead><tr><th>资产</th><th>IP / 网段</th><th>域名</th><th>重要性</th><th>等保</th><th>负责人 / 部门</th><th>环境 / 标签</th><th>未修复漏洞</th><th></th></tr></thead><tbody>${r.assets.map((a, i) => `<tr>
    <td><b>${esc(a.name)}</b>${a.note ? `<div class="muted">${esc(a.note)}</div>` : ''}</td><td class="mono">${esc(a.ip || '-')}</td>
    <td class="mono">${(a.hosts || []).map(esc).join('<br>') || '-'}</td><td>${IMPC(a.importance)}</td><td>${a.mlps ? `第${'一二三四五'[a.mlps - 1]}级` : '-'}</td>
    <td>${esc(a.owner || '-')}<div class="muted">${esc(a.dept || '')}</div></td>
    <td>${esc(a.env || '')}<div class="cell-chips">${(a.tags || []).map((t) => `<span class="chip">${esc(t)}</span>`).join('')}</div></td>
    <td>${a.open_vulns ? `<b>${a.open_vulns}</b> ${sevCounts(a.vuln_by_severity)}` : '<span class="muted">0</span>'}</td>
    <td class="nowrap num"><button type="button" class="btn" data-av="alerts" data-i="${i}" title="查看针对该资产的告警">告警</button>${admin ? ` <button type="button" class="btn" data-av="edit" data-i="${i}">编辑</button>` : ''}</td></tr>`).join('')
    || empty(9, '资产台账为空：点击“导入 CSV”导入 CMDB 资产，或“登记资产”逐个添加')}</tbody>`;
}
$('#avTable').addEventListener('change', async (e) => {
  const sel = e.target.closest('select[data-vi]');
  if (!sel) return;
  const v = av.list[+sel.dataset.vi];
  try { await api('/api/vulns/' + encodeURIComponent(v.id), 'PUT', { status: sel.value }); } catch (err) { alert(err.message); }
  loadAssets().catch(console.error);
});
$('#avTable').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-av]');
  if (!b) return;
  const a = av.list[+b.dataset.i];
  if (b.dataset.av === 'edit') openAsset(a);
  else drillTo('alerts', { params: { asset: a.name }, label: `目标资产：${a.name}` });
});
function openAsset(a) {
  av.editing = a ? a.id : null;
  $('#assetTitle').textContent = a ? `编辑资产 · ${a.name}` : '登记资产';
  $('#asIP').value = a?.ip || '';
  $('#asHosts').value = (a?.hosts || []).join(', ');
  $('#asName').value = a?.name || '';
  $('#asOwner').value = a?.owner || '';
  $('#asDept').value = a?.dept || '';
  $('#asEnv').value = a?.env || '';
  $('#asTags').value = (a?.tags || []).join(', ');
  $('#asNote').value = a?.note || '';
  $('#asMLPS').value = String(a?.mlps || 0);
  av.imp = a?.importance || 'normal';
  segSet('#asImpSeg', 'i', av.imp);
  $('#asDel').hidden = !a;
  setMsg('#asMsg', '');
  openModal('assetModal');
  $('#asIP').focus();
}
segInit('#asImpSeg', (b) => { av.imp = b.dataset.i; });
$('#avAdd').addEventListener('click', () => openAsset(null));
const splitList = (s) => s.split(/[,，;；\s]+/).map((x) => x.trim()).filter(Boolean);
$('#assetForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const body = { ip: $('#asIP').value.trim(), hosts: splitList($('#asHosts').value), name: $('#asName').value.trim(), owner: $('#asOwner').value.trim(), dept: $('#asDept').value.trim(),
    importance: av.imp, mlps: +$('#asMLPS').value, env: $('#asEnv').value.trim(), tags: splitList($('#asTags').value), note: $('#asNote').value.trim() };
  if (!body.ip && !body.hosts.length) { setMsg('#asMsg', '请填写 IP / 网段或域名'); return; }
  ntBusy($('#asSave'), async () => {
    try {
      if (av.editing) await api('/api/assets/' + encodeURIComponent(av.editing), 'PUT', body);
      else await api('/api/assets', 'POST', body);
      closeModal('assetModal');
      loadAssets().catch(console.error);
    } catch (err) { setMsg('#asMsg', err.message); }
  });
});
$('#asDel').addEventListener('click', async () => {
  if (!av.editing || !confirm('确定删除该资产？资产上的漏洞记录保留。')) return;
  try { await api('/api/assets/' + encodeURIComponent(av.editing), 'DELETE'); closeModal('assetModal'); } catch (err) { setMsg('#asMsg', err.message); return; }
  loadAssets().catch(console.error);
});
function impHint() {
  $('#impModeHint').textContent = av.impMode === 'merge'
    ? (av.impType === 'assets' ? '按 IP（或域名）更新已有资产、追加新资产。' : '按 IP、端口与 CVE（或名称）更新已有漏洞、追加新漏洞。')
    : (av.impType === 'assets' ? '先删除以往导入的资产（界面登记的保留），再导入本文件。' : '以本次扫描结果为准：上次存在而本次未出现的未修复漏洞标记为“已修复”。');
  $('#impName').parentElement.hidden = av.impType !== 'vulns';
}
segInit('#impType', (b) => { av.impType = b.dataset.t; impHint(); });
segInit('#impMode', (b) => { av.impMode = b.dataset.m; impHint(); });
$('#avImport').addEventListener('click', () => {
  av.impType = av.view === 'vulns' ? 'vulns' : 'assets';
  av.impMode = 'merge';
  segSet('#impType', 't', av.impType);
  segSet('#impMode', 'm', 'merge');
  $('#impFile').value = '';
  $('#impName').value = '';
  impHint();
  setMsg('#impMsg', '');
  openModal('impModal');
});
$('#impForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = $('#impFile').files[0];
  if (!f) { setMsg('#impMsg', '请选择 CSV 文件'); return; }
  if (f.size > 20 << 20) { setMsg('#impMsg', '文件超过 20MB'); return; }
  ntBusy($('#impSave'), async () => {
    try {
      const qs = new URLSearchParams({ type: av.impType, mode: av.impMode, name: $('#impName').value.trim() || f.name });
      const resp = await fetch('/api/assets/import?' + qs, { method: 'POST', headers: { 'Content-Type': 'text/csv', Accept: 'application/json' }, body: f });
      const r = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(r.error || resp.statusText);
      setMsg('#impMsg', `导入完成：新增 ${r.added}、更新 ${r.updated}${r.removed ? `、${av.impType === 'vulns' ? '标记已修复' : '删除'} ${r.removed}` : ''}、跳过 ${r.skipped}${(r.errors || []).length ? '。\n' + r.errors.slice(0, 8).join('\n') : ''}`, true);
      loadAssets().catch(console.error);
    } catch (err) { setMsg('#impMsg', err.message); }
  });
});

// ---------------- 报表与合规 ----------------
let rpKey = 'week:recent';
segInit('#rpRange', (b) => { rpKey = b.dataset.k; loadReports().catch(console.error); });
const rpQuery = () => { const [period, range] = rpKey.split(':'); return { period, range }; };
const pctText = (v) => (v < 0 ? '-' : Math.round(v * 100) + '%');
async function loadReports() {
  const q = rpQuery();
  const r = await api('/api/reports/periodic?' + new URLSearchParams(q));
  const t = r.totals;
  const chg = (cur, prev) => (prev ? `<span class="${cur > prev ? 'lv-high' : 'nt-on'}">${cur >= prev ? '+' : ''}${Math.round(((cur - prev) * 100) / prev)}%</span>` : '');
  const rank = (list, unit) => (list || []).slice(0, 5).map((x) => `<tr><td>${esc(x.name)}${x.detail ? `<div class="muted">${esc(x.detail)}</div>` : ''}</td><td class="num">${num(x.value)}${unit}</td></tr>`).join('') || empty(2);
  const ic = r.incidents;
  $('#rpBody').innerHTML = `
    <div class="rp-title"><b>${esc(r.title)}</b> <span class="muted">对比 ${esc(r.prev_from)} ~ ${esc(r.prev_to)}</span></div>
    <div class="kpis rp-kpis">
      <div class="kpi"><span class="label">安全评分</span><span class="value">${r.score}</span><span class="sub">${esc(r.grade_label)}${r.score_from >= 0 ? ` · 期初 ${r.score_from}` : ''}</span></div>
      <div class="kpi"><span class="label">攻击</span><span class="value">${num(t.attacks)}</span><span class="sub">上期 ${num(r.prev.attacks)} ${chg(t.attacks, r.prev.attacks)}</span></div>
      <div class="kpi"><span class="label">攻击源</span><span class="value">${num(t.attackers)}</span><span class="sub">新增 ${num(t.new_attackers)}</span></div>
      <div class="kpi"><span class="label">疑似成功</span><span class="value ${t.success ? 'lv-critical' : ''}">${num(t.success)}</span><span class="sub">已拦截 ${num(t.blocked)}</span></div>
      <div class="kpi"><span class="label">事件 新建 / 关闭</span><span class="value">${num(ic.created)} / ${num(ic.closed)}</span><span class="sub">按时处置 ${pctText(ic.sla_rate)}${ic.mttr ? ` · 平均 ${esc(fmtDur(ic.mttr))}` : ''}</span></div>
    </div>
    <ul class="rp-summary">${r.summary.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>
    ${(r.notes || []).map((n) => `<div class="muted">注：${esc(n)}</div>`).join('')}
    <div class="grid-2 rp-ranks">
      <table class="table"><thead><tr><th>攻击类型 TOP</th><th class="num">次数</th></tr></thead><tbody>${rank(r.categories, '')}</tbody></table>
      <table class="table"><thead><tr><th>攻击源 TOP</th><th class="num">次数</th></tr></thead><tbody>${rank(r.attackers, '')}</tbody></table>
    </div>`;
  const e = r.email || {};
  $('#rpMailInfo').innerHTML = e.configured
    ? `邮件：已配置，收件人 ${num(e.recipients)} 个；${e.weekly ? `每周 ${esc(e.weekly)} 自动发送上周周报` : '未开启周报定时发送'}；${e.monthly ? `每月 ${esc(e.monthly)} 自动发送上月月报` : '未开启月报定时发送'}。`
    : '邮件：未配置。在配置文件的 <code>report.smtp</code> 中填写发信服务器、<code>report.recipients</code> 中填写收件人后，可定时发送周报 / 月报。也可点击“打开打印版”后在浏览器中另存为 PDF。';
  $('#rpMail').disabled = !e.configured;
  if (isAdmin()) loadCompliance().catch(console.error);
}
$('#rpOpen').addEventListener('click', () => window.open('/api/reports/periodic?' + new URLSearchParams({ ...rpQuery(), format: 'html' }), '_blank', 'noopener'));
$('#rpMail').addEventListener('click', () => {
  if (!confirm('立即生成当前报告并发送给配置的收件人？')) return;
  ntBusy($('#rpMail'), async () => {
    try { const r = await api('/api/reports/email', 'POST', rpQuery()); alert(`已发送：${r.title}`); } catch (err) { alert('发送失败：' + err.message); }
  });
});
const CP = { pass: ['符合', 'nt-on'], partial: ['部分符合', 'nt-warn'], fail: ['不符合', 'lv-critical'], na: ['不适用', 'muted'] };
let cpLoaded = 0;
async function loadCompliance(force) {
  if (!force && Date.now() - cpLoaded < 60000) return; // 合规检查包含完整性校验，1 分钟内不重复计算
  const r = await api('/api/compliance/mlps');
  cpLoaded = Date.now();
  $('#cpTime').textContent = `检查时间 ${fmtTime(r.generated)}`;
  $('#cpSummary').innerHTML = `<div class="cp-rate"><b>${pctText(r.rate)}</b><span>技术项符合率</span></div>
    <div class="cp-counts"><span class="nt-on">符合 ${r.pass}</span><span class="nt-warn">部分符合 ${r.partial}</span><span class="lv-critical">不符合 ${r.fail}</span><span class="muted">不适用 ${r.na}</span></div>
    <div class="cp-layers">${r.layers.map((l) => `<span class="chip">${esc(l.name)} ${pctText(l.rate)}</span>`).join('')}</div>`;
  $('#cpTable').innerHTML = `<thead><tr><th>控制点</th><th>结果</th><th>证据 / 整改建议</th></tr></thead><tbody>${r.items.map((it) => {
    const [lbl, cls] = CP[it.status] || [it.label, ''];
    return `<tr><td><span class="muted">${esc(it.layer)}</span><br><b>${esc(it.control)}</b><div class="muted cp-req">${esc(it.require)}</div></td>
      <td class="nowrap"><b class="${cls}">${esc(lbl)}</b></td><td>${esc(it.evidence)}${it.advice ? `<div class="cp-adv">整改：${esc(it.advice)}</div>` : ''}</td></tr>`;
  }).join('')}</tbody>`;
}
$('#cpRefresh').addEventListener('click', () => ntBusy($('#cpRefresh'), () => loadCompliance(true).catch((e) => alert(e.message))));
$('#cpOpen').addEventListener('click', () => window.open('/api/compliance/mlps?format=html', '_blank', 'noopener'));

// ---------------- 双因素认证 ----------------
let tfStep = '';
async function openTwoFactor(forced) {
  tfForced = !!forced;
  $('#tfClose').hidden = tfForced;
  $('#tfCancel').hidden = tfForced;
  $('#tfSave').hidden = false;
  if (me.two_factor && !tfForced) {
    tfStep = 'disable';
    $('#tfTitle').textContent = '双因素认证';
    $('#tfBody').innerHTML = `<div class="nt-help"><b class="nt-on">✓ 已启用</b>：登录时除密码外还需输入身份验证器中的动态口令。丢失手机时可用恢复码登录，或请管理员重置。</div>
      ${meta.require_2fa ? '<div class="nt-help nt-warn">平台已开启强制双因素认证：关闭后下次登录将要求重新绑定。</div>' : ''}
      <h4 style="margin:4px 0">关闭双因素认证</h4>
      <label class="field"><span class="flabel">当前密码</span><input id="tfPw" type="password" autocomplete="current-password"></label>
      <label class="field"><span class="flabel">动态口令</span><input id="tfCode" inputmode="numeric" autocomplete="one-time-code" maxlength="20" placeholder="6 位动态口令或恢复码"></label>
      <div class="form-msg" id="tfMsg" role="status"></div>`;
    $('#tfSave').textContent = '关闭双因素认证';
    $('#tfSave').className = 'btn danger';
    openModal('tfModal');
    return;
  }
  tfStep = 'enable';
  $('#tfTitle').textContent = tfForced ? '请先绑定身份验证器' : '启用双因素认证';
  $('#tfSave').textContent = '验证并启用';
  $('#tfSave').className = 'btn primary';
  $('#tfBody').innerHTML = '<div class="muted">正在生成绑定密钥…</div>';
  openModal('tfModal');
  let s;
  try { s = await api('/api/auth/2fa/setup', 'POST', {}); } catch (err) {
    $('#tfBody').innerHTML = `<div class="form-msg err">${esc(err.message)}</div>`;
    $('#tfSave').hidden = true;
    return;
  }
  const secret = s.secret.replace(/(.{4})/g, '$1 ').trim();
  $('#tfBody').innerHTML = `${tfForced ? '<div class="nt-help nt-warn">平台安全策略要求所有账号启用双因素认证，绑定完成后才能继续使用。</div>' : ''}
    <div class="tf-setup">
      <div class="tf-qr" aria-label="绑定二维码">${s.qr_svg || ''}</div>
      <ol class="tf-steps">
        <li>在手机上打开身份验证器 App（Microsoft Authenticator、Google Authenticator、阿里云 App、腾讯身份验证器等）。</li>
        <li>扫描左侧二维码；无法扫描时选择“手动输入密钥”，填写：<div class="tf-secret mono">${esc(secret)}</div><span class="muted">类型：基于时间（TOTP），6 位，30 秒</span></li>
        <li>输入 App 中显示的 6 位动态口令完成绑定。</li>
      </ol>
    </div>
    <label class="field"><span class="flabel">动态口令</span><input id="tfCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="6 位数字"></label>
    <div class="form-msg" id="tfMsg" role="status"></div>`;
  $('#tfCode').focus();
}
$('#menu2FA').addEventListener('click', () => { toggleUserDrop(false); openTwoFactor(false); });
$('#tfForm').addEventListener('submit', (e) => {
  e.preventDefault();
  if (tfStep === 'done') { closeRecovery(); return; }
  const code = ($('#tfCode')?.value || '').replace(/\s/g, '');
  if (!code) { setMsg('#tfMsg', '请输入动态口令'); return; }
  ntBusy($('#tfSave'), async () => {
    try {
      if (tfStep === 'disable') {
        await api('/api/auth/2fa/disable', 'POST', { password: $('#tfPw').value, code });
        me.two_factor = false;
        tfForced = false;
        closeModal('tfModal');
        alert('已关闭双因素认证');
        return;
      }
      const r = await api('/api/auth/2fa/enable', 'POST', { code });
      me.two_factor = true;
      showRecovery(r.recovery || []);
    } catch (err) { setMsg('#tfMsg', err.message); }
  });
});
function showRecovery(codes) {
  tfStep = 'done';
  $('#tfTitle').textContent = '双因素认证已启用';
  $('#tfBody').innerHTML = `<div class="nt-help"><b class="nt-on">✓ 绑定成功。</b>请立即保存以下恢复码：手机丢失或无法使用身份验证器时，每个恢复码可代替动态口令登录一次。恢复码只显示这一次。</div>
    <div class="tf-codes mono">${codes.map((c) => `<span>${esc(c)}</span>`).join('')}</div>
    <div><button type="button" class="btn" id="tfCopy">复制</button> <button type="button" class="btn" id="tfDownload">下载为文本文件</button></div>`;
  $('#tfSave').textContent = '我已保存恢复码';
  $('#tfClose').hidden = true;
  $('#tfCancel').hidden = true;
  const text = `netsa 双因素认证恢复码（账号 ${me.user}）\n每个恢复码只能使用一次，请妥善保管。\n\n${codes.join('\n')}\n`;
  $('#tfCopy').onclick = () => navigator.clipboard?.writeText(text).then(() => { $('#tfCopy').textContent = '已复制'; });
  $('#tfDownload').onclick = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    a.download = `netsa-recovery-${me.user}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
}
function closeRecovery() {
  const reload = tfForced;
  tfForced = false;
  closeModal('tfModal');
  if (reload) location.reload(); // 强制绑定完成后重新进入大屏
}

// ---------------- API 令牌 ----------------
async function loadTokens() {
  if (!isAdmin() || !meta.auth) { $('#tokTable').innerHTML = empty(1, '未开启登录认证时不需要 API 令牌'); $('#tokAdd').hidden = true; return; }
  const list = await api('/api/auth/tokens');
  $('#tokTable').innerHTML = `<thead><tr><th>名称</th><th>令牌</th><th>所属账号</th><th>权限</th><th>创建</th><th>有效期</th><th>最近使用</th><th></th></tr></thead><tbody>${list.map((t) => `<tr class="${t.expired ? 'muted' : ''}">
    <td><b>${esc(t.name)}</b></td><td class="mono">${esc(t.prefix)}…</td><td>${esc(t.user)}</td><td><span class="chip">${esc(ROLE[t.role] || t.role)}</span></td>
    <td class="nowrap muted">${esc(t.creator)} · ${esc(fmtShort(t.created))}</td>
    <td class="nowrap">${zero(t.expires) ? '永不过期' : t.expired ? '<span class="nt-warn">已过期</span>' : esc(fmtShort(t.expires)) + ' 前'}</td>
    <td class="nowrap muted">${zero(t.last_used) ? '从未使用' : `${esc(fmtShort(t.last_used))} · ${esc(t.last_ip || '')}`}</td>
    <td class="num"><button type="button" class="btn danger" data-tok="${esc(t.id)}" data-name="${esc(t.name)}">吊销</button></td></tr>`).join('') || empty(8, '暂无令牌')}</tbody>`;
}
$('#tokAdd').addEventListener('click', () => {
  $('#tokBody').querySelectorAll('label, .hint').forEach((el) => { el.hidden = false; });
  $('#tokResult')?.remove();
  $('#tokName').value = '';
  $('#tokUser').innerHTML = users.map((u) => `<option value="${esc(u.name)}" ${u.name === me.user ? 'selected' : ''}>${esc(u.name)}（${esc(ROLE[u.role] || u.role)}）</option>`).join('');
  $('#tokRole').value = 'viewer';
  $('#tokSave').hidden = false;
  setMsg('#tokMsg', '');
  openModal('tokModal');
  $('#tokName').focus();
});
$('#tokForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const body = { name: $('#tokName').value.trim(), user: $('#tokUser').value, role: $('#tokRole').value, days: +$('#tokDays').value };
  if (!body.name) { setMsg('#tokMsg', '请填写令牌名称'); return; }
  ntBusy($('#tokSave'), async () => {
    try {
      const r = await api('/api/auth/tokens', 'POST', body);
      $('#tokBody').querySelectorAll('label, .hint').forEach((el) => { el.hidden = true; });
      setMsg('#tokMsg', '');
      $('#tokSave').hidden = true;
      const host = location.origin;
      const ex = body.role === 'metrics' ? `curl -H "Authorization: Bearer ${r.token}" ${host}/metrics` : `curl -H "Authorization: Bearer ${r.token}" ${host}/api/incidents?status=active`;
      $('#tokMsg').insertAdjacentHTML('beforebegin', `<div id="tokResult"><div class="nt-help"><b class="nt-on">✓ 令牌已创建。</b>请立即复制保存，关闭后无法再次查看（服务端只保存其哈希）。</div>
        <div class="tf-secret mono" id="tokValue">${esc(r.token)}</div>
        <div><button type="button" class="btn" id="tokCopy">复制令牌</button></div>
        <div class="muted" style="margin-top:6px">调用示例：</div><pre class="cmd">${esc(ex)}</pre></div>`);
      $('#tokCopy').onclick = () => navigator.clipboard?.writeText(r.token).then(() => { $('#tokCopy').textContent = '已复制'; });
      loadTokens().catch(console.error);
    } catch (err) { setMsg('#tokMsg', err.message); }
  });
});
$('#tokTable').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-tok]');
  if (!b || !confirm(`确定吊销令牌「${b.dataset.name}」？使用该令牌的系统将立即无法访问。`)) return;
  try { await api('/api/auth/tokens/' + encodeURIComponent(b.dataset.tok), 'DELETE'); } catch (err) { alert(err.message); }
  loadTokens().catch(console.error);
});

// ---------------- 操作审计 ----------------
function auditQS(limit) {
  const p = new URLSearchParams({ limit });
  if ($('#auSearch').value.trim()) p.set('q', $('#auSearch').value.trim());
  if ($('#auAction').value) p.set('action', $('#auAction').value);
  if ($('#auFailed').checked) p.set('failed', '1');
  return p;
}
async function loadAudit() {
  if (!isAdmin()) return;
  let list;
  if (meta.audit) {
    const r = await api('/api/audit?' + auditQS(300));
    list = r.entries;
    const st = r.stats || {};
    $('#auditInfo').textContent = `共 ${num(st.entries)} 条，留存 ${st.retention_days ? st.retention_days + ' 天' : '永久'}${zero(st.oldest) ? '' : `，最早 ${fmtShort(st.oldest)}`}；以 SHA-256 哈希链防篡改，最多显示 300 条`;
    $('#auExport').href = '/api/audit/export?' + auditQS(100000) + '&format=csv';
  } else {
    list = await api('/api/auth/audit?limit=100');
    $('#auVerify').hidden = true;
    $('#auExport').hidden = true;
  }
  $('#auditTable').innerHTML = `<thead><tr>${meta.audit ? '<th class="num">序号</th>' : ''}<th>时间</th><th>账号</th><th>来源 IP</th><th>操作</th><th>结果</th><th>详情 / 客户端</th></tr></thead><tbody>${list.map((a) => `<tr>
    ${meta.audit ? `<td class="num muted" title="${esc(a.hash || '')}">${a.seq}</td>` : ''}<td class="nowrap muted">${esc(fmtShort(a.time))}</td><td>${esc(a.user)}</td><td class="mono">${esc(a.ip)}</td>
    <td class="nowrap">${esc(a.action || '登录')}</td>
    <td>${a.ok ? '<span class="nt-on">成功</span>' : `<span class="nt-err-inline">失败</span> <span class="muted">${esc(a.reason || '')}</span>`}</td>
    <td class="muted evidence">${esc(a.detail || (a.ok ? a.reason : '') || a.agent || '')}</td></tr>`).join('') || empty(7, '暂无记录')}</tbody>`;
}
let auDebounce;
$('#auSearch').addEventListener('input', () => { clearTimeout(auDebounce); auDebounce = setTimeout(() => loadAudit().catch(console.error), 300); });
['#auAction', '#auFailed'].forEach((s) => $(s).addEventListener('change', () => loadAudit().catch(console.error)));
$('#auVerify').addEventListener('click', () => ntBusy($('#auVerify'), async () => {
  $('#auVerifyMsg').textContent = '校验中…';
  try {
    const v = await api('/api/audit/verify', 'POST', {});
    $('#auVerifyMsg').innerHTML = v.ok
      ? `<span class="nt-on">✓ 完整</span> <span class="muted">${num(v.entries)} 条记录，序号 ${v.first_seq} ~ ${v.last_seq}${v.anchored ? '（更早的记录已按留存策略清理）' : ''}</span>`
      : `<b class="lv-critical">✗ 发现 ${v.problems.length} 处异常</b> <span class="arc-err">${v.problems.slice(0, 3).map(esc).join('；')}</span>`;
    loadAudit().catch(console.error);
  } catch (err) { $('#auVerifyMsg').textContent = err.message; }
}));

// ---------------- 自学习 ----------------
const LN_CHANGE = { calibrate: '自动下调', restore: '恢复', calibrate_ctx: '目标级下调', restore_ctx: '目标级恢复', pin: '锁定', unpin: '解锁', apply: '采纳建议', dismiss: '忽略建议', policy: '策略调整' };
let lnPolicy = null;
const LN_ANOM = { new_net: '新地址登录', odd_hour: '非常用时段', login_fail: '登录失败暴增', bulk_export: '批量导出', sensitive: '高危变更' };
// 近 8 周人工结论中的误报占比（从早到晚）：持续下降说明检测在变准
function lnTrendText(trend) {
  const pts = (trend || []).slice().reverse().filter((w) => w.tp + w.fp > 0);
  if (pts.length < 2) return '';
  return `<br>进化效果：近 ${pts.length} 周有结论的周次，误报占比 ${pts.map((w) => Math.round((w.fp / (w.tp + w.fp)) * 100) + '%').join(' → ')}`;
}
// 平台对当前模型的自动适配与研判表现
function aiAdaptRows(p) {
  if (!p) return '';
  const done = p.parsed + p.unparsed;
  const learned = [p.thinks && '推理模型', p.max_tokens_cap && `输出上限 ${num(p.max_tokens_cap)}`, p.no_response_format && '不支持 JSON 模式', p.no_chat_kwargs && '不支持关闭思考参数',
    p.no_temperature && '不发送 temperature', p.use_max_completion && '使用 max_completion_tokens', p.auth_bearer && '使用 Authorization 认证'].filter(Boolean);
  return `<div class="k">研判表现</div><div>${done ? `成功 ${num(p.parsed)} / ${num(done)} 次（${Math.round((p.parsed / done) * 100)}%）` : '尚未研判'}${p.calls ? ` · 平均 ${(p.latency_ms / p.calls / 1000).toFixed(1)} 秒` : ''}${p.repaired ? ` · 修复格式 ${num(p.repaired)} 次` : ''}${p.truncated ? ` · <span class="lv-medium">截断 ${num(p.truncated)} 次</span>` : ''}${p.refused ? ` · <span class="lv-medium">拒答 ${num(p.refused)} 次</span>` : ''}</div>
    ${learned.length ? `<div class="k">自动适配</div><div>${esc(learned.join(' · '))}</div>` : ''}`;
}
async function loadLearn() {
  const { enabled, report: r, ai_status: aiStatus } = await api('/api/learn');
  if (aiStatus) meta.ai = aiStatus;
  const lastComp = (r.compliance || []).slice(-1)[0];
  $('#lnKpis').innerHTML = [
    ['研判样本', num(r.cases), `确认攻击 ${num(r.tp)} · 误报 ${num(r.fp)}`],
    ['自动生效', num(r.applied.rule + r.applied.target + r.applied.escalated),
      enabled ? `下调 ${num(r.applied.rule + r.applied.target)} · 升级 ${num(r.applied.escalated)} 次（${esc(fmtShort(r.applied.since))} 启动以来）` : '未启用自学习'],
    ['待确认建议', num(r.suggestions.length), '采纳后创建误报抑制'],
    ['平台安全异常', num(r.anomalies.length), r.options.sentinel ? '最近 100 条' : '已关闭'],
    ['合规符合率', lastComp ? Math.round(lastComp.rate * 100) + '%' : '-', lastComp ? `不符合 ${num(lastComp.fail)} 项 · ${esc(fmtShort(lastComp.time))}` : (r.options.compliance ? '启动后约 2 分钟首次自检' : '已关闭')],
  ].map(([l, v, s]) => `<div class="kpi"><span class="label">${l}</span><span class="value">${v}</span><span class="sub">${s}</span></div>`).join('');
  const incLinks = (ids) => (ids || []).slice(0, 6).map((id) => `<a href="#tab=incidents&incident=${id}">#${id}</a>`).join(' ');
  $('#lnSugs').innerHTML = r.suggestions.length
    ? `<table class="table"><thead><tr><th>条件</th><th>误报</th><th>相关事件</th><th></th></tr></thead><tbody>${r.suggestions.map((s) => `<tr>
        <td>${s.kind === 'source' ? `来源 <span class="mono">${esc(s.ip)}</span> <span class="muted">（疑似授权扫描 / 内部测试）</span>` : `规则 <span class="mono">${esc(s.rule_id)}</span>${s.origin === 'ai' ? ' <span class="chip" title="来自历史一致率高的模型，分析员尚未处置">模型判断</span>' : ''}<div class="mono muted">${esc(s.target)}</div>`}</td>
        <td>${num(s.fp)} 次</td><td class="nowrap">${incLinks(s.incidents)}</td>
        <td class="nowrap">${canOperate() ? `<button type="button" class="btn" data-ln="apply" data-id="${esc(s.id)}">采纳</button> <button type="button" class="btn" data-ln="dismiss" data-id="${esc(s.id)}">忽略</button>` : ''}</td></tr>`).join('')}</tbody></table>`
    : '<div class="muted">暂无建议。分析员把事件处置为“误报”后，同一规则在同一目标上反复误报、或同一来源多次被整体判为误报时，会在这里提示。</div>';
  $('#lnAnoms').innerHTML = r.anomalies.length
    ? `<table class="table"><tbody>${r.anomalies.map((a) => `<tr><td class="nowrap muted">${esc(fmtShort(a.time))}</td><td class="nowrap">${badge(a.severity)} ${esc(LN_ANOM[a.kind] || a.kind)}</td>
        <td><b>${esc(a.title)}</b><div class="muted">${esc(a.detail)}</div></td></tr>`).join('')}</tbody></table>`
    : `<div class="muted">${r.options.sentinel ? '未发现异常。账号登录满 5 次后开始按“新地址”判断，满 20 次后按“非常用时段”判断。' : '已关闭（learn.sentinel: false）'}</div>`;
  // 当前生效的策略：自学习结果自动作用于检测（下调 / 升级），误报抑制始终需要人工采纳
  const pol = r.policy;
  lnPolicy = pol;
  $('#lnPolicy').innerHTML = `自动生效策略：自动校准 <b>${pol.calibrate ? '开启' : '关闭'}</b>（规则级 ${num(r.calibrated)} 条：样本 ≥ ${num(pol.min_verdicts)}、准确率 ≤ ${Math.round(pol.max_precision * 100)}%；目标级 ${num(r.ctx_total)} 处：误报 ≥ ${num(r.options.ctx_min_fp)} 次）`
    + ` · 确认攻击源复现升级 <b>${pol.escalate ? '开启' : '关闭'}</b>（${num(pol.escalate_days)} 天内，当前 ${num(r.confirmed)} 个来源）`
    + ` · 学习窗口 <b>${pol.window_days ? `${num(pol.window_days)} 天` : '不限'}</b>${r.expired ? `（${num(r.expired)} 个样本已过期）` : ''}`
    + ` · <span>${r.policy_ui ? `界面设置（${esc(pol.updated_by)}，${esc(fmtShort(pol.updated))}）` : '来自配置文件 learn 段'}</span>`
    + lnTrendText(r.trend);
  const pct = (s) => (s.precision < 0 ? '-' : Math.round(s.precision * 100) + '%');
  $('#lnRules').innerHTML = `<thead><tr><th>规则</th><th>确认攻击</th><th>误报</th><th>准确率</th><th>状态</th><th></th></tr></thead><tbody>${r.rules.map((s) => `<tr>
      <td class="mono">${esc(s.rule)}</td><td>${num(s.tp)}</td><td>${num(s.fp)}</td><td>${pct(s)}</td>
      <td>${s.pinned ? '<span class="chip">已锁定</span>' : s.calibrated ? '<span class="lv-medium">已自动下调一级</span>' : '<span class="muted">正常</span>'}</td>
      <td>${isAdmin() ? `<button type="button" class="btn" data-ln="${s.pinned ? 'unpin' : 'pin'}" data-rule="${esc(s.rule)}">${s.pinned ? '解锁' : '锁定'}</button>` : ''}</td></tr>`).join('') || empty(6, '暂无研判样本：在“事件处置”中把事件处置为已处置或误报后开始学习')}</tbody>`;
  $('#lnCtxIntro').textContent = r.options.calibrate
    ? `规则整体准确率正常、只在个别目标上被研判为误报 ≥ ${r.options.ctx_min_fp} 次且从未确认为攻击时，只下调该目标上的命中一级（最多低于攻击分类底线一级，利用成功仍为严重）；该目标出现确认的攻击或锁定规则后自动恢复`
    : '已关闭（learn.calibrate: false）';
  const more = r.ctx_total > r.contexts.length ? `<tr><td colspan="5" class="muted">另有 ${num(r.ctx_total - r.contexts.length)} 处未列出</td></tr>` : '';
  $('#lnCtx').innerHTML = `<thead><tr><th>规则</th><th>目标</th><th>误报</th><th>相关事件</th><th></th></tr></thead><tbody>${r.contexts.map((c) => `<tr>
      <td class="mono">${esc(c.rule)}</td><td class="mono">${esc(c.target)}</td><td>${num(c.fp)} 次</td><td class="nowrap">${incLinks(c.incidents)}</td>
      <td>${isAdmin() ? `<button type="button" class="btn" data-ln="pin" data-rule="${esc(c.rule)}" title="锁定后该规则不参与任何自动校准">锁定规则</button>` : ''}</td></tr>`).join('')}${more}${r.contexts.length ? '' : empty(5, '暂无：同一规则在同一目标上反复被处置为误报、且从未确认为攻击后，自动只下调该目标')}</tbody>`;
  const pts = (r.compliance || []).slice(-168);
  if (pts.length > 1) {
    const w = 320, h = 60;
    const xy = pts.map((p, i) => `${Math.round((i / (pts.length - 1)) * w)},${Math.round(h - p.rate * h)}`).join(' ');
    $('#lnComp').innerHTML = `<svg viewBox="0 0 ${w} ${h}" class="ln-spark" preserveAspectRatio="none" role="img" aria-label="合规符合率趋势"><polyline points="${xy}" fill="none" stroke="currentColor" stroke-width="2"/></svg>
      <div class="muted">近 ${pts.length} 次自检：最低 ${Math.round(Math.min(...pts.map((p) => p.rate)) * 100)}%，最新 ${Math.round(pts[pts.length - 1].rate * 100)}%</div>`;
  } else {
    $('#lnComp').innerHTML = `<div class="muted">${r.options.compliance ? (pts.length ? `已完成首次自检（符合率 ${Math.round(pts[0].rate * 100)}%），之后每小时一次` : '启动后约 2 分钟执行首次自检') : '已关闭（learn.compliance: false）'}</div>`;
  }
  // 外部模型：接入状态以 /api/meta 为准（运营分析员也可查看），配置只允许管理员修改
  const a = meta.ai || {};
  const pctOf = (n, d) => (d ? Math.round((n / d) * 100) + '%' : '-');
  const trust = (r.ai || []).length
    ? `<table class="table ln-trust"><thead><tr><th>模型</th><th title="以分析员的处置结论为准">一致率</th><th>已评估</th><th title="模型判为误报、分析员确认是攻击">漏判</th><th title="模型判为攻击、分析员判为误报">误判为攻击</th><th title="置信度 ≥ 80% 的结论">高置信一致率</th><th>待处置</th></tr></thead><tbody>${r.ai.map((s) => `<tr>
        <td class="mono">${esc(s.model)}</td><td>${s.rate < 0 ? `<span class="muted">样本不足</span>` : `<b>${Math.round(s.rate * 100)}%</b>`}</td><td>${num(s.judged)}</td>
        <td>${s.missed ? `<span class="lv-high">${num(s.missed)}</span>` : '0'}</td><td>${num(s.overcall)}</td><td>${pctOf(s.high_agree, s.high_conf)}</td><td>${num(s.pending)}</td></tr>`).join('')}</tbody></table>
        <div class="muted">分析员把事件处置为已处置 / 误报后，自动与模型当时的结论比对；模型结论不作为学习样本。已评估满 5 个事件后，AI 研判记录中会附上该模型的一致率。</div>`
    : '';
  $('#lnAI').innerHTML = (a.enabled
    ? `<div class="kv"><div class="k">模型</div><div class="mono">${esc(a.model)} <span class="muted">${esc(a.endpoint)}</span></div>
        <div class="k">密钥</div><div>${a.key_set ? '已设置（只保存在服务端，不会回显）' : '<span class="muted">未设置（按无密钥方式调用，适用于内网模型）</span>'}</div>
        <div class="k">脱敏</div><div>${a.desensitize ? '<span class="nt-on">发送前脱敏</span>（内网地址、口令 / 令牌、手机号、证件号、邮箱）' : '<span class="lv-medium">未脱敏</span>（只适用于完全在内网部署的模型）'}</div>
        <div class="k">自动研判</div><div>${a.auto_triage ? '新出现的高危及以上事件自动研判' : '关闭（在事件详情中手动研判）'}</div>
        <div class="k">调用</div><div>近 1 小时 ${num(a.used_hour)} / ${num(a.max_per_hour)} 次 · 累计 ${num(a.total)} 次${a.failed ? ` · <span class="lv-high">失败 ${num(a.failed)} 次</span>` : ''}${a.last_error ? `<div class="arc-err">${esc(a.last_error)}</div>` : ''}</div>
        <div class="k">协议</div><div>${a.protocol === 'anthropic' ? 'Anthropic（/messages）' : 'OpenAI 兼容（/chat/completions）'}</div>
        ${aiAdaptRows(a.adapt)}</div>`
    : `<div class="muted">未启用。${isAdmin() ? '点击右上角“配置模型”，填写模型地址、模型名称与模型密钥后启用' : '请联系管理员在此页面配置模型地址、名称与密钥'}，即可在事件详情中使用“AI 研判”。同时支持 OpenAI 兼容接口与 Anthropic 接口，内网部署的 vLLM / Ollama 和云端模型都可接入。</div>`) + trust;
  $('#lnLog').innerHTML = `<thead><tr><th>时间</th><th>类型</th><th>操作人</th><th>说明</th></tr></thead><tbody>${r.changes.map((c) => `<tr><td class="nowrap muted">${esc(fmtShort(c.time))}</td>
      <td class="nowrap">${esc(LN_CHANGE[c.kind] || c.kind)}</td><td class="nowrap">${esc(c.user)}</td><td>${esc(c.detail)}</td></tr>`).join('') || empty(4, '暂无记录')}</tbody>`;
}
$('#tab-learn').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-ln]');
  if (!b) return;
  const act = b.dataset.ln;
  if (act === 'apply' && !confirm('采纳后将创建一条误报抑制规则，之后符合条件的命中不再告警。确定采纳？')) return;
  if (act === 'pin' && !confirm('锁定后该规则不参与自动校准（已下调的立即恢复原等级）。确定锁定？')) return;
  const url = b.dataset.id ? `/api/learn/suggestions/${encodeURIComponent(b.dataset.id)}/${act}` : `/api/learn/rules/${encodeURIComponent(b.dataset.rule)}/${act}`;
  ntBusy(b, async () => {
    try { await api(url, 'POST', {}); } catch (err) { alert(err.message); }
    loadLearn().catch(console.error);
  });
});

// ---------------- 自学习策略（管理员） ----------------
$('#lnPolicyEdit').addEventListener('click', () => {
  const p = lnPolicy || {};
  $('#lpCalib').checked = !!p.calibrate;
  $('#lpMin').value = p.min_verdicts || 5;
  $('#lpPrec').value = Math.round((p.max_precision || 0.2) * 100);
  $('#lpEsc').checked = !!p.escalate;
  $('#lpDays').value = p.escalate_days || 30;
  $('#lpWindow').value = p.window_days ?? 180;
  setMsg('#lpMsg', '');
  openModal('lpModal');
  $('#lpCalib').focus();
});
$('#lpForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = {
    calibrate: $('#lpCalib').checked, min_verdicts: parseInt($('#lpMin').value, 10) || 0,
    max_precision: (parseFloat($('#lpPrec').value) || 0) / 100, escalate: $('#lpEsc').checked, escalate_days: parseInt($('#lpDays').value, 10) || 0,
    window_days: parseInt($('#lpWindow').value, 10) || 0,
  };
  ntBusy($('#lpSave'), async () => {
    try {
      await api('/api/learn/policy', 'PUT', f);
      closeModal('lpModal');
      loadLearn().catch(console.error);
    } catch (err) { setMsg('#lpMsg', err.message); }
  });
});

// ---------------- 外部模型配置（管理员） ----------------
// 密钥只提交、不回显：留空表示保持原值；更换模型地址的主机时服务端要求重新填写，防止密钥被发到新地址
async function openAIForm() {
  let r;
  try { r = await api('/api/ai/settings'); } catch (err) { alert(err.message); return; }
  const v = r.settings;
  $('#aiEnabled').checked = v.enabled;
  $('#aiBase').value = v.base_url || '';
  $('#aiModel').value = v.model || '';
  $('#aiKey').value = '';
  $('#aiKey').disabled = false;
  $('#aiKey').placeholder = v.key_set ? '已设置（不修改请留空）' : '模型服务提供的 API Key，如 sk-…';
  $('#aiKeyHint').textContent = v.key_source === 'ui'
    ? `已保存界面填写的密钥${v.key_hint ? `（末 4 位 ${v.key_hint}）` : ''}，只保存在服务端，不会回显；更换模型地址的主机时需要重新填写。`
    : v.key_source === 'env'
      ? `当前使用环境变量 ${v.key_env} 中的密钥；在此填写后改用界面保存的密钥。`
      : '密钥只保存在服务端（文件权限 0600），不会回显到页面；不需要密钥的内网模型可留空。';
  $('#aiClearRow').hidden = !v.key_set;
  $('#aiClear').checked = false;
  $('#aiMax').value = v.max_per_hour || 30;
  $('#aiProto').value = v.protocol || 'openai';
  $('#aiThinking').value = v.thinking || 'auto';
  $('#aiTokens').value = v.max_tokens || 0;
  $('#aiTimeout').value = v.timeout_sec || 120;
  $('#aiDesens').checked = v.desensitize;
  $('#aiAuto').checked = v.auto_triage;
  $('#aiAutoMedium').checked = v.auto_triage_medium;
  $('#aiDowngrade').checked = !v.no_downgrade;
  const who = v.updated_by ? `最近由 ${esc(v.updated_by)} 于 ${esc(fmtShort(v.updated))} 修改。` : (v.from_ui ? '' : '当前值来自配置文件 ai 段。');
  $('#aiNote').innerHTML = (v.persist
    ? '保存后立即生效，无需重启；配置保存在服务端状态目录的 ai.json，优先于配置文件。'
    : '<span class="nt-warn">未配置状态目录（storage.snapshot）：配置只保存在内存中，重启后恢复为配置文件中的值。</span>') + ' ' + who;
  setMsg('#aiMsg', '');
  openModal('aiModal');
  $('#aiBase').focus();
}
function aiCollect() {
  return {
    enabled: $('#aiEnabled').checked, base_url: $('#aiBase').value.trim(), model: $('#aiModel').value.trim(),
    api_key: $('#aiClear').checked ? '' : $('#aiKey').value.trim(), clear_key: $('#aiClear').checked,
    max_per_hour: parseInt($('#aiMax').value, 10) || 30, desensitize: $('#aiDesens').checked, auto_triage: $('#aiAuto').checked, auto_triage_medium: $('#aiAutoMedium').checked,
    protocol: $('#aiProto').value, thinking: $('#aiThinking').value, max_tokens: parseInt($('#aiTokens').value, 10) || 0,
    timeout_sec: parseInt($('#aiTimeout').value, 10) || 120, no_downgrade: !$('#aiDowngrade').checked,
  };
}
$('#aiListBtn').addEventListener('click', () => {
  const f = aiCollect();
  if (!f.base_url) { setMsg('#aiMsg', '请先填写模型地址'); return; }
  setMsg('#aiMsg', '正在读取模型列表…', true);
  ntBusy($('#aiListBtn'), async () => {
    try {
      const { models } = await api('/api/ai/models', 'POST', f);
      $('#aiModelList').innerHTML = (models || []).map((m) => `<option value="${esc(m)}"></option>`).join('');
      if ((models || []).length && !$('#aiModel').value) $('#aiModel').value = models[0];
      setMsg('#aiMsg', (models || []).length ? `接口提供 ${models.length} 个模型：${models.slice(0, 5).join('、')}${models.length > 5 ? ' …' : ''}` : '接口没有返回模型列表，请手工填写', !!(models || []).length);
    } catch (err) { setMsg('#aiMsg', err.message); }
  });
});
$('#lnAIEdit').addEventListener('click', openAIForm);
$('#aiClear').addEventListener('change', (e) => { $('#aiKey').disabled = e.target.checked; });
$('#aiDesens').addEventListener('change', (e) => {
  if (!e.target.checked && !confirm('关闭脱敏后，内网地址、口令与个人信息将原样发送给模型，只适用于完全在内网部署的模型。确定关闭？')) e.target.checked = true;
});
$('#aiForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const f = aiCollect();
  if (f.enabled && (!f.base_url || !f.model)) { setMsg('#aiMsg', '启用时请填写模型地址与模型名称'); return; }
  ntBusy($('#aiSave'), async () => {
    try {
      const r = await api('/api/ai/settings', 'PUT', f);
      meta.ai = r.status; // 事件详情中的“AI 研判”按钮随之显示 / 隐藏
      if (r.warning) alert('配置已生效，但' + r.warning);
      closeModal('aiModal');
      loadLearn().catch(console.error);
    } catch (err) { setMsg('#aiMsg', err.message); }
  });
});
$('#aiTestBtn').addEventListener('click', () => {
  const f = aiCollect();
  if (!f.base_url || !f.model) { setMsg('#aiMsg', '请填写模型地址与模型名称后再测试'); return; }
  setMsg('#aiMsg', '正在测试连接…', true);
  ntBusy($('#aiTestBtn'), async () => {
    try {
      const r = await api('/api/ai/test', 'POST', f);
      if (r.protocol) $('#aiProto').value = r.protocol;
      if ((r.models || []).length) $('#aiModelList').innerHTML = r.models.map((m) => `<option value="${esc(m)}"></option>`).join('');
      setMsg('#aiMsg', r.ok ? `连接成功：${r.model} 用时 ${(r.latency_ms / 1000).toFixed(1)} 秒${r.reply ? `，回复“${r.reply}”` : ''}。${r.note || ''}`
        : `连接失败：${r.error}${(r.models || []).length ? `。接口提供的模型：${r.models.slice(0, 5).join('、')}` : ''}`, r.ok);
    } catch (err) { setMsg('#aiMsg', err.message); }
  });
});

// ---------------- 调度 ----------------
Object.assign(loaders, {
  learn: () => loadLearn().catch(console.error),
  incidents: () => Promise.all([loadIncidents(), loadSuppressions()]).catch(console.error),
  assets: () => loadAssets().catch(console.error),
  reports: () => loadReports().catch(console.error),
  rawlog: () => loadRawlog().catch(console.error),
});
// 事件处置页每 10 秒刷新（对话框打开时暂停，避免打断操作）；其他页面每 30 秒刷新导航上的待处置数
setInterval(() => {
  if (document.hidden || anyModalOpen()) return;
  if (currentTab === 'incidents') pollOnce('incidents', loadIncidents);
}, 10000);
setInterval(() => { if (!document.hidden && currentTab !== 'incidents') refreshIncBadge(); }, 30000);
setTimeout(refreshIncBadge, 1500);
// 只看超时：#tab=incidents&overdue=1（超时提醒消息中的链接）
const _incLoader = loaders.incidents;
// ---------------- 联动封禁 ----------------
const BLOCK_STATUS = { pending: '待审批', active: '生效中', rejected: '已驳回', released: '已解除', expired: '已到期' };
async function loadBlockPanel() {
  const panel = $('#blockPanel');
  panel.hidden = !(meta.block && canOperate());
  if (panel.hidden) return;
  const r = await api('/api/block');
  $('#blockInfo').textContent = `待审批 ${num(r.pending)} · 生效中 ${num(r.active)}${r.webhook_failed ? ` · Webhook 失败 ${num(r.webhook_failed)} 次` : ''}`;
  const rows = (r.items || []).map((x) => {
    let acts = '';
    if (isAdmin() && x.status === 'pending') acts = `<button class="btn sm" data-bk="approve" data-id="${x.id}">批准</button> <button class="btn sm" data-bk="reject" data-id="${x.id}">驳回</button>`;
    if (isAdmin() && x.status === 'active') acts = `<button class="btn sm" data-bk="release" data-id="${x.id}">解除</button>`;
    return `<tr><td class="mono">${ipLink(x.ip)}</td><td>${esc(BLOCK_STATUS[x.status] || x.status)}</td><td class="evidence">${esc(x.reason)}${x.note ? `<div class="muted">${esc(x.note)}</div>` : ''}</td>
      <td>${esc(x.requested_by)}</td><td>${esc(x.decided_by || '-')}</td><td class="nowrap">${x.status === 'active' ? esc(fmtShort(x.expires)) : '-'}</td><td class="nowrap">${acts}</td></tr>`;
  }).join('');
  $('#blockTable').innerHTML = `<thead><tr><th>地址</th><th>状态</th><th>原因</th><th>申请人</th><th>审批人</th><th>到期时间</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="7" class="muted">暂无记录</td></tr>'}</tbody>`;
}
$('#blockTable').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-bk]');
  if (!b) return;
  const act = b.dataset.bk;
  let body = {};
  if (act !== 'approve') {
    const note = prompt(act === 'reject' ? '驳回原因：' : '解除原因：', '');
    if (note === null) return;
    body = { note };
  }
  try {
    await api(`/api/block/${b.dataset.id}/${act}`, 'POST', body);
  } catch (err) { alert(err.message); }
  loadBlockPanel().catch(console.error);
});

// ---------------- 规则运营与对接状态 ----------------
async function loadRuleOps() {
  const r = await api('/api/rules/managed');
  const rules = r.rules || [];
  $('#ruleCount').textContent = `托管规则 ${num(rules.length)} 条`;
  $('#ruleTable').innerHTML = `<thead><tr><th>ID</th><th>名称</th><th>分类</th><th>等级</th><th>匹配范围</th><th>表达式</th><th>来源</th><th></th></tr></thead><tbody>${rules.map((x) => `<tr>
    <td class="mono">${esc(x.id)}</td><td>${esc(x.name)}</td><td>${esc(x.category)}</td><td>${badge(x.severity)}</td><td>${esc(x.target)}</td><td class="mono evidence">${esc(x.pattern)}</td><td>${esc(x.source)}</td>
    <td class="nowrap">${String(x.source).startsWith('pack:') ? '' : `<button class="btn sm" data-rule-edit="${esc(x.id)}">修改</button> <button class="btn sm" data-rule-del="${esc(x.id)}">删除</button>`}</td></tr>`).join('') || '<tr><td colspan="8" class="muted">还没有自定义规则</td></tr>'}</tbody>`;
  ruleOps.rules = rules;
  const packs = r.packs || [];
  $('#packTable').hidden = !packs.length;
  $('#packTable').innerHTML = `<thead><tr><th>规则包</th><th>序号</th><th>规则数</th><th>签名密钥</th><th>安装时间</th><th></th></tr></thead><tbody>${packs.map((p) => `<tr><td>${esc(p.name)}</td><td>${num(p.serial)}</td><td>${num(p.rules)}</td><td class="mono">${esc(p.key_id)}</td><td>${esc(fmtShort(p.updated))}</td><td><button class="btn sm" data-pack-del="${esc(p.name)}">卸载</button></td></tr>`).join('')}</tbody>`;
  const s = await api('/api/integrations');
  const row = (name, state, detail) => `<tr><td>${esc(name)}</td><td>${esc(state)}</td><td class="evidence">${esc(detail)}</td></tr>`;
  const items = [
    row('LDAP 登录', s.sso.ldap ? '已启用' : '未配置', ''),
    row('单点登录（OIDC）', s.sso.oidc ? '已启用' : '未配置', ''),
    row('定时备份', s.backup.dir ? '已启用' : '未配置', s.backup.dir ? '' : '可配置 storage.backup_dir，或用 netsa backup 手动备份'),
    row('处置剧本', s.playbooks.enabled ? `${num(s.playbooks.count)} 个` : '未配置', s.playbooks.enabled ? `已执行 ${num(s.playbooks.runs)} 次，工单系统 ${num(s.playbooks.tickets)} 个` : ''),
  ];
  for (const f of s.forward || []) items.push(row(`SIEM 转发：${f.name}`, f.connected ? '已连接' : '未连接', `${f.protocol} ${f.address} ${f.format}，已发送 ${num(f.sent)}，丢弃 ${num(f.dropped)}${f.last_error ? `；最近错误：${f.last_error}` : ''}`));
  for (const f of s.intel || []) items.push(row(`情报源：${f.name}`, f.last_error ? '更新失败' : (f.updated && !zero(f.updated) ? '正常' : '等待更新'), `${f.type}，${num(f.addrs)} 个 IP、${num(f.nets)} 个网段${f.last_error ? `；最近错误：${f.last_error}` : ''}`));
  $('#intTable').innerHTML = `<thead><tr><th>对接项</th><th>状态</th><th>详情</th></tr></thead><tbody>${items.join('')}</tbody>`;
}
const ruleOps = { rules: [] };
function promptRule(cur) {
  const id = prompt('规则 ID（字母、数字、下划线、点、短横线）：', cur?.id || '');
  if (!id) return null;
  const name = prompt('规则名称：', cur?.name || '');
  if (name === null) return null;
  const pattern = prompt('匹配表达式（RE2 正则）：', cur?.pattern || '');
  if (!pattern) return null;
  const target = prompt('匹配范围（uri / path / ua / referer / any）：', cur?.target || 'uri');
  if (target === null) return null;
  const severity = prompt('等级（info / low / medium / high / critical）：', cur?.severity || 'medium');
  if (severity === null) return null;
  const category = prompt('攻击分类（分类决定等级底线，可留空）：', cur?.category || '');
  if (category === null) return null;
  return { id: id.trim(), name, pattern, target: target.trim(), severity: severity.trim(), category: category.trim() };
}
async function saveRule(rule) {
  const sample = prompt('输入一条样本先试运行（可留空跳过），例如 /index.php?id=1：', '');
  if (sample) {
    const t = await api('/api/rules/test', 'POST', { ...rule, sample });
    if (!confirm(t.matched ? `样本命中：${t.evidence}\n\n确定保存？` : '样本没有命中这条规则，仍要保存吗？')) return;
  }
  await api('/api/rules/managed', 'POST', rule);
}
$('#ruleAdd').addEventListener('click', async () => {
  const rule = promptRule(null);
  if (!rule) return;
  try { await saveRule(rule); loadRuleOps().catch(console.error); } catch (err) { alert(err.message); }
});
$('#ruleTable').addEventListener('click', async (e) => {
  const ed = e.target.closest('[data-rule-edit]');
  const del = e.target.closest('[data-rule-del]');
  try {
    if (ed) {
      const rule = promptRule(ruleOps.rules.find((x) => x.id === ed.dataset.ruleEdit));
      if (rule) await saveRule(rule);
    } else if (del && confirm(`删除规则 ${del.dataset.ruleDel}？`)) {
      await api(`/api/rules/managed/${encodeURIComponent(del.dataset.ruleDel)}`, 'DELETE');
    } else return;
    loadRuleOps().catch(console.error);
  } catch (err) { alert(err.message); }
});
$('#packTable').addEventListener('click', async (e) => {
  const del = e.target.closest('[data-pack-del]');
  if (!del || !confirm(`卸载规则包 ${del.dataset.packDel}？其中的规则将不再生效。`)) return;
  try {
    await api(`/api/rules/packs/${encodeURIComponent(del.dataset.packDel)}`, 'DELETE');
    loadRuleOps().catch(console.error);
  } catch (err) { alert(err.message); }
});
// 从本地文件读取内容：规则包和 Sigma 规则都可能很长，不适合粘贴到输入框
function pickFile(accept) {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.addEventListener('change', () => { input.files[0] ? input.files[0].text().then(resolve) : resolve(null); });
    input.click();
  });
}
$('#rulePack').addEventListener('click', async () => {
  const text = await pickFile('.json');
  if (text === null) return;
  try {
    const st = await api('/api/rules/packs', 'POST', JSON.parse(text));
    alert(`已安装规则包 ${st.name}（序号 ${st.serial}，${st.rules} 条规则）`);
    loadRuleOps().catch(console.error);
  } catch (err) { alert(err.message); }
});
$('#ruleSigma').addEventListener('click', async () => {
  const text = await pickFile('.yml,.yaml');
  if (text === null) return;
  try {
    const pre = await api('/api/rules/sigma', 'POST', { yaml: text, apply: false });
    const skipped = (pre.skipped || []).slice(0, 10).map((s) => `· ${s.title}：${s.reason}`).join('\n');
    if (!(pre.rules || []).length) { alert(`没有可以转换的规则。\n${skipped}`); return; }
    if (!confirm(`可以转换 ${pre.rules.length} 条，跳过 ${(pre.skipped || []).length} 条。\n${skipped}\n\n确定导入？`)) return;
    const res = await api('/api/rules/sigma', 'POST', { yaml: text, apply: true });
    alert(`已导入 ${res.applied} 条规则`);
    loadRuleOps().catch(console.error);
  } catch (err) { alert(err.message); }
});

loaders.incidents = () => {
  if (hashParams.get('overdue') === '1') { hashParams.delete('overdue'); $('#incOverdue').checked = true; segSet('#incStatus', 's', 'active'); }
  loadBlockPanel().catch(console.error);
  return _incLoader();
};
