'use strict';

const $ = (s) => document.querySelector(s);
const form = $('#loginForm');
const btn = $('#loginBtn');
const msg = $('#loginMsg');
const pw = $('#password');

// 登录成功后回到首页；保留告警消息链接中的 #ip=… 等页面内定位
const home = () => location.replace('/' + (location.hash || ''));

// 已登录（或未开启登录认证）时直接进入大屏
fetch('/api/auth/session', { headers: { Accept: 'application/json' } })
  .then((r) => { if (r.ok) home(); })
  .catch(() => {});

$('#togglePw').addEventListener('click', (e) => {
  const show = pw.type === 'password';
  pw.type = show ? 'text' : 'password';
  e.currentTarget.textContent = show ? '隐藏' : '显示';
  e.currentTarget.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
  pw.focus();
});

pw.addEventListener('keyup', (e) => {
  if (e.getModifierState) $('#capsHint').hidden = !e.getModifierState('CapsLock');
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = $('#username').value.trim();
  const password = pw.value;
  if (!username || !password) {
    msg.textContent = '请输入用户名和密码';
    (username ? pw : $('#username')).focus();
    return;
  }
  btn.disabled = true;
  btn.textContent = '登录中…';
  msg.textContent = '';
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (r.ok) {
      home();
      return;
    }
    let text = '登录失败，请稍后重试';
    try { text = (await r.json()).error || text; } catch (_) { /* 非 JSON 响应 */ }
    msg.textContent = text;
    pw.value = '';
    pw.focus();
  } catch (_) {
    msg.textContent = '无法连接服务器，请检查网络';
  } finally {
    btn.disabled = false;
    btn.textContent = '登 录';
  }
});
