'use strict';

const $ = (s) => document.querySelector(s);

// ---------------- 登录 ----------------
const form = $('#loginForm');
const btn = $('#loginBtn');
const msg = $('#loginMsg');
const pw = $('#password');

// 登录成功后回到首页；保留告警消息链接中的 #ip=… 等页面内定位
const home = () => location.replace('/' + (location.hash || ''));

// 已登录（或未开启登录认证）时直接进入大屏
fetch('/api/auth/session', { headers: { Accept: 'application/json' } })
  .then((r) => (r.ok ? r.json() : null))
  .then((s) => { if (s && s.authenticated) home(); })
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
  btn.firstElementChild.textContent = '登录中…';
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
    btn.firstElementChild.textContent = '登 录';
  }
});

// 顶栏时钟
const pad = (n) => String(n).padStart(2, '0');
function tick() {
  const d = new Date();
  $('#hudClock').textContent = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
tick();
setInterval(tick, 1000);

// ---------------- 动态背景：点阵地球 + 攻击轨迹 ----------------
// 陆地位图：1° 分辨率（360×180 位），由内置世界地图栅格化生成；第 0 行为北纬 89.5°，第 0 列为西经 179.5°。
const LAND = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//8AAf///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv//+B//////7fAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/gH/p////////wAAAAAAAAAAwAgAAAAPgAAAAAAAAAAAAAAAAAAAAAAAAAAA///+Af//////+AAAAB7PwAAAAAAAAAAH8AAAAAAAAAAAAAAAAAAAAAAAAcHzDn/w////////4AAAAB/8AAAAAAAAAAAAD4AAAAAAAAAAAAAAAAAAAAAAEYIAxM/AJ///////8AAAAAPFAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAABoDCc+L+AH///////wAAAAAAAAAAAAABwAAAAD/+AAAAAAAAAAAAAAAAAAAAAD/wPz78AAAP/////8AAAAAAAAAAAAD4AAAA////AAAB9oAAAAAAAAAAAAAACAwAAAMAAAAD/////+AAAAAAAAAAAAOAAAAH///6AAAAAAAAAAAAAAAAAAAAP+AYc+M/gAAD////+YAAAAAAAAAAAA4AAAH///+O+CQAOAAAAAAAAAAAAAAAfv24+Q54wAAB////+wAAAAAAAAAAABgAHlH///////4APgAAAAAwAAAAAAAAOP/8EY//9AABf////wAAAAAAAAAAADwAPZ////////43v/gAAAAAAAP8AAAAAAf/A8f//cAA3///gAAAAAAABvAAAAAAfv+////////////8AAAAAB///+BPXH/+GuBgP8AA3////AAAAAABf/wAAAA8Pv/////////////+/H8wAP////////A4DOzwD8AAf///wAAAAAAF///wIBe/3+/////////////////+AD///////////f34Y/wA///4AAAAAAAD///+I////v//////////////////4EP///////////5gD/8Af//gAAAAAAAf//9+P///8//////////////////jw/////////////qAD+YAf/wAAv8AAAA/8f+D///////////////////////AgAf///////////zwx/gAH/wAAP8AAAB/4/+f//////////////////////4AMA///////////+DAA5gAH/gAADAAAAN/z/////////////////////////+AAH///////////4AwgGQAD/AAAAAAAA/+H///////////////////////n/6AAP///////////wAA/AAAB/AAAAAAAB/+D//////////////////////jP+AAAH/9z////////gAA/wAAAMAAAAAACB//Dx////////////////////+A/YAAAA/wAD///////gAA/wQAAAAAAAAAAB9/Ab///////////////////+MBgAAAAAB0AAf//////4AA/94AAAAAAAAAYA5+C///////////////////4AAHAAAAAADcAAD//////4AAf/8AAAAAAAAB8AC+i7//////////////////wAAfgAAAAAMAAAC///////wAf/8AAAAAAAAAYAOeH///////////////////AAA/gAAAAAAAAAC///////+A///AAAAAAAAAcAPQH//////////////////8AAA/AAAAAEAAAAAP///////z///wAAAAAAADOAETv//////////////////+AAA+AAAAAAAAAABL///////x///8AAAAAAAPHAX/////////////////////4AA8AAAAAAAAAAAj///////x///8AAAAAAAPPx//////////////////////6AA4AAAAAAAAAAAB///////5///6AAAAAAAAPj//////////////////////6AAQAAAAAAAAAAABf//////////EAAAAAAAAYP//////////////////////7AAAAAAAAAAAAAABv////////+MNAAAAAAAAC///////////////////////zAAAAAAAAAAAAAAAP////////7wPgAAAAAAAf///////////////////////yAAAAAAAAAAAAAAAL/////////gAgAAAAAAAH///////////////////////iAAAAAAAAAAAAAAAP/////////pAAAAAAAAAD/////vP/h//////////////BAAAAAAAAAAAAAAAP/////////+AAAAAAAAAB//P//GP/B/////////////+AAAAAAAAAAAAAAAAP////////8wAAAAAAAAAB//H/+AP+P/////////////8CAAAAAAAAAAAAAAAP////////wAAAAAAAAADj/jx/+AD/H/////////////4HgAAAAAAAAAAAAAAP////////gAAAAAAAAAH/4Fwf8AA/B////////////+ADAAAAAAAAAAAAAAAP////////gAAAAAAAAAH/wAcP8PB/g////////////8AAAAAAAAAAAAAAAAAP///////8AAAAAAAAAAH/AMHfB///x///////////v4AMAAAAAAAAAAAAAAAP///////8AAAAAAAAAAH/IMCOH///h//////////+ZgAMAAAAAAAAAAAAAAAH///////4AAAAAAAQAAH/AACGP///g//////////8BwAIAAAAAAAAAAAAAAAD///////wAAAAAAAAAAH+AAYCH///w//////////+wYAYAAAAAAAAAAAAAAAD///////wAAAAAAAAAAAgP+AABs//////////////gYD4AAAAAAAAAAAAAAAB///////4AAAAAAAAAAAh/+AAAA//////////////AYfwAAAAAAAAAAAAAAAB///////gAAAAAAAAAAB//8AAAA//////////////Ah2AAAAAAAAAAAAAAAAAP/////+AAAAAAAAAAAD//+AAAB//////////////gDwAAAAAAAAAAAAAAAAAH/////4AAAAAAAAAAAH///4GAB//////////////gBAAAAAAAAAAAAAAAAAAG/////4AAAAAAAAAAAP///8P4D//////////////gCAAAAAAAAAAAAAAAAAACf////4AAAAAAAAAAAP////v////////////////gAAAAAAAAAAAAAAAAAAABv//xAYAAAAAAAAAAAP//////3//H///////////wAAAAAAAAAAAAAAAAAAAAv//AAYAAAAAAAAAAAf/////////H///////////wAAAAAAAAAAAAAAAAAAAB3/+AAcAAAAAAAAAAB///////8//h///////////gAAAAAAAAAAAAAAAAAAAAR/+AAMAAAAAAAAAAD///////8//wH//////////AAAAAAAAAAAAAAAAAAAAAJ/+AAEAAAAAAAAAAH///////+f/wB//////////AAAAAAAAAAAAAAAAAAAAAI/8AAAAAAAAAAAAAH///////+f/4YAf///////8QAAAAAAAAAAAAAAAAAAAACf8AAAAAAAAAAAAAP////////H//+AP///////4gAAAAAAAAAAAAAAAAAAAAAP8AAuAAAAAAAAAAP////////H///AD///////AgAAAAAAAAAAAAAAAAAAAAAH8AQBgAAAAAAAAAf////////n//+ADf/4P//IAAAAAAAAAAAAAAAAAAAAAAAH+A4AYAAAAAAAAAP////////j//+AAf/4H/+AAAAAAAAAAAAAAAAgAAAAAAAH/BwABwAAAAAAAAP////////h//8AAf/gD/8YAAAAAAAAAAAAAAAAAAAAAAAD/lwAD8AAAAAAAAP////////x//4AAf/AD/8QAAAAAAAAAAAAAAAAAAAAAAAAf/wAAAAAAAAAAAP////////4//gAAf+AB/+AAwAAAAAAAAAAAAAAAAAAAAAAH/wAAAAAAAAAAAP////////4f+AAAf8ADP/AAwAAAAAAAAAAAAAAAAAAAAAAAH/AAAAAAAAAAAf////////8f8AAAPwAAP/gAwAAAAAAAAAAAAAAAAAAAAAAAD/gAAAAAAAAAAf////////+fgAAAPwAAP/gAwAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAP/////////eAAAAHwAAN/gAsAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAf/////////gBAAAHwAAE/gACAAAAAAAAAAAAAAAAAAAAAAAADABAAAAAAAAAH/////////gIAAADwAAEfgALAAAAAAAAAAAAAAAAAAAAAAAADgPfIAAAAAAAH/////////34AAADwAAIOABAAAAAAAAAAAAAAAAAAAAAAAAAAyPf+AAAAAAAD//////////4AAADoAAIEACBAAAAAAAAAAAAAAAAAAAAAAAAA8///AAAAAAAB//////////wAAABIAAMAAAHAAAAAAAAAAAAAAAAAAAAAAAAAE///gAAAAAAA//////////wAAAAMAAEAAADgAAAAAAAAAAAAAAAAAAAAAAAAAf//wAAAAAAAf/7///////gAAAAMAADAAMDAAAAAAAAAAAAAAAAAAAAAAAAAA////gAAAAAAP/B///////gAAAAAABDgAOAAAAAAAAAAAAAAAAAAAAAAAAAAAf///wAAAAAACAAn//////AAAAAAAAxgA+AAAAAAAAAAAAAAAAAAAAAAAAAAAf///4AAAAAAAAAD/////+AAAAAAAAZgB4AAAAAAAAAAAAAAAAAAAAAAAAAAA////4AAAAAAAAAD/////8AAAAAAAAMwH8AIAAAAAAAAAAAAAAAAAAAAAAAAB////8AAAAAAAAAD/////4AAAAAAAAHQf8AIAAAAAAAAAAAAAAAAAAAAAAAAD////4AAAAAAAAAH/////gAAAAAAAAHgf88IAAAAAAAAAAAAAAAAAAAAAAAAD////3AAAAAAAAAH/////AAAAAAAAADof8AQgAAAAAAAAAAAAAAAAAAAAAAAH////u4AAAAAAAAH/////AAAAAAAAABwP5wQwAAAAAAAAAAAAAAAAAAAAAAAH////94AAAAAAAAD////+AAAAAAAAAB+P5wAD4AAAAAAAAAAAAAAAAAAAAAAH//////4AAAAAAAB////8AAAAAAAAAA8ARQiP/AAAAAAAAAAAAAAAAAAAAAAH//////8AAAAAAAA////4AAAAAAAAAAcAAAAD/gAAAAAAAAAAAAAAAAAAAAAH///////gAAAAAAA////4AAAAAAAAAAMABAAA/ywAAAAAAAAAAAAAAAAAAAAD///////gAAAAAAAf///4AAAAAAAAAADAAAAIf8BAAAAAAAAAAAAAAAAAAAAD///////gAAAAAAAf///4AAAAAAAAAAB+AABA/4AAAAAAAAAAAAAAAAAAAAAB///////gAAAAAAAf///4AAAAAAAAAAAAfkgAOMAAAAAAAAAAAAAAAAAAAAAA///////AAAAAAAAf///8AAAAAAAAAAAABCAAAGgAAAAAAAAAAAAAAAAAAAAA///////AAAAAAAAP///8AAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAf/////+AAAAAAAAP///8AAAAAAAAAAAAAACgCAEAAAAAAAAAAAAAAAAAAAAAf/////8AAAAAAAAf///8AQAAAAAAAAAAAAB+CAAAAAAAQAAAAAAAAAAAAAAAP/////4AAAAAAAAf///+AQAAAAAAAAAAAAD8DAAAAAAAAAAAAAAAAAAAAAAAP/////4AAAAAAAA////+AwAAAAAAAAAAAAz8DgAAAAAAAAAAAAAAAAAAAAAAH/////4AAAAAAAA////8DwAAAAAAAAAAAD/8DgAAAAAAAAAAAAAAAAAAAAAAB/////4AAAAAAAA////8PwAAAAAAAAAAAH//XgAABABAAAAAAAAAAAAAAAAAAf////4AAAAAAAA////wPgAAAAAAAAAAAP//3wAAAAAAAAAAAAAAAAAAAAAAAP////wAAAAAAAA////gPgAAAAAAAAAAAP///wAAAAAAAAAAAAAAAAAAAAAAAP////wAAAAAAAAf//+APgAAAAAAAAAAAf///8AAAAAAAAAAAAAAAAAAAAAAAP////wAAAAAAAAf//+APgAAAAAAAAAAD////+AAIAAAAAAAAAAAAAAAAAAAAP////gAAAAAAAAP//+AfAAAAAAAAAAAf////+AAEAAAAAAAAAAAAAAAAAAAAP////AAAAAAAAAP///AfAAAAAAAAAAA//////AAAAAAAAAAAAAAAAAAAAAAAP///4AAAAAAAAAP//+APAAAAAAAAAAA//////gAAAAAAAAAAAAAAAAAAAAAAf///gAAAAAAAAAH//+AOAAAAAAAAAAB//////wAAAAAAAAAAAAAAAAAAAAAAf//+AAAAAAAAAAH//4AEAAAAAAAAAAA//////4AAAAAAAAAAAAAAAAAAAAAAf//+AAAAAAAAAAH//4AAAAAAAAAAAAB//////4AAAAAAAAAAAAAAAAAAAAAAf//+AAAAAAAAAAH//4AAAAAAAAAAAAA//////8AAAAAAAAAAAAAAAAAAAAAAf//+AAAAAAAAAAD//wAAAAAAAAAAAAA//////8AAAAAAAAAAAAAAAAAAAAAAf//8AAAAAAAAAAB//gAAAAAAAAAAAAAf/////4AAAAAAAAAAAAAAAAAAAAAA///8AAAAAAAAAAB//gAAAAAAAAAAAAAf/////4AAAAAAAAAAAAAAAAAAAAAA///wAAAAAAAAAAA//AAAAAAAAAAAAAAP/////4AAAAAAAAAAAAAAAAAAAAAAf//wAAAAAAAAAAA/+AAAAAAAAAAAAAAP/AP//wAAAAAAAAAAAAAAAAAAAAAA//vgAAAAAAAAAAA/4AAAAAAAAAAAAAAf8AG//gAAAAAAAAAAAAAAAAAAAAAA//3AAAAAAAAAAAAQAAAAAAAAAAAAAAAOAAF//gAAAAAAAAAAAAAAAAAAAAAB//4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//AAABAAAAAAAAAAAAAAAAAAB//4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/AAAAgAAAAAAAAAAAAAAAAAD//4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/AAAAQAAAAAAAAAAAAAAAAAD//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABYAAAAcAAAAAAAAAAAAAAAAAB/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAAAAAAAAAAAAAAD/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAD/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAADAAAAAAAAAAAAAAAAAAB/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAHAAAAAAAAAAAAAAAAAAB/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAOAAAAAAAAAAAAAAAAAAF/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4AAAAAAAAAAAAAAAAAAH+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4AAAAAAAAAAAAAAAAAAH+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD8AAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

(function globe() {
  const canvas = $('#bg');
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const bits = Uint8Array.from(atob(LAND), (c) => c.charCodeAt(0));
  const isLand = (lat, lon) => {
    const row = Math.min(179, Math.max(0, Math.floor(90 - lat)));
    const col = ((Math.floor(lon + 180) % 360) + 360) % 360;
    const i = row * 360 + col;
    return (bits[i >> 3] >> (7 - (i & 7))) & 1;
  };
  const RAD = Math.PI / 180;
  const vec = (lat, lon) => [Math.cos(lat * RAD) * Math.cos(lon * RAD), Math.sin(lat * RAD), Math.cos(lat * RAD) * Math.sin(lon * RAD)];

  // 受保护资产（攻击轨迹的终点）：上海为主，另有两处分支
  const TARGETS = [vec(31.23, 121.47), vec(31.23, 121.47), vec(31.23, 121.47), vec(39.9, 116.4), vec(22.54, 114.06)];
  const COLORS = ['#ff4d4f', '#ff7a45', '#ffc53d', '#ff4d4f', '#ff7a45'];

  let W = 0, H = 0, dpr = 1, cx = 0, cy = 0, R = 0, dim = 1;
  let pts = null; // [x, y, z, 是否陆地] 交错存储
  let landPts = [];
  let stars = [];

  function layout() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const wide = W > 920;
    cx = wide ? W * 0.6 : W / 2;
    cy = wide ? H * 0.54 : H / 2;
    R = wide ? Math.min(H * 0.4, W * 0.27) : Math.min(W, H) * 0.42;
    dim = wide ? 1 : 0.55;
    // 斐波那契球面均匀取点：陆地全部保留，海洋稀疏保留以勾勒球体轮廓
    const n = Math.round(Math.min(14000, Math.max(5000, R * R * 0.07)));
    const out = [];
    landPts = [];
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < n; i++) {
      const y = 1 - (2 * (i + 0.5)) / n;
      const r = Math.sqrt(1 - y * y);
      const phi = i * golden;
      const x = Math.cos(phi) * r;
      const z = Math.sin(phi) * r;
      const lat = Math.asin(y) / RAD;
      const lon = Math.atan2(z, x) / RAD;
      const land = isLand(lat, lon);
      if (land) {
        out.push(x, y, z, 1);
        if (Math.abs(lat) < 72) landPts.push([x, y, z]);
      } else if (i % 7 === 0) {
        out.push(x, y, z, 0);
      }
    }
    pts = new Float32Array(out);
    stars = Array.from({ length: Math.round((W * H) / 9000) }, () => [Math.random() * W, Math.random() * H, Math.random() * 1.2 + 0.2, Math.random()]);
  }

  // 自转（绕 Y 轴）与倾斜（北半球朝向观察者）
  const TILT = 0.38;
  const cosT = Math.cos(TILT), sinT = Math.sin(TILT);
  let theta = (110 - 90 - 30) * RAD; // 开场时中国即将转到正面
  function project(x, y, z, out) {
    const c = Math.cos(theta), s = Math.sin(theta);
    const x1 = x * c + z * s;
    const z1 = -x * s + z * c;
    const y2 = y * cosT - z1 * sinT;
    const z2 = y * sinT + z1 * cosT;
    out[0] = cx - x1 * R; // 取反使东经在右侧（从球外观察）
    out[1] = cy - y2 * R;
    out[2] = z2; // >0 为朝向观察者的半球
    return out;
  }

  // 攻击轨迹：球面插值 + 抬升高度，头部发光，到达后在目标处产生冲击波纹
  const arcs = [];
  const ripples = [];
  let nextSpawn = 0;
  function slerp(a, b, t) {
    const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    const om = Math.acos(dot);
    if (om < 1e-4) return a.slice();
    const so = Math.sin(om);
    const k1 = Math.sin((1 - t) * om) / so, k2 = Math.sin(t * om) / so;
    return [a[0] * k1 + b[0] * k2, a[1] * k1 + b[1] * k2, a[2] * k1 + b[2] * k2];
  }
  function spawn(now) {
    if (!landPts.length) return;
    const ti = Math.floor(Math.random() * TARGETS.length);
    const to = TARGETS[ti];
    let from;
    for (let k = 0; k < 16; k++) { // 起点不离目标过近，并优先取当前可见的半球
      from = landPts[Math.floor(Math.random() * landPts.length)];
      if (from[0] * to[0] + from[1] * to[1] + from[2] * to[2] >= 0.93) continue;
      if (k < 12 && project(from[0], from[1], from[2], Q)[2] < -0.15) continue;
      break;
    }
    const dist = Math.acos(Math.max(-1, Math.min(1, from[0] * to[0] + from[1] * to[1] + from[2] * to[2])));
    arcs.push({ from, to, t0: now, dur: 1800 + dist * 1400, h: 0.08 + dist * 0.16, color: COLORS[Math.floor(Math.random() * COLORS.length)], done: false });
  }

  const P = [0, 0, 0];
  const Q = [0, 0, 0];
  const visible = (p) => p[2] > 0 || (p[0] - cx) ** 2 + (p[1] - cy) ** 2 > R * R; // 正面或在球体轮廓之外（高空段）

  function drawArc(a, now) {
    const s = Math.min(1, (now - a.t0) / a.dur);
    const tail = Math.max(0, s - 0.5);
    const steps = 28;
    ctx.lineCap = 'round';
    let prev = null;
    for (let i = 0; i <= steps; i++) {
      const t = tail + ((s - tail) * i) / steps;
      const v = slerp(a.from, a.to, t);
      const alt = 1 + a.h * Math.sin(Math.PI * t);
      project(v[0] * alt, v[1] * alt, v[2] * alt, Q);
      const cur = [Q[0], Q[1], visible(Q)];
      if (prev && prev[2] && cur[2]) {
        const k = i / steps;
        ctx.strokeStyle = a.color;
        ctx.globalAlpha = 0.1 + 0.9 * k * k;
        ctx.lineWidth = 0.8 + 2.4 * k;
        ctx.beginPath();
        ctx.moveTo(prev[0], prev[1]);
        ctx.lineTo(cur[0], cur[1]);
        ctx.stroke();
      }
      prev = cur;
    }
    if (prev && prev[2] && s < 1) { // 发光的轨迹头
      const g = ctx.createRadialGradient(prev[0], prev[1], 0, prev[0], prev[1], 13);
      g.addColorStop(0, '#fff');
      g.addColorStop(0.25, a.color);
      g.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.globalAlpha = 1;
      ctx.fillStyle = g;
      ctx.fillRect(prev[0] - 13, prev[1] - 13, 26, 26);
    }
    if (s >= 1 && !a.done) {
      a.done = true;
      ripples.push({ v: a.to, t0: now, color: a.color });
    }
    return s >= 1 && now - a.t0 > a.dur + 600;
  }

  function frame(now) {
    ctx.globalAlpha = 1;
    ctx.clearRect(0, 0, W, H);
    // 星点
    for (const st of stars) {
      ctx.globalAlpha = 0.15 + 0.35 * Math.abs(Math.sin(now / 2400 + st[3] * 9));
      ctx.fillStyle = '#9fc6ff';
      ctx.fillRect(st[0], st[1], st[2], st[2]);
    }
    // 大气光晕与球体底色
    let g = ctx.createRadialGradient(cx, cy, R * 0.92, cx, cy, R * 1.32);
    g.addColorStop(0, 'rgba(58,139,255,0.30)');
    g.addColorStop(0.35, 'rgba(54,207,201,0.10)');
    g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.globalAlpha = dim;
    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.arc(cx, cy, R * 1.32, 0, Math.PI * 2);
    ctx.fill();
    g = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.1, cx, cy, R);
    g.addColorStop(0, 'rgba(22,58,120,0.55)');
    g.addColorStop(1, 'rgba(3,10,26,0.92)');
    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.fill();

    // 雷达扫描
    const sweep = (now / 2600) % (Math.PI * 2);
    if (ctx.createConicGradient) {
      // 扫描扇区按逆时针方向渐隐，前沿为一条亮线
      const cg = ctx.createConicGradient(sweep - 0.7, cx, cy);
      cg.addColorStop(0, 'rgba(95,227,255,0)');
      cg.addColorStop(0.11, 'rgba(95,227,255,0.13)');
      cg.addColorStop(0.1115, 'rgba(95,227,255,0)');
      cg.addColorStop(1, 'rgba(95,227,255,0)');
      ctx.globalAlpha = dim;
      ctx.fillStyle = cg;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.45, 0, Math.PI * 2);
      ctx.fill();
      const ex = cx + Math.cos(sweep) * R * 1.45, ey = cy + Math.sin(sweep) * R * 1.45;
      const lg = ctx.createLinearGradient(cx, cy, ex, ey);
      lg.addColorStop(0, 'rgba(95,227,255,0)');
      lg.addColorStop(0.6, 'rgba(95,227,255,0.35)');
      lg.addColorStop(1, 'rgba(95,227,255,0.05)');
      ctx.strokeStyle = lg;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(ex, ey);
      ctx.stroke();
    }
    // 外圈刻度环与轨道
    ctx.globalAlpha = 0.5 * dim;
    ctx.strokeStyle = 'rgba(95,227,255,0.35)';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 6]);
    ctx.beginPath();
    ctx.arc(cx, cy, R * 1.45, 0, Math.PI * 2);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.strokeStyle = 'rgba(58,139,255,0.35)';
    for (const [rx, ry, rot, speed] of [[1.28, 0.36, -0.42, 5200], [1.16, 0.26, 0.55, 7400]]) {
      ctx.beginPath();
      ctx.ellipse(cx, cy, R * rx, R * ry, rot, 0, Math.PI * 2);
      ctx.stroke();
      const a = (now / speed) % (Math.PI * 2);
      const ex = R * rx * Math.cos(a), ey = R * ry * Math.sin(a);
      const sx = cx + ex * Math.cos(rot) - ey * Math.sin(rot);
      const sy = cy + ex * Math.sin(rot) + ey * Math.cos(rot);
      ctx.fillStyle = '#5fe3ff';
      ctx.globalAlpha = 0.9 * dim;
      ctx.beginPath();
      ctx.arc(sx, sy, 2.2, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 0.5 * dim;
    }

    // 点阵：背面淡显、正面按深度增亮
    for (let i = 0; i < pts.length; i += 4) {
      project(pts[i], pts[i + 1], pts[i + 2], P);
      const d = P[2];
      const land = pts[i + 3] === 1;
      if (land) {
        if (d > 0) {
          ctx.globalAlpha = (0.3 + 0.7 * d) * dim;
          ctx.fillStyle = d > 0.55 ? '#7ff0ff' : '#3fb8ff';
          const sz = 1 + 1.3 * d;
          ctx.fillRect(P[0] - sz / 2, P[1] - sz / 2, sz, sz);
        } else if (d > -0.6) {
          ctx.globalAlpha = 0.07 * dim;
          ctx.fillStyle = '#3a8bff';
          ctx.fillRect(P[0], P[1], 1, 1);
        }
      } else if (d > 0) {
        ctx.globalAlpha = 0.16 * d * dim;
        ctx.fillStyle = '#3a8bff';
        ctx.fillRect(P[0], P[1], 1, 1);
      }
    }

    // 受保护资产的脉冲标记
    project(TARGETS[0][0], TARGETS[0][1], TARGETS[0][2], P);
    if (P[2] > 0) {
      const pulse = (now % 1800) / 1800;
      ctx.strokeStyle = '#36cfc9';
      for (const k of [pulse, (pulse + 0.5) % 1]) {
        ctx.globalAlpha = (1 - k) * 0.9 * dim;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(P[0], P[1], 4 + 22 * k, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.globalAlpha = dim;
      ctx.fillStyle = '#b5fff9';
      ctx.beginPath();
      ctx.arc(P[0], P[1], 3, 0, Math.PI * 2);
      ctx.fill();
    }

    // 攻击轨迹与冲击波纹
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    for (let i = arcs.length - 1; i >= 0; i--) {
      if (drawArc(arcs[i], now)) arcs.splice(i, 1);
    }
    for (let i = ripples.length - 1; i >= 0; i--) {
      const rp = ripples[i];
      const k = (now - rp.t0) / 1200;
      if (k >= 1) { ripples.splice(i, 1); continue; }
      project(rp.v[0], rp.v[1], rp.v[2], P);
      if (P[2] <= 0) continue;
      ctx.globalAlpha = (1 - k) * dim;
      ctx.strokeStyle = rp.color;
      ctx.lineWidth = 2 * (1 - k) + 0.5;
      ctx.beginPath();
      ctx.arc(P[0], P[1], 3 + 26 * k, 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.restore();
    ctx.globalAlpha = 1;
  }

  let last = 0;
  function loop(now) {
    const dt = last ? Math.min(now - last, 100) : 16;
    last = now;
    theta += dt * 0.00006; // 约 105 秒自转一周
    if (now > nextSpawn && arcs.length < 32) {
      spawn(now);
      nextSpawn = now + 140 + Math.random() * 340;
    }
    frame(now);
    requestAnimationFrame(loop);
  }

  layout();
  window.addEventListener('resize', () => { layout(); if (reduce) still(); });
  // 减少动态效果：只绘制一帧静态画面，攻击轨迹定格在飞行途中
  function still() {
    const now = performance.now();
    arcs.length = 0;
    for (let k = 0; k < 16; k++) {
      spawn(now);
      const a = arcs[arcs.length - 1];
      if (a) a.t0 = now - a.dur * (0.5 + Math.random() * 0.45);
    }
    frame(now);
  }
  if (reduce) {
    still();
  } else {
    requestAnimationFrame(loop);
  }
})();
