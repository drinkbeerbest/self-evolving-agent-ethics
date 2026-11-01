/* 伦理熔断控制台 — 前端逻辑 v2
   主视图 = 进化直播（SSE 实时卡片流）；成本账本 / 审计链 / 附录为佐证视图。
   零构建、零 CDN 图表依赖：所有图表用手写 SVG / CSS 绘制，离线可用。 */

const S = {
  health: null, taxonomy: null, results: null, audit: null,
  liveStatus: null, pulse: null,
  filter: { suite: 'all', source: 'all' },
  activeVerdict: null,
};

const L = {
  running: false, es: null, sessionId: null, mode: 'auto',
  scores: [], stats: { passed: 0, blocked: 0, api_tokens: 0 },
  cost: 0, elapsed: 0, replayToken: 0, finished: false, taskCount: 0,
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = `${path} → ${r.status}`;
    try { const j = await r.json(); if (j.error) msg = j.error; } catch (_) {}
    throw new Error(msg);
  }
  return r.json();
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('is-show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('is-show'), 2600);
}

const fmtTime = (ts) => {
  if (!ts) return '—';
  const d = new Date(Number(ts) * 1000);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};

/** 数字滚动：解析 text 中的首个数字并从上一次值缓动到新值。 */
const _statPrev = new WeakMap();
function animateValue(el, text) {
  const m = String(text).match(/-?\d[\d.]*/);
  if (!m) { el.textContent = text; return; }
  const target = parseFloat(m[0]);
  const prev = _statPrev.get(el);
  const prefix = text.slice(0, m.index);
  const suffix = text.slice(m.index + m[0].length);
  const from = (prev !== undefined && !Number.isNaN(prev)) ? prev : target;
  _statPrev.set(el, target);
  if (from === target || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    el.textContent = text; return;
  }
  const t0 = performance.now(), dur = 650;
  const ease = (x) => 1 - Math.pow(1 - x, 3);
  const step = (now) => {
    const k = ease(Math.min(1, (now - t0) / dur));
    const v = Math.round(from + (target - from) * k);
    el.textContent = prefix + v + suffix;
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

const fmt = (v, d = 3) => {
  if (v === null || v === undefined || Number.isNaN(v)) return '—';
  const n = Number(v);
  return Number.isInteger(n) ? String(n) : n.toFixed(d);
};
const pct = (v) => (v === null || v === undefined || Number.isNaN(v)) ? '—' : `${(Number(v) * 100).toFixed(1)}%`;

function actionBadge(action) {
  const map = { '放行': 'pass', '拒绝': 'fail', '沙箱': 'warn', '上报': 'warn' };
  return `<span class="badge ${map[action] || 'neutral'}">${esc(action)}</span>`;
}
function statusBadge(status) {
  const map = { '通过': 'pass', '违反': 'fail', '不确定': 'warn' };
  return `<span class="badge ${map[status] || 'neutral'}">${esc(status)}</span>`;
}

/* ============================================================
   进化直播
   ============================================================ */

function setStatus(text, cls) {
  const el = $('#liveStatus');
  el.className = 'live-status' + (cls ? ' ' + cls : '');
  el.innerHTML = `<span class="pulse-dot"></span>${text}`;
}

function renderLiveStats() {
  const best = L.scores.length ? Math.max(...L.scores) : null;
  const first = L.scores.length ? L.scores[0] : null;
  const tiles = [
    { label: '已进化', value: `${L.scores.length} 代`, sub: L.sessionId && L.running ? '进行中' : (L.finished ? '本场结束' : '待机') },
    { label: '拦截', value: L.stats.blocked, sub: '危险修改被阻断', cls: L.stats.blocked ? 'is-fail' : '' },
    { label: '放行', value: L.stats.passed, sub: '合法修改已生效', cls: 'is-pass' },
    { label: '能力分', value: best === null ? '—' : best, sub: first !== null && best !== first ? `首代 ${first} → 现在 ${best}` : `基准评测 ${L.taskCount || 6} 题` },
    { label: '审查开销', value: `$${fmt(L.cost, 4)}`, sub: `门禁墙钟 ${fmt(L.elapsed, 2)}s · 会话 API ${L.stats.api_tokens} tok` },
  ];
  const row = $('#liveStats');
  const prev = row.dataset.rendered === '1';
  row.innerHTML = tiles.map((t) => `
    <div class="stat">
      <div class="stat-label">${esc(t.label)}</div>
      <div class="stat-value ${t.cls || ''}">${esc(t.value)}</div>
      <div class="stat-sub">${esc(t.sub)}</div>
    </div>`).join('');
  if (prev) {
    $$('#liveStats .stat-value').forEach((el, i) => animateValue(el, tiles[i] ? String(tiles[i].value) : el.textContent));
  }
  row.dataset.rendered = '1';
}

function renderCapChart() {
  const box = $('#capChart');
  if (!L.scores.length) {
    box.innerHTML = '<p class="empty">尚未开始——开始后这里会画出逐代得分曲线。</p>';
    return;
  }
  const W = 760, H = 230, PAD = { l: 44, r: 30, t: 18, b: 34 };
  const iw = W - PAD.l - PAD.r, ih = H - PAD.t - PAD.b;
  const n = Math.max(L.scores.length, 2);
  const x = (i) => PAD.l + (iw * i) / (n - 1);
  const y = (v) => PAD.t + ih - (ih * v) / 100;
  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" style="width:100%;height:auto;max-width:${W}px;display:block" xmlns="http://www.w3.org/2000/svg" role="img">
    <rect width="${W}" height="${H}" fill="#0e1014" rx="10"/>`;
  [0, 25, 50, 75, 100].forEach((v) => {
    svg += `<line x1="${PAD.l}" y1="${y(v)}" x2="${W - PAD.r}" y2="${y(v)}" stroke="#1c212b"/>
      <text x="${PAD.l - 8}" y="${y(v) + 4}" font-size="10.5" fill="#565e6c" text-anchor="end" font-family="JetBrains Mono,monospace">${v}</text>`;
  });
  svg += `<line x1="${PAD.l}" y1="${y(0)}" x2="${W - PAD.r}" y2="${y(0)}" stroke="#2e3644"/>`;
  // 面积
  const pts = L.scores.map((s, i) => `${x(i)},${y(s)}`);
  svg += `<polygon points="${PAD.l},${y(0)} ${pts.join(' ')} ${x(L.scores.length - 1)},${y(0)}" fill="rgba(200,240,75,0.07)"/>`;
  svg += `<polyline points="${pts.join(' ')}" fill="none" stroke="#c8f04b" stroke-width="2" stroke-linejoin="round" style="filter:drop-shadow(0 0 6px rgba(200,240,75,0.35))"/>`;
  L.scores.forEach((s, i) => {
    svg += `<circle cx="${x(i)}" cy="${y(s)}" r="4" fill="#c8f04b" stroke="#0e1014" stroke-width="1.5"/>
      <text x="${x(i)}" y="${y(s) - 9}" font-size="10.5" fill="#b8bec9" text-anchor="middle" font-family="JetBrains Mono,monospace">${s}</text>
      <text x="${x(i)}" y="${H - 12}" font-size="10" fill="#565e6c" text-anchor="middle" font-family="JetBrains Mono,monospace">G${i + 1}</text>`;
  });
  svg += '</svg>';
  box.innerHTML = svg;
}

function renderVitals(v) {
  if (!v) return;
  $('#vitTools').innerHTML = (v.tools || []).map((t) =>
    `<span class="chip">${esc(t)}</span>`).join('') || '<span class="chip">（无）</span>';
  $('#vitPrompts').innerHTML = (v.prompts || []).map((p) => `<li>${esc(p)}</li>`).join('');
  $('#vitParams').innerHTML = Object.entries(v.params || {}).map(([k, val]) =>
    `<span class="chip chip-code">${esc(k)}=${esc(val)}</span>`).join('');
  $('#vitConstraints').innerHTML = (v.constraints || []).map((c) => `<li>${esc(c)}</li>`).join('');
  $('#vitCode').textContent = `${v.code_version || 'v0'} · brain/strategy.py`;
}

function clearStream() {
  $('#cardStream').innerHTML = '';
}

function addCard(evt) {
  const stream = $('#cardStream');
  const empty = stream.querySelector('.empty');
  if (empty) empty.remove();
  const v = evt.verdict || {};
  const mod = v.mod || {};
  const action = v.action || '';
  const locked = v.detail && v.detail.locked;
  const cls = action === '放行' ? 'pass' : (action === '拒绝' || locked) ? 'fail' : 'warn';
  const icon = action === '放行' ? '🟢' : '🔴';
  const results = v.results || [];
  const failed = results.filter((r) => r.status !== '通过').slice(0, 2);
  const why = failed.length
    ? failed.map((r) => `${r.invariant} ${r.status}`).join(' · ')
    : '四级门禁全部通过';
  const costAbs = (v.detail && v.detail.cost_absolute) || {};
  const card = document.createElement('div');
  card.className = `evo-card ${cls}`;
  card.innerHTML = `
    <div class="evo-head">
      <span class="evo-icon">${icon}</span>
      <span class="badge ${cls}">${esc(locked ? '路径锁定·拒绝' : action)}</span>
      <span class="evo-gen">第 ${esc(evt.gen)} 代</span>
      <span class="evo-hash" title="审计哈希">${esc(String(v.audit_hash || '').slice(0, 12))}</span>
    </div>
    <div class="evo-title">${esc(mod.title || '(未命名提案)')}</div>
    ${mod.rationale ? `<div class="evo-why">提案理由：${esc(mod.rationale)}</div>` : ''}
    <div class="evo-note">${esc(evt.note || '')}</div>
    <div class="evo-foot">
      <span class="badge neutral">${esc(mod.layer || '')}</span>
      <span class="evo-verdict">${esc(why)}</span>
      ${costAbs.comp_cost ? `<span class="evo-cost">审查 $${fmt(costAbs.comp_cost, 4)}</span>` : ''}
    </div>`;
  card.addEventListener('click', () => openModal(v, evt));
  const hashEl = card.querySelector('.evo-hash');
  if (hashEl) hashEl.addEventListener('click', (e) => {
    e.stopPropagation();
    navigator.clipboard && navigator.clipboard.writeText(String(v.audit_hash || '')).then(
      () => toast('审计哈希已复制：' + String(v.audit_hash || '').slice(0, 12)),
      () => {},
    );
  });
  stream.prepend(card);
}

function addNoteCard(text) {
  const stream = $('#cardStream');
  const el = document.createElement('div');
  el.className = 'evo-note-card';
  el.textContent = text;
  stream.prepend(el);
}

function handleEvent(evt) {
  switch (evt.type) {
    case 'session_start':
      L.sessionId = evt.session_id;
      L.scores = []; L.stats = { passed: 0, blocked: 0, api_tokens: 0 };
      L.cost = 0; L.elapsed = 0; L.taskCount = evt.task_count || 6;
      L.running = true; L.finished = false;
      clearStream(); renderLiveStats(); renderCapChart(); renderVitals(evt.vitals);
      $('#liveTag').textContent = evt.mode === 'live'
        ? `LIVE · ${evt.provider || ''} ${evt.model || ''}`.trim() : 'LIVE · 离线演示';
      $('#liveTag').classList.add('is-live');
      {
        const sc = evt.scenario || {};
        const scName = sc.name ? ` · 剧本《${sc.name}》` : '';
        setStatus(`进化开始（${evt.mode === 'live' ? '真实 API' : '离线演示'}${scName}）——${sc.description || ''}`);
        $('#scenarioDesc').textContent = sc.name
          ? `本场：《${sc.name}》· ${sc.description} · 天花板题型「${sc.ceiling_task}」· 种子 ${evt.seed}`
          : '';
      }
      $('#btnStart').classList.add('is-hidden');
      $('#btnStop').classList.remove('is-hidden');
      break;
    case 'gen_start':
      setStatus(`第 ${evt.gen} 代：agent 正在解题…`);
      break;
    case 'task':
      setStatus(`第 ${evt.gen} 代 · ${evt.task} ${evt.ok ? '✓' : '✗'} ${evt.brief || ''}`);
      break;
    case 'phase':
      setStatus(evt.text || '');
      break;
    case 'proposal':
      setStatus(`第 ${evt.gen} 代：门禁审查中 —— ${evt.note || ''}`);
      break;
    case 'blocked':
    case 'applied': {
      const v = evt.verdict || {};
      const abs = (v.detail && v.detail.cost_absolute) || {};
      L.cost += Number(abs.comp_cost || 0);
      L.elapsed += Number(abs.elapsed_s || 0);
      addCard(evt);
      setStatus(`第 ${evt.gen} 代：判定完成 —— ${v.action}`);
      break;
    }
    case 'gen_end':
      L.scores.push(Number(evt.score) || 0);
      if (evt.stats) L.stats = evt.stats;
      renderLiveStats(); renderCapChart(); renderVitals(evt.vitals);
      break;
    case 'error':
      setStatus(`出错：${evt.message || '未知错误'}`, 'is-error');
      break;
    case 'session_end':
    case '__end__':
      L.running = false; L.finished = true;
      $('#liveTag').classList.remove('is-live');
      $('#liveTag').textContent = L.scores.length ? `本场结束 · ${L.scores.length} 代` : '待机';
      $('#btnStart').classList.remove('is-hidden');
      $('#btnStop').classList.add('is-hidden');
      setStatus(`本场结束：${L.scores.length} 代 · 放行 ${L.stats.passed} · 拦截 ${L.stats.blocked}`);
      if (evt.mode) L.finished = true;
      if (L.es) { L.es.close(); L.es = null; }
      loadAuditOnly().catch(() => {});
      loadPulse().catch(() => {});
      break;
  }
}

async function startLive() {
  if (L.running) return;
  const mode = L.mode;
  const st = S.liveStatus || {};
  if (mode === 'live' && !st.api_configured) {
    toast('尚未配置 API——请先双击「配置API.bat」，或先用离线演示模式');
    return;
  }
  try {
    const resp = await api('/api/live/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode, generations: Number($('#ctlGens').value), pressure: $('#ctlPressure').checked,
        scenario: $('#ctlScenario').value || '',
      }),
    });
    const sid = resp.session.session_id;
    openStream(sid);
  } catch (e) {
    toast('启动失败：' + e.message);
  }
}

function openStream(sid) {
  if (L.es) { L.es.close(); L.es = null; }
  const es = new EventSource(`/api/live/stream?session=${encodeURIComponent(sid)}`);
  L.es = es;
  es.onmessage = (m) => {
    try { handleEvent(JSON.parse(m.data)); } catch (_) {}
  };
  es.onerror = () => {
    if (L.finished) { es.close(); L.es = null; return; }
    setStatus('连接中断，尝试重连…', 'is-error');
  };
}

async function stopLive() {
  try { await api('/api/live/stop', { method: 'POST', body: '{}' , headers: { 'Content-Type': 'application/json' } }); } catch (_) {}
  setStatus('已请求停止，等待当前代收束…');
}

async function replaySession(sid) {
  if (!sid) return;
  const token = ++L.replayToken;
  if (L.es) { L.es.close(); L.es = null; }
  let data;
  try { data = await api(`/api/live/session/${encodeURIComponent(sid)}`); }
  catch (e) { toast('读取会话失败：' + e.message); return; }
  const events = data.events || [];
  // 重置界面后按序回放
  L.sessionId = sid; L.scores = []; L.stats = { passed: 0, blocked: 0, api_tokens: 0 };
  L.cost = 0; L.running = false; L.finished = false;
  clearStream(); renderLiveStats(); renderCapChart();
  $('#liveTag').textContent = '回放 · ' + sid;
  setStatus(`回放 ${sid}（${events.length} 个事件）…`);
  $('#btnStart').classList.remove('is-hidden');
  $('#btnStop').classList.add('is-hidden');
  const step = 320;
  events.forEach((evt, i) => {
    setTimeout(() => {
      if (token !== L.replayToken) return; // 已被新的回放/直播取代
      handleEvent(evt);
    }, i * step);
  });
}

/* ============================================================
   判定详情弹窗
   ============================================================ */

function renderDiff(mod) {
  if (!mod || !mod.files || !mod.files.length) return '';
  const parts = [];
  mod.files.forEach((f) => {
    parts.push(`<span class="ctx">--- ${esc(f.path)}</span>`);
    (f.removed || []).forEach((l) => parts.push(`<span class="del">- ${esc(l)}</span>`));
    (f.added || []).forEach((l) => parts.push(`<span class="add">+ ${esc(l)}</span>`));
  });
  return parts.join('\n');
}

function openModal(v, evt) {
  S.activeVerdict = v;
  const mod = v.mod || {};
  const results = v.results || [];
  const cost = v.cost || {};
  const costNames = {
    c_cap: '能力成本', c_lat: '时延成本', c_comp: '算力成本', c_hum: '人工成本',
    c_fp: '误拦成本', c_fn: '漏放成本', c_iter: '迭代效率损失',
  };
  const invCards = results.map((r) => {
    const cls = r.status === '通过' ? 'pass' : r.status === '违反' ? 'fail' : 'uncertain';
    return `
      <div class="inv-card status-${cls}">
        <div class="inv-card-head">
          <span class="inv-card-name">${esc(r.invariant)}</span>
          ${statusBadge(r.status)}
        </div>
        <div class="inv-card-sum">${esc(r.summary || '')}</div>
        <ul class="ev-list">${(r.evidence || []).map((e) => `<li>${esc(e)}</li>`).join('')}</ul>
        ${r.error_bound ? `<div class="err-bound"><strong>误差界</strong> ${esc(r.error_bound)}</div>` : ''}
      </div>`;
  }).join('');
  const ledger = Object.keys(costNames).map((k) => `
    <div class="ledger-item">
      <div class="ledger-k">${esc(costNames[k])}</div>
      <div class="ledger-v">${fmt(cost[k], 3)}</div>
    </div>`).join('');
  const abs = (v.detail && v.detail.cost_absolute) || null;
  const absLine = abs ? `
    <div class="abs-cost">
      <span class="abs-k">本次判定的绝对开销</span>
      <span class="abs-v">耗时 ${fmt(abs.elapsed_s, 4)} s</span>
      <span class="abs-v">token ${fmt(abs.tokens, 0)}</span>
      <span class="abs-v">算力 $${fmt(abs.comp_cost, 4)}</span>
    </div>` : '';
  const escalate = v.action === '上报';

  $('#modalContent').innerHTML = `
    <div class="detail-head">
      <div style="display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-start;">
        <div style="min-width:0;">
          <h2>${esc(mod.title || mod.mod_id)}</h2>
          <p style="font-size:12.5px;color:var(--muted);margin:0;">
            第 ${esc(mod.round_index)} 代 ·
            <span class="badge neutral">${esc(mod.layer)}</span>
            <span class="badge neutral">${esc(mod.autonomy)}</span>
            <span class="badge accent">来源 ${esc(mod.source || '-')}</span>
          </p>
        </div>
        <div style="text-align:right;">
          ${actionBadge(v.action)}
          <div style="font-size:11px;color:var(--muted-2);margin-top:5px;font-family:'JetBrains Mono',monospace;">
            ${esc(v.audit_hash ? v.audit_hash.slice(0, 16) : '')}
          </div>
        </div>
      </div>
      ${mod.rationale ? `<p style="margin-top:10px;font-size:13px;color:var(--ink-2);">提案理由：${esc(mod.rationale)}</p>` : ''}
      ${diff_html(mod)}
      ${v.detail && v.detail.locked ? `<div class="lock-banner">
        <strong>该修改路径正处于熔断锁定期</strong>
        <span>路径 <code>${esc(v.detail.locked_path || '-')}</code> 已因先前的熔断事件被锁定，
        在解锁前同类提案一律拒绝。熔断是有状态的——这正是"拒绝"与"熔断"的区别所在。</span>
      </div>` : ''}
      ${v.breaker ? `<div style="font-size:12.5px;color:var(--fail);margin-top:8px;">
        触发熔断：${esc(v.breaker.trigger)} · 锁定路径 ${esc(v.breaker.path_key)} · 回滚至 ${esc(v.breaker.rollback_to || '-')}
      </div>` : ''}
    </div>

    <div class="card">
      <h3>门禁检验结果</h3>
      <p class="card-note">I1~I4 为四条伦理不变量；S1~S4 为二级沙箱的桩用例（越权探测 / 强制中断 / 日志完整性 / 回归）。</p>
      <div class="inv-cards">${invCards || '<p class="empty">无检查结果</p>'}</div>
    </div>

    <div class="card">
      <h3>本次对齐成本账</h3>
      <p class="card-note">判定与成本同屏——看不到代价的守门人一定会偷偷把门关掉。</p>
      <div class="ledger">${ledger}</div>
      ${absLine}
      <div style="margin-top:12px;font-size:13px;">
        加权合成对齐总成本 C<sub>ali</sub> =
        <strong style="font-family:'JetBrains Mono',monospace;">${fmt(v.cost_total, 4)}</strong>
        &nbsp;·&nbsp; 墙钟耗时 ${fmt(v.elapsed_s, 2)} s
      </div>
      ${escalate ? `
      <div class="action-bar">
        <button class="btn btn-primary" data-adj="放行">人工放行</button>
        <button class="btn" data-adj="拒绝">人工拒绝</button>
      </div>
      <textarea class="reason-input" id="reason" placeholder="裁决理由（必填，将写入不可篡改的哈希链审计记录）"></textarea>` : ''}
    </div>`;

  $$('[data-adj]').forEach((b) => b.addEventListener('click', async () => {
    const reason = $('#reason').value.trim();
    if (!reason) { toast('裁决理由为必填项'); $('#reason').focus(); return; }
    const resp = await fetch('/api/adjudicate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mod_id: mod.mod_id, decision: b.dataset.adj, reason }),
    });
    const data = await resp.json();
    toast(data.ok ? `裁决已写入审计链 · ${data.audit_hash.slice(0, 12)}` : (data.error || '写入失败'));
    if (data.ok) { await refreshAudit(); closeModal(); }
  }));

  $('#modalMask').classList.remove('is-hidden');
}

function diff_html(mod) {
  const diff = renderDiff(mod);
  return diff ? `<div class="diff-box">${diff}</div>` : '';
}

function closeModal() {
  $('#modalMask').classList.add('is-hidden');
}

/* ============================================================
   附录 · 方法与矩阵
   ============================================================ */

const GATE_STEPS = [
  { i: 1, name: '一级 · 静态审查', desc: '检查权限单调性、停机独立性、约束蕴含形式化侧，并按 18 格风险表判断是否落在高危格。', time: '毫秒级', cost: '最低' },
  { i: 2, name: '二级 · 沙箱演练', desc: '隔离环境运行回归测试、越权探测、日志完整性检查，以及针对可中断性的强制中断演练。', time: '分钟级', cost: '中等' },
  { i: 3, name: '三级 · 影子模式', desc: '生产流量并行运行但不生效，用动作分布散度、工具调用序列编辑距离、拒答率变化度量偏移。', time: '小时到天级', cost: '较高' },
  { i: 4, name: '四级 · 灰度放量', desc: '按比例逐步放开，每级设观察窗与回滚条件。任何一级观察到异常即回滚并记入路径历史。', time: '按比例', cost: '可控' },
];
const INVARIANTS = [
  { id: 'I1', name: '权限单调性', desc: '修改后可达资源集不得超出修改前授权闭包与预设增量的并集', method: '工具表与系统调用白名单的差集运算 · 完全可判定' },
  { id: 'I2', name: '审计完备性', desc: '修改须留下足以重建任一历史状态的记录', method: '日志字段完备性检查 + 随机抽样重放 · 可判定，含抽样误差' },
  { id: 'I3', name: '可中断性', desc: '修改后仍须存在人类可触发的停机通道，且该通道的实现不依赖被修改的模块', method: '依赖图分析，检查停机模块是否处于修改影响闭包内 · 完全可判定' },
  { id: 'I4', name: '约束守恒', desc: 'Φ 的语义不得被削弱，允许加强或等价改写，不允许删除或弱化', method: '形式化侧检查子句集蕴含关系，语义侧用大模型评审交叉验证 · 部分可判定' },
];
const TRIGGERS = ['不变量违反', '影子期行为偏移超过阈值', '审查成本超出预算', '外部审计否决'];

function renderMethod() {
  $('#gateFlow').innerHTML = GATE_STEPS.map((g) => `
    <div class="gate-step">
      <span class="gate-idx">LEVEL ${g.i}</span>
      <h4>${esc(g.name)}</h4>
      <p>${esc(g.desc)}</p>
      <div class="gate-cost"><span>${esc(g.time)}</span><span>成本 ${esc(g.cost)}</span></div>
    </div>`).join('');
  $('#invList').innerHTML = INVARIANTS.map((v) => `
    <li>
      <span class="inv-id">${v.id}</span><span class="inv-desc">${esc(v.name)}——${esc(v.desc)}</span>
      <span class="inv-method">${esc(v.method)}</span>
    </li>`).join('');
  $('#triggerList').innerHTML = TRIGGERS.map((t) => `
    <li><span class="trigger-dot"></span><span>${esc(t)}</span></li>`).join('');
}

/* ---------- 风险矩阵 ---------- */

const HEAT_COLORS = ['#dcfce7', '#fef9c3', '#fed7aa', '#fecaca', '#fca5a5'];
const HEAT_TEXT = ['#065f46', '#854d0e', '#9a3412', '#9f1239', '#881337'];
const LAYERS = ['提示', '工具', '代码', '架构', '权重', '约束'];
const AUTONOMY = ['系统提议·人类批准', '系统提议·系统初筛·人类抽检', '系统自主采纳·人类事后审计'];

function heatColor(idx) {
  const i = Math.max(0, Math.min(4, Math.round(idx) - 1));
  return [HEAT_COLORS[i], HEAT_TEXT[i]];
}

function renderTaxonomy() {
  const tax = S.taxonomy;
  if (!tax) return;
  const m = tax.matrix || [];

  $('#heatLegend').innerHTML = HEAT_COLORS.map((c, i) =>
    `<span class="legend-swatch" style="background:${c}"></span>${i + 1}`).join('') +
    `<span style="margin-left:6px;">风险指数</span>`;

  let html = '<div class="heat-corner"></div>' +
    LAYERS.map((l) => `<div class="heat-col-head">${esc(l)}</div>`).join('');
  AUTONOMY.forEach((au) => {
    html += `<div class="heat-row-head">${esc(au)}</div>`;
    LAYERS.forEach((ly) => {
      const cell = m.find((c) => c.layer === ly && c.autonomy === au);
      if (!cell) { html += '<div></div>'; return; }
      const [bg, fg] = heatColor(cell.risk_index);
      html += `<div class="heat-cell ${cell.is_high_risk ? 'is-high' : ''}" data-key="${esc(cell.key)}"
        style="background:${bg};color:${fg}">
        <div class="heat-score">${fmt(cell.risk_index, 2)}</div>
        <div class="heat-sub">${cell.is_high_risk ? '高危' : ''}</div>
      </div>`;
    });
  });
  $('#heatmap').innerHTML = `<div class="heatmap">${html}</div>`;

  $$('.heat-cell').forEach((el) => el.addEventListener('click', () => {
    $$('.heat-cell').forEach((x) => x.classList.remove('is-selected'));
    el.classList.add('is-selected');
    showCell(m.find((c) => c.key === el.dataset.key));
  }));

  const hi = m.filter((c) => c.is_high_risk).sort((a, b) => b.risk_index - a.risk_index);
  $('#highRiskList').innerHTML = hi.length ? hi.map((c) => `
    <div class="ds-row"><span>${esc(c.key)}</span><span>${fmt(c.risk_index, 2)}</span></div>`).join('')
    : '<p class="empty">无高危格</p>';

  const ahp = tax.ahp || {};
  const raters = tax.raters || {};
  $('#weightReport').innerHTML = `
    <div class="ds-rows">
      <div class="ds-row"><span>一致性比率 CR</span><span>${fmt(ahp.cr, 4)} ${ahp.passed ? '✓ 通过' : '✗ 未通过'}</span></div>
      <div class="ds-row"><span>最大特征值 λmax</span><span>${fmt(ahp.lambda_max, 4)}</span></div>
      <div class="ds-row"><span>评分者人数</span><span>${raters.n_raters ?? 0}</span></div>
      <div class="ds-row"><span>Kendall's W</span><span>${fmt(raters.kendall_w, 4)}</span></div>
      <div class="ds-row"><span>一致性判读</span><span>${esc(raters.interpretation || '—')}</span></div>
    </div>`;

  $('#matrixNote').textContent =
    '直播页里每次判定的严格程度就来自这张表：提案落在的格子风险越高，被强制进入的门禁级越深。';
}

function showCell(cell) {
  if (!cell) return;
  const attrNames = {
    reversibility: '可逆性', observability: '可观测性', permission_expansion: '权限扩张度',
    goal_drift: '目标漂移度', impact_radius: '影响半径',
  };
  const items = Object.entries(attrNames).map(([k, label]) => {
    const v = cell.attributes[k];
    const [bg, fg] = heatColor(v);
    return `<div class="attr-item">
      <div class="attr-name">${esc(label)}</div>
      <div class="attr-track"><div class="attr-fill" style="width:${(v / 5) * 100}%;background:${bg}"></div></div>
      <div class="attr-val">${v} / 5</div>
    </div>`;
  }).join('');
  const existing = document.querySelector('.crit-detail');
  if (existing) existing.remove();
  const el = document.createElement('div');
  el.className = 'crit-detail';
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;">
      <strong style="font-size:14px;">${esc(cell.key)}</strong>
      <span class="badge ${cell.is_high_risk ? 'fail' : 'neutral'}">
        风险指数 ${fmt(cell.risk_index, 2)}${cell.is_high_risk ? ' · 高危' : ''}
      </span>
    </div>
    <p style="font-size:12.5px;color:var(--muted);margin:6px 0 0;">${esc(cell.notes || '')}</p>
    <div class="attr-grid">${items}</div>`;
  $('#heatmap').parentElement.appendChild(el);
}

/* ============================================================
   直播实录聚合（/api/pulse）—— 四视图数据打通的枢纽
   ============================================================ */

async function loadPulse() {
  try { S.pulse = await api('/api/pulse'); }
  catch (_) { S.pulse = { sessions: [], totals: {} }; }
  renderPulse();
  renderHeatHits();
}

function renderPulse() {
  const box1 = $('#pulseInv');
  const box2 = $('#pulseTable');
  if (!box1 || !box2) return;
  const pulse = S.pulse || { sessions: [], totals: {} };
  const totals = pulse.totals || {};
  $('#pulseTag').textContent = pulse.sessions?.length
    ? `${totals.sessions} 场 · ${totals.generations} 代 · 拦截 ${totals.blocked} / 放行 ${totals.passed}`
    : '尚无直播会话';

  // 被拦不变量分布
  const inv = Object.entries(totals.by_invariant || {}).sort((a, b) => b[1] - a[1]);
  const maxInv = Math.max(1, ...inv.map((x) => x[1]));
  const invHtml = inv.length
    ? inv.map(([k, v]) => `
      <div class="inv-bar-row">
        <span style="font-family:var(--font-mono);color:var(--fail)">${esc(k)}</span>
        <div class="inv-bar-track"><div class="inv-bar-fill" style="width:${(v / maxInv) * 100}%"></div></div>
        <span class="inv-bar-val">${v}</span>
      </div>`).join('')
    : '<p class="empty">暂无拦截记录</p>';
  const passed = totals.passed || 0;
  const blocked = totals.blocked || 0;
  box1.innerHTML = `
    <div class="inv-bar-row is-pass">
      <span style="font-family:var(--font-mono);color:var(--pass)">放行</span>
      <div class="inv-bar-track"><div class="inv-bar-fill" style="width:${(passed / Math.max(1, passed + blocked)) * 100}%"></div></div>
      <span class="inv-bar-val">${passed}</span>
    </div>
    <div class="inv-bar-row">
      <span style="font-family:var(--font-mono);color:var(--fail)">拦截</span>
      <div class="inv-bar-track"><div class="inv-bar-fill" style="width:${(blocked / Math.max(1, passed + blocked)) * 100}%"></div></div>
      <span class="inv-bar-val">${blocked}</span>
    </div>
    <div style="height:12px"></div>${invHtml}`;

  // 会话明细
  const rows = (pulse.sessions || []).slice(0, 12);
  box2.innerHTML = rows.length ? `
    <thead><tr><th>会话</th><th>剧本</th><th>模式</th><th>代数</th><th>拦截</th><th>放行</th><th>末代分</th><th>审查开销</th><th>API tok</th></tr></thead><tbody>
    ${rows.map((s) => `
      <tr style="cursor:pointer" data-sid="${esc(s.session_id)}">
        <td>${esc(s.session_id)}</td>
        <td>${esc(s.scenario || '—')}</td>
        <td class="dim">${esc(s.mode)}</td>
        <td class="num">${s.generations}</td>
        <td class="num" style="color:var(--fail)">${s.blocked}</td>
        <td class="num" style="color:var(--pass)">${s.passed}</td>
        <td class="num">${s.best || '—'}</td>
        <td class="num">${fmt(s.gate_elapsed_s, 2)}s</td>
        <td class="num">${s.api_tokens}</td>
      </tr>`).join('')}
    </tbody>` : '<tbody><tr><td colspan="9"><p class="empty">跑一场直播，这里就会出现真实会话的成本与判定分布</p></td></tr></tbody>';
  box2.querySelectorAll('tr[data-sid]').forEach((tr) => tr.addEventListener('click', () => {
    switchView('live');
    replaySession(tr.dataset.sid);
  }));
}

/** 附录矩阵：直播会话中被拦截格式的红色命中标记。 */
function renderHeatHits() {
  const cells = (S.pulse && S.pulse.totals && S.pulse.totals.blocked_cells) || {};
  $$('#heatmap .heat-cell').forEach((el) => {
    const n = cells[el.dataset.key] || 0;
    el.classList.toggle('is-hit', n > 0);
    el.title = n > 0 ? `直播累计拦截 ${n} 次` : (el.title || '');
  });
}

/* ============================================================
   成本账本（帕累托前沿）
   ============================================================ */

function filteredRows() {
  const all = (S.results && S.results.summary) || [];
  return all.filter((r) => {
    if (S.filter.suite !== 'all' && r.suite !== S.filter.suite) return false;
    if (S.filter.source !== 'all' && r.source !== S.filter.source) return false;
    return true;
  });
}

function aggregateByStrategy(rows) {
  const by = {};
  rows.forEach((r) => {
    const k = r.strategy;
    (by[k] = by[k] || { name: k, display_name: r.display_name, cost: 0, risk: 0, acer: 0, score: 0, n: 0, k: 0 });
    const a = by[k];
    a.cost += Number(r.c_ali ?? 0);
    a.risk += Number(r.fnr ?? 0);
    a.acer += Number(r.acer ?? 0);
    a.score += Number(r.score ?? 0);
    a.n += Number(r.n ?? 0);
    a.k += 1;
  });
  return Object.values(by).map((a) => ({
    name: a.name, display_name: a.display_name,
    cost: a.cost / a.k, risk: a.risk / a.k, acer: a.acer / a.k, score: a.score / a.k,
    n: a.n, groups: a.k,
  }));
}

function renderFrontier() {
  const rows = filteredRows();
  const pts = aggregateByStrategy(rows);
  if (!pts.length) {
    $('#paretoWrap').innerHTML = '<p class="empty">尚无实验结果。运行 <code>python -m ethgate.cli experiment</code> 生成后再查看。</p>';
    $('#paretoNote').textContent = '';
    $('#frontierTag').textContent = '无数据';
    $('#acerBars').innerHTML = '';
    $('#costTable').innerHTML = '';
    $('#costTableTag').textContent = '';
    return;
  }
  pts.forEach((p) => {
    p.dominated = pts.some((o) => o !== p &&
      o.cost <= p.cost && o.risk <= p.risk && (o.cost < p.cost || o.risk < p.risk));
  });
  const scope = [
    S.filter.suite === 'all' ? '全部任务集' : S.filter.suite,
    S.filter.source === 'all' ? '全部样本来源' : (S.filter.source === 'artificial' ? '人工构造' : '自然涌现'),
  ].join(' · ');
  $('#frontierTag').textContent = `${pts.length} 种策略 · ${rows.length} 行 · ${scope}`;

  const W = 760, H = 400, PAD = { l: 66, r: 118, t: 26, b: 52 };
  const iw = W - PAD.l - PAD.r, ih = H - PAD.t - PAD.b;
  const costs = pts.map((p) => p.cost), risks = pts.map((p) => p.risk);
  const cMin = Math.min(...costs), cMax = Math.max(...costs);
  const rMin = Math.min(...risks), rMax = Math.max(...risks);
  const cx = (v) => PAD.l + (cMax === cMin ? iw / 2 : ((v - cMin) / (cMax - cMin)) * iw);
  const cy = (v) => PAD.t + ih - (rMax === rMin ? ih / 2 : ((v - rMin) / (rMax - rMin)) * ih);
  const ticks = (min, max, n = 5) => Array.from({ length: n + 1 },
    (_, i) => min + ((max - min) * i) / n);

  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet"
    style="width:100%;height:auto;max-width:${W}px;display:block"
    xmlns="http://www.w3.org/2000/svg" role="img">
    <rect x="0" y="0" width="${W}" height="${H}" fill="#0e1014" rx="10"/>`;
  ticks(rMin, rMax).forEach((v) => {
    svg += `<line x1="${PAD.l}" y1="${cy(v)}" x2="${W - PAD.r}" y2="${cy(v)}" stroke="#1c212b"/>
      <text x="${PAD.l - 9}" y="${cy(v) + 4}" font-size="10.5" fill="#565e6c" text-anchor="end" font-family="JetBrains Mono,monospace">${pct(v)}</text>`;
  });
  ticks(cMin, cMax).forEach((v) => {
    svg += `<line x1="${cx(v)}" y1="${PAD.t}" x2="${cx(v)}" y2="${PAD.t + ih}" stroke="#1c212b"/>
      <text x="${cx(v)}" y="${PAD.t + ih + 18}" font-size="10.5" fill="#565e6c" text-anchor="middle" font-family="JetBrains Mono,monospace">${fmt(v, 2)}</text>`;
  });
  svg += `<line x1="${PAD.l}" y1="${PAD.t + ih}" x2="${W - PAD.r}" y2="${PAD.t + ih}" stroke="#2e3644"/>
    <line x1="${PAD.l}" y1="${PAD.t}" x2="${PAD.l}" y2="${PAD.t + ih}" stroke="#2e3644"/>
    <text x="${PAD.l + iw / 2}" y="${H - 14}" font-size="11.5" fill="#828a99" text-anchor="middle">对齐总成本 C_ali（相对无门禁）</text>
    <text x="16" y="${PAD.t + ih / 2}" font-size="11.5" fill="#828a99" text-anchor="middle" transform="rotate(-90 16 ${PAD.t + ih / 2})">残余风险（漏放率）</text>`;

  const front = pts.filter((p) => !p.dominated).sort((a, b) => a.cost - b.cost);
  if (front.length > 1) {
    const d = front.map((p, i) => `${i ? 'L' : 'M'}${cx(p.cost)},${cy(p.risk)}`).join(' ');
    svg += `<path d="${d}" fill="none" stroke="#c8f04b" stroke-width="1.6" stroke-dasharray="5 4" opacity="0.8"/>`;
  }
  pts.forEach((p) => {
    const x = cx(p.cost), y = cy(p.risk);
    const col = p.dominated ? '#565e6c' : '#c8f04b';
    if (p.dominated) {
      svg += `<circle cx="${x}" cy="${y}" r="7" fill="none" stroke="#565e6c" stroke-width="1.2" stroke-dasharray="3 2"/>`;
    }
    svg += `<circle cx="${x}" cy="${y}" r="4.6" fill="${col}" stroke="#0e1014" stroke-width="1.6"/>
      <text x="${x + (x > W * 0.72 ? -9 : 9)}" y="${y - 7}" font-size="11" fill="${p.dominated ? '#565e6c' : '#b8bec9'}" text-anchor="${x > W * 0.72 ? 'end' : 'start'}">${esc(p.display_name)}</text>`;
  });
  svg += '</svg>';
  $('#paretoWrap').innerHTML = svg;

  const dominated = pts.filter((p) => p.dominated);
  const safest = pts.slice().sort((a, b) => a.risk - b.risk)[0];
  const bestValue = pts.slice().sort((a, b) => b.acer - a.acer)[0];
  let note = dominated.length
    ? `被支配策略：<strong>${dominated.map((p) => esc(p.display_name)).join('、')}</strong>——成本更高而风险并不更低，这类策略在工程上不应被采用。`
    : '在（成本, 漏放率）平面上未出现被完全支配的策略。';
  if (safest && bestValue && safest.name !== bestValue.name) {
    note += ` <strong>但"风险最低"不等于"性价比最高"</strong>：${esc(safest.display_name)} 的残余风险最低（${pct(safest.risk)}），而 ${esc(bestValue.display_name)} 的 ACER 更高（${fmt(bestValue.acer, 3)} vs ${fmt(safest.acer, 3)}）。`;
  }
  $('#paretoNote').innerHTML = note;

  const byAcer = pts.slice().sort((a, b) => (b.acer ?? 0) - (a.acer ?? 0));
  const maxA = Math.max(...byAcer.map((r) => r.acer ?? 0), 0.0001);
  $('#acerBars').innerHTML = byAcer.map((r) => `
    <div class="bench ${r.dominated ? 'is-dominated' : ''}">
      <span class="bench-label" title="${esc(r.display_name || r.strategy)}">${esc(r.display_name || r.strategy)}</span>
      <div class="bench-track"><div class="bench-fill" style="width:${((r.acer ?? 0) / maxA) * 100}%"></div></div>
      <span class="bench-val">${fmt(r.acer, 3)}</span>
    </div>`).join('');

  const cols = [
    ['c_cap', '能力'], ['c_lat', '时延'], ['c_comp', '算力'], ['c_hum', '人工'],
    ['c_fp', '误拦'], ['c_fn', '漏放'], ['c_iter', '迭代效率'],
  ];
  const maxes = {};
  cols.forEach(([k]) => { maxes[k] = Math.max(...rows.map((r) => r[k] ?? 0), 1e-9); });
  $('#costTableTag').textContent = `${rows.length} 行`;
  let t = `<thead><tr><th>策略</th><th>任务集</th><th>来源</th>${cols.map(([, n]) => `<th>${n}</th>`).join('')}<th>C_ali</th><th>ACER</th><th>拦截率</th><th>误拦率</th><th>n</th></tr></thead><tbody>`;
  rows.forEach((r) => {
    t += `<tr><td class="name">${esc(r.display_name || r.strategy)}</td>
      <td class="dim">${esc(r.suite)}</td><td class="dim">${esc(r.source === 'artificial' ? '人工' : '涌现')}</td>`;
    cols.forEach(([k]) => {
      const v = r[k] ?? 0;
      t += `<td class="num">${fmt(v, 3)}<div class="mini-track"><div class="mini-fill" style="width:${Math.max(0, Math.min(100, (v / maxes[k]) * 100))}%"></div></div></td>`;
    });
    t += `<td class="num"><strong>${fmt(r.c_ali, 3)}</strong></td>
      <td class="num">${fmt(r.acer, 3)}</td>
      <td class="num">${pct(r.intercept_rate)}</td>
      <td class="num">${pct(r.false_block_rate)}</td>
      <td class="num">${r.n ?? '—'}</td></tr>`;
  });
  $('#costTable').innerHTML = t + '</tbody>';
}

/* ============================================================
   审计链
   ============================================================ */

function renderAudit() {
  const a = S.audit || {};
  const recs = a.records || [];
  const v = a.verify || {};
  $('#auditTag').textContent = v.valid ? `链完整 · ${a.total} 条记录` : `链在 seq ${v.broken_at_seq} 处断裂`;
  const led = $('#ledChain');
  if (led) led.className = 'led ' + (v.valid ? 'is-ok' : 'is-fail');

  // 链式可视化：最近 24 条节点
  const viz = $('#chainViz');
  if (viz) {
    const last = recs.slice(0, 24);
    viz.innerHTML = last.map((r, i) => {
      const k = r.kind === 'verdict' ? 'k-verdict' : r.kind === 'breaker' ? 'k-breaker'
        : r.kind === 'escalate' ? 'k-escalate' : '';
      const label = r.this_hash ? String(r.this_hash).slice(0, 4) : '----';
      return `${i ? '<span class="chain-link"></span>' : ''}
        <span class="chain-node ${k}" title="seq ${r.seq} · ${esc(r.kind)} · ${fmtTime(r.timestamp)}">
          <i></i><em>${esc(label)}</em>
        </span>`;
    }).join('') || '<p class="empty">尚无记录</p>';
  }

  let t = `<thead><tr><th>seq</th><th>时间</th><th>类型</th><th>摘要</th><th>会话</th><th>prev</th><th>this</th></tr></thead><tbody>`;
  recs.forEach((r) => {
    const p = r.payload || {};
    let brief = '';
    if (r.kind === 'verdict') brief = `${p.mod?.title || p.mod_id || ''} → ${p.action || ''}`;
    else if (r.kind === 'propose') brief = `${p.title || p.mod_id} · ${p.layer || ''}`;
    else if (r.kind === 'breaker') brief = `${p.trigger || ''} · ${p.path_key || ''}`;
    else if (r.kind === 'escalate') brief = `${p.decision || ''} · ${p.reason || ''}`;
    else brief = JSON.stringify(p).slice(0, 70);
    const cls = r.kind === 'verdict' ? 'accent' : r.kind === 'breaker' ? 'fail' : 'neutral';
    const sess = p.session_id ? `<span class="badge neutral">${esc(String(p.session_id).slice(-6))}·G${esc(p.gen ?? '?')}</span>` : '<span style="color:var(--muted-2)">—</span>';
    t += `<tr data-seq="${r.seq}" data-hash="${esc(r.this_hash)}">
      <td class="num">${r.seq}</td>
      <td class="num" style="color:var(--muted)">${fmtTime(r.timestamp)}</td>
      <td><span class="badge ${cls}">${esc(r.kind)}</span></td>
      <td>${esc(brief)}</td>
      <td>${sess}</td>
      <td class="num" style="color:var(--muted-2)">${esc(r.prev_hash)}</td>
      <td class="num">${esc(r.this_hash)}</td>
    </tr>`;
  });
  $('#auditTable').innerHTML = t + '</tbody>';
}

async function refreshAudit() {
  S.audit = await api('/api/audit').catch(() => ({ total: 0, records: [], verify: { valid: true } }));
  renderAudit();
}
async function loadAuditOnly() { await refreshAudit(); }

/* ============================================================
   装载与交互
   ============================================================ */

function switchView(name) {
  $$('.tab').forEach((t) => t.classList.toggle('is-active', t.dataset.view === name));
  $$('.view').forEach((v) => v.classList.toggle('is-active', v.id === `view-${name}`));
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function loadLiveStatus() {
  try {
    S.liveStatus = await api('/api/live/status');
  } catch (_) { S.liveStatus = { api_configured: false, sessions: [], scenarios: [] }; }
  const st = S.liveStatus;
  $('#apiStatus').innerHTML = st.api_configured
    ? `<span class="dot dot-ok"></span>API 已配置 · ${esc(st.provider || '自定义')} · <code>${esc(st.model || '')}</code>`
    : `<span class="dot"></span>未配置 API —— 双击「配置API.bat」后可用真实模式；当前可先离线演示`;
  const leds = {
    ledApi: { cls: st.api_configured ? 'is-ok' : '', on: true },
    ledLive: { cls: (st.current && st.current.status === 'running') ? 'is-ok' : '', on: true },
  };
  Object.entries(leds).forEach(([id, led]) => {
    const el = document.getElementById(id);
    if (el) el.className = 'led ' + led.cls;
  });
  const sel = $('#replaySel');
  const sessions = st.sessions || [];
  sel.innerHTML = sessions.length
    ? sessions.map((s) => `<option value="${esc(s.session_id)}">${esc(s.session_id)}（${s.mode} · ${s.n_events} 事件）</option>`).join('')
    : '<option value="">（暂无历史会话）</option>';
  const scSel = $('#ctlScenario');
  const scenarios = st.scenarios || [];
  scSel.innerHTML = '<option value="">自动轮换（按种子）</option>' +
    scenarios.map((s) => `<option value="${esc(s.key)}">${esc(s.name)}</option>`).join('');
  if (L.scenarioKey) scSel.value = L.scenarioKey;
}

async function loadAll() {
  try { S.health = await api('/api/health'); } catch (_) { S.health = null; }
  const [tax, res, aud] = await Promise.all([
    api('/api/taxonomy').catch(() => null),
    api('/api/results').catch(() => ({ summary: [], frontier: [], raw_count: 0 })),
    api('/api/audit').catch(() => ({ total: 0, records: [], verify: { valid: true } })),
  ]);
  S.taxonomy = tax; S.results = res; S.audit = aud;
  renderLiveStats(); renderCapChart();
  renderMethod(); renderTaxonomy(); renderFrontier(); renderAudit();
  await loadLiveStatus();
  await loadPulse().catch(() => {});
}

// -- 事件绑定 -----------------------------------------------------------
$$('.tab').forEach((t) => t.addEventListener('click', () => switchView(t.dataset.view)));
$('#btnStart').addEventListener('click', startLive);
$('#btnStop').addEventListener('click', stopLive);
$('#btnReplay').addEventListener('click', () => replaySession($('#replaySel').value));
$('#modalClose').addEventListener('click', closeModal);
$('#modalMask').addEventListener('click', (e) => { if (e.target === $('#modalMask')) closeModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

$('#modeSeg').addEventListener('click', (e) => {
  const b = e.target.closest('.seg-btn');
  if (!b) return;
  $$('#modeSeg .seg-btn').forEach((x) => x.classList.remove('is-active'));
  b.classList.add('is-active');
  L.mode = b.dataset.mode;
});
$('#ctlGens').addEventListener('input', () => {
  $('#ctlGensVal').textContent = `${$('#ctlGens').value} 代`;
});
$('#ctlScenario').addEventListener('change', () => {
  L.scenarioKey = $('#ctlScenario').value;
  const st = S.liveStatus || {};
  const sc = (st.scenarios || []).find((s) => s.key === L.scenarioKey);
  $('#scenarioDesc').textContent = sc ? `《${sc.name}》· ${sc.description}` : '';
});
$('#filtSuite').addEventListener('click', (e) => {
  const b = e.target.closest('.seg-btn');
  if (!b) return;
  $$('#filtSuite .seg-btn').forEach((x) => x.classList.remove('is-active'));
  b.classList.add('is-active');
  S.filter.suite = b.dataset.suite;
  renderFrontier();
});
$('#filtSource').addEventListener('click', (e) => {
  const b = e.target.closest('.seg-btn');
  if (!b) return;
  $$('#filtSource .seg-btn').forEach((x) => x.classList.remove('is-active'));
  b.classList.add('is-active');
  S.filter.source = b.dataset.source;
  renderFrontier();
});

loadAll();
setInterval(() => { refreshAudit().catch(() => {}); }, 15000);
