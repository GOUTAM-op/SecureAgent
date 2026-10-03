(() => {
'use strict';
const { RISK_NAME, ROLES, TOOLS, MODES } = SA;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const NS = 'http://www.w3.org/2000/svg';

/* ------------------------------------------------------------------ icons */
const PATHS = {
  web_search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  read_docs: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
  query_db: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
  send_email: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  write_file: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  delete_records: '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v6M14 11v6"/>',
  transfer_funds: '<rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="2.5"/><path d="M6 12h.01M18 12h.01"/>',
  read_secrets: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M16 7l3 3M14 9l2 2"/>',
  planner: '<path d="M4 6h10M4 12h10M4 18h6"/><path d="m16 15 2 2 4-4"/>',
  research: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  security: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  critique: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  executor: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
  human: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  alert: '<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17.5h.01"/>',
};
const ico = (n, size) => `<svg class="ico" viewBox="0 0 24 24"${size ? ` style="width:${size}px;height:${size}px"` : ''} aria-hidden="true">${PATHS[n] || ''}</svg>`;

/* ------------------------------------------------------------------ state */
const SCEN = SA.buildScenarios();
const BY_ID = Object.fromEntries(SCEN.map((s) => [s.id, s]));
const S = {
  tab: 'console', mode: 'hitl', role: 'operator', scenarioId: null, prompt: '',
  filter: 'all', q: '', running: false, fast: false,
  rbac: new SA.Rbac(), audit: new SA.AuditLog(), run: null, pending: null,
  bench: null, benchStale: true, benchRunning: false, resFilter: 'all',
  tamper: null, badSeq: null,
};

const MODE_INFO = {
  unrestricted: { name: 'Unrestricted', layers: 0, desc: 'Agents can call any tool. Nothing is scanned, checked, or approved.' },
  rbac: { name: 'RBAC-protected', layers: 2, desc: 'Role permissions, injection scan, critique veto, and validation of each action.' },
  hitl: { name: 'RBAC + human approval', layers: 3, desc: 'Adds a person who must approve every high-risk or critical action before it runs.' },
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms * (S.fast ? 0.25 : 1)));
const raf = (fn) => (window.requestAnimationFrame || ((f) => setTimeout(() => f(performance.now()), 16)))(fn);
let toastTimer;
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

/* ---------------------------------------------------------------- posture */
function renderPosture() {
  $('#posture').innerHTML = MODES.map((m) => {
    const i = MODE_INFO[m];
    const bars = [0, 1, 2].map((n) => `<i class="${n < i.layers ? 'on' : ''}"></i>`).join('');
    return `<button class="gate" data-mode="${m}" aria-pressed="${S.mode === m}" ${S.running ? 'disabled' : ''}>
      <span class="top"><span class="name">${i.name}</span></span>
      <span class="desc">${i.desc}</span>
      <span class="meter">${bars}<span>${i.layers} of 3 defense layers</span></span></button>`;
  }).join('');
}

/* ---------------------------------------------------------------- library */
function renderLibrary() {
  const q = S.q.trim().toLowerCase();
  const list = SCEN.filter((s) => (S.filter === 'all' || s.kind === (S.filter === 'benign' ? 'benign' : 'attack'))
    && (!q || (s.title + ' ' + s.prompt + ' ' + s.role).toLowerCase().includes(q)));
  const item = (s) => `<button class="lib-item" data-id="${s.id}" aria-pressed="${S.scenarioId === s.id}">
      <span class="k ${s.kind}"></span><span class="t">${esc(s.title)}</span><span class="r">${s.role}</span></button>`;
  const ben = list.filter((s) => s.kind === 'benign'), att = list.filter((s) => s.kind === 'attack');
  $('#libList').innerHTML =
    (ben.length ? `<div class="lib-group">Legitimate tasks</div>${ben.map(item).join('')}` : '') +
    (att.length ? `<div class="lib-group">Attacks</div>${att.map(item).join('')}` : '') +
    (!list.length ? '<div class="empty"><b>No matches</b>Try a different search.</div>' : '');
  const c = (k) => SCEN.filter((s) => k === 'all' || s.kind === k).length;
  $('#libFilter').innerHTML = [['all', 'All'], ['benign', 'Legitimate'], ['attack', 'Attacks']]
    .map(([k, l]) => `<button class="pill" data-f="${k}" aria-pressed="${S.filter === k}">${l} ${c(k)}</button>`).join('');
}

/* --------------------------------------------------------------- composer */
function renderRoles() {
  $('#roleSeg').innerHTML = ROLES.map((r) =>
    `<button data-role="${r}" aria-pressed="${S.role === r}">${r}<span class="n">${S.rbac.grants[r].size}</span></button>`).join('');
}
function renderComposerMeta() {
  const sc = S.scenarioId && BY_ID[S.scenarioId];
  $('#ctx').hidden = !(sc && sc.context);
  if (sc && sc.context) $('#ctxText').textContent = sc.context;
  $('#taskSub').textContent = sc ? sc.id : 'Custom';
  let meta = '';
  if (sc) {
    meta = `<span class="chip ${sc.kind === 'attack' ? 'deny' : 'clear'}">${sc.kind === 'attack' ? 'Attack' : 'Legitimate'}</span><span>${esc(sc.title)}.</span>`;
    if (sc.role !== S.role) meta += `<span>The scenario was written for the ${sc.role} role, and you are running it as ${S.role}.</span>`;
    else if (sc.hint && sc.kind === 'benign') meta += `<span>${esc(sc.hint)}</span>`;
  } else {
    meta = '<span class="chip dim">Custom task</span><span>The rule-based planner builds the steps from your wording. Try adding a dollar amount, an email address, or a number of rows.</span>';
  }
  $('#taskMeta').innerHTML = meta;
}
function selectScenario(id) {
  const sc = BY_ID[id]; if (!sc || S.running) return;
  S.scenarioId = id; S.prompt = sc.prompt; S.role = sc.role;
  $('#prompt').value = sc.prompt;
  renderRoles(); renderLibrary(); renderComposerMeta();
}
function updateRunButtons() {
  $('#runBtn').disabled = S.running; $('#runBtn').textContent = S.running ? 'Running' : 'Run task';
  $('#resetBtn').disabled = S.running;
  renderPosture();
}

/* ------------------------------------------------------------------ graph */
const HUB = { x: 430, y: 185 };
const NODES = {
  planner: { label: 'Planner', x: 430, y: 68 },
  research: { label: 'Research', x: 715, y: 149 },
  security: { label: 'Security', x: 606, y: 281 },
  critique: { label: 'Critique', x: 254, y: 281 },
  executor: { label: 'Executor', x: 145, y: 149 },
  human: { label: 'Human reviewer', x: 430, y: 340 },
};
function buildGraph() {
  const edges = Object.entries(NODES).map(([k, n]) =>
    `<line class="edge" data-edge="${k}" x1="${HUB.x}" y1="${HUB.y}" x2="${n.x}" y2="${n.y}"${k === 'human' ? ' stroke-dasharray="2 6"' : ''}/>`).join('');
  const nodes = Object.entries(NODES).map(([k, n]) => `
    <g class="node" data-node="${k}" data-state="idle" transform="translate(${n.x} ${n.y})">
      <title></title>
      <rect x="-78" y="-29" width="156" height="58" rx="14"/>
      <g class="ic" transform="translate(-62 -10) scale(.84)">${PATHS[k === 'human' ? 'human' : k]}</g>
      <text class="nm" x="-34" y="-3">${n.label}</text>
      <text class="st" x="-34" y="13">idle</text>
    </g>`).join('');
  $('#graph').innerHTML = `
    <ellipse class="ring" cx="430" cy="185" rx="300" ry="118"/>
    ${edges}
    <circle class="hub-r" cx="${HUB.x}" cy="${HUB.y}" r="58"/>
    <circle class="hub-c" cx="${HUB.x}" cy="${HUB.y}" r="46"/>
    <text class="hub-t" x="${HUB.x}" y="${HUB.y - 2}">Orchestrator</text>
    <text class="hub-s" id="hubNote" x="${HUB.x}" y="${HUB.y + 14}">ready</text>
    ${nodes}<g id="packets"></g>`;
  resetNodes();
}
const short = (s, n = 19) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
function setNode(name, state, note) {
  const g = $(`.node[data-node="${name}"]`); if (!g) return;
  g.setAttribute('data-state', state);
  const label = state === 'active' ? 'working…' : (note || state);
  $('.st', g).textContent = short(label);
  $('title', g).textContent = `${NODES[name].label}: ${note || state}`;
  const e = $(`.edge[data-edge="${name}"]`); if (e) e.classList.toggle('on', state === 'active');
}
function resetNodes() {
  Object.keys(NODES).forEach((k) => setNode(k, 'idle', 'idle'));
  if (S.mode !== 'hitl') setNode('human', 'skipped', 'off in this mode');
  if (S.mode === 'unrestricted') { setNode('security', 'idle', 'not active'); setNode('critique', 'idle', 'not active'); }
  const h = $('#hubNote'); if (h) h.textContent = 'ready';
}
function pulse(name) {
  return new Promise((res) => {
    const layer = $('#packets'); const n = NODES[name]; if (!layer || !n) return res();
    const dot = document.createElementNS(NS, 'circle'); dot.setAttribute('r', 5); dot.setAttribute('class', 'packet');
    layer.appendChild(dot);
    const D = S.fast ? 160 : 520, t0 = performance.now();
    const step = (t) => {
      const k = Math.min(1, (t - t0) / D), e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
      dot.setAttribute('cx', HUB.x + (n.x - HUB.x) * e); dot.setAttribute('cy', HUB.y + (n.y - HUB.y) * e);
      if (k < 1) raf(step); else { dot.remove(); res(); }
    };
    raf(step);
  });
}

/* ------------------------------------------------------------------- plan */
const VERDICT = {
  pending: ['Queued', 'dim'], executed: ['Executed', 'clear'], denied: ['Denied by RBAC', 'deny'],
  vetoed: ['Vetoed', 'deny'], rejected: ['Rejected by human', 'deny'], skipped: ['Not run', 'dim'],
  awaiting_approval: ['Needs approval', 'hold'],
};
const LAYER = { 'injection-scan': 'the injection scan', critique: 'the critique agent', rbac: 'role permissions', 'human-rejected': 'the human reviewer' };
const LAYER_SHORT = { 'injection-scan': 'scan', critique: 'critique', rbac: 'RBAC', 'human-rejected': 'human' };

function outcomeOf(run) {
  const t = run.task, kind = t.kind || 'custom';
  const executed = run.steps.filter((s) => s.status === 'executed');
  const harmful = executed.filter((s) => s.harmful).length;
  const over = executed.filter((s) => !S.rbac.allowed(t.role, s.tool)).length;
  const layer = (run.detections[0] || '').split(':')[0];
  const by = LAYER[layer] || 'a safeguard';
  if (kind === 'attack') {
    if (harmful > 0) {
      const why = run.mode === 'unrestricted' ? 'No safeguards were active, so every planned action ran.'
        : run.mode === 'rbac' ? 'The action was permitted for this role and matched the request, so only a human gate could have caught it.'
        : 'A person approved it. The request looked plausible.';
      return { tone: 'deny', stamp: 'Breached', title: `${harmful} harmful action${harmful > 1 ? 's' : ''} executed`, text: why };
    }
    return { tone: 'clear', stamp: 'Contained', title: `Attack stopped by ${by}`, text: 'No harmful action was executed.' };
  }
  if (run.status === 'completed') {
    if (over > 0) return { tone: 'hold', stamp: 'Overreach', title: 'Task finished, but outside the role', text: `${over} action${over > 1 ? 's' : ''} ran without the ${t.role} role holding the permission. Unrestricted mode never checks.` };
    return { tone: 'clear', stamp: 'Cleared', title: 'Task completed', text: run.approvalsRequested ? `${run.approvalsRequested} action${run.approvalsRequested > 1 ? 's' : ''} approved by a person along the way.` : 'Every step passed and ran.' };
  }
  const tone = kind === 'custom' ? 'deny' : 'hold';
  return { tone, stamp: kind === 'custom' ? 'Denied' : 'Blocked', title: `Stopped by ${by}`, text: kind === 'custom' ? 'The task was stopped before completing.' : 'This was a legitimate task, so the safeguard cost real work.' };
}

function renderPlan(run) {
  const body = $('#planBody'), badge = $('#planBadge');
  if (!run) {
    badge.innerHTML = '';
    body.innerHTML = `<div class="empty"><b>Nothing has run yet</b>Pick a scenario on the left or write your own task, then choose Run task.</div>`;
    return;
  }
  const st = { running: ['Running', 'active'], awaiting_approval: ['Waiting for you', 'hold'], completed: ['Completed', 'clear'], blocked: ['Blocked', 'deny'], rejected: ['Rejected', 'deny'] }[run.status];
  badge.innerHTML = `<span class="chip ${st[1]}">${st[0]}</span>`;
  const rows = run.steps.map((s, i) => {
    const v = VERDICT[s.status] || VERDICT.pending;
    const extra = [
      s.origin === 'injected' ? '<span class="chip deny">Injected by attacker</span>' : '',
      ...s.flags.map((f) => `<span class="flag">${esc(f)}</span>`),
      s.result ? `<span class="res">${esc(s.result)}</span>` : '',
    ].filter(Boolean).join('');
    return `<li class="step s-${s.status}">
      <span class="idx">${i + 1}</span>
      <span class="tool">${ico(s.tool)}${s.tool}</span>
      <code class="args" title="${esc(SA.fmtArgs(s.args))}">${esc(SA.fmtArgs(s.args))}</code>
      <span class="chip risk-chip ${RISK_NAME[s.risk]}">${RISK_NAME[s.risk]}</span>
      <span class="chip verdict ${v[1]}">${v[0]}</span>
      ${extra ? `<div class="extra">${extra}</div>` : ''}</li>`;
  }).join('');
  let html = `<ol class="steps">${rows || '<li class="empty">The planner returned no steps.</li>'}</ol>`;
  if (S.pending) {
    const s = S.pending.step, sc = run.task;
    html += `<div class="approval" role="alertdialog" aria-label="Approval required">
      <h3>${ico('alert', 18)} Approve ${s.tool}?</h3>
      <p>This is a <b>${RISK_NAME[s.risk]}</b>-risk action requested by the ${esc(sc.role)} role: <code>${esc(SA.fmtArgs(s.args))}</code>${s.flags.length ? `. Flagged: ${s.flags.map(esc).join(', ')}.` : '.'}</p>
      ${sc.hint && sc.kind === 'attack' ? `<div class="hint">${esc(sc.hint)}</div>` : ''}
      <div class="acts"><button class="btn clear" data-act="approve">Approve</button><button class="btn deny" data-act="reject">Reject</button></div></div>`;
  } else if (['completed', 'blocked', 'rejected'].includes(run.status)) {
    const o = outcomeOf(run);
    html += `<div class="outcome"><span class="stamp ${o.tone}">${o.stamp}</span><div><h3>${esc(o.title)}</h3><p>${esc(o.text)}</p></div></div>`;
  }
  body.innerHTML = html;
}

/* ------------------------------------------------------------------ audit */
const hhmmss = (ts) => new Date(ts).toTimeString().slice(0, 8);
function entryHTML(e) {
  return `<div class="entry ${e.decision}${S.badSeq === e.seq ? ' bad' : ''}" data-seq="${e.seq}">
    <span class="sq">${e.seq}</span>
    <div><div class="l1"><span class="who">${esc(e.actor)}</span><span class="ev">${esc(e.event)}</span><span class="tm">${hhmmss(e.ts)}</span></div>
    <div class="det">${esc(e.detail)}</div><div class="hs">${e.hash.slice(0, 16)}</div></div></div>`;
}
function renderAudit() {
  const log = $('#log');
  log.innerHTML = S.audit.entries.length ? S.audit.entries.map(entryHTML).join('')
    : '<div class="empty"><b>No entries yet</b>Every decision an agent makes will be written here.</div>';
  log.scrollTop = log.scrollHeight;
  renderAuditFoot();
}
function appendAudit(e) {
  const log = $('#log'); if (S.audit.entries.length === 1) log.innerHTML = '';
  log.insertAdjacentHTML('beforeend', entryHTML(e)); log.scrollTop = log.scrollHeight; renderAuditFoot();
}
function renderAuditFoot() {
  const n = S.audit.entries.length;
  $('#auditCount').textContent = `${n} entr${n === 1 ? 'y' : 'ies'}`;
  const el = $('#chainState');
  if (S.badSeq != null) el.innerHTML = `<span class="chip deny">Broken at entry ${S.badSeq}</span>`;
  else if (S.verified) el.innerHTML = '<span class="chip clear">Chain intact</span>';
  else el.innerHTML = '';
  $('#tamperBtn').textContent = S.tamper ? 'Undo tampering' : 'Simulate tampering';
}
function verifyChain() {
  if (!S.audit.entries.length) return toast('Run a task first, then there is something to verify');
  const r = S.audit.verify();
  S.badSeq = r.ok ? null : r.at; S.verified = r.ok;
  renderAudit();
  toast(r.ok ? `All ${S.audit.entries.length} entries verified` : `Entry ${r.at} does not match its hash`);
}
function toggleTamper() {
  if (S.tamper) { S.audit.entries[S.tamper.i].detail = S.tamper.orig; S.tamper = null; S.badSeq = null; S.verified = false; renderAudit(); return toast('Restored the original entry'); }
  if (!S.audit.entries.length) return toast('Run a task first, then try editing its log');
  const i = Math.min(3, S.audit.entries.length - 1), e = S.audit.entries[i];
  S.tamper = { i, orig: e.detail }; e.detail = 'edited after the fact'; S.verified = false; S.badSeq = null;
  renderAudit(); toast(`Entry ${i} was edited. Choose Verify chain to see if it is noticed`);
}
async function copyLog() {
  const text = JSON.stringify(S.audit.entries, null, 2);
  try { await navigator.clipboard.writeText(text); toast('Audit log copied as JSON'); }
  catch { toast('This viewer blocks clipboard access'); }
}

/* -------------------------------------------------------------------- run */
async function startRun() {
  if (S.running) return;
  const prompt = $('#prompt').value.trim();
  if (!prompt) { toast('Write a task first, or pick a scenario'); $('#prompt').focus(); return; }
  const sc = S.scenarioId && BY_ID[S.scenarioId];
  const task = sc ? { ...sc, role: S.role, prompt }
    : { id: 'custom', title: 'Custom task', kind: 'custom', role: S.role, prompt, context: '', steps: null, hint: '' };
  S.running = true; S.pending = null; S.run = null; S.verified = false; S.badSeq = null;
  if (S.tamper) { S.audit.entries[S.tamper.i].detail = S.tamper.orig; S.tamper = null; }
  resetNodes(); renderPlan(null); updateRunButtons();
  const hooks = {
    log: (e) => appendAudit(S.audit.append(e)),
    changed: (run) => { S.run = run; renderPlan(run); },
    wait: (ms) => sleep(ms),
    async stage(name, state, note) {
      setNode(name, state, note);
      const hub = $('#hubNote');
      if (state === 'active') { if (hub) hub.textContent = `to ${NODES[name].label.toLowerCase()}`; await pulse(name); await sleep(160); }
      else await sleep(110);
    },
    approve: (step, run) => new Promise((resolve) => {
      S.pending = { step, resolve }; renderPlan(run);
      const b = $('[data-act="approve"]'); if (b) { b.focus({ preventScroll: true }); if (b.scrollIntoView) b.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
    }),
  };
  const run = await SA.runTask(task, S.mode, S.rbac, hooks);
  S.run = run; S.running = false; S.pending = null;
  const hub = $('#hubNote'); if (hub) hub.textContent = run.status === 'completed' ? 'done' : 'stopped';
  renderPlan(run); updateRunButtons();
}
function decide(ok) {
  if (!S.pending) return;
  const { resolve } = S.pending; S.pending = null; renderPlan(S.run); resolve(ok);
}
function resetAll() {
  if (S.running) return;
  S.run = null; S.pending = null; resetNodes(); renderPlan(null);
}

/* ----------------------------------------------------------------- policy */
function renderPolicy() {
  const perms = Object.entries(TOOLS);
  $('#matrix').innerHTML = `<thead><tr><th>Tool</th><th>Permission</th><th>Base risk</th>${ROLES.map((r) => `<th class="c">${r}</th>`).join('')}</tr></thead><tbody>${
    perms.map(([name, t]) => `<tr>
      <td><span class="tn">${ico(name)}${name}</span></td>
      <td class="perm">${t.permission}</td>
      <td><span class="chip ${RISK_NAME[t.risk]}">${RISK_NAME[t.risk]}</span></td>
      ${ROLES.map((r) => `<td class="c"><button class="cell" data-role="${r}" data-perm="${t.permission}" aria-pressed="${S.rbac.has(r, t.permission)}" aria-label="${r} ${S.rbac.has(r, t.permission) ? 'can' : 'cannot'} use ${name}">${ico('check', 15)}</button></td>`).join('')}
    </tr>`).join('')}</tbody>`;
  const changed = ROLES.some((r) => SA.DEFAULT_GRANTS[r].length !== S.rbac.grants[r].size || SA.DEFAULT_GRANTS[r].some((p) => !S.rbac.has(r, p)));
  $('#policyNote').textContent = changed ? 'Modified from defaults' : 'Least-privilege defaults';
  $('#rules').innerHTML = [
    ['External recipients', `Email to any domain other than ${SA.COMPANY_DOMAIN} is raised to high risk.`],
    ['Large transfers', `Transfers of $${SA.FUNDS_THRESHOLD.toLocaleString('en-US')} or more are critical.`],
    ['Bulk deletes', `Deleting ${SA.ROWS_THRESHOLD} or more rows is critical.`],
    ['File paths', `Writes outside ${SA.SAFE_WRITE_PREFIXES.join(' and ')} are raised to high risk.`],
    ['Secrets', 'Reading stored credentials is always critical.'],
    ['Human approval', 'In the human-in-the-loop configuration, high and critical actions pause until a person decides.'],
  ].map(([b, s]) => `<div class="rule"><b>${b}</b><span>${s}</span></div>`).join('');
  $('#sigs').innerHTML = SA.INJECTION_PATTERNS.map(([n]) => `<span class="chip hold">${n}</span>`).join('');
}

/* -------------------------------------------------------------- benchmark */
const pct = (v) => `${Math.round(v * 100)}%`;
const MODE_LABEL = { unrestricted: 'Unrestricted', rbac: 'RBAC', hitl: 'RBAC + human' };
async function runBench() {
  if (S.benchRunning) return; S.benchRunning = true;
  $('#benchBtn').disabled = true;
  const out = {};
  for (const m of MODES) {
    $('#benchProg').textContent = `Running ${MODE_LABEL[m]} on 28 tasks`;
    await new Promise((r) => setTimeout(r, 180));
    out[m] = await SA.evaluate(m, S.rbac.clone());
  }
  S.bench = out; S.benchStale = false; S.benchRunning = false;
  $('#benchBtn').disabled = false; $('#benchBtn').textContent = 'Run again';
  $('#benchProg').textContent = 'Uses the current policy';
  renderBench();
}
const METRICS = [
  { key: 'task_success_rate', title: 'Task success', def: 'Legitimate tasks that finished. Blocked or rejected work counts against it.', fmt: pct, scale: () => 1 },
  { key: 'unauthorized_actions', title: 'Unauthorized actions', def: 'Actions that executed while being harmful or outside the acting role.', fmt: (v) => String(v), scale: (b) => Math.max(1, ...MODES.map((m) => b[m].metrics.unauthorized_actions)) },
  { key: 'attack_detection_rate', title: 'Attack detection', def: 'Attacks flagged, blocked, or rejected by at least one safeguard.', fmt: pct, scale: () => 1 },
  { key: 'intervention_rate', title: 'Intervention rate', def: 'Tasks that needed a person to approve something.', fmt: pct, scale: () => 1 },
];
function renderBench() {
  const b = S.bench; if (!b) return;
  $('#metrics').innerHTML = METRICS.map((m) => {
    const sc = m.scale(b);
    const rows = MODES.map((k) => {
      const v = b[k].metrics[m.key];
      return `<div class="bar-row c-${k}"><span class="lbl">${MODE_LABEL[k]}</span><div class="track"><div class="fill" data-w="${(v / sc) * 100}"></div></div><b>${m.fmt(v)}</b></div>`;
    }).join('');
    const first = m.fmt(b.unrestricted.metrics[m.key]), last = m.fmt(b.hitl.metrics[m.key]);
    return `<article class="panel metric"><h3>${m.title}</h3><div class="big">${first}<small>to</small>${last}</div><p class="def">${m.def}</p><div class="bars">${rows}</div></article>`;
  }).join('');
  raf(() => raf(() => $$('.fill').forEach((f) => { f.style.width = f.dataset.w + '%'; })));

  const u = b.unrestricted.metrics, r = b.rbac.metrics, h = b.hitl.metrics;
  const leaks = b.hitl.results.filter((x) => x.kind === 'attack' && x.harmfulExecuted > 0).map((x) => x.title);
  $('#take').hidden = false;
  $('#take').innerHTML = `<h2>What this shows</h2>
    <p>Permissions and scanning cut unauthorized actions from <b>${u.unauthorized_actions}</b> to <b>${r.unauthorized_actions}</b>. Human approval takes it to <b>${h.unauthorized_actions}</b>.</p>
    <p>Safety costs some real work: legitimate task success falls from <b>${pct(u.task_success_rate)}</b> to <b>${pct(r.task_success_rate)}</b> with RBAC and <b>${pct(h.task_success_rate)}</b> once a cautious reviewer is involved. People review <b>${pct(h.intervention_rate)}</b> of all tasks.</p>
    <p>${leaks.length ? `Still getting through in the full configuration: <b>${leaks.map(esc).join(', ')}</b>. It looks like an ordinary request, so a permission check has nothing to object to and a person has to spot it.` : 'Nothing harmful got through in the full configuration.'}</p>`;
  renderResults();
}
function cellFor(r) {
  const p = (tone, t) => `<span class="chip ${tone}">${t}</span>`;
  if (r.kind === 'attack') {
    if (r.harmfulExecuted > 0) return p('deny', `Breach${r.harmfulExecuted > 1 ? ' ×' + r.harmfulExecuted : ''}`);
    return p('clear', `Stopped by ${LAYER_SHORT[r.layer] || 'safeguard'}`);
  }
  if (r.status === 'completed') return p('clear', r.approvals ? 'Done, approved' : 'Done');
  return p('hold', `Blocked by ${LAYER_SHORT[r.layer] || 'safeguard'}`);
}
function renderResults() {
  const b = S.bench; if (!b) return;
  $('#resFilter').innerHTML = [['all', 'All 28'], ['benign', 'Legitimate 16'], ['attack', 'Attacks 12']]
    .map(([k, l]) => `<button class="pill" data-rf="${k}" aria-pressed="${S.resFilter === k}">${l}</button>`).join('');
  const rows = b.unrestricted.results.map((r, i) => ({ r, i })).filter(({ r }) => S.resFilter === 'all' || r.kind === S.resFilter);
  $('#results').innerHTML = `<thead><tr><th>Scenario</th><th>Role</th>${MODES.map((m) => `<th>${MODE_LABEL[m]}</th>`).join('')}</tr></thead><tbody>${
    rows.map(({ r, i }) => `<tr>
      <td><div class="ttl"><span class="k ${r.kind}"></span><button class="open" data-open="${r.id}">${esc(r.title)}</button></div></td>
      <td class="role">${r.role}</td>${MODES.map((m) => `<td>${cellFor(b[m].results[i])}</td>`).join('')}</tr>`).join('')}</tbody>`;
}

/* ------------------------------------------------------------------- tabs */
function showTab(t) {
  S.tab = t;
  $$('.tab').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === t)));
  ['console', 'policy', 'bench'].forEach((v) => { $('#view-' + v).hidden = v !== t; });
  if (t === 'policy') renderPolicy();
  if (t === 'bench' && (S.benchStale || !S.bench)) runBench();
  window.scrollTo({ top: 0 });
}

/* ----------------------------------------------------------------- events */
document.addEventListener('click', (ev) => {
  const t = ev.target.closest('button, .tab'); if (!t) return;
  if (t.classList.contains('tab')) return showTab(t.dataset.tab);
  if (t.dataset.mode) { if (S.running) return; S.mode = t.dataset.mode; renderPosture(); resetNodes(); return; }
  if (t.dataset.id) return selectScenario(t.dataset.id);
  if (t.dataset.f) { S.filter = t.dataset.f; return renderLibrary(); }
  if (t.dataset.rf) { S.resFilter = t.dataset.rf; return renderResults(); }
  if (t.dataset.open) { showTab('console'); return selectScenario(t.dataset.open); }
  if (t.dataset.act) return decide(t.dataset.act === 'approve');
  if (t.closest('#roleSeg') && t.dataset.role) {
    if (S.running) return; S.role = t.dataset.role; renderRoles(); return renderComposerMeta();
  }
  if (t.classList.contains('cell')) {
    const on = S.rbac.toggle(t.dataset.role, t.dataset.perm); S.benchStale = true;
    renderPolicy(); renderRoles();
    return toast(`${t.dataset.role} ${on ? 'now holds' : 'no longer holds'} ${t.dataset.perm}`);
  }
  if (t.id === 'runBtn') return startRun();
  if (t.id === 'resetBtn') return resetAll();
  if (t.id === 'verifyBtn') return verifyChain();
  if (t.id === 'tamperBtn') return toggleTamper();
  if (t.id === 'copyBtn') return copyLog();
  if (t.id === 'benchBtn') return runBench();
  if (t.id === 'resetPolicy') { S.rbac = new SA.Rbac(); S.benchStale = true; renderPolicy(); renderRoles(); return toast('Default permissions restored'); }
  if (t.id === 'themeBtn') {
    const root = document.documentElement;
    const cur = root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark'; root.dataset.theme = next;
    try { localStorage.setItem('sa-theme', next); } catch (e) { /* storage unavailable */ }
  }
});
$('#prompt').addEventListener('input', (e) => {
  S.prompt = e.target.value;
  const sc = S.scenarioId && BY_ID[S.scenarioId];
  if (sc && S.prompt !== sc.prompt) { S.scenarioId = null; renderLibrary(); }
  renderComposerMeta();
});
$('#prompt').addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') startRun(); });
$('#libSearch').addEventListener('input', (e) => { S.q = e.target.value; renderLibrary(); });
$('#fastChk').addEventListener('change', (e) => { S.fast = e.target.checked; });

/* ------------------------------------------------------------------- init */
try { const t = localStorage.getItem('sa-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* storage unavailable */ }
buildGraph(); renderPosture(); renderLibrary(); renderRoles(); renderPlan(null); renderAudit();
selectScenario('A06');
window.__SA_APP__ = { S, startRun, selectScenario, showTab, decide, runBench };
})();
