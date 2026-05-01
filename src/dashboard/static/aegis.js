// AEGIS Dashboard — Client-side (Max Plan + API Plan)

// Auto-detect base path: works at /dashboard/ and at root (aegis.ankr.in)
const API = window.location.pathname.startsWith('/dashboard') ? '/dashboard' : '';

function formatTokens(t) {
  if (t >= 1e9) return (t / 1e9).toFixed(2) + 'B';
  if (t >= 1e6) return (t / 1e6).toFixed(1) + 'M';
  if (t >= 1e3) return (t / 1e3).toFixed(0) + 'K';
  return t.toString();
}

function formatDuration(s) {
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h + 'h ' + m + 'm';
}

async function fetchStatus() {
  try {
    const [[statusRes, sysRes, providersRes, trendRes]] = await Promise.all([
      Promise.all([
        fetch(`${API}/api/status`),
        fetch(`${API}/api/system`),
        fetch(`${API}/api/providers`),
        fetch(`${API}/api/trend`),
      ]),
      loadValves(),
    ]);
    const data = await statusRes.json();
    const sys = await sysRes.json();
    const providers = await providersRes.json();
    const trend = await trendRes.json();

    document.getElementById('plan-badge').textContent = data.plan || 'api';

    const isMax = data.is_max_plan;
    // Toggle ops-strip cards: max plan shows 5h+weekly, api plan shows daily+weekly+monthly
    ['window-5h-card', 'window-weekly-card'].forEach(id => {
      const el = document.getElementById(id); if (el) el.style.display = isMax ? '' : 'none';
    });
    ['daily-card', 'weekly-card', 'monthly-card'].forEach(id => {
      const el = document.getElementById(id); if (el) el.style.display = isMax ? 'none' : '';
    });

    if (isMax) renderMaxPlan(data);
    else renderApiPlan(data);

    renderSystem(sys, providers);
    renderTrend(trend);
    renderSessions(data.sessions || [], isMax);
    renderAlerts(data.alerts || []);
  } catch (e) {
    console.error('Failed to fetch status:', e);
  }
}

function renderSystem(sys, providers) {
  document.getElementById('kpi-processes').textContent = sys.process_count || 0;
  document.getElementById('kpi-velocity').textContent = formatTokens(sys.velocity_5m?.tokens_per_min || 0);
  document.getElementById('kpi-cost-hr').textContent = '$' + (sys.velocity_5m?.cost_per_hour || '0.00');
  document.getElementById('total-cpu').textContent = sys.total_cpu || '0';
  document.getElementById('total-mem').textContent = sys.total_mem_mb || 0;

  // Process list with inline kill/pause controls
  const procList = document.getElementById('processes-list');
  document.getElementById('proc-count-badge').textContent = sys.process_count || 0;
  if (!sys.processes || sys.processes.length === 0) {
    procList.innerHTML = '<div class="empty-state">No agent processes running</div>';
  } else {
    procList.innerHTML = sys.processes.slice(0, 20).map(p => `
      <div class="process-card ${p.name}">
        <span class="proc-name">${p.name}</span>
        <span class="proc-pid">${p.pid}</span>
        <span class="proc-cpu">${p.cpu.toFixed(1)}%</span>
        <span class="proc-mem">${p.mem_mb}MB</span>
        <span class="proc-time">${p.elapsed}</span>
        <span class="proc-cmd" title="${p.cmd}">${p.cmd}</span>
        <span class="proc-actions">
          <button class="btn-xs" onclick="pausePid(${p.pid})" title="Pause (SIGSTOP)">⏸</button>
          <button class="btn-xs btn-xs-kill" onclick="killPid(${p.pid})" title="Kill (SIGKILL)">✕</button>
        </span>
      </div>
    `).join('');
  }
}

function renderTrend(trend) {
  const bars = document.getElementById('trend-bars');
  const days = trend.days || [];
  if (days.length === 0) {
    bars.innerHTML = '<div class="empty-state" style="width:100%">No data yet</div>';
    return;
  }
  const max = Math.max(...days.map(d => d.msgs || 0));
  bars.innerHTML = days.map(d => {
    const h = max > 0 ? Math.max(4, (d.msgs / max) * 100) : 4;
    const label = d.day.slice(5); // MM-DD
    return `
      <div class="trend-bar" style="height: ${h}%" title="${d.day}: ${d.msgs} msgs, ${formatTokens(d.tokens)} tokens">
        <div class="trend-bar-value">${d.msgs}</div>
        <div class="trend-bar-label">${label}</div>
      </div>
    `;
  }).join('');
}

function renderMaxPlan(data) {
  const w5h = data.window_5h;
  const wk = data.window_weekly;

  // 5h window
  document.getElementById('w5h-msg-used').textContent = w5h.messages_used;
  document.getElementById('w5h-msg-limit').textContent = w5h.messages_limit;
  document.getElementById('w5h-tokens').textContent = formatTokens(w5h.tokens_used) + ' / ' + formatTokens(w5h.tokens_limit) + ' tokens';
  document.getElementById('w5h-percent').textContent = w5h.percent.toFixed(0) + '%';
  document.getElementById('w5h-reset').textContent = formatDuration(w5h.time_to_reset_s);
  const w5hBar = document.getElementById('w5h-bar');
  w5hBar.style.width = Math.min(100, w5h.percent) + '%';
  w5hBar.className = 'budget-bar' + (w5h.percent >= 90 ? ' danger' : w5h.percent >= 70 ? ' warning' : '');
  document.getElementById('window-5h-card').style.borderColor = w5h.percent >= 90 ? '#ef4444' : w5h.percent >= 80 ? '#f59e0b' : '';

  // Weekly
  document.getElementById('wk-msg-used').textContent = wk.messages_used;
  document.getElementById('wk-msg-limit').textContent = wk.messages_limit;
  document.getElementById('wk-tokens').textContent = formatTokens(wk.tokens_used) + ' / ' + formatTokens(wk.tokens_limit) + ' tokens';
  document.getElementById('wk-percent').textContent = wk.percent.toFixed(0) + '%';
  const wkBar = document.getElementById('wk-bar');
  wkBar.style.width = Math.min(100, wk.percent) + '%';
  wkBar.className = 'budget-bar' + (wk.percent >= 90 ? ' danger' : wk.percent >= 70 ? ' warning' : '');
  document.getElementById('window-weekly-card').style.borderColor = wk.percent >= 90 ? '#ef4444' : wk.percent >= 80 ? '#f59e0b' : '';
}

function renderApiPlan(data) {
  for (const period of ['daily', 'weekly', 'monthly']) {
    const b = data[period];
    if (!b) continue;
    document.getElementById(`${period}-spent`).textContent = `$${b.spent_usd.toFixed(2)}`;
    document.getElementById(`${period}-limit`).textContent = `$${b.limit_usd}`;
    document.getElementById(`${period}-percent`).textContent = `${b.percent.toFixed(0)}%`;
    const bar = document.getElementById(`${period}-bar`);
    bar.style.width = `${Math.min(100, b.percent)}%`;
    bar.className = 'budget-bar' + (b.percent >= 90 ? ' danger' : b.percent >= 70 ? ' warning' : '');
  }
}

const VALVE_EMOJI = { OPEN:'🟢', THROTTLED:'🟡', CRACKED:'🟠', CLOSED:'🔴', LOCKED:'🛑' };
let valveCache = {};

const PERM_NAMES = [
  'READ','WRITE','EXEC','SPAWN','NET','DB_W','DB_R','DB_SCH',
  'FS_C','FS_D','SVC','SECRET','CFG_W','GIT_W','EXT_API','PRIV',
  'POL_ADM','MASK_ADM','AUD_W','CROSS','PROD',
];

function renderPermDiff(valve) {
  if (!valve) return '';
  const dec = valve.declared_perm_mask;
  const eff = valve.effective_perm_mask;
  const decHex = `0x${dec.toString(16)}`;
  const effHex = `0x${eff.toString(16)}`;
  if (dec === eff) return `<span class="perm-ok" title="perm_mask">${effHex}</span>`;
  const clearedBits = dec & ~eff;
  const clearedNames = PERM_NAMES.filter((_, i) => clearedBits & (1 << i)).join(',');
  return `<span class="perm-narrowed" title="declared ${decHex} → effective ${effHex} | cleared: ${clearedNames}">${decHex}<span class="perm-arrow">→</span><span class="perm-eff">${effHex}</span></span>`;
}

async function loadValves() {
  try {
    const r = await fetch('/api/v2/valves');
    const valves = await r.json();
    valveCache = {};
    for (const v of (Array.isArray(valves) ? valves : [])) valveCache[v.agent_id] = v;
  } catch { /* best-effort */ }
}

async function valveAction(agentId, action) {
  if (!confirm(`${action.toUpperCase()} valve for agent ${agentId.slice(0,8)}?`)) return;
  await fetch(`/api/v2/valve/${encodeURIComponent(agentId)}/${action}`, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ reason: 'dashboard action', by: 'operator' })
  });
  await loadValves();
  refreshDashboard();
}

function renderSessions(sessions, isMax) {
  const list = document.getElementById('sessions-list');
  document.getElementById('session-count').textContent = sessions.length;
  document.getElementById('kpi-sessions').textContent = sessions.length;
  if (sessions.length === 0) {
    list.innerHTML = '<div class="empty-state">No active sessions</div>';
    return;
  }
  list.innerHTML = sessions.map(s => {
    const costDisplay = isMax
      ? `${s.message_count} msgs`
      : `$${s.total_cost_usd.toFixed(2)}`;
    const valve = valveCache[s.session_id];
    const valveEmoji = valve ? (VALVE_EMOJI[valve.state] || '⚪') : '⚪';
    const valveState = valve ? valve.state : '';
    const permDiff = renderPermDiff(valve);
    const sid = s.session_id;
    let valveCtls = '';
    if (valve) {
      if (valve.state === 'OPEN') {
        valveCtls = `
          <button class="btn-xs" onclick="valveAction('${sid}','throttle')" title="Throttle — restricts spawn">⬇ THROTTLE</button>
          <button class="btn-xs btn-xs-kill" onclick="valveAction('${sid}','close')" title="Close — blocks all ops">✕ CLOSE</button>`;
      } else if (valve.state === 'THROTTLED' || valve.state === 'CRACKED') {
        valveCtls = `
          <button class="btn-xs" onclick="valveAction('${sid}','open')" title="Restore full access">↑ OPEN</button>
          <button class="btn-xs btn-xs-kill" onclick="valveAction('${sid}','close')" title="Close — blocks all ops">✕ CLOSE</button>`;
      } else if (valve.state === 'CLOSED' || valve.state === 'LOCKED') {
        valveCtls = `<button class="btn-xs" onclick="valveAction('${sid}','open')" title="Reopen session">↑ OPEN</button>`;
      }
    }
    return `
    <div class="session-card">
      <span class="session-id">${sid.slice(0, 8)}</span>
      <span class="session-cost">${costDisplay}</span>
      <span class="session-meta">${s.agent_spawns} spawns</span>
      ${valveState ? `<span class="session-meta">${valveEmoji} ${valveState} ${permDiff}</span>` : ''}
      <span class="session-valve-ctls">${valveCtls}</span>
      <span class="session-status ${s.status}">${s.status}</span>
    </div>`;
  }).join('');
}

function renderAlerts(alerts) {
  const list = document.getElementById('alerts-list');
  if (alerts.length === 0) {
    list.innerHTML = '<div class="empty-state">No alerts</div>';
    return;
  }
  list.innerHTML = alerts.map(a => `
    <div class="alert-item ${a.severity}">
      <span class="alert-time">${a.timestamp.slice(11, 19)}</span>
      <span class="alert-badge ${a.severity}">${a.severity}</span>
      <span>${a.message}</span>
    </div>
  `).join('');
}

// --- Enforce Mode Toggle ---

async function loadEnforceState() {
  try {
    const res = await fetch(`${API}/api/enforcement`);
    const data = await res.json();
    const isEnforce = data.mode === 'enforce';
    document.getElementById('enforce-toggle').checked = isEnforce;
    updateEnforceBadge(isEnforce);
  } catch {}
}

function updateEnforceBadge(isEnforce) {
  const badge = document.getElementById('enforce-status');
  if (isEnforce) {
    badge.textContent = 'ON — Hard Stop Active';
    badge.className = 'enforce-badge on';
  } else {
    badge.textContent = 'OFF — Alert Only';
    badge.className = 'enforce-badge off';
  }
}

async function toggleEnforce(checked) {
  const mode = checked ? 'enforce' : 'alert';
  if (checked) {
    if (!confirm('Enable Enforce Mode?\n\nWhen ON: AEGIS will send SIGSTOP to ALL agent processes when budget is exhausted. Agents will be paused until you resume them.\n\nRecommended: only enable when you want hard budget control.')) {
      document.getElementById('enforce-toggle').checked = false;
      return;
    }
  }
  try {
    await fetch(`${API}/api/enforcement`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
    updateEnforceBadge(checked);
  } catch (e) {
    alert('Failed to update enforcement mode');
  }
}

async function pauseAll() {
  if (!confirm('Pause all agent processes? (SIGSTOP — resumable)')) return;
  const res = await fetch(`${API}/api/kill`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ signal: 'SIGSTOP' }),
  });
  const data = await res.json();
  alert(`Paused ${data.killed} processes`);
  fetchStatus();
}

async function killAll() {
  if (!confirm('KILL all agent processes? (SIGKILL — cannot be undone)')) return;
  const res = await fetch(`${API}/api/kill`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ signal: 'SIGKILL' }),
  });
  const data = await res.json();
  alert(`Killed ${data.killed} processes`);
  fetchStatus();
}

async function resumeAll() {
  const res = await fetch(`${API}/api/resume`, { method: 'POST' });
  const data = await res.json();
  alert(`Resumed ${data.resumed} processes`);
  fetchStatus();
}

async function killPid(pid) {
  if (!confirm(`KILL process ${pid}? (SIGKILL — cannot be undone)`)) return;
  await fetch(`${API}/api/signal/${pid}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ signal: 'SIGKILL' }),
  });
  fetchStatus();
}

async function pausePid(pid) {
  await fetch(`${API}/api/signal/${pid}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ signal: 'SIGSTOP' }),
  });
  fetchStatus();
}

async function resumePid(pid) {
  await fetch(`${API}/api/signal/${pid}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ signal: 'SIGCONT' }),
  });
  fetchStatus();
}

function connectSSE() {
  const dot = document.getElementById('connection-status');
  const es = new EventSource(`${API}/api/events`);
  es.onopen = () => { dot.className = 'status-dot connected'; };
  es.addEventListener('status', fetchStatus);
  es.addEventListener('usage_update', fetchStatus);
  es.addEventListener('alert', fetchStatus);
  es.onerror = () => { dot.className = 'status-dot disconnected'; };
}

function startClock() {
  function tick() {
    const now = new Date();
    const time = now.toTimeString().slice(0, 8);
    const date = now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
    const el = document.getElementById('header-clock');
    if (el) el.textContent = `${date} ${time}`;
  }
  tick();
  setInterval(tick, 1000);
}

startClock();
fetchStatus();
connectSSE();
loadEnforceState();
setInterval(fetchStatus, 10000);

// KAVACH Approvals Panel
const LEVEL_LABELS = { 1: 'L1 Recoverable', 2: 'L2 Hard to Recover', 3: 'L3 Irreversible', 4: 'L4 CRITICAL' };
const LEVEL_EMOJI  = { 1: '⚠️', 2: '🔴', 3: '🚨', 4: '🛑' };

async function fetchApprovals() {
  try {
    const res = await fetch(`${API}/api/approvals`);
    const data = await res.json();
    renderApprovals(data.pending || []);
  } catch {}
}

function renderApprovals(pending) {
  const list = document.getElementById('kavach-list');
  const badge = document.getElementById('kavach-count');
  if (!pending.length) {
    list.innerHTML = '<div class="empty-state">No pending approvals</div>';
    badge.style.display = 'none';
    return;
  }
  badge.textContent = pending.length;
  badge.style.display = 'inline';
  list.innerHTML = pending.map(a => {
    const lvl = a.level;
    const elapsed = Math.floor((Date.now() - new Date(a.created_at).getTime()) / 1000);
    const remaining = Math.max(0, Math.floor(a.timeout_ms / 1000) - elapsed);
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    const timerStr = remaining > 0 ? `${mins}:${secs.toString().padStart(2,'0')} remaining` : 'EXPIRED';
    const isDualControl = a.status === 'pending_second';
    const dualBadge = isDualControl
      ? `<span class="kavach-dual-badge">🔐 AWAITING 2ND APPROVAL — 1st: ${escHtml(a.first_approver || '?')}</span>`
      : '';
    const explainBtn = !isDualControl
      ? `<button class="kavach-btn explain" onclick="decide('${a.id}','EXPLAIN')">💬 EXPLAIN</button>`
      : '';
    return `
      <div class="kavach-card level-${lvl}${isDualControl ? ' dual-control' : ''}" id="kavach-${a.id}">
        <div class="kavach-header">
          <span class="kavach-level l${lvl}">${LEVEL_EMOJI[lvl]} ${LEVEL_LABELS[lvl]}</span>
          <span class="kavach-timer">${timerStr}</span>
          <span class="kavach-id">${a.id}</span>
        </div>
        ${dualBadge}
        <div class="kavach-command">${escHtml(a.command)}</div>
        <div class="kavach-consequence">${escHtml(a.consequence)}</div>
        <div class="kavach-actions">
          <button class="kavach-btn stop"  onclick="decide('${a.id}','STOP')">🛑 STOP</button>
          <button class="kavach-btn allow" onclick="decide('${a.id}','ALLOW')">✅ ${isDualControl ? '2ND ALLOW' : 'ALLOW'}</button>
          ${explainBtn}
        </div>
      </div>`;
  }).join('');
}

async function decide(id, decision) {
  const card = document.getElementById(`kavach-${id}`);
  if (card) card.style.opacity = '0.5';
  try {
    await fetch(`${API}/api/approvals/${id}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision }),
    });
    setTimeout(fetchApprovals, 500);
  } catch {
    if (card) card.style.opacity = '1';
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

fetchApprovals();
setInterval(fetchApprovals, 3000);  // poll every 3s for new approvals

// Cost Attribution Tree
const STATE_COLOR = { RUNNING:'var(--green)', COMPLETED:'var(--text-dim)', QUARANTINED:'var(--red)', FORCE_CLOSED:'var(--red)', ZOMBIE:'var(--amber)', ORPHAN:'#fb923c', REGISTERED:'var(--blue)' };

async function fetchCostTree() {
  try {
    const res = await fetch(`${API}/api/v1/cost-tree`);
    const data = await res.json();
    renderCostTree(data.tree || []);
  } catch {}
}

function renderCostNode(node, depth) {
  const pct = node.budget_cap_usd > 0 ? Math.min(100, (node.budget_used_usd / node.budget_cap_usd) * 100) : 0;
  const barClass = pct >= 90 ? 'danger' : pct >= 70 ? 'warning' : '';
  const stateColor = STATE_COLOR[node.state] || 'var(--text-dim)';
  const indent = depth * 20;
  const childRows = (node.children || []).map(c => renderCostNode(c, depth + 1)).join('');
  return `
    <div class="ct-node" style="margin-left:${indent}px">
      <div class="ct-header">
        ${depth > 0 ? '<span class="ct-branch">└─</span>' : ''}
        <span class="ct-id" title="${node.agent_id}">${node.agent_id.slice(0,8)}</span>
        <span class="ct-state" style="color:${stateColor}">${node.state}</span>
        <span class="ct-depth">d${node.depth}</span>
        <span class="ct-tools">${node.tool_calls} calls</span>
        ${node.violation_count > 0 ? `<span class="ct-violations">${node.violation_count} violations</span>` : ''}
        <span class="ct-budget-text">$${node.budget_used_usd.toFixed(3)} / $${node.budget_cap_usd.toFixed(2)}</span>
      </div>
      <div class="ct-bar-wrap">
        <div class="ct-bar budget-bar ${barClass}" style="width:${pct}%"></div>
      </div>
      ${childRows}
    </div>`;
}

function renderCostTree(roots) {
  const container = document.getElementById('cost-tree-container');
  const badge = document.getElementById('cost-tree-badge');
  const total = countNodes(roots);
  badge.textContent = total;
  if (!roots.length) {
    container.innerHTML = '<div class="empty-state">No agents tracked yet</div>';
    return;
  }
  container.innerHTML = roots.map(r => renderCostNode(r, 0)).join('');
}

function countNodes(nodes) {
  return nodes.reduce((acc, n) => acc + 1 + countNodes(n.children || []), 0);
}

fetchCostTree();
setInterval(fetchCostTree, 15000);

// Background Agents Panel (@rule:KOS-T095)
async function fetchBgAgents() {
  try {
    const res = await fetch(`${API}/api/bg-agents?hours=24`);
    const agents = await res.json();
    renderBgAgents(Array.isArray(agents) ? agents : []);
  } catch {}
}

function renderBgAgents(agents) {
  const list = document.getElementById('bg-agents-list');
  const badge = document.getElementById('bg-agents-badge');
  const running = agents.filter(a => a.status === 'running');
  if (running.length > 0) {
    badge.textContent = running.length + ' running';
    badge.style.display = '';
    badge.style.background = 'var(--amber)';
    badge.style.color = '#000';
  } else if (agents.length > 0) {
    badge.textContent = agents.length + ' total';
    badge.style.display = '';
    badge.style.background = 'var(--muted, #64748b)';
    badge.style.color = '#fff';
  } else {
    badge.style.display = 'none';
  }
  if (!agents.length) {
    list.innerHTML = '<div class="empty-state">No background agents in last 24h</div>';
    return;
  }
  list.innerHTML = agents.map(a => {
    const age = Math.round((Date.now() - new Date(a.spawned_at).getTime()) / 60000);
    const statusColor = a.status === 'running' ? 'var(--amber)' : a.status === 'completed' ? 'var(--green)' : 'var(--muted,#64748b)';
    const desc = a.description || a.subagent_type || 'unnamed';
    const taskLabel = a.task_id ? `<span style="color:var(--muted,#64748b);font-size:10px">${a.task_id.slice(0,12)}</span>` : '';
    const doneLabel = a.completed_at ? ` → done in ${Math.round((new Date(a.completed_at).getTime() - new Date(a.spawned_at).getTime()) / 60000)}m` : '';
    return `<div class="approval-card" style="border-left:3px solid ${statusColor}">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="font-weight:600">${desc}</span>
        <span style="color:${statusColor};font-size:11px;text-transform:uppercase">${a.status}</span>
      </div>
      <div style="color:var(--muted,#64748b);font-size:11px;margin-top:4px">
        spawned ${age}m ago${doneLabel} ${taskLabel}
      </div>
    </div>`;
  }).join('');
}

fetchBgAgents();
setInterval(fetchBgAgents, 5000);
