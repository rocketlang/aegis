// AEGIS Dashboard — Client-side (Max Plan + API Plan)

const API = '';

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
    const [statusRes, sysRes, providersRes, trendRes] = await Promise.all([
      fetch(`${API}/api/status`),
      fetch(`${API}/api/system`),
      fetch(`${API}/api/providers`),
      fetch(`${API}/api/trend`),
    ]);
    const data = await statusRes.json();
    const sys = await sysRes.json();
    const providers = await providersRes.json();
    const trend = await trendRes.json();

    document.getElementById('plan-badge').textContent = data.plan || 'api';

    const isMax = data.is_max_plan;
    document.getElementById('maxplan-view').style.display = isMax ? '' : 'none';
    document.getElementById('apiplan-view').style.display = isMax ? 'none' : '';

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
  document.getElementById('process-count').textContent = sys.process_count || 0;
  document.getElementById('total-cpu').textContent = sys.total_cpu || '0';
  document.getElementById('total-mem').textContent = sys.total_mem_mb || 0;
  document.getElementById('tokens-per-min').textContent = formatTokens(sys.velocity_5m?.tokens_per_min || 0);
  document.getElementById('msgs-per-min').textContent = sys.velocity_5m?.messages ? (sys.velocity_5m.messages / 5).toFixed(1) : '0';
  document.getElementById('cost-per-hour').textContent = '$' + (sys.velocity_5m?.cost_per_hour || '0.00');

  const p = providers.providers || {};
  document.getElementById('provider-claude').textContent = p['claude-code']?.sessions || 0;
  document.getElementById('provider-codex').textContent = p['openai-codex']?.sessions || 0;

  // Process list
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

function renderSessions(sessions, isMax) {
  const list = document.getElementById('sessions-list');
  document.getElementById('session-count').textContent = sessions.length;
  if (sessions.length === 0) {
    list.innerHTML = '<div class="empty-state">No active sessions</div>';
    return;
  }
  list.innerHTML = sessions.map(s => {
    const costDisplay = isMax
      ? `${s.message_count} msgs`
      : `$${s.total_cost_usd.toFixed(2)}`;
    return `
    <div class="session-card">
      <span class="session-id">${s.session_id.slice(0, 8)}</span>
      <span class="session-cost">${costDisplay}</span>
      <span class="session-meta">${s.agent_spawns} spawns</span>
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

function connectSSE() {
  const dot = document.getElementById('connection-status');
  const es = new EventSource(`${API}/api/events`);
  es.onopen = () => { dot.className = 'status-dot connected'; };
  es.addEventListener('status', fetchStatus);
  es.addEventListener('usage_update', fetchStatus);
  es.addEventListener('alert', fetchStatus);
  es.onerror = () => { dot.className = 'status-dot disconnected'; };
}

fetchStatus();
connectSSE();
setInterval(fetchStatus, 10000);
