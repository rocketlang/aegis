#!/usr/bin/env bun
// AEGIS Dashboard — Fastify server with real-time SSE

import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCors from "@fastify/cors";
import { join } from "path";
import { loadConfig, saveConfig } from "../core/config";
import { getBudgetState, listActiveSessions, getRecentAlerts, setSessionStatus, addAlert, getWindowBudget } from "../core/db";
import { sseSubscribers } from "../core/events";
import { registerSystemRoutes } from "./routes/system";

const config = loadConfig();
const app = Fastify({ logger: false });

app.register(fastifyCors, { origin: true });

// Basic Auth — enabled when config.dashboard.auth.enabled = true
// Covers all routes including static files and API
if (config.dashboard.auth?.enabled) {
  const { username, password } = config.dashboard.auth;
  const expected = "Basic " + Buffer.from(`${username}:${password}`).toString("base64");

  app.addHook("onRequest", async (req, reply) => {
    // Allow health + commands without auth (read-only, no sensitive data)
    if (req.url === "/health" || req.url === "/commands") return;
    const auth = req.headers["authorization"];
    if (auth !== expected) {
      reply.header("WWW-Authenticate", 'Basic realm="AEGIS"');
      reply.code(401).send("Unauthorized");
    }
  });
}

// Simple health check (no auth)
app.get("/health", async () => ({ status: "ok", service: "aegis-dashboard" }));

app.register(fastifyStatic, {
  root: join(import.meta.dir, "static"),
  prefix: "/",
});
registerSystemRoutes(app);

// --- API Routes ---

app.get("/api/status", async () => {
  const isMaxPlan = config.plan && config.plan.startsWith("max");
  return {
    plan: config.plan,
    is_max_plan: isMaxPlan,
    // Always return both views — dashboard picks based on plan
    window_5h: getWindowBudget("5h", config.budget.messages_per_5h, config.budget.tokens_per_5h),
    window_weekly: getWindowBudget("weekly", config.budget.weekly_messages, config.budget.weekly_tokens),
    daily: getBudgetState("daily", config.budget.daily_limit_usd),
    weekly: getBudgetState("weekly", config.budget.weekly_limit_usd),
    monthly: getBudgetState("monthly", config.budget.monthly_limit_usd),
    sessions: listActiveSessions(),
    alerts: getRecentAlerts(10),
    config: {
      daily_limit: config.budget.daily_limit_usd,
      weekly_limit: config.budget.weekly_limit_usd,
      session_limit: config.budget.session_limit_usd,
      spawn_limit: config.budget.spawn_limit_per_session,
      messages_per_5h: config.budget.messages_per_5h,
      weekly_messages: config.budget.weekly_messages,
    },
  };
});

app.get("/api/sessions", async () => {
  return listActiveSessions();
});

app.get("/api/alerts", async (req) => {
  const limit = (req.query as any).limit ? parseInt((req.query as any).limit) : 50;
  return getRecentAlerts(limit);
});

app.post("/api/kill", async (req) => {
  const body = req.body as any;
  const signal = body?.signal === "SIGSTOP" ? 19 : 9;
  const label = signal === 19 ? "SIGSTOP" : "SIGKILL";

  const result = Bun.spawnSync(["pgrep", "-f", "claude"]);
  const pids = result.stdout.toString().trim().split("\n").filter(Boolean);
  let killed = 0;

  for (const pidStr of pids) {
    const pid = parseInt(pidStr);
    if (isNaN(pid)) continue;
    try {
      process.kill(pid, signal);
      killed++;
    } catch { /* */ }
  }

  for (const s of listActiveSessions()) {
    setSessionStatus(s.session_id, signal === 19 ? "paused" : "killed");
  }

  addAlert({
    type: "kill",
    severity: "critical",
    message: `Dashboard ${label}: ${killed} processes`,
    timestamp: new Date().toISOString(),
  });

  return { success: true, killed, signal: label };
});

app.post("/api/resume", async () => {
  const result = Bun.spawnSync(["pgrep", "-f", "claude"]);
  const pids = result.stdout.toString().trim().split("\n").filter(Boolean);
  let resumed = 0;

  for (const pidStr of pids) {
    const pid = parseInt(pidStr);
    if (isNaN(pid)) continue;
    try {
      process.kill(pid, 18); // SIGCONT
      resumed++;
    } catch { /* */ }
  }

  for (const s of listActiveSessions()) {
    setSessionStatus(s.session_id, "active");
  }

  return { success: true, resumed };
});

// --- Enforcement mode toggle ---
app.get("/api/enforcement", async () => {
  const cfg = loadConfig();
  return { mode: cfg.enforcement?.mode || "alert" };
});

app.post("/api/enforcement", async (req) => {
  const body = req.body as any;
  const mode = body?.mode === "enforce" ? "enforce" : "alert";
  const cfg = loadConfig();
  cfg.enforcement = { ...cfg.enforcement, mode };
  saveConfig(cfg);
  return { success: true, mode };
});

// --- SSE for real-time updates ---
app.get("/api/events", async (req, reply) => {
  reply.raw.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  const send = (event: string, data: any) => {
    reply.raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  sseSubscribers.add(send);

  // Send initial state
  send("connected", { timestamp: new Date().toISOString() });

  // Periodic status push (every 5s)
  const interval = setInterval(() => {
    send("status", {
      daily: getBudgetState("daily", config.budget.daily_limit_usd),
      weekly: getBudgetState("weekly", config.budget.weekly_limit_usd),
      sessions: listActiveSessions().length,
    });
  }, 5000);

  req.raw.on("close", () => {
    sseSubscribers.delete(send);
    clearInterval(interval);
  });
});

// Start
// ── GET /commands — command reference page ────────────────────────────────────
app.get("/commands", async (_req, reply) => {
  const cfg = loadConfig();
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS Command Reference</title>
<style>
  :root{--bg:#0a0e1a;--card:#0f1629;--border:#1e2d4a;--text:#e2e8f0;--muted:#64748b;--blue:#38bdf8;--green:#34d399;--amber:#fbbf24;--red:#f87171;--purple:#a78bfa;--teal:#2dd4bf;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:'SF Mono',Consolas,monospace;font-size:13px;padding:24px;}
  h1{color:var(--blue);font-size:20px;margin-bottom:4px;}
  .sub{color:var(--muted);font-size:11px;margin-bottom:24px;}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;}
  .enforce{background:rgba(248,113,113,.15);color:var(--red);border:1px solid rgba(248,113,113,.3);}
  .alert{background:rgba(251,191,36,.1);color:var(--amber);border:1px solid rgba(251,191,36,.25);}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:16px;margin-bottom:24px;}
  .card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;}
  .card-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px;}
  table{width:100%;border-collapse:collapse;}
  td{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:top;}
  td:first-child{color:var(--blue);white-space:nowrap;width:1%;}
  tr:last-child td{border-bottom:none;}
  .comment{color:var(--muted);}
  .sep{height:1px;background:var(--border);margin:20px 0;}
  .kill-box{background:rgba(248,113,113,.06);border:1px solid rgba(248,113,113,.2);border-radius:8px;padding:14px;margin-bottom:16px;}
  .kill-title{color:var(--red);font-weight:700;font-size:11px;text-transform:uppercase;margin-bottom:8px;}
  .restart-box{background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.2);border-radius:8px;padding:14px;}
  .restart-title{color:var(--green);font-weight:700;font-size:11px;text-transform:uppercase;margin-bottom:8px;}
</style>
</head>
<body>
<h1>⚡ AEGIS — Command Reference</h1>
<div class="sub">Agentic Spend Governance · enforcement: <span class="badge ${cfg.enforcement.mode}">${cfg.enforcement.mode}</span> · kill_on_burst: ${cfg.enforcement.mode === "enforce" ? "<span style='color:var(--red)'>ON</span>" : "<span style='color:var(--muted)'>off</span>"}</div>

<div class="kill-box">
  <div class="kill-title">🔴 After Budget Kill — Recovery</div>
  <table>
    <tr><td>recover</td><td>Restart core infra (alias)</td></tr>
    <tr><td>nhi-up</td><td>agent-registry + ai-proxy + aegis + event-bus</td></tr>
    <tr><td>ankr-ctl status</td><td>See what's down</td></tr>
    <tr><td>acs</td><td>Short: ankr-ctl status</td></tr>
    <tr><td>aegis-status</td><td>Check enforcement mode + auto-restart list</td></tr>
  </table>
</div>

<div class="restart-box">
  <div class="restart-title">✅ Auto-Restart (configured)</div>
  <table>
    ${cfg.enforcement.auto_restart_services?.map(s => `<tr><td style="color:var(--green)">${s}</td><td>auto-restarted after kill (${cfg.enforcement.auto_restart_delay_ms ?? 3000}ms delay)</td></tr>`).join("") ?? ""}
  </table>
</div>

<div class="sep"></div>

<div class="grid">
  <div class="card">
    <div class="card-title" style="color:var(--blue)">ankr-ctl Short Aliases</div>
    <table>
      <tr><td>ac</td><td>ankr-ctl</td></tr>
      <tr><td>acs</td><td>ankr-ctl status</td></tr>
      <tr><td>acr &lt;svc&gt;</td><td>ankr-ctl restart &lt;svc&gt;</td></tr>
      <tr><td>astart &lt;svc&gt;</td><td>ankr-ctl start &lt;svc&gt;</td></tr>
      <tr><td>astop &lt;svc&gt;</td><td>ankr-ctl stop &lt;svc&gt;</td></tr>
      <tr><td>alogs &lt;svc&gt;</td><td>ankr-ctl logs &lt;svc&gt;</td></tr>
      <tr><td>ahealth</td><td>ankr-ctl health</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--purple)">Stack Aliases (fire full stack)</div>
    <table>
      <tr><td>mari8x</td><td>ankr-ctl activate mari8x</td></tr>
      <tr><td>ankr-core</td><td>ai-proxy → eon-api → ai360-gateway</td></tr>
      <tr><td>xshield</td><td>ai-proxy → ankrshield-api</td></tr>
      <tr><td>complymitra</td><td>compliance stack</td></tr>
      <tr><td>officers</td><td>all AI360 officer services</td></tr>
      <tr><td>super</td><td>supergraph + superdomain + stackpilot</td></tr>
      <tr><td>anvil</td><td>anvil-backend + router + ui</td></tr>
      <tr><td>herald</td><td>ai360-gateway + herald-telehub</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--teal)">NHI Agent Lifecycle</div>
    <table>
      <tr><td>nhi-up</td><td>Start core NHI infra</td></tr>
      <tr><td>nhi-status</td><td>Registry + AEGIS status</td></tr>
      <tr><td colspan="2" class="comment" style="padding-top:8px">Registry API (port 4586):</td></tr>
      <tr><td style="font-size:11px">GET /api/v2/agents</td><td>List active agents</td></tr>
      <tr><td style="font-size:11px">GET /api/v2/agents/orphans</td><td>Orphan scan</td></tr>
      <tr><td style="font-size:11px">POST /agents/:id/sleep</td><td>Sleep agent</td></tr>
      <tr><td style="font-size:11px">POST /agents/:id/revoke</td><td>Hard revoke (trust_mask=0)</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--amber)">AEGIS API (port 4850)</div>
    <table>
      <tr><td style="font-size:11px">GET /api/status</td><td>Budget state</td></tr>
      <tr><td style="font-size:11px">GET /api/sessions</td><td>Active sessions</td></tr>
      <tr><td style="font-size:11px">GET /api/alerts</td><td>Recent alerts</td></tr>
      <tr><td style="font-size:11px">POST /api/kill</td><td>Manual kill</td></tr>
      <tr><td style="font-size:11px">POST /api/enforcement</td><td>Toggle enforce/alert mode</td></tr>
      <tr><td style="font-size:11px">GET /commands</td><td>This page</td></tr>
      <tr><td colspan="2" class="comment" style="padding-top:8px">Monitor (port 4851):</td></tr>
      <tr><td style="font-size:11px">GET /health</td><td>Enforcement mode + auto-restart list</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--green)">ankr-ctl Key Commands</div>
    <table>
      <tr><td>ankr-ctl activate &lt;stack&gt;</td><td>Start full stack with deps</td></tr>
      <tr><td>ankr-ctl activate --list</td><td>Show all named stacks</td></tr>
      <tr><td>ankr-ctl always-on</td><td>Check + restart always-on services</td></tr>
      <tr><td>ankr-ctl doctor</td><td>Full system health check</td></tr>
      <tr><td>ankr-ctl resurrect</td><td>Restore from last save snapshot</td></tr>
      <tr><td>ankr-ctl save</td><td>Snapshot running services</td></tr>
      <tr><td>ankr-ctl scan secrets</td><td>Scan for plaintext credentials</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--red)">Budget Thresholds</div>
    <table>
      <tr><td>Daily limit</td><td>$${cfg.budget.daily_limit_usd}</td></tr>
      <tr><td>Weekly limit</td><td>$${cfg.budget.weekly_limit_usd}</td></tr>
      <tr><td>Session limit</td><td>$${cfg.budget.session_limit_usd}</td></tr>
      <tr><td>Burst trigger</td><td>3× rolling average above $0.10</td></tr>
      <tr><td>Spawn limit</td><td>${cfg.budget.spawn_limit_per_session} agents/session</td></tr>
      <tr><td>On breach</td><td><span class="badge ${cfg.enforcement.mode}">${cfg.enforcement.mode === "enforce" ? "SIGKILL all claude + subagents" : "alert only"}</span></td></tr>
    </table>
  </div>
</div>

<div style="color:var(--muted);font-size:10px;text-align:center;margin-top:8px">
  AEGIS · ankr.in/aegis · aegis.ankr.in · Jai Guru Ji | PowerBox IT Solutions Pvt Ltd
</div>
</body></html>`;
  return reply.type("text/html").send(html);
});

app.listen({ port: config.dashboard.port, host: "0.0.0.0" }, (err, address) => {
  if (err) {
    console.error("Dashboard failed to start:", err);
    process.exit(1);
  }
  console.log(`[AEGIS] Dashboard: ${address}`);
});
