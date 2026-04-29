#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
// AEGIS Dashboard — Fastify server with real-time SSE

import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCors from "@fastify/cors";
import { join } from "path";
import { loadConfig, saveConfig } from "../core/config";
import { getBudgetState, listActiveSessions, getRecentAlerts, setSessionStatus, addAlert, getWindowBudget, getPendingApprovals, decideKavachApproval, getRecentApprovals, recordAgentUsage, getCostTree, listAgentRows, recordDashboardAccess } from "../core/db";
import { sseSubscribers } from "../core/events";
import { registerSystemRoutes } from "./routes/system";
import { registerForjaRoutes, emitSense } from "./routes/forja";
import { listTenants, getTenantConfig, saveTenantConfig, deleteTenant, ensureTenant, extractTenantId } from "../core/tenant";

const config = loadConfig();
const app = Fastify({ logger: false });

app.register(fastifyCors, { origin: true });

// Basic Auth — enabled when config.dashboard.auth.enabled = true
// Covers all routes including static files and API
if (config.dashboard.auth?.enabled) {
  const { username, password } = config.dashboard.auth;
  const expected = "Basic " + Buffer.from(`${username}:${password}`).toString("base64");

  app.addHook("onRequest", async (req, reply) => {
    // Allow health, commands, and internal KAVACH routes without auth
    if (
      req.url === "/health" ||
      req.url === "/commands" ||
      req.url === "/api/approvals/webhook" ||
      (req.url === "/api/approvals" && req.method === "GET")
    ) return;
    const auth = req.headers["authorization"];
    if (auth !== expected) {
      reply.header("WWW-Authenticate", 'Basic realm="AEGIS"');
      reply.code(401).send("Unauthorized");
    }
  });
}

// @rule:KAV-066 — log every dashboard request IP for hosted-service detection (V2-101)
app.addHook("onRequest", async (req) => {
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
    || req.socket?.remoteAddress
    || "unknown";
  try { recordDashboardAccess(ip, req.url ?? ""); } catch { /* non-fatal */ }
});

// Simple health check (no auth)
app.get("/health", async () => ({ status: "ok", service: "aegis-dashboard" }));

app.register(fastifyStatic, {
  root: join(import.meta.dir, "static"),
  prefix: "/",
});
registerSystemRoutes(app);
registerForjaRoutes(app);

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

// --- V2-060: KAVACH Usage Ingest (from AI Proxy intercept) ---
app.post("/api/v1/agent-usage", async (req) => {
  const body = req.body as {
    agent_id: string;
    model: string;
    input_tokens: number;
    output_tokens: number;
    cache_read_tokens?: number;
    cache_creation_tokens?: number;
    cost_usd: number;
  };
  if (!body?.agent_id || typeof body.cost_usd !== "number") {
    return { ok: false, error: "agent_id and cost_usd required" };
  }
  try {
    recordAgentUsage({
      agent_id: body.agent_id,
      model: body.model || "unknown",
      input_tokens: body.input_tokens || 0,
      output_tokens: body.output_tokens || 0,
      cache_read_tokens: body.cache_read_tokens,
      cache_creation_tokens: body.cache_creation_tokens,
      cost_usd: body.cost_usd,
    });
    return { ok: true };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
});

// --- V2-066: Cost attribution tree ---
app.get("/api/v1/cost-tree", async (req) => {
  const sessionId = (req.query as any).session_id;
  return { tree: getCostTree(sessionId), agents: listAgentRows() };
});

// --- Gate Valve API (KAV-1C-010) ---
import {
  readValve, throttleValve, crackValve, closeValve, lockValve, openValve,
} from "../kavach/gate-valve";
import { existsSync, readdirSync, readFileSync } from "fs";
import { getAegisDir } from "../core/config";

function listValveFiles() {
  const dir = join(getAegisDir(), "agents");
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".valve.json"))
    .map((f) => {
      try { return JSON.parse(readFileSync(join(dir, f), "utf-8")); } catch { return null; }
    })
    .filter(Boolean);
}

app.get("/api/v2/valves", async () => listValveFiles());

app.get("/api/v2/valve/:agentId", async (req) => {
  const { agentId } = req.params as { agentId: string };
  return readValve(agentId);
});

app.post("/api/v2/valve/:agentId/:action", async (req) => {
  const { agentId, action } = req.params as { agentId: string; action: string };
  const body = (req.body as any) ?? {};
  const reason = body.reason ?? "dashboard action";
  const by = body.by ?? "dashboard";
  switch (action) {
    case "throttle": return throttleValve(agentId, reason);
    case "crack":    return crackValve(agentId, reason);
    case "close":    return closeValve(agentId, reason);
    case "lock":     return lockValve(agentId, reason, by);
    case "open": {
      try { return openValve(agentId, by); }
      catch (e: any) { return (req as any).server.httpErrors?.createBadRequest(e.message) ?? { error: e.message }; }
    }
    default:         return { error: `Unknown action: ${action}` };
  }
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

// --- KAVACH Approval Routes (@rule:KAV-052) ---

// List pending + recent approvals
app.get("/api/approvals", async () => {
  return {
    pending: getPendingApprovals(),
    recent: getRecentApprovals(10),
  };
});

// Dashboard STOP/ALLOW/EXPLAIN button
app.post("/api/approvals/:id/decide", async (req, reply) => {
  const { id } = req.params as { id: string };
  const { decision } = req.body as { decision?: string };
  const valid = ["ALLOW", "STOP", "EXPLAIN"];
  if (!valid.includes(decision ?? "")) {
    return reply.code(400).send({ error: "decision must be ALLOW, STOP, or EXPLAIN" });
  }
  const opts = { dual_control: config.kavach?.dual_control_enabled ?? false, require_different_approvers: config.kavach?.dual_control_require_different_approvers ?? false };
  const updated = decideKavachApproval(id, decision as any, "dashboard", opts);
  if (!updated) return reply.code(404).send({ error: "approval not found or already decided" });
  return { ok: true, id, decision };
});

// Webhook receiver — AnkrClaw calls this when user replies via WhatsApp (@rule:KAV-055)
app.post("/api/approvals/webhook", async (req, reply) => {
  const body = req.body as { approval_id?: string; decision?: string; from?: string };
  const { approval_id, decision, from } = body;
  if (!approval_id || !decision) {
    return reply.code(400).send({ error: "approval_id and decision required" });
  }
  const valid = ["ALLOW", "STOP", "EXPLAIN"];
  if (!valid.includes(decision.toUpperCase())) {
    return reply.send({ ok: false, reason: "not a KAVACH decision" });
  }
  const opts = { dual_control: config.kavach?.dual_control_enabled ?? false, require_different_approvers: config.kavach?.dual_control_require_different_approvers ?? false };
  const updated = decideKavachApproval(approval_id, decision.toUpperCase() as any, from ?? "webhook", opts);
  return { ok: updated, id: approval_id, decision: decision.toUpperCase() };
});

// --- [EE] Multi-Tenant API (@rule:KAV-071, KAV-072, KAV-073) ---

app.get("/api/v1/tenants", async () => ({ tenants: listTenants() }));

app.get("/api/v1/tenants/:id", async (req, reply) => {
  const { id } = req.params as { id: string };
  try { return getTenantConfig(id); }
  catch { return reply.code(404).send({ error: "tenant not found" }); }
});

app.post("/api/v1/tenants", async (req, reply) => {
  const body = req.body as { tenant_id?: string; display_name?: string } & Record<string, unknown>;
  const tid = (body?.tenant_id || "").replace(/[^a-zA-Z0-9\-_]/g, "").slice(0, 64);
  if (!tid) return reply.code(400).send({ error: "tenant_id required (alphanumeric, hyphen, underscore)" });
  const cfg = ensureTenant(tid);
  if (body.display_name) { cfg.display_name = String(body.display_name).slice(0, 100); saveTenantConfig(cfg); }
  return { ok: true, tenant: cfg };
});

app.put("/api/v1/tenants/:id", async (req, reply) => {
  const { id } = req.params as { id: string };
  const body = req.body as Partial<ReturnType<typeof getTenantConfig>>;
  try {
    const cfg = getTenantConfig(id);
    const updated = { ...cfg, ...body, tenant_id: id }; // prevent tenant_id override
    saveTenantConfig(updated);
    return { ok: true, tenant: updated };
  } catch { return reply.code(404).send({ error: "tenant not found" }); }
});

app.delete("/api/v1/tenants/:id", async (req, reply) => {
  const { id } = req.params as { id: string };
  const ok = deleteTenant(id);
  if (!ok) return reply.code(400).send({ error: "Cannot delete default tenant or tenant not found" });
  return { ok: true };
});

// [EE] PRAMANA receipts API (@rule:KAV-046)
import { listReceipts, verifyReceipt, getChainIntegrity } from "../kavach/pramana-receipts";

app.get("/api/v1/pramana/:sessionId/receipts", async (req) => {
  const { sessionId } = req.params as { sessionId: string };
  return { receipts: listReceipts(sessionId) };
});

app.get("/api/v1/pramana/:sessionId/integrity", async (req) => {
  const { sessionId } = req.params as { sessionId: string };
  return getChainIntegrity(sessionId);
});

app.post("/api/v1/pramana/verify", async (req, reply) => {
  const receipt = req.body as Parameters<typeof verifyReceipt>[0];
  if (!receipt?.receipt_id) return reply.code(400).send({ error: "receipt body required" });
  return verifyReceipt(receipt);
});

// [EE] HanumanG posture report API (@rule:KAV-015)
import { getSessionPosture } from "../shield/hanumang-ee";

app.get("/api/v1/hanumang/:sessionId/posture", async (req) => {
  const { sessionId } = req.params as { sessionId: string };
  const posture = getSessionPosture(sessionId);
  if (!posture) return { posture_level: "GREEN", score: 100, total_spawns: 0, message: "No spawn history for session" };
  return posture;
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
    <tr><td>aegis status</td><td>Check enforcement mode + budget state</td></tr>
    <tr><td>aegis-monitor &amp;</td><td>Restart monitor (if stopped)</td></tr>
    <tr><td>aegis-dashboard &amp;</td><td>Restart dashboard (if stopped)</td></tr>
    <tr><td>aegis resume</td><td>Resume paused session</td></tr>
  </table>
</div>

<div class="restart-box">
  <div class="restart-title">✅ Auto-Restart (configured)</div>
  <table>
    ${cfg.enforcement.auto_restart_services?.map(s => `<tr><td style="color:var(--green)">${s}</td><td>auto-restarted after kill (${cfg.enforcement.auto_restart_delay_ms ?? 3000}ms delay)</td></tr>`).join("") || "<tr><td colspan='2' class='comment'>None configured — add services to enforcement.auto_restart_services in config.json</td></tr>"}
  </table>
</div>

<div class="sep"></div>

<div class="grid">
  <div class="card">
    <div class="card-title" style="color:var(--blue)">AEGIS CLI Quick Reference</div>
    <table>
      <tr><td>aegis status</td><td>Budget + enforcement state</td></tr>
      <tr><td>aegis cost</td><td>Cost attribution tree</td></tr>
      <tr><td>aegis mask-log &lt;id&gt;</td><td>Gate valve history for agent</td></tr>
      <tr><td>aegis kill</td><td>Emergency SIGKILL</td></tr>
      <tr><td>aegis pause</td><td>SIGSTOP — pauses all processes</td></tr>
      <tr><td>aegis resume</td><td>Resume paused processes</td></tr>
      <tr><td>aegis register</td><td>Check in an agent</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--purple)">Quarantine Management</div>
    <table>
      <tr><td>aegis quarantine list</td><td>List quarantined / orphan agents</td></tr>
      <tr><td style="font-size:11px">aegis quarantine release &lt;id&gt; --reason "…"</td><td>Human release (logged)</td></tr>
      <tr><td>aegis restore-mask &lt;id&gt;</td><td>Restore narrowed permissions</td></tr>
      <tr><td>aegis close &lt;id&gt;</td><td>Check out agent (COMPLETED)</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--teal)">Agent Management</div>
    <table>
      <tr><td>aegis register</td><td>Check in: create policy, register agent</td></tr>
      <tr><td>aegis close &lt;id&gt;</td><td>Check out: COMPLETED + final manifest</td></tr>
      <tr><td>aegis resume &lt;id&gt;</td><td>Show resume manifest after force-close</td></tr>
      <tr><td style="font-size:11px">GET /api/v1/agents</td><td>List active agents (AEGIS API)</td></tr>
      <tr><td style="font-size:11px">GET /api/v1/agents/orphans</td><td>Orphan scan (AEGIS API)</td></tr>
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
    <div class="card-title" style="color:var(--green)">KAVACH DAN Gate</div>
    <table>
      <tr><td style="font-size:11px">GET /api/v1/kavach/approvals</td><td>Pending DAN approvals</td></tr>
      <tr><td style="font-size:11px">POST /api/v1/kavach/decide</td><td>ALLOW / STOP / EXPLAIN</td></tr>
      <tr><td style="font-size:11px">GET /api/v2/forja/state</td><td>Capability manifest + trust_mask</td></tr>
      <tr><td style="font-size:11px">GET /api/v2/forja/proof</td><td>Rule annotation coverage</td></tr>
      <tr><td colspan="2" class="comment" style="padding-top:8px">Config (~/.aegis/config.json):</td></tr>
      <tr><td style="font-size:11px">kavach.enabled</td><td>Toggle DAN gate on/off</td></tr>
      <tr><td style="font-size:11px">kavach.notify_channel</td><td>telegram | whatsapp</td></tr>
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
  AEGIS · github.com/rocketlang/aegis
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
