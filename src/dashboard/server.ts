#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
// AEGIS Dashboard — Fastify server with real-time SSE

import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCors from "@fastify/cors";
import fastifyFormbody from "@fastify/formbody";
import { join } from "path";
import { loadConfig, saveConfig } from "../core/config";
import { issueSessionCookie, clearSessionCookie, verifySession } from "./session";
import { loginPage } from "./login-page";
import { getDb, getBudgetState, listActiveSessions, getRecentAlerts, setSessionStatus, addAlert, getWindowBudget, getPendingApprovals, decideKavachApproval, getRecentApprovals, queryKavachAudit, recordAgentUsage, getCostTree, listAgentRows, recordDashboardAccess, getAllBgAgents, acknowledgeAllBgAgents } from "../core/db";
import { sseSubscribers } from "../core/events";
import { registerSystemRoutes } from "./routes/system";
import { registerForjaRoutes, emitSense } from "./routes/forja";
import { registerBitMaskOSRoutes } from "./routes/bitmaskos";
import { registerAuthRoutes } from "../auth/routes";
import { registerEnforcementRoutes } from "./routes/enforcement";
import { classifyCommand, runKavachGate } from "../kavach/gate";
// [EE] Multi-tenant — graceful degradation when EE not licensed
import { isEE, eeStatus } from "../../ee/license";
type _TenantMod = typeof import("../../ee/core/tenant");
let _listTenants: _TenantMod["listTenants"] = () => [];
let _getTenantConfig: _TenantMod["getTenantConfig"] | null = null;
let _saveTenantConfig: _TenantMod["saveTenantConfig"] = () => {};
let _deleteTenant: _TenantMod["deleteTenant"] = () => false;
let _ensureTenant: _TenantMod["ensureTenant"] | null = null;
let _extractTenantId: _TenantMod["extractTenantId"] = () => "default";
try {
  const tm = require("../../ee/core/tenant") as _TenantMod;
  _listTenants = tm.listTenants;
  _getTenantConfig = tm.getTenantConfig;
  _saveTenantConfig = tm.saveTenantConfig;
  _deleteTenant = tm.deleteTenant;
  _ensureTenant = tm.ensureTenant;
  _extractTenantId = tm.extractTenantId;
} catch { /* EE not available — OSS stubs active */ }

// [EE] PRAMANA receipts — graceful degradation when EE not licensed
type _PramanaMod = typeof import("../../ee/kavach/pramana-receipts");
let _listReceipts: _PramanaMod["listReceipts"] = () => [];
let _verifyReceipt: _PramanaMod["verifyReceipt"] = () => ({ valid: false, reason: "EE_NOT_LICENSED" });
let _getChainIntegrity: _PramanaMod["getChainIntegrity"] = () => ({ intact: false, receipt_count: 0, broken_at: "EE_NOT_LICENSED" });
try {
  const pm = require("../../ee/kavach/pramana-receipts") as _PramanaMod;
  _listReceipts = pm.listReceipts;
  _verifyReceipt = pm.verifyReceipt;
  _getChainIntegrity = pm.getChainIntegrity;
} catch { /* EE not available */ }

// [EE] HanumanG EE posture — graceful degradation when EE not licensed
type _HanumanGMod = typeof import("../../ee/shield/hanumang-ee");
let _getSessionPosture: _HanumanGMod["getSessionPosture"] = () => null;
try {
  const hm = require("../../ee/shield/hanumang-ee") as _HanumanGMod;
  _getSessionPosture = hm.getSessionPosture;
} catch { /* EE not available */ }

const config = loadConfig();
const app = Fastify({ logger: false });

app.register(fastifyCors, { origin: true });
app.register(fastifyFormbody);

// Session auth — cookie-based login replacing Basic Auth browser popup
// Public routes: /health /metrics /login /logout + internal KAVACH APIs
// All other routes require a valid aegis_sid session cookie.
if (config.dashboard.auth?.enabled) {
  const { username, password } = config.dashboard.auth;

  // Login page
  app.get("/login", async (_req, reply) => {
    reply.type("text/html").send(loginPage());
  });

  app.post("/login", async (req, reply) => {
    const body = req.body as Record<string, string> | undefined;
    const u = body?.username?.trim();
    const p = body?.password;
    if (u === username && p === password) {
      reply
        .header("Set-Cookie", issueSessionCookie(u))
        .redirect(req.headers["x-forwarded-prefix"] === "/dashboard" ? "/dashboard" : "/", 302);
    } else {
      reply.type("text/html").code(401).send(loginPage("Invalid username or password."));
    }
  });

  app.get("/logout", async (_req, reply) => {
    reply
      .header("Set-Cookie", clearSessionCookie())
      .redirect("/login", 302);
  });

  // Session guard — all other routes
  app.addHook("onRequest", async (req, reply) => {
    const url = req.url ?? "";
    // Public pass-through
    if (
      url === "/health" ||
      url === "/metrics" ||
      url === "/login" ||
      url === "/logout" ||
      url === "/kavachos" ||    // public landing page (KOS-093)
      url === "/commands" ||
      url.endsWith(".css") ||
      url.endsWith(".js") ||
      url.endsWith(".ico") ||
      url.endsWith(".png") ||
      url === "/api/approvals/webhook" ||
      url === "/api/v1/kavach/health" ||
      url === "/api/v1/kavach/state" ||
      url === "/api/v1/kavach/gate" ||
      url.startsWith("/api/v1/kavach/audit") ||
      url.startsWith("/api/v2/authorize") ||
      url.startsWith("/api/v1/aegis/authorize") ||
      url.startsWith("/api/v1/aegis/sdt") ||
      url.startsWith("/api/bg-agents") ||
      (url === "/api/approvals" && req.method === "GET")
    ) return;

    const { valid } = verifySession(req.headers["cookie"] as string | undefined);
    if (!valid) {
      // API requests get 401 JSON; browser requests get redirect to /login
      const accept = req.headers["accept"] ?? "";
      if (url.startsWith("/api/") || accept.includes("application/json")) {
        reply.code(401).send({ error: "session expired" });
      } else {
        reply.redirect(302, "/login");
      }
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
app.get("/health", async () => ({ status: "ok", service: "aegis-dashboard", ee: eeStatus() }));

// @rule:KOS-093 KavachOS landing page — public, no auth required
app.get("/kavachos", async (_req, reply) => {
  reply.type("text/html").send(kavachosLandingPage());
});

function kavachosLandingPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KavachOS — Runtime Governance for AI Agents</title>
<style>
  :root { --ink: #0d1117; --paper: #f6f8fa; --accent: #e36209; --muted: #57606a; --border: #d0d7de; --code-bg: #161b22; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; background: var(--paper); color: var(--ink); line-height: 1.6; }
  .hero { background: var(--ink); color: #fff; padding: 80px 24px 60px; text-align: center; }
  .hero h1 { font-size: 2.8rem; font-weight: 700; letter-spacing: -0.03em; margin-bottom: 12px; }
  .hero h1 span { color: var(--accent); }
  .hero p { font-size: 1.2rem; color: #8b949e; max-width: 600px; margin: 0 auto 32px; }
  .hero .tagline { font-size: 0.9rem; color: #6e7681; font-style: italic; margin-top: 8px; }
  .cta { display: inline-block; background: var(--accent); color: #fff; padding: 12px 28px; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 1rem; margin: 8px; }
  .cta.outline { background: transparent; border: 1px solid #444; color: #ccc; }
  .section { max-width: 960px; margin: 0 auto; padding: 60px 24px; }
  .section h2 { font-size: 1.8rem; font-weight: 700; margin-bottom: 8px; }
  .section .sub { color: var(--muted); margin-bottom: 40px; }
  .layers { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }
  .layer { border: 1px solid var(--border); border-radius: 8px; padding: 24px; background: #fff; }
  .layer .num { font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--accent); margin-bottom: 8px; }
  .layer h3 { font-size: 1.1rem; font-weight: 700; margin-bottom: 8px; }
  .layer p { font-size: 0.9rem; color: var(--muted); }
  .incident { background: #fff8f0; border-left: 4px solid var(--accent); padding: 24px 28px; border-radius: 0 8px 8px 0; margin: 40px 0; }
  .incident p { color: var(--ink); }
  .incident .amount { font-size: 2rem; font-weight: 700; color: var(--accent); }
  .code-block { background: var(--code-bg); border-radius: 8px; padding: 24px; margin: 24px 0; overflow-x: auto; }
  .code-block pre { color: #e6edf3; font-family: "SF Mono", Consolas, monospace; font-size: 0.85rem; line-height: 1.7; }
  .code-block .comment { color: #8b949e; }
  .code-block .cmd { color: #79c0ff; }
  .code-block .flag { color: #d2a8ff; }
  .code-block .val { color: #a5d6ff; }
  .depth-table { width: 100%; border-collapse: collapse; margin: 24px 0; }
  .depth-table th { background: var(--ink); color: #fff; padding: 10px 16px; text-align: left; font-size: 0.85rem; }
  .depth-table td { padding: 10px 16px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  .depth-table tr:nth-child(even) td { background: #f6f8fa; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .badge.green { background: #dafbe1; color: #1a7f37; }
  .badge.amber { background: #fff3cd; color: #9a6700; }
  .badge.red { background: #ffd7d5; color: #9a0000; }
  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 32px 0; }
  .stat-card { background: #fff; border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
  .stat-card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
  .stat-card .label { font-size: 0.8rem; color: var(--muted); margin-top: 4px; }
  .footer { background: var(--ink); color: #8b949e; text-align: center; padding: 32px 24px; font-size: 0.85rem; }
  .footer a { color: #6e7681; }
  @media (max-width: 768px) { .layers { grid-template-columns: 1fr; } .stat-grid { grid-template-columns: repeat(2, 1fr); } .hero h1 { font-size: 2rem; } }
</style>
</head>
<body>

<div class="hero">
  <h1><span>Kavach</span>OS</h1>
  <p>Runtime governance for AI agents — the OS that enforces policy at the kernel, not the prompt.</p>
  <p class="tagline">Named for Karna's divine armour. The protection is structural, not requested.</p>
  <br>
  <a class="cta" href="https://www.npmjs.com/package/@rocketlang/kavachos" target="_blank">npm install @rocketlang/kavachos</a>
  <a class="cta outline" href="https://github.com/rocketlang/kavachos" target="_blank">View on GitHub</a>
</div>

<div class="section">
  <div class="incident">
    <p style="font-size:0.85rem;color:var(--muted);margin-bottom:8px;">THE INCIDENT THAT BUILT THIS</p>
    <div class="amount">$200</div>
    <p style="margin-top:8px;">A single runaway AI agent, 94 days ago. No guardrail. No budget limit. No syscall boundary. It made 847 LLM API calls in 6 minutes before a human noticed. KavachOS was built from that incident — not from a Gartner report.</p>
  </div>

  <h2>Three-layer enforcement</h2>
  <p class="sub">Every AI agent runs inside all three layers simultaneously. No single layer is sufficient alone.</p>

  <div class="layers">
    <div class="layer">
      <div class="num">Layer 1</div>
      <h3>Kernel (seccomp + Falco)</h3>
      <p>A deterministic seccomp profile is generated from the agent's trust_mask, domain, and delegation_depth before first syscall. Deeper delegation = narrower syscall surface. At depth ≥ 4, all writes move to NOTIFY — the kernel suspends the thread until a human approves.</p>
    </div>
    <div class="layer">
      <div class="num">Layer 2</div>
      <h3>Proxy (budget + DAN gate)</h3>
      <p>Every LLM call routes through the kavachos-proxy. Budget breaches are blocked before the request leaves the box. The DAN gate (levels 1–4) intercepts dangerous actions pre-execution — before the model sees the tool result.</p>
    </div>
    <div class="layer">
      <div class="num">Layer 3</div>
      <h3>Ledger (PRAMANA receipts)</h3>
      <p>Every action produces a SHA-256 chained receipt with delegation_depth embedded. Depth regression between consecutive receipts (within one session) is a tamper indicator — chain is invalidated and DAN-3 fires immediately.</p>
    </div>
  </div>
</div>

<div class="section" style="background:#fff;border-top:1px solid var(--border);border-bottom:1px solid var(--border);max-width:100%;padding:60px 24px;">
  <div style="max-width:960px;margin:0 auto;">
    <h2>Delegation depth — the key primitive</h2>
    <p class="sub">Same trust_mask, same domain, different depth → different syscall surface. Depth is enforced at kernel level, not policy level.</p>
    <table class="depth-table">
      <thead><tr><th>Depth</th><th>Who holds this token</th><th>Syscalls (example: trust_mask=0xFF)</th><th>Write syscalls</th><th>HIL gate</th></tr></thead>
      <tbody>
        <tr><td><strong>1</strong></td><td>Direct human session</td><td>155 ALLOW</td><td>ALLOW</td><td><span class="badge green">off</span></td></tr>
        <tr><td><strong>2</strong></td><td>First-level agent delegation</td><td>152 ALLOW (ptrace/mknod removed)</td><td>ALLOW</td><td><span class="badge green">off</span></td></tr>
        <tr><td><strong>3</strong></td><td>Second-level agent delegation</td><td>149 ALLOW (clone/fork closed)</td><td>ALLOW</td><td><span class="badge green">off</span></td></tr>
        <tr><td><strong>4+</strong></td><td>Deep delegation (untrusted sub-agent)</td><td>32 ALLOW + 12 NOTIFY</td><td><strong>NOTIFY — kernel-gated</strong></td><td><span class="badge red">ACTIVE</span></td></tr>
      </tbody>
    </table>
  </div>
</div>

<div class="section">
  <h2>Install in 3 commands</h2>
  <p class="sub">The 5-minute path from nothing to governed agent.</p>
  <div class="code-block">
    <pre><span class="comment"># 1. Install</span>
<span class="cmd">npm install</span> <span class="val">@rocketlang/kavachos</span>

<span class="comment"># 2. Initialise (writes ~/.aegis/config.json)</span>
<span class="cmd">npx kavachos</span> <span class="flag">init</span>

<span class="comment"># 3. Launch your agent under the kernel</span>
<span class="cmd">npx kavachos</span> <span class="flag">run</span> <span class="val">--trust-mask=0xFF --domain=general</span> <span class="flag">--</span> <span class="val">claude code</span></pre>
  </div>

  <div class="stat-grid">
    <div class="stat-card">
      <div class="value">225</div>
      <div class="label">ANKR services as Customer Zero</div>
    </div>
    <div class="stat-card">
      <div class="value">3</div>
      <div class="label">enforcement layers (kernel/proxy/ledger)</div>
    </div>
    <div class="stat-card">
      <div class="value">94</div>
      <div class="label">days from $200 incident to v1.0</div>
    </div>
    <div class="stat-card">
      <div class="value">0</div>
      <div class="label">syscall-level escapes since deployment</div>
    </div>
  </div>
</div>

<div class="footer">
  <p>Built by <a href="https://ankr.in" target="_blank">ANKR</a> · AGPL-3.0 · Zenodo DOI: 10.5281/zenodo.kavachos-paper · <a href="/api/v2/forja/state" target="_blank">Forja STATE</a></p>
  <p style="margin-top:8px;">Named for Karna's kavach — the armour that could not be removed by any force from outside.</p>
</div>

</body>
</html>`;
}


app.register(fastifyStatic, {
  root: join(import.meta.dir, "static"),
  prefix: "/",
});
registerSystemRoutes(app);
registerForjaRoutes(app);
registerBitMaskOSRoutes(app);
registerAuthRoutes(app);
// @rule:AEG-E-001 enforcement pilot — TIER-A only, shadow mode by default
registerEnforcementRoutes(app);

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

// Config reader — for Limits panel
app.get("/api/config", async () => ({
  plan: config.plan,
  budget: { ...config.budget },
  heartbeat: { ...config.heartbeat },
  pricing_mode: config.pricing_mode,
}));

// Limits writer — updates in-memory config and persists
app.post("/api/config/limits", async (req) => {
  const b = (req.body as Record<string, unknown>) ?? {};
  const budgetKeys = [
    "messages_per_5h","tokens_per_5h","weekly_messages","weekly_tokens",
    "daily_limit_usd","weekly_limit_usd","monthly_limit_usd",
    "session_limit_usd","spawn_limit_per_session","spawn_concurrent_max",
    "cost_estimate_threshold_usd","max_depth",
  ] as const;
  for (const key of budgetKeys) {
    if (b[key] !== undefined) {
      const n = Number(b[key]);
      if (!isNaN(n) && n >= 0) (config.budget as Record<string,number>)[key] = n;
    }
  }
  if (typeof b.plan === "string" && ["api","max_5x","max_20x","pro","team","custom"].includes(b.plan)) {
    (config as any).plan = b.plan;
  }
  if (b.heartbeat_timeout_seconds !== undefined) {
    const n = Number(b.heartbeat_timeout_seconds);
    if (!isNaN(n) && n > 0) config.heartbeat.timeout_seconds = n;
  }
  saveConfig(config);
  return { ok: true, plan: config.plan };
});

// Digital Twin universe — sessions grouped by service + KAVACH posture + ledger count
app.get("/api/universe", async () => {
  const serviceMap: Record<string, string> = {};
  try {
    const raw = await Bun.file("/root/.ankr/config/services.json").text();
    const svcData = JSON.parse(raw) as { services?: Record<string, { path?: string }> };
    for (const [key, val] of Object.entries(svcData.services ?? {})) {
      if (val?.path) serviceMap[val.path] = key;
    }
  } catch { /* unavailable */ }

  const sessions = listActiveSessions() as Array<Record<string, any>>;
  const byPath: Record<string, typeof sessions> = {};
  for (const s of sessions) {
    const p: string = s.project_path ?? "/root";
    if (!byPath[p]) byPath[p] = [];
    byPath[p].push(s);
  }

  const services = Object.entries(byPath)
    .map(([path, sess]) => ({
      path,
      name: serviceMap[path] ?? (path.split("/").pop() || path),
      session_count: sess.length,
      total_messages: sess.reduce((a, s) => a + (s.message_count ?? 0), 0),
      total_spawns:   sess.reduce((a, s) => a + (s.agent_spawns ?? 0), 0),
      total_cost_usd: sess.reduce((a, s) => a + (s.total_cost_usd ?? 0), 0),
      sessions: sess,
    }))
    .sort((a, b) => b.session_count - a.session_count);

  const db = getDb();
  const kStats = db.query(`
    SELECT COUNT(*) as total,
      SUM(CASE WHEN status='allowed' THEN 1 ELSE 0 END) as allowed,
      SUM(CASE WHEN status='stopped' THEN 1 ELSE 0 END) as blocked,
      SUM(CASE WHEN status='timed_out' THEN 1 ELSE 0 END) as timed_out,
      SUM(CASE WHEN level=4 THEN 1 ELSE 0 END) as critical
    FROM kavach_approvals WHERE created_at > datetime('now','-24 hours')
  `).get() as Record<string, number> | null;

  let ledgerCount = 0;
  try {
    ledgerCount = (db.query("SELECT COUNT(*) as n FROM sdt_chain_store").get() as any)?.n ?? 0;
  } catch { /* table may not exist */ }

  return {
    services,
    total_sessions: sessions.length,
    kavach_24h: {
      total: kStats?.total ?? 0,
      allowed: kStats?.allowed ?? 0,
      blocked: kStats?.blocked ?? 0,
      timed_out: kStats?.timed_out ?? 0,
      critical: kStats?.critical ?? 0,
    },
    ledger_seals: ledgerCount,
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

// Per-process signal — dashboard kill/pause/resume individual PIDs
app.post("/api/signal/:pid", async (req) => {
  const pid = parseInt((req.params as any).pid, 10);
  const sig = (req.body as any)?.signal ?? "SIGKILL";
  const sigNum = sig === "SIGSTOP" ? 19 : sig === "SIGCONT" ? 18 : 9;
  if (isNaN(pid) || pid < 2) return { ok: false, error: "invalid pid" };
  try {
    process.kill(pid, sigNum);
    return { ok: true, pid, signal: sig };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
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

// --- V2-130: KAVACH HTTP Gate API — framework-neutral pre-execution gate ---
// @rule:KAV-001 every dangerous action is intercepted before execution
// @rule:AEG-011 framework-agnostic: HTTP POST → universal adapter contract
// @rule:AEG-012 n8n + LangChain + CrewAI call this endpoint; aegis enforces

// POST /api/v1/kavach/gate
// Body: { command: string, tool_name?: string, session_id?: string, dry_run?: boolean }
// Returns: { allow: boolean, level?: number, reason: string, approval_id?: string }
// @rule:KAV-078 HTTP gate returns structured JSON — adapters must never infer from status codes alone
app.post("/api/v1/kavach/gate", async (req, reply) => {
  const body = req.body as {
    command?: string;
    tool_name?: string;
    session_id?: string;
    dry_run?: boolean;
  };

  if (!body?.command || typeof body.command !== "string") {
    return reply.code(400).send({ allow: false, reason: "command is required" });
  }

  const command = body.command.trim();
  const toolName = body.tool_name || "http-gate";
  const sessionId = body.session_id || "http-gate-session";

  // @rule:KAV-001 — classify before anything else
  const classification = classifyCommand(command);

  if (!classification) {
    return { allow: true, level: 0, reason: "no dangerous patterns found" };
  }

  // dry_run: classify only, no notification, no polling
  if (body.dry_run) {
    return {
      allow: false,
      level: classification.level,
      reason: classification.consequence,
      dry_run: true,
    };
  }

  // @rule:KAV-056 — real gate: send notification, wait for decision
  const result = await runKavachGate(command, toolName, sessionId);

  const allow = result.decision === "ALLOW";
  return {
    allow,
    level: result.level,
    reason: result.message,
    decision: result.decision,
    approval_id: result.approval_id || undefined,
    _meta: {
      computed_at: new Date().toISOString(),
      trust_mask_applied: 0,
    },
  };
});

// GET /api/v1/kavach/health — liveness probe for adapters
// @rule:AEG-012 adapters check this before sending gate requests
app.get("/api/v1/kavach/health", async () => {
  return {
    ok: true,
    service: "aegis-kavach-gate",
    version: "2.0.0",
    kavach_enabled: !!(config.kavach?.enabled),
    dashboard_port: config.dashboard.port,
    timestamp: new Date().toISOString(),
  };
});

// GET /api/v1/kavach/state — budget + valve state summary for adapters
// @rule:CA-004 _meta with computed_at + duration_ms
app.get("/api/v1/kavach/state", async () => {
  const t0 = Date.now();
  const budget = getBudgetState("daily", config.budget.daily_limit_usd);
  return {
    budget: {
      daily_spent_usd: budget.spent_usd,
      daily_limit_usd: config.budget.daily_limit_usd,
      daily_remaining_usd: budget.remaining_usd,
      breached: budget.spent_usd >= config.budget.daily_limit_usd,
    },
    kavach_enabled: !!(config.kavach?.enabled),
    _meta: {
      computed_at: new Date().toISOString(),
      duration_ms: Date.now() - t0,
      trust_mask_applied: 0,
    },
  };
});

// GET /api/v1/kavach/audit — query DAN gate decisions (n8n KavachAudit + compliance)
// @rule:KOS-T032 audit replays PRAMANA receipt chain, flags gaps
// @rule:CA-004 _meta minimum on every response
// @rule:INF-KAV-024 filter by session_id, status, level, limit
app.get("/api/v1/kavach/audit", async (req) => {
  const t0 = Date.now();
  const q = req.query as Record<string, string>;
  const { records, total } = queryKavachAudit({
    session_id: q.session_id?.trim() || null,
    status: q.status?.trim() || null,
    level: q.level ? parseInt(q.level, 10) : null,
    limit: q.limit ? parseInt(q.limit, 10) : 50,
  });
  return {
    records,
    total,
    _meta: {
      computed_at: new Date().toISOString(),
      duration_ms: Date.now() - t0,
      trust_mask_applied: 0,
    },
  };
});

// --- [EE] Multi-Tenant API (@rule:KAV-071, KAV-072, KAV-073) ---

app.get("/api/v1/tenants", async (_, reply) => {
  if (!isEE()) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "multi-tenant" });
  return { tenants: _listTenants() };
});

app.get("/api/v1/tenants/:id", async (req, reply) => {
  if (!isEE() || !_getTenantConfig) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "multi-tenant" });
  const { id } = req.params as { id: string };
  try { return _getTenantConfig(id); }
  catch { return reply.code(404).send({ error: "tenant not found" }); }
});

app.post("/api/v1/tenants", async (req, reply) => {
  if (!isEE() || !_ensureTenant) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "multi-tenant" });
  const body = req.body as { tenant_id?: string; display_name?: string } & Record<string, unknown>;
  const tid = (body?.tenant_id || "").replace(/[^a-zA-Z0-9\-_]/g, "").slice(0, 64);
  if (!tid) return reply.code(400).send({ error: "tenant_id required (alphanumeric, hyphen, underscore)" });
  const cfg = _ensureTenant(tid);
  if (body.display_name) { cfg.display_name = String(body.display_name).slice(0, 100); _saveTenantConfig(cfg); }
  return { ok: true, tenant: cfg };
});

app.put("/api/v1/tenants/:id", async (req, reply) => {
  if (!isEE() || !_getTenantConfig) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "multi-tenant" });
  const { id } = req.params as { id: string };
  const body = req.body as Record<string, unknown>;
  try {
    const cfg = _getTenantConfig(id);
    const updated = { ...cfg, ...body, tenant_id: id };
    _saveTenantConfig(updated);
    return { ok: true, tenant: updated };
  } catch { return reply.code(404).send({ error: "tenant not found" }); }
});

app.delete("/api/v1/tenants/:id", async (req, reply) => {
  if (!isEE()) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "multi-tenant" });
  const { id } = req.params as { id: string };
  const ok = _deleteTenant(id);
  if (!ok) return reply.code(400).send({ error: "Cannot delete default tenant or tenant not found" });
  return { ok: true };
});

// [EE] PRAMANA receipts API (@rule:KAV-046)

app.get("/api/v1/pramana/:sessionId/receipts", async (req, reply) => {
  if (!isEE()) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "pramana-receipts" });
  const { sessionId } = req.params as { sessionId: string };
  return { receipts: _listReceipts(sessionId) };
});

app.get("/api/v1/pramana/:sessionId/integrity", async (req, reply) => {
  if (!isEE()) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "pramana-receipts" });
  const { sessionId } = req.params as { sessionId: string };
  return _getChainIntegrity(sessionId);
});

app.post("/api/v1/pramana/verify", async (req, reply) => {
  if (!isEE()) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "pramana-receipts" });
  const receipt = req.body as any;
  if (!receipt?.receipt_id) return reply.code(400).send({ error: "receipt body required" });
  return _verifyReceipt(receipt);
});

// [EE] HanumanG posture report API (@rule:KAV-015)

app.get("/api/v1/hanumang/:sessionId/posture", async (req, reply) => {
  if (!isEE()) return reply.code(402).send({ error: "EE_NOT_LICENSED", feature: "hanumang-ee" });
  const { sessionId } = req.params as { sessionId: string };
  const posture = _getSessionPosture(sessionId);
  if (!posture) return { posture_level: "GREEN", score: 100, total_spawns: 0, message: "No spawn history for session" };
  return posture;
});

// ── GET /metrics — Prometheus text format (@rule:KAV-004 observability) ───────
app.get("/metrics", async (_req, reply) => {
  const db = getDb();

  // --- kavach_gate_decisions_total ---
  // pass = allowed, block = stopped|timed_out, warn = explained|pending|pending_second
  const gateRows = db.query(
    `SELECT status, COUNT(*) as cnt FROM kavach_approvals GROUP BY status`
  ).all() as Array<{ status: string; cnt: number }>;

  let gatePass = 0, gateBlock = 0, gateWarn = 0;
  for (const r of gateRows) {
    if (r.status === "allowed") gatePass += r.cnt;
    else if (r.status === "stopped" || r.status === "timed_out") gateBlock += r.cnt;
    else gateWarn += r.cnt;
  }

  // --- kavach_gate_latency_ms — derive from usage_log timestamps vs approvals ---
  // We approximate latency from time between approval create and decide
  const latencyRows = db.query(
    `SELECT (julianday(decided_at) - julianday(created_at)) * 86400000 AS latency_ms
     FROM kavach_approvals WHERE decided_at IS NOT NULL AND status NOT IN ('pending','pending_second')`
  ).all() as Array<{ latency_ms: number }>;

  const latBuckets = [0.5, 1, 2, 5, 10, 25, 50];
  const latCounts = new Array(latBuckets.length).fill(0);
  let latSum = 0;
  let latTotal = 0;
  for (const row of latencyRows) {
    const ms = row.latency_ms ?? 0;
    latSum += ms;
    latTotal++;
    for (let i = 0; i < latBuckets.length; i++) {
      if (ms <= latBuckets[i]) latCounts[i]++;
    }
  }

  // --- kavach_budget_spent_usd / remaining ---
  const budget = getBudgetState("daily", config.budget.daily_limit_usd);

  // --- kavach_active_sessions ---
  const activeSessions = listActiveSessions().length;

  // --- kavach_hanumang_checks_total ---
  // HanumanG checks correspond to agent spawns. violation_count > 0 = block, else pass
  const hanumangRows = db.query(
    `SELECT SUM(CASE WHEN violation_count > 0 THEN 1 ELSE 0 END) as blocks,
            SUM(CASE WHEN violation_count = 0 THEN 1 ELSE 0 END) as passes
     FROM agents`
  ).get() as { blocks: number | null; passes: number | null } | null;
  const hanumangPass = hanumangRows?.passes ?? 0;
  const hanumangBlock = hanumangRows?.blocks ?? 0;

  // --- kavach_falco_violations_total ---
  // Falco violations land in alerts table with type='falco' or severity in critical/warning/info
  const falcoRows = db.query(
    `SELECT severity, COUNT(*) as cnt FROM alerts WHERE type = 'falco' GROUP BY severity`
  ).all() as Array<{ severity: string; cnt: number }>;
  let falcoCritical = 0, falcoWarning = 0, falcoInfo = 0;
  for (const r of falcoRows) {
    if (r.severity === "critical") falcoCritical += r.cnt;
    else if (r.severity === "warning") falcoWarning += r.cnt;
    else falcoInfo += r.cnt;
  }

  // --- kavach_bmos_authorize_total ---
  const bmosRows = db.query(
    `SELECT authorized, COUNT(*) as cnt FROM authorize_log GROUP BY authorized`
  ).all() as Array<{ authorized: number; cnt: number }>;
  let bmosAuthorized = 0, bmosDenied = 0;
  for (const r of bmosRows) {
    if (r.authorized === 1) bmosAuthorized += r.cnt;
    else bmosDenied += r.cnt;
  }

  // --- kavach_bmos_authorize_latency_us ---
  const bmosLatRows = db.query(
    `SELECT latency_us FROM authorize_log WHERE latency_us IS NOT NULL`
  ).all() as Array<{ latency_us: number }>;
  const bmosLatBuckets = [5, 10, 20, 50, 100];
  const bmosLatCounts = new Array(bmosLatBuckets.length).fill(0);
  let bmosLatSum = 0;
  let bmosLatTotal = 0;
  for (const row of bmosLatRows) {
    const us = row.latency_us ?? 0;
    bmosLatSum += us;
    bmosLatTotal++;
    for (let i = 0; i < bmosLatBuckets.length; i++) {
      if (us <= bmosLatBuckets[i]) bmosLatCounts[i]++;
    }
  }

  // ── Format Prometheus text ──────────────────────────────────────────────────
  const lines: string[] = [];

  // Gate decisions
  lines.push('# HELP kavach_gate_decisions_total Total KAVACH gate decisions by result');
  lines.push('# TYPE kavach_gate_decisions_total counter');
  lines.push(`kavach_gate_decisions_total{result="pass"} ${gatePass}`);
  lines.push(`kavach_gate_decisions_total{result="block"} ${gateBlock}`);
  lines.push(`kavach_gate_decisions_total{result="warn"} ${gateWarn}`);

  // Gate latency histogram
  lines.push('# HELP kavach_gate_latency_ms KAVACH gate decision latency in milliseconds');
  lines.push('# TYPE kavach_gate_latency_ms histogram');
  for (let i = 0; i < latBuckets.length; i++) {
    lines.push(`kavach_gate_latency_ms_bucket{le="${latBuckets[i]}"} ${latCounts[i]}`);
  }
  lines.push(`kavach_gate_latency_ms_bucket{le="+Inf"} ${latTotal}`);
  lines.push(`kavach_gate_latency_ms_sum ${latSum.toFixed(3)}`);
  lines.push(`kavach_gate_latency_ms_count ${latTotal}`);

  // Budget gauges
  lines.push('# HELP kavach_budget_spent_usd Current daily budget spent in USD');
  lines.push('# TYPE kavach_budget_spent_usd gauge');
  lines.push(`kavach_budget_spent_usd ${budget.spent_usd.toFixed(6)}`);
  lines.push('# HELP kavach_budget_remaining_usd Current daily budget remaining in USD');
  lines.push('# TYPE kavach_budget_remaining_usd gauge');
  lines.push(`kavach_budget_remaining_usd ${budget.remaining_usd.toFixed(6)}`);

  // Active sessions
  lines.push('# HELP kavach_active_sessions Number of currently active AEGIS sessions');
  lines.push('# TYPE kavach_active_sessions gauge');
  lines.push(`kavach_active_sessions ${activeSessions}`);

  // HanumanG checks
  lines.push('# HELP kavach_hanumang_checks_total Total HanumanG delegation checks by result');
  lines.push('# TYPE kavach_hanumang_checks_total counter');
  lines.push(`kavach_hanumang_checks_total{result="pass"} ${hanumangPass}`);
  lines.push(`kavach_hanumang_checks_total{result="block"} ${hanumangBlock}`);

  // Falco violations
  lines.push('# HELP kavach_falco_violations_total Total Falco kernel violations by severity');
  lines.push('# TYPE kavach_falco_violations_total counter');
  lines.push(`kavach_falco_violations_total{severity="critical"} ${falcoCritical}`);
  lines.push(`kavach_falco_violations_total{severity="warning"} ${falcoWarning}`);
  lines.push(`kavach_falco_violations_total{severity="info"} ${falcoInfo}`);

  // BMOS authorize totals
  lines.push('# HELP kavach_bmos_authorize_total Total BMOS-Authorize decisions by result');
  lines.push('# TYPE kavach_bmos_authorize_total counter');
  lines.push(`kavach_bmos_authorize_total{result="authorized"} ${bmosAuthorized}`);
  lines.push(`kavach_bmos_authorize_total{result="denied"} ${bmosDenied}`);

  // BMOS authorize latency histogram
  lines.push('# HELP kavach_bmos_authorize_latency_us BMOS-Authorize operation latency in microseconds');
  lines.push('# TYPE kavach_bmos_authorize_latency_us histogram');
  for (let i = 0; i < bmosLatBuckets.length; i++) {
    lines.push(`kavach_bmos_authorize_latency_us_bucket{le="${bmosLatBuckets[i]}"} ${bmosLatCounts[i]}`);
  }
  lines.push(`kavach_bmos_authorize_latency_us_bucket{le="+Inf"} ${bmosLatTotal}`);
  lines.push(`kavach_bmos_authorize_latency_us_sum ${bmosLatSum.toFixed(0)}`);
  lines.push(`kavach_bmos_authorize_latency_us_count ${bmosLatTotal}`);

  // ── Layer 1: Kernel metrics (KOS-T090) ──────────────────────────────────────

  // kernel_profiles: ensure delegation_depth column exists (additive migration)
  try {
    db.exec("ALTER TABLE kernel_profiles ADD COLUMN delegation_depth INTEGER NOT NULL DEFAULT 1");
  } catch { /* already exists */ }
  try {
    db.exec("ALTER TABLE kernel_receipts ADD COLUMN delegation_depth INTEGER NOT NULL DEFAULT 1");
  } catch { /* already exists */ }

  const kernelProfileRows = db.query(
    `SELECT COUNT(*) as total,
            SUM(CASE WHEN datetime(stored_at) > datetime('now','-24 hours') THEN 1 ELSE 0 END) as recent
     FROM kernel_profiles`
  ).get() as { total: number; recent: number } | null;

  const kernelViolRows = db.query(
    `SELECT severity, domain,
            COUNT(*) as cnt
     FROM kernel_receipts kr
     LEFT JOIN kernel_profiles kp ON kr.session_id = kp.session_id
     WHERE kr.event_type NOT IN ('SESSION_OPEN','SESSION_CLOSE')
     GROUP BY severity, domain`
  ).all() as Array<{ severity: string | null; domain: string | null; cnt: number }>;

  const kernelDepthRows = db.query(
    `SELECT delegation_depth, COUNT(*) as cnt FROM kernel_profiles GROUP BY delegation_depth`
  ).all() as Array<{ delegation_depth: number; cnt: number }>;

  // HIL gates: profiles where profile_json has hil_mode:true
  const hilRows = db.query(
    `SELECT COUNT(*) as cnt FROM kernel_profiles WHERE json_extract(profile_json,'$._kavachos.hil_mode') = 1`
  ).get() as { cnt: number } | null;

  const kernelReceiptTotal = db.query(
    `SELECT COUNT(*) as cnt FROM kernel_receipts`
  ).get() as { cnt: number } | null;

  const depthRegressionRows = db.query(
    `SELECT COUNT(*) as cnt FROM kernel_receipts WHERE event_type = 'DEPTH_REGRESSION'`
  ).get() as { cnt: number } | null;

  const chainDriftRows = db.query(
    `SELECT COUNT(*) as cnt FROM kernel_drift_events`
  ).get() as { cnt: number } | null;

  lines.push('# HELP kavachos_kernel_profiles_generated_total Total seccomp profiles generated since deployment');
  lines.push('# TYPE kavachos_kernel_profiles_generated_total counter');
  lines.push(`kavachos_kernel_profiles_generated_total ${kernelProfileRows?.total ?? 0}`);

  lines.push('# HELP kavachos_kernel_active_sessions Profiles generated in the last 24 hours (proxy for active sessions)');
  lines.push('# TYPE kavachos_kernel_active_sessions gauge');
  lines.push(`kavachos_kernel_active_sessions ${kernelProfileRows?.recent ?? 0}`);

  lines.push('# HELP kavachos_kernel_hil_gates_active Sessions currently running with HIL mode (delegation_depth>=4)');
  lines.push('# TYPE kavachos_kernel_hil_gates_active gauge');
  lines.push(`kavachos_kernel_hil_gates_active ${hilRows?.cnt ?? 0}`);

  lines.push('# HELP kavachos_kernel_violations_total Total kernel receipt events (violations, drifts, rate exceeded) by severity and domain');
  lines.push('# TYPE kavachos_kernel_violations_total counter');
  if (kernelViolRows.length === 0) {
    lines.push(`kavachos_kernel_violations_total{severity="none",domain="none"} 0`);
  }
  for (const r of kernelViolRows) {
    lines.push(`kavachos_kernel_violations_total{severity="${r.severity ?? 'unknown'}",domain="${r.domain ?? 'unknown'}"} ${r.cnt}`);
  }

  lines.push('# HELP kavachos_kernel_depth_distribution Number of profiles per delegation depth level');
  lines.push('# TYPE kavachos_kernel_depth_distribution gauge');
  for (const r of kernelDepthRows) {
    lines.push(`kavachos_kernel_depth_distribution{depth="${r.delegation_depth}"} ${r.cnt}`);
  }

  // ── Layer 2: Proxy aliases (KOS-T090) ────────────────────────────────────────
  // Re-expose existing budget data under kavachos_proxy_ namespace for Grafana dashboard

  const proxyModelRows = db.query(
    `SELECT model, COUNT(*) as cnt, SUM(estimated_cost_usd) as cost
     FROM usage_log GROUP BY model`
  ).all() as Array<{ model: string; cnt: number; cost: number }>;

  const budgetBreachRows = db.query(
    `SELECT COUNT(*) as cnt FROM alerts WHERE type = 'budget_breach'`
  ).get() as { cnt: number } | null;

  const danGateRows = db.query(
    `SELECT COUNT(*) as cnt FROM kavach_approvals WHERE level >= 3`
  ).get() as { cnt: number } | null;

  const dailyPct = config.budget.daily_limit_usd > 0
    ? budget.spent_usd / config.budget.daily_limit_usd
    : 0;

  lines.push('# HELP kavachos_proxy_daily_spend_usd Current daily LLM spend in USD');
  lines.push('# TYPE kavachos_proxy_daily_spend_usd gauge');
  lines.push(`kavachos_proxy_daily_spend_usd ${budget.spent_usd.toFixed(6)}`);

  lines.push('# HELP kavachos_proxy_budget_percent_used Fraction of daily budget consumed (0.0–1.0)');
  lines.push('# TYPE kavachos_proxy_budget_percent_used gauge');
  lines.push(`kavachos_proxy_budget_percent_used ${dailyPct.toFixed(6)}`);

  lines.push('# HELP kavachos_proxy_requests_total Total LLM requests routed through proxy by model');
  lines.push('# TYPE kavachos_proxy_requests_total counter');
  for (const r of proxyModelRows) {
    lines.push(`kavachos_proxy_requests_total{model="${r.model ?? 'unknown'}"} ${r.cnt}`);
  }

  lines.push('# HELP kavachos_proxy_budget_breaches_total Total budget limit breaches');
  lines.push('# TYPE kavachos_proxy_budget_breaches_total counter');
  lines.push(`kavachos_proxy_budget_breaches_total ${budgetBreachRows?.cnt ?? 0}`);

  lines.push('# HELP kavachos_proxy_dan_gates_total Total DAN level-3+ gates triggered');
  lines.push('# TYPE kavachos_proxy_dan_gates_total counter');
  lines.push(`kavachos_proxy_dan_gates_total ${danGateRows?.cnt ?? 0}`);

  // ── Layer 3: Ledger metrics (KOS-T090) ───────────────────────────────────────

  const chainIntact = (chainDriftRows?.cnt ?? 0) === 0 ? 1 : 0;

  const receiptByDepthRows = db.query(
    `SELECT delegation_depth, COUNT(*) as cnt FROM kernel_receipts GROUP BY delegation_depth`
  ).all() as Array<{ delegation_depth: number; cnt: number }>;

  lines.push('# HELP kavachos_ledger_chain_intact 1 if no profile drift events detected, 0 if chain broken');
  lines.push('# TYPE kavachos_ledger_chain_intact gauge');
  lines.push(`kavachos_ledger_chain_intact ${chainIntact}`);

  lines.push('# HELP kavachos_ledger_receipts_total Total PRAMANA receipts by delegation depth');
  lines.push('# TYPE kavachos_ledger_receipts_total counter');
  if (receiptByDepthRows.length === 0) {
    lines.push(`kavachos_ledger_receipts_total{delegation_depth="1"} 0`);
  }
  for (const r of receiptByDepthRows) {
    lines.push(`kavachos_ledger_receipts_total{delegation_depth="${r.delegation_depth}"} ${r.cnt}`);
  }

  lines.push('# HELP kavachos_ledger_depth_regressions_total Receipt chain depth regressions detected (tamper indicator)');
  lines.push('# TYPE kavachos_ledger_depth_regressions_total counter');
  lines.push(`kavachos_ledger_depth_regressions_total ${depthRegressionRows?.cnt ?? 0}`);

  lines.push('# HELP kavachos_ledger_receipts_all_total Total PRAMANA receipts across all depths');
  lines.push('# TYPE kavachos_ledger_receipts_all_total counter');
  lines.push(`kavachos_ledger_receipts_all_total ${kernelReceiptTotal?.cnt ?? 0}`);

  lines.push(""); // trailing newline required by Prometheus
  return reply.type("text/plain; version=0.0.4; charset=utf-8").send(lines.join("\n"));
});

// ── Background agents API (@rule:KOS-T095) ────────────────────────────────────
app.get("/api/bg-agents", async (req) => {
  const hours = parseInt((req.query as Record<string,string>).hours ?? "24", 10);
  return getAllBgAgents(Math.min(hours, 168));
});

app.post("/api/bg-agents/ack", async (req) => {
  const { session_id } = (req.body ?? {}) as { session_id?: string };
  if (!session_id) return { error: "session_id required" };
  acknowledgeAllBgAgents(session_id);
  return { ok: true };
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
    <div class="card-title" style="color:var(--amber)">AEGIS API (port ${config.dashboard.port})</div>
    <table>
      <tr><td style="font-size:11px">GET /api/status</td><td>Budget state</td></tr>
      <tr><td style="font-size:11px">GET /api/sessions</td><td>Active sessions</td></tr>
      <tr><td style="font-size:11px">GET /api/alerts</td><td>Recent alerts</td></tr>
      <tr><td style="font-size:11px">POST /api/kill</td><td>Manual kill</td></tr>
      <tr><td style="font-size:11px">POST /api/enforcement</td><td>Toggle enforce/alert mode</td></tr>
      <tr><td style="font-size:11px">GET /commands</td><td>This page</td></tr>
      <tr><td colspan="2" class="comment" style="padding-top:8px">Monitor (port ${config.monitor.health_port}):</td></tr>
      <tr><td style="font-size:11px">GET /health</td><td>Enforcement mode + auto-restart list</td></tr>
    </table>
  </div>

  <div class="card">
    <div class="card-title" style="color:var(--green)">KAVACH Gate API (n8n / LangChain)</div>
    <table>
      <tr><td style="font-size:11px">POST /api/v1/kavach/gate</td><td>Pre-execution DAN gate — adapters call before agent runs</td></tr>
      <tr><td style="font-size:11px">GET /api/v1/kavach/health</td><td>Liveness probe for adapters</td></tr>
      <tr><td style="font-size:11px">GET /api/v1/kavach/state</td><td>Budget + config summary</td></tr>
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
