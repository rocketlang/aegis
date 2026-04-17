#!/usr/bin/env bun
// AEGIS Dashboard — Fastify server with real-time SSE

import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCors from "@fastify/cors";
import { join } from "path";
import { loadConfig } from "../core/config";
import { getBudgetState, listActiveSessions, getRecentAlerts, setSessionStatus, addAlert, getWindowBudget } from "../core/db";
import { sseSubscribers } from "../core/events";
import { registerSystemRoutes } from "./routes/system";

const config = loadConfig();
const app = Fastify({ logger: false });

app.register(fastifyCors, { origin: true });
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
app.listen({ port: config.dashboard.port, host: "0.0.0.0" }, (err, address) => {
  if (err) {
    console.error("Dashboard failed to start:", err);
    process.exit(1);
  }
  console.log(`[AEGIS] Dashboard: ${address}`);
});
