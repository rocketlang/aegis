#!/usr/bin/env bun
// AEGIS Monitor Daemon
// Watches session logs, accumulates spend, enforces budgets

import { loadConfig, resolveWatchPaths } from "../core/config";
import { addUsage, upsertSession, addToBudget } from "../core/db";
import { broadcast } from "../core/events";
import { SessionWatcher } from "./watcher";
import { BudgetEnforcer } from "./enforcer";
import type { UsageRecord } from "../core/types";

const config = loadConfig();
const enforcer = new BudgetEnforcer();
const startTime = Date.now();

// Track last user activity per session (for heartbeat)
const lastUserActivity = new Map<string, number>();

// Forward enforcer events to SSE subscribers (dashboard, if connected)
enforcer.on((event) => {
  broadcast(event.type, event.data);
});

// Usage handler — called for each new usage record from any session file
function onUsage(record: UsageRecord, projectPath: string): void {
  // 1. Persist to DB
  addUsage(record);
  upsertSession(record.session_id, projectPath, record.estimated_cost_usd, record.is_agent_spawn);
  addToBudget(record.estimated_cost_usd, {
    daily: config.budget.daily_limit_usd,
    weekly: config.budget.weekly_limit_usd,
    monthly: config.budget.monthly_limit_usd,
  });

  // 2. Enforce budget rules
  enforcer.check(record);

  // 3. Broadcast to SSE
  broadcast("usage_update", record);
}

// User activity handler — for heartbeat tracking
function onUserActivity(session_id: string): void {
  lastUserActivity.set(session_id, Date.now());
}

// Heartbeat checker — runs every 30s
function checkHeartbeats(): void {
  if (config.heartbeat.timeout_seconds <= 0) return;
  const timeout = config.heartbeat.timeout_seconds * 1000;
  const now = Date.now();

  for (const [session_id, lastActive] of lastUserActivity) {
    if (now - lastActive > timeout) {
      console.log(`[AEGIS] Heartbeat timeout for session ${session_id.slice(0, 8)}`);
      // Could trigger pause here based on config.heartbeat.action
    }
  }
}

// Start watching
const watchPaths = resolveWatchPaths(config);
const watcher = new SessionWatcher(onUsage, onUserActivity, config.monitor.poll_interval_ms);
watcher.start(watchPaths);

// Heartbeat check interval
setInterval(checkHeartbeats, 30_000);

// Health endpoint
const healthServer = Bun.serve({
  port: config.monitor.health_port,
  fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/health") {
      return Response.json({
        status: "ok",
        uptime_s: Math.floor((Date.now() - startTime) / 1000),
        files_watched: watcher.getWatchedFileCount(),
        active_sessions: lastUserActivity.size,
        enforcement_mode: config.enforcement.mode,
        kill_on_budget_breach: config.enforcement.mode === "enforce",
        kill_on_burst: config.enforcement.mode === "enforce",
        burst_multiplier: 3,
        registry_wired: !!config.enforcement.registry_url,
        auto_restart_services: config.enforcement.auto_restart_services ?? [],
        auto_restart_delay_ms: config.enforcement.auto_restart_delay_ms ?? 3000,
      });
    }
    return new Response("AEGIS Monitor", { status: 200 });
  },
});

console.log(`[AEGIS] Monitor started`);
console.log(`[AEGIS] Watching: ${watchPaths.join(", ")}`);
console.log(`[AEGIS] Health endpoint: http://localhost:${config.monitor.health_port}/health`);
console.log(`[AEGIS] Budget: $${config.budget.daily_limit_usd}/day, $${config.budget.weekly_limit_usd}/week`);
