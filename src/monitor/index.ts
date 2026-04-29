#!/usr/bin/env bun
// AEGIS Monitor Daemon
// Watches session logs, accumulates spend, enforces budgets

import { loadConfig, resolveWatchPaths } from "../core/config";
import { addUsage, upsertSession, addToBudget, addAlert, setSessionStatus } from "../core/db";
import { broadcast } from "../core/events";
import { SessionWatcher } from "./watcher";
import { BudgetEnforcer } from "./enforcer";
import { sendSlackAlert } from "../kavach/slack-notifier";
import type { UsageRecord } from "../core/types";

const config = loadConfig();
const enforcer = new BudgetEnforcer();
const startTime = Date.now();

// Track last user activity per session (for heartbeat)
const lastUserActivity = new Map<string, number>();
// Track sessions already alerted as abandoned (avoid re-alerting every 30s)
const abandonedAlerted = new Set<string>();

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

// User activity handler — resets heartbeat clock for the session
function onUserActivity(session_id: string): void {
  const wasAbandoned = abandonedAlerted.has(session_id);
  lastUserActivity.set(session_id, Date.now());
  if (wasAbandoned) {
    // User came back — clear abandoned state
    abandonedAlerted.delete(session_id);
    broadcast("heartbeat_resumed", { session_id, timestamp: new Date().toISOString() });
  }
}

// Heartbeat mode classification
// attended   = last user input < timeout/6 ago
// unattended = last user input ≥ timeout/6 but < timeout ago
// abandoned  = last user input ≥ timeout ago
function classifyHeartbeat(idleMs: number, timeoutMs: number): "attended" | "unattended" | "abandoned" {
  if (idleMs >= timeoutMs) return "abandoned";
  if (idleMs >= timeoutMs / 6) return "unattended";
  return "attended";
}

// Heartbeat checker — runs every 30s
// @rule:KAV-019 (watchdog: detect stale sessions from session logs)
function checkHeartbeats(): void {
  if (config.heartbeat.timeout_seconds <= 0) return;
  const timeoutMs = config.heartbeat.timeout_seconds * 1000;
  const now = Date.now();
  const cfg = loadConfig(); // hot reload

  for (const [session_id, lastActive] of lastUserActivity) {
    const idleMs = now - lastActive;
    const mode = classifyHeartbeat(idleMs, timeoutMs);
    const idleMin = Math.round(idleMs / 60000);

    broadcast("heartbeat_update", { session_id, mode, idle_ms: idleMs, timestamp: new Date().toISOString() });

    if (mode === "abandoned" && !abandonedAlerted.has(session_id)) {
      abandonedAlerted.add(session_id);

      const alert = {
        type: "heartbeat_timeout" as const,
        severity: "warning" as const,
        message: `Session ${session_id.slice(0, 8)} abandoned — no user input for ${idleMin} min (threshold: ${cfg.heartbeat.timeout_seconds / 60} min)`,
        session_id,
        timestamp: new Date().toISOString(),
        acknowledged: false,
      };

      addAlert(alert);
      broadcast("heartbeat_timeout", { session_id, idle_ms: idleMs, mode, timestamp: alert.timestamp });
      process.stderr.write(`[AEGIS] Heartbeat timeout — session ${session_id.slice(0, 8)} idle ${idleMin}m\n`);

      // [EE] Slack heartbeat alert
      sendSlackAlert(cfg, alert).catch(() => {});

      // Act on config.heartbeat.action
      if (cfg.heartbeat.action === "pause") {
        setSessionStatus(session_id, "paused");
        process.stderr.write(`[AEGIS] Session ${session_id.slice(0, 8)} paused (heartbeat.action=pause)\n`);
      } else if (cfg.heartbeat.action === "kill") {
        setSessionStatus(session_id, "killed");
        process.stderr.write(`[AEGIS] Session ${session_id.slice(0, 8)} marked killed (heartbeat.action=kill)\n`);
      }
      // "alert" = default — alert only, no state change
    }
  }

  // Evict sessions that haven't been seen in 4× the timeout (cleanup)
  const evictThreshold = timeoutMs * 4;
  for (const [session_id, lastActive] of lastUserActivity) {
    if (now - lastActive > evictThreshold) {
      lastUserActivity.delete(session_id);
      abandonedAlerted.delete(session_id);
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
      const now = Date.now();
      const timeoutMs = config.heartbeat.timeout_seconds * 1000;
      const sessions = [...lastUserActivity.entries()].map(([id, ts]) => ({
        session_id: id.slice(0, 8),
        idle_ms: now - ts,
        mode: classifyHeartbeat(now - ts, timeoutMs),
      }));
      return Response.json({
        status: "ok",
        uptime_s: Math.floor((Date.now() - startTime) / 1000),
        files_watched: watcher.getWatchedFileCount(),
        active_sessions: lastUserActivity.size,
        heartbeat: {
          timeout_s: config.heartbeat.timeout_seconds,
          action: config.heartbeat.action,
          sessions,
        },
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
console.log(`[AEGIS] Heartbeat: ${config.heartbeat.timeout_seconds}s timeout, action=${config.heartbeat.action}`);
