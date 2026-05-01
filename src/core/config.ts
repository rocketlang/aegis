// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

import { existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import type { AegisConfig } from "./types";

const PORTS_FILE = "/root/.ankr/config/ports.json";

function readPortsJson(): Record<string, unknown> {
  try { return JSON.parse(readFileSync(PORTS_FILE, "utf-8")); } catch { return {}; }
}

// Resolve a dotted path like "security.aegis_dashboard" from ports.json
function resolvePort(portPath: string, fallback: number): number {
  // ankr-ctl injects PORT env var — prefer that (highest priority, no file I/O)
  if (process.env.PORT) return parseInt(process.env.PORT, 10);
  try {
    const ports = readPortsJson();
    const val = portPath.split(".").reduce<unknown>((o, k) => (o as Record<string,unknown>)?.[k], ports);
    if (typeof val === "number") return val;
  } catch {}
  return fallback;
}

export const DASHBOARD_PORT = resolvePort("security.aegis_dashboard", 4850);
export const MONITOR_PORT   = resolvePort("security.aegis_monitor",   4851);

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const CONFIG_PATH = join(AEGIS_DIR, "config.json");

const DEFAULT_CONFIG: AegisConfig = {
  plan: "max_5x",
  budget: {
    daily_limit_usd: 100,
    weekly_limit_usd: 400,
    monthly_limit_usd: 1200,
    session_limit_usd: 25,
    // Max 5x defaults (approx — Anthropic doesn't publish exact numbers)
    messages_per_5h: 225,       // ~225 Opus messages per 5h for Max 5x
    tokens_per_5h: 50_000_000,  // ~50M tokens per 5h (conservative)
    weekly_messages: 3150,      // 14 windows/week × 225
    weekly_tokens: 700_000_000, // 14 × 50M
    spawn_limit_per_session: 50,
    spawn_concurrent_max: 20,
    cost_estimate_threshold_usd: 10,
    max_depth: 5,
  },
  heartbeat: {
    timeout_seconds: 300,
    action: "alert",
  },
  pricing_mode: "api",
  max_plan_discount: 0.2,
  dashboard: {
    port: DASHBOARD_PORT,
    auth: {
      enabled: false,
      username: "aegis",
      password: "changeme",
    },
  },
  monitor: {
    health_port: MONITOR_PORT,
    watch_paths: ["~/.claude/projects"],
    poll_interval_ms: 2000,
  },
  alerts: {
    terminal_bell: true,
    webhook_url: null,
  },
  kavach: {
    enabled: true,
    notify_channel: "telegram" as const,
    notify_telegram_chat_id: process.env.KAVACH_TG_CHAT_ID || "",
    notify_phone: process.env.KAVACH_NOTIFY_PHONE || "",
    notify_email: process.env.KAVACH_NOTIFY_EMAIL || "",
    notify_via_webhook: false,
    webhook_url: "",
    timeout_level1_s: 600,
    timeout_level2_s: 300,
    timeout_level3_s: 120,
    timeout_level4_s: 60,
    // [EE] dual_control + slack fields — defaults in ee/core/config-ee.ts
  },
  enforcement: {
    mode: "alert",        // SAFE DEFAULT — never auto-kill. User must opt-in via config.
    excluded_pids: [],
    excluded_ppids: [],
    registry_url: null,
    registry_admin_key: null,
    // Services to auto-restart after a budget kill — add your own infra here
    auto_restart_services: [],
    auto_restart_delay_ms: 3000,  // 3s after kill to let processes clear
  },
};

export function getAegisDir(): string {
  return AEGIS_DIR;
}

export function getDbPath(): string {
  return join(AEGIS_DIR, "aegis.db");
}

export function ensureAegisDir(): void {
  if (!existsSync(AEGIS_DIR)) {
    mkdirSync(AEGIS_DIR, { recursive: true });
  }
}

export function loadConfig(): AegisConfig {
  ensureAegisDir();
  if (!existsSync(CONFIG_PATH)) {
    writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
    return DEFAULT_CONFIG;
  }
  try {
    const raw = readFileSync(CONFIG_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    return { ...DEFAULT_CONFIG, ...parsed, budget: { ...DEFAULT_CONFIG.budget, ...parsed.budget } };
  } catch {
    return DEFAULT_CONFIG;
  }
}

export function saveConfig(config: AegisConfig): void {
  ensureAegisDir();
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

export function resolveWatchPaths(config: AegisConfig): string[] {
  const home = process.env.HOME || "/root";
  return config.monitor.watch_paths.map((p) => p.replace("~", home));
}
