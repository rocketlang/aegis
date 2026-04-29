// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Test Harness — isolated per-scenario HOME directory
// Each TestHarness instance gets HOME=/tmp/aegis-test-{name}, so every subprocess
// (hook, command, watchdog) reads its own DB + config with no cross-test contamination.

import { Database } from "bun:sqlite";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "fs";

export interface HookResult {
  exitCode: number;
  stderr: string;
  stdout: string;
}

// Minimal schema tables needed for test scenarios — mirrors initSchema() in db.ts
const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS budget_state (
    period TEXT PRIMARY KEY, spent_usd REAL DEFAULT 0, limit_usd REAL, last_updated TEXT
  );
  CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    state TEXT NOT NULL DEFAULT 'RUNNING',
    identity_confidence TEXT NOT NULL DEFAULT 'unknown',
    parent_id TEXT,
    session_id TEXT NOT NULL,
    depth INTEGER DEFAULT 0,
    budget_cap_usd REAL DEFAULT 0,
    budget_used_usd REAL DEFAULT 0,
    budget_pool_reserved REAL DEFAULT 0,
    tool_calls INTEGER DEFAULT 0,
    loop_count INTEGER DEFAULT 0,
    tools_declared INTEGER DEFAULT 0,
    violation_count INTEGER DEFAULT 0,
    spawn_timestamp TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    policy_path TEXT,
    stop_requested INTEGER DEFAULT 0,
    quarantine_reason TEXT,
    quarantine_rule TEXT,
    release_reason TEXT,
    released_by TEXT,
    resume_manifest_path TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY, project_path TEXT,
    first_seen TEXT NOT NULL, last_activity TEXT NOT NULL,
    total_cost_usd REAL DEFAULT 0, message_count INTEGER DEFAULT 0,
    agent_spawns INTEGER DEFAULT 0, status TEXT DEFAULT 'active'
  );
  CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL, model TEXT,
    input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0,
    cache_read_tokens INTEGER DEFAULT 0, cache_creation_tokens INTEGER DEFAULT 0,
    estimated_cost_usd REAL DEFAULT 0, is_agent_spawn INTEGER DEFAULT 0, raw_json TEXT
  );
  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, severity TEXT NOT NULL,
    message TEXT, session_id TEXT, timestamp TEXT NOT NULL, acknowledged INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS kavach_approvals (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, command TEXT NOT NULL,
    tool_name TEXT NOT NULL DEFAULT 'Bash', level INTEGER NOT NULL,
    consequence TEXT NOT NULL, session_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending', first_approver TEXT,
    decided_at TEXT, decided_by TEXT, notified INTEGER DEFAULT 0, timeout_ms INTEGER DEFAULT 300000
  );
  CREATE TABLE IF NOT EXISTS dashboard_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, timestamp TEXT NOT NULL, path TEXT
  );
`;

interface ConfigOverrides {
  enforcement?: { mode?: "alert" | "enforce" };
  budget?: { daily_limit_usd?: number; weekly_limit_usd?: number; monthly_limit_usd?: number; spawn_limit_per_session?: number; max_depth?: number; cost_estimate_threshold_usd?: number };
  heartbeat?: { timeout_seconds?: number; action?: string };
  kavach?: { enabled?: boolean };
}

function buildConfig(overrides: ConfigOverrides): Record<string, unknown> {
  return {
    plan: "api",
    pricing_mode: "api",
    max_plan_discount: 1.0,
    budget: {
      daily_limit_usd: 100,
      weekly_limit_usd: 400,
      monthly_limit_usd: 1200,
      session_limit_usd: 25,
      messages_per_5h: 225,
      tokens_per_5h: 50_000_000,
      weekly_messages: 3150,
      weekly_tokens: 700_000_000,
      spawn_limit_per_session: 50,
      spawn_concurrent_max: 20,
      cost_estimate_threshold_usd: 0.01,
      max_depth: 5,
      ...overrides.budget,
    },
    heartbeat: { timeout_seconds: 300, action: "alert", ...overrides.heartbeat },
    dashboard: { port: 14850, auth: { enabled: false, username: "aegis", password: "test" } },
    monitor: { health_port: 14851, watch_paths: [], poll_interval_ms: 60000 },
    alerts: { terminal_bell: false, webhook_url: null },
    kavach: {
      enabled: true,
      notify_channel: "telegram",
      notify_telegram_chat_id: "",
      notify_phone: "",
      notify_email: "",
      notify_via_webhook: false,
      webhook_url: "",
      timeout_level1_s: 1,
      timeout_level2_s: 1,
      timeout_level3_s: 1,
      timeout_level4_s: 1,
      dual_control_enabled: false,
      dual_control_second_chat_id: "",
      dual_control_second_channel: "telegram",
      dual_control_require_different_approvers: false,
      slack_enabled: false,
      slack_webhook_url: null,
      slack_channel: null,
      slack_username: "AEGIS",
      slack_icon_emoji: ":shield:",
      ...overrides.kavach,
    },
    enforcement: {
      mode: "alert",
      excluded_pids: [],
      excluded_ppids: [],
      registry_url: null,
      registry_admin_key: null,
      auto_restart_services: [],
      auto_restart_delay_ms: 0,
      ...overrides.enforcement,
    },
  };
}

export class TestHarness {
  readonly name: string;
  readonly home: string;
  readonly aegisDir: string;
  readonly dbPath: string;
  readonly configPath: string;

  constructor(name: string) {
    this.name = name;
    this.home = `/tmp/aegis-test-${name}`;
    this.aegisDir = `${this.home}/.aegis`;
    this.dbPath = `${this.aegisDir}/aegis.db`;
    this.configPath = `${this.aegisDir}/config.json`;
  }

  setup(overrides: ConfigOverrides = {}): this {
    mkdirSync(this.aegisDir, { recursive: true });
    writeFileSync(this.configPath, JSON.stringify(buildConfig(overrides), null, 2));
    // Init schema by opening and closing a fresh DB
    const db = new Database(this.dbPath, { create: true });
    db.exec("PRAGMA journal_mode = WAL");
    db.exec(SCHEMA_SQL);
    db.close();
    return this;
  }

  // Direct SQLite access — bypasses the module singleton in db.ts
  // Uses create:true (bun:sqlite create:false has a bug where it throws even for existing files)
  seedDb(fn: (db: Database) => void): this {
    const db = new Database(this.dbPath);
    db.exec("PRAGMA journal_mode = WAL");
    fn(db);
    db.close();
    return this;
  }

  queryDb<T = unknown>(sql: string, ...args: unknown[]): T[] {
    const db = new Database(this.dbPath);
    const rows = db.query(sql).all(...args) as T[];
    db.close();
    return rows;
  }

  writeFile(relativePath: string, content: string): this {
    const full = `${this.aegisDir}/${relativePath}`;
    mkdirSync(full.slice(0, full.lastIndexOf("/")), { recursive: true });
    writeFileSync(full, content);
    return this;
  }

  // Spawn a hook subprocess with HOME pointing to this isolated dir.
  // Routes through cli/index.ts so the default export function is actually called.
  // Passes json as stdin bytes — avoids bun FileSink timing issues with /dev/stdin reads.
  async callHook(
    hookName: string,
    json: Record<string, unknown> = {},
    extraEnv: Record<string, string> = {},
  ): Promise<HookResult> {
    const stdinBytes = Buffer.from(JSON.stringify(json));
    const proc = Bun.spawn(["bun", "src/cli/index.ts", hookName], {
      cwd: "/root/aegis",
      stdin: stdinBytes,
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, HOME: this.home, ...extraEnv },
    });

    const [exitCode, stderr, stdout] = await Promise.all([
      proc.exited,
      new Response(proc.stderr).text(),
      new Response(proc.stdout).text(),
    ]);

    return { exitCode: exitCode ?? 0, stderr, stdout };
  }

  cleanup(): void {
    if (existsSync(this.home)) rmSync(this.home, { recursive: true, force: true });
  }
}

// Today's period key — mirrors periodKey("daily") in db.ts
export function dailyPeriodKey(): string {
  return `daily:${new Date().toISOString().slice(0, 10)}`;
}

export function now(): string {
  return new Date().toISOString();
}

export function minutesAgo(n: number): string {
  return new Date(Date.now() - n * 60_000).toISOString();
}
