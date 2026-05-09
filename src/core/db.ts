// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

import { Database } from "bun:sqlite";
import { getDbPath, ensureAegisDir } from "./config";
import type { UsageRecord, SessionInfo, BudgetState, AlertEvent, WindowBudget, KavachApproval, KavachDecision } from "./types";
// @rule:KAV-089 — DAN Gate approvals sealed as PRAMANA receipts (lazy import avoids circular dep)
function sealApprovalReceipt(approvalId: string, sessionId: string, decidedBy: string, level: number): void {
  try {
    const { sealKernelViolation } = require("../kernel/kernel-receipt");
    sealKernelViolation({
      session_id: sessionId || approvalId,
      agent_id: null,
      event_type: "DAN_APPROVAL",
      violation_details: JSON.stringify({ approval_id: approvalId, decided_by: decidedBy, level }),
      severity: "WARN",
    });
  } catch { /* non-fatal — witnessing is best-effort; audit log is primary record */ }
}

let _db: Database | null = null;

export function getDb(): Database {
  if (_db) return _db;
  ensureAegisDir();
  _db = new Database(getDbPath(), { create: true });
  _db.exec("PRAGMA journal_mode = WAL");
  _db.exec("PRAGMA busy_timeout = 5000");
  initSchema(_db);
  return _db;
}

function initSchema(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS usage_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      model TEXT,
      input_tokens INTEGER DEFAULT 0,
      output_tokens INTEGER DEFAULT 0,
      cache_read_tokens INTEGER DEFAULT 0,
      cache_creation_tokens INTEGER DEFAULT 0,
      estimated_cost_usd REAL DEFAULT 0,
      is_agent_spawn INTEGER DEFAULT 0,
      raw_json TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      project_path TEXT,
      first_seen TEXT NOT NULL,
      last_activity TEXT NOT NULL,
      total_cost_usd REAL DEFAULT 0,
      message_count INTEGER DEFAULT 0,
      agent_spawns INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS budget_state (
      period TEXT PRIMARY KEY,
      spent_usd REAL DEFAULT 0,
      limit_usd REAL,
      last_updated TEXT
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT,
      session_id TEXT,
      timestamp TEXT NOT NULL,
      acknowledged INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_usage_session ON usage_log(session_id);
    CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON usage_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);

    CREATE TABLE IF NOT EXISTS kavach_approvals (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      command TEXT NOT NULL,
      tool_name TEXT NOT NULL DEFAULT 'Bash',
      level INTEGER NOT NULL,
      consequence TEXT NOT NULL,
      session_id TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      first_approver TEXT,
      decided_at TEXT,
      decided_by TEXT,
      notified INTEGER DEFAULT 0,
      timeout_ms INTEGER NOT NULL DEFAULT 600000
    );

    -- Migration: add first_approver if upgrading from older schema
    CREATE INDEX IF NOT EXISTS idx_kavach_status ON kavach_approvals(status);
    CREATE INDEX IF NOT EXISTS idx_kavach_created ON kavach_approvals(created_at);

    -- Phase 2: durable agent session registry (V2-040)
    -- @rule:KAV-002 Agent check-in, KAV-008 quarantine survives restart, KAV-011 identity
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

    CREATE INDEX IF NOT EXISTS idx_agents_state ON agents(state);
    CREATE INDEX IF NOT EXISTS idx_agents_session ON agents(session_id);
    CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

    -- @rule:KAV-066 — hosted-service detection (V2-101)
    -- Logs each unique IP that accesses the dashboard; watchdog checks distinct IP count
    CREATE TABLE IF NOT EXISTS dashboard_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      path TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_dashboard_access_ip ON dashboard_access(ip);
    CREATE INDEX IF NOT EXISTS idx_dashboard_access_ts ON dashboard_access(timestamp);
  `);

  // Additive migrations for existing databases
  try { db.exec(`ALTER TABLE kavach_approvals ADD COLUMN first_approver TEXT`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN loop_count INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN tools_declared INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN stop_requested INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN budget_pool_reserved REAL DEFAULT 0`); } catch {}
  // @rule:KAV-071 multi-tenant isolation — add tenant_id to all scoped tables
  try { db.exec(`ALTER TABLE agents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`); } catch {}
  try { db.exec(`ALTER TABLE kavach_approvals ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`); } catch {}
  try { db.exec(`ALTER TABLE alerts ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON kavach_approvals(tenant_id)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id)`); } catch {}
  // Desk capture columns — KOS-076 session start hook
  try { db.exec(`ALTER TABLE sessions ADD COLUMN hostname TEXT`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN model TEXT`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN git_remote TEXT`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN ended_at TEXT`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN stop_reason TEXT`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN tool_call_count INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN dan_event_count INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN mudrika_uri TEXT`); } catch {}
  // @rule:BMOS-004 BMOS-Authorize audit log — masks ARE the policy; every check is logged
  try { db.exec(`CREATE TABLE IF NOT EXISTS authorize_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    caller TEXT NOT NULL,
    target TEXT NOT NULL,
    capability TEXT NOT NULL,
    authorized INTEGER NOT NULL,
    caller_mask INTEGER,
    target_required_mask INTEGER,
    result_mask INTEGER,
    latency_us INTEGER,
    called_at TEXT NOT NULL
  )`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_authorize_log_caller ON authorize_log(caller)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_authorize_log_called_at ON authorize_log(called_at)`); } catch {}

  // @rule:KOS-T095 background agent guard — track spawns so Stop hook can warn before kill
  try { db.exec(`CREATE TABLE IF NOT EXISTS background_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    spawned_at TEXT NOT NULL,
    completed_at TEXT,
    description TEXT,
    subagent_type TEXT,
    task_id TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    acknowledged INTEGER NOT NULL DEFAULT 0
  )`); } catch {}
  // Migrate: add columns if table exists without them (idempotent)
  try { db.exec(`ALTER TABLE background_agents ADD COLUMN task_id TEXT`); } catch {}
  try { db.exec(`ALTER TABLE background_agents ADD COLUMN status TEXT NOT NULL DEFAULT 'running'`); } catch {}
  try { db.exec(`ALTER TABLE background_agents ADD COLUMN completed_at TEXT`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_bg_agents_session ON background_agents(session_id)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_bg_agents_task_id ON background_agents(task_id)`); } catch {}

  // @rule:AGS-005 SDT chain store — retains parent tokens for chain validation
  // @rule:AGS-014 retention >= max(child.expiry) + 1hr
  try { db.exec(`CREATE TABLE IF NOT EXISTS sdt_chain_store (
    token_id TEXT PRIMARY KEY,
    chain_hash TEXT NOT NULL UNIQUE,
    token_json TEXT NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    expiry TEXT NOT NULL DEFAULT 'task_end',
    issued_at TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    spawner_id TEXT NOT NULL,
    delegated_mask INTEGER NOT NULL DEFAULT 0,
    max_depth INTEGER NOT NULL DEFAULT 5
  )`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_sdt_chain_hash ON sdt_chain_store(chain_hash)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_sdt_agent_id ON sdt_chain_store(agent_id)`); } catch {}

  // @rule:AGS-010 SDT escalations — human-in-loop pending approvals
  try { db.exec(`CREATE TABLE IF NOT EXISTS sdt_escalations (
    escalation_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    decided_at TEXT
  )`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_sdt_esc_agent ON sdt_escalations(agent_id)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_sdt_esc_status ON sdt_escalations(status)`); } catch {}

  // @rule:AGS-015 SDT authorize audit log — every authorize decision sealed immediately
  try { db.exec(`CREATE TABLE IF NOT EXISTS sdt_authorize_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL UNIQUE,
    agent_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    authorized INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL,
    effective_mask INTEGER NOT NULL DEFAULT 0,
    latency_us INTEGER,
    decided_at TEXT NOT NULL
  )`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_sdt_audit_agent ON sdt_authorize_log(agent_id)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_sdt_audit_decided ON sdt_authorize_log(decided_at)`); } catch {}

  // ASE — Agent Session Envelope columns (additive migration)
  // @rule:ASE-001 sealed_hash is the immutable proof of session birth state
  // @rule:ASE-003 declared_caps is first-class; not derived from policy.tools_allowed
  // @rule:ASE-008 parent_session_id in sealed_hash creates auditable delegation chain
  try { db.exec(`ALTER TABLE agents ADD COLUMN sealed_hash TEXT`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN declared_caps TEXT NOT NULL DEFAULT '[]'`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN parent_session_id TEXT REFERENCES agents(agent_id)`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_issued_at TEXT`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_expires_at TEXT`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_budget_usd REAL DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_budget_used_usd REAL DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_service_key TEXT`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_agent_type TEXT DEFAULT 'hook-native'`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_trust_mask INTEGER DEFAULT 1`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_perm_mask INTEGER DEFAULT 1`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_class_mask INTEGER DEFAULT 65535`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_actual_caps TEXT NOT NULL DEFAULT '[]'`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_drift_detected INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN ase_closed_at TEXT`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_agents_parent_session ON agents(parent_session_id)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_agents_sealed_hash ON agents(sealed_hash)`); } catch {}
  try { db.exec(`CREATE INDEX IF NOT EXISTS idx_agents_service_key ON agents(ase_service_key)`); } catch {}
}

// --- Background agent tracking (KOS-T095) ---

export function recordBackgroundAgent(sessionId: string, description?: string, subagentType?: string, taskId?: string): number {
  const db = getDb();
  const result = db.run(
    "INSERT INTO background_agents (session_id, spawned_at, description, subagent_type, task_id, status) VALUES (?, ?, ?, ?, ?, 'running')",
    [sessionId, new Date().toISOString(), description ?? null, subagentType ?? null, taskId ?? null]
  );
  return result.lastInsertRowid as number;
}

export interface BgAgentRow {
  id: number;
  spawned_at: string;
  completed_at: string | null;
  description: string | null;
  subagent_type: string | null;
  task_id: string | null;
  status: string;
}

export function getUnacknowledgedBgAgents(sessionId: string, windowMinutes = 60): BgAgentRow[] {
  const db = getDb();
  const since = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();
  return db.query(
    "SELECT id, spawned_at, completed_at, description, subagent_type, task_id, status FROM background_agents WHERE session_id=? AND acknowledged=0 AND spawned_at >= ?"
  ).all(sessionId, since) as BgAgentRow[];
}

export function completeBgAgent(taskId: string): void {
  const db = getDb();
  db.run(
    "UPDATE background_agents SET status='completed', completed_at=?, acknowledged=1 WHERE task_id=?",
    [new Date().toISOString(), taskId]
  );
}

export function acknowledgeAllBgAgents(sessionId: string): void {
  const db = getDb();
  db.run("UPDATE background_agents SET acknowledged=1, status=CASE WHEN status='running' THEN 'force-quit' ELSE status END WHERE session_id=?", [sessionId]);
}

export function getAllBgAgents(windowHours = 24): BgAgentRow[] {
  const db = getDb();
  const since = new Date(Date.now() - windowHours * 3600 * 1000).toISOString();
  return db.query(
    "SELECT id, spawned_at, completed_at, description, subagent_type, task_id, status FROM background_agents WHERE spawned_at >= ? ORDER BY spawned_at DESC LIMIT 100"
  ).all(since) as BgAgentRow[];
}

// --- Dashboard access (KAV-066 — hosted-service detection) ---

export function recordDashboardAccess(ip: string, path: string): void {
  const db = getDb();
  db.run("INSERT INTO dashboard_access (ip, timestamp, path) VALUES (?, ?, ?)",
    [ip, new Date().toISOString(), path]);
}

export function getDistinctDashboardIpCount(sinceHours = 24 * 7): number {
  const db = getDb();
  const since = new Date(Date.now() - sinceHours * 60 * 60 * 1000).toISOString();
  const row = db.query(
    "SELECT COUNT(DISTINCT ip) as cnt FROM dashboard_access WHERE timestamp >= ?"
  ).get(since) as any;
  return row?.cnt ?? 0;
}

// --- Usage ---

export function addUsage(record: UsageRecord): void {
  const db = getDb();
  db.run(
    `INSERT INTO usage_log (session_id, timestamp, model, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, estimated_cost_usd, is_agent_spawn, raw_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      record.session_id, record.timestamp, record.model,
      record.input_tokens, record.output_tokens, record.cache_read_tokens, record.cache_creation_tokens,
      record.estimated_cost_usd, record.is_agent_spawn ? 1 : 0, record.raw_json || null,
    ]
  );
}

// --- Sessions ---

export function upsertSession(session_id: string, project_path: string, cost: number, is_spawn: boolean): void {
  const db = getDb();
  const now = new Date().toISOString();
  const existing = db.query("SELECT * FROM sessions WHERE session_id = ?").get(session_id) as any;
  if (existing) {
    db.run(
      `UPDATE sessions SET last_activity = ?, total_cost_usd = total_cost_usd + ?, message_count = message_count + 1,
       agent_spawns = agent_spawns + ? WHERE session_id = ?`,
      [now, cost, is_spawn ? 1 : 0, session_id]
    );
  } else {
    db.run(
      `INSERT INTO sessions (session_id, project_path, first_seen, last_activity, total_cost_usd, message_count, agent_spawns, status)
       VALUES (?, ?, ?, ?, ?, 1, ?, 'active')`,
      [session_id, project_path, now, now, cost, is_spawn ? 1 : 0]
    );
  }
}

export function listActiveSessions(): SessionInfo[] {
  const db = getDb();
  return db.query("SELECT * FROM sessions WHERE status IN ('active', 'paused') ORDER BY last_activity DESC").all() as SessionInfo[];
}

export function getSession(session_id: string): SessionInfo | null {
  const db = getDb();
  return db.query("SELECT * FROM sessions WHERE session_id = ?").get(session_id) as SessionInfo | null;
}

export function setSessionStatus(session_id: string, status: string): void {
  const db = getDb();
  db.run("UPDATE sessions SET status = ? WHERE session_id = ?", [status, session_id]);
}

export function getSessionSpawnCount(session_id: string): number {
  const db = getDb();
  const row = db.query("SELECT agent_spawns FROM sessions WHERE session_id = ?").get(session_id) as any;
  return row?.agent_spawns || 0;
}

// --- Budget ---

function periodKey(type: "daily" | "weekly" | "monthly"): string {
  const now = new Date();
  if (type === "daily") return `daily:${now.toISOString().slice(0, 10)}`;
  if (type === "weekly") {
    const d = new Date(now);
    d.setDate(d.getDate() - d.getDay()); // start of week (Sun)
    return `weekly:${d.toISOString().slice(0, 10)}`;
  }
  return `monthly:${now.toISOString().slice(0, 7)}`;
}

export function addToBudget(cost: number, limits: { daily: number; weekly: number; monthly: number }): void {
  const db = getDb();
  const now = new Date().toISOString();
  for (const [type, limit] of [["daily", limits.daily], ["weekly", limits.weekly], ["monthly", limits.monthly]] as const) {
    const key = periodKey(type);
    const existing = db.query("SELECT * FROM budget_state WHERE period = ?").get(key) as any;
    if (existing) {
      db.run("UPDATE budget_state SET spent_usd = spent_usd + ?, last_updated = ? WHERE period = ?", [cost, now, key]);
    } else {
      db.run("INSERT INTO budget_state (period, spent_usd, limit_usd, last_updated) VALUES (?, ?, ?, ?)", [key, cost, limit, now]);
    }
  }
}

export function getBudgetState(type: "daily" | "weekly" | "monthly", limit: number): BudgetState {
  const db = getDb();
  const key = periodKey(type);
  const row = db.query("SELECT * FROM budget_state WHERE period = ?").get(key) as any;
  const spent = row?.spent_usd || 0;
  return {
    period: key,
    spent_usd: spent,
    limit_usd: limit,
    remaining_usd: Math.max(0, limit - spent),
    percent: limit > 0 ? Math.min(100, (spent / limit) * 100) : 0,
  };
}

export function getDailySpend(): number {
  const db = getDb();
  const key = periodKey("daily");
  const row = db.query("SELECT spent_usd FROM budget_state WHERE period = ?").get(key) as any;
  return row?.spent_usd || 0;
}

// --- Window-based budgets (for Max Plan) ---

// 5-hour windows are rolling — start from when user began using Claude this cycle
// For simplicity: compute usage in the last 5 hours from NOW
export function getWindowBudget(
  window_type: "5h" | "weekly",
  messages_limit: number,
  tokens_limit: number
): WindowBudget {
  const db = getDb();
  const now = Date.now();
  const windowMs = window_type === "5h" ? 5 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
  const windowStart = new Date(now - windowMs).toISOString();
  const windowEnd = new Date(now + windowMs).toISOString(); // rolling — "reset" is now+window

  const row = db.query(`
    SELECT
      COUNT(*) as message_count,
      COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens), 0) as total_tokens
    FROM usage_log
    WHERE timestamp >= ?
  `).get(windowStart) as any;

  const messages_used = row?.message_count || 0;
  const tokens_used = row?.total_tokens || 0;

  const msgPct = messages_limit > 0 ? (messages_used / messages_limit) * 100 : 0;
  const tokPct = tokens_limit > 0 ? (tokens_used / tokens_limit) * 100 : 0;
  const percent = Math.min(100, Math.max(msgPct, tokPct));

  // Time to reset: next 5h window boundary (for rolling, it's when oldest message in window ages out)
  const oldestInWindow = db.query(`
    SELECT MIN(timestamp) as oldest FROM usage_log WHERE timestamp >= ?
  `).get(windowStart) as any;

  let time_to_reset_s = Math.floor(windowMs / 1000);
  if (oldestInWindow?.oldest) {
    const oldestMs = new Date(oldestInWindow.oldest).getTime();
    time_to_reset_s = Math.max(0, Math.floor((oldestMs + windowMs - now) / 1000));
  }

  return {
    window_type,
    window_start: windowStart,
    window_end: windowEnd,
    messages_used,
    messages_limit,
    tokens_used,
    tokens_limit,
    percent,
    time_to_reset_s,
  };
}

// --- Alerts ---

export function addAlert(alert: Omit<AlertEvent, "id" | "acknowledged">): void {
  const db = getDb();
  db.run(
    "INSERT INTO alerts (type, severity, message, session_id, timestamp, acknowledged) VALUES (?, ?, ?, ?, ?, 0)",
    [alert.type, alert.severity, alert.message, alert.session_id || null, alert.timestamp]
  );
}

export function getRecentAlerts(limit: number = 50): AlertEvent[] {
  const db = getDb();
  return db.query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?").all(limit) as AlertEvent[];
}

// --- KAVACH Approvals (@rule:KAV-052) ---

export function createKavachApproval(approval: Omit<KavachApproval, "decided_at" | "decided_by" | "notified" | "status" | "first_approver">): KavachApproval {
  const db = getDb();
  const record: KavachApproval = {
    ...approval,
    status: "pending",
    first_approver: null,
    decided_at: null,
    decided_by: null,
    notified: false,
  };
  db.run(
    `INSERT INTO kavach_approvals (id, created_at, command, tool_name, level, consequence, session_id, status, first_approver, decided_at, decided_by, notified, timeout_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL, 0, ?)`,
    [record.id, record.created_at, record.command, record.tool_name, record.level, record.consequence, record.session_id, record.timeout_ms]
  );
  return record;
}

export function getKavachApproval(id: string): KavachApproval | null {
  const db = getDb();
  return db.query("SELECT * FROM kavach_approvals WHERE id = ?").get(id) as KavachApproval | null;
}

export function getPendingApprovals(): KavachApproval[] {
  const db = getDb();
  // Both 'pending' and 'pending_second' are active — need human action
  return db.query(
    "SELECT * FROM kavach_approvals WHERE status IN ('pending', 'pending_second') ORDER BY created_at DESC"
  ).all() as KavachApproval[];
}

// @rule:KAV-060 — Dual-control state machine for L4
// L4 + dual_control: pending → ALLOW → pending_second → ALLOW (different approver) → allowed
// Any STOP at any stage → stopped immediately
// L1-L3 or dual_control disabled: pending → ALLOW → allowed (standard)
export function decideKavachApproval(
  id: string,
  decision: KavachDecision,
  decidedBy: string,
  opts: { dual_control: boolean; require_different_approvers: boolean } = { dual_control: false, require_different_approvers: false }
): boolean {
  const db = getDb();
  const now = new Date().toISOString();
  const approval = getKavachApproval(id);
  if (!approval) return false;

  // STOP is always immediate regardless of stage or level
  if (decision === "STOP" || decision === "TIMEOUT") {
    const status = decision === "STOP" ? "stopped" : "timed_out";
    const result = db.run(
      "UPDATE kavach_approvals SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status IN ('pending', 'pending_second')",
      [status, now, decidedBy, id]
    );
    return (result.changes ?? 0) > 0;
  }

  if (decision === "EXPLAIN") {
    const result = db.run(
      "UPDATE kavach_approvals SET status = 'explained', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'",
      [now, decidedBy, id]
    );
    return (result.changes ?? 0) > 0;
  }

  // ALLOW — check dual-control
  if (approval.status === "pending") {
    const isDualControl = opts.dual_control && approval.level === 4;
    if (isDualControl) {
      // First ALLOW — move to pending_second, record first_approver
      const result = db.run(
        "UPDATE kavach_approvals SET status = 'pending_second', first_approver = ? WHERE id = ? AND status = 'pending'",
        [decidedBy, id]
      );
      return (result.changes ?? 0) > 0;
    }
    // Standard: first ALLOW = done
    const result = db.run(
      "UPDATE kavach_approvals SET status = 'allowed', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'",
      [now, decidedBy, id]
    );
    if ((result.changes ?? 0) > 0) {
      // @rule:KAV-089 seal PRAMANA receipt for this human approval
      sealApprovalReceipt(id, approval.session_id, decidedBy, approval.level);
      return true;
    }
    return false;
  }

  if (approval.status === "pending_second" && decision === "ALLOW") {
    // Second ALLOW — enforce different approver if EE flag set
    if (opts.require_different_approvers && approval.first_approver === decidedBy) {
      return false; // same person can't be both approvers in EE mode
    }
    const result = db.run(
      "UPDATE kavach_approvals SET status = 'allowed', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending_second'",
      [now, decidedBy, id]
    );
    if ((result.changes ?? 0) > 0) {
      // @rule:KAV-089 second approver in dual-control — seal PRAMANA receipt for final approval
      sealApprovalReceipt(id, approval.session_id, decidedBy, approval.level);
      return true;
    }
    return false;
  }

  return false;
}

export function markKavachNotified(id: string): void {
  const db = getDb();
  db.run("UPDATE kavach_approvals SET notified = 1 WHERE id = ?", [id]);
}

export function getRecentApprovals(limit = 20): KavachApproval[] {
  const db = getDb();
  return db.query("SELECT * FROM kavach_approvals ORDER BY created_at DESC LIMIT ?").all(limit) as KavachApproval[];
}

export interface KavachAuditFilter {
  session_id?: string | null;
  status?: string | null;
  level?: number | null;
  limit?: number;
}

export function queryKavachAudit(filter: KavachAuditFilter = {}): { records: KavachApproval[]; total: number } {
  const db = getDb();
  const { session_id, status, level, limit = 50 } = filter;

  const conditions: string[] = [];
  const params: (string | number)[] = [];

  if (session_id) { conditions.push("session_id = ?"); params.push(session_id); }
  if (status) { conditions.push("status = ?"); params.push(status); }
  if (level != null && !isNaN(level)) { conditions.push("level = ?"); params.push(level); }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const cap = Math.min(limit, 500);

  const records = db.query(
    `SELECT id, created_at, command, tool_name, level, consequence, session_id, status, decided_at, decided_by
     FROM kavach_approvals ${where} ORDER BY created_at DESC LIMIT ?`
  ).all(...params, cap) as KavachApproval[];

  const countRow = db.query(`SELECT COUNT(*) as cnt FROM kavach_approvals ${where}`).get(...params) as { cnt: number } | null;

  return { records, total: countRow?.cnt ?? records.length };
}

// --- Phase 2: Agent Registry (V2-040..048) ---

export interface AgentRow {
  agent_id: string;
  state: string;
  identity_confidence: string;
  parent_id: string | null;
  session_id: string;
  depth: number;
  budget_cap_usd: number;
  budget_used_usd: number;
  budget_pool_reserved: number;
  tool_calls: number;
  loop_count: number;
  tools_declared: number;
  violation_count: number;
  spawn_timestamp: string;
  last_seen: string;
  policy_path: string | null;
  stop_requested: number;   // 0 or 1
  quarantine_reason: string | null;
  quarantine_rule: string | null;
  release_reason: string | null;
  released_by: string | null;
  resume_manifest_path: string | null;
}

/** Upsert agent into durable DB registry (V2-040, V2-047). */
export function upsertAgent(agent: AgentRow): void {
  const db = getDb();
  db.run(
    `INSERT INTO agents (
      agent_id, state, identity_confidence, parent_id, session_id, depth,
      budget_cap_usd, budget_used_usd, budget_pool_reserved,
      tool_calls, loop_count, tools_declared, violation_count,
      spawn_timestamp, last_seen, policy_path, stop_requested,
      quarantine_reason, quarantine_rule, release_reason, released_by, resume_manifest_path
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(agent_id) DO UPDATE SET
      state = excluded.state,
      identity_confidence = excluded.identity_confidence,
      parent_id = excluded.parent_id,
      budget_used_usd = excluded.budget_used_usd,
      budget_pool_reserved = excluded.budget_pool_reserved,
      tool_calls = excluded.tool_calls,
      loop_count = excluded.loop_count,
      tools_declared = excluded.tools_declared,
      violation_count = excluded.violation_count,
      last_seen = excluded.last_seen,
      stop_requested = excluded.stop_requested,
      quarantine_reason = excluded.quarantine_reason,
      quarantine_rule = excluded.quarantine_rule,
      release_reason = excluded.release_reason,
      released_by = excluded.released_by,
      resume_manifest_path = excluded.resume_manifest_path`,
    [
      agent.agent_id, agent.state, agent.identity_confidence, agent.parent_id, agent.session_id, agent.depth,
      agent.budget_cap_usd, agent.budget_used_usd, agent.budget_pool_reserved,
      agent.tool_calls, agent.loop_count, agent.tools_declared, agent.violation_count,
      agent.spawn_timestamp, agent.last_seen, agent.policy_path, agent.stop_requested ? 1 : 0,
      agent.quarantine_reason, agent.quarantine_rule, agent.release_reason, agent.released_by, agent.resume_manifest_path,
    ]
  );
}

/** V2-041 — update last_seen + tool_calls counter on PreToolUse. */
export function touchAgent(agentId: string): void {
  const db = getDb();
  const now = new Date().toISOString();
  db.run(
    "UPDATE agents SET last_seen = ?, tool_calls = tool_calls + 1, loop_count = loop_count + 1 WHERE agent_id = ? AND state = 'RUNNING'",
    [now, agentId]
  );
}

// @rule:KAV-008 — quarantine state is durable across KAVACH restarts; SQLite agents table persists it
/** V2-047 — set state (quarantine durability). */
export function setAgentState(
  agentId: string,
  state: string,
  meta: { reason?: string; rule?: string; released_by?: string; resume_manifest_path?: string } = {}
): void {
  const db = getDb();
  const now = new Date().toISOString();
  db.run(
    `UPDATE agents SET state = ?, last_seen = ?,
      quarantine_reason = CASE WHEN ? = 'QUARANTINED' THEN ? ELSE quarantine_reason END,
      quarantine_rule   = CASE WHEN ? = 'QUARANTINED' THEN ? ELSE quarantine_rule END,
      release_reason    = CASE WHEN ? = 'RUNNING' THEN ? ELSE release_reason END,
      released_by       = CASE WHEN ? = 'RUNNING' THEN ? ELSE released_by END,
      resume_manifest_path = COALESCE(?, resume_manifest_path)
     WHERE agent_id = ?`,
    [
      state, now,
      state, meta.reason ?? null,
      state, meta.rule ?? null,
      state, meta.reason ?? null,
      state, meta.released_by ?? null,
      meta.resume_manifest_path ?? null,
      agentId,
    ]
  );
}

/** V2-048 — set stop_requested flag (L1 Soft Stop signal). */
export function requestStop(agentId: string): void {
  const db = getDb();
  db.run("UPDATE agents SET stop_requested = 1 WHERE agent_id = ?", [agentId]);
}

// @rule:BMOS-008 Revocation via expiry: set ase_expires_at = now → immediate credential expiry
// Subsequent tool calls and spawn attempts will be blocked by the expiry gate (BMOS-T-018).
export function revokeAgentExpiry(agentId: string): { revoked: boolean; expires_at: string } {
  const db = getDb();
  const now = new Date().toISOString();
  db.run("UPDATE agents SET ase_expires_at = ? WHERE agent_id = ?", [now, agentId]);
  const changed = db.query("SELECT changes() as n").get() as { n: number };
  return { revoked: changed.n > 0, expires_at: now };
}

/** V2-048 — check if stop_requested is set for this agent. */
export function isStopRequested(agentId: string): boolean {
  const db = getDb();
  const row = db.query("SELECT stop_requested FROM agents WHERE agent_id = ?").get(agentId) as { stop_requested: number } | null;
  return (row?.stop_requested ?? 0) === 1;
}

export function getAgentRow(agentId: string): AgentRow | null {
  const db = getDb();
  return db.query("SELECT * FROM agents WHERE agent_id = ?").get(agentId) as AgentRow | null;
}

export function listAgentRows(): AgentRow[];
export function listAgentRows(states: string[]): AgentRow[];
export function listAgentRows(states?: string[]): AgentRow[] {
  const db = getDb();
  if (!states || states.length === 0) {
    return db.query("SELECT * FROM agents ORDER BY spawn_timestamp DESC").all() as AgentRow[];
  }
  const placeholders = states.map(() => "?").join(",");
  return db.query(`SELECT * FROM agents WHERE state IN (${placeholders}) ORDER BY spawn_timestamp DESC`).all(...states) as AgentRow[];
}

export function incrementViolationCount(agentId: string): number {
  const db = getDb();
  db.run("UPDATE agents SET violation_count = violation_count + 1 WHERE agent_id = ?", [agentId]);
  const row = db.query("SELECT violation_count FROM agents WHERE agent_id = ?").get(agentId) as { violation_count: number } | null;
  return row?.violation_count ?? 0;
}

// --- Phase 3: Cost Attribution (V2-060..065) ---

/**
 * V2-060 — Record AI token usage for an agent, update budget_used_usd.
 * Called by AI Proxy intercept or PostToolUse hook.
 */
export function recordAgentUsage(opts: {
  agent_id: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens?: number;
  cache_creation_tokens?: number;
  cost_usd: number;
}): void {
  const db = getDb();
  const now = new Date().toISOString();
  db.run(
    "UPDATE agents SET budget_used_usd = budget_used_usd + ? WHERE agent_id = ?",
    [opts.cost_usd, opts.agent_id]
  );
  // Also record in usage_log for historical querying
  db.run(
    `INSERT INTO usage_log (session_id, timestamp, model, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, estimated_cost_usd, is_agent_spawn, raw_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    [
      opts.agent_id, now, opts.model,
      opts.input_tokens, opts.output_tokens,
      opts.cache_read_tokens ?? 0, opts.cache_creation_tokens ?? 0,
      opts.cost_usd, null,
    ]
  );
}

/**
 * V2-062 — Atomic budget inheritance check at spawn.
 * Returns null if OK, or error string if spawn would exceed parent budget.
 * @rule:KAV-018 Budget inheritance enforcement
 */
export function checkBudgetInheritance(opts: {
  parent_id: string;
  child_cap_usd: number;
}): { allowed: boolean; error?: string } {
  if (opts.child_cap_usd <= 0) return { allowed: true }; // no cap = inherit parent
  const db = getDb();
  const parent = db.query("SELECT budget_cap_usd, budget_used_usd, budget_pool_reserved FROM agents WHERE agent_id = ?").get(opts.parent_id) as { budget_cap_usd: number; budget_used_usd: number; budget_pool_reserved: number } | null;
  if (!parent) return { allowed: true }; // parent not in registry = no constraint

  const parentRemaining = parent.budget_cap_usd - parent.budget_used_usd - parent.budget_pool_reserved;
  if (parentRemaining < opts.child_cap_usd) {
    return {
      allowed: false,
      error: `Budget inheritance rejected: parent ${opts.parent_id} remaining $${parentRemaining.toFixed(4)} < child cap $${opts.child_cap_usd.toFixed(4)} (KAV-018)`,
    };
  }

  // Reserve the child's cap from parent pool
  db.run(
    "UPDATE agents SET budget_pool_reserved = budget_pool_reserved + ? WHERE agent_id = ?",
    [opts.child_cap_usd, opts.parent_id]
  );
  return { allowed: true };
}

/**
 * V2-063 — Return unused budget to parent pool on agent close/force-close.
 * @rule:KAV-003 Budget pool rebalancing
 */
export function rebalanceBudget(agentId: string): void {
  const db = getDb();
  const agent = db.query("SELECT parent_id, budget_cap_usd, budget_used_usd FROM agents WHERE agent_id = ?").get(agentId) as { parent_id: string | null; budget_cap_usd: number; budget_used_usd: number } | null;
  if (!agent || !agent.parent_id || agent.budget_cap_usd <= 0) return;

  const unused = Math.max(0, agent.budget_cap_usd - agent.budget_used_usd);
  if (unused <= 0) return;

  // Release reservation from parent + credit unused back
  db.run(
    `UPDATE agents SET
      budget_pool_reserved = MAX(0, budget_pool_reserved - ?),
      budget_used_usd = budget_used_usd + ?
     WHERE agent_id = ?`,
    [agent.budget_cap_usd, -unused, agent.parent_id]
  );
}

/**
 * V2-064 — EWMA projected cost for an agent.
 * α=0.3 exponential weighted moving average of per-call cost.
 * Returns { projected_total, pct_of_cap, alert_level }.
 */
export function getAgentCostProjection(agentId: string): {
  budget_used_usd: number;
  budget_cap_usd: number;
  projected_total_usd: number;
  pct_of_cap: number;
  alert_level: "ok" | "warn" | "soft_stop";
} | null {
  const db = getDb();
  const agent = db.query("SELECT budget_cap_usd, budget_used_usd, tool_calls FROM agents WHERE agent_id = ?").get(agentId) as { budget_cap_usd: number; budget_used_usd: number; tool_calls: number } | null;
  if (!agent || agent.budget_cap_usd <= 0) return null;

  const avgCostPerCall = agent.tool_calls > 0 ? agent.budget_used_usd / agent.tool_calls : 0;
  // EWMA: simple projection assuming remaining calls ≈ calls so far (linear model)
  const projected = agent.budget_used_usd + (avgCostPerCall * agent.tool_calls * 0.3);
  const pct = (projected / agent.budget_cap_usd) * 100;

  return {
    budget_used_usd: agent.budget_used_usd,
    budget_cap_usd: agent.budget_cap_usd,
    projected_total_usd: projected,
    pct_of_cap: pct,
    alert_level: pct >= 95 ? "soft_stop" : pct >= 80 ? "warn" : "ok",
  };
}

/**
 * V2-066 — Cost attribution tree for a session.
 * Returns nested agent tree with budget breakdown per agent.
 */
export interface CostTreeNode {
  agent_id: string;
  state: string;
  depth: number;
  budget_cap_usd: number;
  budget_used_usd: number;
  budget_pool_reserved: number;
  tool_calls: number;
  violation_count: number;
  children: CostTreeNode[];
}

export function getCostTree(sessionId?: string): CostTreeNode[] {
  const db = getDb();
  const rows = sessionId
    ? (db.query("SELECT * FROM agents WHERE session_id = ? ORDER BY depth, spawn_timestamp").all(sessionId) as AgentRow[])
    : (db.query("SELECT * FROM agents ORDER BY depth, spawn_timestamp DESC LIMIT 200").all() as AgentRow[]);

  // Build tree from flat list
  const nodeMap = new Map<string, CostTreeNode>();
  const roots: CostTreeNode[] = [];

  for (const row of rows) {
    const node: CostTreeNode = {
      agent_id: row.agent_id,
      state: row.state,
      depth: row.depth,
      budget_cap_usd: row.budget_cap_usd,
      budget_used_usd: row.budget_used_usd,
      budget_pool_reserved: row.budget_pool_reserved,
      tool_calls: row.tool_calls,
      violation_count: row.violation_count,
      children: [],
    };
    nodeMap.set(row.agent_id, node);
  }

  for (const row of rows) {
    const node = nodeMap.get(row.agent_id)!;
    if (row.parent_id && nodeMap.has(row.parent_id)) {
      nodeMap.get(row.parent_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots;
}
