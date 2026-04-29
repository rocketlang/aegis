import { Database } from "bun:sqlite";
import { getDbPath, ensureAegisDir } from "./config";
import type { UsageRecord, SessionInfo, BudgetState, AlertEvent, WindowBudget, KavachApproval, KavachDecision } from "./types";

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
  `);

  // Additive migrations for existing databases
  try { db.exec(`ALTER TABLE kavach_approvals ADD COLUMN first_approver TEXT`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN loop_count INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN tools_declared INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN stop_requested INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE agents ADD COLUMN budget_pool_reserved REAL DEFAULT 0`); } catch {}
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
    return (result.changes ?? 0) > 0;
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
    return (result.changes ?? 0) > 0;
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

export function listAgentRows(states?: string[]): AgentRow[];
export function listAgentRows(states: string[]): AgentRow[] {
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
