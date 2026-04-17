import { Database } from "bun:sqlite";
import { getDbPath, ensureAegisDir } from "./config";
import type { UsageRecord, SessionInfo, BudgetState, AlertEvent, WindowBudget } from "./types";

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
  `);
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
