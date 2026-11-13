// SPDX-License-Identifier: AGPL-3.0-only
// AEGIS — visitor scope: the governor that holds our own agents to their scope holds VISITING principals to theirs.
//
// Designed 13 Nov 2026 (proposals/aegis-aface-pilot--brainstorm--formal--2026-11-13.md §7; founder rulings B1-B4).
// A visiting principal is a signed-in user of one of our products (`user:<id>`) or an agent a person granted through
// the sign-in connector (`grant:<id>`). Each has a scope (capability list), a daily turn budget, an optional expiry and
// a quarantine switch. Products ask one question per costly act: may this principal spend `cost` turns on this
// capability now? The answer is ALLOW or REFUSE with a reason; every decision is logged.
//
//   B1  own table, same shape as `agents` (our own agents' kill switch stays apart from strangers' rows)
//   B2  a per-product token opens only the visitor gate route (see VISITOR_GATE_ROUTE, visitorTokenFor)
//   B3  one turn per model call or outward send; reads are not asked about (nginx budgets them)
//   B4  the product waits at most 300 ms; past that its own floor decides
//
// A principal never sets its own scope: a `user:` row is created with the product's default scope; a `grant:` row
// must already exist (written when a person grants it), otherwise the answer is REFUSE.
// @rule:AFACE-010
import { timingSafeEqual } from "crypto";
import type { SqlDb } from "../core/sqlite.js";

export const VISITOR_GATE_ROUTE = "/api/v2/visitor/gate";
export const VISITOR_TOKEN_MIN = 24;

export interface ProductPolicy { default_scope: string[]; daily_turns: number }

/** Built-in policy for the pilot product; `visitor.products` in ~/.aegis/config.json overrides or adds. */
export const DEFAULT_PRODUCTS: Record<string, ProductPolicy> = {
  "mari8x-legal": {
    default_scope: ["MARI_CHAT", "MARI_OFFICE", "CP_RISK_SCAN", "SWIFT_MT700", "CLAIM_INGEST", "LC_PRESENTATION", "EMAIL_LOI"],
    daily_turns: 50,
  },
};

export interface VisitorRow {
  product: string; principal: string; org: string | null; scope: string; daily_turns: number;
  turns_today: number; day: string; quarantine_reason: string | null; granted_by: string | null;
  expires_at: string | null; created_at: string; last_seen: string;
}

export interface VisitorDecision {
  decision: "ALLOW" | "REFUSE"; reason: string; rule: string;
  product: string; principal: string; capability: string; cost: number;
  turns_today: number; daily_turns: number;
}

export function ensureVisitorTables(db: SqlDb): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS visitor_principals (
      product TEXT NOT NULL,
      principal TEXT NOT NULL,
      org TEXT,
      scope TEXT NOT NULL DEFAULT '[]',
      daily_turns INTEGER NOT NULL DEFAULT 0,
      turns_today INTEGER NOT NULL DEFAULT 0,
      day TEXT NOT NULL DEFAULT '',
      quarantine_reason TEXT,
      quarantined_by TEXT,
      release_reason TEXT,
      released_by TEXT,
      granted_by TEXT,
      expires_at TEXT,
      created_at TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      PRIMARY KEY (product, principal)
    );
    CREATE TABLE IF NOT EXISTS visitor_decisions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      product TEXT NOT NULL,
      principal TEXT NOT NULL,
      capability TEXT NOT NULL,
      cost INTEGER NOT NULL,
      decision TEXT NOT NULL,
      reason TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_visitor_decisions_ts ON visitor_decisions(ts);
    CREATE INDEX IF NOT EXISTS idx_visitor_decisions_principal ON visitor_decisions(product, principal);
  `);
}

const PRINCIPAL = /^(user|grant):[A-Za-z0-9._@:-]{1,128}$/;
const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CAP = /^[A-Z][A-Z0-9_]{0,63}$/;

/** The product whose token this is, compared in constant time; null if none matches. */
export function visitorTokenFor(authorization: string | undefined, tokens: unknown): string | null {
  if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) return null;
  if (!tokens || typeof tokens !== "object") return null;
  const given = Buffer.from(authorization.slice(7), "utf8");
  let found: string | null = null;
  for (const [product, tok] of Object.entries(tokens as Record<string, unknown>)) {
    if (typeof tok !== "string" || tok.length < VISITOR_TOKEN_MIN || /\s/.test(tok)) continue;
    const want = Buffer.from(tok, "utf8");
    if (given.length === want.length && timingSafeEqual(given, want)) found = product; // no early exit: same time per token
  }
  return found;
}

export function policyFor(product: string, overrides: unknown): ProductPolicy | null {
  const o = (overrides && typeof overrides === "object" ? (overrides as Record<string, any>)[product] : undefined);
  const base = DEFAULT_PRODUCTS[product];
  if (!o && !base) return null;
  const scope = Array.isArray(o?.default_scope) ? o.default_scope.filter((c: unknown) => typeof c === "string" && CAP.test(c)) : base?.default_scope ?? [];
  const turns = Number.isInteger(o?.daily_turns) && o.daily_turns > 0 ? o.daily_turns : base?.daily_turns ?? 0;
  return { default_scope: scope, daily_turns: turns };
}

function log(db: SqlDb, d: VisitorDecision, now: Date): VisitorDecision {
  db.prepare(`INSERT INTO visitor_decisions (ts, product, principal, capability, cost, decision, reason) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(now.toISOString(), d.product, d.principal, d.capability, d.cost, d.decision, d.reason);
  return d;
}

export interface GateInput { product: string; principal: string; capability: string; cost?: number; org?: string | null }

/**
 * Decide one visit. `tokenProduct` is the product the presenting token belongs to; it must equal `input.product`.
 * Validation failures are thrown as { status, error } for the route to send; every real decision is logged.
 */
export function decideVisit(db: SqlDb, tokenProduct: string, input: GateInput, overrides: unknown, now = new Date()): VisitorDecision {
  const product = String(input?.product ?? ""), principal = String(input?.principal ?? ""), capability = String(input?.capability ?? "");
  const cost = input?.cost === undefined ? 1 : Number(input.cost);
  if (!NAME.test(product) || !PRINCIPAL.test(principal) || !CAP.test(capability) || !Number.isInteger(cost) || cost < 1 || cost > 10) {
    throw { status: 400, error: "product, principal (user:… or grant:…), capability (UPPER_CASE) and cost 1-10 are required" };
  }
  if (tokenProduct !== product) throw { status: 403, error: "this token is not for that product" };
  const policy = policyFor(product, overrides);
  const base = { product, principal, capability, cost };
  const today = now.toISOString().slice(0, 10), ts = now.toISOString();
  if (!policy) return log(db, { ...base, decision: "REFUSE", reason: "product has no visitor policy", rule: "visitor:no-policy", turns_today: 0, daily_turns: 0 }, now);

  let row = db.prepare<VisitorRow>(`SELECT * FROM visitor_principals WHERE product = ? AND principal = ?`).get(product, principal);
  if (!row) {
    if (principal.startsWith("grant:")) {
      return log(db, { ...base, decision: "REFUSE", reason: "no grant on record: a person grants an agent its scope; it never names its own", rule: "visitor:no-grant", turns_today: 0, daily_turns: 0 }, now);
    }
    db.prepare(`INSERT INTO visitor_principals (product, principal, org, scope, daily_turns, turns_today, day, created_at, last_seen) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`)
      .run(product, principal, input.org ?? null, JSON.stringify(policy.default_scope), policy.daily_turns, today, ts, ts);
    row = db.prepare<VisitorRow>(`SELECT * FROM visitor_principals WHERE product = ? AND principal = ?`).get(product, principal)!;
  }
  const turnsToday = row.day === today ? row.turns_today : 0;
  const counts = { turns_today: turnsToday, daily_turns: row.daily_turns };
  if (row.quarantine_reason) return log(db, { ...base, ...counts, decision: "REFUSE", reason: `quarantined: ${row.quarantine_reason}`, rule: "visitor:quarantined" }, now);
  if (row.expires_at && row.expires_at <= ts) return log(db, { ...base, ...counts, decision: "REFUSE", reason: "grant expired", rule: "visitor:expired" }, now);
  let scope: string[] = [];
  try { scope = JSON.parse(row.scope); } catch { /* unreadable scope = empty scope */ }
  if (!scope.includes(capability)) return log(db, { ...base, ...counts, decision: "REFUSE", reason: `${capability} is not in this principal's scope`, rule: "visitor:out-of-scope" }, now);
  if (turnsToday + cost > row.daily_turns) return log(db, { ...base, ...counts, decision: "REFUSE", reason: `daily budget spent (${row.daily_turns} turns)`, rule: "visitor:budget" }, now);
  db.prepare(`UPDATE visitor_principals SET turns_today = ?, day = ?, last_seen = ? WHERE product = ? AND principal = ?`)
    .run(turnsToday + cost, today, ts, product, principal);
  return log(db, { ...base, decision: "ALLOW", reason: "in scope, within budget", rule: "visitor:allow", turns_today: turnsToday + cost, daily_turns: row.daily_turns }, now);
}

/** Kill switch for one principal. A reason and a person are required both ways. */
export function setQuarantine(db: SqlDb, product: string, principal: string, on: boolean, reason: string, by: string, now = new Date()): boolean {
  if (!reason?.trim() || !by?.trim()) throw { status: 400, error: "reason and by are required" };
  const r = on
    ? db.prepare(`UPDATE visitor_principals SET quarantine_reason = ?, quarantined_by = ?, last_seen = ? WHERE product = ? AND principal = ?`).run(reason.trim(), by.trim(), now.toISOString(), product, principal)
    : db.prepare(`UPDATE visitor_principals SET quarantine_reason = NULL, release_reason = ?, released_by = ?, last_seen = ? WHERE product = ? AND principal = ?`).run(reason.trim(), by.trim(), now.toISOString(), product, principal);
  return Number(r.changes) > 0;
}

/** Record a person's grant to an agent (R4): scope can only narrow the product's default scope. */
export function recordGrant(db: SqlDb, g: { product: string; principal: string; org?: string | null; scope: string[]; daily_turns?: number; granted_by: string; expires_at?: string | null }, overrides: unknown, now = new Date()): VisitorRow {
  const policy = policyFor(g.product, overrides);
  if (!policy) throw { status: 400, error: "product has no visitor policy" };
  if (!/^grant:/.test(g.principal) || !PRINCIPAL.test(g.principal)) throw { status: 400, error: "a grant principal is grant:<id>" };
  if (!g.granted_by?.trim()) throw { status: 400, error: "granted_by (the person) is required" };
  const scope = (g.scope ?? []).filter((c) => policy.default_scope.includes(c));
  const turns = Math.min(policy.daily_turns, Number.isInteger(g.daily_turns) && g.daily_turns! > 0 ? g.daily_turns! : policy.daily_turns);
  const ts = now.toISOString();
  db.prepare(`INSERT INTO visitor_principals (product, principal, org, scope, daily_turns, turns_today, day, granted_by, expires_at, created_at, last_seen)
              VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
              ON CONFLICT(product, principal) DO UPDATE SET org = excluded.org, scope = excluded.scope, daily_turns = excluded.daily_turns,
                granted_by = excluded.granted_by, expires_at = excluded.expires_at, last_seen = excluded.last_seen`)
    .run(g.product, g.principal, g.org ?? null, JSON.stringify(scope), turns, ts.slice(0, 10), g.granted_by.trim(), g.expires_at ?? null, ts, ts);
  return db.prepare<VisitorRow>(`SELECT * FROM visitor_principals WHERE product = ? AND principal = ?`).get(g.product, g.principal)!;
}
