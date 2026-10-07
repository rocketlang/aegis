// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — SQLite backing store
// @rule:NLS-011 immutable receipt storage — append-only sessions table
// @rule:NLS-013 registry-mediated key lookup

import { Database } from "bun:sqlite";
import { join } from "path";
import { mkdirSync, existsSync } from "fs";
import type { SessionRow, KeyRegistryRow } from "./types";

const DB_DIR = join(process.env.HOME ?? "/root", ".ankr", "nallasetu");
const DB_PATH = join(DB_DIR, "nallasetu.db");

let _db: Database | null = null;

export function getDb(): Database {
  if (_db) return _db;
  if (!existsSync(DB_DIR)) mkdirSync(DB_DIR, { recursive: true });
  _db = new Database(DB_PATH);
  _db.run("PRAGMA journal_mode=WAL");
  _db.run(`CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    initiator_id  TEXT NOT NULL,
    responder_id  TEXT NOT NULL,
    session_mask  INTEGER NOT NULL,
    session_class TEXT NOT NULL,
    credential_json TEXT NOT NULL,
    receipt_json  TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    issued_at     TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    pramana_hash  TEXT NOT NULL
  )`);
  _db.run(`CREATE TABLE IF NOT EXISTS key_registry (
    agent_id       TEXT PRIMARY KEY,
    hmac_secret    TEXT NOT NULL,
    public_key_id  TEXT NOT NULL,
    trust_mask     INTEGER NOT NULL DEFAULT 65535,
    registered_at  TEXT NOT NULL,
    source         TEXT NOT NULL DEFAULT 'self',
    revoked        INTEGER NOT NULL DEFAULT 0
  )`);
  // Migrate existing rows missing trust_mask (safe on existing DBs — additive ADD COLUMN only)
  try { _db.run(`ALTER TABLE key_registry ADD COLUMN trust_mask INTEGER NOT NULL DEFAULT 65535`); } catch { /* column exists */ }
  // @rule:NLS-YK-008 — revoked flag so a known-revoked partner can actually be rejected.
  // Additive migration for DBs created before this column existed (mirrors the trust_mask migration).
  try { _db.run(`ALTER TABLE key_registry ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0`); } catch { /* column exists */ }
  _db.run(`CREATE TABLE IF NOT EXISTS pramana_chain (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    receipt_hash  TEXT NOT NULL,
    pramana_hash  TEXT NOT NULL,
    chained_at    TEXT NOT NULL
  )`);
  return _db;
}

// ── Sessions ──────────────────────────────────────────────────────────────────

export function storeSession(row: SessionRow): void {
  const db = getDb();
  db.run(
    `INSERT INTO sessions (session_id, initiator_id, responder_id, session_mask, session_class,
      credential_json, receipt_json, status, issued_at, expires_at, pramana_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.session_id, row.initiator_id, row.responder_id, row.session_mask, row.session_class,
     row.credential_json, row.receipt_json, row.status, row.issued_at, row.expires_at, row.pramana_hash]
  );
}

export function getSession(sessionId: string): SessionRow | null {
  const db = getDb();
  return db.query("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as SessionRow | null;
}

export function revokeSession(sessionId: string, receiptJson: string): void {
  // @rule:NLS-011 — update status only; credential_json never modified
  const db = getDb();
  db.run("UPDATE sessions SET status = 'revoked', receipt_json = ? WHERE session_id = ?",
    [receiptJson, sessionId]);
}

export function expireStale(): number {
  const db = getDb();
  const result = db.run(
    "UPDATE sessions SET status = 'expired' WHERE status = 'active' AND expires_at < ?",
    [new Date().toISOString()]
  );
  return result.changes;
}

// ── Key registry ──────────────────────────────────────────────────────────────

export function registerKey(row: KeyRegistryRow): void {
  const db = getDb();
  // UPSERT (not INSERT OR REPLACE): re-registering an existing agent_id updates its material but
  // PRESERVES an existing `revoked` flag — @rule:NLS-YK-008 revocation is sticky, you cannot
  // un-revoke by re-registering the same id (use reinstateKey for a deliberate, explicit reinstate).
  // A brand-new row starts revoked=0.
  db.run(
    `INSERT INTO key_registry (agent_id, hmac_secret, public_key_id, trust_mask, registered_at, source, revoked)
     VALUES (?, ?, ?, ?, ?, ?, 0)
     ON CONFLICT(agent_id) DO UPDATE SET
       hmac_secret   = excluded.hmac_secret,
       public_key_id = excluded.public_key_id,
       trust_mask    = excluded.trust_mask,
       registered_at = excluded.registered_at,
       source        = excluded.source`,
    [row.agent_id, row.hmac_secret, row.public_key_id, row.trust_mask ?? 65535, row.registered_at, row.source]
  );
}

export function lookupKey(agentId: string): KeyRegistryRow | null {
  // @rule:NLS-013 registry-mediated lookup — SELECT * surfaces `revoked` for the NLS-YK-008 check
  return getDb().query("SELECT * FROM key_registry WHERE agent_id = ?").get(agentId) as KeyRegistryRow | null;
}

export function revokeKey(agentId: string): boolean {
  // @rule:NLS-YK-008 known-revoked partner → REJECT. Marks a registered agent revoked; the handshake
  // engine refuses it as initiator or responder. Returns true if a row changed (idempotent re-revoke → false).
  const result = getDb().run("UPDATE key_registry SET revoked = 1 WHERE agent_id = ? AND revoked = 0", [agentId]);
  return result.changes > 0;
}

export function reinstateKey(agentId: string): boolean {
  // Deliberate, explicit un-revoke (admin path) — the ONLY way to clear a revocation.
  const result = getDb().run("UPDATE key_registry SET revoked = 0 WHERE agent_id = ? AND revoked = 1", [agentId]);
  return result.changes > 0;
}

// ── PRAMANA chain ─────────────────────────────────────────────────────────────

export function getLastPramanaHash(): string {
  const row = getDb().query(
    "SELECT pramana_hash FROM pramana_chain ORDER BY id DESC LIMIT 1"
  ).get() as { pramana_hash: string } | null;
  return row?.pramana_hash ?? "0000000000000000000000000000000000000000000000000000000000000000";
}

export function appendPramanaChain(sessionId: string, receiptHash: string, pramanaHash: string): void {
  getDb().run(
    "INSERT INTO pramana_chain (session_id, receipt_hash, pramana_hash, chained_at) VALUES (?, ?, ?, ?)",
    [sessionId, receiptHash, pramanaHash, new Date().toISOString()]
  );
}
