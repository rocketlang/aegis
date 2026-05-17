// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
//
// AEGIS — Agentic Control Center default bus + SQLite writer
// @rule:ACC-005 — Black-box separation: acc-events.db is separate from
//                  aegis.db and turn-store.db.
// @rule:ACC-011 — Default bus is in-process / single-process. Multi-process
//                  buses (Redis, NATS, Kafka) are consumer choice.
// @rule:ACC-YK-006 — Receipt shape is forward-compatible-additive only.

import { Database } from 'bun:sqlite';
import { mkdirSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { homedir } from 'os';
import { AccReceipt, EventBus } from './types';

// ── Default path resolution ──────────────────────────────────────────────────

export function defaultAccEventsDbPath(): string {
  const aegisDir = process.env.AEGIS_DIR ?? join(homedir(), '.aegis');
  if (!existsSync(aegisDir)) mkdirSync(aegisDir, { recursive: true });
  return join(aegisDir, 'acc-events.db');
}

// ── InMemoryBus — fans events out to N subscribers in-process ────────────────

export type Subscriber = (r: AccReceipt) => void;

export class InMemoryBus implements EventBus {
  private subscribers: Set<Subscriber> = new Set();

  emit(receipt: AccReceipt): void {
    for (const sub of this.subscribers) {
      try {
        sub(receipt);
      } catch {
        // never let one bad subscriber break others (ACC-YK-003)
      }
    }
  }

  subscribe(fn: Subscriber): () => void {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  subscriberCount(): number {
    return this.subscribers.size;
  }
}

// ── SQLiteEventWriter — append-only persistence to ~/.aegis/acc-events.db ───

const SCHEMA = `
CREATE TABLE IF NOT EXISTS acc_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id TEXT NOT NULL,
  primitive TEXT NOT NULL,
  event_type TEXT NOT NULL,
  emitted_at TEXT NOT NULL,
  agent_id TEXT,
  verdict TEXT,
  rules_fired TEXT,         -- JSON-encoded array
  summary TEXT,
  payload TEXT,             -- JSON-encoded object
  ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_acc_primitive_emitted ON acc_events (primitive, emitted_at);
CREATE INDEX IF NOT EXISTS idx_acc_agent_emitted     ON acc_events (agent_id, emitted_at);
CREATE INDEX IF NOT EXISTS idx_acc_event_type        ON acc_events (event_type);
CREATE INDEX IF NOT EXISTS idx_acc_id                ON acc_events (id);
`;

export interface SqliteEventWriterOpts {
  /** Path to acc-events.db. Defaults to ~/.aegis/acc-events.db. */
  path?: string;
}

export class SqliteEventWriter {
  private db: Database;
  private insertStmt: ReturnType<Database['query']>;

  constructor(opts: SqliteEventWriterOpts = {}) {
    const path = opts.path ?? defaultAccEventsDbPath();
    mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(SCHEMA);
    this.insertStmt = this.db.query(`
      INSERT INTO acc_events
        (receipt_id, primitive, event_type, emitted_at, agent_id, verdict, rules_fired, summary, payload)
      VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
  }

  write(receipt: AccReceipt): void {
    try {
      this.insertStmt.run(
        receipt.receipt_id,
        receipt.primitive,
        receipt.event_type,
        receipt.emitted_at,
        receipt.agent_id ?? null,
        receipt.verdict ?? null,
        receipt.rules_fired ? JSON.stringify(receipt.rules_fired) : null,
        receipt.summary ?? null,
        receipt.payload ? JSON.stringify(receipt.payload) : null,
      );
    } catch {
      // never throw — preserves ACC-YK-003 stateless-primitive contract
    }
  }

  /** Returns receipts emitted since `lastId` (exclusive). Used by SSE polling. */
  queryNewer(lastId: number, limit = 100): Array<AccReceipt & { id: number }> {
    const rows = this.db.query(`
      SELECT id, receipt_id, primitive, event_type, emitted_at, agent_id, verdict, rules_fired, summary, payload
      FROM acc_events
      WHERE id > ?
      ORDER BY id ASC
      LIMIT ?
    `).all(lastId, limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: r['id'] as number,
      receipt_id: r['receipt_id'] as string,
      primitive: r['primitive'] as string,
      event_type: r['event_type'] as string,
      emitted_at: r['emitted_at'] as string,
      agent_id: (r['agent_id'] as string | null) ?? undefined,
      verdict: (r['verdict'] as string | null) ?? undefined,
      rules_fired: r['rules_fired'] ? JSON.parse(r['rules_fired'] as string) : undefined,
      summary: (r['summary'] as string | null) ?? undefined,
      payload: r['payload'] ? JSON.parse(r['payload'] as string) : undefined,
    }));
  }

  /** Returns the most recent `limit` events for a given primitive. Used by zone rendering. */
  queryByPrimitive(primitive: string, limit = 50): AccReceipt[] {
    const rows = this.db.query(`
      SELECT receipt_id, primitive, event_type, emitted_at, agent_id, verdict, rules_fired, summary, payload
      FROM acc_events
      WHERE primitive = ?
      ORDER BY id DESC
      LIMIT ?
    `).all(primitive, limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      receipt_id: r['receipt_id'] as string,
      primitive: r['primitive'] as string,
      event_type: r['event_type'] as string,
      emitted_at: r['emitted_at'] as string,
      agent_id: (r['agent_id'] as string | null) ?? undefined,
      verdict: (r['verdict'] as string | null) ?? undefined,
      rules_fired: r['rules_fired'] ? JSON.parse(r['rules_fired'] as string) : undefined,
      summary: (r['summary'] as string | null) ?? undefined,
      payload: r['payload'] ? JSON.parse(r['payload'] as string) : undefined,
    }));
  }

  /** Returns the full timeline for a given agent_id, ordered by emitted_at. */
  queryByAgent(agentId: string, limit = 200): AccReceipt[] {
    const rows = this.db.query(`
      SELECT receipt_id, primitive, event_type, emitted_at, agent_id, verdict, rules_fired, summary, payload
      FROM acc_events
      WHERE agent_id = ?
      ORDER BY emitted_at ASC
      LIMIT ?
    `).all(agentId, limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      receipt_id: r['receipt_id'] as string,
      primitive: r['primitive'] as string,
      event_type: r['event_type'] as string,
      emitted_at: r['emitted_at'] as string,
      agent_id: (r['agent_id'] as string | null) ?? undefined,
      verdict: (r['verdict'] as string | null) ?? undefined,
      rules_fired: r['rules_fired'] ? JSON.parse(r['rules_fired'] as string) : undefined,
      summary: (r['summary'] as string | null) ?? undefined,
      payload: r['payload'] ? JSON.parse(r['payload'] as string) : undefined,
    }));
  }

  /** Returns count of events per primitive. Used by health panel. */
  countsByPrimitive(): Record<string, number> {
    const rows = this.db.query(`
      SELECT primitive, COUNT(*) AS n FROM acc_events GROUP BY primitive
    `).all() as Array<{ primitive: string; n: number }>;
    const out: Record<string, number> = {};
    for (const r of rows) out[r.primitive] = r.n;
    return out;
  }

  /** Returns total event count. Used by health panel. */
  totalCount(): number {
    const row = this.db.query('SELECT COUNT(*) AS n FROM acc_events').get() as { n: number };
    return row.n;
  }

  /** Returns the highest `id` currently in the table. Used by SSE high-water-mark. */
  maxId(): number {
    const row = this.db.query('SELECT COALESCE(MAX(id), 0) AS m FROM acc_events').get() as { m: number };
    return row.m;
  }

  close(): void {
    this.db.close();
  }
}

// ── createDefaultBus — convenience wiring InMemoryBus + SqliteEventWriter ────

export interface DefaultBusOpts {
  /** Override SQLite path. Defaults to ~/.aegis/acc-events.db */
  sqlitePath?: string;
  /** Set to false to skip SQLite persistence (memory-only). Default true. */
  persist?: boolean;
}

export interface DefaultBusHandle {
  bus: InMemoryBus;
  writer: SqliteEventWriter | null;
}

/** Construct an InMemoryBus + (optionally) attach a SqliteEventWriter. */
export function createDefaultBus(opts: DefaultBusOpts = {}): DefaultBusHandle {
  const bus = new InMemoryBus();
  let writer: SqliteEventWriter | null = null;
  if (opts.persist !== false) {
    writer = new SqliteEventWriter({ path: opts.sqlitePath });
    bus.subscribe((r) => writer!.write(r));
  }
  return { bus, writer };
}
