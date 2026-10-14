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

import { openSqlite, type SqlDb, type SqlStatement } from '../core/sqlite.js'; // bun:sqlite under Bun, node:sqlite under Node 22.5+
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

// GTP-024: optional flow fields, in addition to the original columns.
const FLOW_COLUMNS = ['flow_id', 'turn_id', 'parent_turn_id', 'mandate_id', 'session_ref'] as const;
const COLUMNS = 'receipt_id, primitive, event_type, emitted_at, agent_id, verdict, rules_fired, summary, payload, ' + FLOW_COLUMNS.join(', ');

const opt = (v: unknown): string | undefined => (v as string | null) ?? undefined;

function rowToReceipt(r: Record<string, unknown>): AccReceipt {
  return {
    receipt_id: r['receipt_id'] as string,
    primitive: r['primitive'] as string,
    event_type: r['event_type'] as string,
    emitted_at: r['emitted_at'] as string,
    agent_id: opt(r['agent_id']),
    verdict: opt(r['verdict']),
    rules_fired: r['rules_fired'] ? JSON.parse(r['rules_fired'] as string) : undefined,
    summary: opt(r['summary']),
    payload: r['payload'] ? JSON.parse(r['payload'] as string) : undefined,
    flow_id: opt(r['flow_id']),
    turn_id: opt(r['turn_id']),
    parent_turn_id: opt(r['parent_turn_id']),
    mandate_id: opt(r['mandate_id']),
    session_ref: opt(r['session_ref']),
  };
}

export interface SqliteEventWriterOpts {
  /** Path to acc-events.db. Defaults to ~/.aegis/acc-events.db. */
  path?: string;
}

export class SqliteEventWriter {
  private db: SqlDb;
  private insertStmt: SqlStatement;

  constructor(opts: SqliteEventWriterOpts = {}) {
    const path = opts.path ?? defaultAccEventsDbPath();
    mkdirSync(dirname(path), { recursive: true });
    this.db = openSqlite(path);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(SCHEMA);
    // GTP-024: the five flow fields, added to a table created before them (additive: ADD COLUMN only).
    const have = new Set((this.db.query('PRAGMA table_info(acc_events)').all() as Array<{ name: string }>).map((c) => c.name));
    for (const col of FLOW_COLUMNS) {
      if (!have.has(col)) this.db.exec(`ALTER TABLE acc_events ADD COLUMN ${col} TEXT`);
    }
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_acc_flow_emitted ON acc_events (flow_id, emitted_at);');
    this.insertStmt = this.db.query(`
      INSERT INTO acc_events (${COLUMNS})
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        receipt.flow_id ?? null,
        receipt.turn_id ?? null,
        receipt.parent_turn_id ?? null,
        receipt.mandate_id ?? null,
        receipt.session_ref ?? null,
      );
    } catch {
      // never throw — preserves ACC-YK-003 stateless-primitive contract
    }
  }

  /** Returns receipts emitted since `lastId` (exclusive). Used by SSE polling. */
  queryNewer(lastId: number, limit = 100): Array<AccReceipt & { id: number }> {
    const rows = this.db.query(`
      SELECT id, ${COLUMNS}
      FROM acc_events
      WHERE id > ?
      ORDER BY id ASC
      LIMIT ?
    `).all(lastId, limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({ id: r['id'] as number, ...rowToReceipt(r) }));
  }

  /** Returns the most recent `limit` events for a given primitive. Used by zone rendering. */
  queryByPrimitive(primitive: string, limit = 50): AccReceipt[] {
    const rows = this.db.query(`
      SELECT ${COLUMNS}
      FROM acc_events
      WHERE primitive = ?
      ORDER BY id DESC
      LIMIT ?
    `).all(primitive, limit) as Array<Record<string, unknown>>;
    return rows.map(rowToReceipt);
  }

  /** Returns the full timeline for a given agent_id, ordered by emitted_at. */
  queryByAgent(agentId: string, limit = 200): AccReceipt[] {
    const rows = this.db.query(`
      SELECT ${COLUMNS}
      FROM acc_events
      WHERE agent_id = ?
      ORDER BY emitted_at ASC
      LIMIT ?
    `).all(agentId, limit) as Array<Record<string, unknown>>;
    return rows.map(rowToReceipt);
  }

  /** Returns one flow's events, ordered by emitted_at (GTP-018). Used by the flow tree. */
  queryByFlow(flowId: string, limit = 500): AccReceipt[] {
    const rows = this.db.query(`
      SELECT ${COLUMNS}
      FROM acc_events
      WHERE flow_id = ?
      ORDER BY emitted_at ASC, id ASC
      LIMIT ?
    `).all(flowId, limit) as Array<Record<string, unknown>>;
    return rows.map(rowToReceipt);
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
