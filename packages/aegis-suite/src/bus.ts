// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rocketlang/aegis-suite — InMemoryBus + SqliteEventWriter (v0.2.0)
//
// Self-contained default bus implementation for wireAllToBus(). Writes to
// ~/.aegis/acc-events.db using a forward-compatible-additive schema. The
// aegis dashboard (v2.2.0+) reads from the same file using its own copy
// of the same schema — both use CREATE IF NOT EXISTS so the file is
// schema-idempotent regardless of which process writes first.
//
// @rule:ACC-005 — Black-box separation: separate from aegis.db / turn-store.db
// @rule:ACC-011 — In-process / single-process default. Multi-process bus is
//                  consumer choice.
// @rule:ACC-YK-006 — Schema forward-compatible-additive only.

import { Database } from 'bun:sqlite';
import { mkdirSync, existsSync } from 'fs';
import { dirname, join } from 'path';
import { homedir } from 'os';
import type { AccReceipt, EventBus } from './wire';

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
    for (const sub of Array.from(this.subscribers)) {
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

// ── SQLite schema — must match aegis core's reader schema ────────────────────
// If you change this, also change /root/aegis/src/acc/bus.ts SCHEMA in aegis
// core. Schema is CREATE IF NOT EXISTS so additions are safe; never remove or
// rename columns (ACC-YK-006 forward-compatible-additive only).

const SCHEMA = `
CREATE TABLE IF NOT EXISTS acc_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id TEXT NOT NULL,
  primitive TEXT NOT NULL,
  event_type TEXT NOT NULL,
  emitted_at TEXT NOT NULL,
  agent_id TEXT,
  verdict TEXT,
  rules_fired TEXT,
  summary TEXT,
  payload TEXT,
  ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_acc_primitive_emitted ON acc_events (primitive, emitted_at);
CREATE INDEX IF NOT EXISTS idx_acc_agent_emitted     ON acc_events (agent_id, emitted_at);
CREATE INDEX IF NOT EXISTS idx_acc_event_type        ON acc_events (event_type);
CREATE INDEX IF NOT EXISTS idx_acc_id                ON acc_events (id);
`;

export interface SqliteEventWriterOpts {
  path?: string;
}

export class SqliteEventWriter {
  private db: Database;
  private insertStmt: ReturnType<Database['query']>;
  public readonly path: string;

  constructor(opts: SqliteEventWriterOpts = {}) {
    this.path = opts.path ?? defaultAccEventsDbPath();
    mkdirSync(dirname(this.path), { recursive: true });
    this.db = new Database(this.path);
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

  /** Force a WAL checkpoint so writes from this process are visible to readers
   *  in other processes (e.g., the aegis dashboard in a separate process). */
  checkpoint(): void {
    try {
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
    } catch {
      // checkpoint failure non-fatal
    }
  }

  /** Total event count — for health checks. */
  totalCount(): number {
    try {
      const row = this.db.query('SELECT COUNT(*) AS n FROM acc_events').get() as { n: number };
      return row.n;
    } catch {
      return 0;
    }
  }

  close(): void {
    try { this.db.close(); } catch { /* */ }
  }
}

// ── Convenience constructor ──────────────────────────────────────────────────

export interface DefaultBusOpts {
  sqlitePath?: string;
  persist?: boolean;
}

export interface DefaultBusHandle {
  bus: InMemoryBus;
  writer: SqliteEventWriter | null;
}

export function createDefaultBus(opts: DefaultBusOpts = {}): DefaultBusHandle {
  const bus = new InMemoryBus();
  let writer: SqliteEventWriter | null = null;
  if (opts.persist !== false) {
    writer = new SqliteEventWriter({ path: opts.sqlitePath });
    bus.subscribe((r) => writer!.write(r));
  }
  return { bus, writer };
}
