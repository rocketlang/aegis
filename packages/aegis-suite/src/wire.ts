// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rocketlang/aegis-suite — wireAllToBus helper (v0.2.0)
//
// One-call setup that wires all 4 OSS primitive packages to a single
// EventBus + persists to ~/.aegis/acc-events.db. The Agentic Control
// Center (in aegis dashboard v2.2.0+) reads from the same SQLite file.
//
// @rule:ACC-003 — Opt-in. Without wireAllToBus, primitives behave
//                  identically to their v0.1.0 (no emission).
// @rule:ACC-005 — SQLite file at ~/.aegis/acc-events.db, separate from
//                  aegis.db and turn-store.db.

import { setEventBus as setAegisGuardBus } from '@rocketlang/aegis-guard';
import { setEventBus as setChittaBus } from '@rocketlang/chitta-detect';
import { setEventBus as setLakshmanBus } from '@rocketlang/lakshmanrekha';
import { setEventBus as setHanumangBus } from '@rocketlang/hanumang-mandate';
import { createDefaultBus, type InMemoryBus, type SqliteEventWriter } from './bus.js';

// ── Canonical receipt + bus types ────────────────────────────────────────────
//
// Defined locally to avoid pulling any primitive's copy as the canonical one.
// All 4 primitives have structurally compatible local copies; TypeScript
// structural typing makes the wiring work.

export interface AccReceipt {
  receipt_id: string;
  primitive: string;
  event_type: string;
  emitted_at: string;
  agent_id?: string;
  verdict?: string;
  rules_fired?: string[];
  summary?: string;
  payload?: Record<string, unknown>;
}

export interface EventBus {
  emit(receipt: AccReceipt): void;
}

// ── State ────────────────────────────────────────────────────────────────────

let _busHandle: WireHandle | null = null;

export interface WireHandle {
  bus: EventBus;
  /** Subscribe to live events. Returns an unsubscribe function. */
  subscribe?: (fn: (r: AccReceipt) => void) => () => void;
  /** SQLite path actually in use, or undefined if persistence disabled. */
  sqlitePath?: string;
  /** Total receipts written so far (cumulative across this process). */
  receivedCount(): number;
  /** Force WAL checkpoint so writes become visible to readers in other
   *  processes (the aegis dashboard reads from the same file). */
  checkpoint?: () => void;
}

export interface WireAllOpts {
  /** Provide your own bus instead of the default in-memory + SQLite. */
  bus?: EventBus;
  /** Override SQLite path (default ~/.aegis/acc-events.db). */
  sqlitePath?: string;
  /** Set false to skip SQLite persistence (memory only). Default true. */
  persist?: boolean;
}

// ── wireAllToBus ─────────────────────────────────────────────────────────────

/**
 * Wire all 4 OSS primitive packages (aegis-guard, chitta-detect,
 * lakshmanrekha, hanumang-mandate) to a single event bus.
 *
 * Without `opts.bus`, creates a default in-memory bus that persists
 * every event to SQLite at ~/.aegis/acc-events.db. The aegis dashboard
 * (v2.2.0+) reads from this file to render the Agentic Control Center
 * page at `/control-center`.
 *
 * Returns a handle so the caller can subscribe to live events or force
 * WAL checkpoints for cross-process visibility.
 */
export function wireAllToBus(opts: WireAllOpts = {}): WireHandle {
  if (opts.bus) {
    // Caller supplied their own bus
    let count = 0;
    const userBus = opts.bus;
    const wrappedBus: EventBus = {
      emit: (r) => {
        count++;
        userBus.emit(r);
      },
    };
    setAegisGuardBus(wrappedBus as unknown as Parameters<typeof setAegisGuardBus>[0]);
    setChittaBus(wrappedBus as unknown as Parameters<typeof setChittaBus>[0]);
    setLakshmanBus(wrappedBus as unknown as Parameters<typeof setLakshmanBus>[0]);
    setHanumangBus(wrappedBus as unknown as Parameters<typeof setHanumangBus>[0]);
    _busHandle = {
      bus: wrappedBus,
      receivedCount: () => count,
    };
    return _busHandle;
  }

  // Default path — in-memory bus + SQLite writer
  const { bus, writer } = createDefaultBus({
    sqlitePath: opts.sqlitePath,
    persist: opts.persist !== false,
  });

  let count = 0;
  const wrappedBus: EventBus = {
    emit: (r) => {
      count++;
      bus.emit(r);
    },
  };

  setAegisGuardBus(wrappedBus as unknown as Parameters<typeof setAegisGuardBus>[0]);
  setChittaBus(wrappedBus as unknown as Parameters<typeof setChittaBus>[0]);
  setLakshmanBus(wrappedBus as unknown as Parameters<typeof setLakshmanBus>[0]);
  setHanumangBus(wrappedBus as unknown as Parameters<typeof setHanumangBus>[0]);

  _busHandle = {
    bus: wrappedBus,
    subscribe: (fn) => (bus as InMemoryBus).subscribe(fn),
    sqlitePath: writer?.path,
    receivedCount: () => count,
    checkpoint: writer ? () => (writer as SqliteEventWriter).checkpoint() : undefined,
  };
  return _busHandle;
}

/** Detach the bus from all 4 primitives. Primitives revert to v0.1.0 behaviour. */
export function unwireAll(): void {
  setAegisGuardBus(null);
  setChittaBus(null);
  setLakshmanBus(null);
  setHanumangBus(null);
  _busHandle = null;
}

export function getWiredHandle(): WireHandle | null {
  return _busHandle;
}
