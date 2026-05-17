// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
//
// Agentic Control Center — canonical types for event bus + receipt shape.
//
// @rule:ACC-003 — Opt-in event bus. Each primitive exposes setEventBus(bus)
//                    and emits only when a bus has been provided.
// @rule:ACC-004 — Lightweight OSS receipt shape: strict subset of the EE
//                    PRAMANA receipt format (ee/kavach/pramana-receipts.ts).
//                    Forward-compatible-additive only — fields are added,
//                    never removed or renamed (ACC-YK-006).
// @rule:ACC-005 — Black-box separation: the bus is structural; the
//                    consumer chooses where events land (default writer is
//                    SQLite at ~/.aegis/acc-events.db, see Day 3).
//
// Each of the 4 OSS primitives (aegis-guard, chitta-detect, lakshmanrekha,
// hanumang-mandate) declares its own structurally-compatible copy of these
// shapes. The interfaces here are the canonical reference; primitives are
// not required to import from this file. TypeScript structural typing means
// any object matching the shape satisfies all primitives' setEventBus.

/**
 * Lightweight ACC receipt. Each event emitted by a primitive must
 * conform to this shape. Strict subset of EE PRAMANA receipt — EE
 * consumers ingest these events without translation.
 *
 * Forward-compatible-additive-only per ACC-YK-006.
 */
export interface AccReceipt {
  /** Unique receipt ID. Recommended: `${primitive}-${ulid}` or similar. */
  receipt_id: string;

  /** Which primitive emitted: 'aegis-guard' | 'chitta-detect' | 'lakshmanrekha' | 'hanumang-mandate' | 'aegis' | 'kavachos' */
  primitive: string;

  /** Event type — primitive-specific. Examples:
   *  - aegis-guard: 'lock.approval.verified' | 'lock.nonce.consumed' | 'lock.sense.emitted'
   *  - chitta-detect: 'scan.evaluated' | 'fingerprint.matched'
   *  - lakshmanrekha: 'probe.run' | 'probes.batch.complete'
   *  - hanumang-mandate: 'mudrika.verified' | 'posture.scored' */
  event_type: string;

  /** ISO 8601 timestamp. Receipts MUST be ordered by this field (ACC-010). */
  emitted_at: string;

  /** Optional agent identifier — enables per-agent timeline view (ACC-010).
   *  When absent, event is rendered in the primitive's zone but not in any
   *  per-agent timeline. */
  agent_id?: string;

  /** Optional outcome/verdict — primitive-specific. Examples:
   *  PASS / FAIL / refused / complied / BLOCK / etc. */
  verdict?: string;

  /** Optional rule IDs fired during this evaluation (cite by ID, not text).
   *  Examples: ['CG-006', 'INF-CG-001'] or ['ASMAI-S-003']. */
  rules_fired?: string[];

  /** Optional summary string. ≤200 chars recommended; not enforced.
   *  For longer payloads, consumer uses overflow_granthx_ref pattern (CA-001). */
  summary?: string;

  /** Optional opaque payload. Consumer-defined shape. */
  payload?: Record<string, unknown>;
}

/**
 * Minimal event bus interface. Each primitive accepts any object matching
 * this shape via setEventBus(bus).
 *
 * Stateless contract preserved (ACC-YK-003): primitives do not gain
 * persistent state of their own. The bus is consumer-provided; primitives
 * only forward receipts to it when set.
 *
 * Default implementation (in @rocketlang/aegis-suite v0.2.0+):
 *   - In-memory bus (single process)
 *   - Optional SQLite writer to ~/.aegis/acc-events.db
 *   - Optional SSE delivery to the ACC page
 *
 * Consumer-provided implementations may use Redis, NATS, Kafka, etc.
 * Multi-process is consumer's choice per ACC-011.
 */
export interface EventBus {
  /** Emit a receipt onto the bus. MUST NOT throw — if delivery fails,
   *  the bus implementation handles it (log, queue, drop — consumer's call).
   *  Primitives MUST NOT depend on synchronous emission semantics. */
  emit(receipt: AccReceipt): void;
}

// ── Helper: a no-op bus, useful as a default ─────────────────────────────────
//
// Not required to use — primitives default to NO bus (no emission) when
// setEventBus has not been called. This export exists for consumers who
// want to wire a "discard everything" bus during testing or feature flags.

export const NULL_BUS: EventBus = {
  emit: (_r: AccReceipt): void => {
    // intentional no-op
  },
};
