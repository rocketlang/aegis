// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
//
// @rocketlang/aegis-guard — opt-in ACC event bus integration (v0.2.0)
// @rule:ACC-003 — Opt-in event bus. emit only when setEventBus() called.
// @rule:ACC-004 — Lightweight OSS receipt shape (strict subset of EE PRAMANA).
// @rule:ACC-YK-003 — Stateless-primitive contract preserved. No bus = no emit.
// @rule:INF-ACC-005 — emit() is a no-op when no bus has been set.

/**
 * Lightweight receipt shape — structurally compatible with the canonical
 * AccReceipt in /root/aegis/src/acc/types.ts. Defined locally so
 * this primitive can ship without depending on the ACC package.
 */
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

// Module-private bus reference. null by default — emission is no-op.
let _bus: EventBus | null = null;

/**
 * Opt-in: provide an event bus to receive lightweight ACC receipts
 * for every Five Locks primitive call. Pass null to detach.
 *
 * Default behaviour (no bus set): primitives behave EXACTLY as v0.1.0 —
 * no emission, no state, no side effect beyond their primary return value.
 *
 * @rule:ACC-003 @rule:ACC-YK-003
 */
export function setEventBus(bus: EventBus | null): void {
  _bus = bus;
}

/**
 * Internal helper — primitives call this to emit a receipt. No-op when
 * no bus is set. MUST NOT throw — bus implementation handles delivery
 * failures (ACC-YK-003 stateless contract).
 *
 * @rule:INF-ACC-005
 */
export function emitAccReceipt(receipt: Omit<AccReceipt, 'primitive' | 'emitted_at'>): void {
  if (!_bus) return;
  try {
    _bus.emit({
      ...receipt,
      primitive: 'aegis-guard',
      emitted_at: new Date().toISOString(),
    });
  } catch {
    // bus implementation failure must never break the primitive's caller
  }
}

/** Test/introspection helper — does the primitive have a bus set right now? */
export function isBusWired(): boolean {
  return _bus !== null;
}
