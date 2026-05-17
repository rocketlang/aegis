// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
//
// @rocketlang/lakshmanrekha — opt-in Agentic Control Center event bus (v0.2.0)
// @rule:ACC-003 — Opt-in. emit only when setEventBus() called.
// @rule:ACC-004 — Lightweight OSS receipt shape (strict subset of EE PRAMANA).
// @rule:ACC-YK-003 — Stateless-primitive contract preserved.
// @rule:INF-ACC-005 — emit() is a no-op when no bus has been set.

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

let _bus: EventBus | null = null;

export function setEventBus(bus: EventBus | null): void {
  _bus = bus;
}

export function emitAccReceipt(receipt: Omit<AccReceipt, 'primitive' | 'emitted_at'>): void {
  if (!_bus) return;
  try {
    _bus.emit({
      ...receipt,
      primitive: 'lakshmanrekha',
      emitted_at: new Date().toISOString(),
    });
  } catch {
    // bus implementation failure must never break the primitive's caller
  }
}

export function isBusWired(): boolean {
  return _bus !== null;
}
