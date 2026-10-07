// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — SENSE event emitter
// Fire-and-forget to SuperEvents :4580. Never throws — SuperEvents down ≠ handshake failure.
// @rule:NLS-016 latency budget: emit is async, never awaited in critical path

const SUPER_EVENTS_URL =
  process.env.SUPER_EVENTS_URL ?? "http://localhost:4580/events/publish";

export interface NlsSensePayload {
  session_id?: string;
  initiator_id: string;
  responder_id: string;
  session_mask?: number;
  session_class?: string;
  decision: string;
  policy_hash: string;
  latency_ms: number;
  rule_ref: string;
  error?: string;
  counter_scope_mask?: number;
}

// @rule:NLS-012 SENSE events on every handshake decision
export function emitHandshakeSense(
  type: string,
  payload: NlsSensePayload,
  correlationId?: string,
): void {
  // Intentionally not awaited — fire and forget
  fetch(SUPER_EVENTS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source: "nallasetu", type, payload, correlationId }),
    signal: AbortSignal.timeout(800),
  }).catch(() => {
    // SuperEvents offline is not a handshake failure
  });
}
