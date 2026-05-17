// @rule:CA-003 — SENSE events carry before_snapshot, after_snapshot, and delta
// @rule:AEG-HG-2B-003 — boundary-crossing irreversible events must emit to event bus
// @rule:AEG-HG-2B-004 — gate_phase tags event to soak vs live phase
// @rule:AEG-HG-2B-005 — approval_token_ref must be a digest (digestApprovalToken), never raw token

export interface AegisSenseEvent {
  event_type: string;
  service_id: string;
  capability: string;
  operation: string;
  before_snapshot: Record<string, unknown>;
  after_snapshot: Record<string, unknown>;
  delta: Record<string, unknown>;
  emitted_at: string;
  irreversible: boolean;
  correlation_id: string;
  approval_token_ref?: string;
  idempotency_key?: string;
  gate_phase?: string;
}

export type SenseTransport = (event: AegisSenseEvent) => void;

function defaultJsonTransport(event: AegisSenseEvent): void {
  process.stdout.write(JSON.stringify({ aegis_sense: true, ...event }) + '\n');
}

let _transport: SenseTransport = defaultJsonTransport;

export function configureSenseTransport(transport: SenseTransport): void {
  _transport = transport;
}

// @rule:CA-003 — all three snapshot fields are required by the type; callers must supply them.
// approval_token_ref, if present, must already be the output of digestApprovalToken (AEG-HG-2B-005).
// @rule:ACC-003 — also emit an ACC receipt for cockpit observability (no-op when bus unset).
export function emitAegisSenseEvent(event: AegisSenseEvent): void {
  _transport(event);
  emitAccReceiptFromSense(event);
}

import { emitAccReceipt } from './acc-bus.js';

function emitAccReceiptFromSense(event: AegisSenseEvent): void {
  emitAccReceipt({
    receipt_id: `aegis-guard-sense-${event.correlation_id || Date.now()}`,
    event_type: 'lock.sense.emitted',
    verdict: event.irreversible ? 'WARN' : 'PASS',
    rules_fired: ['CA-003', 'AEG-HG-2B-003', 'AEG-HG-2B-005'],
    summary: `${event.service_id}/${event.capability}/${event.operation} ${event.irreversible ? '(irreversible)' : ''}`,
    payload: {
      event_type: event.event_type,
      correlation_id: event.correlation_id,
      approval_token_ref: event.approval_token_ref,
      delta: event.delta,
    },
  });
}
