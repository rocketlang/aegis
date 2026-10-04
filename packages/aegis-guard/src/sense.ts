// @rule:CA-003 — SENSE events carry before_snapshot, after_snapshot, and delta
// @rule:AEG-HG-2B-003 — boundary-crossing irreversible events must emit to event bus
// @rule:AEG-HG-2B-004 — gate_phase tags event to soak vs live phase
// @rule:AEG-HG-2B-005 — approval_token_ref must be a digest (digestApprovalToken), never raw token

import { createHash } from 'crypto';
import { emitAccReceipt } from './acc-bus.js';

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
  _transport = typeof transport === 'function' ? transport : defaultJsonTransport;
}

// The shape digestApprovalToken() returns: 24 lower-case hex characters.
const DIGEST = /^[0-9a-f]{24}$/;

// @rule:AEG-HG-2B-005 — the event is the audit record, and an audit record must not hold
// the thing it audits. A reference that is not already a digest is digested here, so a
// caller who passes the raw token by mistake does not write it to the log. (Same digest
// as digestApprovalToken; computed here so this module does not import the token module.)
function asDigest(ref: unknown): string | undefined {
  if (ref === undefined || ref === null || ref === '') return undefined;
  if (typeof ref === 'string' && DIGEST.test(ref)) return ref;
  return createHash('sha256').update(String(ref)).digest('hex').slice(0, 24);
}

// @rule:CA-003 — all three snapshot fields are required by the type; callers must supply them.
// The SDK does not check that they are present.
// @rule:ACC-003 — also emit an ACC receipt for cockpit observability (no-op when bus unset).
//
// If the transport throws, this throws: the caller of an irreversible operation should
// know its audit event was not written. (A bus that throws is different: it is swallowed.)
export function emitAegisSenseEvent(event: AegisSenseEvent): void {
  const ref = asDigest(event?.approval_token_ref);
  const safe: AegisSenseEvent = { ...event };
  if (ref === undefined) delete safe.approval_token_ref;
  else safe.approval_token_ref = ref;
  _transport(safe);
  emitAccReceiptFromSense(safe);
}

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
