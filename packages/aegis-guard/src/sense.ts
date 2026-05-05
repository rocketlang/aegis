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
export function emitAegisSenseEvent(event: AegisSenseEvent): void {
  _transport(event);
}
