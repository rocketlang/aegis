// @rule:AEG-HG-2B-006 — idempotency protects the operation; nonce protects the approval (separate locks)
// Pattern: check DB for externalRef before mutating. Matching fingerprint = safe no-op. Mismatch = warn + reject.

import { emitAccReceipt } from './acc-bus.js';

export interface IdempotencyCheckResult {
  isDuplicate: boolean;
  payloadMismatch: boolean;
  safeNoOp: boolean;
}

// Functional helper: does not touch DB. Caller provides existingRecord and fingerprints.
// When isDuplicate=true and payloadMismatch=false: safeNoOp=true — return existing record, do not re-execute.
// When isDuplicate=true and payloadMismatch=true: safeNoOp=false — log warning; reject or escalate.
export function checkIdempotency(
  _externalRef: string,
  existingRecord: unknown,
  newFingerprint: string,
  existingFingerprint?: string,
): IdempotencyCheckResult {
  const isDuplicate = existingRecord !== null && existingRecord !== undefined;
  if (!isDuplicate) {
    return { isDuplicate: false, payloadMismatch: false, safeNoOp: false };
  }
  const payloadMismatch =
    existingFingerprint !== undefined && existingFingerprint !== newFingerprint;
  const result: IdempotencyCheckResult = {
    isDuplicate: true,
    payloadMismatch,
    safeNoOp: !payloadMismatch,
  };
  emitAccReceipt({
    receipt_id: `aegis-guard-idem-${_externalRef}`,
    event_type: payloadMismatch ? 'lock.idempotency.mismatch' : 'lock.idempotency.duplicate',
    verdict: payloadMismatch ? 'WARN' : 'PASS',
    rules_fired: ['AEG-HG-2B-006'],
    summary: payloadMismatch
      ? `duplicate externalRef ${_externalRef} with payload mismatch — caller must reject or escalate`
      : `duplicate externalRef ${_externalRef} — safe no-op, return existing`,
  });
  return result;
}

// Build a stable base64 fingerprint from an arbitrary operation payload.
export function buildIdempotencyFingerprint(payload: Record<string, unknown>): string {
  const sorted = Object.keys(payload)
    .sort()
    .reduce<Record<string, unknown>>((acc, k) => { acc[k] = payload[k]; return acc; }, {});
  return Buffer.from(JSON.stringify(sorted)).toString('base64');
}
