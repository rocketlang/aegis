// @rule:AEG-HG-2B-006 — idempotency protects the operation; nonce protects the approval (separate locks)
// @rule:AEG-HG-2B-009 — a duplicate is a safe no-op only when both fingerprints are known
//                       and equal; a fingerprint that was never stored proves nothing
// Pattern: check DB for externalRef before mutating. Matching fingerprint = safe no-op. Mismatch = warn + reject.

import { emitAccReceipt } from './acc-bus.js';

export interface IdempotencyCheckResult {
  isDuplicate: boolean;
  payloadMismatch: boolean;
  safeNoOp: boolean;
  /**
   * False when a record exists but one of the two fingerprints is missing, so the
   * payloads could not be compared. safeNoOp is then false. Added in v0.4.0.
   */
  comparable: boolean;
}

const isText = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

// Functional helper: does not touch DB. Caller provides existingRecord and fingerprints.
// When isDuplicate=true and payloadMismatch=false and comparable=true: safeNoOp=true —
//   return existing record, do not re-execute.
// When isDuplicate=true and payloadMismatch=true: safeNoOp=false — log warning; reject or escalate.
// When isDuplicate=true and comparable=false: safeNoOp=false — the record exists but nothing
//   shows the new request is the same one. Before v0.4.0 this case was a safe no-op.
export function checkIdempotency(
  _externalRef: string,
  existingRecord: unknown,
  newFingerprint: string,
  existingFingerprint?: string,
): IdempotencyCheckResult {
  const isDuplicate = existingRecord !== null && existingRecord !== undefined;
  if (!isDuplicate) {
    return { isDuplicate: false, payloadMismatch: false, safeNoOp: false, comparable: false };
  }
  const comparable = isText(newFingerprint) && isText(existingFingerprint);
  const payloadMismatch = comparable && existingFingerprint !== newFingerprint;
  const result: IdempotencyCheckResult = {
    isDuplicate: true,
    payloadMismatch,
    safeNoOp: comparable && !payloadMismatch,
    comparable,
  };
  const ref = String(_externalRef).slice(0, 80);
  emitAccReceipt({
    receipt_id: `aegis-guard-idem-${ref}`,
    event_type: !comparable
      ? 'lock.idempotency.unverifiable'
      : payloadMismatch ? 'lock.idempotency.mismatch' : 'lock.idempotency.duplicate',
    verdict: result.safeNoOp ? 'PASS' : 'WARN',
    rules_fired: ['AEG-HG-2B-006'],
    summary: !comparable
      ? `duplicate externalRef ${ref} with no fingerprint to compare — caller must reject or escalate`
      : payloadMismatch
        ? `duplicate externalRef ${ref} with payload mismatch — caller must reject or escalate`
        : `duplicate externalRef ${ref} — safe no-op, return existing`,
  });
  return result;
}

// One spelling for one value, at every depth: keys sorted, and the values JSON cannot
// carry written so that they differ from each other and from null.
//
// The values JSON cannot carry are written as an object with one key that starts with "$".
// So that a payload cannot be written to look like one of them, a real key that starts
// with "$" gets a second "$" in front: { $bigint: "1" } and 1n do not collide.
function canonical(v: unknown, seen: Set<object>, fromToJson = false): unknown {
  if (typeof v === 'bigint') return { $bigint: v.toString() };
  if (typeof v === 'number' && !Number.isFinite(v)) return { $number: String(v) };
  if (v === null || typeof v !== 'object') return v;
  // toJSON is asked once. What it returns is read as data, and its own toJSON is not
  // called: a value whose toJSON returns itself would otherwise never finish.
  if (!fromToJson && typeof (v as { toJSON?: unknown }).toJSON === 'function') {
    return canonical((v as { toJSON: () => unknown }).toJSON(), seen, true);
  }
  if (seen.has(v)) throw new Error('buildIdempotencyFingerprint: the payload refers to itself');
  seen.add(v);
  let out: unknown;
  if (Array.isArray(v)) out = v.map((x) => canonical(x, seen));
  else if (v instanceof Map) out = { $map: [...v.entries()].map(([k, x]) => [canonical(k, seen), canonical(x, seen)]) };
  else if (v instanceof Set) out = { $set: [...v.values()].map((x) => canonical(x, seen)) };
  else {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) {
      const x = (v as Record<string, unknown>)[k];
      if (typeof x === 'function' || typeof x === 'symbol') continue; // as JSON leaves them out
      o[k.startsWith('$') ? '$' + k : k] = canonical(x, seen);
    }
    out = o;
  }
  seen.delete(v);
  return out;
}

// Build a stable base64 fingerprint from an arbitrary operation payload.
//
// The fingerprint is the payload itself, encoded — not a hash. Whoever can read a stored
// fingerprint can read the payload. Keep secrets out of it, or hash it before storing.
//
// For a flat payload of text, finite numbers, booleans and null the output is the same as
// before v0.4.0. It differs for: nested objects (their keys are now sorted too), NaN and
// ±Infinity (were null), bigint (threw), Map and Set (were {}), and a key that starts with
// "$" (it gets a second "$"). A field set to undefined is the same as the field being
// absent, as it always was.
export function buildIdempotencyFingerprint(payload: Record<string, unknown>): string {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('buildIdempotencyFingerprint: the payload must be an object of fields');
  }
  return Buffer.from(JSON.stringify(canonical(payload, new Set()))).toString('base64');
}
