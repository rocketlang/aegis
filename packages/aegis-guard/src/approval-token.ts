// @rule:AEG-E-016 — approval tokens are scoped to service_id + capability + operation
// @rule:AEG-HG-2B-005 — approval token references in SENSE use digest, not raw token material
// @rule:AEG-HG-2B-006 — nonce protects the approval; idempotency protects the operation (separate locks)
// @rule:AEG-HG-2B-008 — every field a decision rests on is checked for its type before it is
//                       compared; anything the gate cannot read is a refusal, with the
//                       package's own error, never a pass and never a TypeError

import { createHash } from 'crypto';
import { IrrNoApprovalError } from './errors.js';
import { type NonceStore, defaultNonceStore } from './nonce.js';
import { emitAccReceipt } from './acc-bus.js';
import { signApprovalJwt, verifyApprovalJwt } from './signing.js';

// Token may arrive up to 60s before local clock (NTP tolerance).
const CLOCK_SKEW_MS = 60_000;

export interface ApprovalTokenPayload {
  service_id: string;
  capability: string;
  operation: string;
  issued_at: number;
  expires_at: number;
  issued_by?: string;
  nonce?: string;
  status?: 'approved' | 'revoked' | 'denied';
  action_digest?: string; // @rule:AEG-E-016 — binds the token to the CONCRETE act, not just its label
  [key: string]: unknown;
}

const isTime = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v > 0;
const isText = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const say = (v: unknown): string => (typeof v === 'string' ? v : typeof v).slice(0, 60);
const own = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

// @rule:AEG-E-016 — action-binding is the ENFORCED default (review point 4, 2026-10-07): a token
// that does not name the concrete act (no action_digest) is refused, so one approval cannot stand
// in for every instance. A caller that knowingly accepts the old label-only behaviour sets
// AEGIS_ALLOW_LABEL_ONLY_APPROVAL=1. (The full match — digest equals the act in hand — is still the
// job of verifyActionApprovalToken; this base check guarantees no loose token is accepted anywhere.)
export const LABEL_ONLY_ENV = 'AEGIS_ALLOW_LABEL_ONLY_APPROVAL';
const labelOnlyAllowed = (): boolean => {
  const v = process.env[LABEL_ONLY_ENV];
  return v === '1' || v === 'true' || v === 'yes';
};

// @rule:AEG-HG-2B-005 — SENSE stores proof reference, not proof secret.
// Returns first 24 hex chars of SHA-256 (96 bits) — sufficient for correlation, not reconstruction.
export function digestApprovalToken(token: string): string {
  return createHash('sha256').update(String(token)).digest('hex').slice(0, 24);
}

// @rule:AEG-E-016 @rule:KGT-002 — mint an AEGIS-signed EdDSA JWT (KGT-T1.1).
// Signing requires the AEGIS private key (~/.aegis/approval-signing.key) — present on
// the AEGIS box, where the :4850 dashboard provisions it at boot with
// ensureSigningKeypair(). Throws where the key is absent: a service that cannot sign
// cannot mint, by design. Minting never makes a key.
//
// The payload is signed as given. verifyApprovalToken() will refuse a token without a
// numeric expires_at, so mint with one.
export function mintApprovalToken(payload: ApprovalTokenPayload): string {
  return signApprovalJwt(payload);
}

// @rule:AEG-E-016 — token must match service_id + capability + operation exactly.
// @rule:KGT-002 — signature verified FIRST, fail-closed: unsigned/tampered/alg:none/
// wrong-key tokens are rejected before any scope check. Legacy base64url(JSON) tokens
// (pre-KGT-T1.1, forgeable) are rejected outright.
// @rule:AEG-HG-2B-008 — expires_at must be a number; a status other than 'approved' is a
// refusal here, in LOCK_1, not only in the scoped check.
export function verifyApprovalToken(
  token: string,
  expectedServiceId: string,
  expectedCapability: string,
  expectedOperation: string,
): ApprovalTokenPayload {
  // @rule:ACC-003 @rule:ACC-004 — emit ACC receipt on success OR failure
  const cap = isText(expectedCapability) ? expectedCapability : 'unknown';
  const scope = `${say(expectedServiceId)}/${say(expectedCapability)}/${say(expectedOperation)}`;
  try {
    if (!isText(expectedServiceId) || !isText(expectedCapability) || !isText(expectedOperation)) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: the expected service, capability and operation must each be non-empty text');
    }
    const jwt = verifyApprovalJwt(token);
    if (!jwt.ok) {
      throw new IrrNoApprovalError(cap, `KGT-002: ${jwt.reason}`);
    }
    const payload = jwt.payload as ApprovalTokenPayload;

    if (payload.service_id !== expectedServiceId) {
      throw new IrrNoApprovalError(
        cap,
        `AEG-E-016: token scoped to '${say(payload.service_id)}', not '${expectedServiceId}'`,
      );
    }
    if (payload.capability !== expectedCapability) {
      throw new IrrNoApprovalError(
        cap,
        `AEG-E-016: token capability '${say(payload.capability)}' does not match '${expectedCapability}'`,
      );
    }
    if (payload.operation !== expectedOperation) {
      throw new IrrNoApprovalError(
        cap,
        `AEG-E-016: token operation '${say(payload.operation)}' does not match '${expectedOperation}'`,
      );
    }
    // A token with no expiry, or one written as text, used to compare false against the
    // clock and so never expired.
    if (!isTime(payload.expires_at)) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: token has no numeric expires_at');
    }
    if (Date.now() > payload.expires_at) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: token expired');
    }
    if (payload.issued_at !== undefined) {
      if (!isTime(payload.issued_at)) {
        throw new IrrNoApprovalError(cap, 'AEG-E-016: token issued_at is not a number');
      }
      if (payload.issued_at > Date.now() + CLOCK_SKEW_MS) {
        throw new IrrNoApprovalError(
          cap,
          'AEG-E-016: token issued_at is in the future (clock skew > 60s or forged timestamp)',
        );
      }
      if (payload.issued_at > payload.expires_at) {
        throw new IrrNoApprovalError(cap, 'AEG-E-016: token expires before it was issued');
      }
    }
    // Absent means approved (tokens minted before the field existed). Anything else that
    // is not exactly 'approved' is not an approval.
    if (payload.status !== undefined && payload.status !== 'approved') {
      throw new IrrNoApprovalError(
        cap,
        payload.status === 'revoked' ? 'AEG-E-016: token revoked'
          : payload.status === 'denied' ? 'AEG-E-016: token denied'
          : `AEG-E-016: token status '${say(payload.status)}' is not 'approved'`,
      );
    }
    if (payload.nonce !== undefined && !isText(payload.nonce)) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: token nonce is not text');
    }
    // Action-binding is the enforced default (point 4): a label-only approval authorises every
    // instance of the operation, so refuse it unless the caller opted into the old loose behaviour.
    if (!isText(payload.action_digest) && !labelOnlyAllowed()) {
      throw new IrrNoApprovalError(
        cap,
        `AEG-E-016: approval is not bound to a concrete action (no action_digest) — a label-only ` +
        `approval authorises every instance. Mint with mintActionApprovalToken()/verify with ` +
        `verifyActionApprovalToken(), or set ${LABEL_ONLY_ENV}=1 to accept label-only approvals.`,
      );
    }

    emitAccReceipt({
      receipt_id: `aegis-guard-verify-${digestApprovalToken(token)}`,
      event_type: 'lock.approval.verified',
      verdict: 'PASS',
      rules_fired: ['AEG-E-016'],
      summary: scope,
    });
    return payload;
  } catch (err) {
    emitAccReceipt({
      receipt_id: `aegis-guard-verify-fail-${Date.now()}`,
      event_type: 'lock.approval.rejected',
      verdict: 'FAIL',
      rules_fired: ['AEG-E-016'],
      summary: `${scope} — ${(err as Error).message?.slice(0, 160) ?? 'verification failed'}`,
    });
    throw err;
  }
}

// @rule:AEG-HG-2B-006 — consume nonce before any state mutation; missing nonce = hard reject.
// Nonce TTL is bounded by token lifetime; store unavailable = fail CLOSED (throws, never open).
// @rule:AEG-HG-2B-008 — the nonce must be text, the payload must be in date, and only a
// store that answers exactly `true` has consumed it.
//
// This takes a payload, not a token: it does not check a signature. Pass it what
// verifyApprovalToken() returned.
export async function verifyAndConsumeNonce(
  payload: ApprovalTokenPayload,
  store: NonceStore = defaultNonceStore,
): Promise<void> {
  // @rule:ACC-003 @rule:ACC-004 — emit ACC receipt on success OR failure
  const p = (payload !== null && typeof payload === 'object' ? payload : {}) as ApprovalTokenPayload;
  const cap = isText(p.capability) ? p.capability : 'unknown';
  const scope = `${say(p.service_id)}/${say(p.capability)}/${say(p.operation)}`;
  try {
    if (p !== payload) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: no approval payload');
    }
    if (payload.nonce === undefined || payload.nonce === null || payload.nonce === '') {
      throw new IrrNoApprovalError(
        cap,
        'AEG-E-016: irreversible operation requires nonce for replay prevention',
      );
    }
    // An object as a nonce is a different object each time the token is parsed, so it
    // would never be seen twice.
    if (!isText(payload.nonce)) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: nonce is not text');
    }
    if (!isTime(payload.expires_at)) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: approval has no numeric expires_at');
    }
    // An expired approval has nothing left to protect, and a nonce stored for zero
    // milliseconds is forgotten at once: the same approval could be consumed again.
    const ttlMs = payload.expires_at - Date.now();
    if (ttlMs <= 0) {
      throw new IrrNoApprovalError(cap, 'AEG-E-016: approval expired');
    }
    const consumed = await store.consumeNonce(payload.nonce, ttlMs);
    if (consumed !== true) {
      throw new IrrNoApprovalError(
        cap,
        `AEG-E-016: nonce '${payload.nonce.slice(0, 60)}' already consumed — approval replay rejected`,
      );
    }
    emitAccReceipt({
      receipt_id: `aegis-guard-nonce-${payload.nonce.slice(0, 80)}`,
      event_type: 'lock.nonce.consumed',
      verdict: 'PASS',
      rules_fired: ['AEG-HG-2B-006'],
      summary: scope,
    });
  } catch (err) {
    emitAccReceipt({
      receipt_id: `aegis-guard-nonce-fail-${Date.now()}`,
      event_type: 'lock.nonce.rejected',
      verdict: 'FAIL',
      rules_fired: ['AEG-HG-2B-006'],
      summary: `${scope} — ${(err as Error).message?.slice(0, 160) ?? 'nonce check failed'}`,
    });
    throw err;
  }
}

// @rule:AEG-E-016 — HG-2B: verify scope fields declared by the caller service.
// requiredScope: Record<string, unknown> — caller declares which fields to bind; SDK enforces them.
// Service-agnostic: the caller owns the field names; the SDK never names domain concepts.
// @rule:AEG-HG-2B-008 — a field the caller has no value for binds nothing, so it is a
// refusal: before v0.4.0 `{ vessel_id: undefined }` matched any token without a vessel_id.
//
// An empty requiredScope checks nothing more than verifyApprovalToken() does.
export function verifyScopedApprovalToken(
  token: string,
  expectedServiceId: string,
  expectedCapability: string,
  expectedOperation: string,
  requiredScope: Record<string, unknown>,
): ApprovalTokenPayload {
  const payload = verifyApprovalToken(
    token, expectedServiceId, expectedCapability, expectedOperation,
  );

  if (requiredScope === null || typeof requiredScope !== 'object' || Array.isArray(requiredScope)) {
    throw new IrrNoApprovalError(expectedCapability, 'AEG-E-016: required scope is not an object of fields');
  }

  for (const [field, contextValue] of Object.entries(requiredScope)) {
    if (contextValue === undefined || contextValue === null) {
      throw new IrrNoApprovalError(
        expectedCapability,
        `AEG-E-016: scope field '${field}' has no value to bind the token to`,
      );
    }
    const tokenValue = own(payload, field) ? payload[field] : undefined;
    if (tokenValue !== contextValue) {
      throw new IrrNoApprovalError(
        expectedCapability,
        `AEG-E-016: token ${field} '${String(tokenValue).slice(0, 60)}' does not match scope '${String(contextValue).slice(0, 60)}'`,
      );
    }
  }

  return payload;
}

// @rule:AEG-E-016 — bind an approval to the CONCRETE act, not just its label.
// An independent review (Oct 2026) showed a token scoped only to service/capability/operation
// approves ANY instance of that operation: one 'drop_table' approval drops any table. The fix is a
// digest of the concrete action (which table, which amount, which recipient) carried in the signed
// payload as action_digest; the gate recomputes it from the act in hand and refuses a mismatch.
// This rides the existing, hardened verifyScopedApprovalToken (a field with no token value refuses),
// so a token minted without an action_digest cannot pass the action-bound check at all.

// Deterministic JSON: keys sorted, so {a,b} and {b,a} digest the same.
function stableStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  const o = v as Record<string, unknown>;
  return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + stableStringify(o[k])).join(',') + '}';
}

// SHA-256 of the canonical action. The caller owns what 'the action' is; the SDK never names domain concepts.
export function actionDigest(action: unknown): string {
  return createHash('sha256').update(stableStringify(action)).digest('hex');
}

// Mint an approval already bound to a concrete action (adds action_digest to the signed payload).
export function mintActionApprovalToken(payload: ApprovalTokenPayload, action: unknown): string {
  return mintApprovalToken({ ...payload, action_digest: actionDigest(action) });
}

// Verify an approval against the concrete action in hand. The token MUST carry a matching action_digest;
// a label-only token (no action_digest) is refused here, closing "one approval fits every instance".
export function verifyActionApprovalToken(
  token: string,
  expectedServiceId: string,
  expectedCapability: string,
  expectedOperation: string,
  action: unknown,
): ApprovalTokenPayload {
  return verifyScopedApprovalToken(
    token, expectedServiceId, expectedCapability, expectedOperation,
    { action_digest: actionDigest(action) },
  );
}
