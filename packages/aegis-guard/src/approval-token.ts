// @rule:AEG-E-016 — approval tokens are scoped to service_id + capability + operation
// @rule:AEG-HG-2B-005 — approval token references in SENSE use digest, not raw token material
// @rule:AEG-HG-2B-006 — nonce protects the approval; idempotency protects the operation (separate locks)

import { createHash } from 'crypto';
import { IrrNoApprovalError } from './errors.js';
import { type NonceStore, defaultNonceStore } from './nonce.js';

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
  [key: string]: unknown;
}

// @rule:AEG-HG-2B-005 — SENSE stores proof reference, not proof secret.
// Returns first 24 hex chars of SHA-256 (96 bits) — sufficient for correlation, not reconstruction.
export function digestApprovalToken(token: string): string {
  return createHash('sha256').update(token).digest('hex').slice(0, 24);
}

// @rule:AEG-E-016 — test/dev helper: encode a payload as base64url JSON.
// Production tokens are minted by the AEGIS PROOF system (port 4850), not by services.
export function mintApprovalToken(payload: ApprovalTokenPayload): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

// @rule:AEG-E-016 — token must match service_id + capability + operation exactly.
// Token format: base64url(JSON). Production replacement: JWT signed by AEGIS key at port 4850.
export function verifyApprovalToken(
  token: string,
  expectedServiceId: string,
  expectedCapability: string,
  expectedOperation: string,
): ApprovalTokenPayload {
  let payload: ApprovalTokenPayload;

  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    payload = JSON.parse(decoded) as ApprovalTokenPayload;
  } catch {
    throw new IrrNoApprovalError(expectedCapability, 'token could not be decoded');
  }

  if (payload.service_id !== expectedServiceId) {
    throw new IrrNoApprovalError(
      expectedCapability,
      `AEG-E-016: token scoped to '${payload.service_id}', not '${expectedServiceId}'`,
    );
  }

  if (payload.capability !== expectedCapability) {
    throw new IrrNoApprovalError(
      expectedCapability,
      `AEG-E-016: token capability '${payload.capability}' does not match '${expectedCapability}'`,
    );
  }

  if (payload.operation !== expectedOperation) {
    throw new IrrNoApprovalError(
      expectedCapability,
      `AEG-E-016: token operation '${payload.operation}' does not match '${expectedOperation}'`,
    );
  }

  if (Date.now() > payload.expires_at) {
    throw new IrrNoApprovalError(expectedCapability, 'AEG-E-016: token expired');
  }

  if (payload.issued_at !== undefined && payload.issued_at > Date.now() + CLOCK_SKEW_MS) {
    throw new IrrNoApprovalError(
      expectedCapability,
      'AEG-E-016: token issued_at is in the future (clock skew > 60s or forged timestamp)',
    );
  }

  return payload;
}

// @rule:AEG-HG-2B-006 — consume nonce before any state mutation; missing nonce = hard reject.
// Nonce TTL is bounded by token lifetime; store unavailable = fail CLOSED (throws, never open).
export async function verifyAndConsumeNonce(
  payload: ApprovalTokenPayload,
  store: NonceStore = defaultNonceStore,
): Promise<void> {
  if (!payload.nonce) {
    throw new IrrNoApprovalError(
      payload.capability,
      'AEG-E-016: irreversible operation requires nonce for replay prevention',
    );
  }
  const ttlMs = Math.max(0, payload.expires_at - Date.now());
  const consumed = await store.consumeNonce(payload.nonce, ttlMs);
  if (!consumed) {
    throw new IrrNoApprovalError(
      payload.capability,
      `AEG-E-016: nonce '${payload.nonce}' already consumed — approval replay rejected`,
    );
  }
}

// @rule:AEG-E-016 — HG-2B: verify scope fields declared by the caller service.
// requiredScope: Record<string, unknown> — caller declares which fields to bind; SDK enforces them.
// Service-agnostic: the caller owns the field names; the SDK never names domain concepts.
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

  if (payload.status === 'revoked') {
    throw new IrrNoApprovalError(expectedCapability, 'AEG-E-016: token revoked');
  }
  if (payload.status === 'denied') {
    throw new IrrNoApprovalError(expectedCapability, 'AEG-E-016: token denied');
  }

  for (const [field, contextValue] of Object.entries(requiredScope)) {
    const tokenValue = payload[field];
    if (tokenValue !== contextValue) {
      throw new IrrNoApprovalError(
        expectedCapability,
        `AEG-E-016: token ${field} '${String(tokenValue)}' does not match scope '${String(contextValue)}'`,
      );
    }
  }

  return payload;
}
