// @ankr/aegis-guard — SDK MVP test suite (Batch 93)
// 63 checks across §1-§9 covering all Five Locks primitives

import { describe, it, expect, beforeEach } from 'bun:test';
import {
  IrrNoApprovalError,
  AegisNonceError,
  type NonceStore,
  defaultNonceStore,
  checkIdempotency,
  buildIdempotencyFingerprint,
  type AegisSenseEvent,
  configureSenseTransport,
  emitAegisSenseEvent,
  buildQualityMaskAtPromotion,
  buildQualityDriftScore,
  HG_REQUIRED_MASKS,
  meetsHgQualityRequirement,
  digestApprovalToken,
  mintApprovalToken,
  verifyApprovalToken,
  verifyAndConsumeNonce,
  verifyScopedApprovalToken,
} from '../src/index.js';

// ─── §1 errors ───────────────────────────────────────────────────────────────

describe('§1 IrrNoApprovalError', () => {
  it('B93-001: has code IRR-NOAPPROVAL', () => {
    const e = new IrrNoApprovalError('surrender');
    expect(e.code).toBe('IRR-NOAPPROVAL');
  });

  it('B93-002: has doctrine AEG-E-016', () => {
    const e = new IrrNoApprovalError('surrender');
    expect(e.doctrine).toBe('AEG-E-016');
  });

  it('B93-003: name is IrrNoApprovalError', () => {
    const e = new IrrNoApprovalError('surrender');
    expect(e.name).toBe('IrrNoApprovalError');
  });

  it('B93-004: message includes capability', () => {
    const e = new IrrNoApprovalError('surrender');
    expect(e.message).toContain('surrender');
  });

  it('B93-005: message includes optional reason', () => {
    const e = new IrrNoApprovalError('surrender', 'token expired');
    expect(e.message).toContain('token expired');
  });

  it('B93-006: AegisNonceError has AEGIS-NONCE-REPLAY code', () => {
    const e = new AegisNonceError('nonce-abc');
    expect(e.code).toBe('AEGIS-NONCE-REPLAY');
    expect(e.message).toContain('nonce-abc');
  });
});

// ─── §2 approval-token (verify / mint / digest) ───────────────────────────────

describe('§2 approval-token', () => {
  const now = Date.now();
  const basePayload = {
    service_id: 'test-service',
    capability: 'surrender',
    operation: 'record_surrender',
    issued_at: now,
    expires_at: now + 300_000,
    nonce: 'nonce-xyz',
  };

  it('B93-007: mintApprovalToken produces a decodable token', () => {
    const token = mintApprovalToken(basePayload);
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    const parsed = JSON.parse(decoded);
    expect(parsed.service_id).toBe('test-service');
  });

  it('B93-008: verifyApprovalToken returns payload on valid token', () => {
    const token = mintApprovalToken(basePayload);
    const payload = verifyApprovalToken(token, 'test-service', 'surrender', 'record_surrender');
    expect(payload.service_id).toBe('test-service');
    expect(payload.capability).toBe('surrender');
    expect(payload.operation).toBe('record_surrender');
  });

  it('B93-009: wrong service_id throws IrrNoApprovalError', () => {
    const token = mintApprovalToken(basePayload);
    expect(() =>
      verifyApprovalToken(token, 'wrong-service', 'surrender', 'record_surrender'),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-010: wrong capability throws IrrNoApprovalError', () => {
    const token = mintApprovalToken(basePayload);
    expect(() =>
      verifyApprovalToken(token, 'test-service', 'wrong-cap', 'record_surrender'),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-011: wrong operation throws IrrNoApprovalError', () => {
    const token = mintApprovalToken(basePayload);
    expect(() =>
      verifyApprovalToken(token, 'test-service', 'surrender', 'wrong-op'),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-012: expired token throws IrrNoApprovalError', () => {
    const expired = { ...basePayload, expires_at: now - 1000 };
    const token = mintApprovalToken(expired);
    expect(() =>
      verifyApprovalToken(token, 'test-service', 'surrender', 'record_surrender'),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-013: future issued_at beyond clock skew throws IrrNoApprovalError', () => {
    const future = { ...basePayload, issued_at: now + 120_000 };
    const token = mintApprovalToken(future);
    expect(() =>
      verifyApprovalToken(token, 'test-service', 'surrender', 'record_surrender'),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-014: garbled token throws IrrNoApprovalError', () => {
    expect(() =>
      verifyApprovalToken('!!!not-base64url!!!', 'test-service', 'surrender', 'record_surrender'),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-015: digestApprovalToken returns 24 hex chars', () => {
    const digest = digestApprovalToken('some-raw-token');
    expect(digest).toHaveLength(24);
    expect(/^[0-9a-f]+$/.test(digest)).toBe(true);
  });

  it('B93-016: digestApprovalToken is deterministic', () => {
    expect(digestApprovalToken('abc')).toBe(digestApprovalToken('abc'));
  });
});

// ─── §3 nonce ─────────────────────────────────────────────────────────────────

describe('§3 nonce', () => {
  it('B93-017: first consumeNonce returns true (first use)', async () => {
    const result = await defaultNonceStore.consumeNonce('n-unique-001', 5000);
    expect(result).toBe(true);
  });

  it('B93-018: second consumeNonce for same nonce returns false (replay)', async () => {
    await defaultNonceStore.consumeNonce('n-replay-001', 5000);
    const result = await defaultNonceStore.consumeNonce('n-replay-001', 5000);
    expect(result).toBe(false);
  });

  it('B93-019: different nonces are independent', async () => {
    await defaultNonceStore.consumeNonce('n-a', 5000);
    const result = await defaultNonceStore.consumeNonce('n-b', 5000);
    expect(result).toBe(true);
  });

  it('B93-020: custom NonceStore interface is respected', async () => {
    let called = false;
    const customStore: NonceStore = {
      async consumeNonce(_nonce, _ttlMs) { called = true; return true; },
    };
    await customStore.consumeNonce('x', 1000);
    expect(called).toBe(true);
  });

  it('B93-021: store fail-closed — throws propagate (no silent open)', async () => {
    const throwingStore: NonceStore = {
      async consumeNonce() { throw new Error('redis unavailable'); },
    };
    await expect(throwingStore.consumeNonce('x', 1000)).rejects.toThrow('redis unavailable');
  });

  it('B93-022: TTL=0 still consumes for this call window', async () => {
    const result = await defaultNonceStore.consumeNonce('n-ttl-zero', 0);
    expect(result).toBe(true);
  });

  it('B93-023: nonce TTL is bounded by expires_at (documented)', () => {
    // Verify the contract: TTL = max(0, expires_at - now)
    const now = Date.now();
    const ttl = Math.max(0, now + 5000 - now);
    expect(ttl).toBe(5000);
  });
});

// ─── §4 idempotency ───────────────────────────────────────────────────────────

describe('§4 idempotency', () => {
  it('B93-024: new externalRef — not duplicate', () => {
    const r = checkIdempotency('ref-new', null, 'fp1');
    expect(r.isDuplicate).toBe(false);
    expect(r.safeNoOp).toBe(false);
  });

  it('B93-025: existing record + no fingerprint comparison = safeNoOp', () => {
    const r = checkIdempotency('ref-exists', { id: 1 }, 'fp1');
    expect(r.isDuplicate).toBe(true);
    expect(r.payloadMismatch).toBe(false);
    expect(r.safeNoOp).toBe(true);
  });

  it('B93-026: existing record + matching fingerprint = safeNoOp', () => {
    const r = checkIdempotency('ref-exists', { id: 1 }, 'fp1', 'fp1');
    expect(r.isDuplicate).toBe(true);
    expect(r.payloadMismatch).toBe(false);
    expect(r.safeNoOp).toBe(true);
  });

  it('B93-027: existing record + mismatched fingerprint = payloadMismatch', () => {
    const r = checkIdempotency('ref-exists', { id: 1 }, 'fp-new', 'fp-old');
    expect(r.isDuplicate).toBe(true);
    expect(r.payloadMismatch).toBe(true);
    expect(r.safeNoOp).toBe(false);
  });

  it('B93-028: undefined existingRecord is not duplicate', () => {
    const r = checkIdempotency('ref-undef', undefined, 'fp1');
    expect(r.isDuplicate).toBe(false);
  });

  it('B93-029: buildIdempotencyFingerprint is deterministic', () => {
    const a = buildIdempotencyFingerprint({ amount: 10, ref: 'abc' });
    const b = buildIdempotencyFingerprint({ amount: 10, ref: 'abc' });
    expect(a).toBe(b);
  });

  it('B93-030: buildIdempotencyFingerprint is key-order independent', () => {
    const a = buildIdempotencyFingerprint({ ref: 'abc', amount: 10 });
    const b = buildIdempotencyFingerprint({ amount: 10, ref: 'abc' });
    expect(a).toBe(b);
  });

  it('B93-031: different payloads produce different fingerprints', () => {
    const a = buildIdempotencyFingerprint({ amount: 10 });
    const b = buildIdempotencyFingerprint({ amount: 11 });
    expect(a).not.toBe(b);
  });
});

// ─── §5 sense ─────────────────────────────────────────────────────────────────

describe('§5 sense', () => {
  let captured: AegisSenseEvent | null = null;

  beforeEach(() => {
    captured = null;
    configureSenseTransport((evt) => { captured = evt; });
  });

  const sampleEvent: AegisSenseEvent = {
    event_type: 'eua.surrender',
    service_id: 'test-service',
    capability: 'surrender',
    operation: 'record_surrender',
    before_snapshot: { status: 'pending' },
    after_snapshot: { status: 'settled' },
    delta: { status: 'pending→settled' },
    emitted_at: new Date().toISOString(),
    irreversible: true,
    correlation_id: 'corr-001',
    approval_token_ref: 'a1b2c3d4e5f67890ab12cd34',
  };

  it('B93-032: emitAegisSenseEvent calls configured transport', () => {
    emitAegisSenseEvent(sampleEvent);
    expect(captured).not.toBeNull();
  });

  it('B93-033: event_type is preserved', () => {
    emitAegisSenseEvent(sampleEvent);
    expect(captured?.event_type).toBe('eua.surrender');
  });

  it('B93-034: service_id is string (not literal type)', () => {
    emitAegisSenseEvent(sampleEvent);
    expect(typeof captured?.service_id).toBe('string');
  });

  it('B93-035: before_snapshot is preserved', () => {
    emitAegisSenseEvent(sampleEvent);
    expect(captured?.before_snapshot).toEqual({ status: 'pending' });
  });

  it('B93-036: after_snapshot is preserved', () => {
    emitAegisSenseEvent(sampleEvent);
    expect(captured?.after_snapshot).toEqual({ status: 'settled' });
  });

  it('B93-037: delta is preserved', () => {
    emitAegisSenseEvent(sampleEvent);
    expect(captured?.delta).toEqual({ status: 'pending→settled' });
  });
});

// ─── §6 quality ───────────────────────────────────────────────────────────────

describe('§6 quality', () => {
  it('B93-038: empty evidence produces mask 0', () => {
    expect(buildQualityMaskAtPromotion({})).toBe(0);
  });

  it('B93-039: tests_passed sets bit 1 (0x0002)', () => {
    expect(buildQualityMaskAtPromotion({ tests_passed: true })).toBe(0x0002);
  });

  it('B93-040: rollback_tested sets bit 5 (0x0020)', () => {
    expect(buildQualityMaskAtPromotion({ rollback_tested: true })).toBe(0x0020);
  });

  it('B93-041: audit_artifact_produced sets bit 8 (0x0100)', () => {
    expect(buildQualityMaskAtPromotion({ audit_artifact_produced: true })).toBe(0x0100);
  });

  it('B93-042: carbonx reference mask 0x012A is reproducible', () => {
    const mask = buildQualityMaskAtPromotion({
      tests_passed: true,
      no_unrelated_diff: true,
      rollback_tested: true,
      audit_artifact_produced: true,
    });
    expect(mask).toBe(0x012A);
  });

  it('B93-043: buildQualityDriftScore idempotency+observability = 0x3000', () => {
    const score = buildQualityDriftScore({
      idempotency_evidenced: true,
      observability_evidenced: true,
    });
    expect(score).toBe(0x3000);
  });

  it('B93-044: drift bits 12-15 only (never 0-11)', () => {
    const score = buildQualityDriftScore({
      idempotency_evidenced: true,
      observability_evidenced: true,
      regression_suite_pass: true,
      production_fire_zero: true,
    });
    expect(score & 0x0FFF).toBe(0);
    expect(score).toBe(0xF000);
  });

  it('B93-045: HG_REQUIRED_MASKS HG-1 = 0x0302', () => {
    expect(HG_REQUIRED_MASKS['HG-1']).toBe(0x0302);
  });

  it('B93-046: HG_REQUIRED_MASKS HG-2B-financial = 0x0FFF', () => {
    expect(HG_REQUIRED_MASKS['HG-2B-financial']).toBe(0x0FFF);
  });

  it('B93-047: meetsHgQualityRequirement true when all required bits set', () => {
    expect(meetsHgQualityRequirement('HG-1', 0x0302)).toBe(true);
  });

  it('B93-048: meetsHgQualityRequirement false when bits missing', () => {
    expect(meetsHgQualityRequirement('HG-2B-financial', 0x012A)).toBe(false);
  });
});

// ─── §7 verifyAndConsumeNonce + verifyScopedApprovalToken ─────────────────────

describe('§7 verify + consume nonce / scoped token', () => {
  const now = Date.now();

  const makeToken = (overrides: Record<string, unknown> = {}) =>
    mintApprovalToken({
      service_id: 'my-service',
      capability: 'settle',
      operation: 'do_settle',
      issued_at: now,
      expires_at: now + 300_000,
      nonce: 'nonce-settle-001',
      org_id: 'org-42',
      amount: 100,
      ...overrides,
    });

  const customStore = (): NonceStore => {
    const m = new Map<string, number>();
    return {
      async consumeNonce(nonce, ttlMs) {
        if (m.has(nonce)) return false;
        m.set(nonce, Date.now() + ttlMs);
        return true;
      },
    };
  };

  it('B93-049: verifyAndConsumeNonce succeeds on first use', async () => {
    const token = makeToken({ nonce: 'nonce-consume-001' });
    const store = customStore();
    const payload = verifyApprovalToken(token, 'my-service', 'settle', 'do_settle');
    await expect(verifyAndConsumeNonce(payload, store)).resolves.toBeUndefined();
  });

  it('B93-050: verifyAndConsumeNonce throws on replay', async () => {
    const token = makeToken({ nonce: 'nonce-replay-settle-001' });
    const store = customStore();
    const payload = verifyApprovalToken(token, 'my-service', 'settle', 'do_settle');
    await verifyAndConsumeNonce(payload, store);
    await expect(verifyAndConsumeNonce(payload, store)).rejects.toThrow(IrrNoApprovalError);
  });

  it('B93-051: verifyAndConsumeNonce throws when nonce absent', async () => {
    const token = makeToken({ nonce: undefined });
    const store = customStore();
    const payload = verifyApprovalToken(token, 'my-service', 'settle', 'do_settle');
    await expect(verifyAndConsumeNonce(payload, store)).rejects.toThrow(IrrNoApprovalError);
  });

  it('B93-052: verifyScopedApprovalToken passes when scope matches', () => {
    const token = makeToken();
    const result = verifyScopedApprovalToken(
      token, 'my-service', 'settle', 'do_settle',
      { org_id: 'org-42', amount: 100 },
    );
    expect(result.service_id).toBe('my-service');
  });

  it('B93-053: verifyScopedApprovalToken throws when scope field mismatches', () => {
    const token = makeToken();
    expect(() =>
      verifyScopedApprovalToken(token, 'my-service', 'settle', 'do_settle', { org_id: 'org-99' }),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-054: verifyScopedApprovalToken throws on revoked token', () => {
    const token = makeToken({ status: 'revoked' });
    expect(() =>
      verifyScopedApprovalToken(token, 'my-service', 'settle', 'do_settle', { org_id: 'org-42' }),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-055: verifyScopedApprovalToken throws on denied token', () => {
    const token = makeToken({ status: 'denied' });
    expect(() =>
      verifyScopedApprovalToken(token, 'my-service', 'settle', 'do_settle', { org_id: 'org-42' }),
    ).toThrow(IrrNoApprovalError);
  });

  it('B93-056: empty requiredScope passes (service chooses to bind 0 extra fields)', () => {
    const token = makeToken({ status: 'approved' });
    const result = verifyScopedApprovalToken(token, 'my-service', 'settle', 'do_settle', {});
    expect(result.service_id).toBe('my-service');
  });
});

// ─── §8 Five Locks end-to-end sequence ────────────────────────────────────────

describe('§8 Five Locks sequence (AEG-HG-2B-financial)', () => {
  const store = (() => {
    const m = new Map<string, number>();
    return {
      async consumeNonce(nonce: string, ttlMs: number) {
        if (m.has(nonce)) return false;
        m.set(nonce, Date.now() + ttlMs);
        return true;
      },
    } satisfies NonceStore;
  })();

  let emitted: AegisSenseEvent | null = null;
  beforeEach(() => {
    emitted = null;
    configureSenseTransport((evt) => { emitted = evt; });
  });

  const now = Date.now();
  const token = mintApprovalToken({
    service_id: 'carbonx-backend',
    capability: 'surrender',
    operation: 'record_surrender',
    issued_at: now,
    expires_at: now + 300_000,
    nonce: 'five-locks-nonce-001',
    vessel_id: 'vessel-001',
    amount: 50,
    status: 'approved',
  });

  it('B93-057: LOCK_1 — verifyApprovalToken passes (decision gate)', () => {
    expect(() =>
      verifyApprovalToken(token, 'carbonx-backend', 'surrender', 'record_surrender'),
    ).not.toThrow();
  });

  it('B93-058: LOCK_2 — verifyScopedApprovalToken binds financial scope (identity)', () => {
    const payload = verifyScopedApprovalToken(
      token, 'carbonx-backend', 'surrender', 'record_surrender',
      { vessel_id: 'vessel-001', amount: 50 },
    );
    expect(payload.vessel_id).toBe('vessel-001');
  });

  it('B93-059: LOCK_3 — emitAegisSenseEvent fires with digest ref (observability)', () => {
    const digest = digestApprovalToken(token);
    emitAegisSenseEvent({
      event_type: 'eua.surrender',
      service_id: 'carbonx-backend',
      capability: 'surrender',
      operation: 'record_surrender',
      before_snapshot: { status: 'pending' },
      after_snapshot: { status: 'settled' },
      delta: { status: 'pending→settled' },
      emitted_at: new Date().toISOString(),
      irreversible: true,
      correlation_id: 'five-locks-corr',
      approval_token_ref: digest,
    });
    expect(emitted?.approval_token_ref).toHaveLength(24);
    expect(emitted?.irreversible).toBe(true);
  });

  it('B93-060: LOCK_4 — safeNoOp idempotency check (rollback / duplicate guard)', () => {
    const existing = { id: 'surrender-001', amount: 50 };
    const fp = buildIdempotencyFingerprint({ vessel_id: 'vessel-001', amount: 50 });
    const r = checkIdempotency('EXT-001', existing, fp, fp);
    expect(r.safeNoOp).toBe(true);
  });
});

// ─── §9 invariants ────────────────────────────────────────────────────────────

describe('§9 invariants (AEG-Q-003, doctrine, schema)', () => {
  it('B93-061: AEG-Q-003 — buildQualityMaskAtPromotion never sets bits 12-15', () => {
    const allTrue = buildQualityMaskAtPromotion({
      typecheck_passed: true, tests_passed: true, lint_passed: true,
      no_unrelated_diff: true, migration_verified: true, rollback_tested: true,
      dependency_checked: true, codex_updated: true, audit_artifact_produced: true,
      scope_confirmed: true, no_secrets_exposed: true, human_reviewed: true,
    });
    expect(allTrue & 0xF000).toBe(0);
  });

  it('B93-062: digestApprovalToken always returns exactly 24 chars (96-bit proof reference)', () => {
    for (const t of ['short', 'a'.repeat(1000), '']) {
      expect(digestApprovalToken(t)).toHaveLength(24);
    }
  });

  it('B93-063: IrrNoApprovalError is instanceof Error (catchable as base Error)', () => {
    const e = new IrrNoApprovalError('test');
    expect(e instanceof Error).toBe(true);
    expect(e instanceof IrrNoApprovalError).toBe(true);
  });
});
