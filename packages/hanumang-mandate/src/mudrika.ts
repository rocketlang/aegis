// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// HanumanG — Mudrika verification engine
// @rule:HNG-S-001 — mudrika is the mandatory delegation credential; no mudrika = refuse
// @rule:HNG-S-008 — mudrika structure: principal_id, agent_id, trust_mask, scope_key, ttl, pramana_chain
// @rule:HNG-S-009 — mudrika TTL must not be expired at verification time
// @rule:HNG-S-010 — trust_mask in mudrika must be ≤ trust_mask of principal (spawn invariant)
// @rule:HNG-S-011 — revocation_url must be reachable; REVOKED mudrikas refuse immediately
//
// PHASE-1 LIMIT: verifyMudrika() validates STRUCTURE + TTL + trust_mask range only.
// It does NOT cryptographically verify the `signature` field. Phase-2 will add
// signature verification. Today, mudrika trust is assumed to come from an
// authenticated channel; callers must verify provenance themselves.

import { emitAccReceipt } from './acc-bus.js';

export interface MudrikaPayload {
  mudrika_version: string;
  mudrika_id: string;
  principal_id: string;
  agent_id: string;
  task_id: string;
  trust_mask: number;
  scope_key: string;
  issued_at: string;
  ttl_seconds: number;
  required_return_proof: string;
  revocation_url: string;
  pramana_chain: string[];
  signature?: string;
}

/** Versions this verifier understands: `v1`, `1`, `v1.2`, … */
const SUPPORTED_VERSION = /^v?1(\.\d+)*$/;
/** The longest life a credential may claim: one year. A delegation is not a standing grant. */
export const MAX_TTL_SECONDS = 366 * 24 * 3600;
/** How far ahead of this machine's clock `issued_at` may be. */
export const CLOCK_SKEW_MS = 5 * 60 * 1000;

export type VerifyOutcome = 'PASS' | 'FAIL' | 'EXPIRED' | 'REVOKED';

export interface VerifyResult {
  outcome: VerifyOutcome;
  failure_reason: string | null;
  expires_at: string;
  trust_mask: number;
  scope_key: string;
  principal_id: string;
  mudrika_id: string;
  pramana_chain: string[];
  duration_ms: number;
  /**
   * Always false in this version: the `signature` field is NOT checked (Phase-1 limit).
   * It is a field, and not only a sentence in the README, so that a caller reading the
   * result of a PASS cannot take it for a cryptographic one.
   */
  signature_verified: false;
}

export function verifyMudrika(raw: unknown, expected_agent_id?: string): VerifyResult {
  const t0 = Date.now();

  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return fail('mudrika_missing', t0);
  }

  // Only the object's own fields count. A credential whose fields come from its prototype
  // is not the document that was handed over.
  const m = { ...(raw as object) } as Partial<MudrikaPayload>;

  // Required fields
  if (
    !m.mudrika_id ||
    !m.principal_id ||
    !m.agent_id ||
    !m.task_id ||
    !m.scope_key ||
    !m.issued_at ||
    !m.ttl_seconds
  ) {
    return fail('missing_required_fields', t0);
  }

  // @rule:HNG-S-012 — a field of the wrong type is a refusal, never a value to carry on with.
  // Before v0.3.0 only presence was checked: a trust_mask of NaN or "admin" passed, and
  // a ttl_seconds of 1e18 or "forever" made the function throw instead of answer.
  for (const f of ['mudrika_id', 'principal_id', 'agent_id', 'task_id', 'scope_key', 'issued_at'] as const) {
    if (typeof m[f] !== 'string') return fail(`invalid_field_type: ${f}`, t0);
  }
  if (m.mudrika_version !== undefined && (typeof m.mudrika_version !== 'string' || !SUPPORTED_VERSION.test(m.mudrika_version))) {
    return fail('unsupported_mudrika_version', t0);
  }
  if (typeof m.ttl_seconds !== 'number' || !Number.isFinite(m.ttl_seconds) || m.ttl_seconds <= 0 || m.ttl_seconds > MAX_TTL_SECONDS) {
    return fail('invalid_ttl_seconds', t0);
  }
  if (m.trust_mask !== undefined && m.trust_mask !== null && !Number.isInteger(m.trust_mask)) {
    return fail('invalid_trust_mask', t0);
  }
  if (m.pramana_chain !== undefined && (!Array.isArray(m.pramana_chain) || m.pramana_chain.some((x) => typeof x !== 'string'))) {
    return fail('invalid_pramana_chain', t0);
  }

  // Agent ID must match if the caller names one. An empty or non-text expectation is a
  // caller error and is refused: before v0.3.0 an empty string silently skipped the check.
  if (expected_agent_id !== undefined) {
    if (typeof expected_agent_id !== 'string' || expected_agent_id.length === 0) {
      return fail('invalid_expected_agent_id', t0);
    }
    if (m.agent_id !== expected_agent_id) {
      return fail(`agent_id_mismatch: expected ${expected_agent_id} got ${m.agent_id}`, t0);
    }
  }

  // TTL check — @rule:HNG-S-009
  const issuedAt = new Date(m.issued_at).getTime();
  if (isNaN(issuedAt)) return fail('invalid_issued_at', t0);
  // A credential dated in the future is not yet valid, and with a long ttl would never
  // expire in practice. A small allowance covers clocks that disagree.
  if (issuedAt > Date.now() + CLOCK_SKEW_MS) return fail('issued_in_future', t0);
  const expiresAt = new Date(issuedAt + m.ttl_seconds * 1000);
  if (Date.now() > expiresAt.getTime()) {
    const expiredResult: VerifyResult = {
      outcome: 'EXPIRED',
      failure_reason: `mudrika expired at ${expiresAt.toISOString()}`,
      expires_at: expiresAt.toISOString(),
      trust_mask: m.trust_mask ?? 0,
      scope_key: m.scope_key ?? '',
      principal_id: m.principal_id ?? '',
      mudrika_id: m.mudrika_id ?? '',
      pramana_chain: m.pramana_chain ?? [],
      duration_ms: Date.now() - t0,
      signature_verified: false,
    };
    emitAccReceipt({
      receipt_id: `hanumang-mudrika-expired-${m.mudrika_id ?? t0}`,
      event_type: 'mudrika.rejected',
      agent_id: m.agent_id,
      verdict: 'EXPIRED',
      rules_fired: ['HNG-S-009'],
      summary: `mudrika ${m.mudrika_id ?? '?'} expired at ${expiresAt.toISOString()}`,
    });
    return expiredResult;
  }

  // Spawn invariant — child trust_mask ≤ declared maximum (32-bit)
  // @rule:HNG-S-010 + BitMask OS spawn invariant
  const trust_mask = m.trust_mask ?? 0;
  if (trust_mask < 0 || trust_mask > 0xffffffff) {
    return fail('trust_mask_out_of_range', t0);
  }

  // Pramana chain present (warning if empty — not blocking at verification stage)
  const pramana_chain = m.pramana_chain ?? [];

  const result: VerifyResult = {
    outcome: 'PASS',
    failure_reason: null,
    expires_at: expiresAt.toISOString(),
    trust_mask,
    scope_key: m.scope_key,
    principal_id: m.principal_id,
    mudrika_id: m.mudrika_id,
    pramana_chain,
    duration_ms: Date.now() - t0,
    signature_verified: false,
  };

  // @rule:ACC-003 @rule:ACC-004 — emit ACC receipt for cockpit observability
  emitAccReceipt({
    receipt_id: `hanumang-mudrika-${m.mudrika_id}`,
    event_type: 'mudrika.verified',
    agent_id: m.agent_id,
    verdict: 'PASS',
    rules_fired: ['HNG-S-008', 'HNG-S-009', 'HNG-S-010'],
    summary: `mudrika ${m.mudrika_id} verified for ${m.principal_id} → ${m.agent_id} scope=${m.scope_key}`,
    payload: {
      trust_mask,
      expires_at: result.expires_at,
      pramana_chain_depth: pramana_chain.length,
      duration_ms: result.duration_ms,
    },
  });

  return result;
}

function fail(reason: string, t0: number): VerifyResult {
  const result: VerifyResult = {
    outcome: 'FAIL',
    failure_reason: reason,
    expires_at: new Date().toISOString(),
    trust_mask: 0,
    scope_key: '',
    principal_id: '',
    mudrika_id: '',
    pramana_chain: [],
    duration_ms: Date.now() - t0,
    signature_verified: false,
  };

  // @rule:ACC-003 — emit failure receipt for cockpit observability
  emitAccReceipt({
    receipt_id: `hanumang-mudrika-fail-${t0}`,
    event_type: 'mudrika.rejected',
    verdict: 'FAIL',
    rules_fired: ['HNG-S-008', 'HNG-S-009', 'HNG-S-010'],
    summary: `mudrika rejected: ${reason}`,
  });

  return result;
}
