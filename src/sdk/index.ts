// SPDX-License-Identifier: AGPL-3.0-only
// AEGIS Full SDK — wraps enforcement gate for programmatic integration
// For advanced use cases: multi-agent coordination, session management, budget enforcement.
//
// Usage (Shruthi / advanced profile):
//   import { aegis } from '@rocketlang/aegis'
//
//   // Validate a capability against the AEGIS enforcement registry
//   const decision = await aegis.guard({
//     service_id: 'my-freight-agent',
//     operation: 'write',
//     requested_capability: 'WRITE',
//   })
//   // decision.action → 'ALLOW' | 'WARN' | 'GATE' | 'BLOCK'
//
//   // Simple trust_mask check (no registry, no config)
//   aegis.can(0b1111, 'READ')   // true
//   aegis.can(0b0001, 'WRITE')  // false
//
// @rule:SDK-001 — SDK never reduces enforcement vs internal AEGIS
// @rule:SDK-005 — every SDK enforcement action generates a PRAMANA-compatible receipt
// @rule:ASE-001 — issueEnvelope() issues sealed envelope before agent's first action
// @rule:ASE-002 — verifyEnvelope() re-derives sealed_hash and compares; tamper detection
// @rule:ASE-006 — budget_usd is fixed at issuance; returned in envelope for reference
// @rule:ASE-008 — parent_session_id included in sealed_hash via HTTP issuance

import { evaluate } from '../enforcement/gate.js';
import type { AegisEnforcementRequest, AegisEnforcementDecision, GateDecision } from '../enforcement/types.js';
import { computeSealedHash, verifyEnvelopeIntegrity } from '../core/ase.js';
import type { AgentSessionEnvelope } from '../core/ase.js';

export type { AgentSessionEnvelope };

// ─── Re-export Lite for convenience ──────────────────────────────────────────

export { lite, TRUST_PERM, ROLE_MASK, AegisLiteError } from './lite.js';
export type { LiteAgent, LiteGuardResult, TrustPerm } from './lite.js';

// ─── ASE helpers — envelope issuance + verification ──────────────────────────

export interface IssueEnvelopeOptions {
  agent_type?: 'proxy-native' | 'hook-native';
  service_key?: string;
  tenant_id?: string;
  declared_caps?: string[];
  budget_usd?: number;
  parent_session_id?: string;
  trust_mask?: number;
  perm_mask?: number;
  class_mask?: number;
}

export interface IssueEnvelopeResult {
  ok: boolean;
  session_id?: string;
  agent_id?: string;
  sealed_hash?: string;
  issued_at?: string;
  expires_at?: string;
  perm_mask?: number;
  declared_caps?: string[];
  error?: string;
}

// @rule:ASE-001 — call before agent's first action; wraps POST /api/v1/aegis/session
export async function issueEnvelope(
  aegisUrl: string,
  opts: IssueEnvelopeOptions = {}
): Promise<IssueEnvelopeResult> {
  try {
    const res = await fetch(`${aegisUrl}/api/v1/aegis/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(opts),
      signal: AbortSignal.timeout(5000),
    });
    const body = await res.json() as Record<string, unknown>;
    if (!res.ok) return { ok: false, error: String(body.error ?? res.status) };
    return {
      ok: true,
      session_id: body.session_id as string,
      agent_id: body.agent_id as string,
      sealed_hash: body.sealed_hash as string,
      issued_at: body.issued_at as string,
      expires_at: body.expires_at as string,
      perm_mask: body.perm_mask as number,
      declared_caps: body.declared_caps as string[],
    };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

// @rule:ASE-002 — re-derive sealed_hash locally and compare to stored value
// Returns true if envelope is intact; false = tamper detected (ASE-YK-008)
export function verifyEnvelope(envelope: AgentSessionEnvelope): boolean {
  return verifyEnvelopeIntegrity(envelope);
}

// @rule:ASE-002 — local sealed_hash computation (offline verification without Aegis)
export { computeSealedHash };

// ─── SDK types ────────────────────────────────────────────────────────────────

export interface AegisGuardRequest {
  service_id: string;
  operation: string;
  requested_capability: string;
  caller_id?: string;
  session_id?: string;
  metadata?: Record<string, unknown>;
}

export interface AegisGuardResult {
  action: GateDecision;
  service_id: string;
  operation: string;
  requested_capability: string;
  trust_mask: number;
  trust_mask_hex: string;
  enforcement_mode: string;
  reason: string;
  approval_token?: string;
  raw: AegisEnforcementDecision;
}

// ─── Full SDK ─────────────────────────────────────────────────────────────────

export const aegis = {
  /**
   * Guard a tool call or operation against the AEGIS enforcement registry.
   * Uses services.json as the authoritative trust_mask source.
   * Falls back to shadow mode if services.json is unavailable.
   *
   * @rule:SDK-001 — enforcement never weaker than internal AEGIS
   * @rule:INF-SDK-002 — tool_call not in allowed set → BLOCK with receipt
   */
  guard(request: AegisGuardRequest): AegisGuardResult {
    const raw = evaluate(request as AegisEnforcementRequest);
    return {
      action: raw.gate_decision,
      service_id: raw.service_id,
      operation: raw.operation,
      requested_capability: raw.requested_capability,
      trust_mask: raw.trust_mask,
      trust_mask_hex: raw.trust_mask_hex,
      enforcement_mode: raw.enforcement_mode,
      reason: raw.decision_reason ?? raw.aegis_gate_result,
      approval_token: (raw as any).approval_token,
      raw,
    };
  },

  /**
   * Simple trust_mask capability check — no registry, no config.
   * Equivalent to: (trust_mask & capability_bit) !== 0
   *
   * @param trust_mask  32-bit mask (from agent policy or TRUST_PERM presets)
   * @param capability  Named capability string ('READ', 'WRITE', 'EXECUTE', etc.)
   */
  can(trust_mask: number, capability: keyof typeof CAPABILITY_BITS): boolean {
    const bit = CAPABILITY_BITS[capability];
    if (bit === undefined) {
      console.warn(`[AEGIS SDK] Unknown capability '${capability}'. Use TRUST_PERM constants.`);
      return false;
    }
    return (trust_mask & bit) !== 0;
  },

  /**
   * Batch-validate multiple capabilities against a trust_mask.
   * Returns a map of capability → allowed.
   */
  canAll(trust_mask: number, capabilities: (keyof typeof CAPABILITY_BITS)[]): Record<string, boolean> {
    return Object.fromEntries(
      capabilities.map(cap => [cap, aegis.can(trust_mask, cap)])
    );
  },

  /**
   * Assert a session cost cap before spawning a sub-agent.
   * Returns the decision — does not throw.
   *
   * @rule:INF-SDK-003 — session_cost > budget_cap → FREEZE_AND_NOTIFY
   */
  checkBudget(sessionCostUsd: number, capUsd: number): { allowed: boolean; reason: string } {
    if (sessionCostUsd >= capUsd) {
      return {
        allowed: false,
        reason: `session cost $${sessionCostUsd.toFixed(4)} exceeds cap $${capUsd.toFixed(4)} — spawn blocked`,
      };
    }
    return { allowed: true, reason: `within budget ($${sessionCostUsd.toFixed(4)} / $${capUsd.toFixed(4)})` };
  },

  /**
   * Validate delegation depth before spawning a child agent.
   * @rule:INF-SDK-004 — delegation_chain.depth > MAX_DEPTH → REJECT_SPAWN
   */
  checkDepth(currentDepth: number, maxDepth: number = 5): { allowed: boolean; reason: string } {
    if (currentDepth >= maxDepth) {
      return {
        allowed: false,
        reason: `delegation depth ${currentDepth} at or exceeds max ${maxDepth} — spawn blocked`,
      };
    }
    return { allowed: true, reason: `depth ${currentDepth} within limit ${maxDepth}` };
  },
} as const;

// ─── Capability name → bit mapping ───────────────────────────────────────────

const CAPABILITY_BITS = {
  READ:                1 << 0,
  QUERY:               1 << 1,
  WRITE:               1 << 2,
  EXECUTE:             1 << 3,
  APPROVE:             1 << 4,
  AUDIT:               1 << 5,
  ADMIN:               1 << 6,
  SUPER:               1 << 7,
  BOOK:                1 << 8,
  MANIFEST:            1 << 9,
  BL_ISSUE:            1 << 10,
  RATE_DESK:           1 << 11,
  FEEDER_OPS:          1 << 12,
  NETWORK_PLAN:        1 << 13,
  VESSEL_OPS:          1 << 14,
  COMPLIANCE_OVERRIDE: 1 << 15,
  GATE_IN:             1 << 16,
  TRACK:               1 << 17,
  FTA_CHECK:           1 << 18,
  ALERT_ACK:           1 << 19,
  PORT_OPS:            1 << 20,
  AI_READ:             1 << 24,
  AI_QUERY:            1 << 25,
  AI_SUGGEST:          1 << 26,
  AI_EXECUTE:          1 << 27,
  AI_APPROVE:          1 << 28,
  AUTONOMOUS:          1 << 29,
} as const;
