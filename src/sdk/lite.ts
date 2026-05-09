// SPDX-License-Identifier: AGPL-3.0-only
// AEGIS Lite SDK — zero-config trust_mask validation for external developers
// No services.json, no database, no ANKR infra required.
//
// Usage (Terrence / beginner profile):
//   import { lite, TRUST_PERM } from '@rocketlang/aegis'
//   const agent = lite.create({ id: 'my-agent', trust_mask: TRUST_PERM.READ | TRUST_PERM.EXECUTE })
//   lite.can(agent, TRUST_PERM.WRITE)   // false
//   lite.can(agent, TRUST_PERM.READ)    // true
//   lite.guard(agent, TRUST_PERM.WRITE) // throws AegisLiteError if denied
//
// @rule:SDK-001 — Lite mode never reduces enforcement vs full AEGIS
// @rule:SDK-002 — Lite mode exposes trust_mask validation only; no kernel enforcement

// ─── Re-export trust constants for convenience ────────────────────────────────

export const TRUST_PERM = {
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

export type TrustPerm = typeof TRUST_PERM[keyof typeof TRUST_PERM];

export const ROLE_MASK = {
  GUEST:     0,
  VIEWER:    TRUST_PERM.READ | TRUST_PERM.QUERY,
  WRITER:    TRUST_PERM.READ | TRUST_PERM.QUERY | TRUST_PERM.WRITE,
  EXECUTOR:  TRUST_PERM.READ | TRUST_PERM.QUERY | TRUST_PERM.WRITE | TRUST_PERM.EXECUTE,
  AUDITOR:   TRUST_PERM.READ | TRUST_PERM.QUERY | TRUST_PERM.AUDIT,
  ADMIN:     (1 << 7) - 1,  // bits 0-6
} as const;

// ─── Agent handle ─────────────────────────────────────────────────────────────

export interface LiteAgent {
  id: string;
  trust_mask: number;
  created_at: string;
}

export interface LiteGuardResult {
  allowed: boolean;
  agent_id: string;
  capability: number;
  capability_hex: string;
  trust_mask: number;
  trust_mask_hex: string;
  reason: string;
}

export class AegisLiteError extends Error {
  constructor(
    public readonly agent_id: string,
    public readonly capability: number,
    public readonly trust_mask: number,
  ) {
    super(
      `[AEGIS Lite] Agent '${agent_id}' denied — capability 0x${capability.toString(16).padStart(8, '0')} not in trust_mask 0x${trust_mask.toString(16).padStart(8, '0')}`
    );
    this.name = 'AegisLiteError';
  }
}

// ─── Lite API ─────────────────────────────────────────────────────────────────

export const lite = {
  /**
   * Register an agent with a trust_mask.
   * trust_mask = 0 is valid but will deny all capability checks.
   * @rule:SDK-003 — trust_mask: 0 on non-guest agent triggers a console warning
   */
  create(config: { id: string; trust_mask: number }): LiteAgent {
    if (config.trust_mask === 0) {
      console.warn(`[AEGIS Lite] Warning: agent '${config.id}' has trust_mask: 0 — all capabilities will be denied. Set a non-zero trust_mask or use ROLE_MASK presets.`);
    }
    return {
      id: config.id,
      trust_mask: config.trust_mask,
      created_at: new Date().toISOString(),
    };
  },

  /**
   * Check if an agent holds a capability bit.
   * Returns true/false — never throws.
   */
  can(agent: LiteAgent, capability: number): boolean {
    return (agent.trust_mask & capability) !== 0;
  },

  /**
   * Guard a capability — throws AegisLiteError if denied.
   * Use this at enforcement boundaries.
   */
  guard(agent: LiteAgent, capability: number): LiteGuardResult {
    const allowed = (agent.trust_mask & capability) !== 0;
    const result: LiteGuardResult = {
      allowed,
      agent_id: agent.id,
      capability,
      capability_hex: `0x${capability.toString(16).padStart(8, '0')}`,
      trust_mask: agent.trust_mask,
      trust_mask_hex: `0x${agent.trust_mask.toString(16).padStart(8, '0')}`,
      reason: allowed
        ? `capability bit present in trust_mask`
        : `capability bit not in trust_mask`,
    };
    if (!allowed) throw new AegisLiteError(agent.id, capability, agent.trust_mask);
    return result;
  },

  /**
   * Validate without throwing — returns the result object.
   */
  validate(agent: LiteAgent, capability: number): LiteGuardResult {
    const allowed = (agent.trust_mask & capability) !== 0;
    return {
      allowed,
      agent_id: agent.id,
      capability,
      capability_hex: `0x${capability.toString(16).padStart(8, '0')}`,
      trust_mask: agent.trust_mask,
      trust_mask_hex: `0x${agent.trust_mask.toString(16).padStart(8, '0')}`,
      reason: allowed ? `capability bit present in trust_mask` : `capability bit not in trust_mask`,
    };
  },

  /**
   * Inspect what an agent can and cannot do.
   * Returns a human-readable summary — useful for debugging.
   */
  inspect(agent: LiteAgent): Record<string, boolean> {
    return Object.fromEntries(
      Object.entries(TRUST_PERM).map(([name, bit]) => [name, (agent.trust_mask & bit) !== 0])
    );
  },
} as const;
