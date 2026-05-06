// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Enforcement — DAN Gate Level 0: Bitmask Structural Pre-filter
// @rule:KAV-083 DAN Gate Level 0 — structural rejection before human escalation
// If (agent_mask & required_bit) === 0 → auto-block, no human needed.
// Level 0 runs before trust_mask gate and before any escalation path.
// A zero AND is mathematical proof of incapability — no human review needed.

export interface Level0Decision {
  blocked: boolean;
  reason?: string;
  rule: "KAV-083";
}

/**
 * Level 0 pre-filter: structural bitmask check.
 * If the agent's perm_mask does not have the required bit set, block immediately.
 * No human escalation, no GATE token — the agent structurally cannot perform this operation.
 * @rule:KAV-083
 */
export function level0Gate(agentPermMask: number, requiredBit: number): Level0Decision {
  if ((agentPermMask & requiredBit) === 0) {
    return {
      blocked: true,
      reason: `agent lacks required bit 0x${requiredBit.toString(16).padStart(8, "0")}`,
      rule: "KAV-083",
    };
  }
  return { blocked: false, rule: "KAV-083" };
}
