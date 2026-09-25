// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @rule:KOS-062 proxy validates mudrika on every request; no valid mudrika = deny
//
// Hook-level guard: call assertMudrika(agentId) at the top of every PreToolUse hook.
// If mudrika is absent or invalid → exit(2) blocks the tool call before it executes.

import { checkMudrikaValid } from "../kernel/mudrika";

// @rule:KOS-062
export function assertMudrika(agentId: string): void {
  const { valid, reason } = checkMudrikaValid(agentId);
  if (!valid) {
    console.error(`[KAVACH] mudrika denied: ${agentId} — ${reason ?? "no credential"}`);
    process.exit(2);
  }
}

// Non-fatal variant — returns result for callers that want to log vs hard-stop
export function checkMudrika(agentId: string): { valid: boolean; reason?: string } {
  return checkMudrikaValid(agentId);
}

export const MUDRIKA_ABSENT_REASON = "no mudrika — agent not registered";

/**
 * AF-T-708 — the graded act-class identity verdict (pure; closes the AF-T-602 fail-open).
 * For an ACT-CLASS action (outward write, schema-touching), identity is REQUIRED, not
 * checked-when-present (AFW-010: proven, never assumed):
 *   valid            → PERMIT
 *   present-invalid  → REFUSE at enforce (the hot-path hooks already exit 2 on this — the
 *                      same law from one more layer, no new blocking surface)
 *   absent           → REFUSE at observe (THE fail-open branch; promoted on ledger
 *                      evidence, AF-R-005 procedure — most live sessions carry no mudrika
 *                      today, so enforcing at birth would block routine founder-directed work)
 * Reads and benign commands never reach this — the applies() gate keeps it an act-class
 * requirement, not a reads tax.
 */
export function mudrikaActVerdict(
  m: { valid: boolean; reason?: string },
  principal: string,
): { verdict: "PERMIT" | "REFUSE"; detail: string; source: string; stage?: "enforce" | "observe" } {
  const src = "mudrika store (~/.aegis/agents)";
  if (m.valid) return { verdict: "PERMIT", detail: `identity verified for ${principal.slice(0, 12)}`, source: src };
  if (m.reason === MUDRIKA_ABSENT_REASON) {
    return {
      verdict: "REFUSE",
      detail: `act-class action by ${principal.slice(0, 12)} with NO issued identity — identity is proven, never assumed (AGT-014); an owned agent gets a mudrika at spawn`,
      source: src,
      stage: "observe",
    };
  }
  return {
    verdict: "REFUSE",
    detail: `act-class action by ${principal.slice(0, 12)} with an INVALID mudrika: ${m.reason ?? "unknown"} — a broken credential is worse than none`,
    source: src,
    stage: "enforce",
  };
}
