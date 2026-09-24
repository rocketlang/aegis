// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Agent Tripwire — the staged containment ladder (AF-T-605, AFW-011).
//
// A tripwire hit is evidence, not a verdict. Response is STAGED and EVIDENCE-GATED:
//   watch      — first/low evidence: logged + alerted, no action.
//   throttle   — repeated hits or two independent tells: slow the actor.
//   quarantine — strong evidence: isolate (block further action, keep alive to inspect).
//   revoke     — invalidate identity/access. NEVER reached by evidence alone.
//
// Two invariants, both from AFW-011 (and FP-017's "won't dissolve without a verified capture,
// no override"):
//   1. Never kill on a guess. `revoke` requires an explicit VERIFIED CAPTURE — a human/verified
//      confirmation — no accumulation of hits ever reaches it on its own.
//   2. UNKNOWN escalates, never clears. The ladder never DE-escalates automatically: a computed
//      stage below the prior one is held at the prior stage until a human clears it.
//
// This module is the POLICY (evidence → stage), pure and tunable. Making a stage BITE (a real
// throttle/quarantine/revoke in the valve/Anumati/mudrika machinery) is a separate wiring step
// behind a founder ruling — the same discipline as not auto-wiring check-tripwire.

export type Stage = "watch" | "throttle" | "quarantine" | "revoke";
export const STAGE_ORDER: Stage[] = ["watch", "throttle", "quarantine", "revoke"];
const rank = (s: Stage) => STAGE_ORDER.indexOf(s);

export interface Evidence {
  /** number of tripwire hits attributed to the principal */
  hits: number;
  /** distinct tripwire KINDS seen (e.g. honeypot + canary = 2 independent tells) */
  distinctKinds: number;
  /** a human/verified capture — the ONLY thing that authorises revoke. Never inferred. */
  verifiedCapture?: boolean;
}

export interface StageDecision {
  stage: Stage;
  reason: string;
  /** true when the prior stage was held because the computed stage was lower (never clears). */
  heldAtPrior: boolean;
}

// Thresholds — documented and fixed so the ladder is reproducible; tune here, not by feel.
const THROTTLE_HITS = 2;
const QUARANTINE_HITS = 4;

/** Stage from evidence alone (before the never-de-escalate floor). Revoke is unreachable here. */
function computed(ev: Evidence): Stage {
  if (ev.hits >= QUARANTINE_HITS || (ev.distinctKinds >= 2 && ev.hits >= 3)) return "quarantine";
  if (ev.hits >= THROTTLE_HITS || ev.distinctKinds >= 2) return "throttle";
  return "watch";
}

/**
 * The staged decision. `verifiedCapture` is the only path to revoke (never a guess). Otherwise
 * the stage is computed from evidence, then floored at `priorStage` — the ladder never
 * de-escalates on its own (UNKNOWN escalates, never clears). @rule:AFW-011
 */
export function containmentStage(ev: Evidence, priorStage: Stage = "watch"): StageDecision {
  if (ev.verifiedCapture) {
    return { stage: "revoke", reason: "verified capture confirmed — the only path to revoke", heldAtPrior: false };
  }
  const c = computed(ev);
  if (rank(c) >= rank(priorStage)) {
    const why = c === "watch"
      ? `${ev.hits} hit(s) — first/low evidence, watch only`
      : `${ev.hits} hit(s) across ${ev.distinctKinds} tripwire kind(s) → ${c}`;
    return { stage: c, reason: why, heldAtPrior: false };
  }
  // Computed is lower than where we already are — the ladder does not walk back on its own.
  return {
    stage: priorStage,
    reason: `held at ${priorStage} — evidence computed ${c}, but the ladder never de-escalates on its own (a human clears it)`,
    heldAtPrior: true,
  };
}
