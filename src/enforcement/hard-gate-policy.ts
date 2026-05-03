/**
 * AEGIS Hard-Gate Policy
 *
 * Defines per-service hard-gate configuration and the dry-run simulation
 * function. This module does NOT modify gate.ts behavior. Hard-gate is
 * disabled by default for all services. Enabling a service requires an
 * explicit env var change (AEGIS_HARD_GATE_SERVICES) — a deliberate manual
 * step, not an automated promotion.
 *
 * Global invariants (non-overridable):
 *   READ never hard-blocks in any mode or group (AEG-E-002 extended)
 *   Unknown service remains WARN in all modes
 *   Unknown capability remains GATE/WARN until canonical registry is complete
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false is the default for all services
 * @rule:AEG-HG-002 READ is in never_block for every service in every HG group
 * @rule:AEG-HG-003 hard-gate promotion requires explicit env var — not automatic
 */

// ── Global kill switch ────────────────────────────────────────────────────────
// Changed to true: Batch 32 manual promotion, 2026-05-03.
// Evidence: Batch 31 7/7 soak, 2940 checks, 0 false positives, 110 true positives.
// Rollback: set to false — chirpee immediately returns to soft-canary. No migration needed.
export const HARD_GATE_GLOBALLY_ENABLED = true;

// Per-service activation set. Empty until Stage 1 manual promotion.
// Populated by: AEGIS_HARD_GATE_SERVICES env var (comma-separated service IDs).
// The env var does not exist in production yet — creating it is a manual act.
export const HARD_GATE_SERVICES_ENABLED: ReadonlySet<string> = (() => {
  if (!HARD_GATE_GLOBALLY_ENABLED) return new Set<string>(); // @rule:AEG-HG-001
  const raw = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
  return new Set(raw.split(",").map(s => s.trim()).filter(Boolean));
})();

// ── Types ─────────────────────────────────────────────────────────────────────

export type HGGroup = "HG-0" | "HG-1" | "HG-2" | "HG-3" | "HG-4";

export interface ServiceHardGatePolicy {
  service_id: string;
  hg_group: HGGroup;
  hard_gate_enabled: false; // policy object default is always false; runtime enabling is via env var
  hard_block_capabilities: ReadonlySet<string>; // BLOCK when hard-gate is active
  still_gate_capabilities: ReadonlySet<string>; // GATE even when hard-gate active (not BLOCK)
  always_allow_capabilities: ReadonlySet<string>; // ALLOW regardless
  never_block_capabilities: ReadonlySet<string>; // AEG-E-002: READ always here
  rollout_order: number;
  stage: string;
}

export interface SimulationResult {
  service_id: string;
  requested_capability: string;
  operation: string;
  soft_decision: string;
  simulated_hard_decision: string;
  hard_gate_would_apply: boolean;
  hard_gate_enabled_for_service: boolean;
  reason: string;
  invariant_applied: string | null;
}

// ── chirpee HG-1 policy ───────────────────────────────────────────────────────
//
// HG-1 hard-block scope: malformed / impossible actions only.
// Rationale: read_only authority + BR-0 → false positive is bounded.
// Anything high-consequence (DEPLOY/DELETE/EXECUTE/APPROVE/FULL_AUTONOMY)
// remains GATE even when hard-gate is active — the safety catch stays on
// for operations that matter.
//
// Stage 1 pilot. Chirpee chosen first: consumer text agent, lowest blast,
// false positive surface is visible and immediately recoverable.
//
// HG-1 JUSTIFICATION (established Batch 31 soak run 1, 2026-05-03):
//
//   HG-1 does not hard-block risky real work.
//   HG-1 hard-blocks policy-proven impossible or malformed actions
//   that the soft gate intentionally does not interrupt.
//
//   Evidence:
//     IMPOSSIBLE_OP             → soft=ALLOW, hard-sim=BLOCK (true positive)
//     EMPTY_CAPABILITY_ON_WRITE → soft=ALLOW, hard-sim=BLOCK (true positive)
//
//   Why soft allows: gate sees medium-risk op on read_only+BR-0 — passes.
//   No registry entry exists for malformed caps, so no WARN trigger fires.
//   Why hard blocks: both are in hard_block_capabilities — policy is explicit.
//
//   The gap soft allows + hard blocks = the closed surface HG-1 adds.
//   Run 1: 0 false positives, 10 true positives, 0 production fires, 390/390 PASS.

export const CHIRPEE_HG1_POLICY: ServiceHardGatePolicy = {
  service_id: "chirpee",
  hg_group: "HG-1",
  hard_gate_enabled: false, // @rule:AEG-HG-001 — changed only by AEGIS_HARD_GATE_SERVICES
  hard_block_capabilities: new Set([
    "IMPOSSIBLE_OP",             // demonstrably invalid sentinel operation
    "EMPTY_CAPABILITY_ON_WRITE", // empty capability string on a write-class operation
  ]),
  still_gate_capabilities: new Set([
    // High-consequence ops stay GATE in hard mode — never BLOCK for HG-1
    "CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE",
    "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE",
    "TRIGGER", "EMIT",
  ]),
  always_allow_capabilities: new Set([
    "READ", "GET", "LIST", "QUERY", "SEARCH", "HEALTH",
  ]),
  never_block_capabilities: new Set([
    "READ", // @rule:AEG-HG-002 — AEG-E-002 extended to hard mode
  ]),
  rollout_order: 1,
  stage: "Stage 1 — HG-1 pilot — LIVE 2026-05-03 (Batch 32)",
};

// ── ship-slm HG-1 policy ─────────────────────────────────────────────────────
//
// Stage 2. Identical profile to chirpee: read_only authority + BR-0.
// Policy prepared Batch 34. Soak: Batch 35 7/7 complete (promotion_permitted=true).
// Promoted live: Batch 36, 2026-05-03. AEGIS_HARD_GATE_SERVICES=chirpee,ship-slm,chief-slm
//
// Evidence: 7 soak runs, 1403 total checks, 0 false positives.
// Rollback: remove ship-slm from AEGIS_HARD_GATE_SERVICES — immediately returns to soft-canary.
//
// @rule:AEG-HG-001 hard_gate_enabled=false — runtime enabling is AEGIS_HARD_GATE_SERVICES

export const SHIP_SLM_HG1_POLICY: ServiceHardGatePolicy = {
  service_id: "ship-slm",
  hg_group: "HG-1",
  hard_gate_enabled: false, // @rule:AEG-HG-001
  hard_block_capabilities: new Set([
    "IMPOSSIBLE_OP",
    "EMPTY_CAPABILITY_ON_WRITE",
  ]),
  still_gate_capabilities: new Set([
    "CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE",
    "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE",
    "TRIGGER", "EMIT",
  ]),
  always_allow_capabilities: new Set([
    "READ", "GET", "LIST", "QUERY", "SEARCH", "HEALTH",
  ]),
  never_block_capabilities: new Set([
    "READ", // @rule:AEG-HG-002
  ]),
  rollout_order: 2,
  stage: "Stage 2 — HG-1 LIVE 2026-05-03 (Batch 36) — soak: Batch 35 7/7",
};

// ── chief-slm HG-1 policy ─────────────────────────────────────────────────────
//
// Stage 2. Identical profile to chirpee: read_only authority + BR-0.
// Policy prepared Batch 34. Soak: Batch 35 7/7 complete (promotion_permitted=true).
// Promoted live: Batch 36, 2026-05-03. AEGIS_HARD_GATE_SERVICES=chirpee,ship-slm,chief-slm
//
// Evidence: 7 soak runs, 1403 total checks, 0 false positives.
// Rollback: remove chief-slm from AEGIS_HARD_GATE_SERVICES — immediately returns to soft-canary.
//
// @rule:AEG-HG-001 hard_gate_enabled=false — runtime enabling is AEGIS_HARD_GATE_SERVICES

export const CHIEF_SLM_HG1_POLICY: ServiceHardGatePolicy = {
  service_id: "chief-slm",
  hg_group: "HG-1",
  hard_gate_enabled: false, // @rule:AEG-HG-001
  hard_block_capabilities: new Set([
    "IMPOSSIBLE_OP",
    "EMPTY_CAPABILITY_ON_WRITE",
  ]),
  still_gate_capabilities: new Set([
    "CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE",
    "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE",
    "TRIGGER", "EMIT",
  ]),
  always_allow_capabilities: new Set([
    "READ", "GET", "LIST", "QUERY", "SEARCH", "HEALTH",
  ]),
  never_block_capabilities: new Set([
    "READ", // @rule:AEG-HG-002
  ]),
  rollout_order: 3,
  stage: "Stage 2 — HG-1 LIVE 2026-05-03 (Batch 36) — soak: Batch 35 7/7",
};

// ── Policy registry ───────────────────────────────────────────────────────────
// Batch 34: ship-slm + chief-slm policies added (disabled). Chirpee = Stage 1 live.

export const HARD_GATE_POLICIES: Readonly<Record<string, ServiceHardGatePolicy>> = {
  chirpee:    CHIRPEE_HG1_POLICY,
  "ship-slm": SHIP_SLM_HG1_POLICY,
  "chief-slm": CHIEF_SLM_HG1_POLICY,
};

// ── Live hard-gate enforcement ────────────────────────────────────────────────
//
// applyHardGate: the live enforcement path. Called from gate.ts evaluate()
// when HARD_GATE_GLOBALLY_ENABLED=true.
//
// Reads process.env.AEGIS_HARD_GATE_SERVICES at call time (not import time)
// so that the env var can be set after module load in scripts and tests.
//
// Returns hard_gate_active=true if the service is in the enabled set.
// Returns hard_gate_applied=true only when a hard BLOCK fires.
// All other paths preserve the soft decision unchanged.
//
// @rule:AEG-HG-001 — hard_gate_enabled is a policy default; runtime enabling is env var
// @rule:AEG-HG-002 — READ never hard-blocks regardless of capability list
// @rule:AEG-HG-003 — promotion requires explicit AEGIS_HARD_GATE_SERVICES entry

export interface HardGateResult {
  decision: string;
  hard_gate_active: boolean;   // service has hard-gate running (phase = "hard_gate")
  hard_gate_applied: boolean;  // a hard BLOCK was triggered by hard_block_capabilities
  hard_gate_service: string;
  policy_version: string;
  reason: string;
  invariant_applied: string | null;
}

function isHardGateActiveForService(serviceId: string): boolean {
  if (!HARD_GATE_GLOBALLY_ENABLED) return false;
  const raw = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
  return raw.split(",").map(s => s.trim()).includes(serviceId);
}

export function applyHardGate(
  serviceId: string,
  softDecision: string,
  requestedCapability: string,
  operation: string,
): HardGateResult {
  const policy = HARD_GATE_POLICIES[serviceId];
  const isActive = isHardGateActiveForService(serviceId);

  if (!isActive) {
    return {
      decision: softDecision,
      hard_gate_active: false,
      hard_gate_applied: false,
      hard_gate_service: serviceId,
      policy_version: "none",
      reason: "service not in AEGIS_HARD_GATE_SERVICES",
      invariant_applied: null,
    };
  }

  if (!policy) {
    return {
      decision: softDecision,
      hard_gate_active: true,
      hard_gate_applied: false,
      hard_gate_service: serviceId,
      policy_version: "none",
      reason: "hard-gate active but no policy defined — soft decision preserved",
      invariant_applied: null,
    };
  }

  const cap = requestedCapability.toUpperCase().trim();
  const op  = operation.toLowerCase().trim();

  // @rule:AEG-HG-002 — READ never hard-blocks
  if (policy.never_block_capabilities.has(cap) ||
      ["read","get","list","query","search","health"].includes(op)) {
    return {
      decision: "ALLOW",
      hard_gate_active: true,
      hard_gate_applied: false,
      hard_gate_service: serviceId,
      policy_version: policy.hg_group,
      reason: "READ/GET/LIST/QUERY/SEARCH/HEALTH — never_block invariant (AEG-HG-002)",
      invariant_applied: "AEG-HG-002",
    };
  }

  // always_allow takes priority over hard_block
  if (policy.always_allow_capabilities.has(cap)) {
    return {
      decision: "ALLOW",
      hard_gate_active: true,
      hard_gate_applied: false,
      hard_gate_service: serviceId,
      policy_version: policy.hg_group,
      reason: `${cap} in always_allow_capabilities`,
      invariant_applied: null,
    };
  }

  // Hard-block: the only path to a live BLOCK decision
  if (policy.hard_block_capabilities.has(cap)) {
    return {
      decision: "BLOCK",
      hard_gate_active: true,
      hard_gate_applied: true,
      hard_gate_service: serviceId,
      policy_version: policy.hg_group,
      reason: `${cap} in hard_block_capabilities for ${serviceId} (${policy.hg_group}) — hard BLOCK`,
      invariant_applied: null,
    };
  }

  // still_gate: ONLY fires to downgrade a BLOCK to GATE (defensive).
  // Does NOT upgrade ALLOW to GATE — soft decision is preserved when not a BLOCK.
  // Rationale: soft gate for read_only+BR-0 services returns ALLOW for high-risk ops
  // like EXECUTE/APPROVE/TRIGGER; hard-gate must not override that.
  if (policy.still_gate_capabilities.has(cap) && softDecision === "BLOCK") {
    return {
      decision: "GATE",
      hard_gate_active: true,
      hard_gate_applied: false,
      hard_gate_service: serviceId,
      policy_version: policy.hg_group,
      reason: `${cap} in still_gate_capabilities — hard gate defers, GATE not BLOCK (soft was BLOCK)`,
      invariant_applied: null,
    };
  }

  // Unknown capability or still_gate with non-BLOCK soft: pass through soft decision.
  // Unknown caps never hard-block until canonical registry is complete.
  return {
    decision: softDecision,
    hard_gate_active: true,
    hard_gate_applied: false,
    hard_gate_service: serviceId,
    policy_version: policy.hg_group,
    reason: `${cap} not in hard_block — soft decision preserved (GATE/WARN/ALLOW)`,
    invariant_applied: "unknown_cap_or_still_gate_preserves_soft",
  };
}

// ── Simulation ────────────────────────────────────────────────────────────────
//
// simulateHardGate: computes what a hard gate WOULD decide given:
//   - a soft-canary decision (from evaluate())
//   - the service's hard-gate policy
//   - an optional override to force-enable for dry-run purposes
//
// Does NOT change gate.ts behavior. Does NOT affect production.
// The override parameter exists ONLY for testing policy correctness in
// dry-run batches (Batch 30). It must never be called with override=true
// from inside gate.ts itself.

export function simulateHardGate(
  serviceId: string,
  softDecision: string,
  requestedCapability: string,
  operation: string,
  dryRunOverride = false, // if true: simulate AS IF hard-gate were enabled
): SimulationResult {
  const policy = HARD_GATE_POLICIES[serviceId];
  const cap = requestedCapability.toUpperCase();
  const op  = operation.toLowerCase();

  // No policy defined → preserve soft decision, no hard-gate logic applies
  if (!policy) {
    return {
      service_id: serviceId,
      requested_capability: cap,
      operation,
      soft_decision: softDecision,
      simulated_hard_decision: softDecision,
      hard_gate_would_apply: false,
      hard_gate_enabled_for_service: false,
      reason: `No hard-gate policy defined for ${serviceId} — soft decision preserved`,
      invariant_applied: null,
    };
  }

  const isEnabled = HARD_GATE_GLOBALLY_ENABLED && HARD_GATE_SERVICES_ENABLED.has(serviceId);
  const effectivelyEnabled = isEnabled || dryRunOverride;

  if (!effectivelyEnabled) {
    return {
      service_id: serviceId,
      requested_capability: cap,
      operation,
      soft_decision: softDecision,
      simulated_hard_decision: softDecision,
      hard_gate_would_apply: false,
      hard_gate_enabled_for_service: false,
      reason: "hard_gate_enabled=false for this service — soft decision preserved (dryRunOverride=false)",
      invariant_applied: null,
    };
  }

  // @rule:AEG-HG-002 READ never hard-blocks regardless of policy list
  if (policy.never_block_capabilities.has(cap) || op === "read" || op === "get" ||
      op === "list" || op === "query" || op === "search" || op === "health") {
    return {
      service_id: serviceId,
      requested_capability: cap,
      operation,
      soft_decision: softDecision,
      simulated_hard_decision: "ALLOW",
      hard_gate_would_apply: false,
      hard_gate_enabled_for_service: effectivelyEnabled,
      reason: "READ/GET/LIST/QUERY/SEARCH/HEALTH — never_block invariant (AEG-E-002 extended)",
      invariant_applied: "AEG-HG-002",
    };
  }

  // always_allow takes priority over hard_block
  if (policy.always_allow_capabilities.has(cap)) {
    return {
      service_id: serviceId,
      requested_capability: cap,
      operation,
      soft_decision: softDecision,
      simulated_hard_decision: "ALLOW",
      hard_gate_would_apply: false,
      hard_gate_enabled_for_service: effectivelyEnabled,
      reason: `${cap} is in always_allow_capabilities`,
      invariant_applied: null,
    };
  }

  // Hard-block: the only path to hard BLOCK
  if (policy.hard_block_capabilities.has(cap)) {
    return {
      service_id: serviceId,
      requested_capability: cap,
      operation,
      soft_decision: softDecision,
      simulated_hard_decision: "BLOCK",
      hard_gate_would_apply: true,
      hard_gate_enabled_for_service: effectivelyEnabled,
      reason: `${cap} is in hard_block_capabilities for ${serviceId} (${policy.hg_group}) — hard BLOCK`,
      invariant_applied: null,
    };
  }

  // still_gate: ONLY fires to downgrade a BLOCK to GATE (defensive).
  // Does NOT upgrade ALLOW to GATE — mirrors applyHardGate semantics exactly.
  if (policy.still_gate_capabilities.has(cap) && softDecision === "BLOCK") {
    return {
      service_id: serviceId,
      requested_capability: cap,
      operation,
      soft_decision: softDecision,
      simulated_hard_decision: "GATE",
      hard_gate_would_apply: false,
      hard_gate_enabled_for_service: effectivelyEnabled,
      reason: `${cap} is in still_gate_capabilities — hard gate defers, GATE not BLOCK (soft was BLOCK)`,
      invariant_applied: null,
    };
  }

  // Unknown capability: GATE/WARN — never hard-block until canonical registry complete
  // @rule:AEG-HG-003 (indirect): unknown cap → GATE until registry complete
  const unknownCapDecision = softDecision === "BLOCK" ? "GATE" : softDecision;
  return {
    service_id: serviceId,
    requested_capability: cap,
    operation,
    soft_decision: softDecision,
    simulated_hard_decision: unknownCapDecision,
    hard_gate_would_apply: false,
    hard_gate_enabled_for_service: effectivelyEnabled,
    reason: `${cap} not in any hard-gate list — unknown capability stays GATE/WARN (canonical registry incomplete)`,
    invariant_applied: "unknown_cap_gates_before_blocking",
  };
}
