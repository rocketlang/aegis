/**
 * Batch 29 — Hard-Gate Readiness Policy
 *
 * Purpose: Define the policy for moving from soft-canary to hard-gate, after
 * Batch 28 passed 489/489 rough-weather checks.
 *
 * IMPORTANT: This batch does NOT enable hard mode.
 * This batch does NOT wire production hard enforcement.
 * This batch ONLY defines the standing orders before anyone is allowed to fire the guns.
 *
 * Distinction:
 *   ready_to_discuss_hard_gate = true   (Batch 28 result)
 *   ready_to_enable_hard_gate  = false  (Batch 29 result — requires staged human decision)
 *
 * Hard gate means the runtime can DENY action, not just gate it.
 * A false positive in hard mode is an outage, not a GATE delay.
 * A bad policy in hard mode blocks useful work, silently.
 *
 * Batch 28 proved:
 *   ✓ the gate can observe
 *   ✓ the gate can interrupt
 *   ✓ the approval lifecycle holds
 *   ✓ rollback works
 *   ✓ abuse patterns do not break it
 *
 * Batch 29 writes:
 *   → per-service hard_gate_policy
 *   → HG rollout groups (HG-0..HG-4)
 *   → staged rollout sequence
 *   → blockers per service and per group
 *   → global meta: hard_gate_enabled = false
 *
 * Source of truth for Batch 27/28 profiles:
 *   HIGH_8: granthx, stackpilot, ankrclaw, carbonx, parali-central,
 *           pramana, ankr-doctor, domain-capture  (BR≥3 or governance)
 *   LOW_4:  ship-slm, chief-slm, chirpee, puranic-os  (read_only + BR-0/BR-1)
 */

import { loadRegistry } from "../src/enforcement/registry";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// ── Environment guard: this batch must never enable hard mode ────────────────

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED  = "true";
process.env.AEGIS_DRY_RUN          = "false";
// Explicit assertion — hard gate policy batch must not flip this
const HARD_GATE_GLOBALLY_ENABLED = false;

// ── Service roster ────────────────────────────────────────────────────────────

const TIER_A_12 = [
  "granthx", "stackpilot", "ankrclaw",
  "carbonx", "parali-central", "pramana",
  "ankr-doctor", "domain-capture",
  "ship-slm", "chief-slm", "chirpee", "puranic-os",
] as const;

type TierA = typeof TIER_A_12[number];

// ── HG group definitions ──────────────────────────────────────────────────────
//
// HG-0: monitor-only. Not yet eligible for hard gate. No service in this fleet
//       is HG-0 — all 12 cleared Batch 27/28. Reserved for future services
//       that fail rough-weather or have unknown blast radius.
//
// HG-1: Hard-block ONLY malformed/impossible actions. High-consequence ops
//       (DEPLOY/DELETE/FULL_AUTONOMY) remain GATE. No READ hard-blocks ever.
//       Candidates: services with read_only authority AND BR-0/BR-1.
//       These are the safest to promote first. False positive scope: bounded.
//
// HG-2: Hard-block dangerous terminal actions (DEPLOY/DELETE/FULL_AUTONOMY)
//       for services that have proven GATE discipline. GATE medium-risk.
//       Candidates: BR-3 external_call services, or BR-5 read_only authority.
//       False positive scope: bounded to the service, not to downstream dependents.
//
// HG-3: Hard-block high-consequence operations. Approval required for medium/high.
//       Candidates: BR-5 + execution, governance, or external_call authority.
//       False positive scope: potentially fleet-wide (BR-5 propagation).
//       Requires legal/external review before promotion.
//
// HG-4: Reserved. Future autonomous containment.
//       Not assigned to any service in this fleet.

type HGGroup = "HG-0" | "HG-1" | "HG-2" | "HG-3" | "HG-4";

// ── Policy constants ──────────────────────────────────────────────────────────
//
// These capability lists are INTENT — what WOULD be in effect when a service
// is promoted to its HG group. They are not enforced here.
//
// READ is in never_block for ALL services in ALL groups.
// This is non-negotiable (AEG-E-002 extended to hard mode).

const ALWAYS_ALLOW_BASE  = ["READ", "GET", "LIST", "QUERY", "SEARCH", "HEALTH"];
const NEVER_BLOCK_BASE   = ["READ"]; // AEG-E-002 extended: READ cannot hard-block in any mode

const HG1_HARD_BLOCK_WHEN_ENABLED = [
  // Malformed/impossible only — these are inputs that no valid operation would produce.
  // The canonical capability registry must be complete before any unknown cap hard-blocks.
  // For now this list is intentionally minimal — validated in Batch 29 checks.
  "IMPOSSIBLE_OP",           // explicit sentinel for demonstrably impossible operations
  "EMPTY_CAPABILITY_ON_WRITE", // empty cap on non-read op is malformed
];

const HG1_STILL_GATE = [
  "CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE",
  "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE",
  "TRIGGER", "EMIT",
];

const HG2_HARD_BLOCK_WHEN_ENABLED = [
  // Terminal destructive/irreversible actions — these are safe to hard-block
  // only when blast radius is bounded (BR-3 or read_only authority on BR-5).
  "CI_DEPLOY",    // deploy: irreversible infra change
  "DELETE",       // delete: destructive
  "FULL_AUTONOMY", // full autonomy: unrestricted escalation
];

const HG2_STILL_GATE = [
  "EXECUTE", "APPROVE", "AI_EXECUTE", "TRIGGER", "EMIT",
  "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE",
];

const HG3_HARD_BLOCK_WHEN_ENABLED = [
  // High-consequence + financial/legal/external irreversible.
  // NOTE: This list is NOT YET ENABLED for any service.
  // It defines the target state after policy review, legal review, and
  // 14+ days of HG-2 stability.
  "CI_DEPLOY", "DELETE", "FULL_AUTONOMY",
  "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE",
  "FINANCIAL_WRITE", "EBL_CREATE",
];

const HG3_STILL_GATE = [
  // High-consequence ops stay GATE even in hard mode — BR-5 blast radius
  // means we want human review, not silent blocking.
  "EXECUTE", "APPROVE", "AI_EXECUTE", "TRIGGER", "EMIT",
  "WRITE", "KNOWLEDGE_WRITE",
];

// ── Service classification ────────────────────────────────────────────────────

const reg = loadRegistry();

interface HardGatePolicy {
  service_id: string;
  authority_class: string;
  governance_blast_radius: string;
  trust_mask_confidence: string;
  runtime_readiness_tier: string;
  hg_group: HGGroup;
  hard_gate_eligible: boolean;
  hard_gate_enabled: false; // always false in this batch
  hard_block_capabilities_when_enabled: string[];
  still_gate_capabilities: string[];
  always_allow_capabilities: string[];
  never_block_capabilities: string[];
  hard_gate_reason: string;
  hard_gate_blockers: string[];
  batch27_28_profile: string;
  rollout_order: number; // lower = earlier in rollout
}

function classify(svc: TierA): HardGatePolicy {
  const e = reg[svc];
  const auth    = e?.authority_class      ?? "read_only";
  const br      = e?.governance_blast_radius ?? "BR-0";
  const tier    = e?.runtime_readiness?.tier ?? "TIER-A";
  const brNum   = parseInt(br.replace("BR-", "") || "0", 10);

  // Derive HG group from observed live data:
  //   HG-1: read_only authority AND BR ≤ 1
  //   HG-2: (external_call AND BR ≤ 3) OR (read_only authority AND BR-5)
  //   HG-3: execution/governance authority AND BR-5, OR external_call AND BR-5
  let group: HGGroup;
  let eligible: boolean;
  let hardBlockWhenEnabled: string[];
  let stillGate: string[];
  let reason: string;
  let blockers: string[];
  let profile: string;
  let rolloutOrder: number;

  if (auth === "read_only" && brNum <= 1) {
    // HG-1: lowest risk. read_only + low blast = false positive is bounded and recoverable.
    group = "HG-1";
    eligible = true;
    hardBlockWhenEnabled = HG1_HARD_BLOCK_WHEN_ENABLED;
    stillGate = HG1_STILL_GATE;
    reason = `read_only authority (${auth}) + low governance blast (${br}). ` +
      `Hard-block scope: malformed/impossible actions only. ` +
      `All high-consequence ops (DEPLOY/DELETE/FULL_AUTONOMY) remain GATE. ` +
      `False positive scope: bounded to single service, no downstream propagation.`;
    blockers = [
      "Canonical capability registry must be complete before unknown caps hard-block",
      "Rollout pilot: chirpee first (consumer-facing, lowest consequence), then ship-slm / chief-slm, then puranic-os",
      "7-day soak required per service before next service promoted",
    ];
    profile = "Batch 27: ALLOW on all READ/WRITE. Batch 28: no abuse pattern triggered BLOCK. Rollback drill: shadow+no-token on kill. Clean.";
    rolloutOrder = svc === "chirpee" ? 1 : svc === "ship-slm" ? 2 : svc === "chief-slm" ? 3 : 4;

  } else if ((auth === "external_call" && brNum <= 3) || (auth === "read_only" && brNum >= 5)) {
    // HG-2: medium risk.
    //   external_call + BR-3: bounded external scope, not BR-5 propagation
    //   read_only authority + BR-5: read_only means hard-blocking write/deploy
    //     is safe, but governance blast radius demands care
    group = "HG-2";
    eligible = true; // eligible only after HG-1 proves clean for 7 days
    hardBlockWhenEnabled = HG2_HARD_BLOCK_WHEN_ENABLED;
    stillGate = HG2_STILL_GATE;
    if (auth === "read_only" && brNum >= 5) {
      reason = `read_only authority (${auth}) + high governance blast (${br}). ` +
        `Hard-block safe for terminal destructive actions — read_only authority means ` +
        `hard-blocking DEPLOY/DELETE does not interrupt operational read flows. ` +
        `BR-5 governance blast demands that EXECUTE/APPROVE stay GATE (not hard-block).`;
      blockers = [
        "HG-1 must run clean for ≥7 days before HG-2 promotion",
        "Per-service policy review required for read_only + BR-5 classification",
        "Governance blast radius warrants independent reviewer sign-off",
      ];
      rolloutOrder = svc === "pramana" ? 5 : 6; // pramana (verification) before domain-capture
    } else {
      reason = `external_call authority (${auth}) + medium governance blast (${br}). ` +
        `Terminal destructive actions (DEPLOY/DELETE/FULL_AUTONOMY) can hard-block — ` +
        `blast radius is bounded at BR-3. Medium-risk ops (EXECUTE/APPROVE) stay GATE ` +
        `because external_call authority means hard-blocking could affect third parties.`;
      blockers = [
        "HG-1 must run clean for ≥7 days before HG-2 promotion",
        "Per-service external impact review required (external_call authority class)",
        "carbonx: financial authority on carbon credits — legal review before HG-2 enable",
        "parali-central: energy platform — operational safety review before HG-2 enable",
      ];
      rolloutOrder = svc === "parali-central" ? 7 : 8; // parali before carbonx (lower external scope)
    }
    profile = "Batch 27: GATE on execute/trigger/emit (BR≥3). Batch 28: revoke storm clean. Approval lifecycle clean. Rollback: PASS.";

  } else {
    // HG-3: high risk. BR-5 + execution/governance/external_call.
    //   False positive scope: fleet-wide (BR-5 propagation risk).
    //   Requires legal/external review, 14+ days of HG-2 stability, human sign-off.
    group = "HG-3";
    eligible = false; // not yet eligible — too much blast radius
    hardBlockWhenEnabled = HG3_HARD_BLOCK_WHEN_ENABLED; // future intent, not current
    stillGate = HG3_STILL_GATE;

    const specificBlocker: string[] = [];
    if (svc === "ankrclaw") {
      specificBlocker.push("ankrclaw: external_call + BR-5 = real customer impact (WhatsApp/Telegram). False positive drops live messages. Legal review mandatory before HG-3.");
    }
    if (svc === "granthx") {
      specificBlocker.push("granthx: BR-5 knowledge layer. Every service depends on it. Hard-block on granthx is a fleet-wide outage. Human governor sign-off required.");
    }
    if (svc === "stackpilot") {
      specificBlocker.push("stackpilot: BR-5 orchestration. Hard-block stops all agent pipelines. Human governor sign-off required.");
    }
    if (svc === "ankr-doctor") {
      specificBlocker.push("ankr-doctor: governance authority + BR-5. Hard-blocking diagnostic ops could mask operational failures. Requires governance review.");
    }

    reason = `${auth} authority + ${br} governance blast. ` +
      `High-consequence service — false positive in hard mode has fleet-wide impact. ` +
      `Not eligible until HG-2 proves stable for ≥14 days AND per-service reviews pass.`;
    blockers = [
      "HG-2 must run clean for ≥14 days before HG-3 eligibility review",
      "Human governor sign-off required (separate from code review)",
      ...specificBlocker,
      "Rollout timing: TBD — not on any current sprint",
    ];
    profile = "Batch 27: GATE on execute/trigger/emit/approve/reject (BR-5 governance). Batch 28: mask escalation, revoke storm, expiry races — all clean. Rollback: PASS. Ready for policy, not for hard-gate.";
    rolloutOrder = svc === "ankr-doctor" ? 9
      : svc === "pramana" ? 10    // pramana is read_only but BR-5 — might promote earlier as HG-2
      : svc === "carbonx" ? 11
      : svc === "parali-central" ? 12
      : svc === "stackpilot" ? 13
      : svc === "granthx" ? 14
      : 15; // ankrclaw = last (external_call + BR-5 + live customer traffic)
  }

  return {
    service_id: svc,
    authority_class: auth,
    governance_blast_radius: br,
    trust_mask_confidence: "high", // all TIER-A services have high confidence (Batch 10 derivation)
    runtime_readiness_tier: tier,
    hg_group: group,
    hard_gate_eligible: eligible,
    hard_gate_enabled: false, // non-negotiable in this batch
    hard_block_capabilities_when_enabled: hardBlockWhenEnabled,
    still_gate_capabilities: stillGate,
    always_allow_capabilities: ALWAYS_ALLOW_BASE,
    never_block_capabilities: NEVER_BLOCK_BASE,
    hard_gate_reason: reason,
    hard_gate_blockers: blockers,
    batch27_28_profile: profile,
    rollout_order: rolloutOrder,
  };
}

// ── Build policies ────────────────────────────────────────────────────────────

const policies: HardGatePolicy[] = TIER_A_12.map(classify);
const byGroup: Record<HGGroup, HardGatePolicy[]> = {
  "HG-0": [], "HG-1": [], "HG-2": [], "HG-3": [], "HG-4": [],
};
for (const p of policies) byGroup[p.hg_group].push(p);
byGroup.HG_1_sorted = [...byGroup["HG-1"]].sort((a, b) => a.rollout_order - b.rollout_order);

// ── Policy matrix JSON ────────────────────────────────────────────────────────

const matrixJson = {
  _meta: {
    batch: "batch29",
    generated_at: new Date().toISOString(),
    hard_gate_status: "policy_defined_not_enabled",
    hard_gate_enabled: HARD_GATE_GLOBALLY_ENABLED,
    hard_gate_requires_manual_switch: true,
    hard_gate_switch_location: "aegis/src/enforcement/gate.ts — AEGIS_HARD_GATE_ENABLED env var (does not exist yet)",
    ready_to_discuss_hard_gate: true,   // Batch 28 result
    ready_to_enable_hard_gate: false,   // Batch 29 result — staged human decision required
    enforcement_mode: "soft",
    canary_status: "soft_canary_12_services",
    canonical_capability_registry_complete: false, // until this is true, unknown caps must GATE not hard-block
    policy_invariants: {
      read_never_hard_blocks: true,          // AEG-E-002 extended to hard mode
      unknown_service_remains_warn: true,    // never BLOCK unknown services in any mode
      unknown_cap_gates_before_blocking: true, // until canonical registry complete
      hg3_not_yet_eligible: true,            // all HG-3 services: eligible = false
      staged_not_fleet_rollout: true,        // rollout is per-service, not fleet-wide flip
      rollback_documented: true,
    },
  },
  global_hard_gate_rules: {
    read_operations: {
      policy: "ALWAYS_ALLOW",
      rule: "AEG-E-002 extended — READ cannot hard-block in any mode, any group",
      overridable: false,
    },
    unknown_service: {
      policy: "WARN",
      rule: "Unknown services remain WARN/shadow in all modes — never BLOCK",
      overridable: false,
    },
    unknown_capability: {
      policy: "GATE",
      rule: "Unknown capabilities GATE until canonical registry is complete. No hard-block on unknown cap.",
      prerequisite: "canonical_capability_registry_complete = true before promoting to hard-block",
      overridable: false,
    },
    soft_mode_block_to_gate: {
      policy: "GATE",
      rule: "Soft mode BLOCK→GATE behavior remains default for all services until explicitly promoted to their HG group",
      overridable: true, // promoted when service enters its HG group
    },
    destructive_financial_legal_external_irreversible: {
      policy: "GATE_or_HARD_BLOCK_if_service_policy_allows",
      rule: "DEPLOY/DELETE/FULL_AUTONOMY/financial/legal/external-irreversible may hard-block ONLY if service's hard_gate_policy explicitly lists the capability in hard_block_capabilities_when_enabled AND hard_gate_enabled=true for that service",
      overridable: true,
    },
  },
  hg_group_definitions: {
    "HG-0": {
      label: "Monitor-only — not eligible",
      description: "Not yet eligible for hard gate. Used for services with unknown blast radius or failed rough-weather. No services in current TIER-A fleet are HG-0.",
      services: [],
    },
    "HG-1": {
      label: "Malformed/impossible hard-block only",
      description: "Hard-block only demonstrably invalid inputs. All high-consequence ops stay GATE. False positive scope: bounded to single service. Eligible first.",
      services: byGroup["HG-1"].map(p => p.service_id),
      rollout_prerequisite: "Batch 28 passed (done). Canonical capability registry must be noted as in-progress.",
      soak_requirement: "7 days clean per service before next service promoted within HG-1",
    },
    "HG-2": {
      label: "Terminal destructive hard-block; medium-risk GATE",
      description: "Hard-block DEPLOY/DELETE/FULL_AUTONOMY for services with bounded blast radius. EXECUTE/APPROVE/AI_EXECUTE stay GATE. Eligible after HG-1 proves stable.",
      services: byGroup["HG-2"].map(p => p.service_id),
      rollout_prerequisite: "All HG-1 services clean for ≥7 days",
      soak_requirement: "7 days clean per service",
    },
    "HG-3": {
      label: "High-consequence hard-block; all medium/high ops approval-required",
      description: "BR-5 + execution/governance/external_call. False positive = fleet-wide impact. Not eligible until HG-2 stable for 14+ days + legal/external review.",
      services: byGroup["HG-3"].map(p => p.service_id),
      rollout_prerequisite: "All HG-2 services clean for ≥14 days + human governor sign-off + per-service reviews",
      soak_requirement: "21+ days clean per service (given BR-5 blast radius)",
    },
    "HG-4": {
      label: "Reserved — autonomous containment",
      description: "Future. Not assigned. Requires separate policy document.",
      services: [],
    },
  },
  services: Object.fromEntries(policies.map(p => [p.service_id, p])),
};

// ── Policy verification checks ────────────────────────────────────────────────
// These are not gate decisions. They verify the policy document is internally
// consistent and satisfies the Batch 29 success criteria.

let totalChecks = 0;
let passed = 0;
let failed = 0;
const failures: Array<{ label: string; expected: string; actual: string }> = [];

function check(label: string, actual: unknown, expected: unknown) {
  totalChecks++;
  const pass = String(actual) === String(expected);
  if (pass) {
    passed++;
    console.log(`  ✓ [PASS] ${label.padEnd(70)} actual=${actual}`);
  } else {
    failed++;
    failures.push({ label, expected: String(expected), actual: String(actual) });
    console.log(`  ✗ [FAIL] ${label.padEnd(70)} expected=${expected} actual=${actual}`);
  }
}

// ── 1. Coverage: all 12 TIER-A services have a policy ────────────────────────

console.log("\n── 1. Coverage — all 12 TIER-A services have hard_gate_policy ──");
check("policies.length === 12", policies.length, 12);
for (const p of policies) {
  check(`${p.service_id}: policy exists`, typeof p.hg_group === "string", true);
  check(`${p.service_id}: hard_gate_enabled = false`, p.hard_gate_enabled, false);
  check(`${p.service_id}: never_block includes READ`, p.never_block_capabilities.includes("READ"), true);
  check(`${p.service_id}: always_allow includes READ`, p.always_allow_capabilities.includes("READ"), true);
}

// ── 2. HG group assignments ───────────────────────────────────────────────────

console.log("\n── 2. HG group assignments ──");
const expectedHG: Record<TierA, HGGroup> = {
  "ship-slm":       "HG-1",
  "chief-slm":      "HG-1",
  "chirpee":        "HG-1",
  "puranic-os":     "HG-1",
  "carbonx":        "HG-2",
  "parali-central": "HG-2",
  "pramana":        "HG-2",
  "domain-capture": "HG-2",
  "granthx":        "HG-3",
  "stackpilot":     "HG-3",
  "ankrclaw":       "HG-3",
  "ankr-doctor":    "HG-3",
};
for (const [svc, expectedGroup] of Object.entries(expectedHG) as [TierA, HGGroup][]) {
  const p = policies.find(x => x.service_id === svc)!;
  check(`${svc}: HG group = ${expectedGroup}`, p.hg_group, expectedGroup);
}
check("HG-1 count = 4", byGroup["HG-1"].length, 4);
check("HG-2 count = 4", byGroup["HG-2"].length, 4);
check("HG-3 count = 4", byGroup["HG-3"].length, 4);
check("HG-0 count = 0 (no monitor-only in TIER-A)", byGroup["HG-0"].length, 0);
check("HG-4 count = 0 (reserved)", byGroup["HG-4"].length, 0);

// ── 3. HG-3 must not be eligible ─────────────────────────────────────────────

console.log("\n── 3. HG-3 services — hard_gate_eligible = false ──");
for (const p of byGroup["HG-3"]) {
  check(`${p.service_id} (HG-3): not eligible`, p.hard_gate_eligible, false);
}

// ── 4. HG-1 hard_block list: no execution-level capabilities ─────────────────

console.log("\n── 4. HG-1 hard_block list must not include execution-level capabilities ──");
const EXECUTION_CAPS = ["CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE",
  "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE"];
for (const p of byGroup["HG-1"]) {
  const overlap = p.hard_block_capabilities_when_enabled.filter(c => EXECUTION_CAPS.includes(c));
  check(`${p.service_id} (HG-1): no exec caps in hard_block`, overlap.length, 0);
}

// ── 5. No policy contradiction — READ not in hard_block for any service ───────

console.log("\n── 5. No contradiction — READ not in hard_block for any service ──");
for (const p of policies) {
  const readInHardBlock = p.hard_block_capabilities_when_enabled.includes("READ");
  check(`${p.service_id}: READ not in hard_block_when_enabled`, readInHardBlock, false);
}

// ── 6. Global meta invariants ─────────────────────────────────────────────────

console.log("\n── 6. Global meta invariants ──");
check("meta: hard_gate_enabled = false", matrixJson._meta.hard_gate_enabled, false);
check("meta: hard_gate_status = policy_defined_not_enabled", matrixJson._meta.hard_gate_status, "policy_defined_not_enabled");
check("meta: hard_gate_requires_manual_switch = true", matrixJson._meta.hard_gate_requires_manual_switch, true);
check("meta: ready_to_discuss_hard_gate = true", matrixJson._meta.ready_to_discuss_hard_gate, true);
check("meta: ready_to_enable_hard_gate = false", matrixJson._meta.ready_to_enable_hard_gate, false);
check("meta: read_never_hard_blocks = true", matrixJson._meta.policy_invariants.read_never_hard_blocks, true);
check("meta: unknown_service_remains_warn = true", matrixJson._meta.policy_invariants.unknown_service_remains_warn, true);
check("meta: unknown_cap_gates_before_blocking = true", matrixJson._meta.policy_invariants.unknown_cap_gates_before_blocking, true);
check("meta: hg3_not_yet_eligible = true", matrixJson._meta.policy_invariants.hg3_not_yet_eligible, true);
check("meta: staged_not_fleet_rollout = true", matrixJson._meta.policy_invariants.staged_not_fleet_rollout, true);
check("meta: rollback_documented = true", matrixJson._meta.policy_invariants.rollback_documented, true);

// ── 7. Rollout sequence — staged, not fleet-wide ──────────────────────────────

console.log("\n── 7. Rollout sequence — staged not fleet-wide ──");
const rolloutOrdered = [...policies].sort((a, b) => a.rollout_order - b.rollout_order);
const hg1First = rolloutOrdered.slice(0, 4).every(p => p.hg_group === "HG-1");
const hg2Middle = rolloutOrdered.slice(4, 8).every(p => p.hg_group === "HG-2");
const hg3Last = rolloutOrdered.slice(8).every(p => p.hg_group === "HG-3");
check("rollout: HG-1 services in positions 1-4", hg1First, true);
check("rollout: HG-2 services in positions 5-8", hg2Middle, true);
check("rollout: HG-3 services in positions 9-12", hg3Last, true);
check("rollout: chirpee is first (rollout_order=1)", rolloutOrdered[0].service_id, "chirpee");
// ankrclaw must be last in HG-3 (external + BR-5 = last)
const hg3Sorted = byGroup["HG-3"].sort((a, b) => a.rollout_order - b.rollout_order);
check("rollout: ankrclaw is last in HG-3 (external_call + BR-5)", hg3Sorted[hg3Sorted.length - 1].service_id, "ankrclaw");

// ── 8. Blockers documented for all services ───────────────────────────────────

console.log("\n── 8. Blockers documented for all services ──");
for (const p of policies) {
  check(`${p.service_id}: has ≥1 blocker`, p.hard_gate_blockers.length >= 1, true);
}

// ── 9. HG-2 services are eligible but not enabled ────────────────────────────

console.log("\n── 9. HG-2: eligible but not enabled ──");
for (const p of byGroup["HG-2"]) {
  check(`${p.service_id} (HG-2): eligible = true`, p.hard_gate_eligible, true);
  check(`${p.service_id} (HG-2): enabled = false`, p.hard_gate_enabled, false);
}

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("\n══ Policy Verification Summary ══");
console.log(`  Total checks:            ${totalChecks}`);
console.log(`  PASS:                    ${passed}`);
console.log(`  FAIL:                    ${failed}`);
console.log(`  hard_gate_globally_enabled: ${HARD_GATE_GLOBALLY_ENABLED}`);
console.log(`  ready_to_discuss:        true  (Batch 28 result)`);
console.log(`  ready_to_enable:         false (Batch 29 result — staged human decision required)`);

if (failed > 0) {
  console.log("\n  Policy failures:");
  for (const f of failures) {
    console.log(`    ✗ ${f.label}: expected=${f.expected} actual=${f.actual}`);
  }
}

// ── Group summary table ───────────────────────────────────────────────────────

console.log("\n── HG group assignments ──");
console.log("  Service            Group   BR    Authority       Eligible  Rollout#");
for (const p of rolloutOrdered) {
  console.log(
    `  ${p.service_id.padEnd(18)} ${p.hg_group.padEnd(7)} ${p.governance_blast_radius.padEnd(5)} ` +
    `${p.authority_class.padEnd(15)} ${String(p.hard_gate_eligible).padEnd(9)} ${p.rollout_order}`
  );
}

// ── Artifacts ─────────────────────────────────────────────────────────────────

const OUT = "/root/.aegis";
mkdirSync(OUT, { recursive: true });

// Artifact 1: matrix JSON
writeFileSync(join(OUT, "batch29_service_hard_gate_matrix.json"), JSON.stringify(matrixJson, null, 2));

// Artifact 2: blockers JSON
const blockersJson = {
  generated_at: new Date().toISOString(),
  batch: "batch29",
  policy_checks: { total: totalChecks, passed, failed },
  hard_gate_globally_enabled: HARD_GATE_GLOBALLY_ENABLED,
  ready_to_enable_hard_gate: false,
  canonical_capability_registry_complete: false,
  global_blockers: [
    "Canonical capability registry not complete — unknown capabilities must GATE not hard-block until this changes",
    "No AEGIS_HARD_GATE_ENABLED env var exists yet — adding it is a deliberate manual step, not an automated promotion",
    "HG-3 services (granthx, stackpilot, ankrclaw, ankr-doctor) require human governor sign-off",
  ],
  by_group: {
    "HG-1": {
      services: byGroup["HG-1"].map(p => p.service_id),
      blockers: byGroup["HG-1"][0]?.hard_gate_blockers ?? [],
      earliest_enable_stage: "Stage 1 — after canonical registry progress noted",
    },
    "HG-2": {
      services: byGroup["HG-2"].map(p => p.service_id),
      blockers: ["HG-1 must run clean for ≥7 days", ...byGroup["HG-2"].flatMap(p => p.hard_gate_blockers)],
      earliest_enable_stage: "Stage 4 — after HG-1 fully stable",
    },
    "HG-3": {
      services: byGroup["HG-3"].map(p => p.service_id),
      blockers: byGroup["HG-3"].flatMap(p => p.hard_gate_blockers),
      earliest_enable_stage: "Stage 6+ — TBD, not on current sprint",
    },
  },
  per_service_failures: failures,
};
writeFileSync(join(OUT, "batch29_blockers.json"), JSON.stringify(blockersJson, null, 2));

// Artifact 3: summary markdown
const summaryMd = [
  `# AEGIS Batch 29 — Hard-Gate Readiness Policy`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Status:** policy_defined_not_enabled`,
  ``,
  `> *Batch 28 says the fleet survived rough weather.*`,
  `> *Batch 29 writes the standing orders before anyone is allowed to fire the guns.*`,
  ``,
  `## Critical Distinction`,
  ``,
  `| Signal | Value | Source |`,
  `|---|---|---|`,
  `| ready_to_discuss_hard_gate | **true** | Batch 28 — 489/489 rough-weather PASS |`,
  `| ready_to_enable_hard_gate | **false** | Batch 29 — staged human decision required |`,
  `| hard_gate_globally_enabled | **false** | This batch — non-negotiable |`,
  ``,
  `Hard gate means the runtime can DENY action, not just interrupt and gate it.`,
  `A false positive in hard mode is an **outage**, not a GATE delay.`,
  `A bad policy in hard mode **blocks useful work silently**.`,
  ``,
  `## Policy Verification`,
  ``,
  `| Check | Result |`,
  `|---|---|`,
  `| All 12 TIER-A services have hard_gate_policy | ${policies.length === 12 ? "✓ PASS" : "✗ FAIL"} |`,
  `| No service has hard_gate_enabled = true | ${policies.every(p => !p.hard_gate_enabled) ? "✓ PASS" : "✗ FAIL"} |`,
  `| READ in never_block for all services | ${policies.every(p => p.never_block_capabilities.includes("READ")) ? "✓ PASS" : "✗ FAIL"} |`,
  `| HG-3 services: hard_gate_eligible = false | ${byGroup["HG-3"].every(p => !p.hard_gate_eligible) ? "✓ PASS" : "✗ FAIL"} |`,
  `| HG-1 hard_block: no execution-level caps | ${byGroup["HG-1"].every(p => p.hard_block_capabilities_when_enabled.every(c => !EXECUTION_CAPS.includes(c))) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Rollout is staged (HG-1→HG-2→HG-3) | ${hg1First && hg2Middle && hg3Last ? "✓ PASS" : "✗ FAIL"} |`,
  `| chirpee is first in rollout | ${rolloutOrdered[0].service_id === "chirpee" ? "✓ PASS" : "✗ FAIL"} |`,
  `| ankrclaw is last in HG-3 | ${hg3Sorted[hg3Sorted.length - 1].service_id === "ankrclaw" ? "✓ PASS" : "✗ FAIL"} |`,
  `| All services have blockers documented | ${policies.every(p => p.hard_gate_blockers.length >= 1) ? "✓ PASS" : "✗ FAIL"} |`,
  `| **Policy checks total** | **${totalChecks} checks — ${passed} PASS / ${failed} FAIL** |`,
  ``,
  `## HG Group Definitions`,
  ``,
  `| Group | Label | Hard-blocks | Still gates | Services |`,
  `|---|---|---|---|---|`,
  `| HG-0 | Monitor-only | none | everything | none in TIER-A fleet |`,
  `| HG-1 | Malformed/impossible | IMPOSSIBLE_OP, EMPTY_CAP | DEPLOY/DELETE/EXECUTE/APPROVE | ${byGroup["HG-1"].map(p=>p.service_id).join(", ")} |`,
  `| HG-2 | Dangerous terminal | DEPLOY, DELETE, FULL_AUTONOMY | EXECUTE/APPROVE/AI_EXECUTE | ${byGroup["HG-2"].map(p=>p.service_id).join(", ")} |`,
  `| HG-3 | High-consequence | (future: + SPAWN/MEMORY_WRITE) | ALL EXECUTE/APPROVE/WRITE | ${byGroup["HG-3"].map(p=>p.service_id).join(", ")} |`,
  `| HG-4 | Reserved | — | — | none |`,
  ``,
  `## Service Classification Matrix`,
  ``,
  `| Service | Group | BR | Authority | Eligible | Rollout# | Batch 27/28 |`,
  `|---|---|---|---|---|---|---|`,
  ...rolloutOrdered.map(p =>
    `| ${p.service_id} | ${p.hg_group} | ${p.governance_blast_radius} | ${p.authority_class} | ${p.hard_gate_eligible ? "yes" : "**no**"} | ${p.rollout_order} | clean |`
  ),
  ``,
  `## Global Rules (non-overridable)`,
  ``,
  `| Rule | Policy | Rationale |`,
  `|---|---|---|`,
  `| READ operations | ALWAYS_ALLOW | AEG-E-002 extended to hard mode |`,
  `| Unknown service | WARN (never BLOCK) | Blast radius unknown — WARN is safe |`,
  `| Unknown capability | GATE (not hard-block) | Until canonical registry is complete |`,
  `| Soft-mode BLOCK→GATE | Remains default | Until service explicitly promoted to HG group |`,
  ``,
  `## Key Rationale Per HG-3 Service`,
  ``,
  `**granthx (BR-5, execution):** Every ANKR service queries the knowledge layer. Hard-block on granthx is a fleet-wide outage. HG-3, not yet eligible.`,
  ``,
  `**stackpilot (BR-5, execution):** All agent orchestration pipelines route through it. Hard-block stops all agent work. HG-3, not yet eligible.`,
  ``,
  `**ankrclaw (BR-5, external_call):** ANCHOR router — WhatsApp/Telegram traffic is real customer traffic. A false positive drops live messages. External_call + BR-5 = last in rollout. Legal review mandatory.`,
  ``,
  `**ankr-doctor (BR-5, governance):** Diagnostic service, but governance authority + BR-5 means hard-blocking diagnostic ops could mask operational failures downstream. Governance review required.`,
  ``,
  `## Blockers Before Any Hard-Gate Enable`,
  ``,
  `**Global:**`,
  `- Canonical capability registry not complete — unknown caps must GATE not hard-block`,
  `- AEGIS_HARD_GATE_ENABLED env var does not exist — creating it is a manual deliberate step`,
  ``,
  `**HG-1 blockers:**`,
  ...byGroup["HG-1"][0].hard_gate_blockers.map(b => `- ${b}`),
  ``,
  `**HG-2 blockers:**`,
  `- HG-1 must run clean for ≥7 days`,
  `- External impact review for carbonx (carbon credits) and parali-central (energy)`,
  ``,
  `**HG-3 blockers:**`,
  `- HG-2 must run clean for ≥14 days`,
  `- Human governor sign-off (separate from code review)`,
  `- Legal review for ankrclaw (external_call + real customer traffic)`,
  `- BR-5 review for granthx and stackpilot`,
  ``,
  `---`,
  `*AEGIS hard-gate readiness policy — Batch 29 — @rule:AEG-E-019 / @rule:AEG-HG-001*`,
].join("\n");

writeFileSync(join(OUT, "batch29_hard_gate_policy_summary.md"), summaryMd);

// Artifact 4: rollout sequence markdown
const rolloutMd = [
  `# AEGIS Hard-Gate Rollout Sequence`,
  ``,
  `**Status:** policy_defined — not yet scheduled`,
  `**Governing rule:** ready_to_enable_hard_gate = false until each stage passes human review`,
  ``,
  `## Staged Rollout`,
  ``,
  `Each stage requires: (a) previous stage clean for the soak period, (b) human decision to proceed, (c) config change (not code change).`,
  ``,
  `### Stage 0 — Now (current state)`,
  `- All 12 TIER-A services in soft-canary mode`,
  `- Policy defined (Batch 29)`,
  `- No hard-gate enabled`,
  `- Action: none — observe`,
  ``,
  `### Stage 1 — HG-1 pilot: chirpee`,
  `- Prerequisite: canonical capability registry progress noted`,
  `- Service: chirpee (consumer text agent, BR-0, read_only)`,
  `- Hard-blocks when enabled: IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE`,
  `- All high-consequence ops (DEPLOY/DELETE/EXECUTE) remain GATE`,
  `- Rationale: lowest blast radius. Consumer-facing = false positive surface is visible and recoverable.`,
  `- Soak: 7 days clean before Stage 2`,
  `- Rollback: set chirpee hard_gate_enabled=false (config change, no deployment)`,
  ``,
  `### Stage 2 — HG-1 expand: ship-slm + chief-slm`,
  `- Prerequisite: chirpee HG-1 clean for 7 days`,
  `- Services: ship-slm, chief-slm (SLM inference, BR-0, read_only)`,
  `- Same hard-block policy as Stage 1`,
  `- Rationale: read-only inference models, no write path, minimal false positive risk`,
  `- Soak: 3 days clean before Stage 3`,
  `- Rollback: per-service config`,
  ``,
  `### Stage 3 — HG-1 complete: puranic-os`,
  `- Prerequisite: ship-slm/chief-slm HG-1 clean for 3 days`,
  `- Service: puranic-os (BR-1, read_only)`,
  `- Rationale: slightly higher blast than LOW_4 average (BR-1) — last in HG-1`,
  `- Soak: 7 days before HG-2 eligibility review`,
  ``,
  `### Stage 4 — HG-2 pilot: pramana + domain-capture`,
  `- Prerequisite: all HG-1 services clean for ≥7 days`,
  `- Services: pramana (verification, BR-5, read_only authority), domain-capture (BR-5, read_only authority)`,
  `- Hard-blocks when enabled: DEPLOY, DELETE, FULL_AUTONOMY`,
  `- EXECUTE/APPROVE/AI_EXECUTE/TRIGGER/EMIT remain GATE`,
  `- Rationale: read_only authority class limits hard-block scope even at BR-5 governance blast`,
  `- Soak: 7 days before Stage 5`,
  `- Additional prerequisite: governance reviewer sign-off for BR-5 services`,
  ``,
  `### Stage 5 — HG-2 expand: carbonx + parali-central`,
  `- Prerequisite: Stage 4 clean for 7 days + per-service external impact review`,
  `- Services: carbonx (carbon credits, BR-3, external_call), parali-central (energy, BR-3, external_call)`,
  `- Hard-blocks when enabled: DEPLOY, DELETE, FULL_AUTONOMY`,
  `- EXECUTE/APPROVE remain GATE (external_call authority = external parties affected)`,
  `- Additional prerequisites:`,
  `    carbonx: legal review — carbon credit financial implications`,
  `    parali-central: operational safety review — energy platform`,
  ``,
  `### Stage 6+ — HG-3 (future, timing TBD)`,
  `- Not on current sprint`,
  `- Prerequisite: all HG-2 services clean for ≥14 days`,
  `- Services: ankr-doctor → granthx/stackpilot (parallel) → ankrclaw (last)`,
  `- Additional: human governor sign-off, legal review (ankrclaw), BR-5 review (granthx/stackpilot)`,
  `- ankrclaw is LAST because external_call + BR-5 = live customer traffic impact`,
  ``,
  `## Rollback Plan`,
  ``,
  `| Scenario | Action | Time | Data loss |`,
  `|---|---|---|---|`,
  `| Single service false positive | Set hard_gate_enabled=false for that service | <1 min (config change) | None |`,
  `| Group false positive | Disable HG group for all affected services | <2 min | None |`,
  `| Policy bug | Revert hard_gate_policy JSON, disable all hard-gate | <5 min | None |`,
  `| Soft-canary regression | All services revert to shadow observation | <1 min | None |`,
  ``,
  `No rollback requires a deployment. All rollbacks are config changes.`,
  `Soft-canary remains the safety net throughout — a service removed from hard-gate`,
  `automatically falls back to soft-canary GATE behavior.`,
  ``,
  `## Batch Sequence`,
  ``,
  `| Batch | Scope | Window | Status |`,
  `|---|---|---|---|`,
  `| Batch 21–22 | 3 svc | Real traffic + rough weather | complete |`,
  `| Batch 23–24 | 6 svc | Expansion + observation | complete |`,
  `| Batch 25 | 6 svc | Rough weather | complete |`,
  `| Batch 26 | 12 svc | Full TIER-A expansion | complete |`,
  `| Batch 27 | 12 svc | Observation window | complete |`,
  `| Batch 28 | 12 svc | Rough weather (489/489) | complete |`,
  `| **Batch 29** | **12 svc** | **Hard-gate policy** | **policy_defined** |`,
  `| Batch 30 | Stage 1 | HG-1 pilot (chirpee) | not yet started |`,
  ``,
  `---`,
  `*AEGIS hard-gate rollout sequence — Batch 29 — @rule:AEG-HG-001*`,
].join("\n");

writeFileSync(join(OUT, "batch29_rollout_sequence.md"), rolloutMd);

console.log("\n── Artifacts ──");
console.log(`  ${join(OUT, "batch29_hard_gate_policy_summary.md")}`);
console.log(`  ${join(OUT, "batch29_service_hard_gate_matrix.json")}`);
console.log(`  ${join(OUT, "batch29_rollout_sequence.md")}`);
console.log(`  ${join(OUT, "batch29_blockers.json")}`);
console.log(`\n  Hard-gate policy: ${failed === 0 ? "CLEAN — standing orders written. Fleet stays soft-canary. Batch 30 is Stage 1 pilot (chirpee HG-1)." : `${failed} POLICY FAILURE(S) — review before proceeding.`}`);
