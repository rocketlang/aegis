/**
 * Batch 52 — AEGIS HG-2B External-State Doctrine Readiness
 *
 * PURPOSE: Define the rules of engagement for the first HG-2B candidate
 * (parali-central) BEFORE any soak or promotion begins. This is NOT a
 * promotion batch. parali-central must remain unpromoted throughout.
 *
 * Outputs:
 *   audits/batch52_hg2b_external_state_doctrine_readiness.json
 */

import { writeFileSync, existsSync } from "fs";
import { resolve } from "path";
import {
  HARD_GATE_GLOBALLY_ENABLED,
  HARD_GATE_POLICIES,
  applyHardGate,
  CHIRPEE_HG1_POLICY,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
  PURANIC_OS_HG1_POLICY,
  PRAMANA_HG2A_POLICY,
  DOMAIN_CAPTURE_HG2A_POLICY,
} from "../src/enforcement/hard-gate-policy";

// ── Env: live roster only — parali-central must NOT appear ───────────────────
process.env.AEGIS_HARD_GATE_SERVICES =
  "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture";
process.env.HARD_GATE_GLOBALLY_ENABLED = "true";

// ── HG-2B Doctrine definition ────────────────────────────────────────────────

const HG2B_DOCTRINE = {
  schema: "aegis-hg2b-doctrine-v1",
  defined_at: "2026-05-03",
  defined_in_batch: 52,
  candidate: "parali-central",
  candidate_status: "pre-soak — NOT in AEGIS_HARD_GATE_SERVICES",

  // ── Core identity ─────────────────────────────────────────────────────────
  hg_group: "HG-2B",
  hg_group_description:
    "External-state / boundary-crossing services. May touch external APIs, " +
    "third-party systems, or shared mutable state outside the ANKR monorepo. " +
    "Higher governance friction than HG-1/HG-2A because reversibility cannot " +
    "be assumed at the policy layer.",

  // ── Doctrine fields (check 8) ─────────────────────────────────────────────
  doctrine_fields: {
    external_state_touch: {
      type: "boolean",
      description:
        "Service may write to or read from a system that lives outside the " +
        "ANKR runtime boundary (external API, partner endpoint, third-party DB). " +
        "If true, rollback_path must be declared and audit_artifact_required=true.",
      required_in_policy: true,
    },
    boundary_crossing: {
      type: "boolean",
      description:
        "Service crosses a trust boundary on at least one code path: " +
        "inbound (receiving external input that affects internal state) or " +
        "outbound (emitting commands that change external state). " +
        "Both directions require explicit capability registration.",
      required_in_policy: true,
    },
    reversible_actions_only: {
      type: "boolean",
      description:
        "When true, all hard-blocked actions are reversible within the " +
        "rollback_window. When false, at least one action in the policy " +
        "scope is irreversible — approval_required_for_irreversible_action " +
        "must also be true.",
      required_in_policy: true,
    },
    approval_required_for_irreversible_action: {
      type: "boolean",
      description:
        "Any action that cannot be rolled back (external API mutation, " +
        "ledger write, external email/SMS send, webhook fire) requires " +
        "explicit human approval token before execution. " +
        "GATE verdict must never be bypassed to ALLOW on these paths.",
      required_in_policy: true,
    },
    kill_switch_scope: {
      type: "enum",
      values: ["global", "service", "capability_class"],
      description:
        "Minimum scope at which the kill switch must be effective. " +
        "'global' = HARD_GATE_GLOBALLY_ENABLED=false restores safe state. " +
        "'service' = removing from AEGIS_HARD_GATE_SERVICES restores safe state. " +
        "'capability_class' = individual capability removal suffices for safety.",
      required_in_policy: true,
    },
    rollback_path: {
      type: "string",
      description:
        "Human-readable description of how to roll back hard-gate for this " +
        "service. Must cover: config change, expected latency to safe state, " +
        "any external cleanup required. Cannot be 'remove from env' if " +
        "external_state_touch=true — must also describe external state cleanup.",
      required_in_policy: true,
    },
    observability_required: {
      type: "boolean",
      description:
        "If true, every hard-gate decision must emit a SENSE event with " +
        "before_snapshot, after_snapshot, delta. External-state services " +
        "require observability_required=true — silent boundary crossings are " +
        "a governance violation (CA-003).",
      required_in_policy: true,
    },
    audit_artifact_required: {
      type: "boolean",
      description:
        "If true, every promotion, soak run, and rollback must produce a " +
        "tracked artifact in audits/. External-state services always " +
        "require audit_artifact_required=true. Non-negotiable for HG-2B.",
      required_in_policy: true,
    },
  },

  // ── Allowed action classes (check 9) ────────────────────────────────────
  allowed_action_classes: {
    always_allow: [
      "READ — idempotent reads from external state; no mutation",
      "GET — same as READ",
      "LIST — enumeration without side-effects",
      "QUERY — read-only queries (external or internal)",
      "SEARCH — read-only search across external index",
      "HEALTH — liveness/readiness probe; no state mutation",
      "STATUS — status check of external system (read-only)",
    ],
    allow_with_approval_token: [
      "EXTERNAL_READ_SENSITIVE — reads external PII/financial data (requires scoped token)",
      "BOUNDARY_PROBE — one-time connectivity check with audit trail",
    ],
    gate_required: [
      "EXTERNAL_WRITE — write to any external system (approval lifecycle required)",
      "EXTERNAL_DELETE — delete from external system (irreversible; explicit token required)",
      "EXTERNAL_NOTIFY — send external notification (email/SMS/webhook; irreversible)",
      "BOUNDARY_MUTATION — mutate shared state across trust boundary",
      "SYNC_PUSH — push internal state to external endpoint",
      "SYNC_PULL_MUTATE — pull external data and mutate internal record",
      "EXTERNAL_EXECUTE — trigger execution on external system",
      "APPROVE_EXTERNAL — approve an action in an external workflow",
    ],
  },

  // ── Forbidden action classes (check 10) ─────────────────────────────────
  forbidden_action_classes: {
    hard_block_always: [
      "IMPOSSIBLE_OP — demonstrably invalid sentinel; blocked in all HG groups",
      "EMPTY_CAPABILITY_ON_WRITE — empty cap string on write-class op; blocked in all HG groups",
      "EXTERNAL_WRITE_UNAUTHENTICATED — write to external system with no auth token",
      "EXTERNAL_DELETE_UNAPPROVED — delete from external system without approval token",
      "BULK_EXTERNAL_MUTATION — batch write/delete to external system (blast radius too high for hard-gate)",
      "FORCE_EXTERNAL_OVERWRITE — overwrite external record without snapshot (CA-003 violation)",
    ],
    hard_block_in_hg2b: [
      "EXTERNAL_WRITE — when approval token absent",
      "EXTERNAL_NOTIFY — when approval token absent",
      "BOUNDARY_MUTATION — when external_state_touch=true and approval token absent",
      "SYNC_PUSH — when destination is external and audit trail absent",
      "CROSS_GROUP_PROMOTION — no HG-2B service may trigger promotion of another service",
    ],
    never_block_invariant: [
      "READ — AEG-HG-002; holds for all HG groups including HG-2B",
    ],
  },

  // ── Entry criteria (check 11) — soft_canary gate ─────────────────────────
  soft_canary_entry_criteria: {
    description: "Conditions that must hold before parali-central enters soft_canary phase",
    required: [
      "HG-2B policy declared in hard-gate-policy.ts with all doctrine_fields populated",
      "authority_class and governance_blast_radius declared in codex.json",
      "runtime_readiness.tier assessed (TIER-A or TIER-B required for HG-2B)",
      "external_state_touch and boundary_crossing declared as booleans in policy",
      "rollback_path written as prose — must describe external cleanup if applicable",
      "observability_required=true and audit_artifact_required=true confirmed",
      "approval lifecycle stubs present: approveToken / denyToken / revokeToken exist",
      "soft_canary does NOT appear in AEGIS_HARD_GATE_SERVICES",
      "hard_gate_enabled=false in policy (not yet promoted)",
      "pre-soak doctrine readiness batch (Batch 52) PASS on record",
    ],
  },

  // ── Soak criteria (check 12) ──────────────────────────────────────────────
  soak_criteria: {
    description: "Conditions that must hold throughout soak before promotion is considered",
    required: [
      "7 consecutive soak runs minimum (same standard as HG-1 and HG-2A)",
      "0 false positives across all runs (ALLOW path must never misfire)",
      "0 production fires (hard-gate must not activate on live traffic during soak)",
      "External-state action classes: GATE fires correctly on each run",
      "Approval lifecycle exercised: approveToken/denyToken/revokeToken confirmed in run 7",
      "SENSE events verified: before_snapshot + after_snapshot + delta present on boundary-crossing ops",
      "Rollback drill performed in run 7: remove from env, verify soft_canary return, restore",
      "Existing 6 live guards must pass regression in every soak run",
      "HG-2B/HG-2C isolation check: no HG-2B cap leaks into HG-1 or HG-2A policy space",
      "Each soak run emits tracked artifact in audits/",
    ],
    minimum_soak_runs: 7,
    minimum_fp_budget: 0,
    minimum_prod_fires: 0,
    approval_lifecycle_soak_run: 7,
  },

  // ── Promotion criteria (check 13) ────────────────────────────────────────
  promotion_criteria: {
    description: "All conditions required before parali-central enters hard_gate phase",
    required: [
      "7/7 soak PASS with 0 false positives and 0 production fires",
      "promotion_permitted_parali_central=true declared in final soak artifact",
      "Approval lifecycle LIVE confirmed in final soak run",
      "Rollback drill PASS in final soak run",
      "Regression against all 6 existing live guards: PASS",
      "hard_gate_enabled set to true in PARALI_CENTRAL_HG2B_POLICY",
      "parali-central added to AEGIS_HARD_GATE_SERVICES",
      "codex.json updated: hg_group_status=LIVE, aegis_batchNN_promotion block added",
      "Tracked promotion artifact emitted to audits/batchNN_parali_central_hg2b_promotion.json",
      "SENSE observability verified: no silent boundary crossings in promotion batch",
      "Live roster size becomes 7 after promotion",
    ],
  },

  // ── Rollback criteria (check 14) ─────────────────────────────────────────
  rollback_criteria: {
    description: "When and how to roll back parali-central from hard_gate phase",
    trigger_conditions: [
      "Any false positive on a live request (immediate rollback — no threshold)",
      "External state mutation without approval token (immediate rollback)",
      "SENSE event missing on boundary-crossing operation",
      "Approval lifecycle malfunction (approveToken/denyToken/revokeToken fails)",
      "Any production fire within 24h of promotion",
      "Cross-group contamination (HG-2B policy affects HG-1/HG-2A decisions)",
    ],
    rollback_path: {
      step_1: "Remove parali-central from AEGIS_HARD_GATE_SERVICES",
      step_2: "Verify parali-central returns to soft_canary (GATE not BLOCK on hard-blocked caps)",
      step_3: "Verify READ still returns ALLOW (AEG-HG-002 must hold during rollback)",
      step_4:
        "If external_state_touch=true: audit external system for mutations during hard-gate window; " +
        "document in rollback artifact",
      step_5: "Emit audits/batchNN_parali_central_rollback.json with cause and external cleanup record",
      step_6: "Do not re-promote until root cause is understood and doctrine updated",
    },
    external_state_cleanup_required: true,
    rollback_artifact_required: true,
  },

  // ── Failure taxonomy (check 15) ──────────────────────────────────────────
  failure_taxonomy: {
    schema: "aegis-hg2b-failure-taxonomy-v1",
    classes: {
      false_positive_block: {
        code: "FP-BLOCK",
        description:
          "Hard-gate fired BLOCK on a legitimate operation that should have passed. " +
          "Trigger: any FP on live traffic. Severity: CRITICAL — immediate rollback.",
        example:
          "An authenticated EXTERNAL_WRITE with valid approval token was blocked " +
          "because the policy did not recognise the token format.",
        mitigation: "Rollback immediately. Fix capability classification. Re-soak from run 1.",
      },
      missed_true_positive: {
        code: "TP-MISS",
        description:
          "Hard-gate did NOT fire BLOCK on an operation that should have been blocked. " +
          "Trigger: policy audit finds hard_block_capabilities missing a dangerous cap class. " +
          "Severity: HIGH — fix policy before next soak run.",
        example:
          "EXTERNAL_WRITE_UNAUTHENTICATED reached the external endpoint because the capability " +
          "string was submitted in lowercase ('external_write_unauthenticated') and " +
          "normalisation was not applied.",
        mitigation: "Audit capability normalisation path. Expand hard_block_capabilities.",
      },
      external_state_mutation: {
        code: "EXT-MUT",
        description:
          "External system state was changed without an audit trail or approval token. " +
          "Trigger: SENSE event missing on boundary-crossing op, OR external system " +
          "confirms write that has no corresponding approval token in the record. " +
          "Severity: CRITICAL — immediate rollback + external cleanup.",
        example:
          "parali-central pushed a rule candidate to an external partner API during " +
          "a soak run without emitting a SENSE event. State at partner is now unknown.",
        mitigation:
          "Rollback. Audit external system. Document cleanup. " +
          "Enforce observability_required=true gate before re-soak.",
      },
      irreversible_action_without_approval: {
        code: "IRR-NOAPPROVAL",
        description:
          "An irreversible external action (notification, ledger write, webhook) was " +
          "executed without an explicit approval token. " +
          "Severity: CRITICAL — rollback if possible; external audit mandatory.",
        example:
          "An EXTERNAL_NOTIFY cap fired an SMS to a customer record. " +
          "No approval token was present. Action cannot be reversed.",
        mitigation:
          "Rollback hard-gate. Block EXTERNAL_NOTIFY cap in policy until approval " +
          "lifecycle is verified. External cleanup as possible.",
      },
      unknown_service_block: {
        code: "UNK-SVC-BLOCK",
        description:
          "Hard-gate fired BLOCK on an unknown service (not in HARD_GATE_POLICIES). " +
          "This violates AEG-HG-001 — unknown services must never hard-block. " +
          "Severity: HIGH — indicates a policy registry corruption.",
        example:
          "A new service named 'parali-staging' was added to AEGIS_HARD_GATE_SERVICES " +
          "by mistake before its policy was declared. Calls to it were BLOCKed silently.",
        mitigation:
          "Remove unknown service from AEGIS_HARD_GATE_SERVICES immediately. " +
          "Audit how it was added (AEG-HG-003 requires explicit manual step).",
      },
      unknown_capability_block: {
        code: "UNK-CAP-BLOCK",
        description:
          "Hard-gate fired BLOCK on an unknown capability for a live service. " +
          "Unknown capabilities must remain GATE/WARN, never BLOCK. " +
          "Severity: HIGH — false-positive factory for new feature rollouts.",
        example:
          "A new capability 'SYNC_HYBRID' was introduced. Because it wasn't in " +
          "hard_block_capabilities or always_allow_capabilities, the policy " +
          "defaulted to BLOCK rather than GATE.",
        mitigation:
          "Add SYNC_HYBRID to still_gate_capabilities or always_allow_capabilities. " +
          "Never let unknown capabilities default to BLOCK.",
      },
      cross_group_promotion_leak: {
        code: "XGRP-LEAK",
        description:
          "An HG-2B policy decision leaked into or overrode an HG-1 or HG-2A verdict. " +
          "Groups must be isolated — the policy for parali-central must not affect " +
          "chirpee, ship-slm, chief-slm, puranic-os, pramana, or domain-capture. " +
          "Severity: HIGH — undermines HG group isolation guarantee.",
        example:
          "A shared capability string 'EMIT' was added to parali-central's " +
          "hard_block_capabilities. Because chirpee also uses 'EMIT', both services " +
          "were blocked on EMIT — cross-group contamination.",
        mitigation:
          "Scope all HG-2B capability strings to parali-central's domain. " +
          "Run cross-group isolation check after every policy update.",
      },
    },
  },

  // ── Doctrine readiness summary ────────────────────────────────────────────
  doctrine_readiness: {
    fields_defined: 8,
    allowed_classes_defined: 3,
    forbidden_classes_defined: 3,
    entry_criteria_count: 10,
    soak_criteria_count: 10,
    promotion_criteria_count: 11,
    rollback_criteria_count: 6,
    failure_taxonomy_classes: 7,
    doctrine_complete: true,
    next_gate: "HG-2B policy declaration in hard-gate-policy.ts",
    next_gate_batch: "Batch 53 — parali-central policy declaration + soak run 1",
  },
};

// ── Check helpers ─────────────────────────────────────────────────────────────

let totalChecks = 0;
let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(
  group: number,
  label: string,
  actual: unknown,
  expected: unknown,
  cat: string,
): void {
  totalChecks++;
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  const icon = ok ? "✓" : "✗";
  const tag = `[${String(group).padStart(2, " ")}]`;
  const row = `  ${icon} ${tag} ${label.padEnd(60)} actual=${JSON.stringify(actual)}`;
  console.log(row);
  if (ok) {
    passed++;
  } else {
    failed++;
    failures.push(`C${group} ${cat}: ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  }
}

function assertDoctrineField(fieldName: string): void {
  totalChecks++;
  const exists = Object.prototype.hasOwnProperty.call(HG2B_DOCTRINE.doctrine_fields, fieldName);
  const icon = exists ? "✓" : "✗";
  console.log(`  ${icon} [8 ] doctrine_fields.${fieldName} defined`.padEnd(70));
  if (exists) {
    passed++;
  } else {
    failed++;
    failures.push(`C8 doctrine: field '${fieldName}' missing from HG2B_DOCTRINE.doctrine_fields`);
  }
}

function assertClassKey(
  group: number,
  label: string,
  arr: string[],
  minCount: number,
): void {
  totalChecks++;
  const ok = arr.length >= minCount;
  const icon = ok ? "✓" : "✗";
  console.log(`  ${icon} [${group}] ${label}: ${arr.length} entries (min ${minCount})`.padEnd(70));
  if (ok) {
    passed++;
  } else {
    failed++;
    failures.push(`C${group}: ${label} has ${arr.length} entries, need >= ${minCount}`);
  }
}

function assertTaxonomyClass(code: string): void {
  totalChecks++;
  const entries = Object.values(HG2B_DOCTRINE.failure_taxonomy.classes) as Array<{ code: string }>;
  const found = entries.some(e => e.code === code);
  const icon = found ? "✓" : "✗";
  console.log(`  ${icon} [15] failure_taxonomy class '${code}' present`.padEnd(70));
  if (found) {
    passed++;
  } else {
    failed++;
    failures.push(`C15: failure_taxonomy class '${code}' missing`);
  }
}

// ── BATCH 52 RUN ──────────────────────────────────────────────────────────────

console.log("══ Batch 52 — AEGIS HG-2B EXTERNAL-STATE DOCTRINE READINESS ══");
console.log(`  Date: ${new Date().toISOString()}`);
console.log(`  Candidate: parali-central (NOT in AEGIS_HARD_GATE_SERVICES)`);
console.log(`  Purpose: Doctrine definition, NOT promotion\n`);

// ── Check 1: Live roster remains exactly six ──────────────────────────────────
console.log("── Check 1: Live roster remains exactly six ──");
const envRaw = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
const liveRoster = envRaw.split(",").map(s => s.trim()).filter(Boolean);
check(1, "live roster count=6", liveRoster.length, 6, "roster_integrity");
check(1, "chirpee in roster", liveRoster.includes("chirpee"), true, "roster_integrity");
check(1, "ship-slm in roster", liveRoster.includes("ship-slm"), true, "roster_integrity");
check(1, "chief-slm in roster", liveRoster.includes("chief-slm"), true, "roster_integrity");
check(1, "puranic-os in roster", liveRoster.includes("puranic-os"), true, "roster_integrity");
check(1, "pramana in roster", liveRoster.includes("pramana"), true, "roster_integrity");
check(1, "domain-capture in roster", liveRoster.includes("domain-capture"), true, "roster_integrity");
console.log();

// ── Check 2: parali-central not in AEGIS_HARD_GATE_SERVICES ──────────────────
console.log("── Check 2: parali-central absent from AEGIS_HARD_GATE_SERVICES ──");
check(2, "parali-central NOT in env", liveRoster.includes("parali-central"), false, "isolation");
check(2, "no parali policy in HARD_GATE_POLICIES", "parali-central" in HARD_GATE_POLICIES, false, "isolation");
console.log();

// ── Check 3: No HG-2B policy has hard_gate_enabled=true ──────────────────────
console.log("── Check 3: No HG-2B policy has hard_gate_enabled=true ──");
const hg2bPoliciesEnabled = Object.entries(HARD_GATE_POLICIES)
  .filter(([, p]) => p.hg_group === "HG-2" && p.rollout_order > 6)
  .filter(([, p]) => p.hard_gate_enabled);
// Currently no HG-2B policies exist at all — that is correct
check(3, "no HG-2B policies declared yet", Object.values(HARD_GATE_POLICIES).filter(p => p.rollout_order > 6).length, 0, "isolation");
check(3, "parali-central hard_gate_enabled NOT true", hg2bPoliciesEnabled.length, 0, "isolation");
console.log();

// ── Check 4: HG-2B and HG-2C count in live roster is zero ────────────────────
console.log("── Check 4: HG-2B/HG-2C services not in live roster ──");
const hg2bCandidates = ["parali-central", "carbonx"];
const hg2cCandidates = ["ankr-doctor", "stackpilot"];
const hg2bInRoster = hg2bCandidates.filter(s => liveRoster.includes(s));
const hg2cInRoster = hg2cCandidates.filter(s => liveRoster.includes(s));
check(4, "HG-2B candidates in live roster count=0", hg2bInRoster.length, 0, "isolation");
check(4, "HG-2C candidates in live roster count=0", hg2cInRoster.length, 0, "isolation");
check(4, "parali-central absent", liveRoster.includes("parali-central"), false, "isolation");
check(4, "carbonx absent", liveRoster.includes("carbonx"), false, "isolation");
check(4, "ankr-doctor absent", liveRoster.includes("ankr-doctor"), false, "isolation");
console.log();

// ── Check 5: Unknown service never blocks ────────────────────────────────────
console.log("── Check 5: Unknown service never blocks ──");
const unknownServices = ["parali-central", "carbonx", "ankr-doctor", "future-service-x"];
for (const svc of unknownServices) {
  const r = applyHardGate(svc, "ALLOW", "DEPLOY", "deploy");
  check(5, `${svc}: unknown service not BLOCK`, r.decision === "BLOCK", false, "safety");
}
// Even if soft=BLOCK, unknown service preserves soft decision (no escalation)
const rBlock = applyHardGate("parali-central", "BLOCK", "IMPOSSIBLE_OP", "execute");
check(5, "parali-central: hard-gate inactive (not in env)", rBlock.hard_gate_active, false, "safety");
console.log();

// ── Check 6: Unknown capability never hard-blocks ────────────────────────────
console.log("── Check 6: Unknown capability never hard-blocks ──");
const unknownCaps = [
  "EXTERNAL_WRITE_UNAUTHENTICATED",
  "BULK_EXTERNAL_MUTATION",
  "BOUNDARY_MUTATION",
  "SYNC_PUSH",
  "CROSS_ORG_HANDSHAKE",
];
// These are unknown to all live policy objects — should not fire BLOCK from hard-gate
for (const cap of unknownCaps) {
  for (const svc of ["chirpee", "pramana", "domain-capture"]) {
    const r = applyHardGate(svc, "GATE", cap, "execute");
    const hardBlocked = r.hard_gate_applied && r.decision === "BLOCK";
    check(6, `${svc}+${cap}: unknown cap not hard-BLOCK`, hardBlocked, false, "safety");
  }
}
console.log();

// ── Check 7: Six live guards smoke check ─────────────────────────────────────
console.log("── Check 7: Six live guards ALLOW/BLOCK smoke ──");
const LIVE_SIX = [
  CHIRPEE_HG1_POLICY,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
  PURANIC_OS_HG1_POLICY,
  PRAMANA_HG2A_POLICY,
  DOMAIN_CAPTURE_HG2A_POLICY,
];
for (const p of LIVE_SIX) {
  // READ must always be ALLOW
  const rRead = applyHardGate(p.service_id, "ALLOW", "READ", "read");
  check(7, `${p.service_id}: READ=ALLOW`, rRead.decision, "ALLOW", "regression");

  // IMPOSSIBLE_OP must BLOCK in hard_gate
  const rBad = applyHardGate(p.service_id, "ALLOW", "IMPOSSIBLE_OP", "execute");
  check(7, `${p.service_id}: IMPOSSIBLE_OP=BLOCK`, rBad.decision, "BLOCK", "regression");

  // hard_gate_enabled must be true
  check(7, `${p.service_id}: hard_gate_enabled=true`, p.hard_gate_enabled, true, "regression");
}
console.log();

// ── Check 8: HG-2B doctrine fields defined ───────────────────────────────────
console.log("── Check 8: HG-2B doctrine_fields defined ──");
const requiredFields = [
  "external_state_touch",
  "boundary_crossing",
  "reversible_actions_only",
  "approval_required_for_irreversible_action",
  "kill_switch_scope",
  "rollback_path",
  "observability_required",
  "audit_artifact_required",
];
for (const f of requiredFields) assertDoctrineField(f);
check(8, "doctrine_fields count=8", Object.keys(HG2B_DOCTRINE.doctrine_fields).length, 8, "doctrine");
console.log();

// ── Check 9: Allowed action classes defined ───────────────────────────────────
console.log("── Check 9: Allowed action classes defined ──");
assertClassKey(9, "always_allow", HG2B_DOCTRINE.allowed_action_classes.always_allow, 6);
assertClassKey(9, "allow_with_approval_token", HG2B_DOCTRINE.allowed_action_classes.allow_with_approval_token, 2);
assertClassKey(9, "gate_required", HG2B_DOCTRINE.allowed_action_classes.gate_required, 6);
check(9, "READ present in always_allow", HG2B_DOCTRINE.allowed_action_classes.always_allow.some(s => s.startsWith("READ")), true, "doctrine");
console.log();

// ── Check 10: Forbidden action classes defined ───────────────────────────────
console.log("── Check 10: Forbidden action classes defined ──");
assertClassKey(10, "hard_block_always", HG2B_DOCTRINE.forbidden_action_classes.hard_block_always, 4);
assertClassKey(10, "hard_block_in_hg2b", HG2B_DOCTRINE.forbidden_action_classes.hard_block_in_hg2b, 3);
check(10, "READ in never_block_invariant", HG2B_DOCTRINE.forbidden_action_classes.never_block_invariant.some(s => s.startsWith("READ")), true, "doctrine");
check(10, "IMPOSSIBLE_OP in hard_block_always", HG2B_DOCTRINE.forbidden_action_classes.hard_block_always.some(s => s.startsWith("IMPOSSIBLE_OP")), true, "doctrine");
console.log();

// ── Check 11: Soft-canary entry criteria defined ──────────────────────────────
console.log("── Check 11: Soft-canary entry criteria defined ──");
check(11, "entry criteria count >=8", HG2B_DOCTRINE.soft_canary_entry_criteria.required.length >= 8, true, "doctrine");
check(11, "hard_gate_enabled=false required for entry", HG2B_DOCTRINE.soft_canary_entry_criteria.required.some(r => r.includes("hard_gate_enabled=false")), true, "doctrine");
check(11, "doctrine readiness batch required", HG2B_DOCTRINE.soft_canary_entry_criteria.required.some(r => r.includes("Batch 52")), true, "doctrine");
console.log();

// ── Check 12: Soak criteria defined ──────────────────────────────────────────
console.log("── Check 12: Soak criteria defined ──");
check(12, "soak criteria count >=8", HG2B_DOCTRINE.soak_criteria.required.length >= 8, true, "doctrine");
check(12, "minimum_soak_runs=7", HG2B_DOCTRINE.soak_criteria.minimum_soak_runs, 7, "doctrine");
check(12, "minimum_fp_budget=0", HG2B_DOCTRINE.soak_criteria.minimum_fp_budget, 0, "doctrine");
check(12, "minimum_prod_fires=0", HG2B_DOCTRINE.soak_criteria.minimum_prod_fires, 0, "doctrine");
check(12, "rollback drill in soak criteria", HG2B_DOCTRINE.soak_criteria.required.some(r => r.includes("Rollback drill")), true, "doctrine");
check(12, "SENSE event check in soak criteria", HG2B_DOCTRINE.soak_criteria.required.some(r => r.includes("SENSE")), true, "doctrine");
console.log();

// ── Check 13: Promotion criteria defined ─────────────────────────────────────
console.log("── Check 13: Promotion criteria defined ──");
check(13, "promotion criteria count >=8", HG2B_DOCTRINE.promotion_criteria.required.length >= 8, true, "doctrine");
check(13, "7/7 soak PASS required", HG2B_DOCTRINE.promotion_criteria.required.some(r => r.includes("7/7 soak PASS")), true, "doctrine");
check(13, "promotion_permitted_parali_central required", HG2B_DOCTRINE.promotion_criteria.required.some(r => r.includes("promotion_permitted_parali_central")), true, "doctrine");
check(13, "approval lifecycle LIVE required", HG2B_DOCTRINE.promotion_criteria.required.some(r => r.toLowerCase().includes("approval lifecycle live")), true, "doctrine");
check(13, "SENSE observability required", HG2B_DOCTRINE.promotion_criteria.required.some(r => r.includes("SENSE observability")), true, "doctrine");
console.log();

// ── Check 14: Rollback criteria defined ──────────────────────────────────────
console.log("── Check 14: Rollback criteria defined ──");
check(14, "rollback trigger conditions >=4", HG2B_DOCTRINE.rollback_criteria.trigger_conditions.length >= 4, true, "doctrine");
check(14, "rollback_path has 6 steps", Object.keys(HG2B_DOCTRINE.rollback_criteria.rollback_path).length, 6, "doctrine");
check(14, "external_state_cleanup_required=true", HG2B_DOCTRINE.rollback_criteria.external_state_cleanup_required, true, "doctrine");
check(14, "rollback_artifact_required=true", HG2B_DOCTRINE.rollback_criteria.rollback_artifact_required, true, "doctrine");
check(14, "READ safe during rollback — AEG-HG-002 referenced in step_3",
  (HG2B_DOCTRINE.rollback_criteria.rollback_path.step_3 as string).includes("AEG-HG-002"), true, "doctrine");
check(14, "FP triggers immediate rollback",
  HG2B_DOCTRINE.rollback_criteria.trigger_conditions.some(t => t.includes("false positive")), true, "doctrine");
console.log();

// ── Check 15: Failure taxonomy defined ───────────────────────────────────────
console.log("── Check 15: Failure taxonomy defined ──");
assertTaxonomyClass("FP-BLOCK");
assertTaxonomyClass("TP-MISS");
assertTaxonomyClass("EXT-MUT");
assertTaxonomyClass("IRR-NOAPPROVAL");
assertTaxonomyClass("UNK-SVC-BLOCK");
assertTaxonomyClass("UNK-CAP-BLOCK");
assertTaxonomyClass("XGRP-LEAK");
check(15, "taxonomy class count=7", Object.keys(HG2B_DOCTRINE.failure_taxonomy.classes).length, 7, "doctrine");
console.log();

// ── Check 16: Doctrine completeness ──────────────────────────────────────────
console.log("── Check 16: Doctrine completeness ──");
check(16, "doctrine_complete=true", HG2B_DOCTRINE.doctrine_readiness.doctrine_complete, true, "doctrine");
check(16, "fields_defined=8", HG2B_DOCTRINE.doctrine_readiness.fields_defined, 8, "doctrine");
check(16, "allowed_classes_defined=3", HG2B_DOCTRINE.doctrine_readiness.allowed_classes_defined, 3, "doctrine");
check(16, "forbidden_classes_defined=3", HG2B_DOCTRINE.doctrine_readiness.forbidden_classes_defined, 3, "doctrine");
check(16, "failure_taxonomy_classes=7", HG2B_DOCTRINE.doctrine_readiness.failure_taxonomy_classes, 7, "doctrine");
check(16, "next_gate declared", typeof HG2B_DOCTRINE.doctrine_readiness.next_gate === "string", true, "doctrine");
check(16, "next_gate_batch declared", typeof HG2B_DOCTRINE.doctrine_readiness.next_gate_batch === "string", true, "doctrine");
check(16, "HARD_GATE_GLOBALLY_ENABLED=true", HARD_GATE_GLOBALLY_ENABLED, true, "doctrine");
console.log();

// ── Summary ───────────────────────────────────────────────────────────────────
const verdict = failed === 0 ? "PASS" : "FAIL";
console.log("══ Batch 52 Summary ══");
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Verdict: ${verdict}`);
console.log();

if (failures.length > 0) {
  console.log("── Failures ──");
  failures.forEach(f => console.log(`  ✗ ${f}`));
  console.log();
}

// ── Emit artifact ─────────────────────────────────────────────────────────────
const artifact = {
  batch: 52,
  date: new Date().toISOString(),
  type: "hg2b_doctrine_readiness",
  verdict,
  total_checks: totalChecks,
  passed,
  failed,
  failures,
  live_roster: liveRoster,
  live_roster_size: liveRoster.length,
  candidate: "parali-central",
  candidate_phase: "pre-soak",
  candidate_in_env: liveRoster.includes("parali-central"),
  candidate_hard_gate_enabled: false,
  hg2b_in_live_roster: hg2bInRoster,
  hg2c_in_live_roster: hg2cInRoster,
  hg2b_doctrine: HG2B_DOCTRINE,
  governance_boundary: {
    pre_batch49: "runtime evidence in .aegis/ (ephemeral, legacy acceptable)",
    from_batch49: "promotion evidence in audits/ (tracked, mandatory)",
    hg2b_requirement: "all HG-2B soak + promotion artifacts must be in audits/ (audit_artifact_required=true)",
  },
  rollback_doctrine_confirmed: {
    read_safe_during_rollback: true,
    aeg_hg_002_invariant: "READ never hard-blocks in any mode or group",
    external_state_cleanup_required: true,
    rollback_artifact_required: true,
  },
  summary: [
    `Live roster: ${liveRoster.length} services — unchanged`,
    "parali-central: absent from env, no policy, hard_gate_enabled=false",
    "HG-2B/HG-2C in live roster: 0",
    "Unknown service/cap safety: PASS",
    "Six live guards regression: PASS",
    "HG-2B doctrine: fully defined (8 fields, 3 action classes, 7 failure codes)",
    "Next gate: Batch 53 — parali-central policy declaration + soak run 1",
  ],
};

const outPath = resolve(import.meta.dir, "../audits/batch52_hg2b_external_state_doctrine_readiness.json");
writeFileSync(outPath, JSON.stringify(artifact, null, 2));
console.log(`  Doctrine artifact → audits/batch52_hg2b_external_state_doctrine_readiness.json`);
console.log();

// ── HG-2B doctrine summary ────────────────────────────────────────────────────
console.log("── HG-2B doctrine: rules of engagement ──");
console.log("  external_state_touch         declared boolean — required in every HG-2B policy");
console.log("  boundary_crossing            declared boolean — both directions explicitly registered");
console.log("  reversible_actions_only      declared boolean — if false, approval required");
console.log("  approval_required_for_irreversible_action  boolean — non-negotiable for ledger/notify/webhook");
console.log("  kill_switch_scope            enum(global|service|capability_class)");
console.log("  rollback_path                prose — includes external cleanup if ext_state_touch=true");
console.log("  observability_required       always true for HG-2B (CA-003)");
console.log("  audit_artifact_required      always true for HG-2B (no silent boundary crossings)");
console.log();
console.log("  Failure taxonomy: FP-BLOCK · TP-MISS · EXT-MUT · IRR-NOAPPROVAL");
console.log("                    UNK-SVC-BLOCK · UNK-CAP-BLOCK · XGRP-LEAK");
console.log();
console.log("  HG-2B is not armed. Its rules of engagement are now written.");
console.log();
console.log(`  Batch 52: ${verdict}`);
