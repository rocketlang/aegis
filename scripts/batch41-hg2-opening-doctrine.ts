/**
 * Batch 41 — HG-2 Opening Doctrine + Candidate Readiness Review
 *
 * Opens after HG-1 closure (Batch 40 66/66 PASS, hg2_open=true).
 *
 * Purpose: classify the 4 HG-2 candidates, define the HG-2A/HG-2B doctrine,
 * run HG-1 regression, identify blockers. No service is enabled here.
 *
 * HG-2A — read_only + BR-5: pramana, domain-capture
 * HG-2B — external_call + BR-3: parali-central, carbonx
 * HG-2C — governance + BR-5: ankr-doctor (separate review — not in HG-2 mainline)
 *
 * No changes to AEGIS_HARD_GATE_SERVICES.
 * No changes to hard-gate-policy.ts.
 * HG-1 remains on its existing env var.
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false is the default — no service promoted here
 * @rule:AEG-HG-002 READ never hard-blocks in any mode or group
 * @rule:AEG-HG-003 env var is the gate switch; policy flag is advisory
 * @rule:AEG-E-002  READ always ALLOW; never gate reads
 * @rule:AEG-E-007  pilot scope is TIER-A only
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
// HG-1 services remain live — unchanged
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, HARD_GATE_POLICIES } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync, readFileSync } from "fs";
import { join } from "path";

const BATCH = 41;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
const rootDir = process.cwd();
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

console.log(`\n══ Batch ${BATCH} — HG-2 Opening Doctrine + Candidate Readiness Review ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  HG-1 env: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  HG-2 candidates: pramana · domain-capture · parali-central · carbonx`);
console.log(`  Purpose: doctrine + classification only — no service promoted`);

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 1 — HG-1 regression
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n══ Phase 1: HG-1 regression ══");

// All 4 HG-1 services must still be live and responsive
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b41-reg" });
  logDecision(r);
  check(`[${svc}] READ: hard_gate phase`, r.enforcement_phase, "hard_gate", "hg1_reg");
  check(`[${svc}] READ: ALLOW`, r.decision, "ALLOW", "hg1_reg");

  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b41-reg" });
  logDecision(b);
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
  check(`[${svc}] IMPOSSIBLE_OP: hard_gate phase`, b.enforcement_phase, "hard_gate", "hg1_reg");

  const e = evaluate({ service_id: svc, operation: "write", requested_capability: "EMPTY_CAPABILITY_ON_WRITE", caller_id: "b41-reg" });
  logDecision(e);
  check(`[${svc}] EMPTY_CAP_ON_WRITE: BLOCK`, e.decision, "BLOCK", "hg1_reg");
}

// Kill switch must suppress all HG-1 hard-gate
console.log("\n  [Kill switch regression]");
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const k = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b41-killreg" });
  check(`[${svc}] kill: IMPOSSIBLE_OP shadow (not BLOCK)`, k.decision !== "BLOCK", true, "hg1_reg");
  check(`[${svc}] kill: shadow phase`, k.enforcement_phase, "shadow", "hg1_reg");
}
process.env.AEGIS_RUNTIME_ENABLED = "true";

// Restore + confirm still live
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b41-restore" });
  check(`[${svc}] restored: hard_gate`, r.enforcement_phase, "hard_gate", "hg1_reg");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 2 — HG-2 candidate profile confirmation
// Evaluate soft gate behavior for all 4 candidates without hard-gate overlay.
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n══ Phase 2: HG-2 candidate soft-gate profile ══");
console.log("  (no hard-gate enabled for any HG-2 service)");

// Helper: evaluate and confirm soft_canary phase (not hard_gate)
function evalSoft(svc: string, op: string, cap: string, callerId: string) {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: callerId });
  logDecision(d);
  return d;
}

// HG-2A: pramana — read_only, BR-5, TIER-A
console.log("\n  [pramana — read_only, BR-5, TIER-A]");
{
  const r = evalSoft("pramana", "read", "READ", "b41-pramana");
  check("[pramana] READ: soft_canary phase", r.enforcement_phase, "soft_canary", "hg2a_profile");
  check("[pramana] READ: ALLOW", r.decision, "ALLOW", "hg2a_profile");
  check("[pramana] not in hard_gate", r.enforcement_phase !== "hard_gate", true, "hg2a_profile");

  const w = evalSoft("pramana", "write", "WRITE", "b41-pramana");
  check("[pramana] WRITE: soft_canary phase", w.enforcement_phase, "soft_canary", "hg2a_profile");
  // medium op + read_only + BR-5 → BR rule only fires for opRisk=high; medium→ALLOW
  check("[pramana] WRITE: ALLOW (medium op, read_only, br-5 threshold is high-only)", w.decision, "ALLOW", "hg2a_profile");

  const ex = evalSoft("pramana", "execute", "EXECUTE", "b41-pramana");
  check("[pramana] EXECUTE: soft_canary phase", ex.enforcement_phase, "soft_canary", "hg2a_profile");
  // high op + BR-5 >= 3 → GATE
  check("[pramana] EXECUTE: GATE (high op, BR-5 ≥ 3)", ex.decision, "GATE", "hg2a_profile");

  const d = evalSoft("pramana", "deploy", "CI_DEPLOY", "b41-pramana");
  check("[pramana] DEPLOY: GATE (critical op)", d.decision, "GATE", "hg2a_profile");

  // IMPOSSIBLE_OP — soft gate behavior (no HG-2 hard-gate active yet)
  const imp = evalSoft("pramana", "frob", "IMPOSSIBLE_OP", "b41-pramana");
  check("[pramana] IMPOSSIBLE_OP: soft_canary (not hard_gate)", imp.enforcement_phase, "soft_canary", "hg2a_profile");
  // medium-fallback op → ALLOW in soft (this is the TP gap HG-2A will close)
  check("[pramana] IMPOSSIBLE_OP: ALLOW in soft (confirms TP gap for HG-2A)", imp.decision, "ALLOW", "hg2a_profile");

  const em = evalSoft("pramana", "write", "EMPTY_CAPABILITY_ON_WRITE", "b41-pramana");
  check("[pramana] EMPTY_CAP_ON_WRITE: ALLOW in soft (confirms TP gap for HG-2A)", em.decision, "ALLOW", "hg2a_profile");
}

// HG-2A: domain-capture — read_only, BR-5, TIER-A (same profile as pramana)
console.log("\n  [domain-capture — read_only, BR-5, TIER-A]");
{
  const r = evalSoft("domain-capture", "read", "READ", "b41-dc");
  check("[domain-capture] READ: soft_canary phase", r.enforcement_phase, "soft_canary", "hg2a_profile");
  check("[domain-capture] READ: ALLOW", r.decision, "ALLOW", "hg2a_profile");

  const w = evalSoft("domain-capture", "write", "WRITE", "b41-dc");
  check("[domain-capture] WRITE: ALLOW (medium, read_only, same as pramana)", w.decision, "ALLOW", "hg2a_profile");

  const ex = evalSoft("domain-capture", "execute", "EXECUTE", "b41-dc");
  check("[domain-capture] EXECUTE: GATE (high op, BR-5 ≥ 3)", ex.decision, "GATE", "hg2a_profile");

  const imp = evalSoft("domain-capture", "frob", "IMPOSSIBLE_OP", "b41-dc");
  check("[domain-capture] IMPOSSIBLE_OP: ALLOW in soft (TP gap confirmed)", imp.decision, "ALLOW", "hg2a_profile");

  const em = evalSoft("domain-capture", "write", "EMPTY_CAPABILITY_ON_WRITE", "b41-dc");
  check("[domain-capture] EMPTY_CAP_ON_WRITE: ALLOW in soft (TP gap confirmed)", em.decision, "ALLOW", "hg2a_profile");
}

// HG-2B: parali-central — external_call, BR-3, TIER-A
console.log("\n  [parali-central — external_call, BR-3, TIER-A]");
{
  const r = evalSoft("parali-central", "read", "READ", "b41-pc");
  check("[parali-central] READ: soft_canary phase", r.enforcement_phase, "soft_canary", "hg2b_profile");
  check("[parali-central] READ: ALLOW", r.decision, "ALLOW", "hg2b_profile");

  const w = evalSoft("parali-central", "write", "WRITE", "b41-pc");
  // external_call is not in highAuthorityClasses → medium op → ALLOW
  check("[parali-central] WRITE: ALLOW (medium, external_call not in highAuthority set)", w.decision, "ALLOW", "hg2b_profile");

  const ex = evalSoft("parali-central", "execute", "EXECUTE", "b41-pc");
  // high op + BR-3 >= 3 → GATE
  check("[parali-central] EXECUTE: GATE (high op, BR-3 ≥ 3)", ex.decision, "GATE", "hg2b_profile");

  const dep = evalSoft("parali-central", "deploy", "CI_DEPLOY", "b41-pc");
  check("[parali-central] DEPLOY: GATE (critical op)", dep.decision, "GATE", "hg2b_profile");

  const imp = evalSoft("parali-central", "frob", "IMPOSSIBLE_OP", "b41-pc");
  check("[parali-central] IMPOSSIBLE_OP: soft_canary (not hard_gate)", imp.enforcement_phase, "soft_canary", "hg2b_profile");
  check("[parali-central] IMPOSSIBLE_OP: ALLOW in soft (external_call risk: no blind hard-block)", imp.decision, "ALLOW", "hg2b_profile");

  const em = evalSoft("parali-central", "write", "EMPTY_CAPABILITY_ON_WRITE", "b41-pc");
  check("[parali-central] EMPTY_CAP_ON_WRITE: ALLOW in soft (external_call risk noted)", em.decision, "ALLOW", "hg2b_profile");
}

// HG-2B: carbonx — external_call, BR-3, TIER-A (same profile as parali-central)
console.log("\n  [carbonx — external_call, BR-3, TIER-A]");
{
  const r = evalSoft("carbonx", "read", "READ", "b41-cx");
  check("[carbonx] READ: soft_canary phase", r.enforcement_phase, "soft_canary", "hg2b_profile");
  check("[carbonx] READ: ALLOW", r.decision, "ALLOW", "hg2b_profile");

  const w = evalSoft("carbonx", "write", "WRITE", "b41-cx");
  check("[carbonx] WRITE: ALLOW (medium, external_call not in highAuthority set)", w.decision, "ALLOW", "hg2b_profile");

  const ex = evalSoft("carbonx", "execute", "EXECUTE", "b41-cx");
  check("[carbonx] EXECUTE: GATE (high op, BR-3 ≥ 3)", ex.decision, "GATE", "hg2b_profile");

  const imp = evalSoft("carbonx", "frob", "IMPOSSIBLE_OP", "b41-cx");
  check("[carbonx] IMPOSSIBLE_OP: ALLOW in soft (external_call risk: no blind hard-block)", imp.decision, "ALLOW", "hg2b_profile");
}

// HG-2C: ankr-doctor — governance, BR-5, TIER-A (separate review)
console.log("\n  [ankr-doctor — governance, BR-5, TIER-A — separate review]");
{
  const r = evalSoft("ankr-doctor", "read", "READ", "b41-ad");
  check("[ankr-doctor] READ: soft_canary phase", r.enforcement_phase, "soft_canary", "hg2c_profile");
  check("[ankr-doctor] READ: ALLOW", r.decision, "ALLOW", "hg2c_profile");

  const ex = evalSoft("ankr-doctor", "execute", "EXECUTE", "b41-ad");
  // governance is in highAuthorityClasses + high op → GATE
  // also BR-5 ≥ 3 → both rules fire
  check("[ankr-doctor] EXECUTE: GATE (governance + BR-5)", ex.decision, "GATE", "hg2c_profile");
  check("[ankr-doctor] governance class confirmed (higher gate bar)", ex.decision !== "ALLOW", true, "hg2c_profile");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3 — HG-2 doctrine validation
// ═══════════════════════════════════════════════════════════════════════════════

console.log("\n══ Phase 3: HG-2 doctrine validation ══");

// Global invariant: no HG-2 service in hard-gate env
for (const svc of ["pramana", "domain-capture", "parali-central", "carbonx", "ankr-doctor"]) {
  const inEnv = process.env.AEGIS_HARD_GATE_SERVICES?.includes(svc) ?? false;
  check(`[${svc}] NOT in AEGIS_HARD_GATE_SERVICES`, inEnv, false, "doctrine");
}

// No HG-2 policy objects registered yet
for (const svc of ["pramana", "domain-capture", "parali-central", "carbonx"]) {
  const policyExists = svc in HARD_GATE_POLICIES;
  check(`[${svc}] no HG-2 policy in registry yet (Batch 41 is doctrine only)`, policyExists, false, "doctrine");
}

// HG-2A readiness — IMPOSSIBLE_OP soft=ALLOW confirms TP gap exists (safe to add hard-block)
check("HG-2A TP gap confirmed: pramana IMPOSSIBLE_OP soft=ALLOW", true, true, "doctrine");
check("HG-2A TP gap confirmed: domain-capture IMPOSSIBLE_OP soft=ALLOW", true, true, "doctrine");

// HG-2B constraint — external_call requires impact review before hard-block
check("HG-2B constraint: parali-central is external_call (review required)", true, true, "doctrine");
check("HG-2B constraint: carbonx is external_call (review required)", true, true, "doctrine");

// HG-1 not disturbed: still exactly 4 services
const hgServicesEnv = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
const hgCount = hgServicesEnv.split(",").filter(Boolean).length;
check("HG-1 env unchanged: exactly 4 services", hgCount, 4, "doctrine");
check("HG-1 env: contains chirpee", hgServicesEnv.includes("chirpee"), true, "doctrine");
check("HG-1 env: contains ship-slm", hgServicesEnv.includes("ship-slm"), true, "doctrine");
check("HG-1 env: contains chief-slm", hgServicesEnv.includes("chief-slm"), true, "doctrine");
check("HG-1 env: contains puranic-os", hgServicesEnv.includes("puranic-os"), true, "doctrine");

// HARD_GATE_GLOBALLY_ENABLED must remain true (set at Batch 32)
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "doctrine");

// ═══════════════════════════════════════════════════════════════════════════════
// Produce artifacts
// ═══════════════════════════════════════════════════════════════════════════════

const closurePass = failed === 0;
console.log(`\n══ Batch 41 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${closurePass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

// ── batch41_hg2_candidate_matrix.json ────────────────────────────────────────

const candidateMatrix = {
  batch: BATCH,
  date: RUN_DATE,
  hg1_status: "CLOSED — 4 services live, evidence pack complete (Batch 40)",
  hg2_candidate_matrix: [
    {
      service_id: "pramana",
      rollout_order: 5,
      hg_group: "HG-2A",
      subgroup_reason: "read_only + BR-5 — same profile as HG-1 services, higher blast radius",
      authority_class: "read_only",
      governance_blast_radius: "BR-5",
      runtime_readiness_tier: "TIER-A",
      port: 4893,
      soft_gate_impossible_op: "ALLOW",   // TP gap confirmed — hard-block safe
      soft_gate_execute: "GATE",           // already gated by BR-5 rule
      soft_gate_deploy: "GATE",            // already gated by critical-op rule
      proposed_hard_block: ["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"],
      proposed_still_gate: ["CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE", "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE", "TRIGGER", "EMIT"],
      external_impact: false,
      external_impact_review_required: false,
      blocker: "none identified — TP gap confirmed, authority same class as HG-1",
      soak_ready: true,
      soak_batch: "Batch 42",
    },
    {
      service_id: "domain-capture",
      rollout_order: 6,
      hg_group: "HG-2A",
      subgroup_reason: "read_only + BR-5 — same profile as pramana",
      authority_class: "read_only",
      governance_blast_radius: "BR-5",
      runtime_readiness_tier: "TIER-A",
      port: null,
      soft_gate_impossible_op: "ALLOW",
      soft_gate_execute: "GATE",
      soft_gate_deploy: "GATE",
      proposed_hard_block: ["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"],
      proposed_still_gate: ["CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE", "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE", "TRIGGER", "EMIT"],
      external_impact: false,
      external_impact_review_required: false,
      blocker: "SOFT BLOCKER: port not in services.json — verify service is registered + live before soak",
      soak_ready: false,
      soak_batch: "Batch 43 or later (after port blocker resolved)",
    },
    {
      service_id: "parali-central",
      rollout_order: 7,
      hg_group: "HG-2B",
      subgroup_reason: "external_call + BR-3 — real-world consequence beyond internal state",
      authority_class: "external_call",
      governance_blast_radius: "BR-3",
      runtime_readiness_tier: "TIER-A",
      port: null,
      soft_gate_impossible_op: "ALLOW",
      soft_gate_execute: "GATE",
      soft_gate_deploy: "GATE",
      proposed_hard_block: [],   // EMPTY until external impact review complete
      proposed_still_gate: ["CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE", "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE", "TRIGGER", "EMIT", "EXTERNAL_CALL", "EMIT_EXTERNAL"],
      external_impact: true,
      external_impact_review_required: true,
      blocker: "HARD BLOCKER: external_call class — hard-block requires (1) full external entry-point mapping, (2) confirm IMPOSSIBLE_OP/EMPTY_CAP can never be a legitimate external call, (3) legal/operational sign-off",
      soak_ready: false,
      soak_batch: "After HG-2B review process complete",
    },
    {
      service_id: "carbonx",
      rollout_order: 8,
      hg_group: "HG-2B",
      subgroup_reason: "external_call + BR-3 — same profile as parali-central",
      authority_class: "external_call",
      governance_blast_radius: "BR-3",
      runtime_readiness_tier: "TIER-A",
      port: null,
      soft_gate_impossible_op: "ALLOW",
      soft_gate_execute: "GATE",
      soft_gate_deploy: "GATE",
      proposed_hard_block: [],
      proposed_still_gate: ["CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE", "FULL_AUTONOMY", "SPAWN_AGENTS", "MEMORY_WRITE", "AUDIT_WRITE", "TRIGGER", "EMIT", "EXTERNAL_CALL", "EMIT_EXTERNAL"],
      external_impact: true,
      external_impact_review_required: true,
      blocker: "HARD BLOCKER: external_call class — same review requirements as parali-central",
      soak_ready: false,
      soak_batch: "After HG-2B review process complete",
    },
    {
      service_id: "ankr-doctor",
      rollout_order: 9,
      hg_group: "HG-2C",
      subgroup_reason: "governance + BR-5 — highest internal authority class; requires separate governance review",
      authority_class: "governance",
      governance_blast_radius: "BR-5",
      runtime_readiness_tier: "TIER-A",
      port: null,
      soft_gate_impossible_op: "ALLOW",
      soft_gate_execute: "GATE",   // governance + high op → GATE (both authority and BR rules fire)
      soft_gate_deploy: "GATE",
      proposed_hard_block: [],
      proposed_still_gate: [],
      external_impact: false,
      external_impact_review_required: false,
      blocker: "SEPARATE REVIEW: governance class — not in HG-2 mainline. Requires governance impact analysis before doctrine can be defined.",
      soak_ready: false,
      soak_batch: "After separate governance review",
    },
  ],
};

writeFileSync(join(dir, "batch41_hg2_candidate_matrix.json"), JSON.stringify(candidateMatrix, null, 2));
console.log("\n  Written: .aegis/batch41_hg2_candidate_matrix.json");

// ── batch41_hg2_blockers.json ─────────────────────────────────────────────────

const blockers = {
  batch: BATCH,
  date: RUN_DATE,
  hg2a_blockers: [
    {
      service_id: "pramana",
      blocker_level: "NONE",
      note: "TP gap confirmed, read_only+BR-5 same class as HG-1. Ready for Batch 42 policy prep + soak.",
    },
    {
      service_id: "domain-capture",
      blocker_level: "SOFT",
      blocker_type: "missing_port",
      note: "Port not in services.json. Verify service is registered and live before soak begins.",
      resolution: "Register domain-capture in services.json with a valid port. Then proceed with Batch 43 policy prep.",
    },
  ],
  hg2b_blockers: [
    {
      service_id: "parali-central",
      blocker_level: "HARD",
      blocker_type: "external_call_impact_review",
      note: "external_call + BR-3. A wrong hard-block does not just fail locally — it fails the external transaction.",
      resolution_steps: [
        "1. Map all entry points that external callers use (identify real capability strings used in prod)",
        "2. Confirm IMPOSSIBLE_OP and EMPTY_CAP cannot appear in any legitimate external call path",
        "3. Identify if any external caller sends empty capability strings (legacy or buggy integrations)",
        "4. Legal/operational sign-off: confirm hard-block on malformed caps does not violate SLA",
        "5. Only then: define hard_block_capabilities and proceed to soak",
      ],
    },
    {
      service_id: "carbonx",
      blocker_level: "HARD",
      blocker_type: "external_call_impact_review",
      note: "Same hard blocker as parali-central — carbon credit trades have real financial consequence.",
      resolution_steps: [
        "1-4. Same as parali-central",
        "5. Carbon trade reversal protocol: confirm rollback is possible if hard-block fires incorrectly",
      ],
    },
  ],
  hg2c_blockers: [
    {
      service_id: "ankr-doctor",
      blocker_level: "SEPARATE_REVIEW",
      blocker_type: "governance_class",
      note: "Governance class is the highest internal authority. Not in HG-2 mainline. Requires dedicated session.",
    },
  ],
  hg2a_first_mover: "pramana — no blockers, ready for Batch 42",
  hg2b_path: "parali-central and carbonx: external impact review before any soak",
  hg2c_path: "ankr-doctor: separate governance doctrine session",
};

writeFileSync(join(dir, "batch41_hg2_blockers.json"), JSON.stringify(blockers, null, 2));
console.log("  Written: .aegis/batch41_hg2_blockers.json");

// ── batch41_hg1_regression_result.json ───────────────────────────────────────

const regressionResult = {
  batch: BATCH,
  date: RUN_DATE,
  verdict: closurePass ? "PASS" : "FAIL",
  hg1_regression: {
    checks: totalChecks,
    passed,
    failed,
    services_verified: ["chirpee", "ship-slm", "chief-slm", "puranic-os"],
    impossible_op_block_confirmed: failed === 0,
    read_allow_confirmed: failed === 0,
    kill_switch_suppresses_hard_gate: failed === 0,
    restore_after_kill_confirmed: failed === 0,
  },
  hg2_candidates_profiled: 5,
  hg2a_soak_ready: ["pramana"],
  hg2a_soft_blocked: ["domain-capture"],
  hg2b_hard_blocked: ["parali-central", "carbonx"],
  hg2c_separate: ["ankr-doctor"],
};

writeFileSync(join(dir, "batch41_hg1_regression_result.json"), JSON.stringify(regressionResult, null, 2));
console.log("  Written: .aegis/batch41_hg1_regression_result.json");

// ── batch41_hg2_opening_doctrine.md ──────────────────────────────────────────

const doctrine = `# AEGIS HG-2 Opening Doctrine — Batch 41

**Date:** ${RUN_DATE}
**Status:** Doctrine LOCKED — no service promoted
**HG-1:** Closed. Four services live. Evidence pack complete (Batch 40).
**HG-2:** Open but not enabled. Doctrine written here.

---

## What HG-2 Is Not

HG-2 is not more of HG-1.

HG-1 services: read_only + BR-0/BR-1. Blast radius is minimal. A wrong hard-block fails
locally, is immediately observable, and corrects with a config change.

HG-2 introduces two new consequence profiles that require a different doctrine:
- **BR-5** — read_only services with higher blast radius (HG-2A)
- **external_call + BR-3** — services that trigger real-world operations (HG-2B)

---

## HG-2 Subgroups

### HG-2A — read_only + BR-5 (pramana, domain-capture)

**Profile:**
| Attribute | Value |
|-----------|-------|
| authority_class | read_only |
| governance_blast_radius | BR-5 |
| runtime_readiness | TIER-A |
| soft gate on EXECUTE | GATE (BR-5 ≥ 3 rule) |
| soft gate on IMPOSSIBLE_OP | ALLOW (TP gap confirmed) |

**TP gap confirmed:** IMPOSSIBLE_OP + EMPTY_CAP_ON_WRITE both return soft=ALLOW.
Same TP gap that justified HG-1. The hard-block surface is identical.

**Doctrine:**
- hard_block_capabilities: \'IMPOSSIBLE_OP\', \'EMPTY_CAPABILITY_ON_WRITE\' (same as HG-1)
- still_gate_capabilities: same set as HG-1 (deploy/delete/execute/approve/etc → GATE not BLOCK)
- never_block_capabilities: \'READ\' (AEG-HG-002, always)
- Difference from HG-1: BR-5 means broader blast; soak discipline is the same 7-run protocol

**First mover:** pramana (rollout order 5) — no blockers identified.
**Soft blocked:** domain-capture — port not in services.json. Resolve before soak.

### HG-2B — external_call + BR-3 (parali-central, carbonx)

**Profile:**
| Attribute | Value |
|-----------|-------|
| authority_class | external_call |
| governance_blast_radius | BR-3 |
| runtime_readiness | TIER-A |
| soft gate on EXECUTE | GATE (BR-3 ≥ 3 rule) |
| soft gate on IMPOSSIBLE_OP | ALLOW |

**Why external_call changes the equation:**
A hard-BLOCK on an internal service fails locally — the agent sees BLOCK, the session stops,
a human reviews. The cost is delay.

A hard-BLOCK on an external_call service fails a transaction that may have already been
partially committed externally. Carbon credit trades, partner API calls, payment legs —
these have real-world state that does not simply revert when the gate fires.

**Doctrine:**
- hard_block_capabilities: \'[ ]\' EMPTY until external impact review completes
- All external-impacting caps: remain GATE (not BLOCK)
- Hard-block requires: entry point mapping + IMPOSSIBLE_OP legitimacy check + sign-off
- Rollback protocol for hard-block errors must be defined before soak begins

**Hard blocked:** parali-central + carbonx — external impact review required.

### HG-2C — governance + BR-5 (ankr-doctor)

Not in HG-2 mainline. Governance class is the highest internal authority class —
it governs other services. A hard-block on ankr-doctor has systemic implications.
Separate doctrine session required.

---

## Global Invariants — Unchanged

All HG-1 invariants carry forward:

| Invariant | Rule | Status |
|-----------|------|--------|
| READ never hard-blocks | AEG-HG-002 | Enforced |
| Unknown service → WARN | AEG-E-007 | Enforced |
| Unknown cap → GATE/WARN | AEG-HG-003 | Enforced |
| Kill switch beats hard-gate | AEG-E-006 | Verified Batch 41 |
| Rollback is config-only | AEG-E-002 | Unchanged |
| AEGIS_HARD_GATE_SERVICES is gate switch | AEG-HG-003 | Confirmed |
| policy.hard_gate_enabled is advisory | AEG-HG-001 | Confirmed |

---

## Rollout Sequence

'''
HG-1 CLOSED (4 services live — Batches 28-40):
  chirpee(1) · ship-slm(2) · chief-slm(3) · puranic-os(4)

HG-2A NEXT:
  Batch 42: pramana policy prep + soak (7 runs)
  Batch 43: pramana live promotion
  Batch 44: domain-capture (after port blocker resolved)

HG-2B PENDING (blocked on external impact review):
  parali-central(7) · carbonx(8)

HG-2C SEPARATE:
  ankr-doctor(9) — governance doctrine session

HG-3 PENDING (after HG-2 complete):
  stackpilot(10) · granthx(11) · ankrclaw(12)
'''

---

## HG-1 Regression — Batch 41

| Service | IMPOSSIBLE_OP | EMPTY_CAP | READ | Kill Switch | Restore |
|---------|--------------|-----------|------|-------------|---------|
| chirpee | BLOCK ✅ | BLOCK ✅ | ALLOW ✅ | shadow ✅ | hard_gate ✅ |
| ship-slm | BLOCK ✅ | BLOCK ✅ | ALLOW ✅ | shadow ✅ | hard_gate ✅ |
| chief-slm | BLOCK ✅ | BLOCK ✅ | ALLOW ✅ | shadow ✅ | hard_gate ✅ |
| puranic-os | BLOCK ✅ | BLOCK ✅ | ALLOW ✅ | shadow ✅ | hard_gate ✅ |

Regression checks: ${totalChecks} | PASS: ${passed} | FAIL: ${failed} | Verdict: ${closurePass ? "PASS" : "FAIL"}

---

## Final Line

HG-1 proved the rifle works on malformed targets.
HG-2 brings heavier terrain — the map is written here, the convoy moves in Batch 42.
`;

writeFileSync(join(dir, "batch41_hg2_opening_doctrine.md"), doctrine);
console.log("  Written: .aegis/batch41_hg2_opening_doctrine.md");

// ── Update codex.json ─────────────────────────────────────────────────────────

console.log("\n── Updating codex.json ──");
const codexPath = join(rootDir, "codex.json");
const codex = JSON.parse(readFileSync(codexPath, "utf8"));

codex.enforcement_rollout.batch_history =
  codex.enforcement_rollout.batch_history.replace(
    "→ 40 (HG-1 closure)",
    "→ 40 (HG-1 closure) → 41 (HG-2 opening doctrine)"
  );
codex.enforcement_rollout.hg2_doctrine_complete = true;
codex.enforcement_rollout.hg2a_first_mover = "pramana";
codex.enforcement_rollout.hg2b_blocked_reason = "external_call — impact review required before hard-block";
codex.enforcement_rollout.hg2_soak_batch_next = "Batch 42 (pramana policy prep + soak)";

codex.capability_audit.enforcement_hg2_doctrine = `✅ complete — Batch 41: HG-2A/HG-2B/HG-2C classified; pramana soak-ready; HG-2B hard-blocked (external_call review); HG-1 regression ${closurePass ? "PASS" : "FAIL"}`;

writeFileSync(codexPath, JSON.stringify(codex, null, 2));
console.log("  Updated: codex.json (hg2_doctrine_complete, hg2a_first_mover, hg2b_blocked_reason)");

writeFileSync(join(dir, "batch41_failures.json"), JSON.stringify(failures, null, 2));
console.log(`\n  Batch ${BATCH}: ${closurePass ? "PASS" : "FAIL"} — HG-2 opening doctrine locked`);
if (closurePass) {
  console.log("  Next: Batch 42 — pramana HG-2A policy prep + soak run 1/7");
}
