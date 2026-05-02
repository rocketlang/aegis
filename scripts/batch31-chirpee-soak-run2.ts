/**
 * Batch 31 — Chirpee HG-1 Soak Observation (Run 2 of 7)
 *
 * Hard gate: still disabled. gate.ts: unchanged.
 * HARD_GATE_GLOBALLY_ENABLED = false (TypeScript constant — not a flag).
 *
 * Traffic variation from Run 1:
 *   Wave 1 READ:    8 sessions × 6 ops = 48 decisions (was 30)
 *   Mixed-case:     capabilities tested in mixed case (READ / Read / read / rEaD)
 *   Wave 2 WRITE:   8 sessions × 4 ops = 32 decisions (was 20)
 *   Wave 3 AI_EXE:  5 sessions AI_EXECUTE (was 3) — more critical-op coverage
 *   Wave 4 CRITICAL: unchanged
 *   Wave 5 MALFORM: unchanged — same true positive targets
 *   Waves 6-8:      unchanged structure, new sessions
 *
 * Soak PASS requires (same as run 1):
 *   false_positive_count  = 0
 *   true_positive_count   > 0  (IMPOSSIBLE_OP / EMPTY_CAP_ON_WRITE → BLOCK)
 *   invariant_violations  = 0
 *   production_gate_fires = 0
 *
 * Promote decision is HUMAN-GATED regardless of soak verdict.
 * ready_to_promote_chirpee remains false until 7/7 clean runs + human decision.
 */

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import {
  issueApprovalToken,
  approveToken,
  denyToken,
  revokeToken,
  getApproval,
  runRollbackDrill,
} from "../src/enforcement/approval";
import {
  HARD_GATE_GLOBALLY_ENABLED,
  HARD_GATE_SERVICES_ENABLED,
  CHIRPEE_HG1_POLICY,
  simulateHardGate,
} from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// ── Environment ───────────────────────────────────────────────────────────────

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED  = "true";
process.env.AEGIS_DRY_RUN          = "false";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

const SOAK_RUN = 2; // of 7 required before promote decision
const SOAK_DATE = new Date().toISOString();

// ── Test harness ──────────────────────────────────────────────────────────────

let totalChecks = 0;
let passed = 0;
let failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const pass = String(actual) === String(expected);
  if (pass) {
    passed++;
    console.log(`  ✓ [PASS] ${label.padEnd(72)} actual=${actual}`);
  } else {
    failed++;
    failures.push({ label, expected: String(expected), actual: String(actual), cat });
    console.log(`  ✗ [FAIL] ${label.padEnd(72)} expected=${expected} actual=${actual}`);
  }
}

function okStatus(r: { ok: boolean }): "accepted" | "rejected" {
  return r.ok ? "accepted" : "rejected";
}

function gate(op: string, cap: string, caller = "b31r2", session?: string) {
  const d = evaluate({
    service_id: "chirpee", operation: op, requested_capability: cap,
    caller_id: caller, session_id: session ?? `b31r2-chirpee-${op}-${cap}-${Date.now()}`,
  });
  logDecision(d);
  return d;
}

// ── Soak metrics ──────────────────────────────────────────────────────────────

const soakMetrics = {
  soft_decisions:        { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 },
  sim_production:        { fires: 0, no_fires: 0 },
  sim_dryrun:            { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 },
  false_positives:       0,
  true_positives:        0,
  invariant_violations:  0,
  production_gate_fires: 0,
  waves: {} as Record<string, { decisions: number; false_positives: number; true_positives: number }>,
};

const MALFORMED_CAPS = new Set(["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"]);

function observe(
  label: string,
  op: string,
  cap: string,
  expectedSoftDecision: string,
  expectedSimDecision: string,
  cat: string,
) {
  const d = gate(op, cap, "b31r2-soak");
  soakMetrics.soft_decisions[d.decision as keyof typeof soakMetrics.soft_decisions]++;

  check(`soft: ${label}`, d.decision, expectedSoftDecision, cat);

  const simProd = simulateHardGate("chirpee", d.decision, cap, op, false);
  if (simProd.hard_gate_would_apply) {
    soakMetrics.production_gate_fires++;
  } else {
    soakMetrics.sim_production.no_fires++;
  }
  check(`sim(off): ${label} — hard gate does not fire`, simProd.hard_gate_would_apply, false, cat);
  check(`sim(off): ${label} — soft decision preserved`, simProd.simulated_hard_decision, d.decision, cat);

  const simDry = simulateHardGate("chirpee", d.decision, cap, op, true);
  soakMetrics.sim_dryrun[simDry.simulated_hard_decision as keyof typeof soakMetrics.sim_dryrun]++;
  check(`sim(on): ${label}`, simDry.simulated_hard_decision, expectedSimDecision, cat);

  const isMalformed = MALFORMED_CAPS.has(cap.toUpperCase());
  if (simDry.simulated_hard_decision === "BLOCK" && !isMalformed) {
    soakMetrics.false_positives++;
    soakMetrics.invariant_violations++;
  } else if (simDry.simulated_hard_decision === "BLOCK" && isMalformed) {
    soakMetrics.true_positives++;
  }

  if (!soakMetrics.waves[cat]) {
    soakMetrics.waves[cat] = { decisions: 0, false_positives: 0, true_positives: 0 };
  }
  soakMetrics.waves[cat].decisions++;
  if (simDry.simulated_hard_decision === "BLOCK" && !isMalformed) soakMetrics.waves[cat].false_positives++;
  if (simDry.simulated_hard_decision === "BLOCK" && isMalformed) soakMetrics.waves[cat].true_positives++;

  return { soft: d, simDry, simProd };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pre-check — config unchanged since Batch 30
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Pre-check — config unchanged since Batch 30 ──");
check("HARD_GATE_GLOBALLY_ENABLED = false", HARD_GATE_GLOBALLY_ENABLED, false, "pre");
check("HARD_GATE_SERVICES_ENABLED empty", HARD_GATE_SERVICES_ENABLED.size, 0, "pre");
check("chirpee: hard_gate_enabled = false", CHIRPEE_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chirpee: hg_group = HG-1", CHIRPEE_HG1_POLICY.hg_group, "HG-1", "pre");
check("chirpee: READ in never_block", CHIRPEE_HG1_POLICY.never_block_capabilities.has("READ"), true, "pre");
check("chirpee: IMPOSSIBLE_OP in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "pre");
check("chirpee: EMPTY_CAPABILITY_ON_WRITE in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "pre");
check("chirpee: AI_EXECUTE in still_gate", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("AI_EXECUTE"), true, "pre");
check("chirpee: CI_DEPLOY in still_gate", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("CI_DEPLOY"), true, "pre");

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 1 — READ traffic (8 sessions × 6 ops = 48 decisions)
//   Increased volume from run 1 (was 5 sessions = 30 decisions)
//   READ/op=read/get/list/query/search/health → soft=ALLOW, sim=ALLOW always
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 1: READ traffic — 8 sessions (run 1 was 5) ──");
const readOps = ["read", "get", "list", "query", "search", "health"];
for (let session = 1; session <= 8; session++) {
  for (const op of readOps) {
    observe(`chirpee/${op}[${session}]`, op, "READ", "ALLOW", "ALLOW", "wave1_read");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 1b — Mixed-case capability stress
//   AEG-HG-002 must hold regardless of case: "Read", "READ", "read", "rEaD"
//   simulateHardGate normalises to .toUpperCase() — invariant must still fire
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 1b: Mixed-case capability stress (READ invariant) ──");
const mixedCaseCaps = ["Read", "READ", "read", "rEaD", "GET", "Get", "get", "LIST", "List"];
for (const cap of mixedCaseCaps) {
  const d = evaluate({
    service_id: "chirpee", operation: "read", requested_capability: cap,
    caller_id: "b31r2-mixcase", session_id: `b31r2-mixcase-${cap}-${Date.now()}`,
  });
  logDecision(d);
  const simDry = simulateHardGate("chirpee", d.decision, cap, "read", true);
  check(`mixed-case: '${cap}' → soft ALLOW`, d.decision, "ALLOW", "wave1b_mixcase");
  check(`mixed-case: '${cap}' → sim ALLOW`, simDry.simulated_hard_decision, "ALLOW", "wave1b_mixcase");
  check(`mixed-case: '${cap}' → invariant AEG-HG-002`, simDry.invariant_applied, "AEG-HG-002", "wave1b_mixcase");
  soakMetrics.soft_decisions.ALLOW++;
  if (!soakMetrics.waves["wave1b_mixcase"]) soakMetrics.waves["wave1b_mixcase"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave1b_mixcase"].decisions++;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 2 — WRITE / UPDATE (8 sessions × 4 ops = 32 decisions)
//   Increased from run 1 (was 5 sessions = 20 decisions)
//   WRITE cap not in any policy list → always_allow or unknown → soft=ALLOW, sim=ALLOW
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 2: WRITE/UPDATE — 8 sessions (run 1 was 5) ──");
const writeOps = ["write", "update", "create", "patch"];
for (let session = 1; session <= 8; session++) {
  for (const op of writeOps) {
    observe(`chirpee/${op}[${session}]`, op, "WRITE", "ALLOW", "ALLOW", "wave2_write");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 3 — High-risk ops (5 sessions — run 1 was 3)
//   EXECUTE/APPROVE/TRIGGER/EMIT: soft=ALLOW, sim=GATE (still_gate)
//   AI_EXECUTE: soft=GATE (op_risk=critical), sim=GATE (still_gate)
//   AI_EXECUTE finding confirmed run 1: critical op gates even on read_only+BR-0
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 3: HIGH-RISK ops — 5 sessions (run 1 was 3) ──");
const highRiskAllowOps: [string, string][] = [
  ["execute", "EXECUTE"], ["approve", "APPROVE"], ["trigger", "EXECUTE"], ["emit", "EXECUTE"],
];
const highRiskGateOps: [string, string][] = [
  ["ai-execute", "AI_EXECUTE"],
];
for (let session = 1; session <= 5; session++) {
  for (const [op, cap] of highRiskAllowOps) {
    observe(`chirpee/${op}[${session}]`, op, cap, "ALLOW", "GATE", "wave3_highrisk");
  }
  for (const [op, cap] of highRiskGateOps) {
    // op_risk=critical → soft=GATE, still_gate_capabilities → sim=GATE
    observe(`chirpee/${op}[${session}]`, op, cap, "GATE", "GATE", "wave3_highrisk");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 4 — DEPLOY / DELETE critical (5 sessions × 2 ops = 10 decisions)
//   Soft: GATE (critical threshold)
//   Sim(on): GATE (in still_gate — never BLOCK for HG-1 on real ops)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 4: DEPLOY/DELETE critical (5 sessions) ──");
const criticalOps: [string, string][] = [["deploy", "CI_DEPLOY"], ["delete", "DELETE"]];
const deployTokens: string[] = [];

for (let session = 1; session <= 5; session++) {
  for (const [op, cap] of criticalOps) {
    const { soft } = observe(`chirpee/${op}[${session}]`, op, cap,
      "GATE", "GATE", "wave4_critical");
    if (soft.approval_token) deployTokens.push(soft.approval_token);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 5 — Malformed inputs (5 × each = 10 decisions)
//   HG-1 JUSTIFICATION (confirmed run 1):
//     Soft: ALLOW — gate sees medium-risk op on read_only+BR-0, no registry entry
//     Sim(on): BLOCK — in hard_block_capabilities, policy is explicit
//   These are the ONLY hard BLOCKs in HG-1. The gap is the closed surface.
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 5: Malformed inputs — true positive zone (same as run 1) ──");

for (let i = 1; i <= 5; i++) {
  observe(`chirpee/IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP",
    "ALLOW", "BLOCK", "wave5_malformed");
}

for (let i = 1; i <= 5; i++) {
  observe(`chirpee/EMPTY_CAPABILITY_ON_WRITE[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE",
    "ALLOW", "BLOCK", "wave5_malformed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 6 — Boundary (unknown caps, unknown service, READ invariant stress)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 6: Boundary cases ──");

// Unknown caps — not in hard_block → unknown_cap_gates_before_blocking invariant
for (const cap of ["UNKNOWN_CAP_R2", "FUTURE_FEATURE_R2", "CUSTOM_B31R2"]) {
  const d = gate("frob", cap, "b31r2-boundary");
  const simDry = simulateHardGate("chirpee", d.decision, cap, "frob", true);
  check(`boundary: ${cap} no BLOCK (soft)`, d.decision !== "BLOCK", true, "wave6_boundary");
  check(`boundary: ${cap} no BLOCK (sim)`, simDry.simulated_hard_decision !== "BLOCK", true, "wave6_boundary");
  check(`boundary: ${cap} invariant`, simDry.invariant_applied, "unknown_cap_gates_before_blocking", "wave6_boundary");
  if (!soakMetrics.waves["wave6_boundary"]) soakMetrics.waves["wave6_boundary"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave6_boundary"].decisions++;
  soakMetrics.soft_decisions[d.decision as keyof typeof soakMetrics.soft_decisions]++;
}

// Unknown service — no policy → soft decision preserved
{
  const d = evaluate({
    service_id: "svc-unknown-b31r2", operation: "deploy", requested_capability: "CI_DEPLOY",
    caller_id: "b31r2-boundary", session_id: "b31r2-boundary-unknownsvc",
  });
  logDecision(d);
  const simDry = simulateHardGate("svc-unknown-b31r2", d.decision, "CI_DEPLOY", "deploy", true);
  check("boundary: unknown_service WARN/shadow", `${d.decision}/${d.enforcement_phase}`, "WARN/shadow", "wave6_boundary");
  check("boundary: unknown_service no policy → sim preserves soft", simDry.simulated_hard_decision, d.decision, "wave6_boundary");
  check("boundary: unknown_service hard_gate_would_apply=false", simDry.hard_gate_would_apply, false, "wave6_boundary");
  soakMetrics.waves["wave6_boundary"].decisions++;
}

// READ invariant stress — garbage caps with read op must ALLOW
for (const cap of ["!@#GARBAGE_R2", "NULL_R2", "undefined_r2", ""]) {
  const d = evaluate({
    service_id: "chirpee", operation: "read", requested_capability: cap,
    caller_id: "b31r2-boundary", session_id: `b31r2-readstress-${cap}-${Date.now()}`,
  });
  logDecision(d);
  const simDry = simulateHardGate("chirpee", d.decision, cap, "read", true);
  check(`READ stress: '${cap || "(empty)"}' → ALLOW`, d.decision, "ALLOW", "wave6_boundary");
  check(`READ stress: '${cap || "(empty)"}' sim → ALLOW`, simDry.simulated_hard_decision, "ALLOW", "wave6_boundary");
  check(`READ stress: invariant AEG-HG-002`, simDry.invariant_applied, "AEG-HG-002", "wave6_boundary");
  soakMetrics.soft_decisions.ALLOW++;
  soakMetrics.waves["wave6_boundary"].decisions++;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 7 — Approval lifecycle
//   Uses tokens from wave 4 critical ops (deployTokens, 10 available)
//   approveToken(token, reason, approvedBy)
//   denyToken(token, reason, deniedBy)
//   revokeToken(token, revokedBy, reason)   ← actor before reason
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 7: Approval lifecycle (GATE decisions unchanged by simulation) ──");

if (deployTokens.length >= 4) {
  const [t1, t2, t3, t4] = deployTokens;

  // Normal approve
  const a1 = approveToken(t1, "soak run 2: deploy approved", "captain@ankr");
  check("lifecycle: deploy token approved", okStatus(a1), "accepted", "wave7_lifecycle");

  // Deny
  const dn2 = denyToken(t2, "soak run 2: outside maintenance window", "ops@ankr");
  check("lifecycle: deploy token denied", okStatus(dn2), "accepted", "wave7_lifecycle");

  // Revoke (token must still be pending — t3 not yet touched)
  const rv3 = revokeToken(t3, "security@ankr", "soak run 2: revoke test");
  check("lifecycle: deploy token revoked", okStatus(rv3), "accepted", "wave7_lifecycle");

  // Replay t1 (already approved) → rejected AEG-E-015
  const replay1 = approveToken(t1, "replay attempt soak run 2", "ops@ankr");
  check("lifecycle: replay rejected (AEG-E-015)", okStatus(replay1), "rejected", "wave7_lifecycle");

  // Blank reason → rejected AEG-E-014
  const blankR = approveToken(t4, "   ", "ops@ankr");
  check("lifecycle: blank_reason rejected (AEG-E-014)", okStatus(blankR), "rejected", "wave7_lifecycle");
  denyToken(t4, "soak run 2: cleanup deny", "b31r2-script");
}

// Fresh gate — sim must not interfere with token lifecycle
const freshGate = gate("deploy", "CI_DEPLOY", "b31r2-lifecycle-fresh");
if (freshGate.approval_token) {
  const simFresh = simulateHardGate("chirpee", freshGate.decision, "CI_DEPLOY", "deploy", true);
  check("lifecycle: sim on GATE decision → still GATE (not BLOCK)", simFresh.simulated_hard_decision, "GATE", "wave7_lifecycle");
  check("lifecycle: sim does not consume token", freshGate.approval_token !== undefined, true, "wave7_lifecycle");

  // Expire the token manually and verify rejection
  const rec = getApproval(freshGate.approval_token);
  if (rec) rec.expires_at = new Date(Date.now() - 1000).toISOString();
  const expiredApprove = approveToken(freshGate.approval_token, "late approval soak run 2", "ops@ankr");
  check("lifecycle: expired token rejected (AEG-E-013)", okStatus(expiredApprove), "rejected", "wave7_lifecycle");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 8 — Rollback drill
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 8: Rollback drill ──");

const drill = runRollbackDrill(
  evaluate,
  ["chirpee"],
  [
    { operation: "deploy",     requested_capability: "CI_DEPLOY" },
    { operation: "delete",     requested_capability: "DELETE" },
    { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
  ],
);
check("rollback_drill: PASS", drill.verdict, "PASS", "wave8_rollback");
const cs = drill.services_checked.find(s => s.service_id === "chirpee");
check("chirpee: shadow after kill", cs?.phase_after_kill, "shadow", "wave8_rollback");
check("chirpee: no tokens while killed", cs?.tokens_issued, false, "wave8_rollback");

// sim on GATE-class op during shadow — must be GATE not BLOCK
const simRollback = simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true);
check("rollback: sim result still GATE (not BLOCK)", simRollback.simulated_hard_decision, "GATE", "wave8_rollback");

// ═══════════════════════════════════════════════════════════════════════════════
// Canary status
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Canary status ──");
const canary = getCanaryStatus(["chirpee"]);
const sc = canary.success_criteria;
check("no_read_gates", sc.no_read_gates, true, "canary");
check("no_unknown_service_blocks", sc.no_unknown_service_blocks, true, "canary");
check("no_token_replay_successes", sc.no_token_replay_successes, true, "canary");
check("no_approval_without_reason", sc.no_approval_without_reason, true, "canary");
check("no_revoke_without_reason", sc.no_revoke_without_reason, true, "canary");
check("rollback_drill_passed", sc.rollback_drill_passed, true, "canary");

// ═══════════════════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════════════════

const soakPass = (
  soakMetrics.false_positives       === 0 &&
  soakMetrics.true_positives         > 0  &&
  soakMetrics.invariant_violations   === 0 &&
  soakMetrics.production_gate_fires  === 0 &&
  failed === 0
);

console.log(`
══ Soak Metrics ══
  Soak run:              ${SOAK_RUN} of 7 required
  Soft decisions:        ${Object.values(soakMetrics.soft_decisions).reduce((a, b) => a + b, 0)}
    ALLOW:               ${soakMetrics.soft_decisions.ALLOW}
    WARN:                ${soakMetrics.soft_decisions.WARN}
    GATE:                ${soakMetrics.soft_decisions.GATE}
    BLOCK:               ${soakMetrics.soft_decisions.BLOCK}
  Simulation (off):      ${soakMetrics.sim_production.no_fires} no-fires, ${soakMetrics.sim_production.fires} fires
  Simulation (dry-run):
    ALLOW:               ${soakMetrics.sim_dryrun.ALLOW}
    WARN:                ${soakMetrics.sim_dryrun.WARN}
    GATE:                ${soakMetrics.sim_dryrun.GATE}
    BLOCK:               ${soakMetrics.sim_dryrun.BLOCK}
  False positives:       ${soakMetrics.false_positives} (must be 0)
  True positives:        ${soakMetrics.true_positives} (IMPOSSIBLE_OP/EMPTY_CAP→BLOCK)
  Invariant violations:  ${soakMetrics.invariant_violations} (must be 0)
  Production gate fires: ${soakMetrics.production_gate_fires} (must be 0)
`);

console.log(`══ Soak Summary ══
  Total checks:          ${totalChecks}
  PASS:                  ${passed}
  FAIL:                  ${failed}
  Soak verdict:          ${soakPass ? "PASS" : "FAIL"}
  Hard gate enabled:     false
  ready_to_promote:      false (7 clean runs + human decision required)
`);

if (failures.length > 0) {
  console.log("  Failures:");
  for (const f of failures) {
    console.log(`    ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`);
  }
}

// ── Wave summary ──────────────────────────────────────────────────────────────
console.log("── Wave summary ──");
console.log(`  ${"Wave".padEnd(24)}${"Decisions".padEnd(12)}${"False+".padEnd(10)}${"True+"}`);
for (const [wave, m] of Object.entries(soakMetrics.waves)) {
  console.log(`  ${wave.padEnd(24)}${String(m.decisions).padEnd(12)}${String(m.false_positives).padEnd(10)}${m.true_positives}`);
}

// ── Artifacts ─────────────────────────────────────────────────────────────────
const artifactDir = join(process.cwd(), ".aegis");
mkdirSync(artifactDir, { recursive: true });

const summaryPath = join(artifactDir, "batch31_run2_chirpee_soak_summary.md");
writeFileSync(summaryPath, `# Batch 31 Chirpee Soak Run 2/7
Date: ${SOAK_DATE}
Verdict: ${soakPass ? "PASS" : "FAIL"}
Total checks: ${totalChecks} (PASS: ${passed}, FAIL: ${failed})

## Metrics
- False positives: ${soakMetrics.false_positives}
- True positives: ${soakMetrics.true_positives}
- Invariant violations: ${soakMetrics.invariant_violations}
- Production gate fires: ${soakMetrics.production_gate_fires}

## Traffic variation from run 1
- READ: 8 sessions × 6 ops = 48 decisions (was 30)
- Mixed-case caps: 9 variants tested (READ/Read/read/rEaD/GET/Get/get/LIST/List)
- WRITE: 8 sessions × 4 ops = 32 decisions (was 20)
- AI_EXECUTE: 5 sessions (was 3)
- Malformed: 10 (same targets — IMPOSSIBLE_OP × 5, EMPTY_CAPABILITY_ON_WRITE × 5)

## HG-1 justification (confirmed this run)
HG-1 does not hard-block risky real work.
HG-1 hard-blocks policy-proven impossible or malformed actions
that the soft gate intentionally does not interrupt.

  IMPOSSIBLE_OP             → soft=ALLOW, hard-sim=BLOCK (true positive)
  EMPTY_CAPABILITY_ON_WRITE → soft=ALLOW, hard-sim=BLOCK (true positive)

## Hard gate status
- HARD_GATE_GLOBALLY_ENABLED: false
- ready_to_promote_chirpee: false (${SOAK_RUN}/7 runs complete)
`);

const metricsPath = join(artifactDir, "batch31_run2_soak_metrics.json");
writeFileSync(metricsPath, JSON.stringify({ soak_run: SOAK_RUN, date: SOAK_DATE, verdict: soakPass ? "PASS" : "FAIL", ...soakMetrics, total_checks: totalChecks, passed, failed }, null, 2));

const failuresPath = join(artifactDir, "batch31_run2_failures.json");
writeFileSync(failuresPath, JSON.stringify(failures, null, 2));

console.log("\n── Artifacts ──");
console.log(`  ${summaryPath}`);
console.log(`  ${metricsPath}`);
console.log(`  ${failuresPath}`);
console.log(`\n  Soak run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"} — ${failed} check failures, ${soakMetrics.false_positives} false positives. ${soakPass ? `${7 - SOAK_RUN} more runs before promote decision.` : "Resolve before next soak run."}`);
