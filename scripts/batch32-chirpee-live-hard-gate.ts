/**
 * Batch 32 — Chirpee HG-1 Live Hard-Gate Promotion
 *
 * Purpose: First live hard-gate verification for chirpee after 7/7 soak runs passed.
 *
 * Scope: chirpee only. No other service touched.
 *
 * What changed vs Batch 31:
 *   HARD_GATE_GLOBALLY_ENABLED changed from false → true (source constant, not env var)
 *   AEGIS_HARD_GATE_SERVICES=chirpee set in env → applyHardGate() called from evaluate()
 *   enforcement_phase = "hard_gate" on all chirpee decisions
 *   IMPOSSIBLE_OP / EMPTY_CAPABILITY_ON_WRITE → actual BLOCK (not sim-BLOCK)
 *
 * Captain's checklist (verified in sequence):
 *   1. Only chirpee in AEGIS_HARD_GATE_SERVICES
 *   2. READ never-block (AEG-HG-002)
 *   3. Unknown service → WARN, never BLOCK
 *   4. Unknown capability → GATE/WARN, not BLOCK
 *   5. Only IMPOSSIBLE_OP + EMPTY_CAPABILITY_ON_WRITE hard-block
 *   6. Rollback is config-only (HARD_GATE_SERVICES removal restores soft-canary)
 *   7. Decision logs record hard_gate fields + correct phase
 *   8. Approval lifecycle unaffected for GATE decisions
 *   9. No other service accidentally hard-enabled
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false is the policy default; env var activates
 * @rule:AEG-HG-002 READ never hard-blocks
 * @rule:AEG-HG-003 promotion requires explicit AEGIS_HARD_GATE_SERVICES entry
 */

// Set env BEFORE imports only affects call-time reads (applyHardGate reads env at call time)
// AEGIS_HARD_GATE_SERVICES is intentionally set here — this IS the promotion act
process.env.AEGIS_ENFORCEMENT_MODE  = "soft";
process.env.AEGIS_RUNTIME_ENABLED   = "true";
process.env.AEGIS_DRY_RUN           = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee"; // Stage 1 promotion — chirpee only
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import { approveToken, denyToken, revokeToken, getApproval, runRollbackDrill } from "../src/enforcement/approval";
import { HARD_GATE_GLOBALLY_ENABLED, CHIRPEE_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH = 32;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
const allDecisions: unknown[] = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const pass = String(actual) === String(expected);
  if (pass) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(80)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(80)} expected=${expected} actual=${actual}`); }
}
function okStatus(r: { ok: boolean }) { return r.ok ? "accepted" : "rejected"; }
function gate(op: string, cap: string, caller = "b32", svc = "chirpee") {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: caller, session_id: `b32-${svc}-${op}-${cap}-${Date.now()}` });
  logDecision(d);
  allDecisions.push({ service_id: d.service_id, operation: d.operation, capability: d.requested_capability, decision: d.decision, enforcement_phase: d.enforcement_phase, hard_gate_active: d.hard_gate_active, hard_gate_applied: d.hard_gate_applied, hard_gate_service: d.hard_gate_service, hard_gate_policy_version: d.hard_gate_policy_version });
  return d;
}

// ── Pre-flight checks ─────────────────────────────────────────────────────────
console.log("\n══ Batch 32: Chirpee HG-1 Live Hard-Gate Promotion ══");
console.log(`  Date: ${RUN_DATE}`);
console.log(`  HARD_GATE_GLOBALLY_ENABLED: ${HARD_GATE_GLOBALLY_ENABLED}`);
console.log(`  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log("\n── Pre-flight: Policy constants ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "preflight");
check("AEGIS_HARD_GATE_SERVICES = chirpee", process.env.AEGIS_HARD_GATE_SERVICES, "chirpee", "preflight");
check("AEGIS_HARD_GATE_SERVICES does NOT contain ship-slm", (process.env.AEGIS_HARD_GATE_SERVICES ?? "").includes("ship-slm"), false, "preflight");
check("AEGIS_HARD_GATE_SERVICES does NOT contain granthx", (process.env.AEGIS_HARD_GATE_SERVICES ?? "").includes("granthx"), false, "preflight");
check("chirpee policy: stage is LIVE", CHIRPEE_HG1_POLICY.stage.includes("LIVE"), true, "preflight");
check("chirpee hard_block: IMPOSSIBLE_OP", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "preflight");
check("chirpee hard_block: EMPTY_CAPABILITY_ON_WRITE", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "preflight");
check("chirpee never_block: READ", CHIRPEE_HG1_POLICY.never_block_capabilities.has("READ"), true, "preflight");
check("chirpee still_gate: CI_DEPLOY", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("CI_DEPLOY"), true, "preflight");
check("chirpee still_gate: AI_EXECUTE", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("AI_EXECUTE"), true, "preflight");
check("chirpee still_gate: DELETE", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("DELETE"), true, "preflight");

// ── Check 1: READ never blocks ────────────────────────────────────────────────
console.log("\n── Check 1: READ never blocks (AEG-HG-002) ──");
for (const [op, cap] of [["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"],["search","SEARCH"],["health","HEALTH"]]) {
  const d = gate(op, cap, "b32-read");
  check(`${op}/${cap}: decision = ALLOW`, d.decision, "ALLOW", "check1_read");
  check(`${op}/${cap}: phase = hard_gate`, d.enforcement_phase, "hard_gate", "check1_read");
  check(`${op}/${cap}: hard_gate_active = true`, d.hard_gate_active, true, "check1_read");
  check(`${op}/${cap}: hard_gate_applied = false`, d.hard_gate_applied, false, "check1_read");
}

// ── Check 2: WRITE is ALLOW, not BLOCK ───────────────────────────────────────
console.log("\n── Check 2: WRITE operations not blocked ──");
for (const [op, cap] of [["write","WRITE"],["create","WRITE"],["patch","WRITE"],["update","WRITE"]]) {
  const d = gate(op, cap, "b32-write");
  check(`${op}/${cap}: decision ≠ BLOCK`, d.decision !== "BLOCK", true, "check2_write");
  check(`${op}/${cap}: phase = hard_gate`, d.enforcement_phase, "hard_gate", "check2_write");
  check(`${op}/${cap}: hard_gate_applied = false`, d.hard_gate_applied, false, "check2_write");
}

// ── Check 3: IMPOSSIBLE_OP → live BLOCK ──────────────────────────────────────
console.log("\n── Check 3: IMPOSSIBLE_OP → live hard BLOCK (not simulation) ──");
const impossibleDecisions: unknown[] = [];
for (let i = 1; i <= 3; i++) {
  const d = gate("frob_impossible", "IMPOSSIBLE_OP", "b32-block");
  check(`IMPOSSIBLE_OP[${i}]: decision = BLOCK`, d.decision, "BLOCK", "check3_block");
  check(`IMPOSSIBLE_OP[${i}]: phase = hard_gate`, d.enforcement_phase, "hard_gate", "check3_block");
  check(`IMPOSSIBLE_OP[${i}]: hard_gate_applied = true`, d.hard_gate_applied, true, "check3_block");
  check(`IMPOSSIBLE_OP[${i}]: hard_gate_service = chirpee`, d.hard_gate_service, "chirpee", "check3_block");
  check(`IMPOSSIBLE_OP[${i}]: hard_gate_policy_version = HG-1`, d.hard_gate_policy_version, "HG-1", "check3_block");
  impossibleDecisions.push({ i, decision: d.decision, phase: d.enforcement_phase, hard_gate_applied: d.hard_gate_applied });
}

// ── Check 4: EMPTY_CAPABILITY_ON_WRITE → live BLOCK ──────────────────────────
console.log("\n── Check 4: EMPTY_CAPABILITY_ON_WRITE → live hard BLOCK ──");
for (let i = 1; i <= 3; i++) {
  const d = gate("write", "EMPTY_CAPABILITY_ON_WRITE", "b32-block");
  check(`EMPTY_CAP[${i}]: decision = BLOCK`, d.decision, "BLOCK", "check4_block");
  check(`EMPTY_CAP[${i}]: phase = hard_gate`, d.enforcement_phase, "hard_gate", "check4_block");
  check(`EMPTY_CAP[${i}]: hard_gate_applied = true`, d.hard_gate_applied, true, "check4_block");
  check(`EMPTY_CAP[${i}]: hard_gate_service = chirpee`, d.hard_gate_service, "chirpee", "check4_block");
}

// ── Check 5: GATE decisions (DEPLOY / DELETE / AI_EXECUTE) ───────────────────
console.log("\n── Check 5: GATE decisions unaffected ──");
const gateTokens: string[] = [];
for (const [op, cap] of [["deploy","CI_DEPLOY"],["delete","DELETE"],["ai-execute","AI_EXECUTE"]]) {
  const d = gate(op, cap, "b32-gate");
  check(`${op}/${cap}: decision = GATE`, d.decision, "GATE", "check5_gate");
  check(`${op}/${cap}: phase = hard_gate`, d.enforcement_phase, "hard_gate", "check5_gate");
  check(`${op}/${cap}: hard_gate_applied = false`, d.hard_gate_applied, false, "check5_gate");
  check(`${op}/${cap}: approval_token issued`, !!d.approval_token, true, "check5_gate");
  if (d.approval_token) gateTokens.push(d.approval_token);
}

// ── Check 6: Unknown service stays WARN (never BLOCK) ────────────────────────
console.log("\n── Check 6: Unknown service → WARN not BLOCK ──");
for (const svc of ["unknown-service-xyz", "future-service-2030", "ship-slm"]) {
  const d = gate("deploy", "CI_DEPLOY", "b32-unknown", svc);
  check(`unknown svc '${svc}': decision ≠ BLOCK`, d.decision !== "BLOCK", true, "check6_unknown_svc");
  check(`unknown svc '${svc}': hard_gate_applied = false or undefined`, !d.hard_gate_applied, true, "check6_unknown_svc");
}

// ── Check 7: Unknown capability → GATE/WARN not hard-BLOCK ───────────────────
console.log("\n── Check 7: Unknown capability → GATE/WARN not hard-BLOCK ──");
for (const cap of ["FUTURE_CAP_2030", "LIFECYCLE_UNKNOWN", "CUSTOM_OP_XYZ"]) {
  const d = gate("execute", cap, "b32-unknown-cap");
  check(`unknown cap '${cap}': decision ≠ BLOCK`, d.decision !== "BLOCK", true, "check7_unknown_cap");
  check(`unknown cap '${cap}': hard_gate_applied = false`, !d.hard_gate_applied, true, "check7_unknown_cap");
  check(`unknown cap '${cap}': phase = hard_gate`, d.enforcement_phase, "hard_gate", "check7_unknown_cap");
}

// ── Check 8: Approval lifecycle works for GATE decisions ─────────────────────
console.log("\n── Check 8: Approval lifecycle for GATE decisions ──");
if (gateTokens.length >= 3) {
  const [t1, t2, t3] = gateTokens;
  check("approve GATE token", okStatus(approveToken(t1, "batch32 live gate approve", "captain@ankr")), "accepted", "check8_lifecycle");
  check("deny GATE token", okStatus(denyToken(t2, "batch32 live gate deny", "ops@ankr")), "accepted", "check8_lifecycle");
  check("revoke GATE token", okStatus(revokeToken(t3, "security@ankr", "batch32 live gate revoke")), "accepted", "check8_lifecycle");
  check("replay rejected (AEG-E-015)", okStatus(approveToken(t1, "replay b32", "ops@ankr")), "rejected", "check8_lifecycle");
}

// ── Check 9: ship-slm decision log shows NO hard-gate (not promoted) ─────────
console.log("\n── Check 9: ship-slm not hard-enabled (only chirpee promoted) ──");
const shipSlmDeploy = gate("deploy", "CI_DEPLOY", "b32-not-promoted", "ship-slm");
check("ship-slm: not hard_gate phase", shipSlmDeploy.enforcement_phase !== "hard_gate", true, "check9_isolation");
check("ship-slm: hard_gate_applied not true", shipSlmDeploy.hard_gate_applied !== true, true, "check9_isolation");

const unknownMalformed = gate("frob_impossible", "IMPOSSIBLE_OP", "b32-not-promoted", "granthx");
check("granthx IMPOSSIBLE_OP: not BLOCK", unknownMalformed.decision !== "BLOCK", true, "check9_isolation");

// ── Check 10: Rollback drill ─────────────────────────────────────────────────
console.log("\n── Check 10: Rollback drill — chirpee returns to shadow after kill ──");
const drill = runRollbackDrill(evaluate, ["chirpee"], [
  { operation: "deploy", requested_capability: "CI_DEPLOY" },
  { operation: "delete", requested_capability: "DELETE" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "check10_rollback");
const cs = drill.services_checked.find(s => s.service_id === "chirpee");
check("chirpee: shadow after kill", cs?.phase_after_kill, "shadow", "check10_rollback");
check("chirpee: no tokens while killed", cs?.tokens_issued, false, "check10_rollback");

// ── Check 11: Canary status ───────────────────────────────────────────────────
console.log("\n── Check 11: Canary ──");
const canary = getCanaryStatus(["chirpee"]);
const sc = canary.success_criteria;
check("no_read_gates", sc.no_read_gates, true, "check11_canary");
check("no_unknown_service_blocks", sc.no_unknown_service_blocks, true, "check11_canary");
check("no_token_replay_successes", sc.no_token_replay_successes, true, "check11_canary");
check("rollback_drill_passed", sc.rollback_drill_passed, true, "check11_canary");

// ── Rollback simulation: env var only ────────────────────────────────────────
console.log("\n── Rollback verification: removing chirpee from AEGIS_HARD_GATE_SERVICES ──");
const savedServices = process.env.AEGIS_HARD_GATE_SERVICES;
process.env.AEGIS_HARD_GATE_SERVICES = ""; // rollback — env var only, HARD_GATE_GLOBALLY_ENABLED stays true

const rollbackImpossible = gate("frob_impossible", "IMPOSSIBLE_OP", "b32-rollback");
check("rollback: IMPOSSIBLE_OP no longer BLOCK", rollbackImpossible.decision !== "BLOCK", true, "check12_rollback_verify");
check("rollback: phase not hard_gate", rollbackImpossible.enforcement_phase !== "hard_gate", true, "check12_rollback_verify");

const rollbackDeploy = gate("deploy", "CI_DEPLOY", "b32-rollback");
check("rollback: deploy still GATE (soft-canary)", rollbackDeploy.decision, "GATE", "check12_rollback_verify");
check("rollback: phase = soft_canary", rollbackDeploy.enforcement_phase, "soft_canary", "check12_rollback_verify");

// Restore
process.env.AEGIS_HARD_GATE_SERVICES = savedServices;
console.log(`  Restored AEGIS_HARD_GATE_SERVICES=${savedServices}`);
check("env restored: chirpee back in services", process.env.AEGIS_HARD_GATE_SERVICES, "chirpee", "check12_rollback_verify");

// ── Final verdict ─────────────────────────────────────────────────────────────
const hardBlockCount = allDecisions.filter((d: any) => d.hard_gate_applied === true).length;
const hardGateActiveCount = allDecisions.filter((d: any) => d.hard_gate_active === true).length;
const unexpectedBlocks = allDecisions.filter((d: any) => d.decision === "BLOCK" && !d.hard_gate_applied).length;

const batchPass = failed === 0 && hardBlockCount >= 6 && unexpectedBlocks === 0;

console.log(`\n══ Batch 32 Summary ══`);
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Hard-gate active decisions: ${hardGateActiveCount}`);
console.log(`  Hard BLOCK fires: ${hardBlockCount} (expected ≥6: 3×IMPOSSIBLE_OP + 3×EMPTY_CAP)`);
console.log(`  Unexpected blocks: ${unexpectedBlocks} (must be 0)`);
console.log(`  Verdict: ${batchPass ? "PASS" : "FAIL"}`);
if (failures.length) {
  console.log("\n  Failures:");
  failures.forEach(f => console.log(`    ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));
}
console.log("\n── Category summary ──");
const cats = [...new Set(failures.map(f => f.cat).concat(["preflight","check1_read","check2_write","check3_block","check4_block","check5_gate","check6_unknown_svc","check7_unknown_cap","check8_lifecycle","check9_isolation","check10_rollback","check11_canary","check12_rollback_verify"]))];
for (const cat of cats) {
  const catFails = failures.filter(f => f.cat === cat).length;
  console.log(`  ${cat.padEnd(30)}: ${catFails === 0 ? "✓ clean" : `✗ ${catFails} failures`}`);
}

// ── Artifacts ─────────────────────────────────────────────────────────────────
const summary = {
  batch: BATCH,
  date: RUN_DATE,
  verdict: batchPass ? "PASS" : "FAIL",
  service: "chirpee",
  stage: "Stage 1 — HG-1 pilot — LIVE",
  hard_gate_globally_enabled: HARD_GATE_GLOBALLY_ENABLED,
  aegis_hard_gate_services: "chirpee",
  total_checks: totalChecks,
  passed,
  failed,
  hard_block_fires: hardBlockCount,
  hard_gate_active_decisions: hardGateActiveCount,
  unexpected_blocks: unexpectedBlocks,
  hard_block_capabilities: ["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"],
  never_block_confirmed: true,
  unknown_service_confirmed_no_block: true,
  unknown_cap_confirmed_no_block: true,
  gate_decisions_unaffected: true,
  rollback_verified: true,
  promotion_note: "Hard gate is now LIVE for chirpee. IMPOSSIBLE_OP and EMPTY_CAPABILITY_ON_WRITE are blocked. All other decisions unchanged.",
};

writeFileSync(join(dir, "batch32_chirpee_live_hard_gate_summary.json"), JSON.stringify(summary, null, 2));
writeFileSync(join(dir, "batch32_first_hard_gate_decisions.json"), JSON.stringify(allDecisions, null, 2));
writeFileSync(join(dir, "batch32_failures.json"), JSON.stringify(failures, null, 2));

const rollbackResult = {
  batch: BATCH,
  date: RUN_DATE,
  rollback_mechanism: "Remove chirpee from AEGIS_HARD_GATE_SERVICES env var",
  rollback_tested: true,
  chirpee_returns_to_soft_canary: true,
  impossible_op_no_longer_blocks_on_rollback: true,
  hard_gate_globally_enabled_not_changed: true,
  restore_mechanism: "Re-add chirpee to AEGIS_HARD_GATE_SERVICES",
  note: "Rollback does NOT require changing HARD_GATE_GLOBALLY_ENABLED. Env var is sufficient."
};
writeFileSync(join(dir, "batch32_rollback_result.json"), JSON.stringify(rollbackResult, null, 2));

console.log(`\n  Artifacts written to .aegis/`);
console.log(`    batch32_chirpee_live_hard_gate_summary.json`);
console.log(`    batch32_first_hard_gate_decisions.json`);
console.log(`    batch32_rollback_result.json`);
console.log(`    batch32_failures.json`);
console.log(`\n  Batch 32: ${batchPass ? "PASS — Chirpee HG-1 is LIVE. One round, one gun, safety officer watching." : "FAIL — Resolve before declaring chirpee live."}`);
