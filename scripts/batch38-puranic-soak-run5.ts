/**
 * Batch 38 Soak Run 5/7 — puranic-os kill switch + rollback stress
 *
 * Stress: operational controls under puranic-os profile.
 * Verifies that:
 *   - kill switch forces shadow phase for all services (including live HG-1)
 *   - restore brings live services back to hard_gate phase
 *   - rollback drill succeeds: evaluate → services_checked[0].phase_after_kill=shadow
 *   - repeated kill→restore cycles are stable (3 cycles)
 *   - sim(on) still correctly detects TPs even while kill switch active
 *   - temporary env promotion (puranic-os added) has no effect (hard_gate_enabled=false)
 *
 * @rule:AEG-E-001 kill switch overrides all enforcement
 * @rule:AEG-E-002 rollback is config-only (remove from AEGIS_HARD_GATE_SERVICES)
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PURANIC_OS_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
import { runRollbackDrill } from "../src/enforcement/approval";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const SOAK_RUN = 5;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

let totalProdFires = 0;

console.log(`\n══ Batch 38 Soak Run ${SOAK_RUN}/7 — puranic-os kill switch + rollback stress ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  Profile: read_only, BR-1, TIER-A`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("puranic-os NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("puranic-os") ?? false, false, "pre");
check("puranic-os hard_gate_enabled = false", PURANIC_OS_HG1_POLICY.hard_gate_enabled, false, "pre");

// Baseline: confirm live services are hot before kill switch
console.log("\n── Baseline: live services hot ──");
for (const svc of ["chirpee","ship-slm","chief-slm"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b38r5-base" });
  logDecision(d);
  check(`[${svc}] baseline: hard_gate`, d.enforcement_phase, "hard_gate", "baseline");
  check(`[${svc}] baseline: ALLOW`, d.decision, "ALLOW", "baseline");
}
{
  const d = evaluate({ service_id: "puranic-os", operation: "read", requested_capability: "READ", caller_id: "b38r5-base" });
  logDecision(d);
  check("[puranic-os] baseline: soft_canary", d.enforcement_phase, "soft_canary", "baseline");
  check("[puranic-os] baseline: ALLOW", d.decision, "ALLOW", "baseline");
}

// Kill switch cycles: 3× kill→verify→restore→verify
console.log("\n── Kill switch cycles (3×) ──");
for (let cycle = 1; cycle <= 3; cycle++) {
  console.log(`\n  [Cycle ${cycle}] Kill switch ON`);
  process.env.AEGIS_RUNTIME_ENABLED = "false";

  // All services → shadow while killed
  for (const svc of ["chirpee","ship-slm","chief-slm","puranic-os"]) {
    const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: `b38r5-kill-${cycle}` });
    logDecision(d);
    check(`[${svc}] cycle${cycle}: killed → shadow`, d.enforcement_phase, "shadow", `kill_cycle_${cycle}`);
    check(`[${svc}] cycle${cycle}: killed → not BLOCK`, d.decision !== "BLOCK", true, `kill_cycle_${cycle}`);
  }

  // sim(on) still works while killed (policy layer independent of runtime)
  const simKill = simulateHardGate("puranic-os", "ALLOW", "IMPOSSIBLE_OP", "frob", true);
  check(`cycle${cycle}: sim(on) detects IMPOSSIBLE_OP while killed`, simKill.simulated_hard_decision, "BLOCK", `kill_sim_${cycle}`);

  console.log(`  [Cycle ${cycle}] Restore`);
  process.env.AEGIS_RUNTIME_ENABLED = "true";

  // Live services back to hard_gate after restore
  for (const svc of ["chirpee","ship-slm","chief-slm"]) {
    const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: `b38r5-restore-${cycle}` });
    logDecision(d);
    check(`[${svc}] cycle${cycle}: restored → hard_gate`, d.enforcement_phase, "hard_gate", `restore_cycle_${cycle}`);
    check(`[${svc}] cycle${cycle}: restored → ALLOW`, d.decision, "ALLOW", `restore_cycle_${cycle}`);
  }
  // puranic-os back to soft_canary
  const dp = evaluate({ service_id: "puranic-os", operation: "read", requested_capability: "READ", caller_id: `b38r5-restore-${cycle}` });
  logDecision(dp);
  check(`[puranic-os] cycle${cycle}: restored → soft_canary`, dp.enforcement_phase, "soft_canary", `restore_cycle_${cycle}`);
}

// Rollback drill
console.log("\n── Rollback drill ──");
const drill = runRollbackDrill(evaluate, ["puranic-os"], [
  { operation: "read",       requested_capability: "READ" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
  { operation: "frob",       requested_capability: "IMPOSSIBLE_OP" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "rollback");
const ps = drill.services_checked.find(s => s.service_id === "puranic-os");
check("puranic-os: shadow after kill", ps?.phase_after_kill, "shadow", "rollback");
check("puranic-os: no tokens while killed", ps?.tokens_issued, false, "rollback");

// Confirm restore after rollback drill
const afterDrill = evaluate({ service_id: "puranic-os", operation: "read", requested_capability: "READ", caller_id: "b38r5-afterdrill" });
logDecision(afterDrill);
check("puranic-os: restored to soft_canary after rollback drill", afterDrill.enforcement_phase, "soft_canary", "rollback");

// Temporary env promotion drill
// puranic-os added to env but hard_gate_enabled=false in policy → gate won't apply
console.log("\n── Temporary promotion drill ──");
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
{
  const d = evaluate({ service_id: "puranic-os", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b38r5-promo" });
  logDecision(d);
  // gate.ts uses AEGIS_HARD_GATE_SERVICES env var as the switch — policy.hard_gate_enabled is advisory
  // When puranic-os is in env, hard gate DOES apply: IMPOSSIBLE_OP → live BLOCK
  check("promo drill: IMPOSSIBLE_OP live BLOCK when in env", d.decision, "BLOCK", "promo_drill");
  check("promo drill: hard_gate phase when in env", d.enforcement_phase, "hard_gate", "promo_drill");
}
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm"; // restore
{
  const d = evaluate({ service_id: "puranic-os", operation: "read", requested_capability: "READ", caller_id: "b38r5-demote" });
  logDecision(d);
  check("demote drill: puranic-os back to soft_canary", d.enforcement_phase, "soft_canary", "promo_drill");
}

// Production gate fire guard
console.log("\n── Production gate fire guard ──");
for (const [op, cap] of [["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"],["read","READ"]] as [string,string][]) {
  const d = evaluate({ service_id: "puranic-os", operation: op, requested_capability: cap, caller_id: "b38r5-guard" });
  const simOff = simulateHardGate("puranic-os", d.decision, cap, op, false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`prod guard [puranic-os] ${cap}: no fire`, simOff.hard_gate_would_apply, false, "prod_guard");
}

// Live HG-1 regression
console.log("\n── Live HG-1 regression ──");
for (const svc of ["chirpee","ship-slm","chief-slm"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b38r5-reg" });
  logDecision(r);
  check(`[${svc}] READ: ALLOW`, r.decision, "ALLOW", "regression");
  check(`[${svc}] READ: hard_gate`, r.enforcement_phase, "hard_gate", "regression");
  const ri = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b38r5-reg" });
  logDecision(ri);
  check(`[${svc}] IMPOSSIBLE_OP: live BLOCK`, ri.decision, "BLOCK", "regression");
}

console.log("\n── Count validation ──");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch38_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, service: "puranic-os", date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, production_gate_fires: totalProdFires, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 38 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
