/**
 * Batch 35 Soak Run 5/7 — Kill switch + rollback heavy
 *
 * Stress: AEGIS_RUNTIME_ENABLED kill cycles and env var rollback. Verifies that:
 *   - 3 kill/restore cycles produce consistent shadow→soft_canary transitions
 *   - sim(on) still detects TPs even during kill (policy correct, production suppressed)
 *   - Removing ship-slm/chief-slm from AEGIS_HARD_GATE_SERVICES (hypothetical) is a no-op
 *     since they were never in it — env stays "chirpee"
 *   - chirpee hard-gate survives all kill cycles (post-restore back to BLOCK)
 *   - rollback drill passes for both services
 *
 * @rule:AEG-E-006 kill switch must win over hard-gate overlay in all cycles
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { runRollbackDrill } from "../src/enforcement/approval";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, SHIP_SLM_HG1_POLICY, CHIEF_SLM_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
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

let totalTP = 0, totalFP = 0;

console.log(`\n══ Batch 35 Soak Run ${SOAK_RUN}/7 — Kill switch + rollback heavy ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("chirpee in env (call-time)", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("chirpee") ?? false, true, "pre");
check("ship-slm hard_gate_enabled = false", SHIP_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chief-slm hard_gate_enabled = false", CHIEF_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");

// Baseline: normal soft_canary decisions before any kill
console.log("\n── Baseline: soft_canary before kill ──");
for (const svc of ["ship-slm","chief-slm"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b35r5-baseline" });
  logDecision(d);
  check(`${svc} READ: soft_canary baseline`, d.enforcement_phase, "soft_canary", "baseline");
}
const chirpeeBaseline = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r5-baseline" });
logDecision(chirpeeBaseline);
check("chirpee IMPOSSIBLE_OP baseline: hard_gate", chirpeeBaseline.enforcement_phase, "hard_gate", "baseline");
check("chirpee IMPOSSIBLE_OP baseline: BLOCK", chirpeeBaseline.decision, "BLOCK", "baseline");

// Wave A: 3 kill/restore cycles
console.log("\n── Wave A: 3 kill/restore cycles ──");
for (let cycle = 1; cycle <= 3; cycle++) {
  // Kill
  process.env.AEGIS_RUNTIME_ENABLED = "false";
  for (const svc of ["ship-slm","chief-slm"]) {
    const dKill = evaluate({ service_id: svc, operation: "frob_impossible", requested_capability: "IMPOSSIBLE_OP", caller_id: `b35r5-kill-c${cycle}` });
    logDecision(dKill);
    check(`cycle${cycle} kill: ${svc} IMPOSSIBLE_OP → shadow`, dKill.enforcement_phase, "shadow", "wave_a_kill");
    check(`cycle${cycle} kill: ${svc} not BLOCK`, dKill.decision !== "BLOCK", true, "wave_a_kill");
    // sim(on) during kill: policy still detects TP (production suppressed, policy correct)
    const simKill = simulateHardGate(svc, dKill.decision, "IMPOSSIBLE_OP", "frob_impossible", true);
    check(`cycle${cycle} kill: ${svc} sim(on) still detects BLOCK`, simKill.simulated_hard_decision, "BLOCK", "wave_a_kill");
    if (simKill.simulated_hard_decision === "BLOCK") totalTP++;
  }
  // Chirpee also killed
  const chirpeeKill = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: `b35r5-kill-c${cycle}` });
  logDecision(chirpeeKill);
  check(`cycle${cycle} kill: chirpee IMPOSSIBLE_OP → shadow`, chirpeeKill.enforcement_phase, "shadow", "wave_a_kill");
  check(`cycle${cycle} kill: chirpee not BLOCK (shadow wins)`, chirpeeKill.decision !== "BLOCK", true, "wave_a_kill");

  // Restore
  process.env.AEGIS_RUNTIME_ENABLED = "true";
  for (const svc of ["ship-slm","chief-slm"]) {
    const dRestore = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: `b35r5-restore-c${cycle}` });
    logDecision(dRestore);
    check(`cycle${cycle} restore: ${svc} READ → soft_canary`, dRestore.enforcement_phase, "soft_canary", "wave_a_kill");
    check(`cycle${cycle} restore: ${svc} READ → ALLOW`, dRestore.decision, "ALLOW", "wave_a_kill");
  }
  // Chirpee restores to hard_gate
  const chirpeeRestore = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: `b35r5-restore-c${cycle}` });
  logDecision(chirpeeRestore);
  check(`cycle${cycle} restore: chirpee IMPOSSIBLE_OP → hard_gate`, chirpeeRestore.enforcement_phase, "hard_gate", "wave_a_kill");
  check(`cycle${cycle} restore: chirpee IMPOSSIBLE_OP → BLOCK`, chirpeeRestore.decision, "BLOCK", "wave_a_kill");
}

// Wave B: Env var isolation — removing chirpee from env breaks chirpee hard-gate only
// ship-slm and chief-slm are unaffected (they were never in the set)
console.log("\n── Wave B: Env var isolation ──");
const savedEnv = process.env.AEGIS_HARD_GATE_SERVICES;

// Remove chirpee from env — chirpee drops to soft_canary, others unaffected
process.env.AEGIS_HARD_GATE_SERVICES = "";
const chirpeeNoEnv = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r5-env-test" });
logDecision(chirpeeNoEnv);
check("env cleared: chirpee IMPOSSIBLE_OP → soft_canary (not hard_gate)", chirpeeNoEnv.enforcement_phase, "soft_canary", "wave_b_env");
check("env cleared: chirpee IMPOSSIBLE_OP → ALLOW (soft gate passes)", chirpeeNoEnv.decision !== "BLOCK", true, "wave_b_env");

for (const svc of ["ship-slm","chief-slm"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r5-env-test" });
  logDecision(d);
  check(`env cleared: ${svc} IMPOSSIBLE_OP → soft_canary (unchanged)`, d.enforcement_phase, "soft_canary", "wave_b_env");
  check(`env cleared: ${svc} not BLOCK`, d.decision !== "BLOCK", true, "wave_b_env");
}

// Restore env
process.env.AEGIS_HARD_GATE_SERVICES = savedEnv;
const chirpeeRestored = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r5-env-restore" });
logDecision(chirpeeRestored);
check("env restored: chirpee IMPOSSIBLE_OP → hard_gate", chirpeeRestored.enforcement_phase, "hard_gate", "wave_b_env");
check("env restored: chirpee IMPOSSIBLE_OP → BLOCK", chirpeeRestored.decision, "BLOCK", "wave_b_env");

// Wave C: Rollback drill (both services)
console.log("\n── Wave C: Rollback drill ──");
const drill = runRollbackDrill(evaluate, ["ship-slm","chief-slm"], [
  { operation: "deploy", requested_capability: "CI_DEPLOY" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
  { operation: "delete", requested_capability: "DELETE" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "wave_c_rollback");
for (const svc of ["ship-slm","chief-slm"]) {
  const cs = drill.services_checked.find(s => s.service_id === svc);
  check(`${svc}: shadow after kill`, cs?.phase_after_kill, "shadow", "wave_c_rollback");
  check(`${svc}: no tokens while killed`, cs?.tokens_issued, false, "wave_c_rollback");
}

// Chirpee regression post-all-cycles
console.log("\n── Chirpee regression ──");
const cr = evaluate({ service_id: "chirpee", operation: "read", requested_capability: "READ", caller_id: "b35r5-reg" });
logDecision(cr);
check("chirpee READ → ALLOW hard_gate", cr.decision, "ALLOW", "regression");
const ci = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r5-reg" });
logDecision(ci);
check("chirpee IMPOSSIBLE_OP → live BLOCK", ci.decision, "BLOCK", "regression");
check("chirpee IMPOSSIBLE_OP hard_gate_applied = true", ci.hard_gate_applied, true, "regression");

// Count validation
// TPs: 3 kill cycles × 2 services = 6 (from sim(on) during kill)
console.log("\n── Count validation ──");
check("false positives = 0", totalFP, 0, "count");
check("true positives = 6 (sim during kill)", totalTP, 6, "count");

const soakPass = failed === 0 && totalFP === 0 && totalTP === 6;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch35_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP, kill_cycles: 3, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 35 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
