/**
 * Batch 42 Soak Run 5/7 — rollback / kill-switch heavy
 *
 * Stress: operational controls under pramana HG-2A policy (disabled).
 *   - 3× kill→verify→restore cycles (pramana + HG-1 services)
 *   - sim(on) works while killed (policy layer independent of runtime)
 *   - temporary env promotion: add pramana to env → live BLOCK fires → remove → soft_canary
 *   - rollback drill: runRollbackDrill for pramana + HG-1 services
 *   - HG-1 regression clean after restore
 *
 * @rule:AEG-E-006 kill switch overrides all enforcement
 * @rule:AEG-E-002 rollback is config-only
 * @rule:AEG-HG-003 env var is the runtime gate switch
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PRAMANA_HG2A_POLICY } from "../src/enforcement/hard-gate-policy";
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

let simTPs = 0, prodFires = 0;

console.log(`\n══ Batch 42 Soak Run ${SOAK_RUN}/7 — rollback + kill-switch heavy ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), false, "pre");
check("pramana hard_gate_enabled = false", PRAMANA_HG2A_POLICY.hard_gate_enabled, false, "pre");

// Baseline: pramana soft_canary + HG-1 hot
console.log("\n── Baseline ──");
{
  const dp = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42r5-base" });
  check("pramana baseline: soft_canary", dp.enforcement_phase, "soft_canary", "baseline");
  check("pramana baseline: ALLOW", dp.decision, "ALLOW", "baseline");
}
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r5-base" });
  check(`[${svc}] baseline: hard_gate + ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "baseline");
}

// ── Kill-switch cycles: 3× kill → verify → restore → verify ──────────────────
console.log("\n── Kill-switch cycles (3×) ──");
for (let cycle = 1; cycle <= 3; cycle++) {
  console.log(`\n  [Cycle ${cycle}] Kill ON`);
  process.env.AEGIS_RUNTIME_ENABLED = "false";

  // pramana → shadow while killed
  for (const [op, cap] of [["read", "READ"], ["execute", "EXECUTE"], ["frob", "IMPOSSIBLE_OP"]] as [string, string][]) {
    const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: `b42r5-kill-${cycle}` });
    check(`pramana cycle${cycle} [${cap}]: killed → shadow`, d.enforcement_phase, "shadow", `kill_${cycle}`);
    check(`pramana cycle${cycle} [${cap}]: killed → not BLOCK`, d.decision !== "BLOCK", true, `kill_${cycle}`);
  }

  // HG-1 → shadow while killed
  for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
    const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: `b42r5-kill-${cycle}` });
    check(`[${svc}] cycle${cycle}: killed → shadow + not BLOCK`, d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true, `kill_${cycle}`);
  }

  // sim(on) still detects TP while killed (policy layer is independent of runtime)
  const simKill = simulateHardGate("pramana", "ALLOW", "IMPOSSIBLE_OP", "frob", true);
  check(`cycle${cycle}: sim(on) IMPOSSIBLE_OP while killed → BLOCK (policy independent)`, simKill.simulated_hard_decision, "BLOCK", `kill_sim_${cycle}`);
  if (simKill.hard_gate_would_apply) simTPs++;

  console.log(`  [Cycle ${cycle}] Restore`);
  process.env.AEGIS_RUNTIME_ENABLED = "true";

  // HG-1 back to hard_gate
  for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
    const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: `b42r5-restore-${cycle}` });
    check(`[${svc}] cycle${cycle}: restored → hard_gate + ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, `restore_${cycle}`);
  }
  // pramana back to soft_canary
  const dp = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: `b42r5-restore-${cycle}` });
  check(`pramana cycle${cycle}: restored → soft_canary`, dp.enforcement_phase, "soft_canary", `restore_${cycle}`);
}

// ── Temporary env promotion drill ─────────────────────────────────────────────
// Key env-gate invariant test: add pramana to env → hard_gate fires immediately
// (even though PRAMANA_HG2A_POLICY.hard_gate_enabled=false — env is the switch)
console.log("\n── Temporary env promotion drill ──");
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
{
  const dImp = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r5-promo" });
  logDecision(dImp);
  // When pramana is in env, hard_gate fires: IMPOSSIBLE_OP → live BLOCK
  check("promo drill: IMPOSSIBLE_OP live BLOCK (env switch confirmed)", dImp.decision, "BLOCK", "promo_drill");
  check("promo drill: hard_gate phase", dImp.enforcement_phase, "hard_gate", "promo_drill");

  const dRead = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42r5-promo" });
  check("promo drill: READ ALLOW even when in env (never_block)", dRead.decision, "ALLOW", "promo_drill");
  check("promo drill: hard_gate phase on READ (active but ALLOW)", dRead.enforcement_phase, "hard_gate", "promo_drill");

  const dExec = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r5-promo" });
  check("promo drill: EXECUTE GATE (still_gate, not BLOCK)", dExec.decision, "GATE", "promo_drill");
}
// Demote: remove pramana from env
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
{
  const dDemote = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r5-demote" });
  check("demote: pramana back to soft_canary", dDemote.enforcement_phase, "soft_canary", "promo_drill");
  check("demote: IMPOSSIBLE_OP back to ALLOW (soft only)", dDemote.decision, "ALLOW", "promo_drill");
  if (dDemote.decision === "BLOCK" && dDemote.enforcement_phase === "soft_canary") prodFires++;
}

// ── Rollback drill ────────────────────────────────────────────────────────────
console.log("\n── Rollback drill ──");
const drill = runRollbackDrill(evaluate, ["pramana", "chirpee", "ship-slm", "chief-slm", "puranic-os"], [
  { operation: "read",  requested_capability: "READ" },
  { operation: "frob",  requested_capability: "IMPOSSIBLE_OP" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "rollback");
const ps = drill.services_checked.find(s => s.service_id === "pramana");
check("pramana: shadow after kill in drill", ps?.phase_after_kill, "shadow", "rollback");
check("pramana: no tokens while killed", ps?.tokens_issued, false, "rollback");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const s = drill.services_checked.find(x => x.service_id === svc);
  check(`[${svc}] drill: shadow after kill`, s?.phase_after_kill, "shadow", "rollback");
}

// Confirm restore after drill
const afterDrill = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42r5-afterdrill" });
check("pramana: restored to soft_canary after rollback drill", afterDrill.enforcement_phase, "soft_canary", "rollback");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r5-afterdrill" });
  check(`[${svc}] restored: hard_gate after rollback drill`, d.enforcement_phase, "hard_gate", "rollback");
}

console.log("\n── Count validation ──");
check("simulation TPs = 3 (one per cycle via kill)", simTPs, 3, "count");
check("production fires = 0", prodFires, 0, "count");

const soakPass = failed === 0 && prodFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch42_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN, service: "pramana", hg_group: "HG-2A", date: RUN_DATE,
  verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed,
  simulation_true_positives: simTPs, production_gate_fires: prodFires, ready_to_promote: false,
}, null, 2));
console.log(`\n  Batch 42 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
