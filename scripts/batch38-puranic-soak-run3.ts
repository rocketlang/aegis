/**
 * Batch 38 Soak Run 3/7 — puranic-os burst / high-volume
 *
 * Stress: rapid-fire evaluate() calls across all capability tiers.
 * Verifies that under burst traffic patterns:
 *   - no accumulated FPs from repeated GATE caps
 *   - TP detection is consistent under repeated malformed calls
 *   - production_gate_fires stays 0 throughout
 *   - chirpee/ship-slm/chief-slm live gates unaffected by burst on puranic-os
 *
 * @rule:AEG-E-004 gate is stateless — same input always same output
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PURANIC_OS_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const SOAK_RUN = 3;
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

const MALFORMED = new Set(["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"]);
let totalTP = 0, totalFP = 0, totalProdFires = 0;

function burst(label: string, op: string, cap: string, expSoft: string, expSim: string, cat: string, iterations = 5) {
  for (let i = 0; i < iterations; i++) {
    const svc = "puranic-os";
    const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: `b38r3-burst-${i}`, session_id: `b38r3-${i}-${Date.now()}` });
    logDecision(d);
    check(`soft [${svc}] ${label}[${i}]`, d.decision, expSoft, cat);
    check(`phase [${svc}] ${label}[${i}]`, d.enforcement_phase, "soft_canary", cat);
    const simOff = simulateHardGate(svc, d.decision, cap, op, false);
    if (simOff.hard_gate_would_apply) totalProdFires++;
    check(`sim(off) [${svc}] ${label}[${i}]: no fire`, simOff.hard_gate_would_apply, false, cat);
    const simOn = simulateHardGate(svc, d.decision, cap, op, true);
    check(`sim(on)  [${svc}] ${label}[${i}]`, simOn.simulated_hard_decision, expSim, cat);
    const isMalformed = MALFORMED.has(cap.toUpperCase());
    if (simOn.simulated_hard_decision === "BLOCK" && !isMalformed) totalFP++;
    if (simOn.simulated_hard_decision === "BLOCK" && isMalformed) totalTP++;
  }
}

console.log(`\n══ Batch 38 Soak Run ${SOAK_RUN}/7 — puranic-os burst / high-volume ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  Profile: read_only, BR-1, TIER-A  |  iterations: 5 per case`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("puranic-os NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("puranic-os") ?? false, false, "pre");
check("puranic-os hard_gate_enabled = false", PURANIC_OS_HG1_POLICY.hard_gate_enabled, false, "pre");

// Wave A: Burst on ALLOW caps (5 iters each)
console.log("\n── Wave A: Burst on safe caps ──");
burst("burst:READ",   "read",   "READ",   "ALLOW", "ALLOW", "wave_a_burst_allow", 5);
burst("burst:WRITE",  "write",  "WRITE",  "ALLOW", "ALLOW", "wave_a_burst_allow", 5);
burst("burst:QUERY",  "query",  "QUERY",  "ALLOW", "ALLOW", "wave_a_burst_allow", 5);
burst("burst:HEALTH", "health", "HEALTH", "ALLOW", "ALLOW", "wave_a_burst_allow", 5);

// Wave B: Burst on GATE caps — must GATE every time, never degrade
console.log("\n── Wave B: Burst on GATE caps ──");
burst("burst:AI_EXECUTE", "ai-execute", "AI_EXECUTE", "GATE", "GATE", "wave_b_burst_gate", 5);
burst("burst:CI_DEPLOY",  "deploy",     "CI_DEPLOY",  "GATE", "GATE", "wave_b_burst_gate", 5);
burst("burst:DELETE",     "delete",     "DELETE",     "GATE", "GATE", "wave_b_burst_gate", 5);

// Wave C: Burst on malformed — must sim-BLOCK every time (TP count = 10 per malformed × 5 iters)
// 2 malformed × 5 iters = 10 TPs
console.log("\n── Wave C: Burst on malformed (TP detection consistency) ──");
burst("burst:IMPOSSIBLE_OP",         "frob",  "IMPOSSIBLE_OP",         "ALLOW", "BLOCK", "wave_c_burst_malformed", 5);
burst("burst:EMPTY_CAPABILITY",      "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave_c_burst_malformed", 5);

// Wave D: High-vol mixed traffic (alternating safe/gate/safe) — 10 calls
console.log("\n── Wave D: Interleaved mixed traffic ──");
const mixed: [string, string, string, string][] = [
  ["read","READ","ALLOW","ALLOW"],
  ["ai-execute","AI_EXECUTE","GATE","GATE"],
  ["get","GET","ALLOW","ALLOW"],
  ["deploy","CI_DEPLOY","GATE","GATE"],
  ["query","QUERY","ALLOW","ALLOW"],
  ["delete","DELETE","GATE","GATE"],
  ["list","LIST","ALLOW","ALLOW"],
  ["ai-execute","AI_EXECUTE","GATE","GATE"],
  ["health","HEALTH","ALLOW","ALLOW"],
  ["read","READ","ALLOW","ALLOW"],
];
for (const [op, cap, expSoft, expSim] of mixed) {
  const d = evaluate({ service_id: "puranic-os", operation: op, requested_capability: cap, caller_id: "b38r3-mixed" });
  logDecision(d);
  check(`mixed [puranic-os] ${op}/${cap}: soft`, d.decision, expSoft, "wave_d_mixed");
  check(`mixed [puranic-os] ${op}/${cap}: phase`, d.enforcement_phase, "soft_canary", "wave_d_mixed");
  const simOff = simulateHardGate("puranic-os", d.decision, cap, op, false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`mixed [puranic-os] ${op}/${cap}: no fire`, simOff.hard_gate_would_apply, false, "wave_d_mixed");
  const simOn = simulateHardGate("puranic-os", d.decision, cap, op, true);
  check(`mixed [puranic-os] ${op}/${cap}: sim(on)`, simOn.simulated_hard_decision, expSim, "wave_d_mixed");
}

// Wave E: Regression — live services unaffected by burst on puranic-os
console.log("\n── Wave E: Live HG-1 regression ──");
for (const svc of ["chirpee","ship-slm","chief-slm"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b38r3-reg" });
  logDecision(r);
  check(`[${svc}] READ: ALLOW`, r.decision, "ALLOW", "wave_e_regression");
  check(`[${svc}] READ: hard_gate`, r.enforcement_phase, "hard_gate", "wave_e_regression");
  const ri = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b38r3-reg" });
  logDecision(ri);
  check(`[${svc}] IMPOSSIBLE_OP: live BLOCK`, ri.decision, "BLOCK", "wave_e_regression");
}

// Count validation
// Wave C: 2 malformed × 5 iters = 10 TPs
console.log("\n── Count validation ──");
check("false positives = 0", totalFP, 0, "count");
check("true positives = 10", totalTP, 10, "count");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalFP === 0 && totalTP === 10 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch38_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, service: "puranic-os", date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP, production_gate_fires: totalProdFires, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 38 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
