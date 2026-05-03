/**
 * Batch 35 Soak Run 3/7 — Burst traffic + repeated malformed
 *
 * Stress: volume and repetition. Verifies that:
 *   - repeated IMPOSSIBLE_OP does not degrade (same decision every time)
 *   - burst reads produce no accumulating state side effects
 *   - repeated EMPTY_CAP_ON_WRITE is stable
 *   - sim(off) never fires regardless of call count
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, SHIP_SLM_HG1_POLICY, CHIEF_SLM_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
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

const MALFORMED = new Set(["IMPOSSIBLE_OP","EMPTY_CAPABILITY_ON_WRITE"]);
let totalTP = 0, totalFP = 0, totalProdFires = 0;

function observe(svc: string, label: string, op: string, cap: string, expSoft: string, expSim: string, cat: string) {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: "b35r3", session_id: `b35r3-${svc}-${Date.now()}` });
  logDecision(d);
  check(`soft [${svc}] ${label}`, d.decision, expSoft, cat);
  const simOff = simulateHardGate(svc, d.decision, cap, op, false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`sim(off) [${svc}] ${label}: no fire`, simOff.hard_gate_would_apply, false, cat);
  const simOn = simulateHardGate(svc, d.decision, cap, op, true);
  check(`sim(on)  [${svc}] ${label}`, simOn.simulated_hard_decision, expSim, cat);
  const isMalformed = MALFORMED.has(cap.toUpperCase());
  if (simOn.simulated_hard_decision === "BLOCK" && !isMalformed) totalFP++;
  if (simOn.simulated_hard_decision === "BLOCK" && isMalformed) totalTP++;
}

console.log(`\n══ Batch 35 Soak Run ${SOAK_RUN}/7 — Burst traffic + repeated malformed ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("chirpee in env (call-time)", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("chirpee") ?? false, true, "pre");
check("ship-slm not in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("ship-slm") ?? false, false, "pre");
check("ship-slm hard_gate_enabled = false", SHIP_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chief-slm hard_gate_enabled = false", CHIEF_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");

// Wave A: Read burst — 4 sessions × 6 ops × 2 services
console.log("\n── Wave A: Read burst (4 sessions) ──");
for (let s = 1; s <= 4; s++) {
  for (const svc of ["ship-slm","chief-slm"]) {
    for (const [op,cap] of [["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"],["search","SEARCH"],["health","HEALTH"]] as [string,string][]) {
      observe(svc, `${op}[s${s}]`, op, cap, "ALLOW", "ALLOW", "wave_a_burst_read");
    }
  }
}

// Wave B: Write burst — 3 sessions × 3 ops × 2 services
console.log("\n── Wave B: Write burst (3 sessions) ──");
for (let s = 1; s <= 3; s++) {
  for (const svc of ["ship-slm","chief-slm"]) {
    for (const [op,cap] of [["write","WRITE"],["create","WRITE"],["update","WRITE"]] as [string,string][]) {
      observe(svc, `${op}[s${s}]`, op, cap, "ALLOW", "ALLOW", "wave_b_burst_write");
    }
  }
}

// Wave C: Repeated IMPOSSIBLE_OP — 10 per service (stability check)
// Same result every time: soft=ALLOW, sim=BLOCK. No degradation.
console.log("\n── Wave C: Repeated IMPOSSIBLE_OP (10×) ──");
for (const svc of ["ship-slm","chief-slm"]) {
  for (let i = 1; i <= 10; i++) {
    observe(svc, `IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP", "ALLOW", "BLOCK", "wave_c_burst_malformed");
  }
}

// Wave D: Repeated EMPTY_CAPABILITY_ON_WRITE — 8 per service
console.log("\n── Wave D: Repeated EMPTY_CAPABILITY_ON_WRITE (8×) ──");
for (const svc of ["ship-slm","chief-slm"]) {
  for (let i = 1; i <= 8; i++) {
    observe(svc, `EMPTY_CAP[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave_d_burst_empty");
  }
}

// Wave E: Critical op burst — no accumulation, no degradation
console.log("\n── Wave E: Critical op burst ──");
for (let s = 1; s <= 2; s++) {
  for (const svc of ["ship-slm","chief-slm"]) {
    for (const [op,cap] of [["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"]] as [string,string][]) {
      observe(svc, `${op}[s${s}]`, op, cap, "GATE", "GATE", "wave_e_burst_critical");
    }
  }
}

// Chirpee regression
console.log("\n── Chirpee regression ──");
const cr = evaluate({ service_id: "chirpee", operation: "read", requested_capability: "READ", caller_id: "b35r3-reg" });
logDecision(cr);
check("chirpee READ → ALLOW hard_gate", cr.decision, "ALLOW", "regression");
const ci = evaluate({ service_id: "chirpee", operation: "frob_impossible", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r3-reg" });
logDecision(ci);
check("chirpee IMPOSSIBLE_OP → live BLOCK", ci.decision, "BLOCK", "regression");
check("chirpee IMPOSSIBLE_OP → hard_gate_applied", ci.hard_gate_applied, true, "regression");

// Count validation
// Wave C: 10 × 2 = 20 TPs; Wave D: 8 × 2 = 16 TPs; total = 36
console.log("\n── Count validation ──");
check("false positives = 0", totalFP, 0, "count");
check("true positives = 36", totalTP, 36, "count");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalFP === 0 && totalTP === 36 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch35_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP, production_gate_fires: totalProdFires, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 35 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
