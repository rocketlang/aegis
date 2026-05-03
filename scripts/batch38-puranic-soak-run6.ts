/**
 * Batch 38 Soak Run 6/7 — Boundary conditions (puranic-os)
 *
 * Stress: risk-tier boundaries specific to BR-1 profile.
 * Validates the precise transition points between ALLOW/GATE/BLOCK
 * under puranic-os's authority_class and blast_radius.
 *
 * Key boundaries tested:
 *   - high-risk ops with op="execute": brNum=1 < 3 → ALLOW (not GATE)
 *   - critical-risk ops: GATE regardless of BR-1
 *   - still_gate: BLOCK→GATE, never ALLOW→GATE (downgrade guard)
 *   - hard_block: BLOCK regardless (IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE)
 *   - never_block: READ never BLOCKs even under worst-case policy
 *   - multi-caller / multi-session isolation (same cap, different callers)
 *
 * @rule:AEG-B-001 blast_radius < 3 exempts high-risk from hard-gate escalation
 * @rule:AEG-YK-008 still_gate is a downgrade guard only
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

const SOAK_RUN = 6;
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
let still_gate_upgrades = 0;
let reads_that_blocked = 0;

function observe(svc: string, label: string, op: string, cap: string, expSoft: string, expSim: string, cat: string) {
  const d = evaluate({
    service_id: svc, operation: op, requested_capability: cap,
    caller_id: `b38r6-${Math.random().toString(36).substring(2,6)}`,
    session_id: `b38r6-${svc}-${op}-${cap}-${Date.now()}`
  });
  logDecision(d);
  check(`soft [${svc}] ${label}`, d.decision, expSoft, cat);
  check(`phase [${svc}] ${label}`, d.enforcement_phase, "soft_canary", cat);
  const simOff = simulateHardGate(svc, d.decision, cap, op, false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`sim(off) [${svc}] ${label}: no fire`, simOff.hard_gate_would_apply, false, cat);
  const simOn = simulateHardGate(svc, d.decision, cap, op, true);
  check(`sim(on)  [${svc}] ${label}`, simOn.simulated_hard_decision, expSim, cat);
  const isMalformed = MALFORMED.has(cap.toUpperCase());
  if (simOn.simulated_hard_decision === "BLOCK" && !isMalformed) totalFP++;
  if (simOn.simulated_hard_decision === "BLOCK" &&  isMalformed) totalTP++;
  if (d.decision === "ALLOW" && simOn.simulated_hard_decision === "GATE") still_gate_upgrades++;
  if ((cap.toUpperCase() === "READ" || op === "read") && d.decision === "BLOCK") reads_that_blocked++;
}

console.log(`\n══ Batch 38 Soak Run ${SOAK_RUN}/7 — Boundary conditions ══`);
console.log(`  Date: ${RUN_DATE}  |  puranic-os profile: read_only, BR-1`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("puranic-os NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("puranic-os") ?? false, false, "pre");
check("puranic-os hard_gate_enabled = false", PURANIC_OS_HG1_POLICY.hard_gate_enabled, false, "pre");

// Wave A: high-risk ops — op="execute" → brNum=1 < 3 → ALLOW
console.log("\n── Wave A: high-risk ops (BR-1 exemption) ──");
const highOps: [string, string][] = [
  ["execute", "EXECUTE"],
  ["execute", "FULL_AUTONOMY"],
  ["execute", "SPAWN_AGENTS"],
  ["execute", "MEMORY_WRITE"],
  ["execute", "AUDIT_WRITE"],
  ["approve", "APPROVE"],
  ["trigger", "TRIGGER"],
  ["execute", "EMIT"],
];
for (const [op, cap] of highOps) {
  observe("puranic-os", `high:${cap}`, op, cap, "ALLOW", "ALLOW", "wave_a_high");
}

// Wave B: critical-risk ops — GATE regardless of BR
console.log("\n── Wave B: critical ops (GATE regardless of BR-1) ──");
const critOps: [string, string][] = [
  ["ai-execute", "AI_EXECUTE"],
  ["deploy",     "CI_DEPLOY"],
  ["delete",     "DELETE"],
  ["ai-execute", "run_agent"],   // alias → AI_EXECUTE
  ["deploy",     "rollout"],     // alias → DEPLOY
];
for (const [op, cap] of critOps) {
  observe("puranic-os", `crit:${cap}`, op, cap, "GATE", "GATE", "wave_b_crit");
}

// Wave C: still_gate boundary — BLOCK input → GATE output (downgrade guard)
console.log("\n── Wave C: still_gate downgrade guard ──");
// Only way to test still_gate directly is via simulateHardGate with softDecision="BLOCK"
// Caps in still_gate_capabilities: CI_DEPLOY, DELETE, EXECUTE, APPROVE, AI_EXECUTE, etc.
const stillGateCaps = ["CI_DEPLOY", "DELETE", "EXECUTE", "APPROVE", "AI_EXECUTE", "FULL_AUTONOMY", "TRIGGER"];
for (const cap of stillGateCaps) {
  const simOn = simulateHardGate("puranic-os", "BLOCK", cap, "execute", true);
  check(`still_gate [${cap}]: BLOCK→GATE`, simOn.simulated_hard_decision, "GATE", "wave_c_still_gate");
  check(`still_gate [${cap}]: not raw BLOCK`, simOn.simulated_hard_decision !== "BLOCK", true, "wave_c_still_gate");
}
// Still_gate must NOT fire for ALLOW inputs
for (const cap of ["READ", "GET", "LIST", "WRITE"]) {
  const simOn = simulateHardGate("puranic-os", "ALLOW", cap, "read", true);
  check(`still_gate [${cap}]: ALLOW stays ALLOW`, simOn.simulated_hard_decision, "ALLOW", "wave_c_still_gate");
}

// Wave D: never_block invariant — READ never BLOCKs
console.log("\n── Wave D: never_block invariant ──");
for (const caller of ["sys-1","sys-2","sys-3","anon","b38r6-attacker"]) {
  const d = evaluate({
    service_id: "puranic-os", operation: "read", requested_capability: "READ",
    caller_id: caller, session_id: `b38r6-nb-${caller}`
  });
  logDecision(d);
  check(`never_block READ [${caller}]: not BLOCK`, d.decision !== "BLOCK", true, "wave_d_never_block");
  if (d.decision === "BLOCK") reads_that_blocked++;
}

// Wave E: multi-caller isolation (same cap, different sessions)
console.log("\n── Wave E: multi-caller isolation ──");
const multiCallers = Array.from({length: 8}, (_, i) => `caller-${i}`);
for (const caller of multiCallers) {
  const d = evaluate({
    service_id: "puranic-os", operation: "ai-execute", requested_capability: "AI_EXECUTE",
    caller_id: caller, session_id: `b38r6-mc-${caller}-${Date.now()}`
  });
  logDecision(d);
  check(`multi-caller [${caller}] AI_EXECUTE: GATE`, d.decision, "GATE", "wave_e_multi");
  check(`multi-caller [${caller}] AI_EXECUTE: soft_canary`, d.enforcement_phase, "soft_canary", "wave_e_multi");
  const simOff = simulateHardGate("puranic-os", d.decision, "AI_EXECUTE", "ai-execute", false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`multi-caller [${caller}] sim(off): no fire`, simOff.hard_gate_would_apply, false, "wave_e_multi");
}

// Wave F: hard_block invariant — IMPOSSIBLE_OP / EMPTY must sim BLOCK
console.log("\n── Wave F: hard_block invariant ──");
for (const cap of ["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"]) {
  for (const sofDec of ["ALLOW", "GATE", "BLOCK"]) {
    const simOn = simulateHardGate("puranic-os", sofDec, cap, "write", true);
    check(`hard_block [${cap}] from soft=${sofDec}: BLOCK`, simOn.simulated_hard_decision, "BLOCK", "wave_f_hard_block");
  }
}

// Live HG-1 regression
console.log("\n── Live HG-1 regression ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b38r6-reg" });
  logDecision(r);
  check(`${svc} READ: hard_gate`, r.enforcement_phase, "hard_gate", "regression");
  const bi = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b38r6-reg" });
  logDecision(bi);
  check(`${svc} IMPOSSIBLE_OP: live BLOCK`, bi.decision, "BLOCK", "regression");
}

// Invariant summary
console.log("\n── Invariant validation ──");
check("reads_that_blocked = 0", reads_that_blocked, 0, "invariant");
check("still_gate upgrades = 0", still_gate_upgrades, 0, "invariant");
check("false positives = 0", totalFP, 0, "count");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalFP === 0 && reads_that_blocked === 0 && still_gate_upgrades === 0 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch38_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN, date: RUN_DATE,
  verdict: soakPass ? "PASS" : "FAIL",
  checks: totalChecks, passed, failed,
  true_positives: totalTP, false_positives: totalFP,
  production_gate_fires: totalProdFires,
  reads_that_blocked, still_gate_upgrades,
  ready_to_promote_puranic_os: false,
}, null, 2));
console.log(`\n  Batch 38 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
