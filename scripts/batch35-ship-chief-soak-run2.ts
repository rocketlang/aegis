/**
 * Batch 35 Soak Run 2/7 — Mixed-case + alias normalization
 *
 * Stress: capability name surface. Verifies that:
 *   - mixed-case inputs normalize to canonical form before policy lookup
 *   - capability aliases (run_agent→AI_EXECUTE, invoke→EXECUTE, fetch→READ, etc.)
 *     produce the correct sim(on) decision after normalization
 *   - IMPOSSIBLE_OP does not slip through under alternate casing
 *
 * @rule:AEG-E-008 capability normalization before risk classification
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

const SOAK_RUN = 2;
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
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: "b35r2", session_id: `b35r2-${svc}-${op}-${cap}-${Date.now()}` });
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
  if (simOn.simulated_hard_decision === "BLOCK" && isMalformed) totalTP++;
}

console.log(`\n══ Batch 35 Soak Run ${SOAK_RUN}/7 — Mixed-case + alias normalization ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("AEGIS_HARD_GATE_SERVICES = chirpee only", process.env.AEGIS_HARD_GATE_SERVICES, "chirpee", "pre");
check("chirpee in env (call-time)", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("chirpee") ?? false, true, "pre");
check("ship-slm NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("ship-slm") ?? false, false, "pre");
check("ship-slm hard_gate_enabled = false", SHIP_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chief-slm hard_gate_enabled = false", CHIEF_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");

// Wave A: Mixed-case capability names — normalize to READ/WRITE canonical
// "read" / "READ" / "Read" all route to op_risk=low → ALLOW
console.log("\n── Wave A: Mixed-case READ variants ──");
const mixedReadCaps = ["read","READ","Read","rEaD","get","GET","Get","list","LIST","List","query","QUERY","search","SEARCH"];
for (const svc of ["ship-slm","chief-slm"]) {
  for (const cap of mixedReadCaps) {
    const op = cap.toLowerCase().replace(/[^a-z]/gi, "").substring(0,6);
    observe(svc, `${cap}`, op, cap, "ALLOW", "ALLOW", "wave_a_mixed_read");
  }
}

// Wave B: Alias normalization — capability aliases in CAPABILITY_ALIASES map
// After normalization: fetch→READ, invoke→EXECUTE, run_agent→AI_EXECUTE, etc.
console.log("\n── Wave B: Capability alias normalization ──");
const aliases: [string, string, string, string][] = [
  // [op, cap_alias, expected_soft, expected_sim]
  ["get",     "fetch",      "ALLOW", "ALLOW"],  // fetch → READ → op_risk=low
  ["get",     "get",        "ALLOW", "ALLOW"],  // get → READ
  ["list",    "list",       "ALLOW", "ALLOW"],  // list → READ
  ["execute", "invoke",     "ALLOW", "ALLOW"],  // invoke → EXECUTE → high on read_only+BR-0 = ALLOW
  ["execute", "call_tool",  "ALLOW", "ALLOW"],  // call_tool → EXECUTE
  ["write",   "create",     "ALLOW", "ALLOW"],  // create → WRITE
  ["write",   "update",     "ALLOW", "ALLOW"],  // update → WRITE
  ["write",   "patch",      "ALLOW", "ALLOW"],  // patch → WRITE
  ["write",   "upsert",     "ALLOW", "ALLOW"],  // upsert → WRITE
  ["ai-execute", "run_agent",  "GATE",  "GATE"],   // run_agent → AI_EXECUTE (alias), op=ai-execute → critical → GATE
  ["ai-execute", "call_llm",   "GATE",  "GATE"],   // call_llm → AI_EXECUTE (alias), op=ai-execute → critical → GATE
  ["deploy",  "rollout",    "GATE",  "GATE"],   // rollout → DEPLOY → critical → GATE
  ["deploy",  "release",    "GATE",  "GATE"],   // release → DEPLOY
  ["execute", "accept",     "ALLOW", "ALLOW"],  // accept → APPROVE → high → ALLOW (read_only+BR-0)
  ["execute", "confirm",    "ALLOW", "ALLOW"],  // confirm → APPROVE
  ["execute", "authorize",  "ALLOW", "ALLOW"],  // authorize → APPROVE
];
for (const svc of ["ship-slm","chief-slm"]) {
  for (const [op, cap, expSoft, expSim] of aliases) {
    observe(svc, `alias:${cap}`, op, cap, expSoft, expSim, "wave_b_aliases");
  }
}

// Wave C: Malformed caps — must sim-BLOCK regardless of casing (normalization handles it)
console.log("\n── Wave C: Malformed true positives (casing variants) ──");
// normalization: cap.toUpperCase().trim() in applyHardGate — so these all hit the same entry
const malformedVariants: [string, string][] = [
  ["frob","IMPOSSIBLE_OP"],["frob","impossible_op"],["frob","Impossible_Op"],
  ["write","EMPTY_CAPABILITY_ON_WRITE"],["write","empty_capability_on_write"],["write","Empty_Capability_On_Write"],
];
for (const svc of ["ship-slm","chief-slm"]) {
  for (const [op, cap] of malformedVariants) {
    observe(svc, `malformed:${cap}`, op, cap, "ALLOW", "BLOCK", "wave_c_malformed");
  }
}

// Chirpee regression
console.log("\n── Chirpee regression ──");
const cr = evaluate({ service_id: "chirpee", operation: "read", requested_capability: "READ", caller_id: "b35r2-reg" });
logDecision(cr);
check("chirpee READ → ALLOW", cr.decision, "ALLOW", "regression");
check("chirpee READ → hard_gate phase", cr.enforcement_phase, "hard_gate", "regression");
const ci = evaluate({ service_id: "chirpee", operation: "frob_impossible", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r2-reg" });
logDecision(ci);
check("chirpee IMPOSSIBLE_OP → live BLOCK", ci.decision, "BLOCK", "regression");
check("chirpee IMPOSSIBLE_OP → hard_gate_applied", ci.hard_gate_applied, true, "regression");

// Count validation
console.log("\n── Count validation ──");
// Wave C: 6 malformed × 2 services = 12 TPs
check("false positives = 0", totalFP, 0, "count");
check("true positives = 12", totalTP, 12, "count");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalFP === 0 && totalTP === 12 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch35_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP, production_gate_fires: totalProdFires, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 35 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
