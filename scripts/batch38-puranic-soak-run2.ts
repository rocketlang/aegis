/**
 * Batch 38 Soak Run 2/7 — puranic-os mixed-case + alias normalization
 *
 * Stress: capability name surface. Verifies that:
 *   - mixed-case inputs normalize to canonical form before policy lookup
 *   - capability aliases (run_agent→AI_EXECUTE, fetch→READ, etc.) produce
 *     correct sim(on) decision after normalization under BR-1 profile
 *   - IMPOSSIBLE_OP does not slip through under alternate casing
 *   - puranic-os domain-specific caps (PURANIC_*, SCRIPTURE_*, DHARMA_*) are
 *     unknown but never hard-BLOCK
 *
 * @rule:AEG-E-008 capability normalization before risk classification
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

const MALFORMED = new Set(["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"]);
let totalTP = 0, totalFP = 0, totalProdFires = 0;

function observe(label: string, op: string, cap: string, expSoft: string, expSim: string, cat: string) {
  const svc = "puranic-os";
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: "b38r2", session_id: `b38r2-${op}-${cap}-${Date.now()}` });
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

console.log(`\n══ Batch 38 Soak Run ${SOAK_RUN}/7 — puranic-os mixed-case + alias normalization ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  Profile: read_only, BR-1, TIER-A`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("puranic-os NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("puranic-os") ?? false, false, "pre");
check("puranic-os hard_gate_enabled = false", PURANIC_OS_HG1_POLICY.hard_gate_enabled, false, "pre");
check("puranic-os hard_block size = 2", PURANIC_OS_HG1_POLICY.hard_block_capabilities.size, 2, "pre");

// Wave A: Mixed-case READ variants
console.log("\n── Wave A: Mixed-case READ variants ──");
const mixedReadCaps = ["read","READ","Read","rEaD","get","GET","Get","list","LIST","List","query","QUERY","search","SEARCH","health","HEALTH"];
for (const cap of mixedReadCaps) {
  const op = cap.toLowerCase().replace(/[^a-z]/gi, "").substring(0, 6);
  observe(`${cap}`, op, cap, "ALLOW", "ALLOW", "wave_a_mixed_read");
}

// Wave B: Alias normalization
console.log("\n── Wave B: Capability alias normalization ──");
const aliases: [string, string, string, string][] = [
  ["get",        "fetch",       "ALLOW", "ALLOW"],  // fetch → READ → low
  ["get",        "get",         "ALLOW", "ALLOW"],  // get → READ
  ["list",       "list",        "ALLOW", "ALLOW"],  // list → READ
  ["execute",    "invoke",      "ALLOW", "ALLOW"],  // invoke → EXECUTE → high → ALLOW (BR-1)
  ["execute",    "call_tool",   "ALLOW", "ALLOW"],  // call_tool → EXECUTE
  ["write",      "create",      "ALLOW", "ALLOW"],  // create → WRITE
  ["write",      "update",      "ALLOW", "ALLOW"],  // update → WRITE
  ["write",      "patch",       "ALLOW", "ALLOW"],  // patch → WRITE
  ["write",      "upsert",      "ALLOW", "ALLOW"],  // upsert → WRITE
  ["ai-execute", "run_agent",   "GATE",  "GATE"],   // run_agent → AI_EXECUTE, op=ai-execute → critical
  ["ai-execute", "call_llm",    "GATE",  "GATE"],   // call_llm → AI_EXECUTE, op=ai-execute → critical
  ["deploy",     "rollout",     "GATE",  "GATE"],   // rollout → DEPLOY → critical
  ["deploy",     "release",     "GATE",  "GATE"],   // release → DEPLOY
  ["execute",    "accept",      "ALLOW", "ALLOW"],  // accept → APPROVE → high → ALLOW (BR-1)
  ["execute",    "confirm",     "ALLOW", "ALLOW"],  // confirm → APPROVE
  ["execute",    "authorize",   "ALLOW", "ALLOW"],  // authorize → APPROVE
];
for (const [op, cap, expSoft, expSim] of aliases) {
  observe(`alias:${cap}`, op, cap, expSoft, expSim, "wave_b_aliases");
}

// Wave C: Malformed caps — casing variants, must sim-BLOCK
console.log("\n── Wave C: Malformed true positives (casing variants) ──");
const malformedVariants: [string, string][] = [
  ["frob","IMPOSSIBLE_OP"],["frob","impossible_op"],["frob","Impossible_Op"],
  ["write","EMPTY_CAPABILITY_ON_WRITE"],["write","empty_capability_on_write"],["write","Empty_Capability_On_Write"],
];
for (const [op, cap] of malformedVariants) {
  observe(`malformed:${cap}`, op, cap, "ALLOW", "BLOCK", "wave_c_malformed");
}

// Wave D: puranic-os domain caps — unknown, never hard-BLOCK
console.log("\n── Wave D: Puranic domain caps (unknown, never BLOCK) ──");
const domainCaps = [
  ["execute","PURANIC_QUERY"],
  ["execute","SCRIPTURE_LOOKUP"],
  ["execute","DHARMA_INFER"],
  ["execute","KARMA_CLASSIFY"],
  ["execute","ATMAN_RETRIEVE"],
  ["execute","SMRITI_RECALL"],
  ["execute","YUGA_ASSESS"],
];
for (const [op, cap] of domainCaps) {
  const d = evaluate({ service_id: "puranic-os", operation: op, requested_capability: cap, caller_id: "b38r2-domain" });
  logDecision(d);
  check(`domain cap [puranic-os] ${cap}: not BLOCK`, d.decision !== "BLOCK", true, "wave_d_domain");
  const simOff = simulateHardGate("puranic-os", d.decision, cap, op, false);
  check(`domain cap [puranic-os] ${cap}: no prod fire`, simOff.hard_gate_would_apply, false, "wave_d_domain");
  if (simOff.hard_gate_would_apply) totalProdFires++;
}

// Count validation
// Wave C: 6 malformed × 1 service = 6 TPs
console.log("\n── Count validation ──");
check("false positives = 0", totalFP, 0, "count");
check("true positives = 6", totalTP, 6, "count");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalFP === 0 && totalTP === 6 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch38_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, service: "puranic-os", date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP, production_gate_fires: totalProdFires, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 38 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
