/**
 * Batch 38 Soak Run 7/7 — Final verdict (puranic-os)
 *
 * Loads all 6 prior run metrics. If all 6 passed: promotion_permitted=true.
 * Does not promote — human decides when to add puranic-os to
 * AEGIS_HARD_GATE_SERVICES and set hard_gate_enabled=true in policy.
 *
 * This is the dress rehearsal: one final full traffic sweep before the verdict.
 *
 * @rule:AEG-HG-001 promotion requires 7/7 soak pass + human approval
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PURANIC_OS_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const SOAK_RUN = 7;
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

function loadRunResult(run: number): { verdict: string } | null {
  try {
    const raw = readFileSync(join(dir, `batch38_soak_run${run}_metrics.json`), "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

const MALFORMED = new Set(["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"]);
let totalTP = 0, totalFP = 0, totalProdFires = 0;

function observe(svc: string, label: string, op: string, cap: string, expSoft: string, expSim: string, cat: string) {
  const d = evaluate({
    service_id: svc, operation: op, requested_capability: cap,
    caller_id: "b38r7", session_id: `b38r7-${svc}-${op}-${cap}-${Date.now()}`
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
}

console.log(`\n══ Batch 38 Soak Run ${SOAK_RUN}/7 — Final verdict ══`);
console.log(`  Date: ${RUN_DATE}  |  puranic-os profile: read_only, BR-1`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("puranic-os NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("puranic-os") ?? false, false, "pre");
check("puranic-os hard_gate_enabled = false", PURANIC_OS_HG1_POLICY.hard_gate_enabled, false, "pre");
check("puranic-os rollout_order = 4", PURANIC_OS_HG1_POLICY.rollout_order, 4, "pre");

// Load prior runs
console.log("\n── Prior run history ──");
let priorPassCount = 0;
for (let r = 1; r <= 6; r++) {
  const result = loadRunResult(r);
  const verdict = result?.verdict ?? "MISSING";
  const ok = verdict === "PASS";
  if (ok) priorPassCount++;
  check(`Run ${r}/7: ${verdict}`, verdict, "PASS", "history");
}
check(`Prior runs: ${priorPassCount}/6 PASS`, priorPassCount, 6, "history");

// Final dress-rehearsal sweep
console.log("\n── Final sweep: reads ──");
for (const [op, cap] of [["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"],["search","SEARCH"],["health","HEALTH"]]) {
  observe("puranic-os", `${op}/${cap}`, op, cap, "ALLOW", "ALLOW", "final_read");
}

console.log("\n── Final sweep: writes ──");
for (const [op, cap] of [["write","WRITE"],["create","WRITE"],["update","WRITE"]]) {
  observe("puranic-os", `${op}/${cap}`, op, cap, "ALLOW", "ALLOW", "final_write");
}

console.log("\n── Final sweep: critical ops ──");
for (const [op, cap] of [["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"]]) {
  observe("puranic-os", `${op}/${cap}`, op, cap, "GATE", "GATE", "final_crit");
}

console.log("\n── Final sweep: high ops (BR-1 ALLOW) ──");
for (const [op, cap] of [["execute","EXECUTE"],["execute","APPROVE"],["trigger","TRIGGER"]]) {
  observe("puranic-os", `${op}/${cap}`, op, cap, "ALLOW", "ALLOW", "final_high");
}

console.log("\n── Final sweep: malformed TPs ──");
observe("puranic-os", "IMPOSSIBLE_OP",           "frob",  "IMPOSSIBLE_OP",           "ALLOW", "BLOCK", "final_tp");
observe("puranic-os", "EMPTY_CAPABILITY_ON_WRITE","write", "EMPTY_CAPABILITY_ON_WRITE","ALLOW", "BLOCK", "final_tp");

// Live HG-1 regression
console.log("\n── Live HG-1 regression ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b38r7-reg" });
  logDecision(r);
  check(`${svc} READ: hard_gate`, r.enforcement_phase, "hard_gate", "regression");
  check(`${svc} READ: ALLOW`, r.decision, "ALLOW", "regression");
  const bi = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b38r7-reg" });
  logDecision(bi);
  check(`${svc} IMPOSSIBLE_OP: live BLOCK`, bi.decision, "BLOCK", "regression");
}

// Final count validation
console.log("\n── Final count validation ──");
check("false positives = 0", totalFP, 0, "count");
check("true positives = 2", totalTP, 2, "count");
check("production fires = 0", totalProdFires, 0, "count");

const run7Pass = failed === 0 && totalFP === 0 && totalTP === 2 && totalProdFires === 0;
const soakComplete = run7Pass && priorPassCount === 6;
const promotion_permitted_puranic_os = soakComplete;

console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${run7Pass ? "PASS" : "FAIL"}`);
console.log(`\n  Prior runs:                  ${priorPassCount}/6 PASS`);
console.log(`  Run 7 verdict:               ${run7Pass ? "PASS" : "FAIL"}`);
console.log(`  Soak complete (7/7):         ${soakComplete}`);
console.log(`  promotion_permitted_puranic_os: ${promotion_permitted_puranic_os}`);
console.log(`  hard_gate_enabled_puranic_os:   ${PURANIC_OS_HG1_POLICY.hard_gate_enabled} (human promotes in Batch 39)`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch38_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN, date: RUN_DATE,
  verdict: run7Pass ? "PASS" : "FAIL",
  checks: totalChecks, passed, failed,
  true_positives: totalTP, false_positives: totalFP,
  production_gate_fires: totalProdFires,
  prior_runs_passed: priorPassCount,
  soak_complete: soakComplete,
  promotion_permitted_puranic_os,
  hard_gate_enabled_puranic_os: PURANIC_OS_HG1_POLICY.hard_gate_enabled,
}, null, 2));
console.log(`\n  Batch 38 Run ${SOAK_RUN}/7: ${run7Pass ? "PASS" : "FAIL"}`);
console.log(`\n  Seven watches complete. The fourth guard has passed the range.`);
console.log(`  Promotion decision: ${promotion_permitted_puranic_os ? "PERMITTED (awaiting human gate)" : "NOT YET"}.`);
