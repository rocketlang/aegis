/**
 * Batch 42 Soak Run 2/7 — mixed-case capabilities + alias normalization
 *
 * Verifies that capability normalization (AEG-E-008) works correctly for pramana:
 *   - lowercase/mixed-case variants still route correctly
 *   - aliases (run_agent→AI_EXECUTE, call_llm→AI_EXECUTE, invoke→EXECUTE, fetch→READ)
 *   - IMPOSSIBLE_OP / EMPTY_CAP in lowercase → still TP in simulation
 *   - BR-5 gate behavior consistent under alias normalization
 *
 * @rule:AEG-E-008 normalize capability before classification
 * @rule:AEG-HG-001 pramana not live — soft_canary phase throughout
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED } from "../src/enforcement/hard-gate-policy";
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

let simTPs = 0, prodFires = 0;

console.log(`\n══ Batch 42 Soak Run ${SOAK_RUN}/7 — mixed-case + alias normalization ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), false, "pre");

// HG-1 regression
console.log("\n── HG-1 regression ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r2-reg" });
  logDecision(r);
  check(`[${svc}] READ: hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r2-reg" });
  logDecision(b);
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
}

// ── Mixed-case READ variants ──────────────────────────────────────────────────
console.log("\n── Mixed-case READ variants ──");
for (const cap of ["READ", "read", "Read", "rEaD", "GET", "get", "Get", "LIST", "list"]) {
  const op = cap.toLowerCase().split("_")[0] === "get" ? "get" : cap.toLowerCase().startsWith("list") ? "list" : "read";
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r2-case" });
  logDecision(d);
  check(`pramana [${cap}]: soft_canary + ALLOW`, d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "mixed_case");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana [${cap}]: sim(on) → ALLOW (never_block)`, sim.simulated_hard_decision, "ALLOW", "mixed_case");
  if (sim.hard_gate_would_apply) prodFires++;
}

// ── Alias normalization: READ aliases ────────────────────────────────────────
console.log("\n── Read-class alias normalization ──");
for (const [op, cap] of [
  ["fetch",  "FETCH"],
  ["get",    "GET"],
  ["list",   "LIST"],
  ["search", "search"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r2-alias" });
  logDecision(d);
  check(`pramana alias [${cap}]: soft_canary + ALLOW`, d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "alias");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Alias normalization: critical-class aliases → GATE ───────────────────────
console.log("\n── Critical-class alias normalization ──");
// run_agent / call_llm → AI_EXECUTE → critical → GATE
for (const [op, cap] of [
  ["run_agent",  "run_agent"],
  ["call_llm",   "call_llm"],
  ["run-agent",  "run-agent"],
  ["call-llm",   "call-llm"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r2-alias" });
  logDecision(d);
  check(`pramana [${cap}] → AI_EXECUTE: soft_canary`, d.enforcement_phase, "soft_canary", "alias");
  check(`pramana [${cap}] → AI_EXECUTE: GATE (critical op via alias)`, d.decision, "GATE", "alias");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  // AI_EXECUTE is in still_gate; soft=GATE; still_gate only fires on BLOCK → sim preserves GATE
  check(`pramana [${cap}] sim(on): GATE → GATE (still_gate no-upgrade)`, sim.simulated_hard_decision, "GATE", "alias");
  if (sim.hard_gate_would_apply) prodFires++;
}

// invoke / tool_call / call_tool → EXECUTE → high → GATE (BR-5 ≥ 3)
for (const [op, cap] of [
  ["invoke",    "invoke"],
  ["tool_call", "tool_call"],
  ["tool-call", "tool-call"],
  ["call_tool", "call_tool"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r2-alias" });
  logDecision(d);
  check(`pramana [${cap}] → EXECUTE: GATE (high op, BR-5)`, d.decision, "GATE", "alias");
  check(`pramana [${cap}] → EXECUTE: soft_canary`, d.enforcement_phase, "soft_canary", "alias");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Mixed-case true positives ─────────────────────────────────────────────────
console.log("\n── Mixed-case true positive detection ──");
for (const [op, cap] of [
  ["frob", "IMPOSSIBLE_OP"],
  ["frob", "impossible_op"],
  ["frob", "Impossible_Op"],
  ["write", "EMPTY_CAPABILITY_ON_WRITE"],
  ["write", "empty_capability_on_write"],
  ["write", "Empty_Capability_On_Write"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r2-tp" });
  logDecision(d);
  check(`pramana [${cap}]: live soft_canary + ALLOW`, d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "tp");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana [${cap}]: sim(on) → BLOCK (TP)`, sim.simulated_hard_decision, "BLOCK", "tp");
  if (sim.hard_gate_would_apply) simTPs++;
}

// ── Mixed-case still_gate caps ────────────────────────────────────────────────
console.log("\n── Mixed-case still_gate caps ──");
for (const [op, cap] of [
  ["execute",  "EXECUTE"],
  ["execute",  "execute"],
  ["execute",  "Execute"],
  ["deploy",   "CI_DEPLOY"],
  ["deploy",   "ci_deploy"],
  ["approve",  "APPROVE"],
  ["approve",  "approve"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r2-still" });
  logDecision(d);
  check(`pramana [${cap}]: soft_canary + GATE`, d.enforcement_phase === "soft_canary" && d.decision === "GATE", true, "still_gate");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  // still_gate with soft=GATE (not BLOCK) → preserves GATE
  check(`pramana [${cap}]: sim(on) GATE → GATE (no upgrade)`, sim.simulated_hard_decision, "GATE", "still_gate");
  if (sim.hard_gate_would_apply) prodFires++;
}

// ── Unknown caps (mixed-case, weird) ──────────────────────────────────────────
console.log("\n── Unknown caps — no hard-block ──");
for (const [op, cap] of [
  ["frob", "SOME_UNKNOWN_CAP"],
  ["frob", "some_unknown_cap"],
  ["frob", "Unknown-Cap-123"],
  ["write", "PARTIAL_WRITE"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r2-unk" });
  check(`pramana unknown [${cap}]: soft_canary (not hard_gate)`, d.enforcement_phase, "soft_canary", "unknown");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana unknown [${cap}]: sim(on) → not BLOCK (unknown cap safe)`, sim.simulated_hard_decision !== "BLOCK", true, "unknown");
  if (sim.hard_gate_would_apply) prodFires++;
}

console.log("\n── Count validation ──");
check(`simulation TPs = 6 (3× IMPOSSIBLE_OP + 3× EMPTY_CAP)`, simTPs, 6, "count");
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
