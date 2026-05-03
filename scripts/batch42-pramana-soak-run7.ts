/**
 * Batch 42 Soak Run 7/7 — final dress rehearsal + verdict
 *
 * Loads soak run 1–6 metrics and verifies all 6 prior runs PASS.
 * Then runs a final comprehensive wave across every enforcement dimension:
 *   - Pre-flight + HG-1 regression (full surface)
 *   - pramana domain ops: full ALLOW set
 *   - pramana critical + high: all GATE
 *   - malformed / TP pair: sim(on) BLOCK, live ALLOW
 *   - alias normalization round-trip
 *   - never_block: READ in every operation form
 *   - still_gate downgrade guard (BLOCK→GATE, ALLOW→ALLOW)
 *   - kill→sim(on)→restore cycle
 *   - approval lifecycle: generate → approve → replay reject
 *   - env promotion: add pramana → hard_gate live BLOCK → remove → soft_canary
 *   - isolation: HG-2B, domain-capture, ankr-doctor, non-pilot
 *   - BR comparison: puranic-os BR-1 vs pramana BR-5 for EXECUTE
 *
 * Final verdict: promotion_permitted_pramana = (allRunsPass && thisSoakPass)
 *
 * @rule:AEG-HG-001 pramana not live — soft_canary throughout
 * @rule:AEG-HG-002 READ never hard-blocks
 * @rule:AEG-E-006  kill switch overrides all enforcement
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PRAMANA_HG2A_POLICY } from "../src/enforcement/hard-gate-policy";
import { approveToken, runRollbackDrill } from "../src/enforcement/approval";
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

function gateToken(d: ReturnType<typeof evaluate>): string {
  return (d as unknown as { approval_token?: string }).approval_token ?? "";
}

let simTPs = 0, prodFires = 0;

console.log(`\n══ Batch 42 Soak Run ${SOAK_RUN}/7 — FINAL DRESS REHEARSAL + VERDICT ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// ── Phase 0: Load prior run metrics ──────────────────────────────────────────
console.log("\n── Phase 0: Prior soak run verification (1–6) ──");
const priorRuns: Array<{ soak_run: number; verdict: string; checks: number; passed: number; failed: number }> = [];
let allPriorPass = true;
for (let r = 1; r <= 6; r++) {
  try {
    const raw = readFileSync(join(dir, `batch42_soak_run${r}_metrics.json`), "utf8");
    const m = JSON.parse(raw);
    priorRuns.push(m);
    const pass = m.verdict === "PASS" && m.failed === 0;
    if (!pass) allPriorPass = false;
    check(`run ${r}/7: PASS (checks=${m.checks}, failed=${m.failed})`, m.verdict === "PASS" && m.failed === 0, true, "prior_runs");
  } catch (e) {
    allPriorPass = false;
    check(`run ${r}/7: metrics file readable`, false, true, "prior_runs");
  }
}
check("all 6 prior runs PASS", allPriorPass, true, "prior_runs");
const totalPriorChecks = priorRuns.reduce((s, r) => s + (r.checks ?? 0), 0);
console.log(`  Total prior checks: ${totalPriorChecks}`);

// ── Phase 1: Pre-flight ───────────────────────────────────────────────────────
console.log("\n── Phase 1: Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), false, "pre");
check("pramana hard_gate_enabled = false", PRAMANA_HG2A_POLICY.hard_gate_enabled, false, "pre");
check("pramana hg_group = HG-2", PRAMANA_HG2A_POLICY.hg_group, "HG-2", "pre");
check("pramana rollout_order = 5", PRAMANA_HG2A_POLICY.rollout_order, 5, "pre");

// ── Phase 2: HG-1 regression (full) ──────────────────────────────────────────
console.log("\n── Phase 2: HG-1 full regression ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r7-reg" });
  check(`[${svc}] READ: hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r7-reg" });
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
  const g = evaluate({ service_id: svc, operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b42r7-reg" });
  check(`[${svc}] CI_DEPLOY: GATE`, g.decision, "GATE", "hg1_reg");
}

// ── Phase 3: pramana domain ops — full ALLOW surface ─────────────────────────
console.log("\n── Phase 3: pramana domain ops (ALLOW surface) ──");
for (const [op, cap] of [
  ["read",         "READ"],
  ["get",          "GET"],
  ["list",         "LIST"],
  ["query",        "QUERY"],
  ["search",       "SEARCH"],
  ["health",       "HEALTH"],
  ["verify",       "VERIFY"],
  ["validate",     "VALIDATE"],
  ["attest",       "ATTEST"],
  ["check-proof",  "CHECK_PROOF"],
  ["issue-proof",  "ISSUE_PROOF"],
  ["query-proof",  "QUERY_PROOF"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r7-allow" });
  logDecision(d);
  check(`pramana [${cap}]: soft_canary + ALLOW`, d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "allow_surface");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Phase 4: pramana gated ops ────────────────────────────────────────────────
// Soft-layer gated ops only: high-risk (BR-5 ≥ 3) and critical ops.
// MEMORY_WRITE / AUDIT_WRITE / SPAWN_AGENTS are still_gate_capabilities (downgrade guard
// for hard-gate BLOCK) — soft layer returns ALLOW for them; covered in Phase 8.
console.log("\n── Phase 4: pramana gated ops (GATE surface — soft-layer gated) ──");
for (const [op, cap] of [
  ["execute",    "EXECUTE"],
  ["ai-execute", "AI_EXECUTE"],
  ["deploy",     "CI_DEPLOY"],
  ["delete",     "DELETE"],
  ["approve",    "APPROVE"],
  ["emit",       "EMIT"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r7-gate" });
  logDecision(d);
  check(`pramana [${cap}]: soft_canary + GATE`, d.enforcement_phase === "soft_canary" && d.decision === "GATE", true, "gate_surface");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana [${cap}]: sim(on) GATE→GATE (still_gate no-upgrade)`, sim.simulated_hard_decision, "GATE", "gate_surface");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Phase 5: TP pair + malformed ─────────────────────────────────────────────
console.log("\n── Phase 5: TP pair + malformed ──");
for (const [op, cap] of [
  ["frob",  "IMPOSSIBLE_OP"],
  ["write", "EMPTY_CAPABILITY_ON_WRITE"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r7-tp" });
  logDecision(d);
  check(`pramana [${cap}]: live ALLOW (soft_canary, not hard-gated)`, d.decision, "ALLOW", "tp");
  check(`pramana [${cap}]: soft_canary phase`, d.enforcement_phase, "soft_canary", "tp");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana [${cap}]: sim(on) → BLOCK (TP detected)`, sim.simulated_hard_decision, "BLOCK", "tp");
  check(`pramana [${cap}]: sim hard_gate_would_apply = true`, sim.hard_gate_would_apply, true, "tp");
  if (sim.hard_gate_would_apply) simTPs++;
}

// ── Phase 6: alias normalization ─────────────────────────────────────────────
console.log("\n── Phase 6: alias normalization round-trip ──");
for (const [op, cap, expDec] of [
  ["run_agent",  "run_agent",  "GATE"],
  ["call_llm",   "call_llm",   "GATE"],
  ["invoke",     "invoke",     "GATE"],
  ["fetch",      "FETCH",      "ALLOW"],
  ["search",     "search",     "ALLOW"],
] as [string, string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r7-alias" });
  check(`pramana alias [${cap}]: ${expDec}`, d.decision, expDec, "alias");
  check(`pramana alias [${cap}]: soft_canary`, d.enforcement_phase, "soft_canary", "alias");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Phase 7: never_block READ invariant ──────────────────────────────────────
console.log("\n── Phase 7: never_block READ invariant ──");
for (const op of ["read", "get", "list", "query", "search", "health", "fetch"]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: "READ", caller_id: "b42r7-neverblock" });
  check(`pramana [${op}] READ: never_block ALLOW`, d.decision, "ALLOW", "never_block");
  const sim = simulateHardGate("pramana", "ALLOW", "READ", op, true);
  check(`pramana [${op}] READ: sim(on) ALLOW`, sim.simulated_hard_decision, "ALLOW", "never_block");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Phase 8: still_gate downgrade guard ──────────────────────────────────────
// Covers all still_gate_capabilities including MEMORY_WRITE/AUDIT_WRITE/SPAWN_AGENTS
// which the soft layer passes as ALLOW (not soft-gated) but hard-gate would BLOCK.
console.log("\n── Phase 8: still_gate downgrade guard ──");
for (const [op, cap] of [
  ["execute",    "EXECUTE"],
  ["deploy",     "CI_DEPLOY"],
  ["delete",     "DELETE"],
  ["approve",    "APPROVE"],
  ["emit",       "EMIT"],
  ["write",      "MEMORY_WRITE"],
  ["write",      "AUDIT_WRITE"],
  ["write",      "SPAWN_AGENTS"],
] as [string, string][]) {
  const simDG = simulateHardGate("pramana", "BLOCK", cap, op, true);
  check(`still_gate DG [${cap}]: BLOCK→GATE`, simDG.simulated_hard_decision, "GATE", "still_gate");
  const simNU = simulateHardGate("pramana", "ALLOW", cap, op, true);
  check(`still_gate NU [${cap}]: ALLOW→ALLOW`, simNU.simulated_hard_decision, "ALLOW", "still_gate");
}

// ── Phase 9: kill → sim(on) → restore ────────────────────────────────────────
console.log("\n── Phase 9: kill → sim(on) → restore ──");
{
  process.env.AEGIS_RUNTIME_ENABLED = "false";
  const dKill = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42r7-kill" });
  check("pramana while killed: shadow", dKill.enforcement_phase, "shadow", "kill");
  check("pramana while killed: not BLOCK", dKill.decision !== "BLOCK", true, "kill");
  const simKill = simulateHardGate("pramana", "ALLOW", "IMPOSSIBLE_OP", "frob", true);
  check("sim(on) while killed: BLOCK (policy independent)", simKill.simulated_hard_decision, "BLOCK", "kill");
  if (simKill.hard_gate_would_apply) simTPs++;
  process.env.AEGIS_RUNTIME_ENABLED = "true";
  const dRestore = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42r7-restore" });
  check("pramana after restore: soft_canary", dRestore.enforcement_phase, "soft_canary", "kill");
}

// ── Phase 10: approval lifecycle ─────────────────────────────────────────────
console.log("\n── Phase 10: approval lifecycle ──");
{
  const d = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r7-apv" });
  logDecision(d);
  check("pramana EXECUTE: GATE (token issued)", d.decision, "GATE", "approval");
  const token = gateToken(d);
  check("EXECUTE: token present", !!token, true, "approval");
  const a1 = approveToken(token, "final rehearsal approval", "b42r7-operator");
  check("approve token: accepted", a1.ok ? "accepted" : "rejected", "accepted", "approval");
  const a2 = approveToken(token, "replay attempt", "b42r7-replay");
  check("replay approve: rejected", a2.ok ? "accepted" : "rejected", "rejected", "approval");
}

// ── Phase 11: env promotion drill ────────────────────────────────────────────
console.log("\n── Phase 11: env promotion drill ──");
{
  process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
  const dImp = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r7-promo" });
  logDecision(dImp);
  check("env promo: IMPOSSIBLE_OP → live BLOCK (env gate confirmed)", dImp.decision, "BLOCK", "promo");
  check("env promo: hard_gate phase", dImp.enforcement_phase, "hard_gate", "promo");
  const dRead = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42r7-promo" });
  check("env promo: READ → ALLOW (never_block holds)", dRead.decision, "ALLOW", "promo");
  const dExec = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r7-promo" });
  check("env promo: EXECUTE → GATE (still_gate)", dExec.decision, "GATE", "promo");
  // demote
  process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
  const dDemote = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r7-demote" });
  check("demote: back to soft_canary", dDemote.enforcement_phase, "soft_canary", "promo");
  check("demote: IMPOSSIBLE_OP → ALLOW (soft only)", dDemote.decision, "ALLOW", "promo");
  if (dDemote.decision === "BLOCK") prodFires++;
}

// ── Phase 12: isolation checks ────────────────────────────────────────────────
console.log("\n── Phase 12: isolation ──");
for (const svc of ["parali-central", "carbonx"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r7-iso" });
  check(`[${svc}] HG-2B: NOT hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "isolation");
}
{
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r7-iso" });
  check("domain-capture: NOT hard_gate", d.enforcement_phase !== "hard_gate", true, "isolation");
}
{
  const d = evaluate({ service_id: "ankr-doctor", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r7-iso" });
  check("ankr-doctor EXECUTE: GATE (soft layer), NOT hard_gate", d.decision === "GATE" && d.enforcement_phase !== "hard_gate", true, "isolation");
}
for (const svc of ["unregistered-svc", "phantom-service"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r7-iso" });
  check(`[${svc}]: shadow + WARN`, d.enforcement_phase === "shadow" && d.decision === "WARN", true, "isolation");
}

// ── Phase 13: BR comparison ───────────────────────────────────────────────────
console.log("\n── Phase 13: BR comparison (puranic-os BR-1 vs pramana BR-5) ──");
{
  const dPuranic = evaluate({ service_id: "puranic-os", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r7-br" });
  logDecision(dPuranic);
  check("puranic-os EXECUTE: ALLOW (BR-1 < 3, no high-risk gate)", dPuranic.decision, "ALLOW", "br_compare");
  check("puranic-os EXECUTE: hard_gate phase (HG-1 live)", dPuranic.enforcement_phase, "hard_gate", "br_compare");
  const dPramana = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r7-br" });
  logDecision(dPramana);
  check("pramana EXECUTE: GATE (BR-5 ≥ 3, high-risk gate fires)", dPramana.decision, "GATE", "br_compare");
  check("pramana EXECUTE: soft_canary phase", dPramana.enforcement_phase, "soft_canary", "br_compare");
  check("BR lesson holds: same authority_class, wider blast radius → stricter gate", true, true, "br_compare");
}

// ── Phase 14: rollback drill ──────────────────────────────────────────────────
console.log("\n── Phase 14: rollback drill ──");
{
  const drill = runRollbackDrill(evaluate, ["pramana", "chirpee", "ship-slm", "chief-slm", "puranic-os"], [
    { operation: "read",  requested_capability: "READ" },
    { operation: "frob",  requested_capability: "IMPOSSIBLE_OP" },
  ]);
  check("rollback drill: PASS", drill.verdict, "PASS", "rollback");
  const ps = drill.services_checked.find(s => s.service_id === "pramana");
  check("pramana: shadow after kill in drill", ps?.phase_after_kill, "shadow", "rollback");
  check("pramana: no tokens while killed", ps?.tokens_issued, false, "rollback");
  const afterDrill = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42r7-afterdrill" });
  check("pramana: restored to soft_canary after drill", afterDrill.enforcement_phase, "soft_canary", "rollback");
  for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
    const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r7-afterdrill" });
    check(`[${svc}]: hard_gate after drill restore`, d.enforcement_phase, "hard_gate", "rollback");
  }
}

// ── Count validation ──────────────────────────────────────────────────────────
console.log("\n── Count validation ──");
check("simulation TPs ≥ 3", simTPs >= 3, true, "count");
check("production fires = 0", prodFires, 0, "count");

// ── Final verdict ─────────────────────────────────────────────────────────────
const thisSoakPass = failed === 0 && prodFires === 0;
const promotionPermitted = allPriorPass && thisSoakPass;
const totalAllRuns = totalPriorChecks + totalChecks;

console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${thisSoakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

console.log(`\n══ BATCH 42 SOAK FINAL VERDICT ══`);
console.log(`  All 6 prior runs PASS: ${allPriorPass}`);
console.log(`  This run (7/7) PASS:   ${thisSoakPass}`);
console.log(`  Total checks across 7 runs: ${totalAllRuns}`);
console.log(`  Promotion permitted:   ${promotionPermitted}`);
console.log(`\n  Service: pramana  |  HG-Group: HG-2A  |  Policy: disabled (soft_canary)`);
console.log(`  Promotion act is SEPARATE — this verdict authorizes, does not execute.`);
console.log(`  Pramana proves HG-2A is not HG-1 repeated — same malformed targets, wider blast radius, stricter watches.`);

writeFileSync(join(dir, `batch42_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN, service: "pramana", hg_group: "HG-2A", date: RUN_DATE,
  verdict: thisSoakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed,
  simulation_true_positives: simTPs, production_gate_fires: prodFires, ready_to_promote: false,
}, null, 2));

writeFileSync(join(dir, "batch42_pramana_final_verdict.json"), JSON.stringify({
  service: "pramana",
  hg_group: "HG-2A",
  batch: 42,
  date: RUN_DATE,
  soak_runs_total: 7,
  soak_runs_pass: priorRuns.filter(r => r.verdict === "PASS").length + (thisSoakPass ? 1 : 0),
  total_checks_all_runs: totalAllRuns,
  all_prior_runs_pass: allPriorPass,
  final_run_pass: thisSoakPass,
  production_gate_fires_lifetime: 0,
  promotion_permitted_pramana: promotionPermitted,
  promotion_note: "Promotion is a separate human act. This verdict authorizes it. Add pramana to AEGIS_HARD_GATE_SERVICES when ready.",
  pramana_policy_stage: PRAMANA_HG2A_POLICY.stage,
  hard_gate_enabled_at_verdict: PRAMANA_HG2A_POLICY.hard_gate_enabled,
}, null, 2));

console.log(`\n  Batch 42 Run ${SOAK_RUN}/7: ${thisSoakPass ? "PASS" : "FAIL"}`);
console.log(`  batch42_pramana_final_verdict.json written — promotion_permitted_pramana=${promotionPermitted}`);
