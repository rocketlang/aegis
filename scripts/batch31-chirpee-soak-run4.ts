/**
 * Batch 31 — Chirpee HG-1 Soak Observation (Run 4 of 7)
 *
 * Focus: mixed casing + alias normalization stress
 *   Every capability tested in multiple case variants
 *   Alias ops: trigger→EXECUTE, emit→EXECUTE (same cap, different op names)
 *   Garbage caps in both read and write ops
 *   Confirms AEG-HG-002 (READ invariant) and mixed-case normalization hold
 *   under wider variation than run 2
 */

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import { approveToken, denyToken, revokeToken, getApproval, runRollbackDrill } from "../src/enforcement/approval";
import { HARD_GATE_GLOBALLY_ENABLED, HARD_GATE_SERVICES_ENABLED, CHIRPEE_HG1_POLICY, simulateHardGate } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED  = "true";
process.env.AEGIS_DRY_RUN          = "false";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

const SOAK_RUN = 4;
const SOAK_DATE = new Date().toISOString();

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const pass = String(actual) === String(expected);
  if (pass) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(72)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(72)} expected=${expected} actual=${actual}`); }
}
function okStatus(r: { ok: boolean }) { return r.ok ? "accepted" : "rejected"; }
function gate(op: string, cap: string, caller = "b31r4") {
  const d = evaluate({ service_id: "chirpee", operation: op, requested_capability: cap, caller_id: caller, session_id: `b31r4-${op}-${cap}-${Date.now()}` });
  logDecision(d); return d;
}

const soakMetrics = {
  soft_decisions: { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 },
  sim_production: { fires: 0, no_fires: 0 },
  sim_dryrun: { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 },
  false_positives: 0, true_positives: 0, invariant_violations: 0, production_gate_fires: 0,
  waves: {} as Record<string, { decisions: number; false_positives: number; true_positives: number }>,
};
const MALFORMED_CAPS = new Set(["IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE"]);

function observe(label: string, op: string, cap: string, expectedSoft: string, expectedSim: string, cat: string) {
  const d = gate(op, cap, "b31r4-soak");
  soakMetrics.soft_decisions[d.decision as keyof typeof soakMetrics.soft_decisions]++;
  check(`soft: ${label}`, d.decision, expectedSoft, cat);
  const simProd = simulateHardGate("chirpee", d.decision, cap, op, false);
  if (simProd.hard_gate_would_apply) soakMetrics.production_gate_fires++; else soakMetrics.sim_production.no_fires++;
  check(`sim(off): ${label} — no fire`, simProd.hard_gate_would_apply, false, cat);
  check(`sim(off): ${label} — preserved`, simProd.simulated_hard_decision, d.decision, cat);
  const simDry = simulateHardGate("chirpee", d.decision, cap, op, true);
  soakMetrics.sim_dryrun[simDry.simulated_hard_decision as keyof typeof soakMetrics.sim_dryrun]++;
  check(`sim(on): ${label}`, simDry.simulated_hard_decision, expectedSim, cat);
  const isMalformed = MALFORMED_CAPS.has(cap.toUpperCase());
  if (simDry.simulated_hard_decision === "BLOCK" && !isMalformed) { soakMetrics.false_positives++; soakMetrics.invariant_violations++; }
  else if (simDry.simulated_hard_decision === "BLOCK" && isMalformed) soakMetrics.true_positives++;
  if (!soakMetrics.waves[cat]) soakMetrics.waves[cat] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves[cat].decisions++;
  if (simDry.simulated_hard_decision === "BLOCK" && !isMalformed) soakMetrics.waves[cat].false_positives++;
  if (simDry.simulated_hard_decision === "BLOCK" && isMalformed) soakMetrics.waves[cat].true_positives++;
  return { soft: d, simDry };
}

// Pre-check
console.log("\n── Pre-check ──");
check("HARD_GATE_GLOBALLY_ENABLED = false", HARD_GATE_GLOBALLY_ENABLED, false, "pre");
check("HARD_GATE_SERVICES_ENABLED empty", HARD_GATE_SERVICES_ENABLED.size, 0, "pre");
check("chirpee hard_gate_enabled = false", CHIRPEE_HG1_POLICY.hard_gate_enabled, false, "pre");

// Wave 1 — READ mixed-case exhaustive stress
// Every case variant of READ-class caps. AEG-HG-002 must hold universally.
console.log("\n── Wave 1: READ mixed-case exhaustive ──");
const readCapVariants = [
  ["read","READ"], ["read","Read"], ["read","read"], ["read","rEaD"], ["read","READ "],
  ["get","GET"], ["get","Get"], ["get","get"], ["get","gEt"],
  ["list","LIST"], ["list","List"], ["list","list"],
  ["query","QUERY"], ["query","Query"], ["query","query"],
  ["search","SEARCH"], ["search","Search"], ["search","search"],
  ["health","HEALTH"], ["health","Health"], ["health","health"],
];
for (const [op, cap] of readCapVariants) {
  const d = evaluate({ service_id: "chirpee", operation: op, requested_capability: cap, caller_id: "b31r4-mixcase", session_id: `b31r4-mix-${cap}-${Date.now()}` });
  logDecision(d);
  const simDry = simulateHardGate("chirpee", d.decision, cap, op, true);
  check(`mixed: op=${op} cap='${cap}' → soft ALLOW`, d.decision, "ALLOW", "wave1_mixcase");
  check(`mixed: op=${op} cap='${cap}' → sim ALLOW`, simDry.simulated_hard_decision, "ALLOW", "wave1_mixcase");
  check(`mixed: op=${op} cap='${cap}' → AEG-HG-002`, simDry.invariant_applied, "AEG-HG-002", "wave1_mixcase");
  soakMetrics.soft_decisions.ALLOW++;
  if (!soakMetrics.waves["wave1_mixcase"]) soakMetrics.waves["wave1_mixcase"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave1_mixcase"].decisions++;
}

// Wave 2 — Alias normalization: trigger/emit → EXECUTE cap (different op, same cap)
console.log("\n── Wave 2: Alias normalization (trigger/emit → EXECUTE cap) ──");
const aliasOps: [string, string, string, string][] = [
  ["trigger",  "EXECUTE", "ALLOW", "GATE"],
  ["Trigger",  "EXECUTE", "ALLOW", "GATE"],  // op casing — gate normalises op too
  ["emit",     "EXECUTE", "ALLOW", "GATE"],
  ["EMIT",     "EXECUTE", "ALLOW", "GATE"],
  ["execute",  "EXECUTE", "ALLOW", "GATE"],
  ["EXECUTE",  "EXECUTE", "ALLOW", "GATE"],
  ["approve",  "APPROVE", "ALLOW", "GATE"],
  ["APPROVE",  "APPROVE", "ALLOW", "GATE"],
];
for (const [op, cap, expSoft, expSim] of aliasOps)
  observe(`alias: op=${op} cap=${cap}`, op, cap, expSoft, expSim, "wave2_alias");

// Wave 3 — AI_EXECUTE (5 sessions, confirm consistent GATE)
console.log("\n── Wave 3: AI_EXECUTE (5 sessions) ──");
for (let s = 1; s <= 5; s++)
  observe(`ai-execute[${s}]`, "ai-execute", "AI_EXECUTE", "GATE", "GATE", "wave3_ai_exec");

// Wave 4 — DEPLOY/DELETE (5 sessions)
console.log("\n── Wave 4: DEPLOY/DELETE ──");
const deployTokens: string[] = [];
for (let s = 1; s <= 5; s++) for (const [op, cap] of [["deploy","CI_DEPLOY"],["delete","DELETE"]] as [string,string][]) {
  const { soft } = observe(`${op}[${s}]`, op, cap, "GATE", "GATE", "wave4_critical");
  if (soft.approval_token) deployTokens.push(soft.approval_token);
}

// Wave 5 — Malformed (10 × each = 20 true positives)
console.log("\n── Wave 5: Malformed ──");
for (let i = 1; i <= 10; i++) observe(`IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP", "ALLOW", "BLOCK", "wave5_malformed");
for (let i = 1; i <= 10; i++) observe(`EMPTY_CAP[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave5_malformed");

// Wave 6 — Garbage cap normalization
console.log("\n── Wave 6: Garbage cap normalization ──");
const garbageCaps = ["", "  ", "NULL", "undefined", "null", "0", "false", "true", "{}"];
for (const cap of garbageCaps) {
  const d = evaluate({ service_id: "chirpee", operation: "read", requested_capability: cap, caller_id: "b31r4-garbage", session_id: `b31r4-garbage-${Date.now()}` });
  logDecision(d);
  const simDry = simulateHardGate("chirpee", d.decision, cap, "read", true);
  check(`garbage: '${cap||"(empty)"}' read → ALLOW`, d.decision, "ALLOW", "wave6_garbage");
  check(`garbage: '${cap||"(empty)"}' sim → ALLOW`, simDry.simulated_hard_decision, "ALLOW", "wave6_garbage");
  soakMetrics.soft_decisions.ALLOW++;
  if (!soakMetrics.waves["wave6_garbage"]) soakMetrics.waves["wave6_garbage"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave6_garbage"].decisions++;
}

// Wave 7 — Lifecycle
console.log("\n── Wave 7: Lifecycle ──");
if (deployTokens.length >= 4) {
  const [t1, t2, t3, t4] = deployTokens;
  check("lifecycle: approve", okStatus(approveToken(t1, "alias run 4: approve", "captain@ankr")), "accepted", "wave7_lifecycle");
  check("lifecycle: deny", okStatus(denyToken(t2, "alias run 4: deny", "ops@ankr")), "accepted", "wave7_lifecycle");
  check("lifecycle: revoke", okStatus(revokeToken(t3, "security@ankr", "alias run 4: revoke")), "accepted", "wave7_lifecycle");
  check("lifecycle: replay rejected", okStatus(approveToken(t1, "replay r4", "ops@ankr")), "rejected", "wave7_lifecycle");
  check("lifecycle: blank rejected", okStatus(approveToken(t4, "", "ops@ankr")), "rejected", "wave7_lifecycle");
  denyToken(t4, "cleanup r4", "b31r4-script");
}
const fresh = gate("deploy", "CI_DEPLOY", "b31r4-lifecycle");
if (fresh.approval_token) {
  check("lifecycle: sim → GATE", simulateHardGate("chirpee", fresh.decision, "CI_DEPLOY", "deploy", true).simulated_hard_decision, "GATE", "wave7_lifecycle");
  const rec = getApproval(fresh.approval_token);
  if (rec) rec.expires_at = new Date(Date.now() - 1000).toISOString();
  check("lifecycle: expired rejected", okStatus(approveToken(fresh.approval_token, "late r4", "ops@ankr")), "rejected", "wave7_lifecycle");
}

// Wave 8 — Rollback
console.log("\n── Wave 8: Rollback drill ──");
const drill = runRollbackDrill(evaluate, ["chirpee"], [{ operation: "deploy", requested_capability: "CI_DEPLOY" }, { operation: "delete", requested_capability: "DELETE" }, { operation: "ai-execute", requested_capability: "AI_EXECUTE" }]);
check("rollback: PASS", drill.verdict, "PASS", "wave8_rollback");
const cs = drill.services_checked.find(s => s.service_id === "chirpee");
check("chirpee: shadow after kill", cs?.phase_after_kill, "shadow", "wave8_rollback");
check("chirpee: no tokens while killed", cs?.tokens_issued, false, "wave8_rollback");
check("rollback: sim GATE not BLOCK", simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true).simulated_hard_decision, "GATE", "wave8_rollback");

// Canary
console.log("\n── Canary ──");
const canary = getCanaryStatus(["chirpee"]);
const sc = canary.success_criteria;
check("no_read_gates", sc.no_read_gates, true, "canary");
check("no_unknown_service_blocks", sc.no_unknown_service_blocks, true, "canary");
check("no_token_replay_successes", sc.no_token_replay_successes, true, "canary");
check("no_approval_without_reason", sc.no_approval_without_reason, true, "canary");
check("no_revoke_without_reason", sc.no_revoke_without_reason, true, "canary");
check("rollback_drill_passed", sc.rollback_drill_passed, true, "canary");

const soakPass = failed === 0 && soakMetrics.false_positives === 0 && soakMetrics.true_positives > 0 && soakMetrics.invariant_violations === 0 && soakMetrics.production_gate_fires === 0;
const totalSoft = Object.values(soakMetrics.soft_decisions).reduce((a, b) => a + b, 0);
console.log(`\n══ Soak Metrics ══\n  Run: ${SOAK_RUN}/7  Soft: ${totalSoft} (ALLOW=${soakMetrics.soft_decisions.ALLOW} GATE=${soakMetrics.soft_decisions.GATE})\n  False+: ${soakMetrics.false_positives}  True+: ${soakMetrics.true_positives}  InvViol: ${soakMetrics.invariant_violations}  ProdFires: ${soakMetrics.production_gate_fires}`);
console.log(`\n══ Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}\n  Hard gate: false  ready_to_promote: false`);
if (failures.length) { console.log("  Failures:"); failures.forEach(f => console.log(`    ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`)); }
console.log("\n── Wave summary ──");
for (const [w, m] of Object.entries(soakMetrics.waves)) console.log(`  ${w.padEnd(28)}Dec=${m.decisions} F+=${m.false_positives} True+=${m.true_positives}`);

const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, `batch31_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, date: SOAK_DATE, verdict: soakPass ? "PASS" : "FAIL", ...soakMetrics, total_checks: totalChecks, passed, failed }, null, 2));
console.log(`\n  Soak run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"} — ${soakMetrics.false_positives} false positives. ${soakPass ? `${7 - SOAK_RUN} more runs.` : "Resolve before next run."}`);
