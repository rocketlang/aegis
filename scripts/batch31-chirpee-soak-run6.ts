/**
 * Batch 31 — Chirpee HG-1 Soak Observation (Run 6 of 7)
 *
 * Focus: rollback / kill-switch heavy
 *   Multiple rollback drills (3 drills)
 *   Kill-switch: AEGIS_RUNTIME_ENABLED=false confirmed → shadow + no tokens
 *   Kill-switch restore: enforcement resumes after re-enable
 *   Sim behavior confirmed stable during kill and after restore
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

const SOAK_RUN = 6;
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
function gate(op: string, cap: string, caller = "b31r6") {
  const d = evaluate({ service_id: "chirpee", operation: op, requested_capability: cap, caller_id: caller, session_id: `b31r6-${op}-${cap}-${Date.now()}` });
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
  const d = gate(op, cap, "b31r6-soak");
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

// Wave 1 — Normal traffic before kill (baseline)
console.log("\n── Wave 1: Baseline before kill ──");
for (const op of ["read","get","list"]) observe(`pre-kill/${op}`, op, "READ", "ALLOW", "ALLOW", "wave1_baseline");
for (const op of ["write","create"]) observe(`pre-kill/${op}`, op, "WRITE", "ALLOW", "ALLOW", "wave1_baseline");
observe("pre-kill/ai-execute", "ai-execute", "AI_EXECUTE", "GATE", "GATE", "wave1_baseline");

// Wave 2 — Kill-switch test (manual, not via runRollbackDrill)
console.log("\n── Wave 2: Kill-switch direct test ──");
const savedEnabled = process.env.AEGIS_RUNTIME_ENABLED;
process.env.AEGIS_RUNTIME_ENABLED = "false";

const killedDeploy = evaluate({ service_id: "chirpee", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b31r6-kill", session_id: "b31r6-killed-deploy" });
logDecision(killedDeploy);
check("kill: deploy in shadow phase", killedDeploy.enforcement_phase, "shadow", "wave2_kill");
check("kill: no token while killed", killedDeploy.approval_token === undefined || killedDeploy.approval_token === null, true, "wave2_kill");
soakMetrics.soft_decisions[killedDeploy.decision as keyof typeof soakMetrics.soft_decisions]++;

const killedRead = evaluate({ service_id: "chirpee", operation: "read", requested_capability: "READ", caller_id: "b31r6-kill", session_id: "b31r6-killed-read" });
logDecision(killedRead);
check("kill: READ still ALLOW during kill", killedRead.decision, "ALLOW", "wave2_kill");
soakMetrics.soft_decisions.ALLOW++;

// Sim during kill — should still produce correct results (sim is independent of runtime)
const simDuringKill = simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true);
check("kill: sim during kill → GATE not BLOCK", simDuringKill.simulated_hard_decision, "GATE", "wave2_kill");

// Restore
process.env.AEGIS_RUNTIME_ENABLED = savedEnabled ?? "true";

// Wave 3 — Post-restore: confirm enforcement resumes
console.log("\n── Wave 3: Post-restore enforcement ──");
const postDeploy = gate("deploy", "CI_DEPLOY", "b31r6-post-restore");
check("post-restore: deploy back to soft_canary phase", postDeploy.enforcement_phase !== "shadow" || postDeploy.enforcement_phase === "soft_canary", true, "wave3_restore");
check("post-restore: deploy GATE", postDeploy.decision, "GATE", "wave3_restore");
soakMetrics.soft_decisions.GATE++;
const postRead = gate("read", "READ", "b31r6-post-restore");
check("post-restore: READ still ALLOW", postRead.decision, "ALLOW", "wave3_restore");
soakMetrics.soft_decisions.ALLOW++;

// Wave 4 — Three rollback drills (confirms repeatable)
console.log("\n── Wave 4: Three rollback drills ──");
for (let drillN = 1; drillN <= 3; drillN++) {
  const drill = runRollbackDrill(evaluate, ["chirpee"], [
    { operation: "deploy", requested_capability: "CI_DEPLOY" },
    { operation: "delete", requested_capability: "DELETE" },
    { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
  ]);
  check(`drill[${drillN}]: PASS`, drill.verdict, "PASS", "wave4_drills");
  const cs = drill.services_checked.find(s => s.service_id === "chirpee");
  check(`drill[${drillN}]: shadow after kill`, cs?.phase_after_kill, "shadow", "wave4_drills");
  check(`drill[${drillN}]: no tokens while killed`, cs?.tokens_issued, false, "wave4_drills");
  const simPost = simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true);
  check(`drill[${drillN}]: sim GATE post-drill`, simPost.simulated_hard_decision, "GATE", "wave4_drills");
}

// Wave 5 — Malformed (5 × each = 10 true positives, confirm stable post-kill)
console.log("\n── Wave 5: Malformed post-kill ──");
for (let i = 1; i <= 5; i++) observe(`IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP", "ALLOW", "BLOCK", "wave5_malformed");
for (let i = 1; i <= 5; i++) observe(`EMPTY_CAP[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave5_malformed");

// Wave 6 — Lifecycle (lean — main focus is rollback)
console.log("\n── Wave 6: Lifecycle ──");
const deployTokens: string[] = [];
for (let s = 1; s <= 5; s++) {
  const d = gate("deploy", "CI_DEPLOY", "b31r6-lc");
  if (d.approval_token) deployTokens.push(d.approval_token);
  soakMetrics.soft_decisions.GATE++;
}
if (deployTokens.length >= 4) {
  const [t1, t2, t3, t4] = deployTokens;
  check("lifecycle: approve", okStatus(approveToken(t1, "run 6 kill-soak approve", "captain@ankr")), "accepted", "wave6_lifecycle");
  check("lifecycle: deny", okStatus(denyToken(t2, "run 6 deny", "ops@ankr")), "accepted", "wave6_lifecycle");
  check("lifecycle: revoke", okStatus(revokeToken(t3, "security@ankr", "run 6 revoke")), "accepted", "wave6_lifecycle");
  check("lifecycle: replay rejected", okStatus(approveToken(t1, "replay r6", "ops@ankr")), "rejected", "wave6_lifecycle");
  check("lifecycle: blank rejected", okStatus(approveToken(t4, "", "ops@ankr")), "rejected", "wave6_lifecycle");
  denyToken(t4, "cleanup r6", "b31r6-script");
}

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
console.log(`\n  Soak run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"} — ${soakMetrics.false_positives} false positives. ${soakPass ? "1 more run before promote decision." : "Resolve."}`);
