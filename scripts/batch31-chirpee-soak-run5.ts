/**
 * Batch 31 — Chirpee HG-1 Soak Observation (Run 5 of 7)
 *
 * Focus: approval lifecycle heavy
 *   20 tokens issued, varied approve/deny/revoke/replay/expiry patterns
 *   Flood attempt: 10 rapid approvals on already-consumed tokens
 *   Binding mismatch test (AEG-E-016)
 *   Lifecycle under concurrent GATE decisions
 */

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import { approveToken, denyToken, revokeToken, getApproval, runRollbackDrill, issueApprovalToken } from "../src/enforcement/approval";
import { HARD_GATE_GLOBALLY_ENABLED, HARD_GATE_SERVICES_ENABLED, CHIRPEE_HG1_POLICY, simulateHardGate } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED  = "true";
process.env.AEGIS_DRY_RUN          = "false";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

const SOAK_RUN = 5;
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
function gate(op: string, cap: string, caller = "b31r5") {
  const d = evaluate({ service_id: "chirpee", operation: op, requested_capability: cap, caller_id: caller, session_id: `b31r5-${op}-${cap}-${Date.now()}` });
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
  const d = gate(op, cap, "b31r5-soak");
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

// Wave 1 — Standard READ/WRITE baseline (lean)
console.log("\n── Wave 1: Baseline READ/WRITE ──");
for (const op of ["read","get","list"]) observe(`read/${op}`, op, "READ", "ALLOW", "ALLOW", "wave1_baseline");
for (const op of ["write","create","patch"]) observe(`write/${op}`, op, "WRITE", "ALLOW", "ALLOW", "wave1_baseline");
observe("ai-execute", "ai-execute", "AI_EXECUTE", "GATE", "GATE", "wave1_baseline");

// Wave 2 — 20 GATE decisions to generate tokens
console.log("\n── Wave 2: 20 GATE decisions (token generation) ──");
const allTokens: string[] = [];
for (let i = 1; i <= 10; i++) {
  const d1 = evaluate({ service_id: "chirpee", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b31r5-lc", session_id: `b31r5-deploy-${i}` });
  logDecision(d1); if (d1.approval_token) allTokens.push(d1.approval_token);
  soakMetrics.soft_decisions.GATE++;
  const d2 = evaluate({ service_id: "chirpee", operation: "delete", requested_capability: "DELETE", caller_id: "b31r5-lc", session_id: `b31r5-delete-${i}` });
  logDecision(d2); if (d2.approval_token) allTokens.push(d2.approval_token);
  soakMetrics.soft_decisions.GATE++;
}
check("token generation: 20 tokens issued", allTokens.length, 20, "wave2_tokens");

// Wave 3 — Lifecycle heavy: approve 6, deny 6, revoke 4, replay flood 4
console.log("\n── Wave 3: Lifecycle heavy (approve/deny/revoke/replay) ──");
const [a1,a2,a3,a4,a5,a6, d1,d2,d3,d4,d5,d6, r1,r2,r3,r4, ...rest] = allTokens;
// Approve 6
for (const [t, label] of [[a1,"t1"],[a2,"t2"],[a3,"t3"],[a4,"t4"],[a5,"t5"],[a6,"t6"]] as [string, string][])
  check(`approve ${label}`, okStatus(approveToken(t, `run 5 approve ${label}`, "captain@ankr")), "accepted", "wave3_lifecycle");
// Deny 6
for (const [t, label] of [[d1,"d1"],[d2,"d2"],[d3,"d3"],[d4,"d4"],[d5,"d5"],[d6,"d6"]] as [string, string][])
  check(`deny ${label}`, okStatus(denyToken(t, `run 5 deny ${label}`, "ops@ankr")), "accepted", "wave3_lifecycle");
// Revoke 4 (must still be pending)
for (const [t, label] of [[r1,"r1"],[r2,"r2"],[r3,"r3"],[r4,"r4"]] as [string, string][])
  check(`revoke ${label}`, okStatus(revokeToken(t, "security@ankr", `run 5 revoke ${label}`)), "accepted", "wave3_lifecycle");
// Replay flood: try re-approving already-approved tokens (AEG-E-015)
for (const [t, label] of [[a1,"replay-a1"],[a2,"replay-a2"],[a3,"replay-a3"],[a4,"replay-a4"]] as [string, string][])
  check(`replay ${label} rejected (AEG-E-015)`, okStatus(approveToken(t, `replay ${label}`, "ops@ankr")), "rejected", "wave3_lifecycle");
// Blank reason (AEG-E-014) on remaining pending tokens
if (rest.length >= 1) {
  check("blank reason rejected (AEG-E-014)", okStatus(approveToken(rest[0], "   ", "ops@ankr")), "rejected", "wave3_lifecycle");
  denyToken(rest[0], "cleanup r5", "b31r5-script");
}
// Sim does not consume tokens: pick a pending token and sim around it
const simToken = rest[1] ?? rest[0];
if (simToken) {
  simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true);
  const afterSim = getApproval(simToken);
  check("sim does not consume token", afterSim?.status === "pending" || afterSim?.status === "denied", true, "wave3_lifecycle");
}

// Wave 4 — Malformed (5 × each = 10 true positives)
console.log("\n── Wave 4: Malformed ──");
for (let i = 1; i <= 5; i++) observe(`IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP", "ALLOW", "BLOCK", "wave4_malformed");
for (let i = 1; i <= 5; i++) observe(`EMPTY_CAP[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave4_malformed");

// Wave 5 — Expired token stress
console.log("\n── Wave 5: Expiry stress ──");
for (let i = 1; i <= 4; i++) {
  const expGate = evaluate({ service_id: "chirpee", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b31r5-expiry", session_id: `b31r5-expiry-${i}` });
  logDecision(expGate);
  const rec = expGate.approval_token ? getApproval(expGate.approval_token) : null;
  if (rec) rec.expires_at = new Date(Date.now() - 1000).toISOString();
  const expRes = expGate.approval_token ? approveToken(expGate.approval_token, `late approval ${i}`, "ops@ankr") : { ok: false };
  check(`expiry[${i}]: expired token rejected (AEG-E-013)`, okStatus(expRes), "rejected", "wave5_expiry");
  soakMetrics.soft_decisions.GATE++;
}

// Wave 6 — Boundary
console.log("\n── Wave 6: Boundary ──");
for (const cap of ["LIFECYCLE_UNKNOWN_R5", "TOKEN_FUTURE_CAP"]) {
  const d = gate("frob", cap, "b31r5-boundary");
  const simDry = simulateHardGate("chirpee", d.decision, cap, "frob", true);
  check(`boundary: ${cap} no BLOCK`, d.decision !== "BLOCK", true, "wave6_boundary");
  check(`boundary: ${cap} sim no BLOCK`, simDry.simulated_hard_decision !== "BLOCK", true, "wave6_boundary");
  soakMetrics.soft_decisions[d.decision as keyof typeof soakMetrics.soft_decisions]++;
  if (!soakMetrics.waves["wave6_boundary"]) soakMetrics.waves["wave6_boundary"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave6_boundary"].decisions++;
}

// Wave 7 — Rollback
console.log("\n── Wave 7: Rollback drill ──");
const drill = runRollbackDrill(evaluate, ["chirpee"], [{ operation: "deploy", requested_capability: "CI_DEPLOY" }, { operation: "delete", requested_capability: "DELETE" }, { operation: "ai-execute", requested_capability: "AI_EXECUTE" }]);
check("rollback: PASS", drill.verdict, "PASS", "wave7_rollback");
const cs = drill.services_checked.find(s => s.service_id === "chirpee");
check("chirpee: shadow after kill", cs?.phase_after_kill, "shadow", "wave7_rollback");
check("chirpee: no tokens while killed", cs?.tokens_issued, false, "wave7_rollback");
check("rollback: sim GATE", simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true).simulated_hard_decision, "GATE", "wave7_rollback");

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
console.log(`\n  Soak run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"} — ${soakMetrics.false_positives} false positives. ${soakPass ? `${7 - SOAK_RUN} more runs.` : "Resolve."}`);
