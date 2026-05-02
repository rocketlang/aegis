/**
 * Batch 31 — Chirpee HG-1 Soak Observation (Run 3 of 7)
 *
 * Focus: burst traffic + repeated malformed attempts
 *   READ burst: 15 sessions × 6 ops = 90 decisions
 *   WRITE burst: 12 sessions × 4 ops = 48 decisions
 *   Malformed repeated: 15 × IMPOSSIBLE_OP + 15 × EMPTY_CAPABILITY_ON_WRITE = 30 true positive targets
 *   High-risk: 5 sessions AI_EXECUTE
 *   Critical: 5 sessions DEPLOY/DELETE
 *   Boundary + lifecycle + rollback: unchanged structure
 *
 * Invariants (must hold every run):
 *   false_positives = 0
 *   true_positives > 0 (IMPOSSIBLE_OP / EMPTY_CAP_ON_WRITE → BLOCK in sim)
 *   invariant_violations = 0
 *   production_gate_fires = 0
 *   READ never blocks · unknown service never blocks · unknown cap never hard-blocks
 *   AI_EXECUTE → soft=GATE · hard gate OFF · ready_to_promote=false
 */

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import {
  approveToken, denyToken, revokeToken, getApproval, runRollbackDrill,
} from "../src/enforcement/approval";
import {
  HARD_GATE_GLOBALLY_ENABLED, HARD_GATE_SERVICES_ENABLED,
  CHIRPEE_HG1_POLICY, simulateHardGate,
} from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED  = "true";
process.env.AEGIS_DRY_RUN          = "false";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

const SOAK_RUN = 3;
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
function gate(op: string, cap: string, caller = "b31r3") {
  const d = evaluate({ service_id: "chirpee", operation: op, requested_capability: cap, caller_id: caller, session_id: `b31r3-${op}-${cap}-${Date.now()}` });
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
  const d = gate(op, cap, "b31r3-soak");
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
check("chirpee hg_group = HG-1", CHIRPEE_HG1_POLICY.hg_group, "HG-1", "pre");
check("IMPOSSIBLE_OP in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "pre");
check("EMPTY_CAP in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "pre");
check("READ in never_block", CHIRPEE_HG1_POLICY.never_block_capabilities.has("READ"), true, "pre");

// Wave 1 — READ burst (15 sessions × 6 ops = 90)
console.log("\n── Wave 1: READ burst — 15 sessions ──");
const readOps = ["read", "get", "list", "query", "search", "health"];
for (let s = 1; s <= 15; s++) for (const op of readOps)
  observe(`chirpee/${op}[${s}]`, op, "READ", "ALLOW", "ALLOW", "wave1_read_burst");

// Wave 2 — WRITE burst (12 sessions × 4 ops = 48)
console.log("\n── Wave 2: WRITE burst — 12 sessions ──");
const writeOps = ["write", "update", "create", "patch"];
for (let s = 1; s <= 12; s++) for (const op of writeOps)
  observe(`chirpee/${op}[${s}]`, op, "WRITE", "ALLOW", "ALLOW", "wave2_write_burst");

// Wave 3 — AI_EXECUTE high-risk (5 sessions)
console.log("\n── Wave 3: AI_EXECUTE — 5 sessions ──");
for (let s = 1; s <= 5; s++) {
  for (const [op, cap] of [["execute","EXECUTE"],["approve","APPROVE"],["emit","EXECUTE"]] as [string,string][])
    observe(`chirpee/${op}[${s}]`, op, cap, "ALLOW", "GATE", "wave3_highrisk");
  observe(`chirpee/ai-execute[${s}]`, "ai-execute", "AI_EXECUTE", "GATE", "GATE", "wave3_highrisk");
}

// Wave 4 — DEPLOY/DELETE critical (5 sessions)
console.log("\n── Wave 4: DEPLOY/DELETE — 5 sessions ──");
const deployTokens: string[] = [];
for (let s = 1; s <= 5; s++) for (const [op, cap] of [["deploy","CI_DEPLOY"],["delete","DELETE"]] as [string,string][]) {
  const { soft } = observe(`chirpee/${op}[${s}]`, op, cap, "GATE", "GATE", "wave4_critical");
  if (soft.approval_token) deployTokens.push(soft.approval_token);
}

// Wave 5 — Malformed burst: 15 × each = 30 true positives
console.log("\n── Wave 5: Malformed burst — 15 × each ──");
for (let i = 1; i <= 15; i++)
  observe(`chirpee/IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP", "ALLOW", "BLOCK", "wave5_malformed");
for (let i = 1; i <= 15; i++)
  observe(`chirpee/EMPTY_CAP[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave5_malformed");

// Wave 6 — Boundary
console.log("\n── Wave 6: Boundary ──");
for (const cap of ["BURST_UNKNOWN_R3", "STRESS_CAP_R3", "FLOOD_CAP_R3"]) {
  const d = gate("frob", cap, "b31r3-boundary");
  const simDry = simulateHardGate("chirpee", d.decision, cap, "frob", true);
  check(`boundary: ${cap} no BLOCK (soft)`, d.decision !== "BLOCK", true, "wave6_boundary");
  check(`boundary: ${cap} no BLOCK (sim)`, simDry.simulated_hard_decision !== "BLOCK", true, "wave6_boundary");
  check(`boundary: ${cap} invariant`, simDry.invariant_applied, "unknown_cap_gates_before_blocking", "wave6_boundary");
  soakMetrics.soft_decisions[d.decision as keyof typeof soakMetrics.soft_decisions]++;
  if (!soakMetrics.waves["wave6_boundary"]) soakMetrics.waves["wave6_boundary"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave6_boundary"].decisions++;
}
{ // unknown service
  const d = evaluate({ service_id: "svc-burst-r3", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b31r3-boundary", session_id: "b31r3-unknownsvc" });
  logDecision(d);
  const sim = simulateHardGate("svc-burst-r3", d.decision, "CI_DEPLOY", "deploy", true);
  check("boundary: unknown_service WARN/shadow", `${d.decision}/${d.enforcement_phase}`, "WARN/shadow", "wave6_boundary");
  check("boundary: unknown_service sim preserves soft", sim.simulated_hard_decision, d.decision, "wave6_boundary");
  soakMetrics.waves["wave6_boundary"].decisions++;
}
for (const cap of ["READ", "!@#BURST_GARBAGE", ""]) {
  const d = evaluate({ service_id: "chirpee", operation: "read", requested_capability: cap, caller_id: "b31r3-boundary", session_id: `b31r3-readstress-${Date.now()}` });
  logDecision(d);
  const sim = simulateHardGate("chirpee", d.decision, cap, "read", true);
  check(`READ stress: '${cap||"(empty)"}' → ALLOW`, d.decision, "ALLOW", "wave6_boundary");
  check(`READ stress: '${cap||"(empty)"}' sim → ALLOW`, sim.simulated_hard_decision, "ALLOW", "wave6_boundary");
  check(`READ stress: invariant AEG-HG-002`, sim.invariant_applied, "AEG-HG-002", "wave6_boundary");
  soakMetrics.soft_decisions.ALLOW++;
  soakMetrics.waves["wave6_boundary"].decisions++;
}

// Wave 7 — Lifecycle
console.log("\n── Wave 7: Approval lifecycle ──");
if (deployTokens.length >= 4) {
  const [t1, t2, t3, t4] = deployTokens;
  check("lifecycle: approve", okStatus(approveToken(t1, "burst run 3: deploy approved", "captain@ankr")), "accepted", "wave7_lifecycle");
  check("lifecycle: deny", okStatus(denyToken(t2, "burst run 3: deny", "ops@ankr")), "accepted", "wave7_lifecycle");
  check("lifecycle: revoke", okStatus(revokeToken(t3, "security@ankr", "burst run 3: revoke")), "accepted", "wave7_lifecycle");
  check("lifecycle: replay rejected", okStatus(approveToken(t1, "replay burst r3", "ops@ankr")), "rejected", "wave7_lifecycle");
  check("lifecycle: blank rejected", okStatus(approveToken(t4, "  ", "ops@ankr")), "rejected", "wave7_lifecycle");
  denyToken(t4, "cleanup r3", "b31r3-script");
}
const freshGate = gate("deploy", "CI_DEPLOY", "b31r3-lifecycle");
if (freshGate.approval_token) {
  const simFresh = simulateHardGate("chirpee", freshGate.decision, "CI_DEPLOY", "deploy", true);
  check("lifecycle: sim → GATE not BLOCK", simFresh.simulated_hard_decision, "GATE", "wave7_lifecycle");
  check("lifecycle: sim does not consume token", freshGate.approval_token !== undefined, true, "wave7_lifecycle");
  const rec = getApproval(freshGate.approval_token);
  if (rec) rec.expires_at = new Date(Date.now() - 1000).toISOString();
  check("lifecycle: expired rejected", okStatus(approveToken(freshGate.approval_token, "late r3", "ops@ankr")), "rejected", "wave7_lifecycle");
}

// Wave 8 — Rollback
console.log("\n── Wave 8: Rollback drill ──");
const drill = runRollbackDrill(evaluate, ["chirpee"], [
  { operation: "deploy", requested_capability: "CI_DEPLOY" },
  { operation: "delete", requested_capability: "DELETE" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
]);
check("rollback: PASS", drill.verdict, "PASS", "wave8_rollback");
const cs = drill.services_checked.find(s => s.service_id === "chirpee");
check("chirpee: shadow after kill", cs?.phase_after_kill, "shadow", "wave8_rollback");
check("chirpee: no tokens while killed", cs?.tokens_issued, false, "wave8_rollback");
check("rollback: sim GATE not BLOCK", simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true).simulated_hard_decision, "GATE", "wave8_rollback");

// Canary
console.log("\n── Canary status ──");
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
console.log(`\n══ Soak Metrics ══\n  Soak run: ${SOAK_RUN} of 7\n  Soft decisions: ${totalSoft} (ALLOW=${soakMetrics.soft_decisions.ALLOW} GATE=${soakMetrics.soft_decisions.GATE} BLOCK=${soakMetrics.soft_decisions.BLOCK})\n  Sim(off): ${soakMetrics.sim_production.no_fires} no-fires, ${soakMetrics.sim_production.fires} fires\n  Sim(dry): ALLOW=${soakMetrics.sim_dryrun.ALLOW} GATE=${soakMetrics.sim_dryrun.GATE} BLOCK=${soakMetrics.sim_dryrun.BLOCK}\n  False positives: ${soakMetrics.false_positives}\n  True positives: ${soakMetrics.true_positives}\n  Invariant violations: ${soakMetrics.invariant_violations}\n  Production fires: ${soakMetrics.production_gate_fires}`);
console.log(`\n══ Summary ══\n  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}\n  Verdict: ${soakPass ? "PASS" : "FAIL"}\n  Hard gate: false  ready_to_promote: false`);
if (failures.length) { console.log("  Failures:"); failures.forEach(f => console.log(`    ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`)); }
console.log("\n── Wave summary ──");
console.log(`  ${"Wave".padEnd(28)}${"Dec".padEnd(6)}${"F+".padEnd(6)}True+`);
for (const [w, m] of Object.entries(soakMetrics.waves)) console.log(`  ${w.padEnd(28)}${String(m.decisions).padEnd(6)}${String(m.false_positives).padEnd(6)}${m.true_positives}`);

const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, `batch31_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, date: SOAK_DATE, verdict: soakPass ? "PASS" : "FAIL", ...soakMetrics, total_checks: totalChecks, passed, failed }, null, 2));
console.log(`\n  Soak run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"} — ${failed} failures, ${soakMetrics.false_positives} false positives. ${soakPass ? `${7 - SOAK_RUN} more runs before promote decision.` : "Resolve before next run."}`);
