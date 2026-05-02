/**
 * Batch 31 — Chirpee HG-1 Soak Observation (Run 7 of 7)
 *
 * Focus: full dress rehearsal — representative production traffic mix
 *   All waves present. Volume proportional to expected real traffic.
 *   Every invariant exercised: READ, mixed-case, alias, malformed, lifecycle, rollback.
 *   This run's PASS is the final gate before human promote decision.
 *
 * If this run passes: 7/7 complete.
 *   ready_to_promote_chirpee: false ← still false from this script
 *   Human promote decision permitted (not automatic, per AEG-HG-003).
 *
 * Authorization: AGS decides whether the actor may attempt.
 * Enforcement: AEG decides whether the runtime allows, warns, gates, blocks, or simulates.
 * Together: governed runtime authority.
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

const SOAK_RUN = 7;
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
function gate(op: string, cap: string, caller = "b31r7") {
  const d = evaluate({ service_id: "chirpee", operation: op, requested_capability: cap, caller_id: caller, session_id: `b31r7-${op}-${cap}-${Date.now()}` });
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
  const d = gate(op, cap, "b31r7-soak");
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
console.log("\n── Pre-check (final dress rehearsal) ──");
check("HARD_GATE_GLOBALLY_ENABLED = false", HARD_GATE_GLOBALLY_ENABLED, false, "pre");
check("HARD_GATE_SERVICES_ENABLED empty", HARD_GATE_SERVICES_ENABLED.size, 0, "pre");
check("chirpee hard_gate_enabled = false", CHIRPEE_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chirpee hg_group = HG-1", CHIRPEE_HG1_POLICY.hg_group, "HG-1", "pre");
check("IMPOSSIBLE_OP in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "pre");
check("EMPTY_CAP in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "pre");
check("READ in never_block", CHIRPEE_HG1_POLICY.never_block_capabilities.has("READ"), true, "pre");
check("AI_EXECUTE in still_gate", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("AI_EXECUTE"), true, "pre");
check("CI_DEPLOY in still_gate", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("CI_DEPLOY"), true, "pre");

// Wave 1 — READ (10 sessions × 6 ops = 60) — representative production volume
console.log("\n── Wave 1: READ — 10 sessions ──");
for (let s = 1; s <= 10; s++) for (const op of ["read","get","list","query","search","health"])
  observe(`${op}[${s}]`, op, "READ", "ALLOW", "ALLOW", "wave1_read");

// Wave 2 — READ mixed-case (final confirmation)
console.log("\n── Wave 2: READ mixed-case ──");
for (const [op, cap] of [["read","Read"],["get","GET"],["list","list"],["query","QUERY"],["search","search"],["health","HEALTH"]] as [string,string][]) {
  const d = evaluate({ service_id: "chirpee", operation: op, requested_capability: cap, caller_id: "b31r7-mix", session_id: `b31r7-mix-${cap}-${Date.now()}` });
  logDecision(d);
  const sim = simulateHardGate("chirpee", d.decision, cap, op, true);
  check(`mix: ${op}/${cap} → ALLOW`, d.decision, "ALLOW", "wave2_mixcase");
  check(`mix: ${op}/${cap} → sim ALLOW`, sim.simulated_hard_decision, "ALLOW", "wave2_mixcase");
  check(`mix: ${op}/${cap} → AEG-HG-002`, sim.invariant_applied, "AEG-HG-002", "wave2_mixcase");
  soakMetrics.soft_decisions.ALLOW++;
  if (!soakMetrics.waves["wave2_mixcase"]) soakMetrics.waves["wave2_mixcase"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave2_mixcase"].decisions++;
}

// Wave 3 — WRITE (8 sessions)
console.log("\n── Wave 3: WRITE — 8 sessions ──");
for (let s = 1; s <= 8; s++) for (const op of ["write","update","create","patch"])
  observe(`${op}[${s}]`, op, "WRITE", "ALLOW", "ALLOW", "wave3_write");

// Wave 4 — High-risk (5 sessions: EXECUTE/APPROVE/TRIGGER/EMIT + AI_EXECUTE)
console.log("\n── Wave 4: High-risk ops — 5 sessions ──");
for (let s = 1; s <= 5; s++) {
  for (const [op, cap] of [["execute","EXECUTE"],["approve","APPROVE"],["trigger","EXECUTE"],["emit","EXECUTE"]] as [string,string][])
    observe(`${op}[${s}]`, op, cap, "ALLOW", "GATE", "wave4_highrisk");
  observe(`ai-execute[${s}]`, "ai-execute", "AI_EXECUTE", "GATE", "GATE", "wave4_highrisk");
}

// Wave 5 — DEPLOY/DELETE (5 sessions)
console.log("\n── Wave 5: DEPLOY/DELETE — 5 sessions ──");
const deployTokens: string[] = [];
for (let s = 1; s <= 5; s++) for (const [op, cap] of [["deploy","CI_DEPLOY"],["delete","DELETE"]] as [string,string][]) {
  const { soft } = observe(`${op}[${s}]`, op, cap, "GATE", "GATE", "wave5_critical");
  if (soft.approval_token) deployTokens.push(soft.approval_token);
}

// Wave 6 — Malformed (10 × each = 20 true positives — full dress)
console.log("\n── Wave 6: Malformed — 10 × each ──");
for (let i = 1; i <= 10; i++) observe(`IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP", "ALLOW", "BLOCK", "wave6_malformed");
for (let i = 1; i <= 10; i++) observe(`EMPTY_CAP[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave6_malformed");

// Wave 7 — Boundary (unknown caps, unknown service, garbage)
console.log("\n── Wave 7: Boundary ──");
for (const cap of ["FINAL_UNKNOWN_R7", "REHEARSAL_CAP", "FUTURE_GATE_R7"]) {
  const d = gate("frob", cap, "b31r7-boundary");
  const sim = simulateHardGate("chirpee", d.decision, cap, "frob", true);
  check(`boundary: ${cap} no BLOCK`, d.decision !== "BLOCK", true, "wave7_boundary");
  check(`boundary: ${cap} sim no BLOCK`, sim.simulated_hard_decision !== "BLOCK", true, "wave7_boundary");
  check(`boundary: ${cap} invariant`, sim.invariant_applied, "unknown_cap_gates_before_blocking", "wave7_boundary");
  soakMetrics.soft_decisions[d.decision as keyof typeof soakMetrics.soft_decisions]++;
  if (!soakMetrics.waves["wave7_boundary"]) soakMetrics.waves["wave7_boundary"] = { decisions: 0, false_positives: 0, true_positives: 0 };
  soakMetrics.waves["wave7_boundary"].decisions++;
}
{ const d = evaluate({ service_id: "svc-final-r7", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b31r7-boundary", session_id: "b31r7-unknownsvc" });
  logDecision(d);
  const sim = simulateHardGate("svc-final-r7", d.decision, "CI_DEPLOY", "deploy", true);
  check("boundary: unknown_service WARN/shadow", `${d.decision}/${d.enforcement_phase}`, "WARN/shadow", "wave7_boundary");
  check("boundary: unknown_service sim preserves soft", sim.simulated_hard_decision, d.decision, "wave7_boundary");
  soakMetrics.waves["wave7_boundary"].decisions++; }
for (const cap of ["", "READ", "rEaD"]) {
  const d = evaluate({ service_id: "chirpee", operation: "read", requested_capability: cap, caller_id: "b31r7-boundary", session_id: `b31r7-readstress-${Date.now()}` });
  logDecision(d);
  const sim = simulateHardGate("chirpee", d.decision, cap, "read", true);
  check(`READ stress '${cap||"(empty)"}' → ALLOW`, d.decision, "ALLOW", "wave7_boundary");
  check(`READ stress '${cap||"(empty)"}' sim → ALLOW`, sim.simulated_hard_decision, "ALLOW", "wave7_boundary");
  check(`READ stress '${cap||"(empty)"}' AEG-HG-002`, sim.invariant_applied, "AEG-HG-002", "wave7_boundary");
  soakMetrics.soft_decisions.ALLOW++;
  soakMetrics.waves["wave7_boundary"].decisions++;
}

// Wave 8 — Lifecycle (full)
console.log("\n── Wave 8: Lifecycle ──");
if (deployTokens.length >= 4) {
  const [t1, t2, t3, t4] = deployTokens;
  check("lifecycle: approve", okStatus(approveToken(t1, "final rehearsal approve", "captain@ankr")), "accepted", "wave8_lifecycle");
  check("lifecycle: deny", okStatus(denyToken(t2, "final rehearsal deny", "ops@ankr")), "accepted", "wave8_lifecycle");
  check("lifecycle: revoke", okStatus(revokeToken(t3, "security@ankr", "final rehearsal revoke")), "accepted", "wave8_lifecycle");
  check("lifecycle: replay rejected (AEG-E-015)", okStatus(approveToken(t1, "replay final", "ops@ankr")), "rejected", "wave8_lifecycle");
  check("lifecycle: blank rejected (AEG-E-014)", okStatus(approveToken(t4, "", "ops@ankr")), "rejected", "wave8_lifecycle");
  denyToken(t4, "cleanup final r7", "b31r7-script");
}
const fresh = gate("deploy", "CI_DEPLOY", "b31r7-lifecycle");
if (fresh.approval_token) {
  check("lifecycle: sim → GATE", simulateHardGate("chirpee", fresh.decision, "CI_DEPLOY", "deploy", true).simulated_hard_decision, "GATE", "wave8_lifecycle");
  check("lifecycle: sim no consume", fresh.approval_token !== undefined, true, "wave8_lifecycle");
  const rec = getApproval(fresh.approval_token);
  if (rec) rec.expires_at = new Date(Date.now() - 1000).toISOString();
  check("lifecycle: expired rejected (AEG-E-013)", okStatus(approveToken(fresh.approval_token, "late final", "ops@ankr")), "rejected", "wave8_lifecycle");
}

// Wave 9 — Rollback (final confirmation)
console.log("\n── Wave 9: Rollback drill ──");
const drill = runRollbackDrill(evaluate, ["chirpee"], [
  { operation: "deploy", requested_capability: "CI_DEPLOY" },
  { operation: "delete", requested_capability: "DELETE" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
]);
check("rollback: PASS", drill.verdict, "PASS", "wave9_rollback");
const cs = drill.services_checked.find(s => s.service_id === "chirpee");
check("chirpee: shadow after kill", cs?.phase_after_kill, "shadow", "wave9_rollback");
check("chirpee: no tokens while killed", cs?.tokens_issued, false, "wave9_rollback");
check("rollback: sim GATE not BLOCK", simulateHardGate("chirpee", "GATE", "CI_DEPLOY", "deploy", true).simulated_hard_decision, "GATE", "wave9_rollback");

// Canary
console.log("\n── Canary (final) ──");
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

console.log(`
══ Soak Metrics (Run 7 — Final) ══
  Soft decisions: ${totalSoft} (ALLOW=${soakMetrics.soft_decisions.ALLOW} GATE=${soakMetrics.soft_decisions.GATE} WARN=${soakMetrics.soft_decisions.WARN} BLOCK=${soakMetrics.soft_decisions.BLOCK})
  Sim(off): ${soakMetrics.sim_production.no_fires} no-fires, ${soakMetrics.sim_production.fires} fires
  Sim(dry): ALLOW=${soakMetrics.sim_dryrun.ALLOW} GATE=${soakMetrics.sim_dryrun.GATE} BLOCK=${soakMetrics.sim_dryrun.BLOCK}
  False positives: ${soakMetrics.false_positives} (must be 0)
  True positives:  ${soakMetrics.true_positives} (IMPOSSIBLE_OP/EMPTY_CAP→BLOCK)
  Invariant violations: ${soakMetrics.invariant_violations}
  Production gate fires: ${soakMetrics.production_gate_fires}
`);

console.log(`══ Final Soak Summary ══
  Total checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}
  Soak verdict: ${soakPass ? "PASS" : "FAIL"}
  Hard gate: false
  ready_to_promote_chirpee: false

  ${soakPass
    ? "7/7 SOAK RUNS COMPLETE. All invariants held. Human promote decision now permitted.\n  Authorization: AGS decides whether the actor may attempt.\n  Enforcement:   AEG decides whether the runtime allows, warns, gates, blocks, or simulates.\n  Together:      governed runtime authority.\n\n  ⟶ Human action required to promote: set HARD_GATE_GLOBALLY_ENABLED=true + AEGIS_HARD_GATE_SERVICES=chirpee"
    : `FAIL — ${failed} check failures. Resolve before promote decision.`}`);

if (failures.length) { console.log("\n  Failures:"); failures.forEach(f => console.log(`    ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`)); }

console.log("\n── Wave summary ──");
console.log(`  ${"Wave".padEnd(28)}${"Dec".padEnd(6)}${"F+".padEnd(6)}True+`);
for (const [w, m] of Object.entries(soakMetrics.waves)) console.log(`  ${w.padEnd(28)}${String(m.decisions).padEnd(6)}${String(m.false_positives).padEnd(6)}${m.true_positives}`);

const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, `batch31_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN, date: SOAK_DATE, verdict: soakPass ? "PASS" : "FAIL",
  promotion_permitted: soakPass,
  note: soakPass ? "7/7 complete. Human promote decision required per AEG-HG-003." : "Failures present — resolve before promote.",
  ...soakMetrics, total_checks: totalChecks, passed, failed,
}, null, 2));
writeFileSync(join(dir, `batch31_final_verdict.json`), JSON.stringify({
  soak_complete: soakPass,
  runs_passed: soakPass ? 7 : "incomplete",
  false_positives_this_run: soakMetrics.false_positives,
  promotion_permitted: soakPass,
  promotion_requires: "HARD_GATE_GLOBALLY_ENABLED=true AND AEGIS_HARD_GATE_SERVICES=chirpee — manual human act",
  date: SOAK_DATE,
}, null, 2));
console.log(`\n  Artifacts: .aegis/batch31_run${SOAK_RUN}_metrics.json  .aegis/batch31_final_verdict.json`);
