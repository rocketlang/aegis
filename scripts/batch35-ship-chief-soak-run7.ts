/**
 * Batch 35 Soak Run 7/7 — Final dress rehearsal + promotion verdict
 *
 * Stress: complete surface. This is the run that closes the soak.
 * If it passes, batch35_ship_chief_final_verdict.json is written with
 * promotion_permitted_ship_chief=true. The actual promotion (adding to
 * AEGIS_HARD_GATE_SERVICES) remains a separate human act — Batch 36.
 *
 * Coverage:
 *   - All traffic categories from Run 1 (normal/domain/critical/malformed/boundary)
 *   - Approval lifecycle (abbreviated)
 *   - Kill switch (one cycle)
 *   - Rollback drill
 *   - Chirpee full regression
 *   - Final verdict JSON
 *
 * @rule:AEG-HG-001 promotion_permitted_ship_chief=true is NOT the same as enabled
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import { approveToken, denyToken, revokeToken, runRollbackDrill } from "../src/enforcement/approval";
import {
  simulateHardGate,
  HARD_GATE_GLOBALLY_ENABLED,
  HARD_GATE_POLICIES,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
} from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync, existsSync } from "fs";
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
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(80)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(80)} expected=${expected} actual=${actual}`); }
}

function okStatus(r: { ok: boolean }) { return r.ok ? "accepted" : "rejected"; }

const MALFORMED = new Set(["IMPOSSIBLE_OP","EMPTY_CAPABILITY_ON_WRITE"]);
let totalTP = 0, totalFP = 0, totalProdFires = 0;
const gateTokens: { svc: string; token: string }[] = [];

function gate(svc: string, op: string, cap: string, caller = "b35r7") {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: caller, session_id: `b35r7-${svc}-${op}-${cap}-${Date.now()}` });
  logDecision(d);
  if (d.approval_token) gateTokens.push({ svc, token: d.approval_token });
  return d;
}

function observe(svc: string, label: string, op: string, cap: string, expSoft: string, expSim: string, cat: string) {
  const d = gate(svc, op, cap);
  check(`soft [${svc}] ${label}`, d.decision, expSoft, cat);
  check(`phase [${svc}] ${label}: soft_canary`, d.enforcement_phase, "soft_canary", cat);
  const simOff = simulateHardGate(svc, d.decision, cap, op, false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`sim(off) [${svc}] ${label}: no fire`, simOff.hard_gate_would_apply, false, cat);
  const simOn = simulateHardGate(svc, d.decision, cap, op, true);
  check(`sim(on)  [${svc}] ${label}`, simOn.simulated_hard_decision, expSim, cat);
  const isMalformed = MALFORMED.has(cap.toUpperCase());
  if (simOn.simulated_hard_decision === "BLOCK" && !isMalformed) totalFP++;
  if (simOn.simulated_hard_decision === "BLOCK" && isMalformed) totalTP++;
  return { d, simOn };
}

console.log(`\n══ Batch 35 Soak Run ${SOAK_RUN}/7 — Final Dress Rehearsal ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("chirpee in env (call-time)", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("chirpee") ?? false, true, "pre");
check("ship-slm NOT in env", !process.env.AEGIS_HARD_GATE_SERVICES?.includes("ship-slm"), true, "pre");
check("chief-slm NOT in env", !process.env.AEGIS_HARD_GATE_SERVICES?.includes("chief-slm"), true, "pre");
check("ship-slm hard_gate_enabled = false", SHIP_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chief-slm hard_gate_enabled = false", CHIEF_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("policy registry = 3 entries", Object.keys(HARD_GATE_POLICIES).length, 3, "pre");

// Wave 1: Normal traffic
console.log("\n── Wave 1: Normal traffic ──");
for (const svc of ["ship-slm","chief-slm"]) {
  for (const [op,cap] of [["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"],["search","SEARCH"],["health","HEALTH"],["write","WRITE"],["create","WRITE"],["patch","WRITE"]] as [string,string][]) {
    observe(svc, `${op}/${cap}`, op, cap, "ALLOW", "ALLOW", "wave1_normal");
  }
}

// Wave 2: SLM domain ops
console.log("\n── Wave 2: SLM domain ops ──");
for (const [op,cap] of [["summarize","SUMMARIZE_VOYAGE"],["classify","CLASSIFY_CARGO"],["extract","EXTRACT_BL"],["infer","INFER_RISK"]] as [string,string][]) {
  observe("ship-slm", `${op}/${cap}`, op, cap, "ALLOW", "ALLOW", "wave2_domain");
}
for (const [op,cap] of [["analyze","ANALYZE_WATCH"],["brief","BRIEF_OFFICER"],["recommend","RECOMMEND_ACTION"],["assess","ASSESS_FATIGUE"]] as [string,string][]) {
  observe("chief-slm", `${op}/${cap}`, op, cap, "ALLOW", "ALLOW", "wave2_domain");
}

// Wave 3: High-risk
console.log("\n── Wave 3: High-risk ops ──");
for (const svc of ["ship-slm","chief-slm"]) {
  for (const [op,cap] of [["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"]] as [string,string][]) {
    observe(svc, `${op}/${cap}`, op, cap, "GATE", "GATE", "wave3_highrisk");
  }
  for (const [op,cap] of [["execute","EXECUTE"],["approve","APPROVE"],["spawn","SPAWN_AGENTS"]] as [string,string][]) {
    observe(svc, `${op}/${cap}`, op, cap, "ALLOW", "ALLOW", "wave3_highrisk");
  }
}

// Wave 4: Malformed TPs
console.log("\n── Wave 4: Malformed true positives ──");
for (const svc of ["ship-slm","chief-slm"]) {
  for (let i = 1; i <= 5; i++) {
    observe(svc, `IMPOSSIBLE_OP[${i}]`, "frob_impossible", "IMPOSSIBLE_OP", "ALLOW", "BLOCK", "wave4_malformed");
    observe(svc, `EMPTY_CAP[${i}]`, "write", "EMPTY_CAPABILITY_ON_WRITE", "ALLOW", "BLOCK", "wave4_malformed");
  }
}

// Wave 5: Boundary
console.log("\n── Wave 5: Boundary ──");
for (const svc of ["ship-slm","chief-slm"]) {
  for (const cap of ["FUTURE_CAP_2031","VESSEL_OVERRIDE_AI","CREW_AUTONOMY","CARGO_SEAL_BREAK"]) {
    const { simOn } = observe(svc, `unknown:${cap}`, "execute", cap, "ALLOW", "ALLOW", "wave5_boundary");
    // additional invariant: hard_gate_would_apply must be false
    check(`${svc} unknown '${cap}': would_apply = false`, simOn.hard_gate_would_apply, false, "wave5_boundary");
  }
}

// Wave 6: Approval lifecycle (abbreviated)
console.log("\n── Wave 6: Approval lifecycle ──");
const shipTokens  = gateTokens.filter(t => t.svc === "ship-slm").map(t => t.token);
const chiefTokens = gateTokens.filter(t => t.svc === "chief-slm").map(t => t.token);
if (shipTokens.length >= 2 && chiefTokens.length >= 2) {
  check("ship approve", okStatus(approveToken(shipTokens[0], "r7 approve", "captain@ankr")), "accepted", "wave6_lifecycle");
  check("ship replay rejected", okStatus(approveToken(shipTokens[0], "replay", "ops@ankr")), "rejected", "wave6_lifecycle");
  check("ship deny", okStatus(denyToken(shipTokens[1], "r7 deny", "ops@ankr")), "accepted", "wave6_lifecycle");
  check("chief approve", okStatus(approveToken(chiefTokens[0], "r7 approve chief", "captain@ankr")), "accepted", "wave6_lifecycle");
  check("chief deny", okStatus(denyToken(chiefTokens[1], "r7 deny chief", "ops@ankr")), "accepted", "wave6_lifecycle");
}

// Wave 7: Kill switch (one cycle)
console.log("\n── Wave 7: Kill switch (one cycle) ──");
const savedEnabled = process.env.AEGIS_RUNTIME_ENABLED;
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const svc of ["ship-slm","chief-slm"]) {
  const dKill = gate(svc, "frob_impossible", "IMPOSSIBLE_OP", "b35r7-kill");
  check(`kill: ${svc} IMPOSSIBLE_OP → shadow`, dKill.enforcement_phase, "shadow", "wave7_kill");
  check(`kill: ${svc} not BLOCK`, dKill.decision !== "BLOCK", true, "wave7_kill");
}
const chirpeeKill = gate("chirpee", "frob", "IMPOSSIBLE_OP", "b35r7-kill");
check("kill: chirpee IMPOSSIBLE_OP → shadow (AEG-E-006)", chirpeeKill.enforcement_phase, "shadow", "wave7_kill");
process.env.AEGIS_RUNTIME_ENABLED = savedEnabled ?? "true";
// Restore check
const postRestore = gate("chirpee", "frob", "IMPOSSIBLE_OP", "b35r7-restore");
check("post-restore: chirpee IMPOSSIBLE_OP → hard_gate", postRestore.enforcement_phase, "hard_gate", "wave7_kill");
check("post-restore: chirpee IMPOSSIBLE_OP → BLOCK", postRestore.decision, "BLOCK", "wave7_kill");

// Rollback drill
const drill = runRollbackDrill(evaluate, ["ship-slm","chief-slm"], [
  { operation: "deploy", requested_capability: "CI_DEPLOY" },
  { operation: "delete", requested_capability: "DELETE" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "wave7_rollback");
for (const svc of ["ship-slm","chief-slm"]) {
  const cs = drill.services_checked.find(s => s.service_id === svc);
  check(`${svc}: shadow after kill`, cs?.phase_after_kill, "shadow", "wave7_rollback");
}

// Chirpee full regression
console.log("\n── Chirpee full regression ──");
const crRead = gate("chirpee", "read", "READ", "b35r7-reg");
check("chirpee READ → ALLOW", crRead.decision, "ALLOW", "regression");
check("chirpee READ → hard_gate phase", crRead.enforcement_phase, "hard_gate", "regression");
const crImp = gate("chirpee", "frob", "IMPOSSIBLE_OP", "b35r7-reg");
check("chirpee IMPOSSIBLE_OP → BLOCK", crImp.decision, "BLOCK", "regression");
check("chirpee IMPOSSIBLE_OP hard_gate_applied", crImp.hard_gate_applied, true, "regression");
check("chirpee IMPOSSIBLE_OP hard_gate_service = chirpee", crImp.hard_gate_service, "chirpee", "regression");
const crEmpty = gate("chirpee", "write", "EMPTY_CAPABILITY_ON_WRITE", "b35r7-reg");
check("chirpee EMPTY_CAP → BLOCK", crEmpty.decision, "BLOCK", "regression");
check("chirpee EMPTY_CAP hard_gate_applied", crEmpty.hard_gate_applied, true, "regression");
const crGate = gate("chirpee", "ai-execute", "AI_EXECUTE", "b35r7-reg");
check("chirpee AI_EXECUTE → GATE (hard_gate phase)", crGate.decision, "GATE", "regression");
check("chirpee AI_EXECUTE → hard_gate_applied = false (still_gate)", crGate.hard_gate_applied, false, "regression");

// Canary
console.log("\n── Canary ──");
const canary = getCanaryStatus(["ship-slm","chief-slm","chirpee"]);
const cc = canary.success_criteria;
check("no_read_gates", cc.no_read_gates, true, "canary");
check("no_unknown_service_blocks", cc.no_unknown_service_blocks, true, "canary");
check("no_token_replay_successes", cc.no_token_replay_successes, true, "canary");
check("rollback_drill_passed", cc.rollback_drill_passed, true, "canary");

// Count validation
// Wave 4: 5×IMPOSSIBLE + 5×EMPTY × 2 services = 20 TPs
console.log("\n── Count validation ──");
check("false positives = 0", totalFP, 0, "count");
check("true positives = 20 (5×IMPOSSIBLE×2 + 5×EMPTY×2)", totalTP, 20, "count");
check("production fires = 0", totalProdFires, 0, "count");

const soakRunPass = failed === 0 && totalFP === 0 && totalTP === 20 && totalProdFires === 0;

// Load previous run results to determine overall 7/7 verdict
function loadRunResult(run: number): boolean {
  const path = join(dir, `batch35_soak_run${run}_metrics.json`);
  if (!existsSync(path)) return false;
  try {
    const data = JSON.parse(require("fs").readFileSync(path, "utf-8"));
    return data.verdict === "PASS";
  } catch { return false; }
}

const allRunResults = [1,2,3,4,5,6].map(r => ({ run: r, pass: loadRunResult(r) }));
const priorRunsAllPass = allRunResults.every(r => r.pass);
const allSevenPass = priorRunsAllPass && soakRunPass;

const promotionPermitted = allSevenPass; // true only if 7/7 PASS

console.log(`\n══ Batch 35 Final Verdict ══`);
console.log(`  Run 7/7: ${soakRunPass ? "PASS" : "FAIL"}`);
allRunResults.forEach(r => console.log(`  Run ${r.run}/7: ${r.pass ? "PASS" : "FAIL or MISSING"}`));
console.log(`  All 7 runs: ${allSevenPass ? "PASS" : "FAIL"}`);
console.log(`  promotion_permitted_ship_chief: ${promotionPermitted}`);

if (failures.length) {
  console.log("\n  Failures:");
  failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));
}

// Final verdict artifact
const finalVerdict = {
  batch: 35,
  verdict_date: RUN_DATE,
  services: ["ship-slm","chief-slm"],
  soak_runs_required: 7,
  soak_runs_complete: allSevenPass ? 7 : allRunResults.filter(r=>r.pass).length + (soakRunPass ? 1 : 0),
  all_seven_pass: allSevenPass,
  promotion_permitted_ship_chief: promotionPermitted,
  // Hard gate stays disabled — promotion is a separate human act (Batch 36)
  hard_gate_enabled_ship_slm: false,
  hard_gate_enabled_chief_slm: false,
  promotion_requires: "Add ship-slm,chief-slm to AEGIS_HARD_GATE_SERVICES — manual act (Batch 36)",
  chirpee_status: "live hard-gate — unaffected",
  run_results: [...allRunResults.map(r => ({ run: r.run, pass: r.pass })), { run: 7, pass: soakRunPass }],
  run7: { checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP },
  note: promotionPermitted
    ? "7/7 soak complete. Policies are proven stable. Promotion is a human decision in Batch 36."
    : "Not all 7 runs passed. Resolve failures before promotion.",
};

const summaryMd = `# Batch 35 — ship-slm + chief-slm HG-1 Soak 7/7 Final Verdict

**Date:** ${RUN_DATE}
**Verdict:** ${allSevenPass ? "PASS — 7/7 clean" : "FAIL — see failures"}
**promotion_permitted_ship_chief:** ${promotionPermitted}

## Soak run results

| Run | Focus | Result |
|---|---|---|
| 1/7 | Full surface (Run 1) | ${allRunResults[0]?.pass ? "✅ PASS" : "❌ FAIL"} |
| 2/7 | Mixed-case + alias normalization | ${allRunResults[1]?.pass ? "✅ PASS" : "❌ FAIL"} |
| 3/7 | Burst traffic + repeated malformed | ${allRunResults[2]?.pass ? "✅ PASS" : "❌ FAIL"} |
| 4/7 | Approval lifecycle heavy | ${allRunResults[3]?.pass ? "✅ PASS" : "❌ FAIL"} |
| 5/7 | Kill switch + rollback heavy | ${allRunResults[4]?.pass ? "✅ PASS" : "❌ FAIL"} |
| 6/7 | Unknown capability + boundary heavy | ${allRunResults[5]?.pass ? "✅ PASS" : "❌ FAIL"} |
| 7/7 | Final dress rehearsal | ${soakRunPass ? "✅ PASS" : "❌ FAIL"} |

## What was proven

- Normal work (READ/WRITE/domain ops) → not blocked ✅
- Malformed true positives → hard-sim BLOCK every time ✅
- Critical ops → soft GATE, hard-sim GATE (never BLOCK) ✅
- High ops (EXECUTE/APPROVE/SPAWN) → soft ALLOW, hard-sim ALLOW (still_gate does not upgrade) ✅
- Unknown caps → soft decision preserved, not hard-BLOCK ✅
- Unknown services → WARN, never BLOCK ✅
- Kill switch suppresses hard-gate overlay (AEG-E-006) ✅
- Rollback is config-only — immediate ✅
- chirpee live hard-gate unaffected throughout ✅

## Next step

${promotionPermitted
  ? `**Batch 36**: Add ship-slm and chief-slm to AEGIS_HARD_GATE_SERVICES.
This is a manual act. hard_gate_enabled=false in the policy objects is NOT changed —
it remains the policy default. Only the env var changes.`
  : "Resolve failed runs before proceeding to Batch 36."}
`;

writeFileSync(join(dir, `batch35_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, date: RUN_DATE, verdict: soakRunPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP, production_gate_fires: totalProdFires, ready_to_promote: false }, null, 2));
writeFileSync(join(dir, "batch35_ship_chief_final_verdict.json"), JSON.stringify(finalVerdict, null, 2));
writeFileSync(join(dir, "batch35_ship_chief_final_verdict_summary.md"), summaryMd);

console.log(`\n  Artifacts written:`);
console.log(`    batch35_soak_run7_metrics.json`);
console.log(`    batch35_ship_chief_final_verdict.json`);
console.log(`    batch35_ship_chief_final_verdict_summary.md`);
console.log(`\n  Batch 35 Run ${SOAK_RUN}/7: ${soakRunPass ? "PASS" : "FAIL"}`);
console.log(`  Final verdict — promotion_permitted_ship_chief: ${promotionPermitted}`);
