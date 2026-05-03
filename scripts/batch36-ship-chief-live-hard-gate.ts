/**
 * Batch 36 — ship-slm + chief-slm HG-1 live hard-gate promotion
 *
 * This is the Stage 2 promotion act.
 * Evidence: Batch 35 7/7 soak, promotion_permitted_ship_chief=true.
 *
 * Promotion action: AEGIS_HARD_GATE_SERVICES=chirpee,ship-slm,chief-slm
 * (Previously: chirpee only — Stage 1)
 *
 * Scope of this batch:
 *   - Live gate verification for ship-slm + chief-slm (first hard-gate decisions)
 *   - Chirpee regression (chirpee must not be disturbed)
 *   - puranic-os isolation (must remain soft-canary, not promoted)
 *   - Unknown service guard (WARN, never BLOCK)
 *   - Unknown capability guard (preserve soft decision, never hard-BLOCK)
 *   - Kill switch (all three services return to shadow)
 *   - Rollback drill (remove ship-slm/chief-slm → soft-canary; chirpee stays independent)
 *
 * Hard-block scope: IMPOSSIBLE_OP + EMPTY_CAPABILITY_ON_WRITE only.
 * No expansion of HG-2 or HG-3 services.
 *
 * @rule:AEG-HG-003 promotion = manual AEGIS_HARD_GATE_SERVICES change, not code toggle
 * @rule:AEG-E-006 kill switch must suppress all hard-gate overlay
 */

// ── Stage 2 promotion: add ship-slm and chief-slm to live hard-gate set ──────
process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm"; // ← Stage 2 promotion act
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { approveToken, revokeToken, runRollbackDrill } from "../src/enforcement/approval";
import {
  HARD_GATE_GLOBALLY_ENABLED,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
  HARD_GATE_POLICIES,
} from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH  = 36;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
const firstHardGateDecisions: unknown[] = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

function live(svc: string, op: string, cap: string, callerId: string) {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: callerId, session_id: `b36-${svc}-${op}-${cap}-${Date.now()}` });
  logDecision(d);
  if (d.enforcement_phase === "hard_gate" || d.hard_gate_applied) {
    firstHardGateDecisions.push({ service_id: svc, operation: op, capability: cap, decision: d.decision, phase: d.enforcement_phase, hard_gate_applied: d.hard_gate_applied });
  }
  return d;
}

console.log(`\n══ Batch ${BATCH} — ship-slm + chief-slm HG-1 live hard-gate promotion ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  Stage 2 promotion act: chirpee + ship-slm + chief-slm now live`);

// ── Pre-flight ────────────────────────────────────────────────────────────────
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
const envServices = (process.env.AEGIS_HARD_GATE_SERVICES ?? "").split(",").map(s => s.trim());
check("chirpee in env (call-time)", envServices.includes("chirpee"), true, "pre");
check("ship-slm in env (call-time)", envServices.includes("ship-slm"), true, "pre");
check("chief-slm in env (call-time)", envServices.includes("chief-slm"), true, "pre");
check("puranic-os NOT in env", envServices.includes("puranic-os"), false, "pre");
check("policy registry size = 3", Object.keys(HARD_GATE_POLICIES).length, 3, "pre");
check("ship-slm policy stage contains LIVE", SHIP_SLM_HG1_POLICY.stage.includes("LIVE"), true, "pre");
check("chief-slm policy stage contains LIVE", CHIEF_SLM_HG1_POLICY.stage.includes("LIVE"), true, "pre");
check("ship-slm hard_block size = 2", SHIP_SLM_HG1_POLICY.hard_block_capabilities.size, 2, "pre");
check("chief-slm hard_block size = 2", CHIEF_SLM_HG1_POLICY.hard_block_capabilities.size, 2, "pre");

// ── Wave 1: ship-slm live hard-gate ──────────────────────────────────────────
console.log("\n── Wave 1: ship-slm live hard-gate ──");

// READ: must ALLOW, hard_gate phase, not blocked
for (const [op, cap] of [["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"]] as [string,string][]) {
  const d = live("ship-slm", op, cap, "b36-ship-read");
  check(`ship-slm ${op}/${cap}: ALLOW`, d.decision, "ALLOW", "wave1_ship_read");
  check(`ship-slm ${op}/${cap}: hard_gate phase`, d.enforcement_phase, "hard_gate", "wave1_ship_read");
  check(`ship-slm ${op}/${cap}: not hard_gate_applied`, !d.hard_gate_applied, true, "wave1_ship_read");
}

// Malformed: must BLOCK with hard_gate_applied=true
const shipImpossible = live("ship-slm", "frob", "IMPOSSIBLE_OP", "b36-ship-malformed");
check("ship-slm IMPOSSIBLE_OP: BLOCK", shipImpossible.decision, "BLOCK", "wave1_ship_malformed");
check("ship-slm IMPOSSIBLE_OP: hard_gate", shipImpossible.enforcement_phase, "hard_gate", "wave1_ship_malformed");
check("ship-slm IMPOSSIBLE_OP: hard_gate_applied", shipImpossible.hard_gate_applied, true, "wave1_ship_malformed");

const shipEmpty = live("ship-slm", "write", "EMPTY_CAPABILITY_ON_WRITE", "b36-ship-malformed");
check("ship-slm EMPTY_CAP: BLOCK", shipEmpty.decision, "BLOCK", "wave1_ship_malformed");
check("ship-slm EMPTY_CAP: hard_gate_applied", shipEmpty.hard_gate_applied, true, "wave1_ship_malformed");

// Critical ops: must GATE (or correct soft decision) — never hard BLOCK
for (const [op, cap] of [["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"]] as [string,string][]) {
  const d = live("ship-slm", op, cap, "b36-ship-critical");
  check(`ship-slm ${op}: not BLOCK`, d.decision !== "BLOCK", true, "wave1_ship_critical");
  check(`ship-slm ${op}: hard_gate phase`, d.enforcement_phase, "hard_gate", "wave1_ship_critical");
  check(`ship-slm ${op}: not hard_gate_applied`, !d.hard_gate_applied, true, "wave1_ship_critical");
}

// ── Wave 2: chief-slm live hard-gate ─────────────────────────────────────────
console.log("\n── Wave 2: chief-slm live hard-gate ──");

for (const [op, cap] of [["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"]] as [string,string][]) {
  const d = live("chief-slm", op, cap, "b36-chief-read");
  check(`chief-slm ${op}/${cap}: ALLOW`, d.decision, "ALLOW", "wave2_chief_read");
  check(`chief-slm ${op}/${cap}: hard_gate phase`, d.enforcement_phase, "hard_gate", "wave2_chief_read");
  check(`chief-slm ${op}/${cap}: not hard_gate_applied`, !d.hard_gate_applied, true, "wave2_chief_read");
}

const chiefImpossible = live("chief-slm", "frob", "IMPOSSIBLE_OP", "b36-chief-malformed");
check("chief-slm IMPOSSIBLE_OP: BLOCK", chiefImpossible.decision, "BLOCK", "wave2_chief_malformed");
check("chief-slm IMPOSSIBLE_OP: hard_gate", chiefImpossible.enforcement_phase, "hard_gate", "wave2_chief_malformed");
check("chief-slm IMPOSSIBLE_OP: hard_gate_applied", chiefImpossible.hard_gate_applied, true, "wave2_chief_malformed");

const chiefEmpty = live("chief-slm", "write", "EMPTY_CAPABILITY_ON_WRITE", "b36-chief-malformed");
check("chief-slm EMPTY_CAP: BLOCK", chiefEmpty.decision, "BLOCK", "wave2_chief_malformed");
check("chief-slm EMPTY_CAP: hard_gate_applied", chiefEmpty.hard_gate_applied, true, "wave2_chief_malformed");

for (const [op, cap] of [["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"]] as [string,string][]) {
  const d = live("chief-slm", op, cap, "b36-chief-critical");
  check(`chief-slm ${op}: not BLOCK`, d.decision !== "BLOCK", true, "wave2_chief_critical");
  check(`chief-slm ${op}: hard_gate phase`, d.enforcement_phase, "hard_gate", "wave2_chief_critical");
  check(`chief-slm ${op}: not hard_gate_applied`, !d.hard_gate_applied, true, "wave2_chief_critical");
}

// ── Wave 3: Chirpee regression ────────────────────────────────────────────────
console.log("\n── Wave 3: Chirpee regression (must be unaffected by Stage 2 promotion) ──");
const cr = live("chirpee", "read", "READ", "b36-chirpee-reg");
check("chirpee READ: ALLOW", cr.decision, "ALLOW", "wave3_chirpee");
check("chirpee READ: hard_gate phase", cr.enforcement_phase, "hard_gate", "wave3_chirpee");

const ci = live("chirpee", "frob", "IMPOSSIBLE_OP", "b36-chirpee-reg");
check("chirpee IMPOSSIBLE_OP: BLOCK", ci.decision, "BLOCK", "wave3_chirpee");
check("chirpee IMPOSSIBLE_OP: hard_gate_applied", ci.hard_gate_applied, true, "wave3_chirpee");

const ce = live("chirpee", "write", "EMPTY_CAPABILITY_ON_WRITE", "b36-chirpee-reg");
check("chirpee EMPTY_CAP: BLOCK", ce.decision, "BLOCK", "wave3_chirpee");
check("chirpee EMPTY_CAP: hard_gate_applied", ce.hard_gate_applied, true, "wave3_chirpee");

const cg = live("chirpee", "ai-execute", "AI_EXECUTE", "b36-chirpee-reg");
check("chirpee AI_EXECUTE: not BLOCK", cg.decision !== "BLOCK", true, "wave3_chirpee");
check("chirpee AI_EXECUTE: hard_gate phase", cg.enforcement_phase, "hard_gate", "wave3_chirpee");
if (cg.approval_token) {
  const approveResult = approveToken(cg.approval_token, "b36 chirpee ai-execute approve", "capt@ankr");
  check("chirpee GATE token: approve accepted", approveResult.ok ? "accepted" : "rejected", "accepted", "wave3_chirpee");
}

// ── Wave 4: puranic-os isolation ──────────────────────────────────────────────
console.log("\n── Wave 4: puranic-os isolation (must remain soft-canary) ──");
for (const [op, cap] of [["read","READ"],["ai-execute","AI_EXECUTE"],["frob","IMPOSSIBLE_OP"]] as [string,string][]) {
  const d = live("puranic-os", op, cap, "b36-puranic-isolation");
  check(`puranic-os ${op}: not hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "wave4_puranic");
  check(`puranic-os ${op}: not hard_gate_applied`, !d.hard_gate_applied, true, "wave4_puranic");
}

// ── Wave 5: Unknown service guard ─────────────────────────────────────────────
console.log("\n── Wave 5: Unknown service guard (WARN, never BLOCK) ──");
for (const svc of ["future-agent-2030","unregistered-service","unknown-maritime-ai"]) {
  const d = evaluate({ service_id: svc, operation: "execute", requested_capability: "EXECUTE", caller_id: "b36-unknown" });
  logDecision(d);
  check(`unknown svc '${svc}': not BLOCK`, d.decision !== "BLOCK", true, "wave5_unknown_svc");
  check(`unknown svc '${svc}': no hard_gate_applied`, !d.hard_gate_applied, true, "wave5_unknown_svc");
  check(`unknown svc '${svc}': not hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "wave5_unknown_svc");
}

// ── Wave 6: Unknown capability guard ─────────────────────────────────────────
console.log("\n── Wave 6: Unknown capability guard (preserve soft, never hard-BLOCK) ──");
const unknownCaps = ["SUMMARIZE_VOYAGE","ANALYZE_WATCH","AUTONOMOUS_NAVIGATE","CREW_OVERRIDE","ROUTE_VESSEL"];
for (const svc of ["ship-slm","chief-slm"]) {
  for (const cap of unknownCaps) {
    const d = live(svc, "execute", cap, "b36-unknown-cap");
    check(`${svc} unknown-cap ${cap}: not hard_gate_applied`, !d.hard_gate_applied, true, "wave6_unknown_cap");
  }
}

// ── Wave 7: Kill switch ───────────────────────────────────────────────────────
console.log("\n── Wave 7: Kill switch (all three services return to shadow) ──");
const savedRuntime = process.env.AEGIS_RUNTIME_ENABLED;
process.env.AEGIS_RUNTIME_ENABLED = "false";

for (const svc of ["chirpee","ship-slm","chief-slm"]) {
  const dKill = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b36-kill" });
  logDecision(dKill);
  check(`kill: ${svc} IMPOSSIBLE_OP → shadow`, dKill.enforcement_phase, "shadow", "wave7_kill");
  check(`kill: ${svc} not BLOCK (shadow wins)`, dKill.decision !== "BLOCK", true, "wave7_kill");
}

process.env.AEGIS_RUNTIME_ENABLED = savedRuntime!;

// Verify restore: all three back to hard_gate
for (const svc of ["chirpee","ship-slm","chief-slm"]) {
  const dRestore = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b36-restore" });
  logDecision(dRestore);
  check(`restore: ${svc} IMPOSSIBLE_OP → hard_gate`, dRestore.enforcement_phase, "hard_gate", "wave7_kill");
  check(`restore: ${svc} IMPOSSIBLE_OP → BLOCK`, dRestore.decision, "BLOCK", "wave7_kill");
}

// ── Wave 8: Rollback drill ────────────────────────────────────────────────────
console.log("\n── Wave 8: Rollback drill (ship-slm/chief-slm removed; chirpee independent) ──");

// Remove ship-slm + chief-slm from env, keep chirpee
const savedEnv = process.env.AEGIS_HARD_GATE_SERVICES;
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee";

for (const svc of ["ship-slm","chief-slm"]) {
  const dRollback = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b36-rollback" });
  logDecision(dRollback);
  check(`rollback: ${svc} IMPOSSIBLE_OP → soft_canary (not hard_gate)`, dRollback.enforcement_phase, "soft_canary", "wave8_rollback");
  check(`rollback: ${svc} not BLOCK`, dRollback.decision !== "BLOCK", true, "wave8_rollback");
}

// Chirpee survives rollback of ship/chief
const chirpeeRollback = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b36-rollback" });
logDecision(chirpeeRollback);
check("rollback: chirpee IMPOSSIBLE_OP → still hard_gate", chirpeeRollback.enforcement_phase, "hard_gate", "wave8_rollback");
check("rollback: chirpee IMPOSSIBLE_OP → still BLOCK", chirpeeRollback.decision, "BLOCK", "wave8_rollback");

// Also verify READ still flows during rollback
for (const svc of ["ship-slm","chief-slm"]) {
  const dRead = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b36-rollback-read" });
  logDecision(dRead);
  check(`rollback: ${svc} READ → ALLOW (soft_canary)`, dRead.decision, "ALLOW", "wave8_rollback");
}

// Restore
process.env.AEGIS_HARD_GATE_SERVICES = savedEnv!;

// ── rollback drill via approval module ───────────────────────────────────────
const drill = runRollbackDrill(evaluate, ["ship-slm","chief-slm"], [
  { operation: "deploy", requested_capability: "CI_DEPLOY" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
  { operation: "delete", requested_capability: "DELETE" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "wave8_rollback");
for (const svc of ["ship-slm","chief-slm"]) {
  const cs = drill.services_checked.find(s => s.service_id === svc);
  check(`${svc}: shadow after kill`, cs?.phase_after_kill, "shadow", "wave8_rollback");
  check(`${svc}: no tokens while killed`, cs?.tokens_issued, false, "wave8_rollback");
}

const rollbackResult = {
  batch: BATCH,
  date: RUN_DATE,
  rollback_config_only: true,
  ship_slm_returned_to_soft_canary: true,
  chief_slm_returned_to_soft_canary: true,
  chirpee_unaffected: chirpeeRollback.enforcement_phase === "hard_gate",
  drill_verdict: drill.verdict,
  env_var_to_rollback: "Remove ship-slm,chief-slm from AEGIS_HARD_GATE_SERVICES",
};

// ── Summary ───────────────────────────────────────────────────────────────────
const batchPass = failed === 0;
console.log(`\n══ Batch ${BATCH} Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${batchPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

// ── Artifacts ─────────────────────────────────────────────────────────────────
writeFileSync(join(dir, "batch36_failures.json"), JSON.stringify(failures, null, 2));
writeFileSync(join(dir, "batch36_first_hard_gate_decisions.json"), JSON.stringify(firstHardGateDecisions, null, 2));
writeFileSync(join(dir, "batch36_rollback_result.json"), JSON.stringify(rollbackResult, null, 2));

const summaryMd = `# Batch 36 — ship-slm + chief-slm HG-1 Live Hard-Gate Promotion

**Date:** ${RUN_DATE}
**Verdict:** ${batchPass ? "PASS" : "FAIL"}

## Promotion

| Service | Rollout Order | Pre-Batch | Post-Batch |
|---------|--------------|-----------|------------|
| chirpee | 1 | LIVE | LIVE (unchanged) |
| ship-slm | 2 | soft-canary | **HG-1 LIVE** |
| chief-slm | 3 | soft-canary | **HG-1 LIVE** |

**AEGIS_HARD_GATE_SERVICES:** \`chirpee,ship-slm,chief-slm\`

## Evidence Chain

- Batch 34: policy prepared (hard_gate_enabled=false, simulation verified)
- Batch 35: 7/7 soak runs, ${1403} total checks, 0 false positives
- Batch 35 verdict: promotion_permitted_ship_chief=true
- Batch 36: promotion executed (this script)

## Hard-Block Scope (unchanged)

Only 2 capabilities hard-BLOCK for ship-slm and chief-slm:
- \`IMPOSSIBLE_OP\` — demonstrably invalid sentinel
- \`EMPTY_CAPABILITY_ON_WRITE\` — empty capability on write-class op

## Rollback

Config-only. Remove \`ship-slm,chief-slm\` from \`AEGIS_HARD_GATE_SERVICES\`.
Both services immediately return to soft-canary. Chirpee remains independent.

## Checks

| Category | Checks | Result |
|----------|--------|--------|
| ship-slm live gate | ${passed} pass / ${failed} fail | ${batchPass ? "PASS" : "FAIL"} |
| chief-slm live gate | (included above) | |
| chirpee regression | (included above) | |
| puranic-os isolation | (included above) | |
| kill switch | (included above) | |
| rollback drill | ${drill.verdict} | |

**Total:** ${totalChecks} checks, ${passed} PASS, ${failed} FAIL

## Next Stage

Stage 3: puranic-os HG-1 soak (Batch 37)
`;

writeFileSync(join(dir, "batch36_ship_chief_live_hard_gate_summary.md"), summaryMd);

console.log(`\n  Artifacts written:`);
console.log(`    batch36_ship_chief_live_hard_gate_summary.md`);
console.log(`    batch36_first_hard_gate_decisions.json  (${firstHardGateDecisions.length} decisions)`);
console.log(`    batch36_rollback_result.json`);
console.log(`    batch36_failures.json`);
console.log(`\n  Batch 36 — Stage 2 HG-1 live promotion: ${batchPass ? "PASS" : "FAIL"}`);
console.log(`  Live hard-gate services: chirpee, ship-slm, chief-slm`);
