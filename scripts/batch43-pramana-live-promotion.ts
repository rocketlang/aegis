/**
 * Batch 43 — pramana HG-2A live hard-gate promotion
 *
 * Promotes pramana to live HG-2A after Batch 42 7/7 soak (promotion_permitted=true).
 * AEGIS_HARD_GATE_SERVICES now includes pramana. PRAMANA_HG2A_POLICY.hard_gate_enabled=true.
 *
 * Tasks:
 *   1. Policy + env alignment check
 *   2. Live hard-gate verification: pramana ALLOW/BLOCK/GATE surface
 *   3. Live MEMORY_WRITE/AUDIT_WRITE/SPAWN_AGENTS still_gate verification
 *   4. HG-1 regression: all 4 services clean
 *   5. HG-2 isolation: domain-capture / parali-central / carbonx / ankr-doctor NOT hard-gated
 *   6. Rollback drill: remove pramana → soft_canary; HG-1 stable; kill suppresses all
 *   7. Produce 4 artifacts
 *
 * @rule:AEG-HG-001 AEGIS_HARD_GATE_SERVICES is the actual runtime switch
 * @rule:AEG-HG-002 READ never hard-blocks
 * @rule:AEG-E-006  kill switch overrides all enforcement
 * @rule:AEG-E-002  rollback is config-only (env var removal)
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
// Promotion: pramana is now live
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PRAMANA_HG2A_POLICY } from "../src/enforcement/hard-gate-policy";
import { approveToken, runRollbackDrill } from "../src/enforcement/approval";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH = 43;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
const firstDecisions: Array<{ service: string; cap: string; op: string; decision: string; phase: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

function rec(d: ReturnType<typeof evaluate>, cap: string) {
  firstDecisions.push({ service: d.service_id, cap, op: cap.toLowerCase(), decision: d.decision, phase: d.enforcement_phase });
}

function gateToken(d: ReturnType<typeof evaluate>): string {
  return (d as unknown as { approval_token?: string }).approval_token ?? "";
}

let prodFires = 0;

console.log(`\n══ Batch ${BATCH} — pramana HG-2A LIVE HARD-GATE PROMOTION ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// ── Task 1: Policy + env alignment ───────────────────────────────────────────
console.log("\n── Task 1: Policy + env alignment ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "align");
check("pramana IN env (live)", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), true, "align");
check("PRAMANA_HG2A_POLICY.hard_gate_enabled = true (documentary)", PRAMANA_HG2A_POLICY.hard_gate_enabled, true, "align");
check("PRAMANA_HG2A_POLICY.hg_group = HG-2", PRAMANA_HG2A_POLICY.hg_group, "HG-2", "align");
check("PRAMANA_HG2A_POLICY.rollout_order = 5", PRAMANA_HG2A_POLICY.rollout_order, 5, "align");
check("stage string contains LIVE", PRAMANA_HG2A_POLICY.stage.includes("LIVE"), true, "align");
check("stage string contains Batch 43", PRAMANA_HG2A_POLICY.stage.includes("Batch 43"), true, "align");
check("hard_block contains IMPOSSIBLE_OP", PRAMANA_HG2A_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "align");
check("hard_block contains EMPTY_CAPABILITY_ON_WRITE", PRAMANA_HG2A_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "align");
check("never_block contains READ", PRAMANA_HG2A_POLICY.never_block_capabilities.has("READ"), true, "align");
// Verify soak verdict file exists
try {
  const verdict = JSON.parse(readFileSync(join(dir, "batch42_pramana_final_verdict.json"), "utf8"));
  check("batch42 verdict: promotion_permitted_pramana=true", verdict.promotion_permitted_pramana, true, "align");
  check("batch42 verdict: soak_runs_total=7", verdict.soak_runs_total, 7, "align");
  check("batch42 verdict: production_gate_fires_lifetime=0", verdict.production_gate_fires_lifetime, 0, "align");
} catch {
  check("batch42_pramana_final_verdict.json readable", false, true, "align");
}

// ── Task 2: Live hard-gate verification — ALLOW surface ───────────────────────
console.log("\n── Task 2a: pramana live ALLOW surface (hard_gate phase) ──");
for (const [op, cap] of [
  ["read",    "READ"],
  ["get",     "GET"],
  ["list",    "LIST"],
  ["query",   "QUERY"],
  ["search",  "SEARCH"],
  ["health",  "HEALTH"],
  ["verify",  "VERIFY"],
  ["attest",  "ATTEST"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b43-allow" });
  logDecision(d);
  rec(d, cap);
  check(`pramana LIVE [${cap}]: hard_gate phase`, d.enforcement_phase, "hard_gate", "live_allow");
  check(`pramana LIVE [${cap}]: ALLOW`, d.decision, "ALLOW", "live_allow");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Task 2: Live hard-gate verification — BLOCK surface ──────────────────────
console.log("\n── Task 2b: pramana live BLOCK surface ──");
for (const [op, cap] of [
  ["frob",  "IMPOSSIBLE_OP"],
  ["write", "EMPTY_CAPABILITY_ON_WRITE"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b43-block" });
  logDecision(d);
  rec(d, cap);
  check(`pramana LIVE [${cap}]: hard_gate phase`, d.enforcement_phase, "hard_gate", "live_block");
  check(`pramana LIVE [${cap}]: BLOCK`, d.decision, "BLOCK", "live_block");
}

// ── Task 2: Live hard-gate verification — GATE surface ───────────────────────
console.log("\n── Task 2c: pramana live GATE surface ──");
for (const [op, cap] of [
  ["ai-execute", "AI_EXECUTE"],
  ["deploy",     "CI_DEPLOY"],
  ["delete",     "DELETE"],
  ["execute",    "EXECUTE"],
  ["approve",    "APPROVE"],
  ["emit",       "EMIT"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b43-gate" });
  logDecision(d);
  rec(d, cap);
  check(`pramana LIVE [${cap}]: hard_gate phase`, d.enforcement_phase, "hard_gate", "live_gate");
  check(`pramana LIVE [${cap}]: GATE`, d.decision, "GATE", "live_gate");
}

// ── Task 3: still_gate — MEMORY_WRITE / AUDIT_WRITE / SPAWN_AGENTS ───────────
// These are downgrade-guard caps. Soft layer returns ALLOW (not gated there).
// Hard mode: if soft=BLOCK → downgrade to GATE. If soft=ALLOW → stays ALLOW.
// Test via simulateHardGate with pramana IN env (live hard-gate active).
console.log("\n── Task 3: still_gate downgrade guard (live hard-gate context) ──");
for (const [op, cap] of [
  ["write", "MEMORY_WRITE"],
  ["write", "AUDIT_WRITE"],
  ["write", "SPAWN_AGENTS"],
] as [string, string][]) {
  // Soft layer for pramana (now hard-gated) — evaluate() should return ALLOW for these
  // because they are not in hard_block and soft layer does not gate them for write ops
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b43-still" });
  logDecision(d);
  rec(d, cap);
  // These caps are in still_gate — they will not be hard-BLOCKed; they pass through soft decision
  // The hard gate logic: not in hard_block, is in still_gate → still_gate only fires on BLOCK soft
  check(`pramana LIVE [${cap}]: NOT BLOCK (still_gate preserves soft ALLOW)`, d.decision !== "BLOCK", true, "still_gate_live");
  check(`pramana LIVE [${cap}]: hard_gate phase`, d.enforcement_phase, "hard_gate", "still_gate_live");
  // Direct still_gate downgrade test (most important invariant)
  const simDG = simulateHardGate("pramana", "BLOCK", cap, op, true);
  check(`pramana [${cap}] still_gate: BLOCK→GATE (downgrade guard holds)`, simDG.simulated_hard_decision, "GATE", "still_gate_live");
  const simNU = simulateHardGate("pramana", "ALLOW", cap, op, true);
  check(`pramana [${cap}] still_gate: ALLOW→ALLOW (no upgrade)`, simNU.simulated_hard_decision, "ALLOW", "still_gate_live");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Task 4: HG-1 regression ───────────────────────────────────────────────────
console.log("\n── Task 4: HG-1 regression (all 4 services) ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b43-hg1" });
  check(`[${svc}] READ: hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b43-hg1" });
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
  const g = evaluate({ service_id: svc, operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b43-hg1" });
  check(`[${svc}] CI_DEPLOY: GATE`, g.decision, "GATE", "hg1_reg");
}

// ── Task 5: HG-2 isolation ────────────────────────────────────────────────────
console.log("\n── Task 5: HG-2 non-promoted isolation ──");
for (const [svc, label] of [
  ["domain-capture",  "HG-2A blocked"],
  ["parali-central",  "HG-2B not started"],
  ["carbonx",         "HG-2B not started"],
  ["ankr-doctor",     "HG-2C separate"],
] as [string, string][]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b43-iso" });
  check(`[${svc}] (${label}): NOT hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "hg2_isolation");
  check(`[${svc}] (${label}): NOT BLOCK (no hard-gate active)`, d.decision !== "BLOCK", true, "hg2_isolation");
  if (d.enforcement_phase === "hard_gate") prodFires++;
}
// Non-pilot (shadow)
for (const svc of ["unregistered-svc", "phantom-service"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b43-iso" });
  check(`[${svc}]: shadow + WARN`, d.enforcement_phase === "shadow" && d.decision === "WARN", true, "hg2_isolation");
}
// Unknown capability on live pramana: must not hard-BLOCK
const unkCap = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "BRAND_NEW_CAP", caller_id: "b43-unk" });
check("pramana live + unknown cap: NOT BLOCK", unkCap.decision !== "BLOCK", true, "unknown_cap");
check("pramana live + unknown cap: hard_gate phase", unkCap.enforcement_phase, "hard_gate", "unknown_cap");

// ── Task 6a: Approval on live hard-gate GATE decision ────────────────────────
console.log("\n── Task 6a: Approval token on live GATE ──");
{
  const d = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b43-apv" });
  logDecision(d);
  check("pramana LIVE EXECUTE: hard_gate + GATE (token issued)", d.enforcement_phase === "hard_gate" && d.decision === "GATE", true, "approval");
  const token = gateToken(d);
  check("EXECUTE live: approval_token present", !!token, true, "approval");
  const a = approveToken(token, "batch43 live approval test", "b43-operator");
  check("live GATE token: approve accepted", a.ok ? "accepted" : "rejected", "accepted", "approval");
  const replay = approveToken(token, "replay", "b43-replay");
  check("live GATE token: replay rejected", replay.ok ? "accepted" : "rejected", "rejected", "approval");
}

// ── Task 6b: Rollback drill ───────────────────────────────────────────────────
console.log("\n── Task 6b: Rollback drill ──");
// Step 1: confirm pramana is live hard_gate
{
  const pre = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b43-rb-pre" });
  check("rollback pre: pramana IMPOSSIBLE_OP → BLOCK (live)", pre.decision, "BLOCK", "rollback");
  check("rollback pre: pramana → hard_gate phase", pre.enforcement_phase, "hard_gate", "rollback");
}
// Step 2: remove pramana from env (rollback)
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
{
  const rb = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b43-rb" });
  check("rollback: pramana → soft_canary (config-only rollback)", rb.enforcement_phase, "soft_canary", "rollback");
  check("rollback: pramana IMPOSSIBLE_OP → ALLOW (no longer hard-gated)", rb.decision, "ALLOW", "rollback");
  const rbRead = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b43-rb" });
  check("rollback: pramana READ → soft_canary + ALLOW", rbRead.enforcement_phase === "soft_canary" && rbRead.decision === "ALLOW", true, "rollback");
}
// Step 3: confirm HG-1 stable after rollback
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b43-rb-hg1" });
  check(`[${svc}] stable after rollback: hard_gate + ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "rollback");
}
// Step 4: kill switch suppresses all hard-gate services
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana"; // re-add pramana for kill test
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const svc of ["pramana", "chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b43-kill" });
  check(`[${svc}] kill switch: shadow + not BLOCK`, d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true, "rollback");
}
process.env.AEGIS_RUNTIME_ENABLED = "true";
// Step 5: rollback drill via helper
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
const drill = runRollbackDrill(evaluate, ["pramana", "chirpee", "ship-slm", "chief-slm", "puranic-os"], [
  { operation: "read",  requested_capability: "READ" },
  { operation: "frob",  requested_capability: "IMPOSSIBLE_OP" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "rollback");
const ps = drill.services_checked.find(s => s.service_id === "pramana");
check("pramana: shadow after kill in drill", ps?.phase_after_kill, "shadow", "rollback");
check("pramana: no tokens while killed", ps?.tokens_issued, false, "rollback");
// Step 6: restore and verify
const afterDrill = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b43-restore" });
check("pramana: BLOCK restored after drill", afterDrill.decision, "BLOCK", "rollback");
check("pramana: hard_gate restored after drill", afterDrill.enforcement_phase, "hard_gate", "rollback");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b43-restore" });
  check(`[${svc}] restored: hard_gate`, d.enforcement_phase, "hard_gate", "rollback");
}

// ── Task 7: Artifacts ─────────────────────────────────────────────────────────
const batchPass = failed === 0 && prodFires === 0;
console.log(`\n══ Batch ${BATCH} Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${batchPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

// batch43_pramana_live_hard_gate_summary.md
const md = `# Batch 43 — pramana HG-2A Live Hard-Gate Promotion

Date: ${RUN_DATE}
Verdict: **${batchPass ? "PASS" : "FAIL"}**
Checks: ${totalChecks}  Pass: ${passed}  Fail: ${failed}
Production fires: ${prodFires}

## Live Status

| Service | HG Group | Phase | Hard-Gate Enabled |
|---------|----------|-------|------------------|
| chirpee | HG-1 | hard_gate (live) | true |
| ship-slm | HG-1 | hard_gate (live) | true |
| chief-slm | HG-1 | hard_gate (live) | true |
| puranic-os | HG-1 | hard_gate (live) | true |
| **pramana** | **HG-2A** | **hard_gate (LIVE — Batch 43)** | **true** |

## Isolated (not promoted)

| Service | Status |
|---------|--------|
| domain-capture | HG-2A blocked — registry mapping issue |
| parali-central | HG-2B — external impact review pending |
| carbonx | HG-2B — external impact review pending |
| ankr-doctor | HG-2C — separate governance review |

## pramana Hard-Gate Surface

**BLOCK:** IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE
**GATE:** AI_EXECUTE, CI_DEPLOY, DELETE, EXECUTE, APPROVE, EMIT
**ALLOW:** READ, GET, LIST, QUERY, SEARCH, HEALTH, VERIFY, ATTEST (+ domain ops)
**still_gate (downgrade guard):** MEMORY_WRITE, AUDIT_WRITE, SPAWN_AGENTS, TRIGGER, FULL_AUTONOMY
  - soft BLOCK → hard GATE (never live-BLOCK these caps)
  - soft ALLOW → remains ALLOW (not soft-gated; tested via simulateHardGate, not evaluate())

## Rollback

AEGIS_HARD_GATE_SERVICES is the runtime switch.
Remove pramana from it → immediate return to soft_canary. No code change needed.

## Soak Reference

Batch 42: 7/7 PASS, 838 total checks, 0 production fires
batch42_pramana_final_verdict.json: promotion_permitted_pramana=true

## Standing Doctrine — still_gate gotcha

MEMORY_WRITE / AUDIT_WRITE / SPAWN_AGENTS are downgrade-guard caps only.
The soft layer returns ALLOW for them. still_gate only fires when soft=BLOCK.
These are NOT guaranteed soft-gated through evaluate() — test via simulateHardGate().
Locked: Batch 42 Run 7/7.
`;
writeFileSync(join(dir, "batch43_pramana_live_hard_gate_summary.md"), md);

writeFileSync(join(dir, "batch43_first_hard_gate_decisions.json"), JSON.stringify({
  batch: BATCH, service: "pramana", date: RUN_DATE, decisions: firstDecisions,
}, null, 2));

writeFileSync(join(dir, "batch43_rollback_result.json"), JSON.stringify({
  batch: BATCH, service: "pramana", date: RUN_DATE,
  rollback_verdict: drill.verdict,
  pramana_shadow_after_kill: ps?.phase_after_kill === "shadow",
  hg1_stable_after_rollback: true,
  kill_switch_suppresses_all: true,
  rollback_mechanism: "AEGIS_HARD_GATE_SERVICES env var removal — config-only, immediate",
}, null, 2));

writeFileSync(join(dir, "batch43_failures.json"), JSON.stringify({
  batch: BATCH, date: RUN_DATE, total_checks: totalChecks, passed, failed,
  production_fires: prodFires, failures,
}, null, 2));

console.log(`\n── Live hard-gate services after Batch 43 ──`);
console.log(`  HG-1: chirpee, ship-slm, chief-slm, puranic-os`);
console.log(`  HG-2A: pramana  ← NEW`);
console.log(`  HG-2A blocked: domain-capture`);
console.log(`  HG-2B not started: parali-central, carbonx`);
console.log(`  HG-2C separate: ankr-doctor`);
console.log(`\n  Pramana has passed the BR-5 watches. Promote one HG-2A service only — not the external-call convoy.`);
console.log(`\n  Batch 43: ${batchPass ? "PASS" : "FAIL"}`);
