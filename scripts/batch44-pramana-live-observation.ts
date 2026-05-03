/**
 * Batch 44 — pramana HG-2A live observation + HG-2A closure check
 *
 * Observes pramana after live HG-2A promotion (Batch 43).
 * Watch the BR-5 wake before touching external-call territory.
 *
 * Tasks:
 *   1. pramana live observation — full decision surface
 *   2. HG-1 regression — all 4 services clean
 *   3. HG-2 blocker status — domain-capture / HG-2B / HG-2C all isolated
 *   4. Kill-switch drill — all 5 live services shadow; restore clean
 *   5. HG-2A closure check — pramana health after first live period
 *
 * @rule:AEG-HG-001 AEGIS_HARD_GATE_SERVICES is the actual runtime switch
 * @rule:AEG-HG-002 READ never hard-blocks
 * @rule:AEG-E-006  kill switch overrides all enforcement
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PRAMANA_HG2A_POLICY } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH = 44;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
const observations: Array<{ service: string; cap: string; op: string; decision: string; phase: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

function obs(d: ReturnType<typeof evaluate>, cap: string) {
  observations.push({ service: d.service_id, cap, op: cap.toLowerCase(), decision: d.decision, phase: d.enforcement_phase });
}

let prodFires = 0;

console.log(`\n══ Batch ${BATCH} — pramana HG-2A LIVE OBSERVATION + CLOSURE CHECK ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  pramana stage: ${PRAMANA_HG2A_POLICY.stage}`);

// ── Pre-flight ────────────────────────────────────────────────────────────────
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana IN env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), true, "pre");
check("PRAMANA_HG2A_POLICY.hard_gate_enabled = true", PRAMANA_HG2A_POLICY.hard_gate_enabled, true, "pre");
check("5 services in env", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").length, 5, "pre");

// ── Task 1: pramana live observation ─────────────────────────────────────────
console.log("\n── Task 1a: pramana live ALLOW surface ──");
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
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b44-allow" });
  logDecision(d);
  obs(d, cap);
  check(`pramana [${cap}]: hard_gate + ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "obs_allow");
  if (d.decision === "BLOCK") prodFires++;
}

console.log("\n── Task 1b: pramana live BLOCK surface (malformed hard-block) ──");
for (const [op, cap] of [
  ["frob",  "IMPOSSIBLE_OP"],
  ["write", "EMPTY_CAPABILITY_ON_WRITE"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b44-block" });
  logDecision(d);
  obs(d, cap);
  check(`pramana [${cap}]: hard_gate + BLOCK`, d.enforcement_phase === "hard_gate" && d.decision === "BLOCK", true, "obs_block");
}

console.log("\n── Task 1c: pramana live GATE surface (critical + high-risk BR-5) ──");
for (const [op, cap] of [
  ["ai-execute", "AI_EXECUTE"],
  ["deploy",     "CI_DEPLOY"],
  ["delete",     "DELETE"],
  ["execute",    "EXECUTE"],
  ["approve",    "APPROVE"],
  ["emit",       "EMIT"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b44-gate" });
  logDecision(d);
  obs(d, cap);
  check(`pramana [${cap}]: hard_gate + GATE`, d.enforcement_phase === "hard_gate" && d.decision === "GATE", true, "obs_gate");
  if (d.decision === "BLOCK") prodFires++;
}

console.log("\n── Task 1d: pramana still_gate caps (preserve soft decision) ──");
for (const [op, cap] of [
  ["write", "MEMORY_WRITE"],
  ["write", "AUDIT_WRITE"],
  ["write", "SPAWN_AGENTS"],
  ["emit",  "TRIGGER"],
  ["exec",  "FULL_AUTONOMY"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b44-still" });
  obs(d, cap);
  check(`pramana [${cap}]: NOT BLOCK (still_gate preserves soft decision)`, d.decision !== "BLOCK", true, "obs_still_gate");
  check(`pramana [${cap}]: hard_gate phase`, d.enforcement_phase, "hard_gate", "obs_still_gate");
  // Downgrade guard confirmation
  const simDG = simulateHardGate("pramana", "BLOCK", cap, op, true);
  check(`pramana [${cap}] DG: BLOCK→GATE`, simDG.simulated_hard_decision, "GATE", "obs_still_gate");
  if (d.decision === "BLOCK") prodFires++;
}

console.log("\n── Task 1e: unknown capability on live pramana ──");
for (const [op, cap] of [
  ["frob", "BRAND_NEW_CAP"],
  ["frob", "SOME_FUTURE_OP"],
  ["frob", "CAP_NOT_IN_REGISTRY"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b44-unk" });
  obs(d, cap);
  check(`pramana unknown [${cap}]: hard_gate phase`, d.enforcement_phase, "hard_gate", "obs_unknown");
  check(`pramana unknown [${cap}]: NOT BLOCK`, d.decision !== "BLOCK", true, "obs_unknown");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Task 2: HG-1 regression ───────────────────────────────────────────────────
console.log("\n── Task 2: HG-1 regression ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b44-hg1" });
  check(`[${svc}] READ: hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b44-hg1" });
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
}

// ── Task 3: HG-2 blocker status ───────────────────────────────────────────────
console.log("\n── Task 3: HG-2 blocker status ──");
// domain-capture: registry/service mapping issue — not in env, NOT hard-gated
{
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b44-blocker" });
  check("domain-capture: NOT hard_gate (registry blocker active)", d.enforcement_phase !== "hard_gate", true, "blockers");
  check("domain-capture: NOT BLOCK (not hard-enabled)", d.decision !== "BLOCK", true, "blockers");
}
// HG-2B: parali-central / carbonx — external impact review required
for (const svc of ["parali-central", "carbonx"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b44-blocker" });
  check(`[${svc}] HG-2B: NOT hard_gate (external impact review pending)`, d.enforcement_phase !== "hard_gate", true, "blockers");
  check(`[${svc}] HG-2B: NOT BLOCK`, d.decision !== "BLOCK", true, "blockers");
}
// HG-2C: ankr-doctor — separate governance review
{
  const d = evaluate({ service_id: "ankr-doctor", operation: "execute", requested_capability: "EXECUTE", caller_id: "b44-blocker" });
  check("ankr-doctor HG-2C: NOT hard_gate (governance review pending)", d.enforcement_phase !== "hard_gate", true, "blockers");
  check("ankr-doctor HG-2C: GATE (soft governance layer active)", d.decision, "GATE", "blockers");
}
// Non-pilot services → shadow
for (const svc of ["unregistered-svc", "phantom-service", "test-unknown"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b44-blocker" });
  check(`[${svc}]: shadow + WARN (not registered)`, d.enforcement_phase === "shadow" && d.decision === "WARN", true, "blockers");
}
// Confirm pramana is the only HG-2 live service
check("only pramana in HG-2 live (no HG-2B enabled)", !["parali-central", "carbonx", "domain-capture", "ankr-doctor"].some(
  s => process.env.AEGIS_HARD_GATE_SERVICES?.includes(s)
), true, "blockers");

// ── Task 4: Kill-switch drill (all 5 live services) ──────────────────────────
console.log("\n── Task 4: Kill-switch drill (5 live services) ──");
const LIVE_5 = ["pramana", "chirpee", "ship-slm", "chief-slm", "puranic-os"];

// Verify live state before kill
for (const svc of LIVE_5) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b44-pre-kill" });
  const expectPhase = d.enforcement_phase === "hard_gate";
  check(`[${svc}] pre-kill: hard_gate`, expectPhase, true, "kill_drill");
}

// Kill
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const svc of LIVE_5) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b44-kill" });
  check(`[${svc}] killed: shadow`, d.enforcement_phase, "shadow", "kill_drill");
  check(`[${svc}] killed: NOT BLOCK`, d.decision !== "BLOCK", true, "kill_drill");
}

// READ still not BLOCK while killed
for (const svc of LIVE_5) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b44-kill-read" });
  check(`[${svc}] killed + READ: not BLOCK`, d.decision !== "BLOCK", true, "kill_drill");
}

// Restore
process.env.AEGIS_RUNTIME_ENABLED = "true";
for (const svc of LIVE_5) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b44-restore" });
  check(`[${svc}] restored: hard_gate`, d.enforcement_phase, "hard_gate", "kill_drill");
}
// Spot-check BLOCK surface restored
for (const svc of LIVE_5) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b44-restore-block" });
  check(`[${svc}] restored: IMPOSSIBLE_OP → BLOCK`, d.decision, "BLOCK", "kill_drill");
}
// pramana READ still ALLOW after restore
{
  const d = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b44-restore" });
  check("pramana restored: READ → hard_gate + ALLOW", d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "kill_drill");
}

// ── Task 5: HG-2A closure check ──────────────────────────────────────────────
console.log("\n── Task 5: HG-2A closure check ──");
check("pramana hard_gate_enabled = true (documentary alignment)", PRAMANA_HG2A_POLICY.hard_gate_enabled, true, "closure");
check("pramana hg_group = HG-2", PRAMANA_HG2A_POLICY.hg_group, "HG-2", "closure");
check("pramana rollout_order = 5", PRAMANA_HG2A_POLICY.rollout_order, 5, "closure");
check("stage contains LIVE + Batch 43", PRAMANA_HG2A_POLICY.stage.includes("LIVE") && PRAMANA_HG2A_POLICY.stage.includes("Batch 43"), true, "closure");
check("hard_block_capabilities size = 2", PRAMANA_HG2A_POLICY.hard_block_capabilities.size, 2, "closure");
check("still_gate_capabilities size = 11", PRAMANA_HG2A_POLICY.still_gate_capabilities.size, 11, "closure");
check("always_allow_capabilities size = 6", PRAMANA_HG2A_POLICY.always_allow_capabilities.size, 6, "closure");
check("never_block contains READ", PRAMANA_HG2A_POLICY.never_block_capabilities.has("READ"), true, "closure");
// Production fires sanity check
check("production fires = 0 (no unintended hard-BLOCKs this batch)", prodFires, 0, "closure");

// ── Count + verdict ───────────────────────────────────────────────────────────
console.log("\n── Count validation ──");
check("production fires = 0", prodFires, 0, "count");

const batchPass = failed === 0 && prodFires === 0;
console.log(`\n══ Batch ${BATCH} Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${batchPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

// ── Artifacts ─────────────────────────────────────────────────────────────────

const blockerMd = `# Batch 44 — HG-2 Blocker Status

Date: ${RUN_DATE}

## HG-2A

| Service | Rollout | Status | Blocker |
|---------|---------|--------|---------|
| pramana | 5 | **LIVE** (Batch 43, 2026-05-03) | none — soak Batch 42 7/7 |
| domain-capture | — | **BLOCKED** | registry/service mapping issue — port not in services.json; soft-blocked from soak |

## HG-2B (external_call — NOT started)

| Service | Rollout | Status | Blocker |
|---------|---------|--------|---------|
| parali-central | — | NOT STARTED | external impact review required |
| carbonx | — | NOT STARTED | external impact review required |

**HG-2B doctrine note:** external_call services require external-state doctrine before soak.
A wrong hard-block on external_call corrupts external state, not just stops a local session.
Open HG-2B only after external-state doctrine is written and reviewed.

## HG-2C (governance)

| Service | Status | Blocker |
|---------|--------|---------|
| ankr-doctor | NOT STARTED | separate governance review — HG-2C is its own review track |

## Recommended next path

Option A (preferred): fix domain-capture registry mapping → soak/promote as HG-2A.
  Finish HG-2A before opening external-call territory.

Option B: write HG-2B external-state doctrine → then parali-central/carbonx soak.
  Only after Option A completes or is formally deferred.
`;

const summaryMd = `# Batch 44 — pramana HG-2A Live Observation Summary

Date: ${RUN_DATE}
Verdict: **${batchPass ? "PASS" : "FAIL"}**
Checks: ${totalChecks}  Pass: ${passed}  Fail: ${failed}
Production fires: ${prodFires}

## Live Observation

All pramana decision surfaces verified after first live period (Batch 43 → Batch 44):

| Surface | Caps | Result |
|---------|------|--------|
| ALLOW | READ/GET/LIST/QUERY/SEARCH/HEALTH/VERIFY/VALIDATE/ATTEST/CHECK_PROOF/ISSUE_PROOF/QUERY_PROOF | hard_gate + ALLOW |
| BLOCK | IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE | hard_gate + BLOCK |
| GATE | AI_EXECUTE, CI_DEPLOY, DELETE, EXECUTE, APPROVE, EMIT | hard_gate + GATE |
| still_gate | MEMORY_WRITE, AUDIT_WRITE, SPAWN_AGENTS, TRIGGER, FULL_AUTONOMY | NOT BLOCK; downgrade guard holds |
| unknown cap | BRAND_NEW_CAP, SOME_FUTURE_OP, CAP_NOT_IN_REGISTRY | hard_gate phase, NOT BLOCK |

## HG-1 Regression

All 4 HG-1 services clean: READ → ALLOW, IMPOSSIBLE_OP → BLOCK.

## Kill-Switch Drill (all 5 live services)

All 5 services (pramana + 4 HG-1) → shadow while killed, no BLOCK.
All 5 restored cleanly to hard_gate after kill cleared.

## HG-2A Closure

pramana health after live promotion:
- hard_gate_enabled = true
- stage = ${PRAMANA_HG2A_POLICY.stage}
- 0 production fires this batch
- policy surface unchanged from promotion (2 hard-block, 11 still-gate, 6 always-allow)

## What NOT to do next

Do NOT open HG-2B (parali-central, carbonx). External-call doctrine not written.
Do NOT promote ankr-doctor. HG-2C governance review separate.

## Recommended next step

Fix domain-capture registry mapping. Soak + promote as HG-2A (next).
Finish HG-2A before opening external-call territory.
`;

writeFileSync(join(dir, "batch44_pramana_live_observation_summary.md"), summaryMd);
writeFileSync(join(dir, "batch44_hg2a_closure_check.json"), JSON.stringify({
  batch: BATCH, date: RUN_DATE,
  service: "pramana",
  hg_group: "HG-2A",
  verdict: batchPass ? "PASS" : "FAIL",
  checks: totalChecks, passed, failed,
  production_fires: prodFires,
  hard_gate_enabled: PRAMANA_HG2A_POLICY.hard_gate_enabled,
  stage: PRAMANA_HG2A_POLICY.stage,
  hard_block_caps_count: PRAMANA_HG2A_POLICY.hard_block_capabilities.size,
  still_gate_caps_count: PRAMANA_HG2A_POLICY.still_gate_capabilities.size,
  hg2a_live_services: ["pramana"],
  hg2a_blocked: ["domain-capture"],
  hg2b_not_started: ["parali-central", "carbonx"],
  hg2c_separate: ["ankr-doctor"],
  recommended_next: "fix domain-capture registry mapping, soak/promote as HG-2A",
  do_not_open: "HG-2B (external_call) — external-state doctrine not written",
  observations,
}, null, 2));
writeFileSync(join(dir, "batch44_failures.json"), JSON.stringify({
  batch: BATCH, date: RUN_DATE, total_checks: totalChecks, passed, failed, production_fires: prodFires, failures,
}, null, 2));
writeFileSync(join(dir, "batch44_hg2_blockers.md"), blockerMd);

console.log(`\n── HG-2 state after Batch 44 ──`);
console.log(`  HG-2A live:    pramana`);
console.log(`  HG-2A blocked: domain-capture (registry issue)`);
console.log(`  HG-2B:         NOT started — parali-central, carbonx (external-state doctrine required)`);
console.log(`  HG-2C:         NOT started — ankr-doctor (governance review separate)`);
console.log(`\n  Pramana is live. Now watch the BR-5 wake before sending the convoy toward external waters.`);
console.log(`\n  Batch ${BATCH}: ${batchPass ? "PASS" : "FAIL"}`);
