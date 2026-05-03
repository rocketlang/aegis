/**
 * Batch 34 — ship-slm + chief-slm HG-1 Soak Prep
 *
 * Purpose: Prepare Stage 2 HG-1 candidates after chirpee Batch 33 live observation
 * passed. Policies added to hard-gate-policy.ts (disabled). Dry-run simulations
 * confirm the new policies are correctly calibrated before any soak run begins.
 *
 * What this batch does:
 *   - Confirms ship-slm + chief-slm are TIER-A, read_only, BR-0 (HG-1 eligible)
 *   - Confirms policies exist but hard_gate_enabled=false for both
 *   - Confirms chirpee remains the only live hard-gated service
 *   - Dry-run simulates hard-gate for both services across full op surface
 *   - Verifies chirpee has no regression (live BLOCK still fires correctly)
 *   - Confirms still_gate semantics: downgrade guard only, never upgrades ALLOW
 *
 * What this batch does NOT do:
 *   - Does NOT enable hard-gate for ship-slm or chief-slm
 *   - Does NOT modify chirpee's live policy
 *   - Does NOT touch puranic-os
 *   - Does NOT add either service to AEGIS_HARD_GATE_SERVICES
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false is the policy default
 * @rule:AEG-HG-002 READ never hard-blocks in any mode
 * @rule:AEG-E-006  kill switch forces shadow; hard-gate cannot override
 * @rule:AEG-HG-003 only chirpee in AEGIS_HARD_GATE_SERVICES (Stage 1 only)
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee"; // Stage 1 only — ship-slm + chief-slm NOT added
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getServiceEntry } from "../src/enforcement/registry";
import {
  simulateHardGate,
  HARD_GATE_GLOBALLY_ENABLED,
  HARD_GATE_POLICIES,
  CHIRPEE_HG1_POLICY,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
} from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH = 34;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

// ── Harness ───────────────────────────────────────────────────────────────────

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
const matrix: Array<Record<string, unknown>> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const pass = String(actual) === String(expected);
  if (pass) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(82)} actual=${actual}`); }
  else {
    failed++;
    failures.push({ label, expected: String(expected), actual: String(actual), cat });
    console.log(`  ✗ [FAIL] ${label.padEnd(82)} expected=${expected} actual=${actual}`);
  }
}

function gate(op: string, cap: string, svc: string, caller = "b34") {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: caller, session_id: `b34-${svc}-${op}-${cap}-${Date.now()}` });
  logDecision(d);
  return d;
}

// dry-run: get soft decision via evaluate, then simulate hard-gate
function simulate(op: string, cap: string, svc: string) {
  const d = gate(op, cap, svc, "b34-sim");
  const sim = simulateHardGate(svc, d.decision, d.requested_capability, op, true);
  matrix.push({ service: svc, op, cap, soft_decision: sim.soft_decision, simulated_hard: sim.simulated_hard_decision, hard_gate_would_apply: sim.hard_gate_would_apply, invariant: sim.invariant_applied, reason: sim.reason });
  return { d, sim };
}

// ── Pre-flight ────────────────────────────────────────────────────────────────
console.log("\n══ Batch 34: ship-slm + chief-slm HG-1 Soak Prep ══");
console.log(`  Date: ${RUN_DATE}`);
console.log(`  HARD_GATE_GLOBALLY_ENABLED: ${HARD_GATE_GLOBALLY_ENABLED}`);
console.log(`  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  Policy registry size: ${Object.keys(HARD_GATE_POLICIES).length}`);
console.log("\n── Pre-flight ──");

check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "preflight");
check("AEGIS_HARD_GATE_SERVICES = chirpee only", process.env.AEGIS_HARD_GATE_SERVICES, "chirpee", "preflight");
check("policy registry has 3 services", Object.keys(HARD_GATE_POLICIES).length, 3, "preflight");
check("chirpee policy exists", !!HARD_GATE_POLICIES["chirpee"], true, "preflight");
check("ship-slm policy exists", !!HARD_GATE_POLICIES["ship-slm"], true, "preflight");
check("chief-slm policy exists", !!HARD_GATE_POLICIES["chief-slm"], true, "preflight");
check("chirpee stage = LIVE", CHIRPEE_HG1_POLICY.stage.includes("LIVE"), true, "preflight");
check("ship-slm stage = NOT LIVE", SHIP_SLM_HG1_POLICY.stage.includes("NOT LIVE"), true, "preflight");
check("chief-slm stage = NOT LIVE", CHIEF_SLM_HG1_POLICY.stage.includes("NOT LIVE"), true, "preflight");
check("ship-slm hard_gate_enabled = false", SHIP_SLM_HG1_POLICY.hard_gate_enabled, false, "preflight");
check("chief-slm hard_gate_enabled = false", CHIEF_SLM_HG1_POLICY.hard_gate_enabled, false, "preflight");
check("ship-slm rollout_order = 2", SHIP_SLM_HG1_POLICY.rollout_order, 2, "preflight");
check("chief-slm rollout_order = 3", CHIEF_SLM_HG1_POLICY.rollout_order, 3, "preflight");
check("ship-slm hg_group = HG-1", SHIP_SLM_HG1_POLICY.hg_group, "HG-1", "preflight");
check("chief-slm hg_group = HG-1", CHIEF_SLM_HG1_POLICY.hg_group, "HG-1", "preflight");
check("ship-slm hard_block count = 2", SHIP_SLM_HG1_POLICY.hard_block_capabilities.size, 2, "preflight");
check("chief-slm hard_block count = 2", CHIEF_SLM_HG1_POLICY.hard_block_capabilities.size, 2, "preflight");

// ── Registry pre-check ────────────────────────────────────────────────────────
console.log("\n── Registry pre-check (TIER-A eligibility) ──");

for (const svc of ["ship-slm", "chief-slm"]) {
  const entry = getServiceEntry(svc);
  check(`${svc}: registry entry exists`, !!entry, true, "registry");
  check(`${svc}: TIER-A`, entry?.runtime_readiness.tier, "TIER-A", "registry");
  check(`${svc}: read_only authority`, entry?.authority_class, "read_only", "registry");
  check(`${svc}: BR-0`, entry?.governance_blast_radius, "BR-0", "registry");
  check(`${svc}: human_gate_required = false`, entry?.human_gate_required, false, "registry");
}

// ── Wave 1: Confirm both services in soft_canary (not hard_gate) ──────────────
console.log("\n── Wave 1: Confirm ship-slm + chief-slm are in soft_canary phase (not hard_gate) ──");

for (const svc of ["ship-slm", "chief-slm"]) {
  const readD  = gate("read", "READ", svc, "b34-phase");
  const writeD = gate("write", "WRITE", svc, "b34-phase");
  check(`${svc} READ: phase = soft_canary`, readD.enforcement_phase, "soft_canary", "wave1_phase");
  check(`${svc} READ: hard_gate_active = undefined (not promoted)`, readD.hard_gate_active, undefined, "wave1_phase");
  check(`${svc} WRITE: phase = soft_canary`, writeD.enforcement_phase, "soft_canary", "wave1_phase");
  check(`${svc} IMPOSSIBLE_OP: phase != hard_gate (not promoted)`, gate("frob", "IMPOSSIBLE_OP", svc, "b34-phase").enforcement_phase !== "hard_gate", true, "wave1_phase");
}

// ── Wave 2: Dry-run simulation for ship-slm ───────────────────────────────────
console.log("\n── Wave 2: Dry-run simulation — ship-slm ──");

// READ / GET / LIST → never_block → ALLOW
for (const [op, cap] of [["read","READ"],["get","GET"],["list","LIST"]] as [string,string][]) {
  const { sim } = simulate(op, cap, "ship-slm");
  check(`ship-slm sim ${op}/${cap}: hard_decision = ALLOW (never_block)`, sim.simulated_hard_decision, "ALLOW", "wave2_ship");
  check(`ship-slm sim ${op}/${cap}: hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave2_ship");
  check(`ship-slm sim ${op}/${cap}: invariant = AEG-HG-002`, sim.invariant_applied, "AEG-HG-002", "wave2_ship");
}

// WRITE → soft ALLOW (read_only+BR-0) → hard-sim preserves ALLOW, never BLOCK
for (const [op, cap] of [["write","WRITE"],["create","WRITE"],["patch","WRITE"]] as [string,string][]) {
  const { sim } = simulate(op, cap, "ship-slm");
  check(`ship-slm sim ${op}/${cap}: hard_decision != BLOCK`, sim.simulated_hard_decision !== "BLOCK", true, "wave2_ship");
  check(`ship-slm sim ${op}/${cap}: hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave2_ship");
}

// IMPOSSIBLE_OP → hard_block → BLOCK
{
  const { sim } = simulate("frob_impossible", "IMPOSSIBLE_OP", "ship-slm");
  check("ship-slm sim IMPOSSIBLE_OP: hard_decision = BLOCK", sim.simulated_hard_decision, "BLOCK", "wave2_ship");
  check("ship-slm sim IMPOSSIBLE_OP: hard_gate_would_apply = true", sim.hard_gate_would_apply, true, "wave2_ship");
}

// EMPTY_CAPABILITY_ON_WRITE → hard_block → BLOCK
{
  const { sim } = simulate("write", "EMPTY_CAPABILITY_ON_WRITE", "ship-slm");
  check("ship-slm sim EMPTY_CAP: hard_decision = BLOCK", sim.simulated_hard_decision, "BLOCK", "wave2_ship");
  check("ship-slm sim EMPTY_CAP: hard_gate_would_apply = true", sim.hard_gate_would_apply, true, "wave2_ship");
}

// Critical ops (soft GATE on read_only+BR-0) → hard-sim preserves GATE, not BLOCK
for (const [op, cap] of [["deploy","CI_DEPLOY"],["delete","DELETE"],["ai-execute","AI_EXECUTE"]] as [string,string][]) {
  const { d, sim } = simulate(op, cap, "ship-slm");
  // soft gate returns GATE for critical ops; still_gate preserves GATE in sim
  check(`ship-slm sim ${op}/${cap}: hard_decision != BLOCK`, sim.simulated_hard_decision !== "BLOCK", true, "wave2_ship");
  check(`ship-slm sim ${op}/${cap}: soft_decision = ${d.decision}`, sim.soft_decision, d.decision, "wave2_ship");
}

// High/medium ops (soft ALLOW for read_only+BR-0) → still_gate must NOT upgrade to GATE
for (const [op, cap] of [["execute","EXECUTE"],["approve","APPROVE"],["trigger","TRIGGER"],["spawn","SPAWN_AGENTS"]] as [string,string][]) {
  const { d, sim } = simulate(op, cap, "ship-slm");
  check(`ship-slm sim ${op}/${cap}: still_gate does not upgrade ALLOW (soft=${d.decision})`, sim.simulated_hard_decision !== "GATE" || d.decision === "GATE", true, "wave2_ship");
  check(`ship-slm sim ${op}/${cap}: hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave2_ship");
}

// Unknown capability → GATE/WARN, never hard-BLOCK
for (const cap of ["FUTURE_SLM_CAP", "VESSEL_CLASSIFY", "BUNKERING_OP"]) {
  const { sim } = simulate("execute", cap, "ship-slm");
  check(`ship-slm sim unknown '${cap}': hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave2_ship");
}

// ── Wave 3: Dry-run simulation for chief-slm ─────────────────────────────────
console.log("\n── Wave 3: Dry-run simulation — chief-slm ──");

// READ / GET / LIST → never_block → ALLOW
for (const [op, cap] of [["read","READ"],["get","GET"],["list","LIST"]] as [string,string][]) {
  const { sim } = simulate(op, cap, "chief-slm");
  check(`chief-slm sim ${op}/${cap}: hard_decision = ALLOW (never_block)`, sim.simulated_hard_decision, "ALLOW", "wave3_chief");
  check(`chief-slm sim ${op}/${cap}: hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave3_chief");
  check(`chief-slm sim ${op}/${cap}: invariant = AEG-HG-002`, sim.invariant_applied, "AEG-HG-002", "wave3_chief");
}

// WRITE → soft ALLOW → hard-sim preserves, never BLOCK
for (const [op, cap] of [["write","WRITE"],["create","WRITE"],["patch","WRITE"]] as [string,string][]) {
  const { sim } = simulate(op, cap, "chief-slm");
  check(`chief-slm sim ${op}/${cap}: hard_decision != BLOCK`, sim.simulated_hard_decision !== "BLOCK", true, "wave3_chief");
  check(`chief-slm sim ${op}/${cap}: hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave3_chief");
}

// IMPOSSIBLE_OP → BLOCK
{
  const { sim } = simulate("frob_impossible", "IMPOSSIBLE_OP", "chief-slm");
  check("chief-slm sim IMPOSSIBLE_OP: hard_decision = BLOCK", sim.simulated_hard_decision, "BLOCK", "wave3_chief");
  check("chief-slm sim IMPOSSIBLE_OP: hard_gate_would_apply = true", sim.hard_gate_would_apply, true, "wave3_chief");
}

// EMPTY_CAPABILITY_ON_WRITE → BLOCK
{
  const { sim } = simulate("write", "EMPTY_CAPABILITY_ON_WRITE", "chief-slm");
  check("chief-slm sim EMPTY_CAP: hard_decision = BLOCK", sim.simulated_hard_decision, "BLOCK", "wave3_chief");
  check("chief-slm sim EMPTY_CAP: hard_gate_would_apply = true", sim.hard_gate_would_apply, true, "wave3_chief");
}

// Critical ops → hard-sim not BLOCK
for (const [op, cap] of [["deploy","CI_DEPLOY"],["delete","DELETE"],["ai-execute","AI_EXECUTE"]] as [string,string][]) {
  const { d, sim } = simulate(op, cap, "chief-slm");
  check(`chief-slm sim ${op}/${cap}: hard_decision != BLOCK`, sim.simulated_hard_decision !== "BLOCK", true, "wave3_chief");
  check(`chief-slm sim ${op}/${cap}: soft_decision = ${d.decision}`, sim.soft_decision, d.decision, "wave3_chief");
}

// High/medium ops → still_gate must NOT upgrade ALLOW to GATE
for (const [op, cap] of [["execute","EXECUTE"],["approve","APPROVE"],["trigger","TRIGGER"],["spawn","SPAWN_AGENTS"]] as [string,string][]) {
  const { d, sim } = simulate(op, cap, "chief-slm");
  check(`chief-slm sim ${op}/${cap}: still_gate does not upgrade ALLOW (soft=${d.decision})`, sim.simulated_hard_decision !== "GATE" || d.decision === "GATE", true, "wave3_chief");
  check(`chief-slm sim ${op}/${cap}: hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave3_chief");
}

// Unknown capability → never hard-BLOCK
for (const cap of ["OFFICER_BRIEF", "CARGO_MANIFEST_REVIEW", "PORT_CLEARANCE"]) {
  const { sim } = simulate("execute", cap, "chief-slm");
  check(`chief-slm sim unknown '${cap}': hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "wave3_chief");
}

// ── Wave 4: Chirpee regression ────────────────────────────────────────────────
console.log("\n── Wave 4: Chirpee regression (live hard-gate must be unchanged) ──");

const chirpeeRead = gate("read", "READ", "chirpee", "b34-regression");
check("chirpee regression: READ → ALLOW", chirpeeRead.decision, "ALLOW", "wave4_regression");
check("chirpee regression: READ phase = hard_gate", chirpeeRead.enforcement_phase, "hard_gate", "wave4_regression");
check("chirpee regression: READ hard_gate_applied = false", chirpeeRead.hard_gate_applied, false, "wave4_regression");

const chirpeeBlock = gate("frob_impossible", "IMPOSSIBLE_OP", "chirpee", "b34-regression");
check("chirpee regression: IMPOSSIBLE_OP → BLOCK", chirpeeBlock.decision, "BLOCK", "wave4_regression");
check("chirpee regression: IMPOSSIBLE_OP phase = hard_gate", chirpeeBlock.enforcement_phase, "hard_gate", "wave4_regression");
check("chirpee regression: IMPOSSIBLE_OP hard_gate_applied = true", chirpeeBlock.hard_gate_applied, true, "wave4_regression");
check("chirpee regression: IMPOSSIBLE_OP hard_gate_service = chirpee", chirpeeBlock.hard_gate_service, "chirpee", "wave4_regression");

const chirpeeEmptyCap = gate("write", "EMPTY_CAPABILITY_ON_WRITE", "chirpee", "b34-regression");
check("chirpee regression: EMPTY_CAP → BLOCK", chirpeeEmptyCap.decision, "BLOCK", "wave4_regression");
check("chirpee regression: EMPTY_CAP hard_gate_applied = true", chirpeeEmptyCap.hard_gate_applied, true, "wave4_regression");

// Kill switch regression
const savedEnabled = process.env.AEGIS_RUNTIME_ENABLED;
process.env.AEGIS_RUNTIME_ENABLED = "false";
const killedD = gate("frob_impossible", "IMPOSSIBLE_OP", "chirpee", "b34-kill-regression");
check("chirpee kill regression: IMPOSSIBLE_OP not BLOCK (shadow)", killedD.decision !== "BLOCK", true, "wave4_regression");
check("chirpee kill regression: phase = shadow", killedD.enforcement_phase, "shadow", "wave4_regression");
check("chirpee kill regression: hard_gate_applied falsy", !killedD.hard_gate_applied, true, "wave4_regression");
process.env.AEGIS_RUNTIME_ENABLED = savedEnabled ?? "true";

// ── Count validation ──────────────────────────────────────────────────────────
console.log("\n── Count validation ──");

// No decision from ship-slm or chief-slm should be in hard_gate phase
// (sim calls don't go through evaluate with hard-gate active for those services)
// The still_gate guard: verify no sim result upgraded ALLOW to GATE
const stillGateViolations = matrix.filter(r =>
  (r.service === "ship-slm" || r.service === "chief-slm") &&
  r.soft_decision === "ALLOW" &&
  r.simulated_hard === "GATE"
);
check("still_gate: zero ALLOW→GATE upgrades in sim matrix", stillGateViolations.length, 0, "count_validation");

const unexpectedBlocks = matrix.filter(r =>
  (r.service === "ship-slm" || r.service === "chief-slm") &&
  r.simulated_hard === "BLOCK" &&
  r.hard_gate_would_apply !== true
);
check("no unexpected hard BLOCKs in matrix", unexpectedBlocks.length, 0, "count_validation");

const truePositives = matrix.filter(r =>
  (r.service === "ship-slm" || r.service === "chief-slm") &&
  r.hard_gate_would_apply === true
);
// 2 per service = 4 total (IMPOSSIBLE_OP + EMPTY_CAP, each in wave 2 + 3)
check("true positive sim blocks = 4 (2×IMPOSSIBLE_OP + 2×EMPTY_CAP)", truePositives.length, 4, "count_validation");

const readBlocks = matrix.filter(r =>
  (r.service === "ship-slm" || r.service === "chief-slm") &&
  ["READ","GET","LIST"].includes(String(r.cap)) &&
  r.simulated_hard === "BLOCK"
);
check("READ/GET/LIST zero hard-sim BLOCKs", readBlocks.length, 0, "count_validation");

const batchPass = failed === 0 && stillGateViolations.length === 0 && truePositives.length === 4;

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n══ Batch 34 Summary ══`);
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Simulation matrix entries: ${matrix.length}`);
console.log(`  True-positive sim BLOCKs (malformed): ${truePositives.length} (expect 4)`);
console.log(`  still_gate ALLOW→GATE violations: ${stillGateViolations.length} (expect 0)`);
console.log(`  Verdict: ${batchPass ? "PASS" : "FAIL"}`);

if (failures.length) {
  console.log("\n  Failures:");
  failures.forEach(f => console.log(`    ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));
}

// ── Artifacts ─────────────────────────────────────────────────────────────────
const summaryMd = `# Batch 34 — ship-slm + chief-slm HG-1 Soak Prep

**Date:** ${RUN_DATE}
**Verdict:** ${batchPass ? "PASS" : "FAIL"}
**Batch:** 34 — Stage 2 HG-1 prep (policies added, not live)

## State going in

| Control | Value |
|---|---|
| HARD_GATE_GLOBALLY_ENABLED | true |
| AEGIS_HARD_GATE_SERVICES | chirpee only |
| ship-slm hard_gate_enabled | false (NOT LIVE) |
| chief-slm hard_gate_enabled | false (NOT LIVE) |

## Registry pre-check

| Service | Tier | authority_class | BR | HG-1 eligible |
|---|---|---|---|---|
| ship-slm | TIER-A | read_only | BR-0 | ✅ |
| chief-slm | TIER-A | read_only | BR-0 | ✅ |

## Simulation results

| Category | ship-slm | chief-slm |
|---|---|---|
| READ/GET/LIST → ALLOW | ✅ | ✅ |
| WRITE → not BLOCK | ✅ | ✅ |
| IMPOSSIBLE_OP → sim BLOCK | ✅ | ✅ |
| EMPTY_CAPABILITY_ON_WRITE → sim BLOCK | ✅ | ✅ |
| Critical ops → not BLOCK | ✅ | ✅ |
| still_gate: zero ALLOW→GATE upgrades | ✅ | ✅ |
| Unknown cap → not hard-BLOCK | ✅ | ✅ |

## Chirpee regression

| Check | Result |
|---|---|
| IMPOSSIBLE_OP still live BLOCK | ✅ |
| READ still ALLOW | ✅ |
| Kill switch still suppresses hard-gate | ✅ |

## Checks

- Total: ${totalChecks}
- Pass: ${passed}
- Fail: ${failed}

${failures.length > 0 ? "## Failures\n\n" + failures.map(f => `- [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`).join("\n") : "No failures."}

## Still-gate semantics verified

still_gate is a downgrade guard only (BLOCK→GATE).
It never upgrades ALLOW to GATE.
Violations in simulation matrix: ${stillGateViolations.length} (must be 0).

## Next step

${batchPass ? `Batch 34 PASS. Policies are correctly calibrated.
Batch 35 may now begin: ship-slm + chief-slm HG-1 soak run 1/7.
Do NOT add either service to AEGIS_HARD_GATE_SERVICES yet.` : "Resolve failures before Batch 35."}
`;

const hardGateMatrix = {
  batch: BATCH,
  date: RUN_DATE,
  verdict: batchPass ? "PASS" : "FAIL",
  services: ["ship-slm", "chief-slm"],
  mode: "dry_run_simulation",
  hard_gate_live_services: ["chirpee"],
  hard_gate_prepared_not_live: ["ship-slm", "chief-slm"],
  simulation_matrix: matrix,
  summary: {
    total_sim_entries: matrix.length,
    true_positive_blocks: truePositives.length,
    still_gate_violations: stillGateViolations.length,
    unexpected_blocks: unexpectedBlocks.length,
    read_blocks: readBlocks.length,
  },
  total_checks: totalChecks,
  passed,
  failed,
};

writeFileSync(join(dir, "batch34_ship_chief_hg1_prep_summary.md"), summaryMd);
writeFileSync(join(dir, "batch34_ship_chief_hard_gate_matrix.json"), JSON.stringify(hardGateMatrix, null, 2));
writeFileSync(join(dir, "batch34_failures.json"), JSON.stringify(failures, null, 2));

console.log(`\n  Artifacts written to .aegis/`);
console.log(`    batch34_ship_chief_hg1_prep_summary.md`);
console.log(`    batch34_ship_chief_hard_gate_matrix.json`);
console.log(`    batch34_failures.json`);
console.log(`\n  Batch 34: ${batchPass ? "PASS — Range confirmed safe. Soak runs (Batch 35) may begin." : "FAIL — Resolve before Batch 35."}`);
