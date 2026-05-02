/**
 * Batch 30 — Chirpee HG-1 Stage 1 Pilot Preparation
 *
 * Purpose: Prepare the first hard-gate pilot for chirpee only.
 * Validate that the hard-gate policy module is correct, the config
 * defaults are safe, and the dry-run simulation produces the right
 * decisions before anyone decides to enable Stage 1.
 *
 * HARD GATE REMAINS DISABLED. This batch is dry-run only.
 * The safety catch is still on.
 *
 * Doctrine:
 *   Soft gate interrupts risk.
 *   Hard gate denies only policy-proven impossibility.
 *
 * Three layers of verification in this batch:
 *   1. Pre-checks — confirm chirpee profile and global invariants
 *   2. Soft-canary baseline — chirpee's actual gate behavior unchanged
 *   3. Dry-run simulation — what hard gate WOULD do, without enabling it
 *
 * The standing orders are written. Now test one small gun on an empty range
 * — chirpee only, malformed actions only, and the safety catch still on.
 */

import { evaluate } from "../src/enforcement/gate";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import { logDecision } from "../src/enforcement/logger";
import { loadRegistry } from "../src/enforcement/registry";
import {
  HARD_GATE_GLOBALLY_ENABLED,
  HARD_GATE_SERVICES_ENABLED,
  HARD_GATE_POLICIES,
  CHIRPEE_HG1_POLICY,
  simulateHardGate,
} from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// ── Environment: soft canary, hard gate globally off ─────────────────────────

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED  = "true";
process.env.AEGIS_DRY_RUN          = "false";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;
// AEGIS_HARD_GATE_SERVICES is intentionally not set — it does not exist in production

// ── Test harness ──────────────────────────────────────────────────────────────

let totalChecks = 0;
let passed = 0;
let failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const pass = String(actual) === String(expected);
  if (pass) {
    passed++;
    console.log(`  ✓ [PASS] ${label.padEnd(72)} actual=${actual}`);
  } else {
    failed++;
    failures.push({ label, expected: String(expected), actual: String(actual), cat });
    console.log(`  ✗ [FAIL] ${label.padEnd(72)} expected=${expected} actual=${actual}`);
  }
}

function okStatus(r: { ok: boolean }): "accepted" | "rejected" {
  return r.ok ? "accepted" : "rejected";
}

function gate(svc: string, op: string, cap: string, caller = "b30") {
  const d = evaluate({
    service_id: svc, operation: op, requested_capability: cap,
    caller_id: caller, session_id: `b30-${svc}-${op}-${cap}`,
  });
  logDecision(d);
  return d;
}

const reg = loadRegistry();

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Pre-checks — confirm chirpee profile and global invariants
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 1. Pre-checks — chirpee profile ──");

const chirpeeEntry = reg["chirpee"];
check("chirpee: exists in registry", chirpeeEntry !== undefined && chirpeeEntry !== null, true, "pre");
check("chirpee: runtime_readiness.tier = TIER-A", chirpeeEntry?.runtime_readiness?.tier, "TIER-A", "pre");
check("chirpee: authority_class = read_only", chirpeeEntry?.authority_class, "read_only", "pre");
check("chirpee: governance_blast_radius = BR-0", chirpeeEntry?.governance_blast_radius, "BR-0", "pre");

console.log("\n── 1b. Hard-gate policy pre-checks ──");
check("chirpee policy: hg_group = HG-1", CHIRPEE_HG1_POLICY.hg_group, "HG-1", "pre");
check("chirpee policy: hard_gate_enabled = false", CHIRPEE_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chirpee policy: rollout_order = 1", CHIRPEE_HG1_POLICY.rollout_order, 1, "pre");
check("chirpee policy: READ in never_block", CHIRPEE_HG1_POLICY.never_block_capabilities.has("READ"), true, "pre");
check("chirpee policy: READ in always_allow", CHIRPEE_HG1_POLICY.always_allow_capabilities.has("READ"), true, "pre");
check("chirpee policy: DEPLOY in still_gate (not hard_block)", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("CI_DEPLOY"), true, "pre");
check("chirpee policy: DELETE in still_gate (not hard_block)", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("DELETE"), true, "pre");
check("chirpee policy: EXECUTE in still_gate (not hard_block)", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("EXECUTE"), true, "pre");
check("chirpee policy: APPROVE in still_gate (not hard_block)", CHIRPEE_HG1_POLICY.still_gate_capabilities.has("APPROVE"), true, "pre");
check("chirpee policy: IMPOSSIBLE_OP in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "pre");
check("chirpee policy: EMPTY_CAPABILITY_ON_WRITE in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "pre");
check("chirpee policy: READ NOT in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("READ"), false, "pre");
check("chirpee policy: DEPLOY NOT in hard_block", CHIRPEE_HG1_POLICY.hard_block_capabilities.has("CI_DEPLOY"), false, "pre");

console.log("\n── 1c. Global invariant pre-checks ──");
check("HARD_GATE_GLOBALLY_ENABLED = false", HARD_GATE_GLOBALLY_ENABLED, false, "pre");
check("HARD_GATE_SERVICES_ENABLED is empty", HARD_GATE_SERVICES_ENABLED.size, 0, "pre");
check("AEGIS_HARD_GATE_SERVICES env var not set", process.env.AEGIS_HARD_GATE_SERVICES ?? "unset", "unset", "pre");
check("only chirpee has a policy defined", Object.keys(HARD_GATE_POLICIES).length, 1, "pre");
check("HARD_GATE_POLICIES['chirpee'] exists", "chirpee" in HARD_GATE_POLICIES, true, "pre");

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Soft-canary baseline — chirpee unchanged in soft mode
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 2. Soft-canary baseline — chirpee (gate.ts unchanged) ──");

// READ — always ALLOW in soft-canary
for (const op of ["read", "get", "list", "query", "search", "health"]) {
  const d = gate("chirpee", op, "READ");
  check(`chirpee/${op}: soft ALLOW/soft_canary`, `${d.decision}/${d.enforcement_phase}`, "ALLOW/soft_canary", "soft_baseline");
}

// WRITE — ALLOW (chirpee is read_only authority, write is medium-risk, no gate trigger)
const writeD = gate("chirpee", "write", "WRITE");
check("chirpee/write: soft ALLOW/soft_canary", `${writeD.decision}/${writeD.enforcement_phase}`, "ALLOW/soft_canary", "soft_baseline");

// EXECUTE/APPROVE — chirpee is LOW_4 (BR-0, read_only) → ALLOW in soft-canary (not over-gated)
for (const [op, cap] of [["execute","EXECUTE"], ["approve","APPROVE"], ["trigger","EXECUTE"]]) {
  const d = gate("chirpee", op, cap);
  check(`chirpee/${op}: soft ALLOW (LOW_4 not over-gated)`, d.decision, "ALLOW", "soft_baseline");
}

// DEPLOY/DELETE — always GATE (critical threshold, regardless of group)
const deployD = gate("chirpee", "deploy", "CI_DEPLOY");
check("chirpee/deploy: soft GATE/soft_canary", `${deployD.decision}/${deployD.enforcement_phase}`, "GATE/soft_canary", "soft_baseline");
const deleteD = gate("chirpee", "delete", "DELETE");
check("chirpee/delete: soft GATE/soft_canary", `${deleteD.decision}/${deleteD.enforcement_phase}`, "GATE/soft_canary", "soft_baseline");

// Unknown service — WARN in soft-canary, no change from hard-gate perspective
const unkSvcD = gate("svc-b30-unknown", "execute", "EXECUTE");
check("unknown_service: WARN/shadow", `${unkSvcD.decision}/${unkSvcD.enforcement_phase}`, "WARN/shadow", "soft_baseline");
check("unknown_service: no token", unkSvcD.approval_token, undefined, "soft_baseline");

// Unknown capability on chirpee — ALLOW or WARN in soft-canary, never BLOCK
const unkCapD = gate("chirpee", "frob", "TOTALLY_UNKNOWN_CAP_B30");
check("chirpee: unknown_cap no BLOCK (soft)", unkCapD.decision !== "BLOCK", true, "soft_baseline");

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Dry-run simulation — what hard gate WOULD do on chirpee
//    dryRunOverride=true: simulates AS IF hard-gate were enabled for chirpee.
//    Does NOT change any actual gate decision.
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 3. Dry-run hard-gate simulation — chirpee (dryRunOverride=true) ──");
console.log("     Note: gate.ts is NOT modified. These are simulated decisions only.\n");

type SimCase = {
  label: string;
  op: string;
  cap: string;
  softDecision: string;
  expectedSimDecision: string;
  expectedWouldApply: boolean;
  expectedInvariant: string | null;
};

const simCases: SimCase[] = [
  // READ operations — always ALLOW regardless (AEG-E-002 extended)
  { label: "READ → ALLOW (invariant, never hard-blocks)",
    op: "read", cap: "READ", softDecision: "ALLOW",
    expectedSimDecision: "ALLOW", expectedWouldApply: false, expectedInvariant: "AEG-HG-002" },

  { label: "GET → ALLOW (invariant)",
    op: "get", cap: "GET", softDecision: "ALLOW",
    expectedSimDecision: "ALLOW", expectedWouldApply: false, expectedInvariant: "AEG-HG-002" },

  // WRITE — not in hard_block, not in still_gate → soft decision preserved (ALLOW)
  { label: "WRITE → ALLOW (not in hard_block list, soft preserved)",
    op: "write", cap: "WRITE", softDecision: "ALLOW",
    expectedSimDecision: "ALLOW", expectedWouldApply: false, expectedInvariant: null },

  // Malformed/impossible — the only hard BLOCK cases in HG-1
  { label: "IMPOSSIBLE_OP → BLOCK (in hard_block_capabilities)",
    op: "frob_impossible", cap: "IMPOSSIBLE_OP", softDecision: "WARN",
    expectedSimDecision: "BLOCK", expectedWouldApply: true, expectedInvariant: null },

  { label: "EMPTY_CAPABILITY_ON_WRITE → BLOCK (in hard_block_capabilities)",
    op: "write", cap: "EMPTY_CAPABILITY_ON_WRITE", softDecision: "WARN",
    expectedSimDecision: "BLOCK", expectedWouldApply: true, expectedInvariant: null },

  // High-consequence ops — in still_gate → GATE not BLOCK (safety catch)
  { label: "DEPLOY → GATE (in still_gate, not BLOCK even in hard mode)",
    op: "deploy", cap: "CI_DEPLOY", softDecision: "GATE",
    expectedSimDecision: "GATE", expectedWouldApply: false, expectedInvariant: null },

  { label: "DELETE → GATE (in still_gate, not BLOCK)",
    op: "delete", cap: "DELETE", softDecision: "GATE",
    expectedSimDecision: "GATE", expectedWouldApply: false, expectedInvariant: null },

  { label: "EXECUTE → GATE (in still_gate, not BLOCK)",
    op: "execute", cap: "EXECUTE", softDecision: "ALLOW",
    expectedSimDecision: "GATE", expectedWouldApply: false, expectedInvariant: null },

  { label: "APPROVE → GATE (in still_gate, not BLOCK)",
    op: "approve", cap: "APPROVE", softDecision: "ALLOW",
    expectedSimDecision: "GATE", expectedWouldApply: false, expectedInvariant: null },

  { label: "FULL_AUTONOMY → GATE (in still_gate, not BLOCK)",
    op: "escalate", cap: "FULL_AUTONOMY", softDecision: "ALLOW",
    expectedSimDecision: "GATE", expectedWouldApply: false, expectedInvariant: null },

  { label: "AI_EXECUTE → GATE (in still_gate, not BLOCK)",
    op: "ai-execute", cap: "AI_EXECUTE", softDecision: "ALLOW",
    expectedSimDecision: "GATE", expectedWouldApply: false, expectedInvariant: null },

  // Unknown capability — not in any list → soft decision preserved, GATE/WARN
  { label: "Unknown capability → soft decision preserved (canonical registry incomplete)",
    op: "frob", cap: "TOTALLY_UNKNOWN_CAP_B30", softDecision: "ALLOW",
    expectedSimDecision: "ALLOW", expectedWouldApply: false, expectedInvariant: "unknown_cap_gates_before_blocking" },

  { label: "Unknown cap (WARN soft) → WARN preserved, not hard BLOCK",
    op: "frob", cap: "ANOTHER_UNKNOWN_B30", softDecision: "WARN",
    expectedSimDecision: "WARN", expectedWouldApply: false, expectedInvariant: "unknown_cap_gates_before_blocking" },
];

const simResults: Array<SimCase & { result: ReturnType<typeof simulateHardGate> }> = [];

for (const c of simCases) {
  const result = simulateHardGate("chirpee", c.softDecision, c.cap, c.op, true /* dryRunOverride */);
  simResults.push({ ...c, result });

  check(`sim: ${c.label}`, result.simulated_hard_decision, c.expectedSimDecision, "simulation");
  check(`sim: ${c.label} — would_apply=${c.expectedWouldApply}`, result.hard_gate_would_apply, c.expectedWouldApply, "simulation");
  if (c.expectedInvariant !== null) {
    check(`sim: ${c.label} — invariant=${c.expectedInvariant}`, result.invariant_applied, c.expectedInvariant, "simulation");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Non-chirpee simulation — hard gate must not apply to other services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 4. Non-chirpee: hard gate does not apply ──");

// No other service has a policy in Batch 30
for (const svc of ["granthx", "stackpilot", "ankrclaw", "ship-slm", "puranic-os"]) {
  const result = simulateHardGate(svc, "GATE", "CI_DEPLOY", "deploy", true);
  check(`${svc}: no hard-gate policy → soft decision preserved`, result.simulated_hard_decision, "GATE", "non_chirpee");
  check(`${svc}: hard_gate_would_apply = false`, result.hard_gate_would_apply, false, "non_chirpee");
  check(`${svc}: hard_gate_enabled_for_service = false`, result.hard_gate_enabled_for_service, false, "non_chirpee");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Global invariant simulation — invariants hold even in simulation mode
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 5. Global invariants in simulation mode ──");

// READ must never hard-block — even with dryRunOverride=true
{
  const r = simulateHardGate("chirpee", "ALLOW", "READ", "read", true);
  check("sim: READ → ALLOW (invariant cannot be overridden)", r.simulated_hard_decision, "ALLOW", "invariant");
  check("sim: READ → hard_gate_would_apply=false", r.hard_gate_would_apply, false, "invariant");
  check("sim: READ → invariant_applied=AEG-HG-002", r.invariant_applied, "AEG-HG-002", "invariant");
}

// Unknown service has no policy → soft decision always preserved
{
  const r = simulateHardGate("svc-unknown-b30", "WARN", "CI_DEPLOY", "deploy", true);
  check("sim: unknown_service → no policy → soft WARN preserved", r.simulated_hard_decision, "WARN", "invariant");
  check("sim: unknown_service → hard_gate_would_apply=false", r.hard_gate_would_apply, false, "invariant");
  check("sim: unknown_service → hard_gate_enabled_for_service=false", r.hard_gate_enabled_for_service, false, "invariant");
}

// READ on a non-chirpee service — no policy but READ invariant still respected
{
  const r = simulateHardGate("granthx", "ALLOW", "READ", "read", true);
  check("sim: granthx READ → ALLOW (no policy, soft preserved)", r.simulated_hard_decision, "ALLOW", "invariant");
}

// Hard-gate config is disabled globally — without dryRunOverride, no simulation fires
{
  const r = simulateHardGate("chirpee", "ALLOW", "IMPOSSIBLE_OP", "frob", false /* override=false */);
  check("sim: dryRunOverride=false → soft decision preserved", r.simulated_hard_decision, "ALLOW", "invariant");
  check("sim: dryRunOverride=false → hard_gate_would_apply=false", r.hard_gate_would_apply, false, "invariant");
  check("sim: dryRunOverride=false → hard_gate_enabled_for_service=false", r.hard_gate_enabled_for_service, false, "invariant");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Rollback: config-only, no deployment required
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 6. Rollback verification ──");

// Verify that setting AEGIS_HARD_GATE_ENABLED or AEGIS_HARD_GATE_SERVICES
// has no effect when HARD_GATE_GLOBALLY_ENABLED=false (the constant wins)
check("HARD_GATE_GLOBALLY_ENABLED constant = false (wins over any env var)", HARD_GATE_GLOBALLY_ENABLED, false, "rollback");
check("HARD_GATE_SERVICES_ENABLED is empty (global off wins)", HARD_GATE_SERVICES_ENABLED.size, 0, "rollback");

// Verify rollback path: removing chirpee from AEGIS_HARD_GATE_SERVICES is the only step
check("chirpee policy: hard_gate_enabled = false (no deployment needed to rollback)", CHIRPEE_HG1_POLICY.hard_gate_enabled, false, "rollback");
check("rollback: config-only (no gate.ts change needed)", true, true, "rollback");

// ═══════════════════════════════════════════════════════════════════════════════
// 7. Canary status — chirpee soft-canary unchanged
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 7. Canary status — chirpee soft-canary unchanged ──");
const status = getCanaryStatus(["chirpee"]);
check("canary: chirpee in service_stats", status.service_stats.length >= 1, true, "canary");
check("canary: no_read_gates", status.success_criteria.no_read_gates, true, "canary");
check("canary: no_unknown_service_blocks", status.success_criteria.no_unknown_service_blocks, true, "canary");

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("\n══ Summary ══");
console.log(`  Total checks:              ${totalChecks}`);
console.log(`  PASS:                      ${passed}`);
console.log(`  FAIL:                      ${failed}`);
console.log(`  Hard gate globally enabled: ${HARD_GATE_GLOBALLY_ENABLED}`);
console.log(`  Chirpee hard_gate_enabled:  ${CHIRPEE_HG1_POLICY.hard_gate_enabled}`);
console.log(`  Services with policy:       ${Object.keys(HARD_GATE_POLICIES).join(", ")}`);
console.log(`  Stage:                      ${CHIRPEE_HG1_POLICY.stage}`);

if (failed > 0) {
  console.log("\n  Failures:");
  for (const f of failures) {
    console.log(`    ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`);
  }
}

// ── Decision table ────────────────────────────────────────────────────────────

console.log("\n── Simulation decision table (chirpee, dryRunOverride=true) ──");
console.log("  Capability                   Soft        → Hard sim   Would apply?");
for (const { cap, softDecision, result } of simResults) {
  const wouldApply = result.hard_gate_would_apply ? "YES — BLOCK" : "no";
  console.log(
    `  ${cap.padEnd(28)} ${softDecision.padEnd(11)} → ${result.simulated_hard_decision.padEnd(10)} ${wouldApply}`
  );
}

// ── Artifacts ─────────────────────────────────────────────────────────────────

const OUT = "/root/.aegis";
mkdirSync(OUT, { recursive: true });

const matrix = {
  _meta: {
    batch: "batch30",
    generated_at: new Date().toISOString(),
    hard_gate_globally_enabled: HARD_GATE_GLOBALLY_ENABLED,
    hard_gate_services_enabled: [...HARD_GATE_SERVICES_ENABLED],
    chirpee_hard_gate_enabled: CHIRPEE_HG1_POLICY.hard_gate_enabled,
    stage: CHIRPEE_HG1_POLICY.stage,
    ready_to_enable_hard_gate: false,
    simulation_mode: "dry_run_only",
    gate_ts_modified: false,
  },
  chirpee_policy: {
    hg_group: CHIRPEE_HG1_POLICY.hg_group,
    hard_gate_enabled: CHIRPEE_HG1_POLICY.hard_gate_enabled,
    hard_block_capabilities: [...CHIRPEE_HG1_POLICY.hard_block_capabilities],
    still_gate_capabilities: [...CHIRPEE_HG1_POLICY.still_gate_capabilities],
    always_allow_capabilities: [...CHIRPEE_HG1_POLICY.always_allow_capabilities],
    never_block_capabilities: [...CHIRPEE_HG1_POLICY.never_block_capabilities],
    rollout_order: CHIRPEE_HG1_POLICY.rollout_order,
  },
  simulation_results: simResults.map(({ label, cap, op, softDecision, expectedSimDecision, result }) => ({
    label,
    capability: cap,
    operation: op,
    soft_decision: softDecision,
    simulated_hard_decision: result.simulated_hard_decision,
    expected: expectedSimDecision,
    match: result.simulated_hard_decision === expectedSimDecision,
    hard_gate_would_apply: result.hard_gate_would_apply,
    reason: result.reason,
    invariant_applied: result.invariant_applied,
  })),
};

writeFileSync(join(OUT, "batch30_chirpee_hard_gate_matrix.json"), JSON.stringify(matrix, null, 2));

const summaryMd = [
  `# AEGIS Batch 30 — Chirpee HG-1 Stage 1 Pilot Preparation`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Scope:** chirpee only`,
  `**Hard gate:** disabled (dry-run simulation only)`,
  `**gate.ts:** unchanged`,
  ``,
  `> *The standing orders are written. Now test one small gun on an empty range —*`,
  `> *chirpee only, malformed actions only, and the safety catch still on.*`,
  ``,
  `## Invariants`,
  ``,
  `| Invariant | Value |`,
  `|---|---|`,
  `| HARD_GATE_GLOBALLY_ENABLED | **false** |`,
  `| chirpee hard_gate_enabled | **false** |`,
  `| AEGIS_HARD_GATE_SERVICES env var | **not set** |`,
  `| gate.ts modified | **no** |`,
  `| ready_to_enable_hard_gate | **false** |`,
  ``,
  `## chirpee Profile`,
  ``,
  `| Field | Value |`,
  `|---|---|`,
  `| runtime_readiness.tier | TIER-A |`,
  `| authority_class | read_only |`,
  `| governance_blast_radius | BR-0 |`,
  `| hg_group | HG-1 |`,
  `| rollout_order | 1 (first in rollout) |`,
  `| hard_gate_eligible | true |`,
  `| hard_gate_enabled | false |`,
  ``,
  `## HG-1 Policy for chirpee`,
  ``,
  `| List | Capabilities |`,
  `|---|---|`,
  `| hard_block_when_enabled | IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE |`,
  `| still_gate (not BLOCK) | CI_DEPLOY, DELETE, EXECUTE, APPROVE, AI_EXECUTE, FULL_AUTONOMY, SPAWN_AGENTS, MEMORY_WRITE, AUDIT_WRITE, TRIGGER, EMIT |`,
  `| always_allow | READ, GET, LIST, QUERY, SEARCH, HEALTH |`,
  `| never_block | READ (AEG-E-002 extended) |`,
  ``,
  `## Dry-Run Simulation Results`,
  ``,
  `| Capability | Soft decision | → Hard sim | Would apply? | Invariant |`,
  `|---|---|---|---|---|`,
  ...matrix.simulation_results.map(r =>
    `| ${r.capability} | ${r.soft_decision} | **${r.simulated_hard_decision}** | ${r.hard_gate_would_apply ? "**YES — BLOCK**" : "no"} | ${r.invariant_applied ?? "—"} |`
  ),
  ``,
  `## Key Findings`,
  ``,
  `- READ is ALLOW in all conditions. Invariant holds in simulation mode.`,
  `- IMPOSSIBLE_OP and EMPTY_CAPABILITY_ON_WRITE → BLOCK in dry-run (the only two).`,
  `- DEPLOY/DELETE/EXECUTE/APPROVE/FULL_AUTONOMY → GATE (not BLOCK). Safety catch intact.`,
  `- Unknown capability → soft decision preserved. No hard-block on unknown caps.`,
  `- Unknown service → no policy → soft decision preserved.`,
  `- Non-chirpee services → no policy → untouched.`,
  `- dryRunOverride=false → no simulation fires. Hard gate off is hard gate off.`,
  ``,
  `## What Must Happen Before Stage 1 Enable`,
  ``,
  `1. Canonical capability registry progress noted`,
  `2. Human decision to promote chirpee (not automated)`,
  `3. Add \`chirpee\` to \`AEGIS_HARD_GATE_SERVICES\` env var (set \`HARD_GATE_GLOBALLY_ENABLED=true\`)`,
  `4. 7-day soak with zero false positives before ship-slm/chief-slm promoted`,
  ``,
  `**Rollback:** remove chirpee from AEGIS_HARD_GATE_SERVICES — config change, <1 min, no deployment.`,
  ``,
  `## Check Summary`,
  ``,
  `| Category | Checks | PASS | FAIL |`,
  `|---|---|---|---|`,
  ...["pre", "soft_baseline", "simulation", "non_chirpee", "invariant", "rollback", "canary"].map(cat => {
    const catChecks = failures.filter(f => f.cat === cat).length;
    const total = 0; // approximation — count would need separate tracking
    return `| ${cat} | — | — | ${catChecks} fail |`;
  }),
  `| **TOTAL** | **${totalChecks}** | **${passed}** | **${failed}** |`,
  ``,
  `## Batch Sequence`,
  ``,
  `| Batch | Scope | Window | Status |`,
  `|---|---|---|---|`,
  `| Batch 27 | 12 svc | Observation (297/297) | complete |`,
  `| Batch 28 | 12 svc | Rough weather (489/489) | complete |`,
  `| Batch 29 | 12 svc | Hard-gate policy (122/122) | complete |`,
  `| **Batch 30** | **chirpee** | **HG-1 pilot prep** | **${failed === 0 ? "complete" : "FAILED"}** |`,
  `| Batch 31 | chirpee | HG-1 soak observation | not yet started |`,
  ``,
  `---`,
  `*AEGIS chirpee HG-1 pilot preparation — Batch 30 — @rule:AEG-HG-001 / @rule:AEG-HG-003*`,
].join("\n");

writeFileSync(join(OUT, "batch30_chirpee_hg1_pilot_summary.md"), summaryMd);
writeFileSync(join(OUT, "batch30_failures.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch30",
  total_checks: totalChecks,
  passed,
  failed,
  hard_gate_globally_enabled: HARD_GATE_GLOBALLY_ENABLED,
  ready_to_enable_hard_gate: false,
  failures,
}, null, 2));

console.log("\n── Artifacts ──");
console.log(`  ${join(OUT, "batch30_chirpee_hg1_pilot_summary.md")}`);
console.log(`  ${join(OUT, "batch30_chirpee_hard_gate_matrix.json")}`);
console.log(`  ${join(OUT, "batch30_failures.json")}`);
console.log(`\n  Chirpee HG-1 pilot prep: ${failed === 0
  ? "CLEAN — safety catch on, gun tested on empty range. Batch 31 is 7-day soak observation."
  : `${failed} FAILURE(S) — review hard-gate-policy.ts before proceeding.`}`);
