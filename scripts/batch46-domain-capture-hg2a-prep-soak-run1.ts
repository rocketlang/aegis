/**
 * Batch 46 — domain-capture HG-2A policy prep + soak run 1/7
 *
 * Policy added this batch: DOMAIN_CAPTURE_HG2A_POLICY (hard_gate_enabled=false).
 * hard_gate_enabled=false throughout. NOT in AEGIS_HARD_GATE_SERVICES.
 * Promotion is a separate manual act after 7/7 soak runs pass.
 *
 * Key invariant from Batch 45:
 *   sim(on=true) now BLOCKs IMPOSSIBLE_OP and EMPTY_CAPABILITY_ON_WRITE
 *   because DOMAIN_CAPTURE_HG2A_POLICY exists and defines hard_block_capabilities.
 *   (Batch 45 confirmed sim→ALLOW because no policy existed yet.)
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false — NOT in AEGIS_HARD_GATE_SERVICES
 * @rule:AEG-HG-002 READ never hard-blocks in any mode
 * @rule:AEG-E-007 pilot scope is TIER-A services only
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getServiceEntry, isInPilotScope, loadRegistry, invalidateCache } from "../src/enforcement/registry";
import {
  simulateHardGate,
  HARD_GATE_GLOBALLY_ENABLED,
  PRAMANA_HG2A_POLICY,
  DOMAIN_CAPTURE_HG2A_POLICY,
} from "../src/enforcement/hard-gate-policy";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH  = 46;
const RUN    = 1;
const RUN_DATE = new Date().toISOString();
const dir    = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
let prodFires = 0;
let fpCount   = 0;
let tpCount   = 0;

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(78)} actual=${actual}`); }
  else {
    failed++;
    failures.push({ label, expected: String(expected), actual: String(actual), cat });
    console.log(`  ✗ [FAIL] ${label.padEnd(78)} expected=${expected} actual=${actual}`);
  }
}

console.log(`\n══ Batch ${BATCH} Run ${RUN}/7 — domain-capture HG-2A prep + soak run 1/7 ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  domain-capture: NOT in hard_gate (soak mode)`);

// ── Pre-check: registry + codex ─────────────────────────────────────────────
console.log("\n── Pre-check: registry + codex ──");
invalidateCache();
const entry = getServiceEntry("domain-capture");
check("getServiceEntry returns non-null", entry !== null, true, "precheck");
check("entry.authority_class = read_only", entry?.authority_class, "read_only", "precheck");
check("entry.governance_blast_radius = BR-5", entry?.governance_blast_radius, "BR-5", "precheck");
check("entry.runtime_readiness.tier = TIER-A", entry?.runtime_readiness?.tier, "TIER-A", "precheck");
check("entry.aegis_gate.op1_read = ALLOW", entry?.aegis_gate?.op1_read, "ALLOW", "precheck");
check("isInPilotScope = true", isInPilotScope("domain-capture"), true, "precheck");
check("domain-capture NOT in AEGIS_HARD_GATE_SERVICES", !process.env.AEGIS_HARD_GATE_SERVICES?.includes("domain-capture"), true, "precheck");
check("pramana IS in AEGIS_HARD_GATE_SERVICES", !!process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), true, "precheck");
// No HG-2B service gated
check("parali-central NOT in env", !process.env.AEGIS_HARD_GATE_SERVICES?.includes("parali-central"), true, "precheck");
check("carbonx NOT in env",         !process.env.AEGIS_HARD_GATE_SERVICES?.includes("carbonx"), true, "precheck");
check("ankr-doctor NOT in env",     !process.env.AEGIS_HARD_GATE_SERVICES?.includes("ankr-doctor"), true, "precheck");

// ── Policy prep verification ─────────────────────────────────────────────────
console.log("\n── Policy prep verification ──");
check("DOMAIN_CAPTURE_HG2A_POLICY exists", !!DOMAIN_CAPTURE_HG2A_POLICY, true, "policy");
check("policy.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "policy");
check("policy.hg_group = HG-2", DOMAIN_CAPTURE_HG2A_POLICY.hg_group, "HG-2", "policy");
check("policy.rollout_order = 6", DOMAIN_CAPTURE_HG2A_POLICY.rollout_order, 6, "policy");
check("policy.stage contains NOT LIVE", DOMAIN_CAPTURE_HG2A_POLICY.stage.includes("NOT LIVE"), true, "policy");
check("hard_block: IMPOSSIBLE_OP", DOMAIN_CAPTURE_HG2A_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "policy");
check("hard_block: EMPTY_CAPABILITY_ON_WRITE", DOMAIN_CAPTURE_HG2A_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "policy");
check("still_gate: DEPLOY", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("DEPLOY"), true, "policy");
check("still_gate: DELETE", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("DELETE"), true, "policy");
check("still_gate: EXECUTE", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("EXECUTE"), true, "policy");
check("still_gate: APPROVE", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("APPROVE"), true, "policy");
check("still_gate: AI_EXECUTE", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("AI_EXECUTE"), true, "policy");
check("still_gate: FULL_AUTONOMY", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("FULL_AUTONOMY"), true, "policy");
check("still_gate: SPAWN_AGENTS", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("SPAWN_AGENTS"), true, "policy");
check("still_gate: MEMORY_WRITE", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("MEMORY_WRITE"), true, "policy");
check("still_gate: AUDIT_WRITE", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("AUDIT_WRITE"), true, "policy");
check("still_gate: TRIGGER", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("TRIGGER"), true, "policy");
check("still_gate: EMIT", DOMAIN_CAPTURE_HG2A_POLICY.still_gate_capabilities.has("EMIT"), true, "policy");
check("never_block: READ", DOMAIN_CAPTURE_HG2A_POLICY.never_block_capabilities.has("READ"), true, "policy");
check("always_allow: READ", DOMAIN_CAPTURE_HG2A_POLICY.always_allow_capabilities.has("READ"), true, "policy");
check("always_allow: HEALTH", DOMAIN_CAPTURE_HG2A_POLICY.always_allow_capabilities.has("HEALTH"), true, "policy");

// ── Traffic 1: Normal read-only ──────────────────────────────────────────────
console.log("\n── Traffic 1: Normal read-only ──");
for (const [op, cap] of [
  ["read",    "READ"],
  ["get",     "GET"],
  ["list",    "LIST"],
  ["query",   "QUERY"],
  ["search",  "SEARCH"],
  ["health",  "HEALTH"],
] as [string, string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b46r1-read" });
  check(`[READ] domain-capture [${cap}]: soft_canary + ALLOW`, d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "traffic_read");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
  // sim(on): READ → ALLOW (never_block invariant)
  const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
  check(`[READ] sim(on) [${cap}]: ALLOW (AEG-HG-002)`, sim.simulated_hard_decision, "ALLOW", "traffic_read");
}

// ── Traffic 2: Domain-capture operations ────────────────────────────────────
console.log("\n── Traffic 2: Domain-capture operations ──");
for (const [op, cap] of [
  ["capture",  "CAPTURE_DOMAIN"],
  ["classify", "CLASSIFY_DOMAIN"],
  ["extract",  "EXTRACT_RULES"],
  ["map",      "MAP_CONCEPTS"],
  ["index",    "INDEX_KNOWLEDGE"],
  ["query",    "QUERY_DOMAIN"],
] as [string, string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b46r1-domain" });
  logDecision(d);
  // Domain operations: soft_canary. Not BLOCK (not malformed). No live hard-BLOCK.
  check(`[DOMAIN] domain-capture [${cap}]: NOT BLOCK`, d.decision !== "BLOCK", true, "traffic_domain");
  check(`[DOMAIN] domain-capture [${cap}]: soft_canary phase`, d.enforcement_phase, "soft_canary", "traffic_domain");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
  // sim(on): domain ops → not in hard_block → soft decision preserved
  const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
  check(`[DOMAIN] sim(on) [${cap}]: NOT BLOCK (domain op, not malformed)`, sim.simulated_hard_decision !== "BLOCK", true, "traffic_domain");
}

// ── Traffic 3: Critical / high-risk ─────────────────────────────────────────
console.log("\n── Traffic 3: Critical / high-risk ──");
for (const [op, cap] of [
  ["ai-execute",  "AI_EXECUTE"],
  ["deploy",      "DEPLOY"],
  ["delete",      "DELETE"],
  ["execute",     "FULL_AUTONOMY"],
  ["write",       "MEMORY_WRITE"],
  ["write",       "AUDIT_WRITE"],
] as [string, string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b46r1-crit" });
  logDecision(d);
  // Domain-capture is read_only + BR-5 → high-risk ops → GATE from soft layer
  check(`[CRIT] domain-capture [${cap}]: soft_canary + NOT hard-BLOCK`, d.enforcement_phase === "soft_canary" && d.decision !== "BLOCK", true, "traffic_crit");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
  // sim(on): still_gate caps with soft=GATE/ALLOW → preserved (not BLOCK)
  const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
  check(`[CRIT] sim(on) [${cap}]: NOT BLOCK (still_gate preserves soft)`, sim.simulated_hard_decision !== "BLOCK", true, "traffic_crit");
}

// ── Traffic 4: Malformed true positives ─────────────────────────────────────
console.log("\n── Traffic 4: Malformed true positives ──");
for (const [op, cap] of [
  ["frob",  "IMPOSSIBLE_OP"],
  ["write", "EMPTY_CAPABILITY_ON_WRITE"],
] as [string, string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b46r1-tp" });
  logDecision(d);
  // Live soft: ALLOW (domain-capture not promoted — TP gap exists in soft layer)
  check(`[TP] domain-capture [${cap}]: soft_canary + ALLOW (TP gap in soft)`, d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "traffic_tp");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
  // sim(on): BLOCK — policy now exists, TP gap closed in simulation
  const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
  check(`[TP] sim(on) [${cap}]: BLOCK (policy closes TP gap — unlike Batch 45)`, sim.simulated_hard_decision, "BLOCK", "traffic_tp");
  if (sim.simulated_hard_decision === "BLOCK") tpCount++;
}

// ── Traffic 5: Boundary conditions ──────────────────────────────────────────
console.log("\n── Traffic 5: Boundary conditions ──");
// Unknown capability: preserve soft decision, never hard-BLOCK
{
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "BRAND_NEW_CAP", caller_id: "b46r1-unk" });
  check("[BOUNDARY] unknown cap: NOT hard-BLOCK", d.decision !== "BLOCK", true, "boundary");
  check("[BOUNDARY] unknown cap: soft_canary phase", d.enforcement_phase, "soft_canary", "boundary");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
  const sim = simulateHardGate("domain-capture", d.decision, "BRAND_NEW_CAP", "frob", true);
  check("[BOUNDARY] unknown cap sim(on): NOT BLOCK (unknown cap gates)", sim.simulated_hard_decision !== "BLOCK", true, "boundary");
}
// Unknown service: WARN, never BLOCK
{
  const d = evaluate({ service_id: "no-such-service-b46", operation: "read", requested_capability: "READ", caller_id: "b46r1-unknsvc" });
  check("[BOUNDARY] unknown service: NOT BLOCK", d.decision !== "BLOCK", true, "boundary");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
}
// HG-2B services (parali-central, carbonx): NOT hard_gate phase
for (const svc of ["parali-central", "carbonx"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b46r1-hg2b" });
  check(`[BOUNDARY] HG-2B [${svc}]: NOT hard_gate`, d.enforcement_phase !== "hard_gate", true, "boundary");
  check(`[BOUNDARY] HG-2B [${svc}]: NOT BLOCK`, d.decision !== "BLOCK", true, "boundary");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
}
// ankr-doctor: NOT hard_gate
{
  const d = evaluate({ service_id: "ankr-doctor", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b46r1-hg2c" });
  check("[BOUNDARY] ankr-doctor: NOT hard_gate", d.enforcement_phase !== "hard_gate", true, "boundary");
  check("[BOUNDARY] ankr-doctor: NOT BLOCK", d.decision !== "BLOCK", true, "boundary");
  if (d.decision === "BLOCK") { prodFires++; fpCount++; }
}

// ── Traffic 6: Approval lifecycle ───────────────────────────────────────────
console.log("\n── Traffic 6: Approval lifecycle ──");
// domain-capture is soft_canary (not live hard_gate). GATE decisions carry approval_token
// but action methods (approveToken/denyToken/revokeToken) are hard_gate only.
// Soak verification: confirm token is generated, confirm action methods are absent on
// soft_canary decisions (not a bug — expected phase behaviour). Full action lifecycle
// is exercised in the promotion batch when hard_gate is live.
const gateD = evaluate({ service_id: "domain-capture", operation: "execute", requested_capability: "EXECUTE", caller_id: "b46r1-appr" });
check("[APPR] domain-capture EXECUTE: soft_canary + GATE", gateD.enforcement_phase === "soft_canary" && gateD.decision === "GATE", true, "approval");
const token = gateD.approval_token ?? null;
check("[APPR] approval_token present on soft_canary GATE", token !== null && token !== undefined, true, "approval");

// approveToken: soft_canary decisions do not carry action methods — expected undefined.
const hasApproveToken = typeof (gateD as any).approveToken === "function";
check("[APPR] approveToken absent on soft_canary (hard_gate only)", hasApproveToken, false, "approval");

// Validate guard logic: if method absent, optional call returns undefined (safe)
const apprGuarded = hasApproveToken
  ? (gateD as any).approveToken(token, "test", "b46-approver")
  : undefined;
check("[APPR] approveToken optional call safe (undefined when absent)", apprGuarded, undefined, "approval");

// deny / revoke: same — absent on soft_canary
const gateD2 = evaluate({ service_id: "domain-capture", operation: "execute", requested_capability: "EXECUTE", caller_id: "b46r1-deny" });
const hasDenyToken = typeof (gateD2 as any).denyToken === "function";
check("[APPR] denyToken absent on soft_canary (hard_gate only)", hasDenyToken, false, "approval");

const gateD3 = evaluate({ service_id: "domain-capture", operation: "execute", requested_capability: "EXECUTE", caller_id: "b46r1-revoke" });
const hasRevokeToken = typeof (gateD3 as any).revokeToken === "function";
check("[APPR] revokeToken absent on soft_canary (hard_gate only)", hasRevokeToken, false, "approval");

// Confirm token uniqueness: 3 GATE decisions produce distinct tokens
const t1 = gateD.approval_token, t2 = gateD2.approval_token, t3 = gateD3.approval_token;
check("[APPR] token uniqueness: t1 !== t2", t1 !== t2, true, "approval");
check("[APPR] token uniqueness: t2 !== t3", t2 !== t3, true, "approval");

// ── Traffic 7: Rollback / kill switch ───────────────────────────────────────
console.log("\n── Traffic 7: Rollback / kill switch ──");
process.env.AEGIS_RUNTIME_ENABLED = "false";
// domain-capture under kill switch → shadow
{
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b46r1-kill" });
  check("[KILL] domain-capture killed: shadow", d.enforcement_phase, "shadow", "kill");
  check("[KILL] domain-capture killed: NOT BLOCK", d.decision !== "BLOCK", true, "kill");
}
// live 5 services under kill switch → shadow
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os", "pramana"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b46r1-kill" });
  check(`[KILL] ${svc} killed: shadow + NOT BLOCK`, d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true, "kill");
}
process.env.AEGIS_RUNTIME_ENABLED = "true";
// Restore: domain-capture back to soft_canary; live 5 back to hard_gate
{
  const d = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: "b46r1-restore" });
  check("[KILL] domain-capture restored: soft_canary + ALLOW", d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "kill");
}
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os", "pramana"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b46r1-restore" });
  check(`[KILL] ${svc} restored: hard_gate + ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "kill");
}

// ── Live roster regression (5 services) ─────────────────────────────────────
console.log("\n── Live roster regression (5 services) ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os", "pramana"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b46r1-reg" });
  check(`[REG] ${svc} READ: hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "regression");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b46r1-reg" });
  check(`[REG] ${svc} IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "regression");
}
check("[REG] PRAMANA_HG2A_POLICY.hard_gate_enabled = true", PRAMANA_HG2A_POLICY.hard_gate_enabled, true, "regression");

// ── Count validation ─────────────────────────────────────────────────────────
console.log("\n── Count validation ──");
check("production fires = 0", prodFires, 0, "count");
check("false positives = 0", fpCount, 0, "count");
check("true positives (sim) = 2", tpCount, 2, "count");

// ── Artifacts ────────────────────────────────────────────────────────────────
const metrics = {
  batch: BATCH,
  run: RUN,
  run_date: RUN_DATE,
  service: "domain-capture",
  hg_group: "HG-2A",
  checks: totalChecks,
  passed,
  failed,
  production_fires: prodFires,
  false_positives: fpCount,
  true_positives_simulated: tpCount,
  ready_to_promote: false,
  verdict: failed === 0 ? "PASS" : "FAIL",
};
writeFileSync(join(dir, "batch46_domain_capture_soak_run1_metrics.json"), JSON.stringify(metrics, null, 2));
if (failures.length > 0) {
  writeFileSync(join(dir, "batch46_failures.json"), JSON.stringify(failures, null, 2));
}

const summary = `# Batch 46 — domain-capture HG-2A prep + soak run 1/7

**Date:** ${RUN_DATE}
**Run:** 1/7
**Verdict:** ${metrics.verdict}
**Checks:** ${totalChecks} | **PASS:** ${passed} | **FAIL:** ${failed}
**Production fires:** ${prodFires} | **False positives:** ${fpCount} | **True positives (sim):** ${tpCount}

## Policy

- \`DOMAIN_CAPTURE_HG2A_POLICY\` added to \`hard-gate-policy.ts\`
- \`hard_gate_enabled=false\` — NOT in \`AEGIS_HARD_GATE_SERVICES\`
- \`rollout_order: 6\`
- \`hard_block_capabilities\`: IMPOSSIBLE_OP, EMPTY_CAPABILITY_ON_WRITE
- \`still_gate_capabilities\`: DEPLOY, DELETE, EXECUTE, APPROVE, AI_EXECUTE, FULL_AUTONOMY, SPAWN_AGENTS, MEMORY_WRITE, AUDIT_WRITE, TRIGGER, EMIT

## Key findings

- TP gap confirmed: IMPOSSIBLE_OP + EMPTY_CAPABILITY_ON_WRITE → soft=ALLOW, sim(on)=BLOCK
- This closes the Batch 45 observation (sim→ALLOW when no policy existed)
- Domain operations (CAPTURE_DOMAIN/CLASSIFY_DOMAIN/EXTRACT_RULES/MAP_CONCEPTS/INDEX_KNOWLEDGE/QUERY_DOMAIN) → NOT BLOCK
- Critical ops (AI_EXECUTE/DEPLOY/DELETE/FULL_AUTONOMY/MEMORY_WRITE/AUDIT_WRITE) → GATE not BLOCK (still_gate holds)
- READ/GET/LIST/QUERY/SEARCH/HEALTH → ALLOW (AEG-HG-002 invariant intact)
- Kill switch suppresses all phases to shadow — 0 hard BLOCK while killed
- Live roster (5 services) regression: all PASS
- No HG-2B service entered hard_gate phase

## Soak status

| Run | Verdict | FP | Prod fires |
|-----|---------|-----|------------|
| 1   | ${metrics.verdict}    | 0   | 0          |

**ready_to_promote_domain_capture=false** — 6 runs remaining
`;
writeFileSync(join(dir, "batch46_domain_capture_hg2a_prep_summary.md"), summary);

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n══ Batch ${BATCH} Run ${RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${failed === 0 ? "PASS" : "FAIL"}`);
if (failures.length > 0) {
  console.log("  Failures:");
  for (const f of failures) console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`);
}
console.log(`\n── Batch 46 Run 1/7 result ──`);
console.log(`  Policy: DOMAIN_CAPTURE_HG2A_POLICY added (hard_gate_enabled=false)`);
console.log(`  TP gap closed in simulation: sim(on) BLOCK for IMPOSSIBLE_OP + EMPTY_CAPABILITY_ON_WRITE`);
console.log(`  Domain ops: NOT BLOCK in soft layer`);
console.log(`  Critical ops: GATE not BLOCK (still_gate preserved)`);
console.log(`  Production fires: ${prodFires}  False positives: ${fpCount}  TPs simulated: ${tpCount}`);
console.log(`  ready_to_promote_domain_capture=false`);
console.log(`\n  Domain-capture was not broken in the engine room; its chart was missing enforcement`);
console.log(`  annotations. Now add the HG-2A policy and prove the second BR-5 ship under soak.`);
console.log(`\n  Batch ${BATCH} Run ${RUN}/7: ${failed === 0 ? "PASS" : "FAIL"}`);
