/**
 * Batch 42 Soak Run 1/7 — pramana HG-2A policy prep observation
 *
 * First soak run for pramana (rollout order 5, HG-2A).
 * Profile: read_only authority, BR-5, TIER-A.
 *
 * Key invariants verified this run:
 *   - pramana is NOT in AEGIS_HARD_GATE_SERVICES (policy is NOT live)
 *   - pramana stays in soft_canary phase throughout
 *   - simulateHardGate(dryRunOverride=true) correctly fires BLOCK for TPs
 *   - no live hard-gate overlay on pramana
 *   - domain-capture remains blocked from soak (registry issue)
 *   - HG-1 regression clean (all 4 services remain live)
 *   - approval lifecycle correct for GATE tokens
 *   - kill switch suppresses hard-gate for all HG-1 services
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false — pramana not live
 * @rule:AEG-HG-002 READ never hard-blocks in any mode
 * @rule:AEG-HG-003 env var is gate switch; pramana not in env
 * @rule:AEG-E-002  READ always ALLOW
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
// HG-1 services only — pramana NOT added
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PRAMANA_HG2A_POLICY } from "../src/enforcement/hard-gate-policy";
import { approveToken, denyToken, revokeToken } from "../src/enforcement/approval";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const SOAK_RUN = 1;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

function gateToken(d: ReturnType<typeof evaluate>): string {
  return (d as unknown as { approval_token?: string }).approval_token ?? "";
}
function okStatus(r: { ok: boolean }) { return r.ok ? "accepted" : "rejected"; }

let simTPs = 0;
let prodFires = 0;

console.log(`\n══ Batch 42 Soak Run ${SOAK_RUN}/7 — pramana HG-2A policy prep observation ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  Profile: pramana — read_only, BR-5, TIER-A, rollout_order=5`);
console.log(`  Status: policy staged (PRAMANA_HG2A_POLICY), NOT live`);

// ══ Pre-flight ════════════════════════════════════════════════════════════════

console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana NOT in AEGIS_HARD_GATE_SERVICES", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), false, "pre");
check("domain-capture NOT in AEGIS_HARD_GATE_SERVICES", process.env.AEGIS_HARD_GATE_SERVICES?.includes("domain-capture"), false, "pre");
check("pramana hard_gate_enabled = false (NOT LIVE)", PRAMANA_HG2A_POLICY.hard_gate_enabled, false, "pre");
check("pramana rollout_order = 5", PRAMANA_HG2A_POLICY.rollout_order, 5, "pre");
check("pramana hg_group = HG-2", PRAMANA_HG2A_POLICY.hg_group, "HG-2", "pre");
check("pramana hard_block has IMPOSSIBLE_OP", PRAMANA_HG2A_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "pre");
check("pramana hard_block has EMPTY_CAPABILITY_ON_WRITE", PRAMANA_HG2A_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "pre");
check("pramana never_block has READ", PRAMANA_HG2A_POLICY.never_block_capabilities.has("READ"), true, "pre");

// domain-capture must remain blocked from soak (soft blocker: port not in services.json)
{
  const dc = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: "b42-pre" });
  // domain-capture is registered in services.json (soft_canary) — but port is missing (noted blocker)
  // Blocker is operational (not a soak_ready flag in code): we just confirm it's not in hard_gate
  check("domain-capture NOT in hard_gate phase", dc.enforcement_phase !== "hard_gate", true, "pre");
  check("domain-capture NOT in AEGIS_HARD_GATE_SERVICES (soak blocked)", process.env.AEGIS_HARD_GATE_SERVICES?.includes("domain-capture"), false, "pre");
}

// ══ HG-1 regression ══════════════════════════════════════════════════════════

console.log("\n── HG-1 regression ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42-reg" });
  logDecision(r);
  check(`[${svc}] READ: hard_gate`, r.enforcement_phase, "hard_gate", "hg1_reg");
  check(`[${svc}] READ: ALLOW`, r.decision, "ALLOW", "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42-reg" });
  logDecision(b);
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
}

// ══ Phase A: Normal read-only traffic ════════════════════════════════════════

console.log("\n── Phase A: Normal read-only traffic ──");
for (const [op, cap] of [
  ["read",   "READ"],
  ["get",    "READ"],
  ["list",   "LIST"],
  ["query",  "QUERY"],
  ["search", "SEARCH"],
  ["health", "HEALTH"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42-readtraffic" });
  logDecision(d);
  check(`pramana [${op}/${cap}]: soft_canary phase (not hard_gate)`, d.enforcement_phase, "soft_canary", "phase_a");
  check(`pramana [${op}/${cap}]: ALLOW`, d.decision, "ALLOW", "phase_a");

  // sim(on) for read caps → always ALLOW (never_block invariant)
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana [${op}/${cap}]: sim(on) → ALLOW (never_block)`, sim.simulated_hard_decision, "ALLOW", "phase_a");
  check(`pramana [${op}/${cap}]: sim hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "phase_a");
}

// ══ Phase B: Pramana domain ops (proof/verification traffic) ═════════════════

console.log("\n── Phase B: Pramana-domain proof/verification traffic ──");
// Pramana is a SHA-256 receipt chain + Merkle proof service.
// Verification, attestation, and proof-query ops are its core traffic.
// These map to medium risk (not in OPERATION_RISK_MAP → medium fallback) → ALLOW for read_only.
for (const [op, cap] of [
  ["verify",       "VERIFY"],
  ["validate",     "VALIDATE"],
  ["attest",       "ATTEST"],
  ["check-proof",  "CHECK_PROOF"],
  ["issue-proof",  "ISSUE_PROOF"],
  ["query-proof",  "QUERY_PROOF"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42-domain" });
  logDecision(d);
  check(`pramana [${cap}]: soft_canary phase`, d.enforcement_phase, "soft_canary", "phase_b");
  // medium risk + read_only + not critical → ALLOW
  check(`pramana [${cap}]: ALLOW (medium risk, read_only, BR-5 high threshold)`, d.decision, "ALLOW", "phase_b");

  // sim(on) for domain ops — not in hard_block → ALLOW preserved
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana [${cap}]: sim(on) → ALLOW (not in hard_block)`, sim.simulated_hard_decision, "ALLOW", "phase_b");
  check(`pramana [${cap}]: sim hard_gate_would_apply = false`, sim.hard_gate_would_apply, false, "phase_b");
  if (sim.hard_gate_would_apply) prodFires++;
}

// ══ Phase C: Critical/high-risk traffic ══════════════════════════════════════

console.log("\n── Phase C: Critical/high-risk traffic ──");
// These should return GATE (not BLOCK) for pramana in soft mode.
// BR-5 ≥ 3 rule fires for high-risk ops; critical ops always GATE.
// sim(on) for still_gate caps with soft=GATE → preserves GATE (no upgrade to BLOCK).
for (const [op, cap] of [
  ["execute",      "EXECUTE"],
  ["ai-execute",   "AI_EXECUTE"],
  ["deploy",       "CI_DEPLOY"],
  ["delete",       "DELETE"],
  ["approve",      "APPROVE"],
  ["emit",         "EMIT"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42-critical" });
  logDecision(d);
  check(`pramana [${cap}]: soft_canary phase`, d.enforcement_phase, "soft_canary", "phase_c");
  // high/critical ops → GATE (approval token issued)
  check(`pramana [${cap}]: GATE (soft layer governs high/critical ops)`, d.decision, "GATE", "phase_c");

  // sim(on): still_gate caps with softDecision=GATE → GATE (not upgraded to BLOCK)
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana [${cap}]: sim(on) GATE → GATE (still_gate no-upgrade)`, sim.simulated_hard_decision, "GATE", "phase_c");
  check(`pramana [${cap}]: sim hard_gate_would_apply = false (GATE preserved)`, sim.hard_gate_would_apply, false, "phase_c");
}

// MEMORY_WRITE and AUDIT_WRITE — high consequence internal caps
for (const [op, cap] of [
  ["write",  "MEMORY_WRITE"],
  ["write",  "AUDIT_WRITE"],
  ["write",  "FULL_AUTONOMY"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42-critical2" });
  logDecision(d);
  check(`pramana [${cap}]: soft_canary phase`, d.enforcement_phase, "soft_canary", "phase_c");
  // MEMORY_WRITE/AUDIT_WRITE/FULL_AUTONOMY — not in OPERATION_RISK_MAP by op="write" (medium)
  // capKey maps: memory_write/audit_write not in HIGH_CONSEQUENCE_BITS for trust_mask=1
  // Falls through to medium → ALLOW for read_only pramana
  // NOTE: still_gate would NOT fire for ALLOW soft decisions — correct behavior
  check(`pramana [${cap}]: ALLOW (write-class op, medium risk, read_only passes)`, d.decision, "ALLOW", "phase_c");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  // still_gate check: softDecision=ALLOW, cap in still_gate → still_gate only fires on BLOCK
  // So sim result = ALLOW (soft decision preserved — no upgrade)
  check(`pramana [${cap}]: sim(on) ALLOW → ALLOW (still_gate no-upgrade invariant)`, sim.simulated_hard_decision, "ALLOW", "phase_c");
  if (sim.hard_gate_would_apply) prodFires++;
}

// ══ Phase D: Malformed true positives ════════════════════════════════════════

console.log("\n── Phase D: Malformed true positives (simulation) ──");
// Live eval: pramana is NOT in hard_gate → soft_canary, ALLOW
// sim(on=true): IMPOSSIBLE_OP/EMPTY_CAP → BLOCK (TP confirmed)
// sim(on=false): soft decision preserved (policy disabled, no override)
{
  const live = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42-tp" });
  logDecision(live);
  check("pramana IMPOSSIBLE_OP: live soft_canary (NOT hard_gate)", live.enforcement_phase, "soft_canary", "tp");
  check("pramana IMPOSSIBLE_OP: live ALLOW (no hard-gate active)", live.decision, "ALLOW", "tp");

  const simOn = simulateHardGate("pramana", live.decision, "IMPOSSIBLE_OP", "frob", true);
  check("pramana IMPOSSIBLE_OP: sim(on) → BLOCK (TP confirmed)", simOn.simulated_hard_decision, "BLOCK", "tp");
  check("pramana IMPOSSIBLE_OP: sim(on) hard_gate_would_apply = true", simOn.hard_gate_would_apply, true, "tp");
  if (simOn.hard_gate_would_apply) simTPs++;

  const simOff = simulateHardGate("pramana", live.decision, "IMPOSSIBLE_OP", "frob", false);
  check("pramana IMPOSSIBLE_OP: sim(off) → ALLOW (policy not enabled)", simOff.simulated_hard_decision, "ALLOW", "tp");
  check("pramana IMPOSSIBLE_OP: sim(off) hard_gate_would_apply = false", simOff.hard_gate_would_apply, false, "tp");
}
{
  const live = evaluate({ service_id: "pramana", operation: "write", requested_capability: "EMPTY_CAPABILITY_ON_WRITE", caller_id: "b42-tp" });
  logDecision(live);
  check("pramana EMPTY_CAP_ON_WRITE: live soft_canary (NOT hard_gate)", live.enforcement_phase, "soft_canary", "tp");
  check("pramana EMPTY_CAP_ON_WRITE: live ALLOW", live.decision, "ALLOW", "tp");

  const simOn = simulateHardGate("pramana", live.decision, "EMPTY_CAPABILITY_ON_WRITE", "write", true);
  check("pramana EMPTY_CAP_ON_WRITE: sim(on) → BLOCK (TP confirmed)", simOn.simulated_hard_decision, "BLOCK", "tp");
  check("pramana EMPTY_CAP_ON_WRITE: sim(on) hard_gate_would_apply = true", simOn.hard_gate_would_apply, true, "tp");
  if (simOn.hard_gate_would_apply) simTPs++;

  const simOff = simulateHardGate("pramana", live.decision, "EMPTY_CAPABILITY_ON_WRITE", "write", false);
  check("pramana EMPTY_CAP_ON_WRITE: sim(off) → ALLOW", simOff.simulated_hard_decision, "ALLOW", "tp");
}

// ══ Phase E: Boundary conditions ═════════════════════════════════════════════

console.log("\n── Phase E: Boundary conditions ──");

// Unknown capability — not in hard_block, should preserve soft decision
{
  const unk = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "UNKNOWN_NEW_CAP", caller_id: "b42-unk" });
  logDecision(unk);
  check("pramana UNKNOWN_CAP: soft_canary phase (not hard_gate)", unk.enforcement_phase, "soft_canary", "boundary");
  // medium fallback → ALLOW
  check("pramana UNKNOWN_CAP: ALLOW in soft", unk.decision, "ALLOW", "boundary");
  const simUnk = simulateHardGate("pramana", unk.decision, "UNKNOWN_NEW_CAP", "frob", true);
  // Not in hard_block → preserved (ALLOW → ALLOW)
  check("pramana UNKNOWN_CAP: sim(on) → ALLOW (unknown cap not hard-blocked)", simUnk.simulated_hard_decision, "ALLOW", "boundary");
  check("pramana UNKNOWN_CAP: sim hard_gate_would_apply = false", simUnk.hard_gate_would_apply, false, "boundary");
  if (simUnk.hard_gate_would_apply) prodFires++;
}

// Unknown service → WARN, shadow — never enters hard_gate
{
  const us = evaluate({ service_id: "unregistered-svc", operation: "read", requested_capability: "READ", caller_id: "b42-unk" });
  check("unknown service: shadow phase", us.enforcement_phase, "shadow", "boundary");
  check("unknown service: WARN", us.decision, "WARN", "boundary");
  check("unknown service: not in hard_gate", us.enforcement_phase !== "hard_gate", true, "boundary");
}

// still_gate downgrade guard: sim(BLOCK, EXECUTE, execute, true) → GATE (not BLOCK)
{
  const simDG = simulateHardGate("pramana", "BLOCK", "EXECUTE", "execute", true);
  check("still_gate downgrade: sim(BLOCK) + EXECUTE → GATE (not BLOCK)", simDG.simulated_hard_decision, "GATE", "boundary");
  check("still_gate downgrade: hard_gate_would_apply = false (not a hard BLOCK)", simDG.hard_gate_would_apply, false, "boundary");
}

// still_gate non-upgrade: sim(ALLOW, EXECUTE, execute, true) → ALLOW (not GATE)
{
  const simNU = simulateHardGate("pramana", "ALLOW", "EXECUTE", "execute", true);
  check("still_gate no-upgrade: sim(ALLOW) + EXECUTE → ALLOW (not upgraded to GATE)", simNU.simulated_hard_decision, "ALLOW", "boundary");
}

// domain-capture: NOT eligible for soak (registry issue — port missing)
{
  const dc = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42-dc" });
  check("domain-capture IMPOSSIBLE_OP: soft_canary (not hard_gate — registry issue)", dc.enforcement_phase, "soft_canary", "boundary");
  check("domain-capture IMPOSSIBLE_OP: ALLOW (no hard_gate active — soak blocked)", dc.decision, "ALLOW", "boundary");
}

// HG-2B services not in hard_gate
for (const svc of ["parali-central", "carbonx"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42-hg2b" });
  check(`[${svc}] NOT in hard_gate phase (HG-2B isolated)`, d.enforcement_phase !== "hard_gate", true, "boundary");
}

// ══ Phase F: Approval lifecycle ═══════════════════════════════════════════════

console.log("\n── Phase F: Approval lifecycle ──");
// GATE decisions for pramana EXECUTE produce approval_token

const d1 = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42-appr" });
const d2 = evaluate({ service_id: "pramana", operation: "ai-execute", requested_capability: "AI_EXECUTE", caller_id: "b42-appr" });
const d3 = evaluate({ service_id: "pramana", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b42-appr" });
check("pramana EXECUTE: GATE (token issued)", d1.decision, "GATE", "lifecycle");
check("pramana AI_EXECUTE: GATE (token issued)", d2.decision, "GATE", "lifecycle");
check("pramana CI_DEPLOY: GATE (token issued)", d3.decision, "GATE", "lifecycle");
check("pramana EXECUTE: approval_token present", !!gateToken(d1), true, "lifecycle");
check("pramana AI_EXECUTE: approval_token present", !!gateToken(d2), true, "lifecycle");
check("pramana CI_DEPLOY: approval_token present", !!gateToken(d3), true, "lifecycle");

// Approve d1
const a1 = approveToken(gateToken(d1), "verified by operator b42", "b42-approver");
check("approve d1: accepted", okStatus(a1), "accepted", "lifecycle");

// Replay of d1 must be rejected
const replay1 = approveToken(gateToken(d1), "retry", "b42-approver");
check("replay d1: rejected (already approved)", okStatus(replay1), "rejected", "lifecycle");

// Blank approval_reason rejected
const blankReason = approveToken(gateToken(d2), "", "b42-approver");
check("blank approval_reason: rejected", okStatus(blankReason), "rejected", "lifecycle");

// Blank approved_by rejected
const blankBy = approveToken(gateToken(d2), "valid reason", "");
check("blank approved_by: rejected", okStatus(blankBy), "rejected", "lifecycle");

// Deny d2 with valid reason
const deny2 = denyToken(gateToken(d2), "scope too broad", "b42-approver");
check("deny d2: accepted", okStatus(deny2), "accepted", "lifecycle");

// Approve-after-deny is rejected
const approveAfterDeny = approveToken(gateToken(d2), "trying again", "b42-approver");
check("approve-after-deny: rejected", okStatus(approveAfterDeny), "rejected", "lifecycle");

// Revoke d3
const rev3 = revokeToken(gateToken(d3), "b42-revoker", "policy updated during review");
check("revoke d3: accepted", okStatus(rev3), "accepted", "lifecycle");

// Approve-after-revoke is rejected
const approveAfterRevoke = approveToken(gateToken(d3), "trying again", "b42-approver");
check("approve-after-revoke: rejected", okStatus(approveAfterRevoke), "rejected", "lifecycle");

// Service isolation: pramana tokens must not be usable for chirpee (different service context)
// chirpee is read_only+BR-0: only critical ops (deploy/delete) produce GATE, not high ops
const dChirpee = evaluate({ service_id: "chirpee", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b42-iso" });
check("chirpee CI_DEPLOY: GATE (critical op, token issued)", dChirpee.decision, "GATE", "lifecycle");
check("chirpee token is different from pramana token", gateToken(dChirpee) !== gateToken(d1), true, "lifecycle");

// ══ Phase G: Kill switch ══════════════════════════════════════════════════════

console.log("\n── Phase G: Kill switch ──");
process.env.AEGIS_RUNTIME_ENABLED = "false";

// Kill: pramana → shadow (already soft_canary, now shadow)
for (const [op, cap] of [["read", "READ"], ["frob", "IMPOSSIBLE_OP"], ["execute", "EXECUTE"]] as [string, string][]) {
  const k = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42-kill" });
  check(`pramana [${cap}]: kill → shadow`, k.enforcement_phase, "shadow", "kill_switch");
  check(`pramana [${cap}]: kill → not BLOCK`, k.decision !== "BLOCK", true, "kill_switch");
}

// Kill: HG-1 hard-gate suppressed
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const k = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42-kill" });
  check(`[${svc}] kill: shadow (hard-gate suppressed)`, k.enforcement_phase, "shadow", "kill_switch");
  check(`[${svc}] kill: IMPOSSIBLE_OP not BLOCK`, k.decision !== "BLOCK", true, "kill_switch");
}

process.env.AEGIS_RUNTIME_ENABLED = "true";

// Restore: HG-1 back to hard_gate
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42-restore" });
  check(`[${svc}] restored: hard_gate`, r.enforcement_phase, "hard_gate", "kill_switch");
}
// pramana: back to soft_canary after restore
{
  const rp = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: "b42-restore" });
  check("pramana restored: soft_canary", rp.enforcement_phase, "soft_canary", "kill_switch");
}

// ══ Production fire guard ═════════════════════════════════════════════════════

console.log("\n── Production fire guard ──");
for (const [op, cap] of [
  ["read",       "READ"],
  ["get",        "READ"],
  ["verify",     "VERIFY"],
  ["validate",   "VALIDATE"],
  ["attest",     "ATTEST"],
  ["check-proof","CHECK_PROOF"],
  ["write",      "WRITE"],
  ["execute",    "EXECUTE"],
  ["ai-execute", "AI_EXECUTE"],
  ["deploy",     "CI_DEPLOY"],
] as [string, string][]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42-guard" });
  const simGuard = simulateHardGate("pramana", d.decision, cap, op, false);
  if (simGuard.hard_gate_would_apply) prodFires++;
  check(`prod guard [pramana] ${cap}: no fire (policy off)`, simGuard.hard_gate_would_apply, false, "prod_guard");
}

// ══ Count validation ══════════════════════════════════════════════════════════

console.log("\n── Count validation ──");
check("simulation TPs = 2 (IMPOSSIBLE_OP + EMPTY_CAP)", simTPs, 2, "count");
check("production fires = 0", prodFires, 0, "count");

// ══ Summary ═══════════════════════════════════════════════════════════════════

const soakPass = failed === 0 && prodFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

// ══ Artifacts ════════════════════════════════════════════════════════════════

writeFileSync(join(dir, `batch42_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN,
  service: "pramana",
  hg_group: "HG-2A",
  date: RUN_DATE,
  verdict: soakPass ? "PASS" : "FAIL",
  checks: totalChecks,
  passed,
  failed,
  simulation_true_positives: simTPs,
  production_gate_fires: prodFires,
  ready_to_promote: false,
  policy_live: false,
  note: "Soak run 1/7. Policy staged, NOT enabled. Sim TPs confirmed. 6 more runs required.",
}, null, 2));

const summary = `# Batch 42 Soak Run ${SOAK_RUN}/7 — pramana HG-2A Policy Prep

**Date:** ${RUN_DATE}
**Verdict:** ${soakPass ? "PASS" : "FAIL"}
**Checks:** ${totalChecks} | PASS: ${passed} | FAIL: ${failed}

## State

| Control | Value |
|---------|-------|
| AEGIS_HARD_GATE_SERVICES | chirpee,ship-slm,chief-slm,puranic-os (HG-1 only) |
| pramana hard_gate_enabled | false (NOT LIVE) |
| pramana in AEGIS_HARD_GATE_SERVICES | NO |
| domain-capture soak status | BLOCKED (registry issue: port missing) |

## Observations — Run 1

### Phase A: Read-only traffic
All READ/GET/LIST/QUERY/SEARCH/HEALTH → soft_canary, ALLOW.
sim(on) → ALLOW (never_block invariant confirmed).

### Phase B: Pramana domain ops
VERIFY/VALIDATE/ATTEST/CHECK_PROOF/ISSUE_PROOF/QUERY_PROOF → soft_canary, ALLOW.
Medium-risk ops, read_only authority, BR-5 rule only fires on high-risk.
sim(on) → ALLOW (not in hard_block).

### Phase C: Critical/high-risk
EXECUTE/AI_EXECUTE/CI_DEPLOY/DELETE/APPROVE/EMIT → soft_canary, GATE (approval_token issued).
sim(on) for still_gate caps: GATE soft → GATE (no upgrade invariant confirmed).
MEMORY_WRITE/AUDIT_WRITE/FULL_AUTONOMY with op=write → ALLOW (write-class = medium risk).
sim(on) for ALLOW soft → ALLOW (still_gate no-upgrade confirmed).

### Phase D: Malformed TPs (simulation)
IMPOSSIBLE_OP: live=ALLOW (soft_canary, no hard-gate) / sim(on)=BLOCK → **TP confirmed**
EMPTY_CAP_ON_WRITE: live=ALLOW / sim(on)=BLOCK → **TP confirmed**
sim(off): policy disabled → soft decision preserved (both ALLOW)
sim_true_positives = ${simTPs}

### Phase E: Boundaries
Unknown cap → ALLOW in soft, sim(on) → ALLOW (not hard-blocked).
Unknown service → shadow, WARN.
still_gate downgrade guard: sim(BLOCK, EXECUTE) → GATE.
still_gate non-upgrade: sim(ALLOW, EXECUTE) → ALLOW.
domain-capture: soft_canary, ALLOW (soak blocked, no hard-gate).

### Phase F: Approval lifecycle
Approve valid token → accepted.
Replay → rejected.
Blank reason/approvedBy → rejected.
Deny → accepted. Approve-after-deny → rejected.
Revoke → accepted. Approve-after-revoke → rejected.
Service isolation: pramana and chirpee tokens distinct.

### Phase G: Kill switch
Kill: pramana → shadow (all ops). HG-1 → shadow (hard-gate suppressed for all).
Restore: HG-1 → hard_gate. pramana → soft_canary.

## Failures

${soakPass ? "None." : failures.map(f => `- [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`).join("\n")}

## Progress

Run 1/7 ${soakPass ? "PASS" : "FAIL"}. 6 runs remaining before promotion eligibility.
ready_to_promote_pramana = false
`;

writeFileSync(join(dir, `batch42_pramana_hg2a_prep_summary.md`), summary);
writeFileSync(join(dir, `batch42_failures.json`), JSON.stringify(failures, null, 2));

console.log(`\n  Written: .aegis/batch42_soak_run${SOAK_RUN}_metrics.json`);
console.log(`  Written: .aegis/batch42_pramana_hg2a_prep_summary.md`);
console.log(`  Written: .aegis/batch42_failures.json`);
console.log(`\n  Batch 42 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
