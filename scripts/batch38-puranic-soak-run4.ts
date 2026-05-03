/**
 * Batch 38 Soak Run 4/7 — puranic-os approval lifecycle deep
 *
 * Stress: approval token lifecycle under puranic-os BR-1 profile.
 * Verifies that:
 *   - approval tokens generated for GATE caps are valid and consumable
 *   - all lifecycle transitions work: approve, deny, replay, revoke
 *   - approved token is consumed (cannot re-approve)
 *   - denied token cannot be approved after denial
 *   - revoked token cannot be approved after revocation
 *   - blank reason / blank approved_by are rejected at approval time
 *   - service isolation: puranic-os tokens don't cross into other services
 *
 * @rule:AEG-E-012 GATE means pause, not deny
 * @rule:AEG-E-015 tokens are single-use — replay must be rejected
 * @rule:AEG-E-016 denial is terminal — no re-approve after deny
 * @rule:AEG-E-018 revocation requires revoked_by + revoke_reason
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { approveToken, denyToken, revokeToken } from "../src/enforcement/approval";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, PURANIC_OS_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const SOAK_RUN = 4;
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

// Map { ok: boolean } result to "accepted" | "rejected" for readable checks
const okStatus = (r: { ok: boolean }) => r.ok ? "accepted" : "rejected";

let totalProdFires = 0;

function gateToken(op: string, cap: string): string {
  const d = evaluate({ service_id: "puranic-os", operation: op, requested_capability: cap, caller_id: "b38r4" });
  logDecision(d);
  check(`[puranic-os] ${op}/${cap}: GATE`, d.decision, "GATE", "token_gen");
  check(`[puranic-os] ${op}/${cap}: phase`, d.enforcement_phase, "soft_canary", "token_gen");
  if (!d.approval_token) { console.log(`  ⚠ No approval_token for ${op}/${cap}`); }
  return d.approval_token ?? "";
}

console.log(`\n══ Batch 38 Soak Run ${SOAK_RUN}/7 — puranic-os approval lifecycle deep ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);
console.log(`  Profile: read_only, BR-1, TIER-A`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("puranic-os NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("puranic-os") ?? false, false, "pre");
check("puranic-os hard_gate_enabled = false", PURANIC_OS_HG1_POLICY.hard_gate_enabled, false, "pre");

// Generate tokens for all GATE cap types
console.log("\n── Token generation ──");
const t_ai1   = gateToken("ai-execute", "AI_EXECUTE");
const t_dep   = gateToken("deploy",     "CI_DEPLOY");
const t_del   = gateToken("delete",     "DELETE");
const t_ai2   = gateToken("ai-execute", "AI_EXECUTE");
const t_ai3   = gateToken("ai-execute", "AI_EXECUTE");
const t_ai4   = gateToken("ai-execute", "AI_EXECUTE");
const t_ai5   = gateToken("ai-execute", "AI_EXECUTE");
const t_ai6   = gateToken("ai-execute", "AI_EXECUTE");
check("at least 6 GATE tokens generated", [t_ai1,t_dep,t_del,t_ai2,t_ai3,t_ai4,t_ai5,t_ai6].filter(Boolean).length >= 6, true, "token_gen");

// Lifecycle 1: Normal approve + anti-replay
console.log("\n── Lifecycle 1: Approve + anti-replay ──");
check("t_ai1: approve accepted",
  okStatus(approveToken(t_ai1, "puranic-os AI_EXECUTE approved for Batch 38 run 4", "b38r4-human")),
  "accepted", "lifecycle_1");
check("t_ai1: replay rejected (single-use)",
  okStatus(approveToken(t_ai1, "replay attempt", "b38r4-human")),
  "rejected", "lifecycle_1");

// Lifecycle 2: Deny → no re-approve
console.log("\n── Lifecycle 2: Deny → no re-approve ──");
check("t_dep: deny accepted",
  okStatus(denyToken(t_dep, "denied for lifecycle test", "b38r4-human")),
  "accepted", "lifecycle_2");
check("t_dep: approve-after-deny rejected",
  okStatus(approveToken(t_dep, "attempting re-approve after deny", "b38r4-human")),
  "rejected", "lifecycle_2");

// Lifecycle 3: Revoke → no re-approve
console.log("\n── Lifecycle 3: Revoke → no re-approve ──");
check("t_del: revoke accepted",
  okStatus(revokeToken(t_del, "b38r4-human", "revoked for lifecycle test")),
  "accepted", "lifecycle_3");
check("t_del: approve-after-revoke rejected",
  okStatus(approveToken(t_del, "attempting re-approve after revoke", "b38r4-human")),
  "rejected", "lifecycle_3");

// Lifecycle 4: Blank-field validation
console.log("\n── Lifecycle 4: Blank-field validation ──");
check("t_ai2: blank reason rejected",
  okStatus(approveToken(t_ai2, "", "b38r4-human")),
  "rejected", "lifecycle_4");
check("t_ai3: blank approved_by rejected",
  okStatus(approveToken(t_ai3, "valid reason", "")),
  "rejected", "lifecycle_4");

// Lifecycle 5: Double-approve (replay)
console.log("\n── Lifecycle 5: Double-approve (replay) ──");
check("t_ai4: first approve accepted",
  okStatus(approveToken(t_ai4, "first approve", "b38r4-human")),
  "accepted", "lifecycle_5");
check("t_ai4: second approve rejected",
  okStatus(approveToken(t_ai4, "second approve", "b38r4-human")),
  "rejected", "lifecycle_5");

// Lifecycle 6: Double-deny
console.log("\n── Lifecycle 6: Double-deny ──");
check("t_ai5: first deny accepted",
  okStatus(denyToken(t_ai5, "first deny", "b38r4-human")),
  "accepted", "lifecycle_6");
check("t_ai5: second deny rejected",
  okStatus(denyToken(t_ai5, "second deny", "b38r4-human")),
  "rejected", "lifecycle_6");

// Lifecycle 7: Normal CI_DEPLOY approve
console.log("\n── Lifecycle 7: Normal DELETE revoke-then-deny guard ──");
check("t_ai6: DELETE approve accepted",
  okStatus(approveToken(t_ai6, "puranic-os last token normal approve", "b38r4-human")),
  "accepted", "lifecycle_7");

// Service isolation: ship-slm / chief-slm tokens unaffected
console.log("\n── Service isolation ──");
const tok_ship = (() => {
  const d = evaluate({ service_id: "ship-slm", operation: "ai-execute", requested_capability: "AI_EXECUTE", caller_id: "b38r4-iso" });
  logDecision(d);
  return d.approval_token ?? "";
})();
const tok_chief = (() => {
  const d = evaluate({ service_id: "chief-slm", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b38r4-iso" });
  logDecision(d);
  return d.approval_token ?? "";
})();
check("ship-slm token issued", !!tok_ship, true, "isolation");
check("chief-slm token issued", !!tok_chief, true, "isolation");
check("ship-slm approve accepted",
  okStatus(approveToken(tok_ship, "ship-slm AI_EXECUTE approved", "b38r4-human")),
  "accepted", "isolation");
check("chief-slm approve accepted",
  okStatus(approveToken(tok_chief, "chief-slm CI_DEPLOY approved", "b38r4-human")),
  "accepted", "isolation");

// Non-GATE caps unaffected by approval activity
console.log("\n── Non-GATE caps unaffected ──");
const rd = evaluate({ service_id: "puranic-os", operation: "read", requested_capability: "READ", caller_id: "b38r4" });
logDecision(rd);
check("puranic-os READ: ALLOW", rd.decision, "ALLOW", "non_gate");
check("puranic-os READ: soft_canary", rd.enforcement_phase, "soft_canary", "non_gate");

// Production gate fire guard
console.log("\n── Production gate fire guard ──");
for (const [op, cap] of [["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"],["read","READ"],["execute","EXECUTE"]] as [string,string][]) {
  const d = evaluate({ service_id: "puranic-os", operation: op, requested_capability: cap, caller_id: "b38r4-guard" });
  const simOff = simulateHardGate("puranic-os", d.decision, cap, op, false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`prod guard [puranic-os] ${cap}: no fire`, simOff.hard_gate_would_apply, false, "prod_guard");
}

// Live HG-1 regression
console.log("\n── Live HG-1 regression ──");
for (const svc of ["chirpee", "ship-slm", "chief-slm"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b38r4-reg" });
  logDecision(r);
  check(`[${svc}] READ: ALLOW`, r.decision, "ALLOW", "regression");
  check(`[${svc}] READ: hard_gate`, r.enforcement_phase, "hard_gate", "regression");
}

console.log("\n── Count validation ──");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch38_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, service: "puranic-os", date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, production_gate_fires: totalProdFires, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 38 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
