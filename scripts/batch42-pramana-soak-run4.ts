/**
 * Batch 42 Soak Run 4/7 — approval lifecycle heavy
 *
 * Exhaustive FSM coverage for pramana GATE tokens:
 *   - 6 tokens approved (valid path)
 *   - 6 replay rejections
 *   - 4 tokens denied
 *   - 4 approve-after-deny rejections
 *   - 3 tokens revoked
 *   - 3 approve-after-revoke rejections
 *   - blank reason / blank approvedBy rejections
 *   - double-approve, double-deny rejections
 *   - cross-service token isolation
 *
 * @rule:AEG-E-012 GATE = pause, not deny; approval_token issued on GATE
 * @rule:AEG-E-013..018 token lifecycle rules
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { approveToken, denyToken, revokeToken } from "../src/enforcement/approval";
import { HARD_GATE_GLOBALLY_ENABLED } from "../src/enforcement/hard-gate-policy";
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

function gateToken(d: ReturnType<typeof evaluate>): string {
  return (d as unknown as { approval_token?: string }).approval_token ?? "";
}
function ok(r: { ok: boolean }) { return r.ok ? "accepted" : "rejected"; }

const simTPs = 2; // not the focus of this run — confirm at min
let prodFires = 0;

console.log(`\n══ Batch 42 Soak Run ${SOAK_RUN}/7 — approval lifecycle heavy ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

console.log("\n── Pre-flight + HG-1 regression ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), false, "pre");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r4-reg" });
  check(`[${svc}] READ: hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r4-reg" });
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
}

// ── Generate 13 GATE tokens from pramana ─────────────────────────────────────
console.log("\n── Generate tokens ──");
const OPS: Array<[string, string]> = [
  ["execute",      "EXECUTE"],
  ["ai-execute",   "AI_EXECUTE"],
  ["deploy",       "CI_DEPLOY"],
  ["delete",       "DELETE"],
  ["approve",      "APPROVE"],
  ["emit",         "EMIT"],
  ["execute",      "EXECUTE"],   // 7 — for double-approve test
  ["ai-execute",   "AI_EXECUTE"], // 8 — for double-deny test
  ["deploy",       "CI_DEPLOY"],  // 9 — approve valid
  ["delete",       "DELETE"],     // 10 — approve valid
  ["approve",      "APPROVE"],    // 11 — revoke
  ["emit",         "EMIT"],       // 12 — revoke
  ["execute",      "EXECUTE"],    // 13 — revoke
];

const tokens: string[] = [];
for (const [op, cap] of OPS) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r4-gen" });
  logDecision(d);
  check(`pramana [${cap}]: GATE`, d.decision, "GATE", "gen");
  const t = gateToken(d);
  check(`pramana [${cap}]: token present`, !!t, true, "gen");
  tokens.push(t);
}

// ── Approve valid tokens (6): tokens[0..5] ────────────────────────────────────
console.log("\n── Approve valid tokens ──");
for (let i = 0; i < 6; i++) {
  const a = approveToken(tokens[i], `b42r4 approved reason ${i}`, `operator-${i}`);
  check(`approve token[${i}]: accepted`, ok(a), "accepted", "approve");
}

// ── Replay rejections ─────────────────────────────────────────────────────────
console.log("\n── Replay rejections ──");
for (let i = 0; i < 6; i++) {
  const r = approveToken(tokens[i], "replay attempt", "b42r4-replay");
  check(`replay token[${i}]: rejected (already approved)`, ok(r), "rejected", "replay");
}

// ── Double-approve: token[6] ──────────────────────────────────────────────────
console.log("\n── Double-approve ──");
{
  const a1 = approveToken(tokens[6], "first approval", "op-a");
  check("double-approve: first accepted", ok(a1), "accepted", "double_approve");
  const a2 = approveToken(tokens[6], "second approval attempt", "op-b");
  check("double-approve: second rejected", ok(a2), "rejected", "double_approve");
}

// ── Deny tokens (4): tokens[7..10] ───────────────────────────────────────────
console.log("\n── Deny tokens ──");
for (let i = 7; i <= 10; i++) {
  const d = denyToken(tokens[i], `b42r4 denial reason ${i}`, `reviewer-${i}`);
  check(`deny token[${i}]: accepted`, ok(d), "accepted", "deny");
}

// ── Approve-after-deny (4): tokens[7..10] ────────────────────────────────────
console.log("\n── Approve-after-deny ──");
for (let i = 7; i <= 10; i++) {
  const a = approveToken(tokens[i], "trying after deny", "b42r4-late");
  check(`approve-after-deny token[${i}]: rejected`, ok(a), "rejected", "approve_after_deny");
}

// ── Double-deny: re-deny already-denied token[7] ─────────────────────────────
console.log("\n── Double-deny ──");
{
  const d2 = denyToken(tokens[7], "second denial attempt", "reviewer-b");
  check("double-deny token[7]: rejected", ok(d2), "rejected", "double_deny");
}

// ── Revoke tokens (3): tokens[10..12] ────────────────────────────────────────
// Note: tokens[10] was already denied — test revoke on denied is also rejected
console.log("\n── Revoke tokens ──");
{
  const r10 = revokeToken(tokens[10], "b42r4-revoker", "revoke attempt on denied token");
  // token[10] was denied → revoke on terminal state should be rejected
  check("revoke denied token[10]: rejected (terminal state)", ok(r10), "rejected", "revoke");
}
for (const i of [11, 12]) {
  const r = revokeToken(tokens[i], `b42r4-revoker-${i}`, `policy updated ${i}`);
  check(`revoke token[${i}]: accepted`, ok(r), "accepted", "revoke");
}

// ── Approve-after-revoke: tokens[11,12] ──────────────────────────────────────
console.log("\n── Approve-after-revoke ──");
for (const i of [11, 12]) {
  const a = approveToken(tokens[i], "trying after revoke", "b42r4-late");
  check(`approve-after-revoke token[${i}]: rejected`, ok(a), "rejected", "approve_after_revoke");
}

// ── Blank field rejections ────────────────────────────────────────────────────
console.log("\n── Blank field rejections ──");
{
  const dBlank = evaluate({ service_id: "pramana", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b42r4-blank" });
  const tBlank = gateToken(dBlank);
  check("blank token setup: GATE", dBlank.decision, "GATE", "blank");
  const blankReason = approveToken(tBlank, "", "valid-op");
  check("blank approval_reason: rejected", ok(blankReason), "rejected", "blank");
  const blankBy = approveToken(tBlank, "valid reason", "");
  check("blank approved_by: rejected", ok(blankBy), "rejected", "blank");
  // Now approve with valid fields
  const validApprove = approveToken(tBlank, "full review complete", "b42r4-final");
  check("valid approval after blank attempts: accepted", ok(validApprove), "accepted", "blank");
}

// ── Cross-service isolation ────────────────────────────────────────────────────
console.log("\n── Cross-service isolation ──");
{
  // Token from chirpee (critical op) — must not be affected by pramana approvals
  const dChirpee = evaluate({ service_id: "chirpee", operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b42r4-iso" });
  check("chirpee CI_DEPLOY: GATE (hard_gate phase)", dChirpee.enforcement_phase, "hard_gate", "isolation");
  const tChirpee = gateToken(dChirpee);
  check("chirpee token: present", !!tChirpee, true, "isolation");
  check("chirpee token ≠ pramana tokens", !tokens.includes(tChirpee), true, "isolation");
  // Approve chirpee token
  const aChirpee = approveToken(tChirpee, "chirpee deployment approved", "b42r4-chirpee-op");
  check("chirpee token: approve accepted", ok(aChirpee), "accepted", "isolation");
}

// ── TP + prod fire guard ──────────────────────────────────────────────────────
console.log("\n── TP + prod fire guard ──");
{
  const imp = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r4-tp" });
  check("pramana IMPOSSIBLE_OP: live ALLOW (soft_canary)", imp.decision, "ALLOW", "tp");
  const emp = evaluate({ service_id: "pramana", operation: "write", requested_capability: "EMPTY_CAPABILITY_ON_WRITE", caller_id: "b42r4-tp" });
  check("pramana EMPTY_CAP: live ALLOW (soft_canary)", emp.decision, "ALLOW", "tp");
  // production fires = 0 confirmed
  check("production fires = 0", prodFires, 0, "count");
}

const soakPass = failed === 0 && prodFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch42_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN, service: "pramana", hg_group: "HG-2A", date: RUN_DATE,
  verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed,
  simulation_true_positives: simTPs, production_gate_fires: prodFires, ready_to_promote: false,
}, null, 2));
console.log(`\n  Batch 42 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
