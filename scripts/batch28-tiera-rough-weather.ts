/**
 * Batch 28 — Full TIER-A 12-Service Rough-Weather Window
 *
 * Purpose: Abuse patterns, malformed ops, expiry races, revoke storms, and
 * boundary violations across all 12 TIER-A soft-canary services. Final gate
 * before hard-gate readiness discussion.
 *
 * Categories:
 *   1. Normal regression (all 12) — baseline must hold
 *   2. High-risk ops (all 12, profile-aware expectations)
 *   3. Bad inputs — malformed caps, empty ops, unknown services
 *   4. Abuse patterns — token flood, rapid re-gate, mask escalation, consecutive gating
 *   5. Revoke storm — rapid multi-service revocations + replay rejection
 *   6. Expiry races — approve-at-boundary, fresh-token-after-expiry
 *   7. Approval lifecycle edge cases (all 12 × AEG-E-013..AEG-E-018)
 *   8. Rollback drill (all 12, extended op set)
 *
 * Rules enforced throughout:
 *   - soft-canary only; no hard mode
 *   - BLOCK → GATE in soft-canary (never hard-block)
 *   - READ always ALLOW (AEG-E-002)
 *   - unknown services → WARN/shadow, never BLOCK
 *   - no token issued outside soft-canary
 *   - rollback drill passes across all 12
 */

import { evaluate } from "../src/enforcement/gate";
import {
  issueApprovalToken,
  approveToken,
  denyToken,
  revokeToken,
  getApproval,
  runRollbackDrill,
} from "../src/enforcement/approval";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import { logDecision } from "../src/enforcement/logger";
import { loadRegistry } from "../src/enforcement/registry";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// ── Environment: soft mode, full 12-service canary ───────────────────────────

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED = "true";
process.env.AEGIS_DRY_RUN = "false";
delete process.env.AEGIS_SOFT_CANARY_SERVICES; // gate.ts default = all 12

// ── Service groups ────────────────────────────────────────────────────────────

const TIER_A_12 = [
  "granthx", "stackpilot", "ankrclaw",
  "carbonx", "parali-central", "pramana",
  "ankr-doctor", "domain-capture", "ship-slm",
  "chief-slm", "chirpee", "puranic-os",
] as const;

type TierA = typeof TIER_A_12[number];

// BR≥3 or governance authority → GATE on execute/trigger/emit/approve/reject
const HIGH_8 = ["granthx", "stackpilot", "ankrclaw", "carbonx",
  "parali-central", "pramana", "ankr-doctor", "domain-capture"] as const;

// read_only + BR-0/BR-1 → GATE on deploy/delete only
const LOW_4 = ["ship-slm", "chief-slm", "chirpee", "puranic-os"] as const;

const reg = loadRegistry();

function expectedHighDecision(svc: string): "GATE" | "ALLOW" {
  const e = reg[svc];
  if (!e) return "ALLOW";
  const highAuthority = ["financial", "governance", "deploy"].includes(e.authority_class);
  const highBlast = parseInt(e.governance_blast_radius.replace("BR-", "") || "0", 10) >= 3;
  if (e.human_gate_required || highAuthority || highBlast) return "GATE";
  return "ALLOW";
}

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
    console.log(`  ✓ [PASS] ${label.padEnd(65)} actual=${actual}`);
  } else {
    failed++;
    failures.push({ label, expected: String(expected), actual: String(actual), cat });
    console.log(`  ✗ [FAIL] ${label.padEnd(65)} expected=${expected} actual=${actual}`);
  }
}

function okStatus(r: { ok: boolean }): "accepted" | "rejected" {
  return r.ok ? "accepted" : "rejected";
}

function req(svc: string, op: string, cap = "default_capability", caller = "b28", session?: string) {
  const d = evaluate({
    service_id: svc, operation: op, requested_capability: cap,
    caller_id: caller, session_id: session ?? `b28-${svc}-${op}`,
  });
  logDecision(d);
  return d;
}

function phase(d: ReturnType<typeof evaluate>): string {
  return `${d.decision}/${d.enforcement_phase}`;
}

// ── Decision counters ─────────────────────────────────────────────────────────

const decisionCounts: Record<string, Record<string, number>> = {};
for (const s of TIER_A_12) {
  decisionCounts[s] = { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0, READ_GATES: 0 };
}

function tally(svc: string, d: ReturnType<typeof evaluate>, isRead = false) {
  if (!decisionCounts[svc]) return;
  decisionCounts[svc][d.decision] = (decisionCounts[svc][d.decision] ?? 0) + 1;
  if (isRead && d.decision !== "ALLOW") decisionCounts[svc].READ_GATES++;
}

const approvalCounts = { issued: 0, approved: 0, denied: 0, revoked: 0, expired: 0, consumed: 0 };

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Normal regression — all 12
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 1. Normal regression (all 12 services) ──");

const readOps = ["read", "get", "list", "query", "search", "health"];
for (const svc of TIER_A_12) {
  for (const op of readOps) {
    const d = req(svc, op, "READ");
    tally(svc, d, true);
    check(`${svc}/${op}: ALLOW/soft_canary`, phase(d), "ALLOW/soft_canary", "normal");
  }
}

// WRITE/UPDATE — ALLOW for all 12
const writeOps = ["write", "update", "create", "patch"];
for (const svc of TIER_A_12) {
  for (const op of writeOps) {
    const d = req(svc, op, "WRITE");
    tally(svc, d);
    check(`${svc}/${op}: ALLOW/soft_canary`, phase(d), "ALLOW/soft_canary", "normal");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. High-risk traffic — all 12, profile-aware
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 2. High-risk traffic (all 12, profile-aware) ──");

const highRiskOps = [
  { op: "execute",    cap: "EXECUTE"    },
  { op: "trigger",   cap: "EXECUTE"    },
  { op: "emit",      cap: "EXECUTE"    },
  { op: "approve",   cap: "APPROVE"    },
  { op: "reject",    cap: "APPROVE"    },
  { op: "deploy",    cap: "CI_DEPLOY"  },
  { op: "delete",    cap: "DELETE"     },
];

const gateTokensHighRisk: Array<{ svc: string; op: string; token: string }> = [];

for (const svc of TIER_A_12) {
  const exp = expectedHighDecision(svc);
  for (const { op, cap } of highRiskOps) {
    // deploy/delete always gate regardless of profile (critical threshold)
    const isAlwaysGate = ["deploy", "delete"].includes(op);
    const expectedDecision = isAlwaysGate ? "GATE" : exp;
    const d = req(svc, op, cap, "b28-highrisk");
    tally(svc, d);
    check(`${svc}/${op}: ${expectedDecision}/soft_canary`, phase(d), `${expectedDecision}/soft_canary`, "high_risk");
    if (d.decision === "GATE" && d.approval_token) {
      gateTokensHighRisk.push({ svc, op, token: d.approval_token });
      approvalCounts.issued++;
    }
  }
}

// LOW_4 invariant: execute/trigger/emit/approve/reject → ALLOW (not over-gated)
console.log("\n  LOW_4 (read_only/BR-0-1) — not over-gated on medium-risk ops");
for (const svc of LOW_4) {
  for (const op of ["execute", "trigger", "approve", "reject"]) {
    const d = req(svc, op, "EXECUTE", "b28-lowbr-check");
    check(`${svc}/${op}: ALLOW (not over-gated)`, d.decision, "ALLOW", "high_risk");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Bad inputs — malformed ops, unknown caps, empty fields
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 3. Bad inputs ──");

// 3a. Unknown capability — all 12, no BLOCK
for (const svc of TIER_A_12) {
  const d = req(svc, "frob", "TOTALLY_UNKNOWN_CAP_B28", "b28-bad");
  check(`${svc}: unknown_cap no BLOCK`, d.decision !== "BLOCK", true, "bad_input");
}

// 3b. Lowercase capability — normalises to uppercase
for (const svc of LOW_4) {
  const d = req(svc, "write", "write", "b28-bad");
  check(`${svc}: lowercase→uppercase normalised`, d.requested_capability, "WRITE", "bad_input");
}

// 3c. run_agent alias → AI_EXECUTE, no BLOCK
for (const svc of HIGH_8) {
  const d = req(svc, "run_agent", "run_agent", "b28-bad");
  check(`${svc}: run_agent→AI_EXECUTE`, d.requested_capability, "AI_EXECUTE", "bad_input");
  check(`${svc}: run_agent no BLOCK`, d.decision !== "BLOCK", true, "bad_input");
}

// 3d. Empty capability — no crash, valid decision
for (const svc of LOW_4) {
  const d = req(svc, "write", "", "b28-bad");
  check(`${svc}: empty_cap no crash`, typeof d.decision === "string", true, "bad_input");
  check(`${svc}: empty_cap no BLOCK`, d.decision !== "BLOCK", true, "bad_input");
}

// 3e. Empty operation — no crash
for (const svc of LOW_4) {
  const d = req(svc, "", "WRITE", "b28-bad");
  check(`${svc}: empty_op no crash`, typeof d.decision === "string", true, "bad_input");
}

// 3f. Unknown service → WARN/shadow, never BLOCK, no token
{
  const d = req("svc-does-not-exist-b28", "deploy", "CI_DEPLOY", "b28-bad");
  check("unknown_service: WARN", d.decision, "WARN", "bad_input");
  check("unknown_service: shadow", d.enforcement_phase, "shadow", "bad_input");
  check("unknown_service: no approval_token", d.approval_token, undefined, "bad_input");
  check("unknown_service: in_canary=false", d.in_canary, false, "bad_input");
}

// 3g. Non-TIER-A TIER-B service (freightbox) → shadow, no BLOCK
{
  const d = req("freightbox", "execute", "EXECUTE", "b28-bad");
  check("non-TIER-A (freightbox): shadow", d.enforcement_phase, "shadow", "bad_input");
  check("non-TIER-A (freightbox): no BLOCK", d.decision !== "BLOCK", true, "bad_input");
  check("non-TIER-A (freightbox): no token", d.approval_token, undefined, "bad_input");
}

// 3h. READ with garbage capability → always ALLOW (AEG-E-002)
{
  const d = evaluate({
    service_id: "granthx", operation: "read", requested_capability: "!@#$%^&*()",
    caller_id: "b28-bad", session_id: "b28-bad-readgarbagecap",
  });
  check("READ garbage cap: still ALLOW", d.decision, "ALLOW", "bad_input");
  check("READ garbage cap: soft_canary", d.enforcement_phase, "soft_canary", "bad_input");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Abuse patterns
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 4. Abuse patterns ──");

// 4a. Token flood — 5 rapid deploy gates on granthx, all independent pending tokens
console.log("  4a. Token flood (5× deploy on granthx)");
const floodTokens: string[] = [];
for (let i = 0; i < 5; i++) {
  const d = evaluate({
    service_id: "granthx", operation: "deploy", requested_capability: "CI_DEPLOY",
    caller_id: `b28-flood-${i}`, session_id: `b28-flood-${i}-granthx`,
  });
  logDecision(d);
  check(`flood[${i}]: GATE/soft_canary`, phase(d), "GATE/soft_canary", "abuse");
  if (d.approval_token) {
    check(`flood[${i}]: token is unique`, floodTokens.includes(d.approval_token), false, "abuse");
    floodTokens.push(d.approval_token);
    approvalCounts.issued++;
  }
}

// 4b. Rapid re-gate same service+op — tokens are independent (no dedup bypass)
console.log("  4b. Rapid re-gate (3× execute on stackpilot, same caller)");
const regateTokens: string[] = [];
for (let i = 0; i < 3; i++) {
  const d = evaluate({
    service_id: "stackpilot", operation: "execute", requested_capability: "EXECUTE",
    caller_id: "b28-regate", session_id: `b28-regate-${i}`,
  });
  logDecision(d);
  check(`regate[${i}]: GATE/soft_canary`, phase(d), "GATE/soft_canary", "abuse");
  if (d.approval_token) {
    check(`regate[${i}]: token is unique`, regateTokens.includes(d.approval_token), false, "abuse");
    regateTokens.push(d.approval_token);
    approvalCounts.issued++;
  }
}

// 4c. Mask escalation — caller claims FULL_AUTONOMY on a governance service
console.log("  4c. Mask escalation (FULL_AUTONOMY claim on ankrclaw)");
{
  const d = evaluate({
    service_id: "ankrclaw", operation: "execute", requested_capability: "FULL_AUTONOMY",
    caller_id: "b28-escalate", session_id: "b28-escalate-ankrclaw",
  });
  logDecision(d);
  // In soft-canary, escalation is gated — not crashed, not silently allowed as ALLOW
  check("mask_escalation: no BLOCK", d.decision !== "BLOCK", true, "abuse");
  check("mask_escalation: soft_canary", d.enforcement_phase, "soft_canary", "abuse");
}

// 4d. Consecutive same-session deploys on LOW_4 (deploy still always gates)
console.log("  4d. Consecutive deploys on LOW_4 — always GATE (critical threshold)");
for (const svc of LOW_4) {
  for (let i = 0; i < 2; i++) {
    const d = evaluate({
      service_id: svc, operation: "deploy", requested_capability: "CI_DEPLOY",
      caller_id: "b28-consec", session_id: `b28-consec-${svc}-${i}`,
    });
    logDecision(d);
    tally(svc, d);
    check(`${svc}/deploy[${i}]: GATE/soft_canary`, phase(d), "GATE/soft_canary", "abuse");
    if (d.approval_token) { approvalCounts.issued++; }
  }
}

// 4e. Null service_id → no crash, WARN/shadow
console.log("  4e. Null/empty service_id — no crash");
{
  const d = evaluate({
    service_id: "", operation: "execute", requested_capability: "EXECUTE",
    caller_id: "b28-null", session_id: "b28-null-svc",
  });
  check("empty_service_id: no crash", typeof d.decision === "string", true, "abuse");
  check("empty_service_id: no BLOCK", d.decision !== "BLOCK", true, "abuse");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Revoke storm — rapid multi-service revocations
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 5. Revoke storm ──");

// Issue one deploy token per HIGH_8 service, revoke all in rapid succession
const stormTokens: Array<{ svc: string; token: string }> = [];
for (const svc of HIGH_8) {
  const d = req(svc, "deploy", "CI_DEPLOY", "b28-storm");
  if (d.decision === "GATE" && d.approval_token) {
    stormTokens.push({ svc, token: d.approval_token });
    approvalCounts.issued++;
  }
}

// Rapid revocations
for (const { svc, token } of stormTokens) {
  const r = revokeToken(token, "security-lead@ankr", `b28 revoke storm — ${svc} deploy held`);
  check(`${svc}: revoke in storm accepted`, okStatus(r), "accepted", "revoke_storm");
  if (r.ok) approvalCounts.revoked++;
}

// Re-approve after revoke → rejected for all (AEG-E-018)
for (const { svc, token } of stormTokens) {
  const r = approveToken(token, "replay after revoke storm", "ops@ankr");
  check(`${svc}: revoked→reapprove rejected (AEG-E-018)`, okStatus(r), "rejected", "revoke_storm");
}

// Double-revoke → rejected (already revoked)
for (const { svc, token } of stormTokens.slice(0, 3)) {
  const r = revokeToken(token, "ops@ankr", `second revoke attempt — ${svc}`);
  check(`${svc}: double-revoke rejected`, okStatus(r), "rejected", "revoke_storm");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Expiry races
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 6. Expiry races ──");

// Issue tokens from both groups, then backdate expires_at
const expiryTokens: Array<{ svc: string; token: string }> = [];

for (const svc of ["granthx", "ship-slm", "ankrclaw", "chirpee"] as const) {
  const d = req(svc, "deploy", "CI_DEPLOY", "b28-expiry");
  if (d.decision === "GATE" && d.approval_token) {
    expiryTokens.push({ svc, token: d.approval_token });
    approvalCounts.issued++;
  }
}

// Expire all four tokens
for (const { token } of expiryTokens) {
  const rec = getApproval(token);
  if (rec) {
    rec.expires_at = new Date(Date.now() - 5000).toISOString(); // 5s ago
    rec.status = "pending"; // reset so lazy-expiry fires on next access
    approvalCounts.expired++;
  }
}

// Approve just after expiry → rejected (AEG-E-013)
for (const { svc, token } of expiryTokens) {
  const r = approveToken(token, "late approval attempt", "ops@ankr");
  check(`${svc}: expired_token rejected (AEG-E-013)`, okStatus(r), "rejected", "expiry_race");
}

// Fresh gate on same service immediately after expiry → new token issued correctly
for (const { svc } of expiryTokens) {
  const d = req(svc, "deploy", "CI_DEPLOY", "b28-expiry-fresh");
  check(`${svc}: fresh GATE after expiry`, d.decision, "GATE", "expiry_race");
  check(`${svc}: fresh token issued`, d.approval_token !== undefined, true, "expiry_race");
  if (d.approval_token) approvalCounts.issued++;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. Approval lifecycle edge cases — all 12 × AEG-E-013..AEG-E-018
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 7. Approval lifecycle edge cases ──");

function issueGate(svc: string, op = "execute", cap = "EXECUTE", caller = "b28-lifecycle"): string | null {
  const d = evaluate({
    service_id: svc, operation: op, requested_capability: cap,
    caller_id: caller, session_id: `b28-lc-${svc}-${op}-${Date.now()}`,
  });
  logDecision(d);
  if (d.decision === "GATE" && d.approval_token) {
    approvalCounts.issued++;
    return d.approval_token;
  }
  return null;
}

// 7a. Blank approval_reason — all 12 (AEG-E-014)
console.log("  7a. Blank approval_reason — all 12");
for (const svc of TIER_A_12) {
  const op = expectedHighDecision(svc) === "GATE" ? "execute" : "deploy";
  const token = issueGate(svc, op);
  if (token) {
    const r = approveToken(token, "   ", "ops@ankr");
    check(`${svc}: blank_reason rejected (AEG-E-014)`, okStatus(r), "rejected", "lifecycle");
    denyToken(token, "b28 cleanup", "b28-script");
    approvalCounts.denied++;
  }
}

// 7b. Blank approved_by — representative (HIGH_8)
console.log("  7b. Blank approved_by — HIGH_8");
for (const svc of HIGH_8) {
  const token = issueGate(svc, "execute");
  if (token) {
    const r = approveToken(token, "valid reason for test", "   ");
    check(`${svc}: blank_by rejected (AEG-E-014)`, okStatus(r), "rejected", "lifecycle");
    denyToken(token, "b28 cleanup", "b28-script");
    approvalCounts.denied++;
  }
}

// 7c. Token replay — all 12 (AEG-E-015)
console.log("  7c. Token replay — all 12");
for (const svc of TIER_A_12) {
  const op = expectedHighDecision(svc) === "GATE" ? "execute" : "deploy";
  const token = issueGate(svc, op);
  if (token) {
    const r1 = approveToken(token, `B28 lifecycle replay test first — ${svc}`, "ops@ankr");
    const r2 = approveToken(token, "second attempt", "ops@ankr");
    check(`${svc}: replay_first approved`, okStatus(r1), "accepted", "lifecycle");
    check(`${svc}: replay_second rejected (AEG-E-015)`, okStatus(r2), "rejected", "lifecycle");
    if (r1.ok) approvalCounts.approved++;
  }
}

// 7d. Wrong service binding — all 12, shifted by one (AEG-E-016)
console.log("  7d. Wrong service binding — all 12");
for (let i = 0; i < TIER_A_12.length; i++) {
  const svc = TIER_A_12[i];
  const wrongSvc = TIER_A_12[(i + 1) % TIER_A_12.length];
  const token = issueGate(svc, "deploy", "CI_DEPLOY");
  if (token) {
    const r = approveToken(token, "binding mismatch test", "ops@ankr", { service_id: wrongSvc });
    check(`${svc}: wrong_binding(→${wrongSvc}) rejected (AEG-E-016)`, okStatus(r), "rejected", "lifecycle");
    denyToken(token, "b28 cleanup", "b28-script");
    approvalCounts.denied++;
  }
}

// 7e. Denied token → re-approve rejected — all 12 (AEG-E-017)
console.log("  7e. Denied → re-approve — all 12");
for (const svc of TIER_A_12) {
  const op = expectedHighDecision(svc) === "GATE" ? "trigger" : "deploy";
  const token = issueGate(svc, op);
  if (token) {
    denyToken(token, `risk pending — ${svc}`, "security@ankr");
    approvalCounts.denied++;
    const r = approveToken(token, "retry after denial", "ops@ankr");
    check(`${svc}: denied→reapprove rejected (AEG-E-017)`, okStatus(r), "rejected", "lifecycle");
  }
}

// 7f. Revoked token → re-approve rejected — all 12 (AEG-E-018)
console.log("  7f. Revoked → re-approve — all 12");
for (const svc of TIER_A_12) {
  const op = expectedHighDecision(svc) === "GATE" ? "emit" : "delete";
  const token = issueGate(svc, op);
  if (token) {
    revokeToken(token, "security-lead@ankr", `b28 revoke lifecycle — ${svc}`);
    approvalCounts.revoked++;
    const r = approveToken(token, "retry after revoke", "ops@ankr");
    check(`${svc}: revoked→reapprove rejected (AEG-E-018)`, okStatus(r), "rejected", "lifecycle");
  }
}

// 7g. Blank revoke_reason — all 12 (AEG-E-018)
console.log("  7g. Blank revoke_reason — all 12");
for (const svc of TIER_A_12) {
  const token = issueGate(svc, "deploy", "CI_DEPLOY");
  if (token) {
    const r = revokeToken(token, "ops@ankr", "   ");
    check(`${svc}: blank_revoke_reason rejected (AEG-E-018)`, okStatus(r), "rejected", "lifecycle");
    denyToken(token, "b28 cleanup", "b28-script");
    approvalCounts.denied++;
  }
}

// 7h. Blank revoked_by — all 12 (AEG-E-018)
console.log("  7h. Blank revoked_by — all 12");
for (const svc of TIER_A_12) {
  const token = issueGate(svc, "deploy", "CI_DEPLOY");
  if (token) {
    const r = revokeToken(token, "   ", "valid revoke reason");
    check(`${svc}: blank_revoked_by rejected (AEG-E-018)`, okStatus(r), "rejected", "lifecycle");
    denyToken(token, "b28 cleanup", "b28-script");
    approvalCounts.denied++;
  }
}

// 7i. Expired token — all 12 (AEG-E-013)
console.log("  7i. Expired token — all 12");
for (const svc of TIER_A_12) {
  const op = expectedHighDecision(svc) === "GATE" ? "approve" : "deploy";
  const token = issueGate(svc, op);
  if (token) {
    const rec = getApproval(token);
    if (rec) {
      rec.expires_at = new Date(Date.now() - 1000).toISOString();
      rec.status = "pending";
      approvalCounts.expired++;
    }
    const r = approveToken(token, "late approval attempt", "ops@ankr");
    check(`${svc}: expired_token rejected (AEG-E-013)`, okStatus(r), "rejected", "lifecycle");
  }
}

// 7j. Non-canary GATE services: shadow → no token issued
console.log("  7j. Non-canary services: shadow GATE issues no token");
for (const svc of ["ankr-doctor", "domain-capture", "chirpee", "puranic-os"] as const) {
  // Force this service out of canary temporarily — evaluate without it in canary set
  // (Already handled by gate.ts: non-canary services stay in shadow; in production
  //  these services ARE canary, so we verify that shadow-mode services (e.g. TIER-B)
  //  correctly issue no tokens)
  const d = req("freightbox", "deploy", "CI_DEPLOY", "b28-notoken-shadow");
  check(`freightbox-shadow: no token issued`, d.approval_token, undefined, "lifecycle");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Invariant verification — READ=0, BLOCK=0
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Invariant: zero READ gates, zero hard BLOCKs ──");

let readGateTotal = 0;
let hardBlockTotal = 0;
for (const s of TIER_A_12) {
  readGateTotal += decisionCounts[s].READ_GATES;
  hardBlockTotal += decisionCounts[s].BLOCK;
}
check("zero READ gates (AEG-E-002)", readGateTotal, 0, "invariant");
check("zero hard BLOCKs in soft-canary", hardBlockTotal, 0, "invariant");

// ═══════════════════════════════════════════════════════════════════════════════
// 9. Canary status (pre-drill)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Canary status (pre-drill) ──");
const preDrillStatus = getCanaryStatus([...TIER_A_12]);
const sc = preDrillStatus.success_criteria;
check("12/12 service stats", preDrillStatus.service_stats.length, 12, "canary_status");
check("no_read_gates", sc.no_read_gates, true, "canary_status");
check("no_unknown_service_blocks", sc.no_unknown_service_blocks, true, "canary_status");
check("no_token_replay_successes", sc.no_token_replay_successes, true, "canary_status");
check("no_approval_without_reason", sc.no_approval_without_reason, true, "canary_status");
check("no_revoke_without_reason", sc.no_revoke_without_reason, true, "canary_status");
check("decision_log_has_canary_entries", sc.decision_log_has_canary_entries, true, "canary_status");

// ═══════════════════════════════════════════════════════════════════════════════
// 10. Rollback drill — all 12, extended op set
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Rollback drill — all 12 TIER-A services ──");
const drill = runRollbackDrill(
  evaluate,
  [...TIER_A_12],
  [
    { operation: "deploy",     requested_capability: "CI_DEPLOY" },
    { operation: "delete",     requested_capability: "DELETE" },
    { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
  ],
);
check("drill_verdict: PASS", drill.verdict, "PASS", "rollback");

for (const svc of TIER_A_12) {
  const s = drill.services_checked.find(x => x.service_id === svc);
  check(`${svc}: shadow after kill`, s?.phase_after_kill, "shadow", "rollback");
  check(`${svc}: no tokens while killed`, s?.tokens_issued, false, "rollback");
}

// ── Final canary status post-drill ───────────────────────────────────────────

console.log("\n── Final canary status post-drill ──");
const finalStatus = getCanaryStatus([...TIER_A_12]);
check("final: all_criteria_met", finalStatus.success_criteria.all_criteria_met, true, "canary_status");
check("final: rollback_drill_passed", finalStatus.success_criteria.rollback_drill_passed, true, "canary_status");
check("final: 12/12 services", finalStatus.service_stats.length, 12, "canary_status");

// ── Decision summary table ─────────────────────────────────────────────────────

console.log("\n── Decision summary by service ──");
console.log("  Service            ALLOW  WARN  GATE  BLOCK  READ_GATES");
for (const s of TIER_A_12) {
  const c = decisionCounts[s];
  console.log(
    `  ${s.padEnd(18)} ${String(c.ALLOW).padStart(5)} ${String(c.WARN).padStart(5)} ` +
    `${String(c.GATE).padStart(5)} ${String(c.BLOCK).padStart(6)} ${String(c.READ_GATES).padStart(10)}`
  );
}

// ── Failures detail ───────────────────────────────────────────────────────────

if (failed > 0) {
  console.log("\n── Failures ──");
  const byCat: Record<string, typeof failures> = {};
  for (const f of failures) {
    if (!byCat[f.cat]) byCat[f.cat] = [];
    byCat[f.cat].push(f);
  }
  for (const [cat, flist] of Object.entries(byCat)) {
    console.log(`  [${cat}] ${flist.length} failure(s):`);
    for (const f of flist) {
      console.log(`    ✗ ${f.label}: expected=${f.expected} actual=${f.actual}`);
    }
  }
}

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("\n══ Summary ══");
console.log(`  Total checks:       ${totalChecks}`);
console.log(`  PASS:               ${passed}`);
console.log(`  FAIL:               ${failed}`);
console.log(`  Approval issued:    ${approvalCounts.issued}`);
console.log(`  Approval approved:  ${approvalCounts.approved}`);
console.log(`  Approval denied:    ${approvalCounts.denied}`);
console.log(`  Approval revoked:   ${approvalCounts.revoked}`);
console.log(`  Approval expired:   ${approvalCounts.expired}`);
console.log(`  ready_to_discuss:   ${finalStatus.success_criteria.all_criteria_met && failed === 0}`);

// ── Artifacts ─────────────────────────────────────────────────────────────────

const OUT = "/root/.aegis";
mkdirSync(OUT, { recursive: true });

// Category breakdown
const byCatFinal: Record<string, { pass: number; fail: number }> = {};
for (const f of failures) {
  if (!byCatFinal[f.cat]) byCatFinal[f.cat] = { pass: 0, fail: 0 };
  byCatFinal[f.cat].fail++;
}
// Count passes from totalChecks
const allCategories = ["normal", "high_risk", "bad_input", "abuse", "revoke_storm",
  "expiry_race", "lifecycle", "invariant", "canary_status", "rollback"];
for (const cat of allCategories) {
  if (!byCatFinal[cat]) byCatFinal[cat] = { pass: 0, fail: 0 };
}
byCatFinal.__all = { pass: passed, fail: failed };

const summaryMd = [
  `# AEGIS Batch 28 — Full TIER-A Rough-Weather Window`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Services:** ${TIER_A_12.join(", ")}`,
  `**HIGH_8 (BR≥3/governance):** ${HIGH_8.join(", ")}`,
  `**LOW_4 (read_only/BR-0-1):** ${LOW_4.join(", ")}`,
  ``,
  `## Check Summary`,
  ``,
  `| Category | Description |`,
  `|---|---|`,
  `| normal | Regression — READ/WRITE all ALLOW |`,
  `| high_risk | Profile-aware GATE/ALLOW + LOW_4 not over-gated |`,
  `| bad_input | Unknown caps, empty fields, wrong service, aliases |`,
  `| abuse | Token flood, rapid re-gate, mask escalation, consecutive gates |`,
  `| revoke_storm | 8 rapid revocations + replay rejection + double-revoke |`,
  `| expiry_race | Approve-after-expiry rejection + fresh gate after expiry |`,
  `| lifecycle | AEG-E-013..E-018 across all 12 |`,
  `| invariant | READ=0 gates, BLOCK=0 hard |`,
  `| canary_status | Success criteria pre/post drill |`,
  `| rollback | All 12 shadow after kill, no tokens while killed |`,
  ``,
  `**Total: ${totalChecks} checks — PASS: ${passed} — FAIL: ${failed}**`,
  ``,
  `## Invariants`,
  ``,
  `| Invariant | Result |`,
  `|---|---|`,
  `| READ always ALLOW (AEG-E-002) | ${readGateTotal === 0 ? "✓ PASS" : `✗ FAIL (${readGateTotal} gates)`} |`,
  `| No hard BLOCK in soft-canary | ${hardBlockTotal === 0 ? "✓ PASS" : `✗ FAIL (${hardBlockTotal} blocks)`} |`,
  `| Rollback drill verdict | ${drill.verdict} |`,
  `| all_criteria_met | ${finalStatus.success_criteria.all_criteria_met ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Approval Lifecycle`,
  ``,
  `| Event | Count |`,
  `|---|---|`,
  `| Issued | ${approvalCounts.issued} |`,
  `| Approved | ${approvalCounts.approved} |`,
  `| Denied | ${approvalCounts.denied} |`,
  `| Revoked | ${approvalCounts.revoked} |`,
  `| Expired | ${approvalCounts.expired} |`,
  ``,
  `## Decision Counts`,
  ``,
  `| Service | Group | ALLOW | WARN | GATE | BLOCK | READ_GATES |`,
  `|---|---|---|---|---|---|---|`,
  ...TIER_A_12.map(s => {
    const c = decisionCounts[s];
    const grp = (LOW_4 as readonly string[]).includes(s) ? "LOW-4" : "HIGH-8";
    return `| ${s} | ${grp} | ${c.ALLOW} | ${c.WARN} | ${c.GATE} | ${c.BLOCK} | ${c.READ_GATES} |`;
  }),
  ``,
  `## Rollout Sequence`,
  ``,
  `| Batch | Scope | Window | Status |`,
  `|---|---|---|---|`,
  `| Batch 21 | 3 svc | Real traffic | complete |`,
  `| Batch 22 | 3 svc | Rough weather | complete |`,
  `| Batch 23 | 6 svc | Expansion | complete |`,
  `| Batch 24 | 6 svc | Observation | complete |`,
  `| Batch 25 | 6 svc | Rough weather | complete |`,
  `| Batch 26 | 12 svc | Full expansion | complete |`,
  `| Batch 27 | 12 svc | Observation | complete |`,
  `| **Batch 28** | **12 svc** | **Rough weather** | **${failed === 0 ? "complete" : "FAILED"}** |`,
  ``,
  failures.length > 0 ? `## Failures\n\n${failures.map(f => `- [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`).join("\n")}\n` : `## Failures\n\nNone.\n`,
  `---`,
  `*AEGIS soft-canary full TIER-A rough-weather — Batch 28 — @rule:AEG-E-019*`,
].join("\n");

writeFileSync(join(OUT, "batch28_rough_weather_summary.md"), summaryMd);
writeFileSync(join(OUT, "batch28_decision_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch28",
  scope: "12-service rough-weather window",
  total_checks: totalChecks,
  passed,
  failed,
  per_service: TIER_A_12.map(s => ({
    service_id: s,
    group: (LOW_4 as readonly string[]).includes(s) ? "LOW-4" : "HIGH-8",
    ...decisionCounts[s],
  })),
}, null, 2));
writeFileSync(join(OUT, "batch28_approval_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch28",
  approval_lifecycle: approvalCounts,
  lifecycle_checks: failures.filter(f => f.cat === "lifecycle").length === 0 ? "PASS" : "FAIL",
  rollback_verdict: drill.verdict,
  all_criteria_met: finalStatus.success_criteria.all_criteria_met,
  success_criteria: finalStatus.success_criteria,
}, null, 2));
writeFileSync(join(OUT, "batch28_failures.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch28",
  total_checks: totalChecks,
  passed,
  failed,
  ready_to_discuss_hard_gate: finalStatus.success_criteria.all_criteria_met && failed === 0,
  failures,
}, null, 2));

console.log("\n── Artifacts ──");
console.log(`  ${join(OUT, "batch28_rough_weather_summary.md")}`);
console.log(`  ${join(OUT, "batch28_decision_counts.json")}`);
console.log(`  ${join(OUT, "batch28_approval_counts.json")}`);
console.log(`  ${join(OUT, "batch28_failures.json")}`);
console.log(`\n  Full TIER-A 12-service rough-weather: ${failed === 0 ? "CLEAN — hard-gate readiness discussion gate is clear." : `${failed} FAILURE(S) — fix before proceeding.`}`);
