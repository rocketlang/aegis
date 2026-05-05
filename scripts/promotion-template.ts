/**
 * AEGIS Promotion Script Template (Batch 78+)
 *
 * Copy this file and fill in the SERVICE_KEY, REPO_PATH, and service-specific
 * sections. Every promotion script must follow this structure to satisfy
 * AEG-PROV-001 and the hard-gate promotion doctrine.
 *
 * Mandatory pre-promotion checklist (non-negotiable):
 *   §0. assertSourceControlProvenance — AEG-PROV-001: ALL repos must be clean
 *       or carry an explicit RepoWaiver. This runs BEFORE everything else.
 *       A dirty tree without a waiver exits the script immediately.
 *   §1. Policy doctrine — hard_gate_enabled=true in policy object
 *   §2. Runtime roster — service is in AEGIS_HARD_GATE_SERVICES
 *   §3. Soak chain — all soak artifacts PASS, final has promotion_permitted=true
 *   §4. Domain controls — service-specific source checks (Five Locks if HG-2B-financial)
 *
 * The deliberate act:
 *   Adding the service to AEGIS_HARD_GATE_SERVICES is the human ceremony.
 *   This script verifies the state that results from that ceremony.
 *
 * Retroactive coverage note:
 *   Promotions before Batch 78 (chirpee, ship-slm, chief-slm, puranic-os,
 *   pramana, domain-capture, parali-central, carbonx-backend) did not carry
 *   source_control_provenance. The carbonx gap was repaired retroactively
 *   via Batch 75A (e13094b). No future promotion may skip §0.
 *
 * @rule:AEG-PROV-001 no hard-gate promotion without committed source in all repos
 * @rule:AEG-HG-001   hard_gate_enabled is the policy declaration
 * @rule:AEG-HG-003   env var addition is the deliberate act
 */

import { writeFileSync } from "fs";
import { join } from "path";
import {
  assertSourceControlProvenance,
  type SourceControlProvenance,
} from "../src/enforcement/provenance.js";
import { HARD_GATE_POLICIES, HARD_GATE_GLOBALLY_ENABLED } from "../src/enforcement/hard-gate-policy.js";

// ── FILL IN: service identity ──────────────────────────────────────────────────
const SERVICE_KEY = "REPLACE_ME";          // e.g. "my-svc"
const REPO_PATH   = "REPLACE_ME";          // e.g. "/root/apps/my-svc"
const BATCH       = 0;                     // batch number for this promotion
const AUDITS      = "/root/aegis/audits";
const PROMOTION_ARTIFACT = `batch${BATCH}_${SERVICE_KEY}_promotion.json`;

// ── Harness ───────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(group: number, label: string, actual: unknown, expected: unknown, tag: string): void {
  const ok = actual === expected;
  const pad = String(group).padStart(2, " ");
  if (ok) {
    passed++;
    console.log(`  ✓ [${pad}] ${label.padEnd(72)} actual=${JSON.stringify(actual)}`);
  } else {
    failed++;
    failures.push(`${tag}: [${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
    console.log(`  ✗ [${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  }
}

function section(title: string): void {
  console.log(`\n── ${title} ──`);
}

// ════════════════════════════════════════════════════════════════════════════
// §0 — AEG-PROV-001: Source-control provenance (MANDATORY FIRST CHECK)
//
// All repos in the promotion scope must be clean, or each dirty repo must
// carry an explicit RepoWaiver with reason, approver, expiry, and
// acknowledged_risk. A dirty tree without a waiver exits here — immediately.
// ════════════════════════════════════════════════════════════════════════════

section("§0 Source-control provenance (AEG-PROV-001)");

let scp: SourceControlProvenance;
try {
  scp = assertSourceControlProvenance({
    repos: [
      { name: "aegis",      path: "/root/aegis" },
      { name: SERVICE_KEY,  path: REPO_PATH },
      // Add more repos if the service spans multiple sub-repos, e.g.:
      // { name: "service-frontend", path: "/root/apps/my-svc-frontend" },
      //
      // To waive a dirty repo (exceptional path — requires explicit text):
      // {
      //   name: "my-svc",
      //   path: REPO_PATH,
      //   waiver: {
      //     reason: "explain exactly why the tree is dirty",
      //     approver: "founder",
      //     expiry: "2026-05-12",
      //     waiver_id: `waiver-batch${BATCH}-${SERVICE_KEY}-001`,
      //     acknowledged_risk: "repair artifact required within one batch (Batch 75A pattern)",
      //   },
      // },
    ],
    batch: BATCH,
    service_id: SERVICE_KEY,
  });
  console.log(`  ✓ [ 0] AEG-PROV-001 all repos clean (aegis + ${SERVICE_KEY})         actual=true`);
  if (scp.dirty_tree_waiver_used) {
    console.log(`  ⚠      dirty_tree_waiver_used=true — waiver recorded, repair artifact required`);
  }
  passed++;
} catch (e: unknown) {
  const err = e as Error;
  console.error(`  ✗ [ 0] AEG-PROV-001 FAILED — ${err.message}`);
  // Write a failed artifact so the block is recorded
  writeFileSync(
    join(AUDITS, PROMOTION_ARTIFACT),
    JSON.stringify({
      audit_id: `batch${BATCH}-${SERVICE_KEY}-promotion`,
      batch: BATCH,
      service: SERVICE_KEY,
      date: new Date().toISOString().slice(0, 10),
      verdict: "FAIL",
      checks_passed: 0,
      checks_failed: 1,
      source_control_provenance_failed: true,
      source_control_provenance_error: err.message,
    }, null, 2) + "\n",
  );
  console.error("\n  PROMOTION BLOCKED: commit all source changes or add RepoWaiver.\n");
  process.exit(1);
}

// ════════════════════════════════════════════════════════════════════════════
// §1 — Policy doctrine
// ════════════════════════════════════════════════════════════════════════════

section("§1 Policy doctrine");

const policy = HARD_GATE_POLICIES[SERVICE_KEY];
check(1, `HARD_GATE_POLICIES["${SERVICE_KEY}"] exists`,   policy !== undefined, true, "policy");
check(2, "hard_gate_enabled=true in policy",               policy?.hard_gate_enabled, true, "policy");
check(3, "HARD_GATE_GLOBALLY_ENABLED=true",                HARD_GATE_GLOBALLY_ENABLED, true, "policy");
// FILL IN additional service-specific policy checks:
// check(4, "rollout_order=N",                             policy?.rollout_order, N, "policy");
// check(5, "financial_settlement_doctrine=true",          policy?.financial_settlement_doctrine, true, "policy");

// ════════════════════════════════════════════════════════════════════════════
// §2 — Runtime roster
// ════════════════════════════════════════════════════════════════════════════

section("§2 Runtime roster");

const liveServices = (process.env.AEGIS_HARD_GATE_SERVICES ?? "")
  .split(",").map(s => s.trim()).filter(Boolean);
check(10, `${SERVICE_KEY} is in AEGIS_HARD_GATE_SERVICES`,
  liveServices.includes(SERVICE_KEY), true, "runtime");
// FILL IN: check(11, "live roster count=N", liveServices.length, N, "runtime");

// ════════════════════════════════════════════════════════════════════════════
// §3 — Soak chain
// ════════════════════════════════════════════════════════════════════════════

section("§3 Soak chain");

// FILL IN: import readAudit and verify each batch artifact, e.g.:
// const finalSoak = readAudit("batchNN_final_soak.json");
// check(20, "Final soak verdict=PASS",           finalSoak.verdict, "PASS", "chain");
// check(21, "Final soak promotion_permitted=true", finalSoak.promotion_permitted, true, "chain");

// ════════════════════════════════════════════════════════════════════════════
// §4 — Service domain controls (FILL IN per HG-group)
// ════════════════════════════════════════════════════════════════════════════

section("§4 Service domain controls");

// HG-1: no domain-specific checks needed beyond policy
// HG-2A: verify external state cleanup path exists
// HG-2B: verify approval_required source annotations
// HG-2B-financial: verify Five Locks in source (verifyFinancialApprovalToken,
//   externalRef @unique, positive-amount guard, SENSE irreversible=true, simulateSurrender)


// ════════════════════════════════════════════════════════════════════════════
// §5 — AEGIS-Q Quality evidence (Batch 89+)
//
// Compute quality_mask_at_promotion from what the promotion script can verify.
// Only bits 0–11 (point-in-time) may be set here — AEG-Q-002.
// quality_drift_score (bits 12–15) is set post-promotion only — AEG-Q-003.
//
// Required masks: HG-1=0x0302 · HG-2A=0x0B83 · HG-2B=0x0FAB · HG-2B-financial=0x0FFF
// ════════════════════════════════════════════════════════════════════════════

// FILL IN: set bits that the promotion script can verify mechanically.
// Example (HG-2A service with tests, typecheck, audit, source clean, codex, human review):
//   const QUALITY_MASK_AT_PROMOTION =
//     (1 << 0)  |   // Q-001 typecheck_passed
//     (1 << 1)  |   // Q-002 tests_passed
//     (1 << 7)  |   // Q-008 codex_updated
//     (1 << 8)  |   // Q-009 audit_artifact_written
//     (1 << 9)  |   // Q-010 source_clean  (AEG-PROV-001 passed above)
//     (1 << 11);    // Q-012 human_reviewed

// const qualityResult = assertQualityEvidence(policy?.hg_group ?? "HG-1", QUALITY_MASK_AT_PROMOTION);
// check(N, "Quality evidence satisfies HG group minimum",
//   qualityResult.verdict, "PASS", "quality");
// if (qualityResult.verdict === "FAIL") {
//   console.log(`  Missing: ${qualityResult.missing_bits.join(", ")}`);
// }

// ════════════════════════════════════════════════════════════════════════════
// Summary + artifact
// ════════════════════════════════════════════════════════════════════════════

console.log("\n" + "─".repeat(72));
console.log(`\n  Passed: ${passed}/${passed + failed}`);
if (failed > 0) {
  console.log(`\n  FAILURES (${failed}):`);
  for (const f of failures) console.log(`    ${f}`);
}

const verdict = failed === 0 ? "PASS" : "FAIL";

// source_control_provenance is mandatory in every promotion artifact (Batch 78+)
const artifact = {
  audit_id: `batch${BATCH}-${SERVICE_KEY}-promotion`,
  batch: BATCH,
  type: "promotion",
  service: SERVICE_KEY,
  date: new Date().toISOString().slice(0, 10),
  checks_total: passed + failed,
  checks_passed: passed,
  checks_failed: failed,
  verdict,
  hard_gate_enabled: true,
  // FILL IN: live_roster_count_after, live_services_after, etc.
  source_control_provenance: {
    rule:                           scp.rule,
    verified:                       scp.verified,
    repos:                          scp.repos,
    dirty_tree_waiver_used:         scp.dirty_tree_waiver_used,
    promotion_permitted:            scp.promotion_permitted,
    source_control_provenance_failed: scp.source_control_provenance_failed,
    checked_at:                     scp.checked_at,
  },
};

writeFileSync(
  join(AUDITS, PROMOTION_ARTIFACT),
  JSON.stringify(artifact, null, 2) + "\n",
);

console.log(`\n  Artifact: audits/${PROMOTION_ARTIFACT}`);
console.log(`  Verdict: ${verdict}\n`);

if (verdict === "FAIL") process.exit(1);
