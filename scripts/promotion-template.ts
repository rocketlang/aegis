/**
 * AEGIS Promotion Script Template
 *
 * Copy this file and fill in the SERVICE_KEY, REPO_PATH, and service-specific
 * sections. Every promotion script must follow this structure to satisfy
 * AEG-PROV-001 and the hard-gate promotion doctrine.
 *
 * Mandatory pre-promotion checklist (non-negotiable):
 *   1. assertCleanSourceTree — AEG-PROV-001: source must be committed
 *   2. All soak artifacts exist and verdict=PASS
 *   3. Final soak artifact has promotion_permitted=true
 *   4. Human has added SERVICE_KEY to AEGIS_HARD_GATE_SERVICES (env var)
 *   5. hard_gate_enabled=true in the service's policy object
 *
 * The deliberate act:
 *   Adding the env var is the human ceremony. This script verifies the state
 *   that results from that ceremony. It does not perform the ceremony itself.
 *
 * @rule:AEG-PROV-001 no hard-gate promotion without committed source
 * @rule:AEG-HG-001   hard_gate_enabled is the policy declaration
 * @rule:AEG-HG-003   env var addition is the deliberate act
 */

import { writeFileSync } from "fs";
import { join } from "path";
import { assertCleanSourceTree } from "../src/enforcement/provenance.js";
import { HARD_GATE_POLICIES, HARD_GATE_GLOBALLY_ENABLED } from "../src/enforcement/hard-gate-policy.js";

// ── FILL IN: service identity ──────────────────────────────────────────────────
const SERVICE_KEY = "REPLACE_ME";          // e.g. "my-service"
const REPO_PATH   = "REPLACE_ME";          // e.g. "/root/apps/my-service"
const BATCH       = 0;                     // batch number
const AUDITS      = "/root/aegis/audits";

// ── FILL IN: soak artifact filenames (last 2 are always required) ─────────────
const FINAL_SOAK_ARTIFACT  = `REPLACE_ME_batchNN_${SERVICE_KEY}_soak_final.json`;
const PROMOTION_ARTIFACT   = `batch${BATCH}_${SERVICE_KEY}_promotion.json`;

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
// STEP 1 — AEG-PROV-001: Assert clean source tree
// This check happens BEFORE anything else. A dirty tree stops promotion.
// To override: supply an explicit DirtyTreeWaiver (see provenance.ts).
// ════════════════════════════════════════════════════════════════════════════

section("§0 Provenance pre-check (AEG-PROV-001)");

let provenance;
try {
  provenance = assertCleanSourceTree(REPO_PATH);
  // Uncomment to supply a waiver when tree is intentionally dirty:
  // provenance = assertCleanSourceTree(REPO_PATH, {
  //   reason: "explain why the tree is dirty",
  //   authorized_by: "founder",
  //   waiver_id: `waiver-${new Date().toISOString().slice(0,10)}-001`,
  //   acknowledged_risk: "audited; will repair post-promotion per AEG-PROV-001 Batch 75A pattern",
  // });
  console.log(`  ✓ [ 0] AEG-PROV-001 source tree clean (${REPO_PATH})              actual=true`);
  passed++;
} catch (e: unknown) {
  const err = e as Error;
  console.error(`  ✗ [ 0] AEG-PROV-001 FAILED — ${err.message}`);
  console.error("\n  PROMOTION BLOCKED: commit all source changes before promoting.\n");
  process.exit(1);
}

// ════════════════════════════════════════════════════════════════════════════
// STEP 2 — Policy doctrine checks
// ════════════════════════════════════════════════════════════════════════════

section("§1 Policy doctrine");

const policy = HARD_GATE_POLICIES[SERVICE_KEY];

check(1, `HARD_GATE_POLICIES["${SERVICE_KEY}"] exists`,       policy !== undefined, true, "policy");
check(2, "hard_gate_enabled=true in policy",                   policy?.hard_gate_enabled, true, "policy");
check(3, "HARD_GATE_GLOBALLY_ENABLED=true",                    HARD_GATE_GLOBALLY_ENABLED, true, "policy");
// FILL IN: add service-specific policy checks here
// check(4, "service_id matches",                               policy?.service_id, SERVICE_KEY, "policy");

// ════════════════════════════════════════════════════════════════════════════
// STEP 3 — Runtime: service is in AEGIS_HARD_GATE_SERVICES
// ════════════════════════════════════════════════════════════════════════════

section("§2 Runtime roster");

const liveServices = (process.env.AEGIS_HARD_GATE_SERVICES ?? "").split(",").map(s => s.trim()).filter(Boolean);
check(5, `${SERVICE_KEY} is in AEGIS_HARD_GATE_SERVICES`,
  liveServices.includes(SERVICE_KEY), true, "runtime");
// FILL IN: assert expected roster count
// check(6, "Live roster count", liveServices.length, EXPECTED_COUNT, "runtime");

// ════════════════════════════════════════════════════════════════════════════
// STEP 4 — Soak chain: final soak artifact has promotion_permitted=true
// FILL IN: replace artifact paths, add checks for each soak run
// ════════════════════════════════════════════════════════════════════════════

section("§3 Soak chain verification");

// FILL IN: import readAudit and check each batch artifact
// const finalSoak = readAudit(FINAL_SOAK_ARTIFACT);
// check(10, "Final soak verdict=PASS", finalSoak.verdict, "PASS", "chain");
// check(11, "Final soak promotion_permitted=true", finalSoak.promotion_permitted, true, "chain");

// ════════════════════════════════════════════════════════════════════════════
// STEP 5 — Domain-specific checks (FILL IN per service)
// ════════════════════════════════════════════════════════════════════════════

section("§4 Service domain controls");

// FILL IN: source-file checks, Five Locks (if HG-2B-financial), etc.

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
  // AEG-PROV-001: provenance field is mandatory in every promotion artifact
  provenance: provenance
    ? {
        rule: provenance.rule,
        source_tree_clean: provenance.source_tree_clean,
        uncommitted_files: provenance.uncommitted_files,
        waiver: provenance.waiver,
        waiver_applied: provenance.waiver_applied,
        promotion_permitted: provenance.promotion_permitted,
        checked_at: provenance.checked_at,
      }
    : null,
  // FILL IN: hard_gate_enabled, live_roster_count, etc.
};

writeFileSync(
  join(AUDITS, PROMOTION_ARTIFACT),
  JSON.stringify(artifact, null, 2) + "\n",
);

console.log(`\n  Artifact: audits/${PROMOTION_ARTIFACT}`);
console.log(`  Verdict: ${verdict}\n`);

if (verdict === "FAIL") process.exit(1);
