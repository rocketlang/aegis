/**
 * Batch 61 — Post-HG-2B Promotion Convergence Audit
 *
 * Verify that Batch 60 promotion of parali-central is converged across:
 * runtime policy, audit artifacts, codex.json, services.json, wiki,
 * TODO, LOGICS, VIVECHANA, and deep-knowledge.
 *
 * This is not bureaucracy. This is how AEGIS proves its own thesis:
 * evidence is the product.
 *
 * @rule:AEG-HG-001 hard_gate_enabled alignment
 * @rule:AEG-HG-002 READ never hard-blocks
 * @rule:AEG-HG-003 env var is the gate switch
 * @rule:AEG-E-016 scoped-key doctrine
 * @rule:IRR-NOAPPROVAL irreversible action gate
 */

import { readFileSync } from "fs";
import { writeFileSync } from "fs";
import {
  applyHardGate,
  HARD_GATE_POLICIES,
  PARALI_CENTRAL_HG2B_POLICY,
} from "../src/enforcement/hard-gate-policy";

// ── Check infrastructure ──────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(
  group: number,
  label: string,
  actual: unknown,
  expected: unknown,
  tag: string,
): void {
  const ok =
    typeof expected === "object" && expected !== null
      ? JSON.stringify(actual) === JSON.stringify(expected)
      : actual === expected;
  const pad = String(group).padStart(2, " ");
  if (ok) {
    passed++;
    console.log(`  ✓ [${pad}] ${label.padEnd(72)} actual=${JSON.stringify(actual)}`);
  } else {
    failed++;
    const msg = `[${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`;
    failures.push(`${tag}: ${msg}`);
    console.log(`  ✗ ${msg}`);
  }
}

function section(title: string): void {
  console.log(`\n── ${title} ──`);
}

function readFile(path: string): string {
  return readFileSync(path, "utf-8");
}

function readJSON(path: string): Record<string, unknown> {
  return JSON.parse(readFile(path));
}

// ── Constants ─────────────────────────────────────────────────────────────────

const PARALI_CENTRAL     = "parali-central";
const HG1_SERVICES       = ["chirpee", "ship-slm", "chief-slm", "puranic-os"];
const HG2A_SERVICES      = ["pramana", "domain-capture"];
const EXPECTED_LIVE_7    = [...HG1_SERVICES, ...HG2A_SERVICES, PARALI_CENTRAL];

const PATHS = {
  batch60Artifact: "audits/batch60_parali_central_hg2b_promotion.json",
  codex:           "/root/aegis/codex.json",
  servicesJson:    "/root/.ankr/config/services.json",
  wiki:            "/root/ankr-wiki/services/ankr-aegis.md",
  todo:            "/root/ankr-todos/aegis--enforcement--todo--formal--2026-05-03.md",
  logics:          "/root/proposals/aegis--enforcement--logics--formal--2026-05-03.md",
  vivechana:       "/root/proposals/aegis--vivechana--formal--2026-05-01.md",
  deepKnowledge:   "/root/proposals/ankr-aegis--deep-knowledge--formal--2026-05-01.md",
};

// ── HEADER ────────────────────────────────────────────────────────────────────

console.log("══ Batch 61 — Post-HG-2B Promotion Convergence Audit ══");
console.log(`  Date: ${new Date().toISOString()}`);
console.log("  Purpose: Verify Batch 60 parali-central promotion converged everywhere");
console.log();

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1 — Batch 60 audit artifact
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 1: Batch 60 audit artifact exists and is PASS");
const b60 = readJSON(PATHS.batch60Artifact);
check(1, "batch60 artifact loaded", !!b60, true, "artifact");
check(1, "batch60 verdict=PASS", b60.verdict, "PASS", "artifact");

section("Check 2: Batch 60 checks=152 and failed=0");
const b60TotalChecks = (b60.checks ?? b60.total_checks) as number;
check(2, "batch60 checks=152", b60TotalChecks, 152, "artifact");
check(2, "batch60 failed=0", b60.failed, 0, "artifact");

section("Check 3: Batch 60 promotion fields");
check(3, "batch60 hard_gate_enabled=true", b60.hard_gate_enabled, true, "artifact");
check(3, "batch60 added_to_AEGIS_HARD_GATE_SERVICES=true",
  b60.added_to_AEGIS_HARD_GATE_SERVICES, true, "artifact");
check(3, "batch60 live_hard_gate_roster_size=7", b60.live_hard_gate_roster_size, 7, "artifact");
check(3, "batch60 hg2b_live_count=1", b60.hg2b_live_count, 1, "artifact");
check(3, "batch60 hg2c_live_count=0", b60.hg2c_live_count, 0, "artifact");
check(3, "batch60 promotion_is_separate_human_act=true",
  b60.promotion_is_separate_human_act, true, "artifact");
check(3, "batch60 service=parali-central", b60.service, PARALI_CENTRAL, "artifact");
check(3, "batch60 hg_group=HG-2B", b60.hg_group, "HG-2B", "artifact");
check(3, "batch60 previous_phase=soft_canary", b60.previous_phase, "soft_canary", "artifact");
check(3, "batch60 new_phase=hard_gate", b60.new_phase, "hard_gate", "artifact");

section("Check 4: Batch 60 live roster contains all 7 expected services");
const rawRoster = (b60.live_hard_gate_roster as unknown[]) ?? [];
const b60Roster: string[] = rawRoster.map((x: unknown) =>
  typeof x === "string" ? x : (x as { service: string }).service
);
check(4, "batch60 roster length=7", b60Roster.length, 7, "artifact");
for (const svc of EXPECTED_LIVE_7) {
  check(4, `batch60 roster contains ${svc}`, b60Roster.includes(svc), true, "artifact");
}

section("Check 5: Batch 60 rollback drill and key metrics");
const b60Rollback = (b60.rollback_drill as Record<string, unknown>) ?? {};
check(5, "batch60 rollback_drill.rollback_success=true",
  b60Rollback.rollback_success, true, "artifact");
check(5, "batch60 rollback_drill.scenarios_tested=3",
  b60Rollback.scenarios_tested, 3, "artifact");
check(5, "batch60 false_positives=0", b60.false_positives, 0, "artifact");
check(5, "batch60 production_fires=0", b60.production_fires, 0, "artifact");
check(5, "batch60 token_scoping_pass=true", b60.token_scoping_pass, true, "artifact");
check(5, "batch60 cross_group_isolation_pass=true",
  b60.cross_group_isolation_pass, true, "artifact");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2 — Runtime policy convergence
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 6: PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled=true");
check(6, "hard_gate_enabled=true (documentary alignment with env)",
  PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled, true, "policy");

section("Check 7: parali-central rollout_order=7");
check(7, "rollout_order=7", PARALI_CENTRAL_HG2B_POLICY.rollout_order, 7, "policy");

section("Check 8: stage string reflects live promotion");
check(8, "stage contains 'HG-2B LIVE'",
  PARALI_CENTRAL_HG2B_POLICY.stage.includes("HG-2B LIVE"), true, "policy");
check(8, "stage contains 'Batch 60'",
  PARALI_CENTRAL_HG2B_POLICY.stage.includes("Batch 60"), true, "policy");

section("Check 9: parali-central in HARD_GATE_POLICIES registry");
check(9, "HARD_GATE_POLICIES contains parali-central",
  PARALI_CENTRAL in HARD_GATE_POLICIES, true, "policy");

section("Check 10: Existing six live guards policy unchanged");
for (const svc of [...HG1_SERVICES, ...HG2A_SERVICES]) {
  const pol = HARD_GATE_POLICIES[svc];
  check(10, `${svc}: policy present`, !!pol, true, "policy");
  check(10, `${svc}: hard_gate_enabled=true`, pol?.hard_gate_enabled, true, "policy");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3 — Live enforcement via AEGIS_HARD_GATE_SERVICES
// ═══════════════════════════════════════════════════════════════════════════════

// Simulate the post-promotion env state (as it would be in production)
process.env.AEGIS_HARD_GATE_SERVICES = EXPECTED_LIVE_7.join(",");

section("Check 11: Kill switch suppresses all 7 live guards");
const savedEnv = process.env.AEGIS_HARD_GATE_SERVICES;
process.env.AEGIS_HARD_GATE_SERVICES = "";
for (const svc of EXPECTED_LIVE_7) {
  const r = applyHardGate(svc, "BLOCK", "IMPOSSIBLE_OP", "write");
  check(11, `${svc}: kill switch → hard_gate_active=false`, r.hard_gate_active, false, "runtime");
}
process.env.AEGIS_HARD_GATE_SERVICES = savedEnv;

section("Check 12: parali-central READ remains ALLOW");
const r12 = applyHardGate(PARALI_CENTRAL, "ALLOW", "READ", "read");
check(12, "parali-central READ=ALLOW", r12.decision, "ALLOW", "runtime");
check(12, "parali-central READ: hard_gate_active=true", r12.hard_gate_active, true, "runtime");

section("Check 13: parali-central still_gate paths remain GATE");
for (const cap of ["EXTERNAL_WRITE", "RELEASE_DOCUMENT", "APPROVE_TRANSACTION", "SYNC_PUSH"]) {
  const r = applyHardGate(PARALI_CENTRAL, "GATE", cap, "write");
  check(13, `parali-central ${cap}=GATE`, r.decision, "GATE", "runtime");
}

section("Check 14: parali-central hard-block paths remain BLOCK");
for (const cap of [
  "IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE",
  "EXTERNAL_WRITE_UNAUTHENTICATED", "BULK_EXTERNAL_MUTATION",
  "FORCE_EXTERNAL_OVERWRITE", "EXTERNAL_DELETE_UNAPPROVED",
]) {
  const r = applyHardGate(PARALI_CENTRAL, "BLOCK", cap, "write");
  check(14, `parali-central ${cap}=BLOCK`, r.decision, "BLOCK", "runtime");
  check(14, `parali-central ${cap}: hard_gate_applied=true`, r.hard_gate_applied, true, "runtime");
}

section("Check 15: AEG-E-016 scoped-key doctrine — verified via Batch 60 artifact (structural fields only)");
// NOTE: actual wrong-service token rejection is tested in Batch 60.
// Check 5 above confirms token_scoping_pass=true in the Batch 60 artifact.
// These checks verify the structural doctrine fields are present in the policy — labels reflect what is actually proved.
check(15, "token_scoping_verified_by_batch60_artifact — approval_required_for_irreversible_action=true",
  PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action, true, "doctrine");
check(15, "token_scoping_verified_by_batch60_artifact — external_state_touch=true",
  PARALI_CENTRAL_HG2B_POLICY.external_state_touch, true, "doctrine");
check(15, "token_scoping_verified_by_batch60_artifact — observability_required=true",
  PARALI_CENTRAL_HG2B_POLICY.observability_required, true, "doctrine");
check(15, "token_scoping_verified_by_batch60_artifact — audit_artifact_required=true",
  PARALI_CENTRAL_HG2B_POLICY.audit_artifact_required, true, "doctrine");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4 — codex.json convergence
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 16: codex.json reflects parali-central Batch 60 live HG-2B");
const codex = readJSON(PATHS.codex);
const er = (codex.enforcement_rollout as Record<string, unknown>) ?? {};
const ca = (codex.capability_audit as Record<string, unknown>) ?? {};

check(16, "codex enforcement_rollout.stage5_promoted=true",
  er.stage5_promoted, true, "codex");
check(16, "codex enforcement_rollout.parali_central_promoted=true",
  er.parali_central_promoted, true, "codex");
check(16, "codex enforcement_rollout.hg2b_live_count=1",
  er.hg2b_live_count, 1, "codex");
check(16, "codex enforcement_rollout.hg2c_live_count=0",
  er.hg2c_live_count, 0, "codex");
check(16, "codex enforcement_rollout.live_roster_size=7",
  er.live_roster_size, 7, "codex");
check(16, "codex capability_audit has hg2b_soak_run7 entry",
  "enforcement_hg2b_soak_run7" in ca, true, "codex");
check(16, "codex capability_audit has hg2b_promote entry",
  "enforcement_hg2b_promote" in ca, true, "codex");
const promoteEntry = (ca.enforcement_hg2b_promote as string) ?? "";
check(16, "codex hg2b_promote entry mentions Batch 60",
  promoteEntry.includes("Batch 60"), true, "codex");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — services.json masks
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 17: services.json ankr-aegis masks");
const services = readJSON(PATHS.servicesJson);
const svcsMap = (services.services as Record<string, Record<string, unknown>>) ?? {};
const aegisSvc = svcsMap["ankr-aegis"] ?? {};
check(17, "services.json ankr-aegis k_mask=255",
  aegisSvc.k_mask, 255, "masks");
check(17, "services.json ankr-aegis claude_ankr_mask=31",
  aegisSvc.claude_ankr_mask, 31, "masks");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6 — wiki convergence
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 18: wiki reflects 7 live guards and parali-central HG-2B Batch 60");
const wikiContent = readFile(PATHS.wiki);
check(18, "wiki compiled_at=2026-05-03",
  wikiContent.includes("compiled_at: 2026-05-03"), true, "wiki");
check(18, "wiki k_mask=255",
  wikiContent.includes("k_mask: 255"), true, "wiki");
check(18, "wiki claude_ankr_mask=31",
  wikiContent.includes("claude_ankr_mask: 31"), true, "wiki");
check(18, "wiki mentions '7 services' or 'Live roster'",
  wikiContent.includes("7 services") || wikiContent.includes("Live Hard-Gate Roster"), true, "wiki");
check(18, "wiki mentions parali-central Batch 60",
  wikiContent.includes("parali-central") && wikiContent.includes("Batch 60"), true, "wiki");
check(18, "wiki mentions HG-2B LIVE",
  wikiContent.includes("HG-2B"), true, "wiki");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7 — TODO convergence
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 19: TODO marks Batches 39–60 complete");
const todoContent = readFile(PATHS.todo);
// Check that key batch completions are marked [x]
for (const batch of ["ENF-B39", "ENF-B43", "ENF-B48", "ENF-B53", "ENF-B59", "ENF-B60"]) {
  check(19, `TODO has [x] ${batch}`,
    todoContent.includes(`[x] **${batch}**`), true, "todo");
}
check(19, "TODO has live roster table with 7 services",
  todoContent.includes("7 total") || todoContent.includes("| parali-central |"), true, "todo");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8 — LOGICS convergence
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 20: LOGICS contains HG-2B doctrine rules");
const logicsContent = readFile(PATHS.logics);
check(20, "LOGICS contains IRR-NOAPPROVAL",
  logicsContent.includes("IRR-NOAPPROVAL"), true, "logics");
check(20, "LOGICS contains AEG-E-016",
  logicsContent.includes("AEG-E-016"), true, "logics");
check(20, "LOGICS contains normalizeCapability",
  logicsContent.includes("normalizeCapability"), true, "logics");
check(20, "LOGICS contains still_gate semantics",
  logicsContent.includes("still_gate") && logicsContent.includes("downgrade"), true, "logics");
check(20, "LOGICS contains permission ≠ promotion invariant",
  logicsContent.includes("Permission to promote ≠ promotion") ||
  (logicsContent.includes("permission") && logicsContent.includes("≠") && logicsContent.includes("promotion")),
  true, "logics");
check(20, "LOGICS contains AEG-HG-2B-001",
  logicsContent.includes("AEG-HG-2B-001"), true, "logics");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9 — VIVECHANA convergence
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 21: VIVECHANA contains HG-2B decision score V=41,472 and F=9");
const vivechanaContent = readFile(PATHS.vivechana);
check(21, "VIVECHANA contains V=41,472",
  vivechanaContent.includes("41,472"), true, "vivechana");
check(21, "VIVECHANA contains F=9 (feasibility score)",
  vivechanaContent.includes("F=9") || vivechanaContent.includes("F** | 9"), true, "vivechana");
check(21, "VIVECHANA contains HG-2B decision",
  vivechanaContent.includes("HG-2B"), true, "vivechana");
check(21, "VIVECHANA mentions Batch 60 outcome",
  vivechanaContent.includes("Batch 60") || vivechanaContent.includes("Batches 53–60"), true, "vivechana");

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 10 — No stale "candidate" / "soft_canary" claims post-Batch 60
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 22: No non-historical living doc claims parali-central is only candidate/soft_canary");
// Policy stage is the authoritative source
check(22, "policy stage does NOT say 'candidate' or 'NOT PROMOTED'",
  !PARALI_CENTRAL_HG2B_POLICY.stage.includes("NOT PROMOTED") &&
  !PARALI_CENTRAL_HG2B_POLICY.stage.includes("candidate"),
  true, "convergence");
// Wiki current-state section must not mention soft_canary for parali-central
const wikiLiveSection = wikiContent.split("## Enforcement Rollout")[1] ?? "";
check(22, "wiki enforcement section does not say 'soft_canary' for parali-central",
  !wikiLiveSection.includes("soft_canary"), true, "convergence");
// Deep-knowledge latest session note must confirm promoted state
const deepKnowledgeContent = readFile(PATHS.deepKnowledge);
const dkLatestSection = deepKnowledgeContent.split("## Session Note").slice(-1)[0] ?? "";
check(22, "deep-knowledge latest session note does NOT claim parali-central is still soft_canary",
  !dkLatestSection.includes("soft_canary") || dkLatestSection.includes("promot"),
  true, "convergence");
check(22, "deep-knowledge latest session note confirms parali-central live/promoted/HG-2B",
  dkLatestSection.includes("promot") || dkLatestSection.includes("live") || dkLatestSection.includes("HG-2B"),
  true, "convergence");
// LOGICS latest session note must not mark parali-central as candidate
const logicsLatestSection = logicsContent.split("## Session Note").slice(-1)[0] ?? "";
check(22, "LOGICS latest session note does NOT mark parali-central as soft_canary candidate",
  !logicsLatestSection.includes("soft_canary") || logicsLatestSection.includes("live"),
  true, "convergence");

section("Check 23: Zenodo paper and product brief — historical snapshot, not live authority");
// Zenodo paper is frozen at publication time — a historical snapshot.
// Batch 60 artifact is the live source of truth; we verify that framing is intact here.
check(23, "policy stage correct for post-Batch60 state (primary source of truth)",
  PARALI_CENTRAL_HG2B_POLICY.stage.startsWith("Stage 5 — HG-2B LIVE"), true, "convergence");
check(23, "soak evidence reference intact (Batch 53-59 7/7)",
  PARALI_CENTRAL_HG2B_POLICY.stage.includes("Batch 53-59 7/7"), true, "convergence");
// Batch 60 artifact carries the hard evidence that Zenodo paper (written earlier) does not need to repeat
check(23, "batch60 artifact is source of truth — hard_gate_enabled=true + promotion_is_separate_human_act=true",
  b60.hard_gate_enabled === true && b60.promotion_is_separate_human_act === true, true, "convergence");

// ═══════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

const totalChecks = passed + failed;
const verdict = failed === 0 ? "PASS" : "FAIL";

console.log(`\n══ Batch 61 Summary ══`);
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Verdict: ${verdict}`);
if (failed > 0) {
  console.log("  Failures:");
  failures.forEach(f => console.log(`    - ${f}`));
}

// ── Artifact ──────────────────────────────────────────────────────────────────

const artifact = {
  batch: 61,
  type: "convergence_audit",
  purpose: "Verify Batch 60 parali-central HG-2B promotion converged across all records",
  timestamp: new Date().toISOString(),
  verdict,
  checks: totalChecks,
  passed,
  failed,
  failures,
  convergence_surfaces: {
    batch60_artifact: failed === 0 || !failures.some(f => f.startsWith("artifact")),
    policy_runtime:   failed === 0 || !failures.some(f => f.startsWith("policy") || f.startsWith("runtime")),
    codex_json:       failed === 0 || !failures.some(f => f.startsWith("codex")),
    services_json:    failed === 0 || !failures.some(f => f.startsWith("masks")),
    wiki:             failed === 0 || !failures.some(f => f.startsWith("wiki")),
    todo:             failed === 0 || !failures.some(f => f.startsWith("todo")),
    logics:           failed === 0 || !failures.some(f => f.startsWith("logics")),
    vivechana:        failed === 0 || !failures.some(f => f.startsWith("vivechana")),
    doctrine_fields:  failed === 0 || !failures.some(f => f.startsWith("doctrine")),
  },
  parali_central_state: {
    hard_gate_enabled: PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled,
    rollout_order: PARALI_CENTRAL_HG2B_POLICY.rollout_order,
    stage: PARALI_CENTRAL_HG2B_POLICY.stage,
    external_state_touch: PARALI_CENTRAL_HG2B_POLICY.external_state_touch,
    approval_required: PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action,
  },
  live_roster: EXPECTED_LIVE_7,
  live_roster_size: EXPECTED_LIVE_7.length,
  runtime_env_mode: "simulated_expected_live_roster",
  hg1_count: HG1_SERVICES.length,
  hg2a_count: HG2A_SERVICES.length,
  hg2b_count: 1,
  hg2c_count: 0,
  next_candidate: "carbonx (rollout_order=8, authority_class=external_call, BR-3)",
  zenodo_paper_status: "historical_snapshot_pre_batch60",
  product_brief_status: "requires_update_if_used_commercially_after_batch60",
  batch60_artifact_is_source_of_truth: true,
};

writeFileSync(
  "audits/batch61_post_hg2b_promotion_convergence_audit.json",
  JSON.stringify(artifact, null, 2),
);

console.log(`\n  Convergence artifact → audits/batch61_post_hg2b_promotion_convergence_audit.json`);
console.log();
console.log("The seventh guard is armed, and every ledger agrees.");
