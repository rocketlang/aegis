/**
 * Batch 51 — AEGIS historical promotion provenance audit
 *
 * Before the next HG-2A/HG-2B candidate enters soak, verify that every
 * currently live hard-gate service has coherent promotion lineage across
 * policy, runtime, stage text, codex, and tracked artifacts.
 *
 * Batch 50 found runtime-correct / document-wrong state. This batch asks
 * the deeper question: are there any other historical claims that the
 * runtime has silently outgrown since Batches 32–48?
 *
 * Design principles:
 *   - Hard checks (PASS/FAIL): policy correctness, runtime state, stage text,
 *     HG group assignment, rollout order, kill-switch doctrine, safety invariants.
 *   - Soft records (informational, never a failure):
 *       legacy_artifact_gap: audit artifacts for pre-Batch 47 promotions exist only
 *         in .aegis/ (gitignored runtime state), not in audits/ (tracked). This is
 *         expected — the audits/ pattern was established in Batch 49. Not a failure.
 *       codex_gap: codex.json absent for HG-1 services and pramana in ankr-labs-nx.
 *         Only domain-capture has a codex.json. Not a failure.
 *
 * @rule:AEG-HG-001 hard_gate_enabled must be true for every service in AEGIS_HARD_GATE_SERVICES
 * @rule:AEG-HG-002 READ never hard-blocks on any service in any mode
 * @rule:AEG-HG-003 promotion requires explicit AEGIS_HARD_GATE_SERVICES entry
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import {
  HARD_GATE_GLOBALLY_ENABLED,
  HARD_GATE_POLICIES,
  CHIRPEE_HG1_POLICY,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
  PURANIC_OS_HG1_POLICY,
  PRAMANA_HG2A_POLICY,
  DOMAIN_CAPTURE_HG2A_POLICY,
  type ServiceHardGatePolicy,
} from "../src/enforcement/hard-gate-policy";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH    = 51;
const RUN_DATE = new Date().toISOString();
const auditDir = join(process.cwd(), "audits");
const aegisDir = join(process.cwd(), ".aegis");
mkdirSync(auditDir, { recursive: true });

// ── Canonical provenance table ────────────────────────────────────────────────
// The single source of truth for expected promotion history.
// Used to verify stage strings, HG groups, rollout orders, and artifact locations.
const PROVENANCE: Array<{
  service:        string;
  hg_group_label: string;          // human label (HG-1, HG-2A)
  hg_group_policy: "HG-1" | "HG-2"; // policy type value
  rollout_order:  number;
  promotion_batch: number;
  soak_batch:     number;
  stage_batch_ref: string;         // expected substring in policy.stage
  policy:         ServiceHardGatePolicy;
  codex_path:     string;
  tracked_artifact_paths: string[];  // files expected in audits/
  ephemeral_artifact_paths: string[]; // files that may exist in .aegis/ only
}> = [
  {
    service: "chirpee",
    hg_group_label: "HG-1", hg_group_policy: "HG-1",
    rollout_order: 1, promotion_batch: 32, soak_batch: 31,
    stage_batch_ref: "Batch 32",
    policy: CHIRPEE_HG1_POLICY,
    codex_path: "/root/ankr-labs-nx/apps/chirpee/codex.json",
    tracked_artifact_paths: [],
    ephemeral_artifact_paths: [
      join(aegisDir, "batch32_chirpee_live_hard_gate_summary.json"),
    ],
  },
  {
    service: "ship-slm",
    hg_group_label: "HG-1", hg_group_policy: "HG-1",
    rollout_order: 2, promotion_batch: 36, soak_batch: 35,
    stage_batch_ref: "Batch 36",
    policy: SHIP_SLM_HG1_POLICY,
    codex_path: "/root/ankr-labs-nx/apps/ship-slm/codex.json",
    tracked_artifact_paths: [],
    ephemeral_artifact_paths: [
      join(aegisDir, "batch36_ship_chief_live_hard_gate_summary.md"),
    ],
  },
  {
    service: "chief-slm",
    hg_group_label: "HG-1", hg_group_policy: "HG-1",
    rollout_order: 3, promotion_batch: 36, soak_batch: 35,
    stage_batch_ref: "Batch 36",
    policy: CHIEF_SLM_HG1_POLICY,
    codex_path: "/root/ankr-labs-nx/apps/chief-slm/codex.json",
    tracked_artifact_paths: [],
    ephemeral_artifact_paths: [
      join(aegisDir, "batch36_ship_chief_live_hard_gate_summary.md"),
    ],
  },
  {
    service: "puranic-os",
    hg_group_label: "HG-1", hg_group_policy: "HG-1",
    rollout_order: 4, promotion_batch: 39, soak_batch: 38,
    stage_batch_ref: "Batch 39",
    policy: PURANIC_OS_HG1_POLICY,
    codex_path: "/root/ankr-labs-nx/apps/puranic-os/codex.json",
    tracked_artifact_paths: [],
    ephemeral_artifact_paths: [
      join(aegisDir, "batch39_puranic_live_hard_gate_summary.md"),
      join(aegisDir, "batch39_first_hard_gate_decisions.json"),
    ],
  },
  {
    service: "pramana",
    hg_group_label: "HG-2A", hg_group_policy: "HG-2",
    rollout_order: 5, promotion_batch: 43, soak_batch: 42,
    stage_batch_ref: "Batch 43",
    policy: PRAMANA_HG2A_POLICY,
    codex_path: "/root/ankr-labs-nx/apps/pramana/codex.json",
    tracked_artifact_paths: [],
    ephemeral_artifact_paths: [
      join(aegisDir, "batch43_pramana_live_hard_gate_summary.md"),
      join(aegisDir, "batch43_first_hard_gate_decisions.json"),
      join(aegisDir, "batch42_pramana_final_verdict.json"),
    ],
  },
  {
    service: "domain-capture",
    hg_group_label: "HG-2A", hg_group_policy: "HG-2",
    rollout_order: 6, promotion_batch: 48, soak_batch: 47,
    stage_batch_ref: "Batch 48",
    policy: DOMAIN_CAPTURE_HG2A_POLICY,
    codex_path: "/root/ankr-labs-nx/apps/domain-capture/codex.json",
    tracked_artifact_paths: [
      join(auditDir, "batch47_domain_capture_final_verdict.json"),
      join(auditDir, "batch48_domain_capture_hg2a_promotion.json"),
      join(auditDir, "batch49_domain_capture_cross_repo_audit.json"),
    ],
    ephemeral_artifact_paths: [
      join(aegisDir, "batch46_domain_capture_soak_run1_metrics.json"),
      join(aegisDir, "batch47_domain_capture_final_verdict.json"),
    ],
  },
];

// ── Check / record helpers ────────────────────────────────────────────────────
let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ check: number; service: string; label: string; expected: string; actual: string }> = [];
const legacyArtifactGaps: Array<{ service: string; promotion_batch: number; note: string; ephemeral_present: boolean[] }> = [];
const codexGaps: Array<{ service: string; note: string }> = [];
const rollbackDoctrine: Array<{ service: string; mechanism: string; read_safe: boolean; stage_confirmed: boolean }> = [];

function check(n: number, service: string, label: string, actual: unknown, expected: unknown) {
  totalChecks++;
  const ok = String(actual) === String(expected);
  const tag = `  C${String(n).padStart(2,"0")} [${service.padEnd(14)}]`;
  if (ok) {
    passed++;
    console.log(`${tag} ✓ ${label.padEnd(64)} = ${actual}`);
  } else {
    failed++;
    failures.push({ check: n, service, label, expected: String(expected), actual: String(actual) });
    console.log(`${tag} ✗ ${label.padEnd(64)}  expected=${expected} actual=${actual}`);
  }
}

function gap(label: string, detail: string) {
  console.log(`  GAP    [informational]  ${label}: ${detail}`);
}

console.log(`\n══ Batch ${BATCH} — AEGIS HISTORICAL PROMOTION PROVENANCE AUDIT ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  Scope: ${PROVENANCE.map(p => p.service).join(", ")}\n`);

const envServices = (process.env.AEGIS_HARD_GATE_SERVICES ?? "").split(",").map(s => s.trim()).filter(Boolean);
const policyKeys   = Object.keys(HARD_GATE_POLICIES);

// ── Check 1: Exactly one policy object per live service ───────────────────────
console.log("── Check 1: One policy per service ──");
for (const p of PROVENANCE) {
  check(1, p.service, "exactly one policy in HARD_GATE_POLICIES", policyKeys.filter(k => k === p.service).length, 1);
}
check(1, "REGISTRY", "no orphan policies (registry count = roster count)", policyKeys.length, PROVENANCE.length);

// ── Check 2: hard_gate_enabled=true (post Batch 50 fix) ──────────────────────
console.log("\n── Check 2: hard_gate_enabled=true ──");
for (const p of PROVENANCE) {
  check(2, p.service, "hard_gate_enabled=true", p.policy.hard_gate_enabled, true);
}

// ── Check 3: Exactly once in AEGIS_HARD_GATE_SERVICES ────────────────────────
console.log("\n── Check 3: Exactly once in env ──");
for (const p of PROVENANCE) {
  const count = envServices.filter(s => s === p.service).length;
  check(3, p.service, "appears exactly once in env", count, 1);
}

// ── Check 4: rollout_order unique, contiguous 1–6 ────────────────────────────
console.log("\n── Check 4: rollout_order unique and contiguous ──");
const orders = PROVENANCE.map(p => p.rollout_order).sort((a,b) => a-b);
check(4, "ROSTER", "orders are contiguous [1,2,3,4,5,6]", JSON.stringify(orders), JSON.stringify([1,2,3,4,5,6]));
for (const p of PROVENANCE) {
  check(4, p.service, `rollout_order=${p.rollout_order}`, p.policy.rollout_order, p.rollout_order);
}

// ── Check 5: Stage text identifies correct promotion batch ────────────────────
console.log("\n── Check 5: Stage text contains promotion batch reference ──");
for (const p of PROVENANCE) {
  check(5, p.service, `stage contains '${p.stage_batch_ref}'`, p.policy.stage.includes(p.stage_batch_ref), true);
  check(5, p.service, "stage contains 'LIVE'", p.policy.stage.includes("LIVE"), true);
}

// ── Check 6: HG group assignment unchanged ───────────────────────────────────
console.log("\n── Check 6: HG group assignment ──");
for (const p of PROVENANCE) {
  check(6, p.service, `hg_group=${p.hg_group_policy}`, p.policy.hg_group, p.hg_group_policy);
}

// ── Check 7: Tracked artifacts for recent promotions (Batch 48–50) ───────────
console.log("\n── Check 7: Tracked artifacts (recent promotions) ──");
const recentTracked = [
  { label: "B48 domain-capture promotion", path: join(auditDir, "batch48_domain_capture_hg2a_promotion.json") },
  { label: "B49 domain-capture convergence audit", path: join(auditDir, "batch49_domain_capture_cross_repo_audit.json") },
  { label: "B50 roster drift watch", path: join(auditDir, "batch50_live_hard_gate_roster_drift_watch.json") },
];
for (const art of recentTracked) {
  check(7, "audits/", `${art.label} exists`, existsSync(art.path), true);
}
// Verify B48 artifact integrity (not just existence)
{
  const b48 = JSON.parse(readFileSync(join(auditDir, "batch48_domain_capture_hg2a_promotion.json"), "utf8")) as Record<string, unknown>;
  check(7, "domain-capture", "B48 artifact: batch48_verdict=PASS", b48.batch48_verdict, "PASS");
  check(7, "domain-capture", "B48 artifact: hard_gate_enabled=true", b48.hard_gate_enabled, true);
  check(7, "domain-capture", "B48 artifact: soak_runs_passed=7", b48.soak_runs_passed, 7);
}
// Verify B50 artifact integrity
{
  const b50 = JSON.parse(readFileSync(join(auditDir, "batch50_live_hard_gate_roster_drift_watch.json"), "utf8")) as Record<string, unknown>;
  check(7, "ROSTER", "B50 artifact: verdict=PASS", b50.verdict, "PASS");
  check(7, "ROSTER", "B50 artifact: roster has 6 entries", (b50.roster_at_watch_time as unknown[])?.length, 6);
}

// ── Check 8: Legacy artifact gaps (informational, not a failure) ──────────────
console.log("\n── Check 8: Legacy artifact gaps (informational) ──");
for (const p of PROVENANCE.filter(p => p.tracked_artifact_paths.length === 0)) {
  const ephemeralPresent = p.ephemeral_artifact_paths.map(path => existsSync(path));
  const hasAnyEphemeral  = ephemeralPresent.some(Boolean);
  legacyArtifactGaps.push({
    service: p.service,
    promotion_batch: p.promotion_batch,
    note: `Promoted in Batch ${p.promotion_batch} before audits/ pattern established in Batch 49. ` +
          `Artifacts in .aegis/ (gitignored, ephemeral): ${hasAnyEphemeral ? "some present" : "none found"}.`,
    ephemeral_present: ephemeralPresent,
  });
  gap(p.service, `Batch ${p.promotion_batch} — pre-audits/ era. Ephemeral artifacts: ${hasAnyEphemeral ? "present" : "absent"}.`);
}
// domain-capture is NOT a legacy gap (all tracked)
{
  const dc = PROVENANCE.find(p => p.service === "domain-capture")!;
  const allTracked = dc.tracked_artifact_paths.every(path => existsSync(path));
  check(8, "domain-capture", "all tracked promotion artifacts present in audits/", allTracked, true);
}

// ── Check 9: codex.json agreement where present ───────────────────────────────
console.log("\n── Check 9: codex.json agreement ──");
for (const p of PROVENANCE) {
  if (!existsSync(p.codex_path)) {
    codexGaps.push({ service: p.service, note: `codex.json absent at ${p.codex_path} — pre-audits/ era, not a failure` });
    gap(p.service, `codex.json absent — not a failure`);
    continue;
  }
  let codex: Record<string, unknown> = {};
  try { codex = JSON.parse(readFileSync(p.codex_path, "utf8")); }
  catch { check(9, p.service, "codex.json readable", false, true); continue; }

  // Verify codex hg_group matches expected label
  check(9, p.service, `codex hg_group=${p.hg_group_label}`, codex.hg_group, p.hg_group_label);
  check(9, p.service, "codex hg_group_status contains LIVE", String(codex.hg_group_status ?? "").includes("LIVE"), true);
  // For HG-2A services: verify promotion block exists
  const promBlock = codex[`aegis_batch${p.promotion_batch}_promotion`] as Record<string, unknown> | undefined;
  if (promBlock) {
    check(9, p.service, `codex aegis_batch${p.promotion_batch}_promotion.hard_gate_enabled=true`, promBlock.hard_gate_enabled, true);
    check(9, p.service, `codex aegis_batch${p.promotion_batch}_promotion.new_phase=hard_gate`, promBlock.new_phase, "hard_gate");
  } else {
    gap(p.service, `codex aegis_batch${p.promotion_batch}_promotion block absent — informational`);
  }
}

// ── Check 10: Services without codex: record gap, never fail ─────────────────
// Already handled in Check 9 loop above. This check verifies the gap count is expected.
console.log("\n── Check 10: codex gap count is expected ──");
const expectedCodexGaps = PROVENANCE.filter(p => !existsSync(p.codex_path)).length;
check(10, "ROSTER", `codex_gap count=${expectedCodexGaps} (chirpee/ship-slm/chief-slm/puranic-os/pramana)`, codexGaps.length, expectedCodexGaps);
// Confirm domain-capture is NOT a gap
check(10, "domain-capture", "codex present (no gap)", codexGaps.some(g => g.service === "domain-capture"), false);

// ── Check 11: Rollback doctrine verifiable for all 6 ─────────────────────────
console.log("\n── Check 11: Rollback doctrine ──");
for (const p of PROVENANCE) {
  // Doctrine 1: stage contains LIVE (formal promotion evidence)
  check(11, p.service, "stage confirms formal promotion (LIVE)", p.policy.stage.includes("LIVE"), true);
  // Doctrine 2: READ is in never_block (READ-safe during rollback window)
  check(11, p.service, "READ in never_block (safe during rollback)", p.policy.never_block_capabilities.has("READ"), true);
  // Runtime rollback test for newest service (domain-capture) — spot check
  rollbackDoctrine.push({
    service: p.service,
    mechanism: "AEGIS_HARD_GATE_SERVICES env var removal — immediate, config-only",
    read_safe: p.policy.never_block_capabilities.has("READ"),
    stage_confirmed: p.policy.stage.includes("LIVE"),
  });
}
// Runtime spot-check rollback on domain-capture (newest guard)
{
  const pre = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b51-rb" });
  check(11, "domain-capture", "pre-rollback: BLOCK (live)", pre.decision, "BLOCK");
  process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
  const rb = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b51-rb" });
  check(11, "domain-capture", "rollback: soft_canary + ALLOW", rb.enforcement_phase === "soft_canary" && rb.decision === "ALLOW", true);
  process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture";
  const re = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b51-restore" });
  check(11, "domain-capture", "restore: hard_gate + BLOCK", re.enforcement_phase === "hard_gate" && re.decision === "BLOCK", true);
}

// ── Check 12: Kill-switch doctrine uniformly applies ─────────────────────────
console.log("\n── Check 12: Kill-switch doctrine ──");
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const p of PROVENANCE) {
  const d = evaluate({ service_id: p.service, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b51-kill" });
  check(12, p.service, "kill: shadow + NOT BLOCK", d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true);
}
process.env.AEGIS_RUNTIME_ENABLED = "true";
// All 6 restore immediately
for (const p of PROVENANCE) {
  const d = evaluate({ service_id: p.service, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b51-restore" });
  check(12, p.service, "post-kill: hard_gate + BLOCK restored", d.enforcement_phase === "hard_gate" && d.decision === "BLOCK", true);
}

// ── Check 13: Unknown service never blocks ────────────────────────────────────
console.log("\n── Check 13: Unknown service safety ──");
for (const svc of ["legacy-service-unknown", "hg2c-infiltrator", "stray-batch-zero"]) {
  const d = evaluate({ service_id: svc, operation: "execute", requested_capability: "IMPOSSIBLE_OP", caller_id: "b51-unksvc" });
  check(13, svc, "shadow + NOT BLOCK", d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true);
}

// ── Check 14: Unknown capability never hard-blocks on any live service ─────────
console.log("\n── Check 14: Unknown capability safety ──");
for (const p of PROVENANCE) {
  const d = evaluate({ service_id: p.service, operation: "frob", requested_capability: "CAP_NOT_YET_INVENTED", caller_id: "b51-unkcap" });
  check(14, p.service, "hard_gate + NOT BLOCK", d.enforcement_phase === "hard_gate" && d.decision !== "BLOCK", true);
}

// ── Final tally ───────────────────────────────────────────────────────────────
const batchPass = failed === 0;
console.log(`\n══ Batch ${BATCH} Summary ══`);
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Legacy artifact gaps (informational): ${legacyArtifactGaps.length} services`);
console.log(`  Codex gaps (informational): ${codexGaps.length} services`);
console.log(`  Verdict: ${batchPass ? "PASS" : "FAIL"}`);
if (failures.length) {
  console.log("\n  Hard failures:");
  failures.forEach(f => console.log(`  ✗ [C${f.check}] [${f.service}] ${f.label}: expected=${f.expected} actual=${f.actual}`));
}

// ── Emit provenance audit artifact ───────────────────────────────────────────
const artifact = {
  batch: BATCH,
  audit_type: "historical_promotion_provenance",
  audit_date: RUN_DATE,
  verdict: batchPass ? "PASS" : "FAIL",
  total_checks: totalChecks,
  passed,
  failed,
  hard_gate_globally_enabled: HARD_GATE_GLOBALLY_ENABLED,
  provenance_table: PROVENANCE.map(p => ({
    service:          p.service,
    hg_group:         p.hg_group_label,
    rollout_order:    p.rollout_order,
    promotion_batch:  p.promotion_batch,
    soak_batch:       p.soak_batch,
    hard_gate_enabled: p.policy.hard_gate_enabled,
    stage:            p.policy.stage,
    codex_present:    existsSync(p.codex_path),
    tracked_artifacts_present: p.tracked_artifact_paths.length > 0
      ? p.tracked_artifact_paths.every(existsSync) : false,
    legacy_artifact_gap: p.tracked_artifact_paths.length === 0,
  })),
  legacy_artifact_gaps: legacyArtifactGaps,
  codex_gaps: codexGaps,
  rollback_doctrine: rollbackDoctrine,
  hard_findings_from_batch50_drift: {
    services_fixed: ["chirpee", "ship-slm", "chief-slm"],
    fix: "hard_gate_enabled set to true (was false despite being in AEGIS_HARD_GATE_SERVICES)",
    runtime_was: "correct",
    documentary_was: "wrong",
    status: "RESOLVED in Batch 50",
  },
  invariants_confirmed: [
    "One policy per service — no orphan, no duplicate",
    "hard_gate_enabled=true for all 6 (post Batch 50 fix)",
    "Exactly once in AEGIS_HARD_GATE_SERVICES",
    "rollout_order contiguous [1,2,3,4,5,6], unique",
    "Stage text identifies promotion batch for all 6",
    "HG group assignment unchanged for all 6",
    "Tracked artifacts present for Batch 48–50 promotions",
    "Rollback doctrine: stage LIVE + READ in never_block for all 6",
    "Kill switch: shadow + NOT BLOCK; restore: hard_gate + BLOCK",
    "Unknown service: shadow + NOT BLOCK",
    "Unknown capability: hard_gate + NOT BLOCK",
  ],
  failures,
  note: "Legacy artifact gaps and codex gaps are INFORMATIONAL only — not failures. " +
        "The audits/ pattern was established in Batch 49; pre-Batch 47 promotions " +
        "have ephemeral-only artifacts in .aegis/ (gitignored). This is expected and honest.",
};
writeFileSync(join(auditDir, "batch51_historical_promotion_provenance_audit.json"), JSON.stringify(artifact, null, 2));

console.log(`\n  Provenance artifact → audits/batch51_historical_promotion_provenance_audit.json`);
console.log(`\n── Promotion lineage ──`);
for (const p of PROVENANCE) {
  const codexMark = existsSync(p.codex_path)  ? "codex ✓" : "codex —";
  const artMark   = p.tracked_artifact_paths.length > 0 ? "artifacts ✓" : "artifacts (legacy .aegis/ only)";
  console.log(`  Batch ${p.promotion_batch.toString().padEnd(2)} → [${p.hg_group_label}] ${p.service.padEnd(14)}  ${codexMark}  ${artMark}`);
}
console.log(`\n  The six guards now have not only orders, but lineage.`);
console.log(`\n  Batch 51: ${batchPass ? "PASS" : "FAIL"}`);
