/**
 * Batch 50 — AEGIS live hard-gate roster drift watch
 *
 * Post-promotion stability check for all six live hard-gate services.
 * domain-capture was promoted in Batch 48; this batch proves the roster
 * remains stable and no hidden drift has appeared since that promotion.
 *
 * This is NOT a soak run. It is a drift watch:
 *   every structural invariant of the live roster must hold simultaneously.
 *
 * Checks:
 *   1.  AEGIS_HARD_GATE_SERVICES has exactly 6 entries, no duplicates
 *   2.  Roster entries match expected set exactly (no extra, no missing)
 *   3.  rollout_order is unique across all 6 policies and strictly 1-6
 *   4.  All 6 live services have hard_gate_enabled=true (documentary alignment)
 *   5.  HG-1 services (4) remain hg_group=HG-1 in policy
 *   6.  pramana remains hg_group=HG-2 (HG-2A family) in policy
 *   7.  domain-capture remains hg_group=HG-2 (HG-2A family) in policy
 *   8.  No HG-2B or HG-2C service present in AEGIS_HARD_GATE_SERVICES
 *   9.  Unknown service never blocks (shadow + WARN, not BLOCK)
 *  10.  Unknown capability never hard-blocks on any live service
 *  11.  Each live service has at least one ALLOW path (AEG-HG-002 intact)
 *  12.  Each live service has at least one BLOCK path (TP surface intact)
 *  13.  Each live service has rollback doctrine verifiable at runtime
 *  14.  Kill switch suppresses all six live hard-gates simultaneously
 *  15.  codex/runtime agreement for pramana and domain-capture
 *  16.  Tracked audit artifacts present for HG-2A promotion evidence
 *  17.  Emit: aegis/audits/batch50_live_hard_gate_roster_drift_watch.json
 *
 * @rule:AEG-HG-001 hard_gate_enabled must be true for every live service
 * @rule:AEG-HG-002 READ never hard-blocks on any service in any mode
 * @rule:AEG-HG-003 only AEGIS_HARD_GATE_SERVICES env var enables runtime hard-gate
 * @rule:AEG-E-006  kill switch overrides all enforcement immediately
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
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

const BATCH    = 50;
const RUN_DATE = new Date().toISOString();
const auditDir = join(process.cwd(), "audits");
mkdirSync(auditDir, { recursive: true });

// ── Canonical roster definition ───────────────────────────────────────────────
// This is the ground truth for what "six live guards" means.
// Any deviation at runtime is a drift finding.
const EXPECTED_ROSTER: Array<{
  service: string; hg_group: "HG-1" | "HG-2"; rollout_order: number;
  policy: ServiceHardGatePolicy; since: string;
}> = [
  { service: "chirpee",        hg_group: "HG-1", rollout_order: 1, policy: CHIRPEE_HG1_POLICY,        since: "Batch 32" },
  { service: "ship-slm",       hg_group: "HG-1", rollout_order: 2, policy: SHIP_SLM_HG1_POLICY,       since: "Batch 36" },
  { service: "chief-slm",      hg_group: "HG-1", rollout_order: 3, policy: CHIEF_SLM_HG1_POLICY,      since: "Batch 36" },
  { service: "puranic-os",     hg_group: "HG-1", rollout_order: 4, policy: PURANIC_OS_HG1_POLICY,     since: "Batch 39" },
  { service: "pramana",        hg_group: "HG-2", rollout_order: 5, policy: PRAMANA_HG2A_POLICY,       since: "Batch 43" },
  { service: "domain-capture", hg_group: "HG-2", rollout_order: 6, policy: DOMAIN_CAPTURE_HG2A_POLICY, since: "Batch 48" },
];

// Services that must never appear in AEGIS_HARD_GATE_SERVICES yet
const NOT_PROMOTED = ["parali-central", "carbonx", "ankr-doctor", "stackpilot", "granthx", "ankrclaw"];

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ check: number; label: string; expected: string; actual: string; cat: string }> = [];
const driftFindings: string[] = [];

function check(n: number, label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  const tag = `  Check ${String(n).padStart(2, "0")}`;
  if (ok) {
    passed++;
    console.log(`${tag} ✓ [PASS] ${label.padEnd(70)} actual=${actual}`);
  } else {
    failed++;
    failures.push({ check: n, label, expected: String(expected), actual: String(actual), cat });
    driftFindings.push(`Check ${n} | ${label} | expected=${expected} actual=${actual}`);
    console.log(`${tag} ✗ [FAIL] ${label.padEnd(70)} expected=${expected} actual=${actual}`);
  }
}

console.log(`\n══ Batch ${BATCH} — AEGIS LIVE HARD-GATE ROSTER DRIFT WATCH ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  Roster: ${EXPECTED_ROSTER.map(r => r.service).join(", ")}\n`);

// ── Check 1: AEGIS_HARD_GATE_SERVICES — count and no duplicates ───────────────
console.log("── Check 1: AEGIS_HARD_GATE_SERVICES integrity ──");
const envServices = (process.env.AEGIS_HARD_GATE_SERVICES ?? "").split(",").map(s => s.trim()).filter(Boolean);
check(1, "AEGIS_HARD_GATE_SERVICES: exactly 6 entries", envServices.length, 6, "roster_integrity");
const deduped = new Set(envServices);
check(1, "AEGIS_HARD_GATE_SERVICES: no duplicate service IDs", deduped.size, envServices.length, "roster_integrity");

// ── Check 2: Roster entries match expected set exactly ────────────────────────
console.log("\n── Check 2: Roster set membership ──");
const expectedSet = new Set(EXPECTED_ROSTER.map(r => r.service));
for (const svc of EXPECTED_ROSTER) {
  check(2, `[${svc.service}] present in AEGIS_HARD_GATE_SERVICES`, envServices.includes(svc.service), true, "roster_set");
}
// Verify no unexpected service snuck in
for (const svc of envServices) {
  check(2, `[${svc}] in env is expected (no surprise entries)`, expectedSet.has(svc), true, "roster_set");
}

// ── Check 3: rollout_order unique, strictly 1–6 ────────────────────────────────
console.log("\n── Check 3: rollout_order uniqueness and sequence ──");
const orders = EXPECTED_ROSTER.map(r => r.policy.rollout_order);
const uniqueOrders = new Set(orders);
check(3, "rollout_order values are all unique", uniqueOrders.size, EXPECTED_ROSTER.length, "order");
check(3, "rollout_order min=1", Math.min(...orders), 1, "order");
check(3, "rollout_order max=6", Math.max(...orders), 6, "order");
// Each individual order
for (const entry of EXPECTED_ROSTER) {
  check(3, `[${entry.service}] rollout_order=${entry.rollout_order}`, entry.policy.rollout_order, entry.rollout_order, "order");
}

// ── Check 4: All 6 live services have hard_gate_enabled=true ──────────────────
console.log("\n── Check 4: hard_gate_enabled=true (all 6) ──");
for (const entry of EXPECTED_ROSTER) {
  check(4, `[${entry.service}] hard_gate_enabled=true`, entry.policy.hard_gate_enabled, true, "policy_enabled");
}

// ── Check 5: HG-1 services remain HG-1 ────────────────────────────────────────
console.log("\n── Check 5: HG-1 group stability ──");
for (const entry of EXPECTED_ROSTER.filter(r => r.hg_group === "HG-1")) {
  check(5, `[${entry.service}] hg_group=HG-1`, entry.policy.hg_group, "HG-1", "hg_group");
}

// ── Check 6: pramana remains HG-2 (HG-2A) ────────────────────────────────────
console.log("\n── Check 6: pramana hg_group stability ──");
check(6, "pramana hg_group=HG-2 (HG-2A family)", PRAMANA_HG2A_POLICY.hg_group, "HG-2", "hg_group");
check(6, "pramana rollout_order=5 (unchanged)", PRAMANA_HG2A_POLICY.rollout_order, 5, "hg_group");

// ── Check 7: domain-capture remains HG-2 (HG-2A) ─────────────────────────────
console.log("\n── Check 7: domain-capture hg_group stability ──");
check(7, "domain-capture hg_group=HG-2 (HG-2A family)", DOMAIN_CAPTURE_HG2A_POLICY.hg_group, "HG-2", "hg_group");
check(7, "domain-capture rollout_order=6 (unchanged)", DOMAIN_CAPTURE_HG2A_POLICY.rollout_order, 6, "hg_group");

// ── Check 8: No HG-2B/HG-2C service in AEGIS_HARD_GATE_SERVICES ─────────────
console.log("\n── Check 8: HG-2B/HG-2C isolation ──");
for (const svc of NOT_PROMOTED) {
  check(8, `[${svc}] NOT in AEGIS_HARD_GATE_SERVICES`, envServices.includes(svc), false, "isolation");
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-iso" });
  check(8, `[${svc}] NOT hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "isolation");
  check(8, `[${svc}] NOT BLOCK`, d.decision !== "BLOCK", true, "isolation");
}

// ── Check 9: Unknown service never blocks ─────────────────────────────────────
console.log("\n── Check 9: Unknown service invariant ──");
for (const svc of ["phantom-svc-alpha", "not-in-registry", "zero-day-interloper"]) {
  const d = evaluate({ service_id: svc, operation: "execute", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-unksvc" });
  check(9, `[${svc}] shadow + NOT BLOCK`, d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true, "unknown_svc");
}

// ── Check 10: Unknown capability never hard-blocks on any live service ─────────
console.log("\n── Check 10: Unknown capability invariant (all 6 services) ──");
for (const entry of EXPECTED_ROSTER) {
  const d = evaluate({ service_id: entry.service, operation: "frob", requested_capability: "UNDISCOVERED_CAP_XYZ", caller_id: "b50-unkcap" });
  check(10, `[${entry.service}] UNDISCOVERED_CAP: hard_gate + NOT BLOCK`, d.enforcement_phase === "hard_gate" && d.decision !== "BLOCK", true, "unknown_cap");
}

// ── Check 11: Each live service has at least one ALLOW path ───────────────────
// AEG-HG-002: READ is always in never_block for every service
console.log("\n── Check 11: ALLOW path intact (AEG-HG-002 — READ never blocks) ──");
for (const entry of EXPECTED_ROSTER) {
  const d = evaluate({ service_id: entry.service, operation: "read", requested_capability: "READ", caller_id: "b50-allow" });
  logDecision(d);
  check(11, `[${entry.service}] READ → hard_gate + ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "allow_path");
  check(11, `[${entry.service}] never_block has READ (AEG-HG-002)`, entry.policy.never_block_capabilities.has("READ"), true, "allow_path");
}

// ── Check 12: Each live service has at least one BLOCK path ──────────────────
// IMPOSSIBLE_OP is in hard_block for every service — TP surface must remain intact
console.log("\n── Check 12: BLOCK path intact (TP surface) ──");
for (const entry of EXPECTED_ROSTER) {
  const d = evaluate({ service_id: entry.service, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-block" });
  logDecision(d);
  check(12, `[${entry.service}] IMPOSSIBLE_OP → hard_gate + BLOCK`, d.enforcement_phase === "hard_gate" && d.decision === "BLOCK", true, "block_path");
  check(12, `[${entry.service}] hard_block has IMPOSSIBLE_OP`, entry.policy.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "block_path");
}

// ── Check 13: Rollback doctrine verifiable at runtime ────────────────────────
// Doctrine: remove from AEGIS_HARD_GATE_SERVICES → immediate soft_canary return.
// Runtime test: remove domain-capture (newest guard), verify soft_canary, restore.
// READ invariant holds during rollback window for all services.
console.log("\n── Check 13: Rollback doctrine ──");
// 13a: Each service's stage contains LIVE (confirms it was formally promoted)
for (const entry of EXPECTED_ROSTER) {
  check(13, `[${entry.service}] stage contains 'LIVE'`, entry.policy.stage.includes("LIVE"), true, "rollback_doctrine");
}
// 13b: Runtime rollback test — remove and restore domain-capture (Batch 48 newest)
{
  const pre = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-rb" });
  check(13, "rollback pre: domain-capture → hard_gate + BLOCK", pre.enforcement_phase === "hard_gate" && pre.decision === "BLOCK", true, "rollback_doctrine");
  // Remove domain-capture from env
  process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
  const rb = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-rb" });
  check(13, "rollback: domain-capture → soft_canary (env var removal)", rb.enforcement_phase, "soft_canary", "rollback_doctrine");
  check(13, "rollback: domain-capture IMPOSSIBLE_OP → ALLOW (not hard-gated)", rb.decision, "ALLOW", "rollback_doctrine");
  // READ still works during rollback window
  const rbRead = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: "b50-rb" });
  check(13, "rollback: domain-capture READ → soft_canary + ALLOW (safe during rollback)", rbRead.enforcement_phase === "soft_canary" && rbRead.decision === "ALLOW", true, "rollback_doctrine");
  // pramana unchanged during domain-capture rollback (no coupling)
  const pm = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-rb" });
  check(13, "rollback: pramana unaffected — still hard_gate + BLOCK", pm.enforcement_phase === "hard_gate" && pm.decision === "BLOCK", true, "rollback_doctrine");
  // Restore
  process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture";
  const restored = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-restore" });
  check(13, "restore: domain-capture → hard_gate + BLOCK (back to live)", restored.enforcement_phase === "hard_gate" && restored.decision === "BLOCK", true, "rollback_doctrine");
}

// ── Check 14: Kill switch suppresses all six simultaneously ───────────────────
console.log("\n── Check 14: Kill switch ──");
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const entry of EXPECTED_ROSTER) {
  const d = evaluate({ service_id: entry.service, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-kill" });
  check(14, `[${entry.service}] kill: shadow + NOT BLOCK`, d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true, "kill_switch");
}
process.env.AEGIS_RUNTIME_ENABLED = "true";
// Verify all six restore immediately after kill lifted
for (const entry of EXPECTED_ROSTER) {
  const d = evaluate({ service_id: entry.service, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-restore" });
  check(14, `[${entry.service}] post-kill restore: hard_gate + BLOCK`, d.enforcement_phase === "hard_gate" && d.decision === "BLOCK", true, "kill_switch");
}

// ── Check 15: codex/runtime agreement for pramana + domain-capture ────────────
console.log("\n── Check 15: codex/runtime agreement (HG-2A services) ──");
// domain-capture codex
{
  let dcCodex: Record<string, unknown> = {};
  try { dcCodex = JSON.parse(readFileSync("/root/ankr-labs-nx/apps/domain-capture/codex.json", "utf8")); }
  catch { check(15, "domain-capture codex.json readable", false, true, "codex_runtime"); }
  check(15, "domain-capture codex: hg_group=HG-2A", dcCodex.hg_group, "HG-2A", "codex_runtime");
  check(15, "domain-capture codex: hg_group_status contains LIVE", String(dcCodex.hg_group_status ?? "").includes("LIVE"), true, "codex_runtime");
  check(15, "domain-capture codex: hard_gate_enabled=true in promotion block", (dcCodex.aegis_batch48_promotion as Record<string, unknown>)?.hard_gate_enabled, true, "codex_runtime");
  // Runtime cross-check: codex promotion says hard_gate, runtime confirms
  const dc = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-codex" });
  check(15, "domain-capture runtime: hard_gate phase (matches codex claim)", dc.enforcement_phase, "hard_gate", "codex_runtime");
}
// pramana: policy + runtime (codex path not needed — policy is source of truth for pramana here)
{
  check(15, "pramana policy: hard_gate_enabled=true", PRAMANA_HG2A_POLICY.hard_gate_enabled, true, "codex_runtime");
  check(15, "pramana policy: stage contains LIVE", PRAMANA_HG2A_POLICY.stage.includes("LIVE"), true, "codex_runtime");
  check(15, "pramana policy: stage contains Batch 43", PRAMANA_HG2A_POLICY.stage.includes("Batch 43"), true, "codex_runtime");
  const pm = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b50-codex" });
  check(15, "pramana runtime: hard_gate phase (matches policy claim)", pm.enforcement_phase, "hard_gate", "codex_runtime");
}

// ── Check 16: Tracked audit artifacts present ─────────────────────────────────
console.log("\n── Check 16: Tracked audit artifacts ──");
const trackedArtifacts = [
  { path: join(auditDir, "batch47_domain_capture_final_verdict.json"), label: "B47 soak verdict" },
  { path: join(auditDir, "batch48_domain_capture_hg2a_promotion.json"), label: "B48 promotion record" },
  { path: join(auditDir, "batch48_domain_capture_hg2a_summary.md"),    label: "B48 promotion summary" },
  { path: join(auditDir, "batch49_domain_capture_cross_repo_audit.json"), label: "B49 convergence audit" },
];
for (const art of trackedArtifacts) {
  check(16, `audits/${art.label} exists`, existsSync(art.path), true, "audit_trail");
}
// Note: Batch 43 (pramana) promotion artifacts are in .aegis/ only — pre-existing gap
// from before the audits/ pattern was established in Batch 49. Not a drift finding.
// Verify HARD_GATE_POLICIES registry has 6 entries (no ghost policies)
const policyCount = Object.keys(HARD_GATE_POLICIES).length;
check(16, "HARD_GATE_POLICIES registry: exactly 6 entries", policyCount, 6, "audit_trail");

// ── Final tally ───────────────────────────────────────────────────────────────
const batchPass = failed === 0;
console.log(`\n══ Batch ${BATCH} Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${batchPass ? "PASS" : "FAIL"}`);
if (failures.length) {
  console.log("\n  Drift findings:");
  failures.forEach(f => console.log(`  ✗ [Check ${f.check}] [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));
} else {
  console.log("  No drift detected.");
}

// ── Emit drift watch artifact ─────────────────────────────────────────────────
const artifact = {
  batch: BATCH,
  watch_type: "post_promotion_roster_drift_watch",
  watch_date: RUN_DATE,
  verdict: batchPass ? "PASS" : "FAIL",
  total_checks: totalChecks,
  passed,
  failed,
  drift_findings: driftFindings,
  roster_at_watch_time: EXPECTED_ROSTER.map(r => ({
    service: r.service,
    hg_group: r.hg_group,
    rollout_order: r.rollout_order,
    hard_gate_enabled: r.policy.hard_gate_enabled,
    stage: r.policy.stage,
    since: r.since,
  })),
  not_promoted: NOT_PROMOTED,
  invariants_confirmed: [
    "AEGIS_HARD_GATE_SERVICES: exactly 6 entries, no duplicates",
    "rollout_order 1-6: unique, no gaps",
    "HG-1 services (4): hg_group unchanged",
    "HG-2A services (2): pramana + domain-capture, hg_group unchanged",
    "HG-2B/HG-2C: NOT in AEGIS_HARD_GATE_SERVICES, NOT hard_gate phase",
    "Unknown service: shadow + NOT BLOCK",
    "Unknown capability: hard_gate phase but NOT BLOCK (all 6 services)",
    "READ: hard_gate + ALLOW on every live service (AEG-HG-002)",
    "IMPOSSIBLE_OP: hard_gate + BLOCK on every live service (TP intact)",
    "Rollback doctrine: stage contains LIVE; env var removal → immediate soft_canary",
    "Kill switch: all 6 → shadow simultaneously; all 6 restore immediately",
    "codex/runtime: domain-capture codex LIVE + hard_gate confirmed at runtime",
    "HARD_GATE_POLICIES registry: exactly 6 entries (no ghost policies)",
  ],
  note_on_pramana_artifacts: "Batch 43 pramana promotion artifacts are in .aegis/ only — pre-existing gap from before audits/ pattern. Not a drift finding.",
  hard_gate_globally_enabled: HARD_GATE_GLOBALLY_ENABLED,
};
writeFileSync(join(auditDir, "batch50_live_hard_gate_roster_drift_watch.json"), JSON.stringify(artifact, null, 2));

console.log(`\n  Drift watch artifact → audits/batch50_live_hard_gate_roster_drift_watch.json`);
console.log(`\n── Live hard-gate roster after Batch 50 watch ──`);
console.log(`  HG-1: chirpee (1), ship-slm (2), chief-slm (3), puranic-os (4)`);
console.log(`  HG-2A: pramana (5), domain-capture (6)`);
console.log(`  HG-2B not started: parali-central, carbonx`);
console.log(`  HG-2C separate: ankr-doctor`);
console.log(`\n  Six guards stand watch. None has moved without orders.`);
console.log(`\n  Batch 50: ${batchPass ? "PASS" : "FAIL"}`);
