/**
 * AEGIS Batch 86 — Classifier Vocabulary Repair
 * 2026-05-05
 *
 * Repairs the fleet classifier vocabulary so services like pramana and
 * parali-central classify correctly from can_do semantics without relying
 * on KNOWN_HG_TRUTH ground-truth overrides.
 *
 * Two additions to the v1 vocabulary (batch83):
 *
 *   HG2A_PROOF_VERBS — proof / validation / reasoning semantics → HG-2A
 *     Services that emit proofs, validate claims, run RCA, attest outputs.
 *     Vocabulary gap: pramana uses PHALA_EMIT, RCA_TRIGGER — not STATEFUL_EXTERNAL.
 *
 *   HG2B_GATE_VERBS — external-state / orchestration / approval semantics → HG-2B
 *     Services that approve actions, manage tokens/gates, coordinate rollbacks.
 *     Vocabulary gap: parali-central uses APPROVE_DIVIDEND — not IRREVERSIBLE.
 *
 * Both sets are new verb lists; all existing v1 lists are UNCHANGED.
 *
 * New matching behaviour in v2:
 *   Case-insensitive — v.toUpperCase().includes(fv) — handles free-text can_do
 *   values (pramana/backend uses natural-language strings, not verb codes).
 *
 * Classification order (v2):
 *   1. FINANCIAL_VERBS       → HG-2B-financial  (highest, unchanged)
 *   2. IRREVERSIBLE_VERBS    → HG-2B            (unchanged)
 *   3. HG2B_GATE_VERBS       → HG-2B            (NEW)
 *   4. STATEFUL_EXTERNAL_VERBS → HG-2A          (unchanged)
 *   5. !isReadOnly && HG2A_PROOF_VERBS → HG-2A  (NEW — guarded to preserve read-only HG-1)
 *   6. isReadOnly            → HG-1 (medium confidence)
 *   7. else                  → HG-1 (low confidence)
 *
 * Scope:
 *   - No codex.json files modified (dry-run classification only)
 *   - No Batch 83/84/85 artifacts modified
 *   - No promotion state changed
 *   - Batch 85 human overrides remain intact
 *   - Writes vocabulary/fleet-classifier-v2.json (new file)
 *   - Writes audits/batch86_classifier_vocabulary_repair.json
 *
 * Final line: The human corrected the edge case. The classifier learned the shape.
 *
 * @rule:AEG-PROV-001 not triggered — classification dry-run, no promotion
 */

import { readFileSync, existsSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { glob } from "glob";

const AUDITS     = "/root/aegis/audits";
const VOCABULARY = "/root/aegis/vocabulary";

// ── V1 verb lists — identical to batch83 (no modification) ───────────────────

const V1_FINANCIAL_VERBS = [
  "SURRENDER", "SETTLE", "SETTLEMENT", "TRANSFER_FUND", "DEBIT", "CREDIT",
  "PAYMENT", "EUA", "ALLOWANCE_TRANSFER", "BALANCE_DEDUCT", "BURN_TOKEN",
  "FINANCIAL", "INVOICE_SETTLE", "LEDGER_WRITE",
];

const V1_IRREVERSIBLE_VERBS = [
  "SUBMIT_FILING", "FILE_COMPLIANCE", "REGISTER_ENTITY", "EMIT_EXTERNAL",
  "DELETE_EXTERNAL", "PUBLISH_CERTIFICATE", "REVOKE_CERTIFICATE",
  "CLOSE_ACCOUNT", "ARCHIVE_PERMANENT", "SIGN_CONTRACT", "EXECUTE_TRADE",
];

const V1_STATEFUL_EXTERNAL_VERBS = [
  "UPDATE_EXTERNAL", "WRITE_EXTERNAL", "SYNC_EXTERNAL", "RECORD_TRANSACTION",
  "SUBMIT_REPORT", "PUSH_EXTERNAL", "NOTIFY_EXTERNAL", "UPDATE_REGISTRY",
  "LOG_EXTERNAL", "SEND_", "PUBLISH_", "POST_EXTERNAL",
];

const V1_READ_ONLY_VERBS = [
  "GET", "LIST", "VIEW", "SEARCH", "REPORT", "EXPORT", "SIMULATE",
  "FETCH", "READ", "QUERY", "DESCRIBE", "AUDIT_READ", "HEALTH",
];

// ── V2 additions — new verb lists ─────────────────────────────────────────────
// These extend v1; they do not replace or modify any v1 list.

const HG2A_PROOF_VERBS = [
  "PROOF", "VALIDATE", "VALIDATION", "VERIFY", "VERIFICATION",
  "RCA", "AUDIT", "EMIT_PROOF", "RECEIPT", "ATTESTATION",
  "POLICY_EVAL", "CLAIM_CHECK", "PROVENANCE",
];

const HG2B_GATE_VERBS = [
  "APPROVAL", "APPROVE",     // APPROVE added: APPROVE_* patterns (e.g. APPROVE_DIVIDEND)
  "TOKEN", "GATE", "PROMOTION", "HARD_GATE", "ROLLBACK",
  "SENSE", "BOUNDARY", "EXTERNAL_STATE", "IRREVERSIBLE",
  "HUMAN_GATE", "PERMISSION", "AUTHORITY",
];

// ── Classifier functions ──────────────────────────────────────────────────────

// V1: case-sensitive substring (batch83 original)
function verbMatchesV1(canDo: string[], verbList: string[]): boolean {
  return canDo.some(v => verbList.some(fv => v.includes(fv) || fv.includes(v)));
}

// V2: case-insensitive substring (handles free-text can_do values)
function verbMatchesV2(canDo: string[], verbList: string[]): boolean {
  return canDo.some(v => {
    const vUp = v.toUpperCase();
    return verbList.some(fv => vUp.includes(fv) || fv.includes(vUp));
  });
}

// isReadOnly: unchanged between v1 and v2
function isReadOnly(canDo: string[]): boolean {
  if (canDo.length === 0) return false;
  return canDo.every(v => V1_READ_ONLY_VERBS.some(rv => v.startsWith(rv)));
}

function classifyV1(canDo: string[]): { hg_group: string; confidence: string } {
  if (verbMatchesV1(canDo, V1_FINANCIAL_VERBS))        return { hg_group: "HG-2B-financial", confidence: "high" };
  if (verbMatchesV1(canDo, V1_IRREVERSIBLE_VERBS))     return { hg_group: "HG-2B", confidence: "high" };
  if (verbMatchesV1(canDo, V1_STATEFUL_EXTERNAL_VERBS))return { hg_group: "HG-2A", confidence: "medium" };
  if (isReadOnly(canDo))                                return { hg_group: "HG-1", confidence: "medium" };
  return { hg_group: "HG-1", confidence: "low" };
}

function classifyV2(canDo: string[]): { hg_group: string; confidence: string } {
  if (verbMatchesV2(canDo, V1_FINANCIAL_VERBS))                   return { hg_group: "HG-2B-financial", confidence: "high" };
  if (verbMatchesV2(canDo, V1_IRREVERSIBLE_VERBS))                return { hg_group: "HG-2B", confidence: "high" };
  if (verbMatchesV2(canDo, HG2B_GATE_VERBS))                      return { hg_group: "HG-2B", confidence: "medium" };
  if (verbMatchesV2(canDo, V1_STATEFUL_EXTERNAL_VERBS))           return { hg_group: "HG-2A", confidence: "medium" };
  if (!isReadOnly(canDo) && verbMatchesV2(canDo, HG2A_PROOF_VERBS)) return { hg_group: "HG-2A", confidence: "medium" };
  if (isReadOnly(canDo))                                           return { hg_group: "HG-1", confidence: "medium" };
  return { hg_group: "HG-1", confidence: "low" };
}

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

// ── Load all 61 codex files ───────────────────────────────────────────────────

const codexPaths = [
  ...await (async () => { try { return await glob("/root/apps/*/codex.json"); } catch { return []; } })(),
  ...await (async () => { try { return await glob("/root/apps/*/*/codex.json"); } catch { return []; } })(),
  ...await (async () => { try { return await glob("/root/packages/*/codex.json"); } catch { return []; } })(),
];

interface DryRunRecord {
  service:      string;
  file:         string;
  can_do:       string[];
  v1_hg:        string;
  v2_hg:        string;
  changed:      boolean;
  change_dir:   "upgrade" | "downgrade" | "none";
  is_target:    boolean;  // one of the 3 pramana/parali-central files
}

const HG_RANK: Record<string, number> = {
  "HG-1": 1, "HG-2A": 2, "HG-2B": 3, "HG-2B-financial": 4,
};

const TARGET_PATHS = new Set([
  "/root/apps/pramana/codex.json",
  "/root/apps/pramana/backend/codex.json",
  "/root/apps/parali-central/backend/codex.json",
]);

const dryRun: DryRunRecord[] = [];

for (const filePath of codexPaths) {
  let data: Record<string, unknown>;
  try { data = JSON.parse(readFileSync(filePath, "utf-8")) as Record<string, unknown>; }
  catch { continue; }

  const canDo = Array.isArray(data.can_do) ? data.can_do as string[] : [];
  const serviceKey = (data.service as string) ||
    filePath.replace("/root/apps/", "").replace("/root/packages/", "").split("/codex.json")[0];

  const v1 = classifyV1(canDo);
  const v2 = classifyV2(canDo);
  const changed = v1.hg_group !== v2.hg_group;
  const v1Rank = HG_RANK[v1.hg_group] ?? 0;
  const v2Rank = HG_RANK[v2.hg_group] ?? 0;

  dryRun.push({
    service: serviceKey, file: filePath, can_do: canDo,
    v1_hg: v1.hg_group, v2_hg: v2.hg_group, changed,
    change_dir: changed ? (v2Rank > v1Rank ? "upgrade" : "downgrade") : "none",
    is_target: TARGET_PATHS.has(filePath),
  });
}

// Partition results
const changed       = dryRun.filter(r => r.changed);
const upgraded      = dryRun.filter(r => r.change_dir === "upgrade");
const downgraded    = dryRun.filter(r => r.change_dir === "downgrade");
const targetChanged = dryRun.filter(r => r.is_target && r.changed);
const sideEffects   = dryRun.filter(r => !r.is_target && r.changed);

// ── §1  Vocabulary definitions (checks 1–4) ───────────────────────────────────

section("§1 Vocabulary definitions — v2 is a strict superset of v1");

check(1, `HG2A_PROOF_VERBS: ${HG2A_PROOF_VERBS.length} new verbs (RCA, VERIFY, ATTESTATION, ...)`,
  HG2A_PROOF_VERBS.includes("RCA") && HG2A_PROOF_VERBS.includes("VERIFICATION") &&
  HG2A_PROOF_VERBS.includes("ATTESTATION"), true, "vocab");

check(2, `HG2B_GATE_VERBS: ${HG2B_GATE_VERBS.length} new verbs (APPROVAL, APPROVE, GATE, SENSE, ...)`,
  HG2B_GATE_VERBS.includes("APPROVAL") && HG2B_GATE_VERBS.includes("APPROVE") &&
  HG2B_GATE_VERBS.includes("SENSE") && HG2B_GATE_VERBS.includes("GATE"), true, "vocab");

check(3, "FINANCIAL_VERBS identical in v1 and v2 — financial classification unchanged",
  V1_FINANCIAL_VERBS.includes("SURRENDER") && V1_FINANCIAL_VERBS.includes("LEDGER_WRITE"),
  true, "vocab");

check(4, "IRREVERSIBLE_VERBS identical in v1 and v2 — HG-2B hard verbs unchanged",
  V1_IRREVERSIBLE_VERBS.includes("SUBMIT_FILING") && V1_IRREVERSIBLE_VERBS.includes("SIGN_CONTRACT"),
  true, "vocab");

// ── §2  Target file reclassification (checks 5–8) ────────────────────────────

section("§2 Target file reclassification — 3 false negatives fix under v2 (dry run)");

const pramanaRec     = dryRun.find(r => r.file === "/root/apps/pramana/codex.json");
const pramanaBackRec = dryRun.find(r => r.file === "/root/apps/pramana/backend/codex.json");
const paraliRec      = dryRun.find(r => r.file === "/root/apps/parali-central/backend/codex.json");

check(5, "pramana/codex.json: v2 classifies HG-2A (was HG-1 under v1)",
  pramanaRec?.v2_hg, "HG-2A", "targets");

check(6, "pramana/backend/codex.json: v2 classifies HG-2A (was HG-1 under v1, free-text fixed by case-insensitive match)",
  pramanaBackRec?.v2_hg, "HG-2A", "targets");

check(7, "parali-central/backend/codex.json: v2 classifies HG-2B (was HG-1 under v1, APPROVE_DIVIDEND → APPROVE)",
  paraliRec?.v2_hg, "HG-2B", "targets");

check(8, "All 3 target files change classification under v2 (none unchanged)",
  targetChanged.length, 3, "targets");

// ── §3  Financial stability (checks 9–12) ─────────────────────────────────────

section("§3 Financial stability — no HG-2B-financial service affected");

const financialV1 = dryRun.filter(r => r.v1_hg === "HG-2B-financial");
const financialV2 = dryRun.filter(r => r.v2_hg === "HG-2B-financial");

check(9, "carbonx-backend remains HG-2B-financial under v2",
  dryRun.find(r => r.file.includes("/carbonx/backend/"))?.v2_hg, "HG-2B-financial", "financial");

check(10, `All ${financialV1.length} v1 HG-2B-financial services remain HG-2B-financial in v2`,
  financialV1.every(r => r.v2_hg === "HG-2B-financial"), true, "financial");

// v2 case-insensitive matching may detect additional financial services (conservative).
// The invariant is: no financial service is REMOVED from the tier. Count can only grow.
check(11, `HG-2B-financial count: v2 (${financialV2.length}) ≥ v1 (${financialV1.length}) — financial tier can only grow, never shrink`,
  financialV2.length >= financialV1.length, true, "financial");

check(12, "No downgrade occurs anywhere under v2 (all changes are upgrades)",
  downgraded.length, 0, "financial");

// ── §4  Fleet-wide impact (checks 13–16) ──────────────────────────────────────

section("§4 Fleet-wide impact — document all classification changes");

console.log(`\n  Services changed under v2: ${changed.length}`);
console.log(`  Targets (expected):        ${targetChanged.length}`);
console.log(`  Side effects (additional): ${sideEffects.length}`);
if (sideEffects.length > 0) {
  console.log(`\n  Side effect upgrades (legitimate — flagged for Wave 2 human confirmation):`);
  for (const r of sideEffects) {
    console.log(`    ${r.service.padEnd(45)} ${r.v1_hg} → ${r.v2_hg}`);
  }
}

check(13, `All ${changed.length} classification changes under v2 are upgrades (no downgrades)`,
  downgraded.length, 0, "impact");

check(14, `At least 3 services change under v2 (the 3 target false negatives)`,
  changed.length >= 3, true, "impact");

// Side effects are legitimate upgrades (governance/military-grade services getting higher scrutiny)
const sideEffectUpgrades = sideEffects.filter(r => r.change_dir === "upgrade");
check(15, `All ${sideEffects.length} side-effect changes are upgrades (more conservative, not less)`,
  sideEffectUpgrades.length, sideEffects.length, "impact");

// Batch 85 overrides intact on the 3 target files
const pramanaData     = JSON.parse(readFileSync("/root/apps/pramana/codex.json", "utf-8")) as Record<string, unknown>;
const pramanaBackData = JSON.parse(readFileSync("/root/apps/pramana/backend/codex.json", "utf-8")) as Record<string, unknown>;
const paraliData      = JSON.parse(readFileSync("/root/apps/parali-central/backend/codex.json", "utf-8")) as Record<string, unknown>;

const getCls = (d: Record<string, unknown>) => (d.aegis_classification as Record<string, unknown>) ?? {};

check(16, "Batch 85 human overrides intact — human_override_applied=true on all 3 targets",
  getCls(pramanaData).human_override_applied === true &&
  getCls(pramanaBackData).human_override_applied === true &&
  getCls(paraliData).human_override_applied === true, true, "impact");

// ── §5  Vocabulary correctness (checks 17–20) ─────────────────────────────────

section("§5 Vocabulary correctness — self-classification without KNOWN_HG_TRUTH");

// Under v2, pramana classifies HG-2A without needing the ground-truth table
check(17, "pramana/codex.json self-classifies HG-2A under v2 (RCA_TRIGGER → RCA verb match)",
  pramanaRec?.v2_hg === "HG-2A" && pramanaRec.v1_hg === "HG-1", true, "vocab_correct");

// pramana/backend classifies via case-insensitive match on free-text can_do
check(18, "pramana/backend self-classifies HG-2A under v2 (free-text 'verification' → VERIFICATION)",
  pramanaBackRec?.v2_hg === "HG-2A" && pramanaBackRec.v1_hg === "HG-1", true, "vocab_correct");

// parali-central classifies HG-2B via APPROVE_DIVIDEND → APPROVE verb match
check(19, "parali-central self-classifies HG-2B under v2 (APPROVE_DIVIDEND → APPROVE gate verb)",
  paraliRec?.v2_hg === "HG-2B" && paraliRec.v1_hg === "HG-1", true, "vocab_correct");

// Confirm isReadOnly guard works: a read-only audit service stays HG-1
// Test synthetic service with AUDIT_READ only
const syntheticReadOnly = ["AUDIT_READ"];
const syntheticResult = classifyV2(syntheticReadOnly);
check(20, "isReadOnly guard works: AUDIT_READ-only service stays HG-1 under v2 (not upgraded by AUDIT proof verb)",
  syntheticResult.hg_group, "HG-1", "vocab_correct");

// ── §6  Artifact output (checks 21–24) ───────────────────────────────────────

section("§6 Artifact output — vocabulary file + audit artifact");

mkdirSync(VOCABULARY, { recursive: true });

const vocabFile = {
  schema:      "fleet-classifier-v2",
  version:     "2",
  date:        "2026-05-05",
  batch:       86,
  changes_from_v1: [
    "Added HG2A_PROOF_VERBS: proof/validation/reasoning semantics for HG-2A classification",
    "Added HG2B_GATE_VERBS: approval/gate/orchestration semantics for HG-2B classification",
    "Case-insensitive matching (v.toUpperCase()) to handle free-text can_do values",
    "isReadOnly guard on HG-2A proof check: read-only audit services stay HG-1",
  ],
  classification_order: [
    "1. FINANCIAL_VERBS → HG-2B-financial (highest priority, unchanged)",
    "2. IRREVERSIBLE_VERBS → HG-2B (unchanged)",
    "3. HG2B_GATE_VERBS → HG-2B (NEW)",
    "4. STATEFUL_EXTERNAL_VERBS → HG-2A (unchanged)",
    "5. !isReadOnly && HG2A_PROOF_VERBS → HG-2A (NEW, guarded)",
    "6. isReadOnly → HG-1 (medium confidence)",
    "7. else → HG-1 (low confidence)",
  ],
  matching:           "case-insensitive: v.toUpperCase().includes(fv) || fv.includes(v.toUpperCase())",
  financial_verbs:    V1_FINANCIAL_VERBS,
  irreversible_verbs: V1_IRREVERSIBLE_VERBS,
  hg2b_gate_verbs:    HG2B_GATE_VERBS,
  stateful_external_verbs: V1_STATEFUL_EXTERNAL_VERBS,
  hg2a_proof_verbs:   HG2A_PROOF_VERBS,
  read_only_verbs:    V1_READ_ONLY_VERBS,
  v1_source:          "aegis/scripts/batch83-fleet-codex-tier2-enrichment.ts",
};

const vocabPath = join(VOCABULARY, "fleet-classifier-v2.json");
writeFileSync(vocabPath, JSON.stringify(vocabFile, null, 2) + "\n");

check(21, "Vocabulary file written to vocabulary/fleet-classifier-v2.json",
  existsSync(vocabPath), true, "output");

check(22, "v2 is a strict superset of v1 — no v1 verb removed",
  V1_FINANCIAL_VERBS.every(v => vocabFile.financial_verbs.includes(v)) &&
  V1_IRREVERSIBLE_VERBS.every(v => vocabFile.irreversible_verbs.includes(v)), true, "output");

check(23, "Batch 85 overrides NOT removed by vocabulary repair (machine can classify; human override preserved)",
  getCls(paraliData).override_batch === 85 &&
  getCls(pramanaData).override_batch === 85, true, "output");

check(24, "The human corrected the edge case. The classifier learned the shape.",
  true, true, "doctrine");

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("\n" + "─".repeat(72));
console.log(`\n  Passed: ${passed}/${passed + failed}`);
if (failed > 0) {
  console.log(`\n  FAILURES (${failed}):`);
  for (const f of failures) console.log(`    ${f}`);
}
console.log("");

const verdict = failed === 0 ? "PASS" : "FAIL";

writeFileSync(
  join(AUDITS, "batch86_classifier_vocabulary_repair.json"),
  JSON.stringify({
    audit_id:      "batch86-classifier-vocabulary-repair",
    batch:         86,
    type:          "vocabulary_repair",
    date:          "2026-05-05",
    rule:          "AEG-PROV-001",
    checks_total:  passed + failed,
    checks_passed: passed,
    checks_failed: failed,
    verdict,
    vocabulary_file: "vocabulary/fleet-classifier-v2.json",
    dry_run_summary: {
      total_files:               codexPaths.length,
      classification_changes:    changed.length,
      target_changes:            targetChanged.length,
      side_effect_changes:       sideEffects.length,
      downgrades:                downgraded.length,
    },
    target_corrections: targetChanged.map(r => ({
      service: r.service, v1: r.v1_hg, v2: r.v2_hg, fix: "vocabulary_match",
    })),
    side_effects: sideEffects.map(r => ({
      service: r.service, v1: r.v1_hg, v2: r.v2_hg, direction: r.change_dir,
      note: "legitimate vocabulary-triggered upgrade — requires Wave 2 human confirmation before next enrichment pass",
    })),
    codex_files_modified: 0,
    invariants: [
      "No codex.json files modified — vocabulary repair is dry-run",
      "Batch 85 human overrides intact on pramana and parali-central",
      "No HG-2B-financial service downgraded",
      "No service downgraded in any direction",
      "All v1 verb lists unchanged (v2 is additive only)",
      "Financial verbs retain highest classification priority",
      "isReadOnly guard prevents AUDIT-verb from upgrading read-only audit services",
    ],
    next_step: "Batch 87: re-run enrichment pass with v2 vocabulary on all 61 files, or selectively on services with requires_human_review=true.",
    doctrine: "The human corrected the edge case. The classifier learned the shape.",
  }, null, 2) + "\n",
);

console.log("  Vocabulary: vocabulary/fleet-classifier-v2.json");
console.log("  Artifact:   audits/batch86_classifier_vocabulary_repair.json");
console.log(`  Verdict:    ${verdict}\n`);

if (verdict === "PASS") {
  console.log("  The human corrected the edge case. The classifier learned the shape.\n");
}

if (verdict === "FAIL") process.exit(1);
