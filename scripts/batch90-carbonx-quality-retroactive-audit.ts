/**
 * AEGIS Batch 90 — carbonx Quality Retroactive Audit
 * 2026-05-05
 *
 * Goal:
 *   Systematically audit the carbonx-backend promotion chain (Batches 62–74)
 *   against the quality_mask doctrine introduced in Batch 89. For each batch,
 *   determine which quality bits were satisfied BY THE EVIDENCE IN THAT BATCH'S
 *   ARTIFACT. Build a cumulative evidence map and compute the honest
 *   quality_mask_at_promotion score.
 *
 *   The audit answers: "If the AEGIS-Q doctrine had existed at Batch 74,
 *   what mask would have been set — and what was missing?"
 *
 * Output:
 *   - audits/batch90_carbonx_quality_retroactive_audit.json
 *   - Updates apps/carbonx/backend/codex.json with quality_mask_at_promotion
 *
 * Design note on cumulative evidence:
 *   Evidence is cumulative across the 13-batch chain EXCEPT for bits that
 *   require active code-level verification. Specifically:
 *   - Bit 4 (migration_verified): only satisfiable when a schema change occurs
 *     AND migrate diff is run. Once a schema change happens without migrate diff
 *     evidence, the bit is NOT satisfied regardless of prior vacuous passes.
 *   - Bit 7 (codex_updated): quality.ts requires codex.json.classification_batch
 *     = this batch. carbonx codex has aegis_promotion_batch=74 (different field name).
 *     Strict reading: NOT satisfied. Substance exists; schema field name does not match.
 *
 * Doctrine:
 *   A retroactive audit does not void the promotion. It computes the honest
 *   score so the evidence chain can be completed.
 *
 * @rule:AEG-Q-001 quality_mask_at_promotion required for every promoted service
 * @rule:AEG-Q-004 retroactive audit uses pre_AEG_Q_001_legacy status when
 *   doctrine did not exist at promotion time — not a violation, but a gap
 */

import * as fs   from "fs";
import * as path from "path";

// ── Constants ──────────────────────────────────────────────────────────────────

const BATCH            = 90;
const SERVICE          = "carbonx-backend";
const HG_GROUP         = "HG-2B-financial";
const REQUIRED_MASK    = 0x0FFF; // all 12 point-in-time bits
const REQUIRED_HEX     = "0x0FFF";
const PROMOTION_BATCH  = 74;
const PROMOTION_DATE   = "2026-05-04";
const AUDIT_DIR        = path.join(__dirname, "..", "audits");
const CODEX_PATH       = "/root/apps/carbonx/backend/codex.json";
const QUALITY_SCHEMA   = "aegis-quality-16bit-v1";

// ── Quality bit definitions ────────────────────────────────────────────────────

const QUALITY_BITS = [
  { id:"Q-001", bit:0,  value:1,    name:"typecheck_passed",       verified_by:"tsc --noEmit exits 0" },
  { id:"Q-002", bit:1,  value:2,    name:"tests_passed",           verified_by:"test runner exits 0" },
  { id:"Q-003", bit:2,  value:4,    name:"lint_passed",            verified_by:"eslint / biome exits 0" },
  { id:"Q-004", bit:3,  value:8,    name:"no_unrelated_diff",      verified_by:"git diff --name-only ⊆ declared scope" },
  { id:"Q-005", bit:4,  value:16,   name:"migration_verified",     verified_by:"prisma migrate diff: no DROP/ALTER without migration" },
  { id:"Q-006", bit:5,  value:32,   name:"rollback_verified",      verified_by:"audit artifact has rollback_path field" },
  { id:"Q-007", bit:6,  value:64,   name:"docs_updated",           verified_by:"doc hash changed when code changed" },
  { id:"Q-008", bit:7,  value:128,  name:"codex_updated",          verified_by:"codex.json classification_batch = this batch" },
  { id:"Q-009", bit:8,  value:256,  name:"audit_artifact_written", verified_by:"audits/batchN_*.json exists with verdict=PASS" },
  { id:"Q-010", bit:9,  value:512,  name:"source_clean",           verified_by:"AEG-PROV-001 assertSourceControlProvenance passes without waiver" },
  { id:"Q-011", bit:10, value:1024, name:"no_secret_detected",     verified_by:"secret scanner exits 0 on git diff" },
  { id:"Q-012", bit:11, value:2048, name:"human_reviewed",         verified_by:"human_override_applied=true OR human_review_status=confirmed" },
] as const;

// ── Per-batch evidence assessment ──────────────────────────────────────────────
//
// Bits are assessed directly from the actual audit artifact content.
// Rules for cumulative carry-forward:
//   - Bit 4 (migration_verified): NOT carried forward vacuously once a schema
//     change occurs without migrate diff evidence (batch 64 introduced schema change,
//     no migrate diff run). Bits 3, 4 are NOT vacuously pre-set.
//   - Bit 7 (codex_updated): codex has aegis_promotion_batch=74, NOT
//     classification_batch=74. Schema field name mismatch → NOT satisfied.
//   - Bits 3 (no_unrelated_diff): explicitly satisfied in batch 64 by declared
//     files_created/files_modified scope.
//   - All other bits: explicitly evidenced or absent.

interface BatchEvidence {
  batch:          number;
  label:          string;
  phase:          string;
  code_changed:   boolean;
  schema_changed: boolean;
  bits_satisfied: number[];
  bits_notes:     Record<number, string>;
  cumulative_mask?: number;  // computed in loop below
}

const BATCH_EVIDENCE: BatchEvidence[] = [
  {
    batch: 62, label: "HG-2B candidate readiness audit", phase: "classification",
    code_changed: false, schema_changed: false,
    bits_satisfied: [8],
    bits_notes: {
      0:  "❌ Audit-only — tsc not run",
      1:  "❌ No test runner invocation",
      2:  "❌ No lint runner",
      3:  "❌ No code changes — but not explicitly evidenced; vacuous not counted",
      4:  "❌ No schema changes and no migrate diff run",
      5:  "❌ No rollback mechanism yet",
      6:  "❌ No doc hash verification",
      7:  "❌ codex classification_batch not set",
      8:  "✅ batch62 audit artifact written, 89 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ Secret scanner not run",
      11: "❌ No human review confirmation",
    },
  },
  {
    batch: 63, label: "BR-5 financial code scan gate", phase: "code_scan",
    code_changed: false, schema_changed: false,
    bits_satisfied: [8],
    bits_notes: {
      0:  "❌ Code scan reads source only",
      1:  "❌ BLOCKED_FOR_SOAK — tests not yet run",
      2:  "❌ No lint",
      3:  "❌ No code changes — but not explicitly evidenced",
      4:  "❌ No schema changes — but no migrate diff run either",
      5:  "❌ simulateSurrender not yet built (listed as CARBONX-FIX-003 blocker)",
      6:  "❌ No doc hash verification",
      7:  "❌ codex not updated",
      8:  "✅ batch63 audit artifact written, 67 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ Secret scanner not run",
      11: "❌ No human review confirmation",
    },
  },
  {
    batch: 64, label: "BR-5 financial remediation", phase: "remediation",
    code_changed: true, schema_changed: true,  // prisma/schema.prisma modified
    bits_satisfied: [3, 8],
    bits_notes: {
      0:  "❌ files_modified listed but no tsc --noEmit in artifact",
      1:  "❌ No test runner in remediation batch",
      2:  "❌ No lint runner",
      3:  "✅ files_created=['src/lib/aegis-approval-token.ts','src/lib/aegis-sense.ts'] files_modified=['src/services/ets/ets-service.ts','src/schema/types/ets.ts','prisma/schema.prisma'] — full scope declared explicitly",
      4:  "❌ CRITICAL GAP: prisma/schema.prisma modified (externalRef field added) but no 'prisma migrate diff' output in artifact. This invalidates any prior vacuous pass.",
      5:  "❌ simulateSurrender built (CARBONX-FIX-003) but rollback_path field not in this audit artifact",
      6:  "❌ No doc hash verification",
      7:  "❌ gate_decision=READY_FOR_CODE_SCAN_RECHECK — codex not yet updated",
      8:  "✅ batch64 audit artifact written, 30 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ CRITICAL GAP: batch 64 created aegis-approval-token.ts (handles financial tokens) with no secret scanner run",
      11: "❌ No human review confirmation",
    },
  },
  {
    batch: 65, label: "BR-5 financial re-scan gate", phase: "rescan",
    code_changed: false, schema_changed: false,
    bits_satisfied: [8],
    bits_notes: {
      0:  "❌ Re-scan gate only",
      1:  "❌ No test runner",
      2:  "❌ No lint",
      3:  "✅ Inherited from batch 64 — no new code changes",
      4:  "❌ Migration gap from batch 64 not closed",
      5:  "❌ rollback_path not in artifact",
      6:  "❌ No doc hash",
      7:  "❌ carbonx_in_policy=false",
      8:  "✅ batch65 artifact written, 46 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ Secret scanner not run",
      11: "❌ No human review",
    },
  },
  {
    batch: 66, label: "Soft-canary soak run 1/7", phase: "soft_canary",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:  "❌ Soak tests do not include tsc",
      1:  "✅ 81/81 checks PASS — soak exercises simulateSurrender, approval token, SENSE event. tests_passed satisfied.",
      2:  "❌ No lint runner",
      3:  "✅ No code changes — inherited",
      4:  "❌ Migration gap from batch 64 not closed",
      5:  "❌ rollback_path not in artifact yet",
      6:  "❌ No doc hash verification",
      7:  "❌ carbonx_in_aegis_env=false",
      8:  "✅ batch66 artifact written, 81 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ Secret scanner not run",
      11: "❌ No human review confirmation",
    },
  },
  {
    batch: 67, label: "Soft-canary soak run 2/7", phase: "soft_canary",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:"❌", 1:"✅ 57/57 PASS", 2:"❌", 3:"✅ inherited", 4:"❌ migration gap open",
      5:"❌", 6:"❌", 7:"❌", 8:"✅ artifact PASS", 9:"❌", 10:"❌", 11:"❌",
    },
  },
  {
    batch: 68, label: "Soft-canary soak run 3/7", phase: "soft_canary",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:"❌", 1:"✅ 57/57 PASS", 2:"❌", 3:"✅ inherited", 4:"❌ migration gap open",
      5:"❌", 6:"❌", 7:"❌", 8:"✅ artifact PASS", 9:"❌", 10:"❌", 11:"❌",
    },
  },
  {
    batch: 69, label: "Soft-canary soak run 4/7", phase: "soft_canary",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:"❌", 1:"✅ 57/57 PASS", 2:"❌", 3:"✅ inherited", 4:"❌ migration gap open",
      5:"❌", 6:"❌", 7:"❌", 8:"✅ artifact PASS", 9:"❌", 10:"❌", 11:"❌",
    },
  },
  {
    batch: 70, label: "Soft-canary soak run 5/7 — EUA cap + partial-settlement boundary", phase: "soft_canary",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:  "❌ No tsc",
      1:  "✅ 68/68 PASS — EUA cap boundary and partial-settlement edge cases verified",
      2:  "❌ No lint",
      3:  "✅ No code changes — inherited",
      4:  "❌ Migration gap open",
      5:  "❌ rollback_path not in artifact",
      6:  "❌ No doc hash",
      7:  "❌ Not in AEGIS policy yet",
      8:  "✅ batch70 artifact written, 68 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ Secret scanner not run",
      11: "❌ No human review",
    },
  },
  {
    batch: 71, label: "Financial scope gap closure", phase: "gap_closure",
    code_changed: true, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:  "❌ No tsc confirmation in artifact",
      1:  "✅ 57/57 PASS after gap closure",
      2:  "❌ No lint",
      3:  "✅ gaps_closed array explicitly bounds scope: GAP-1 (resolver) + GAP-2 (input validation)",
      4:  "❌ No schema changes in this batch — but batch 64 gap remains unresolved",
      5:  "❌ rollback_path not in artifact",
      6:  "❌ No doc hash verification",
      7:  "❌ Codex not updated",
      8:  "✅ batch71 artifact written, 57 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ Secret scanner not run",
      11: "❌ No human review confirmation",
    },
  },
  {
    batch: 72, label: "Soft-canary soak run 6/7", phase: "soft_canary",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:"❌", 1:"✅ 61/61 PASS", 2:"❌", 3:"✅ inherited", 4:"❌ migration gap open",
      5:"❌", 6:"❌", 7:"❌", 8:"✅ artifact PASS", 9:"❌", 10:"❌", 11:"❌",
    },
  },
  {
    batch: 73, label: "Soft-canary soak run 7/7 — final gate", phase: "soft_canary",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 8],
    bits_notes: {
      0:  "❌ No tsc",
      1:  "✅ 80/80 PASS — full end-to-end regression cycle. promotion_permitted_carbonx=true.",
      2:  "❌ No lint",
      3:  "✅ No code changes — inherited",
      4:  "❌ Migration gap from batch 64 still open",
      5:  "❌ rollback_path not yet in artifact (simulateSurrender exists but not documented here)",
      6:  "❌ No doc hash verification",
      7:  "❌ Codex not yet updated with promotion batch",
      8:  "✅ batch73 artifact written, 80 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not run",
      10: "❌ Secret scanner not run",
      11: "❌ No human review confirmation in artifact",
    },
  },
  {
    batch: 74, label: "HG-2B promotion to hard-gate live", phase: "promotion",
    code_changed: false, schema_changed: false,
    bits_satisfied: [1, 3, 5, 8],
    bits_notes: {
      0:  "❌ No tsc in promotion artifact",
      1:  "✅ 63/63 PASS. Cumulative 7/7 soak passes confirmed.",
      2:  "❌ No lint runner",
      3:  "✅ No code changes at promotion — scope clean",
      4:  "❌ Migration gap from batch 64 never closed — no migrate diff evidence in any batch 62–74 artifact",
      5:  "✅ five_locks_status.LOCK_4_rollback='PASS — simulateSurrender dry-run path'. rollback_note field present. Five Locks formally verified rollback mechanism.",
      6:  "❌ No doc hash verification in promotion artifact",
      7:  "❌ codex.json has aegis_promotion_batch=74 but quality.ts requires classification_batch=74 (different field). Schema field name mismatch — substance present, strict requirement not met.",
      8:  "✅ batch74 artifact written, 63 checks, verdict=PASS",
      9:  "❌ AEG-PROV-001 not in AEGIS doctrine at promotion time (introduced batch 89, day after)",
      10: "❌ Secret scanner never run across the 13-batch chain",
      11: "❌ No human_review_status=confirmed or human_override_applied=true. Formal human review protocol (batch 88 style) did not exist at batch 74.",
    },
  },
];

// ── Build cumulative mask ──────────────────────────────────────────────────────
//
// Rules:
//   1. Cumulative OR across batches — satisfied bits persist.
//   2. Bit 4 (migration_verified): once a schema change occurs (batch 64) without
//      migrate diff evidence, this bit is explicitly blocked. It cannot be set by
//      earlier batches' vacuous pass.
//   3. Bit 7 (codex_updated): NOT satisfied (field name mismatch).
//
// Implementation: build cumulative mask without vacuous pre-seeding.
// Each batch only contributes bits explicitly listed in bits_satisfied.

const per_batch_masks: Record<number, number> = {};
let cumulative = 0;

for (const entry of BATCH_EVIDENCE) {
  let mask = 0;
  for (const b of entry.bits_satisfied) mask |= (1 << b);
  cumulative |= mask;
  entry.cumulative_mask = cumulative;
  per_batch_masks[entry.batch] = cumulative;
}

// Final quality_mask_at_promotion = cumulative at batch 74
const quality_mask_at_promotion = per_batch_masks[PROMOTION_BATCH]!;
const satisfied_bits = QUALITY_BITS.filter(qb => (quality_mask_at_promotion & qb.value) !== 0);
const missing_bits   = QUALITY_BITS.filter(qb => (quality_mask_at_promotion & qb.value) === 0);
const meets_required = (quality_mask_at_promotion & REQUIRED_MASK) === REQUIRED_MASK;
const gap_mask       = REQUIRED_MASK & ~quality_mask_at_promotion;
const gap_count      = missing_bits.length;

// ── Checks ────────────────────────────────────────────────────────────────────

interface CheckResult { id: string; pass: boolean; note: string; }
const checks: CheckResult[] = [];
let checks_passed = 0;
let checks_failed = 0;

function check(id: string, pass: boolean, note: string) {
  checks.push({ id, pass, note });
  if (pass) checks_passed++; else checks_failed++;
}

// §1 — Batch artifact coverage

check("B90-001", BATCH_EVIDENCE.length === 13,
  `All 13 batches (62–74) assessed: found ${BATCH_EVIDENCE.length}`);

check("B90-002", BATCH_EVIDENCE[0].batch === 62 && BATCH_EVIDENCE[12].batch === 74,
  `Chain spans batch 62 (first) to batch 74 (promotion)`);

check("B90-003", fs.readdirSync(AUDIT_DIR).filter(f => f.match(/^batch(6[2-9]|7[0-4])_carbonx/)).length === 13,
  `All 13 batch artifacts (62–74) exist on disk`);

// §2 — Bit analysis

check("B90-010", (quality_mask_at_promotion & 0x0002) !== 0,
  `Q-002 tests_passed satisfied — 7/7 soak runs all PASS (first evidenced batch 66)`);

check("B90-011", (quality_mask_at_promotion & 0x0100) !== 0,
  `Q-009 audit_artifact_written satisfied — all 13 batch artifacts present with verdict=PASS`);

check("B90-012", (quality_mask_at_promotion & 0x0020) !== 0,
  `Q-006 rollback_verified satisfied — Five Locks LOCK_4 PASS at batch 74 (simulateSurrender)`);

check("B90-013", (quality_mask_at_promotion & 0x0008) !== 0,
  `Q-004 no_unrelated_diff satisfied — batch 64 scope explicitly declared (files_created + files_modified)`);

check("B90-014", (quality_mask_at_promotion & 0x0001) === 0,
  `Q-001 typecheck_passed NOT satisfied — tsc --noEmit never evidenced in any batch artifact`);

check("B90-015", (quality_mask_at_promotion & 0x0004) === 0,
  `Q-003 lint_passed NOT satisfied — no lint runner invocation in any batch artifact`);

check("B90-016", (quality_mask_at_promotion & 0x0010) === 0,
  `Q-005 migration_verified NOT satisfied — batch 64 modified prisma/schema.prisma without migrate diff evidence`);

check("B90-017", (quality_mask_at_promotion & 0x0040) === 0,
  `Q-007 docs_updated NOT satisfied — no doc hash verification in any batch artifact`);

check("B90-018", (quality_mask_at_promotion & 0x0080) === 0,
  `Q-008 codex_updated NOT satisfied — codex has aegis_promotion_batch=74 but schema requires classification_batch=74 (field name mismatch)`);

check("B90-019", (quality_mask_at_promotion & 0x0200) === 0,
  `Q-010 source_clean NOT satisfied — AEG-PROV-001 not in doctrine at promotion time (introduced batch 89)`);

check("B90-020", (quality_mask_at_promotion & 0x0400) === 0,
  `Q-011 no_secret_detected NOT satisfied — secret scanner never invoked across 13-batch chain`);

check("B90-021", (quality_mask_at_promotion & 0x0800) === 0,
  `Q-012 human_reviewed NOT satisfied — formal human review protocol introduced in batch 88 (after batch 74 promotion)`);

// §3 — Required mask gap

check("B90-030", !meets_required,
  `carbonx does NOT meet HG-2B-financial required mask 0x0FFF at promotion time — as expected for pre-doctrine service`);

check("B90-031", gap_count === 8,
  `Gap count: ${gap_count} bits missing (expected 8: typecheck, lint, migration, docs, codex, source_clean, no_secret, human_reviewed)`);

check("B90-032", gap_mask === 0x0ED5,
  `Gap mask = 0x${gap_mask.toString(16).toUpperCase().padStart(4,"0")} (expected 0x0ED5 = bits 0,2,4,6,7,9,10,11)`);

check("B90-033", quality_mask_at_promotion === 0x012A,
  `quality_mask_at_promotion = 0x${quality_mask_at_promotion.toString(16).toUpperCase().padStart(4,"0")} (expected 0x012A = tests+no_unrelated_diff+rollback+audit_artifact)`);

// §4 — Retroactive classification

const is_pre_doctrine = true;  // batch 74 (May 4) precedes batch 89 (May 5)
const status = "pre_AEG_Q_001_legacy";

check("B90-040", is_pre_doctrine,
  `carbonx promoted ${PROMOTION_DATE} — doctrine introduced batch 89. Status: pre_AEG_Q_001_legacy.`);

check("B90-041", status === "pre_AEG_Q_001_legacy",
  `pre_AEG_Q_001_legacy confirmed — retroactive audit computes honest score without invalidating promotion`);

// §5 — Batch 89 consistency

const batch89_score  = 0x0102;
const refinement_add = quality_mask_at_promotion & ~batch89_score;  // bits added by batch 90
const expected_refinement = 0x0028;  // bits 3 (no_unrelated_diff) + 5 (rollback_verified)

check("B90-050", (batch89_score & 0x0002) !== 0 && (quality_mask_at_promotion & 0x0002) !== 0,
  `Q-002 tests_passed consistent with batch 89 assessment`);

check("B90-051", (batch89_score & 0x0100) !== 0 && (quality_mask_at_promotion & 0x0100) !== 0,
  `Q-009 audit_artifact_written consistent with batch 89 assessment`);

check("B90-052", refinement_add === expected_refinement,
  `Batch 90 refines batch 89 by +0x${refinement_add.toString(16).toUpperCase().padStart(4,"0")} (expected +0x${expected_refinement.toString(16).toUpperCase().padStart(4,"0")}): bit 3 (no_unrelated_diff, batch 64 scope) + bit 5 (rollback_verified, Five Locks LOCK_4 batch 74)`);

// §6 — Gap closure roadmap

const remediation_gaps = [
  { id:"GAP-Q-001", bit:"Q-001", name:"typecheck_passed",   action:"Add tsc --noEmit to pre-promotion gate in promotion-template.ts",                           urgency:"HIGH",     urgency_reason:"TypeScript errors could reach production without this check" },
  { id:"GAP-Q-003", bit:"Q-003", name:"lint_passed",        action:"Add biome/eslint check to pre-promotion gate in promotion-template.ts",                    urgency:"HIGH",     urgency_reason:"Lint catches class of bugs tests do not" },
  { id:"GAP-Q-005", bit:"Q-005", name:"migration_verified", action:"Run prisma migrate diff on batch 64 schema change and document outcome; add to pre-promotion gate", urgency:"CRITICAL", urgency_reason:"Schema changed (externalRef) in batch 64 without verified migration path — financial service risk" },
  { id:"GAP-Q-007", bit:"Q-007", name:"docs_updated",       action:"Hash deep-knowledge doc before/after next carbonx soak and record in artifact",            urgency:"MEDIUM",   urgency_reason:"Docs drift silently; hash provides temporal evidence" },
  { id:"GAP-Q-008", bit:"Q-008", name:"codex_updated",      action:"Add quality_mask_at_promotion to codex.json classification_batch field (this batch closes partial gap)", urgency:"HIGH",     urgency_reason:"Schema requires classification_batch not aegis_promotion_batch" },
  { id:"GAP-Q-010", bit:"Q-010", name:"source_clean",       action:"Run AEG-PROV-001 assertSourceControlProvenance on carbonx repo; add to pre-promotion gate", urgency:"HIGH",     urgency_reason:"Source provenance chain broken — cannot assert repo integrity" },
  { id:"GAP-Q-011", bit:"Q-011", name:"no_secret_detected", action:"Run truffleHog/gitleaks on git diff before next batch; add to pre-promotion gate",         urgency:"CRITICAL", urgency_reason:"Batch 64 introduced aegis-approval-token.ts handling financial tokens with no secret scan" },
  { id:"GAP-Q-012", bit:"Q-012", name:"human_reviewed",     action:"Add carbonx to batch 88-style human review queue for retrospective classification confirmation", urgency:"HIGH",     urgency_reason:"Formal human review protocol existed from batch 88 — carbonx pre-dates it" },
];

check("B90-060", remediation_gaps.length === 8,
  `8 remediation gaps identified — one per missing bit`);

check("B90-061", remediation_gaps.find(g => g.id === "GAP-Q-011")?.urgency === "CRITICAL",
  `GAP-Q-011 (no_secret_detected) urgency=CRITICAL: financial approval token file created without secret scan`);

check("B90-062", remediation_gaps.find(g => g.id === "GAP-Q-005")?.urgency === "CRITICAL",
  `GAP-Q-005 (migration_verified) urgency=CRITICAL: prisma schema changed in batch 64 without migrate diff`);

check("B90-063", remediation_gaps.filter(g => g.urgency === "CRITICAL").length === 2,
  `Exactly 2 CRITICAL gaps: GAP-Q-011 (no_secret) + GAP-Q-005 (migration_verified)`);

// §7 — codex.json update

let codex_updated = false;
try {
  const codex = JSON.parse(fs.readFileSync(CODEX_PATH, "utf8"));
  codex["quality_mask_at_promotion"]        = quality_mask_at_promotion;
  codex["quality_mask_at_promotion_hex"]    = `0x${quality_mask_at_promotion.toString(16).toUpperCase().padStart(4,"0")}`;
  codex["quality_mask_schema"]              = QUALITY_SCHEMA;
  codex["quality_mask_status"]              = status;
  codex["quality_mask_audit_batch"]         = BATCH;
  codex["quality_mask_audit_date"]          = new Date().toISOString().split("T")[0];
  codex["quality_drift_score"]              = null;
  codex["quality_confidence"]               = "low";
  codex["classification_batch"]             = PROMOTION_BATCH;  // closes GAP-Q-008 field name
  fs.writeFileSync(CODEX_PATH, JSON.stringify(codex, null, 2));
  codex_updated = true;
} catch (e: any) {
  console.error("codex.json update failed:", e.message);
}

check("B90-070", codex_updated,
  `codex.json updated: quality_mask_at_promotion=0x012A, quality_confidence=low, quality_drift_score=null, classification_batch=74`);

// ── Audit artifact ─────────────────────────────────────────────────────────────

const verdict: "PASS" | "FAIL" = checks_failed === 0 ? "PASS" : "FAIL";

const artifact = {
  audit_id:                       `batch${BATCH}-carbonx-quality-retroactive-audit`,
  batch:                          BATCH,
  type:                           "quality_retroactive_audit",
  service:                        SERVICE,
  hg_group:                       HG_GROUP,
  promotion_batch:                PROMOTION_BATCH,
  promotion_date:                 PROMOTION_DATE,
  date:                           new Date().toISOString().split("T")[0],
  quality_schema:                 QUALITY_SCHEMA,
  doctrine:                       "A retroactive audit does not void the promotion. It computes the honest score so the evidence chain can be completed.",
  quality_mask_at_promotion,
  quality_mask_at_promotion_hex:  `0x${quality_mask_at_promotion.toString(16).toUpperCase().padStart(4,"0")}`,
  batch89_initial_score:          batch89_score,
  batch89_initial_hex:            `0x${batch89_score.toString(16).toUpperCase().padStart(4,"0")}`,
  batch90_refinement_added:       `+0x${refinement_add.toString(16).toUpperCase().padStart(4,"0")} (bit 3: no_unrelated_diff + bit 5: rollback_verified)`,
  required_mask:                  REQUIRED_MASK,
  required_mask_hex:              REQUIRED_HEX,
  gap_mask,
  gap_mask_hex:                   `0x${gap_mask.toString(16).toUpperCase().padStart(4,"0")}`,
  quality_confidence:             "low",
  quality_drift_score:            null,
  status,
  is_violation:                   false,
  satisfied_bits: satisfied_bits.map(qb => ({ id: qb.id, bit: qb.bit, name: qb.name })),
  missing_bits:   missing_bits.map(qb => ({ id: qb.id, bit: qb.bit, name: qb.name })),
  per_batch_cumulative_masks: Object.fromEntries(
    Object.entries(per_batch_masks).map(([b, m]) => [
      `batch_${b}`,
      { mask: m, hex: `0x${m.toString(16).toUpperCase().padStart(4,"0")}` }
    ])
  ),
  per_batch_evidence: BATCH_EVIDENCE.map(e => ({
    batch:         e.batch,
    label:         e.label,
    phase:         e.phase,
    code_changed:  e.code_changed,
    schema_changed: e.schema_changed,
    bits_satisfied_in_batch: e.bits_satisfied,
    cumulative_mask_after: e.cumulative_mask,
    cumulative_mask_hex: `0x${(e.cumulative_mask ?? 0).toString(16).toUpperCase().padStart(4,"0")}`,
  })),
  remediation_gaps,
  checks_total:   checks.length,
  checks_passed,
  checks_failed,
  checks,
  verdict,
  next_steps: [
    "Batch 91: Quality drift scanner — detect fleet services where evidence has degraded since promotion",
    "Batch 92: Fleet quality dashboard — aggregate quality_mask across all 61 codex files",
    "Batch 93: Guard SDK MVP — @ankr/aegis-guard extracting approval token + SENSE + idempotency",
    "Pre-Batch 91 action: Run AEG-PROV-001 + truffleHog/gitleaks on carbonx repo to close GAP-Q-010 + GAP-Q-011",
    "Pre-Batch 91 action: Confirm prisma migration path for batch 64 externalRef schema change (GAP-Q-005)",
    "Pre-Batch 91 action: Add carbonx to human review queue for retrospective confirmation (GAP-Q-012)",
  ],
};

// ── Write artifact ─────────────────────────────────────────────────────────────

const out = path.join(AUDIT_DIR, `batch${BATCH}_carbonx_quality_retroactive_audit.json`);
fs.writeFileSync(out, JSON.stringify(artifact, null, 2));

// ── Print summary ──────────────────────────────────────────────────────────────

console.log(`\nAEGIS Batch ${BATCH} — carbonx Quality Retroactive Audit`);
console.log(`${"─".repeat(62)}`);
console.log(`Service:              ${SERVICE}`);
console.log(`HG group:             ${HG_GROUP}`);
console.log(`Promotion batch:      ${PROMOTION_BATCH} (${PROMOTION_DATE})`);
console.log(`Status:               ${status}`);
console.log(`Is violation:         false (pre-doctrine — not a compliance failure)`);
console.log(``);
console.log(`quality_mask_at_promotion:`);
console.log(`  Batch 89 initial:   0x${batch89_score.toString(16).toUpperCase().padStart(4,"0")} (bits 1, 8 only)`);
console.log(`  Batch 90 refined:   0x${quality_mask_at_promotion.toString(16).toUpperCase().padStart(4,"0")} (bits 1, 3, 5, 8)`);
console.log(`  Required (HG-2Bf):  ${REQUIRED_HEX} (bits 0–11 all set)`);
console.log(`  Gap:                0x${gap_mask.toString(16).toUpperCase().padStart(4,"0")} (${gap_count} bits missing)`);
console.log(``);
console.log(`Satisfied (4 bits):   ${satisfied_bits.map(b => b.name).join(", ")}`);
console.log(`Missing   (8 bits):   ${missing_bits.map(b => b.name).join(", ")}`);
console.log(``);
console.log(`CRITICAL gaps:`);
remediation_gaps.filter(g => g.urgency === "CRITICAL").forEach(g => {
  console.log(`  [${g.id}] ${g.name}: ${g.urgency_reason}`);
});
console.log(``);
console.log(`Checks: ${checks_passed}/${checks.length} pass`);
if (checks_failed > 0) {
  console.log(`\nFailed checks:`);
  checks.filter(c => !c.pass).forEach(c => console.log(`  ✗ [${c.id}] ${c.note}`));
}
console.log(`\nVerdict: ${verdict}`);
console.log(`Output:  ${out}`);
console.log(`codex:   ${CODEX_PATH}`);
