/**
 * AEGIS Batch 89 — AEGIS-Q Quality Evidence Doctrine
 * 2026-05-05
 *
 * Goal:
 *   Define quality_mask_at_promotion and quality_drift_score as first-class
 *   evidence fields for every AEGIS-governed service. Verify the schema is
 *   internally consistent. Run retroactive quality audit against carbonx
 *   and parali-central promotion chains. Add quality gate to promotion template.
 *
 * Output:
 *   - aegis/quality/quality-mask-schema.json       (written by setup step)
 *   - aegis/src/enforcement/quality.ts             (written by setup step)
 *   - promotion-template.ts §5 quality gate        (updated here)
 *   - audits/batch89_aegis_q_quality_evidence_doctrine.json
 *
 * Two time horizons — never conflate:
 *   quality_mask_at_promotion (bits 0–11): verifiable at the moment of action
 *   quality_drift_score       (bits 12–15): observable only post-promotion
 *
 * Doctrine:
 *   Safety is permission. Quality is survival. Drift is the audit of time.
 *
 * Final line:
 *   Safety says the agent may act. Quality says the work deserves to survive.
 *
 * @rule:AEG-Q-001 every promoted service must carry quality_mask_at_promotion
 * @rule:AEG-Q-002 bits 12–15 must never be set in quality_mask_at_promotion
 * @rule:AEG-Q-003 quality_drift_score is set post-promotion only
 */

import { readFileSync, existsSync, writeFileSync } from "fs";
import { join } from "path";
import {
  QUALITY_BITS,
  QUALITY_SCHEMA,
  HG_REQUIRED_QUALITY_MASK,
  assertQualityEvidence,
  qualityConfidence,
  computeQualityDriftScore,
} from "../src/enforcement/quality.js";

const AUDITS     = "/root/aegis/audits";
const SCHEMA_FILE = "/root/aegis/quality/quality-mask-schema.json";
const QUALITY_TS  = "/root/aegis/src/enforcement/quality.ts";
const TEMPLATE_TS = "/root/aegis/scripts/promotion-template.ts";

// ── Harness ───────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(n: number, label: string, actual: unknown, expected: unknown, tag: string): void {
  const ok = actual === expected;
  const pad = String(n).padStart(2, " ");
  if (ok) {
    passed++;
    console.log(`  ✓ [${pad}] ${label.padEnd(72)} actual=${JSON.stringify(actual)}`);
  } else {
    failed++;
    failures.push(`${tag}: [${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
    console.log(`  ✗ [${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  }
}

function section(t: string): void { console.log(`\n── ${t} ──`); }

// ── §1  Schema definition (checks 1–4) ───────────────────────────────────────

section("§1 Schema definition — 16-bit, two horizons");

const schema = JSON.parse(readFileSync(SCHEMA_FILE, "utf-8")) as Record<string, unknown>;

check(1, `Schema file exists and schema="${QUALITY_SCHEMA}"`,
  schema.schema, QUALITY_SCHEMA, "schema");

const pointInTimeBits = QUALITY_BITS.filter(b => b.horizon === "point_in_time");
const longitudinalBits = QUALITY_BITS.filter(b => b.horizon === "longitudinal");

check(2, "Point-in-time bits: exactly 12 (bits 0–11)",
  pointInTimeBits.length, 12, "schema");

check(3, "Longitudinal bits: exactly 4 (bits 12–15)",
  longitudinalBits.length, 4, "schema");

check(4, "Two time horizons correctly separated — longitudinal bits 12–15 never overlap point-in-time",
  pointInTimeBits.every(b => b.bit < 12) && longitudinalBits.every(b => b.bit >= 12),
  true, "schema");

// ── §2  Bit definitions correctness (checks 5–8) ─────────────────────────────

section("§2 Bit definitions — Q-001 to Q-016 correctly wired");

check(5, "source_clean (Q-010, bit 9) maps to AEG-PROV-001 — provenance linkage confirmed",
  QUALITY_BITS.find(b => b.name === "source_clean")?.verified_by?.includes("AEG-PROV-001"),
  true, "bits");

check(6, "audit_artifact_written (Q-009, bit 8) is required for all HG groups",
  Object.values(HG_REQUIRED_QUALITY_MASK).every(mask => (mask & 256) !== 0),
  true, "bits");

check(7, "human_reviewed (Q-012, bit 11) is NOT required for HG-1 (machine-only tier)",
  (HG_REQUIRED_QUALITY_MASK["HG-1"]! & 2048) === 0,
  true, "bits");

check(8, "All 12 point-in-time bits are required for HG-2B-financial (0x0FFF)",
  HG_REQUIRED_QUALITY_MASK["HG-2B-financial"], 0x0FFF, "bits");

// ── §3  Required masks — superset invariant (checks 9–12) ────────────────────

section("§3 Required masks — strict superset chain HG-1 ⊂ HG-2A ⊂ HG-2B ⊂ HG-2B-financial");

const hg1  = HG_REQUIRED_QUALITY_MASK["HG-1"]!;
const hg2a = HG_REQUIRED_QUALITY_MASK["HG-2A"]!;
const hg2b = HG_REQUIRED_QUALITY_MASK["HG-2B"]!;
const hgFin= HG_REQUIRED_QUALITY_MASK["HG-2B-financial"]!;

check(9,  `HG-1 required=0x${hg1.toString(16).toUpperCase().padStart(4,"0")} — strict subset of HG-2A`,
  (hg2a & hg1) === hg1 && hg2a !== hg1, true, "masks");

check(10, `HG-2A required=0x${hg2a.toString(16).toUpperCase().padStart(4,"0")} — strict subset of HG-2B`,
  (hg2b & hg2a) === hg2a && hg2b !== hg2a, true, "masks");

check(11, `HG-2B required=0x${hg2b.toString(16).toUpperCase().padStart(4,"0")} — strict subset of HG-2B-financial`,
  (hgFin & hg2b) === hg2b && hgFin !== hg2b, true, "masks");

check(12, "All required masks use only bits 0–11 (point-in-time only at promotion time)",
  [hg1, hg2a, hg2b, hgFin].every(m => (m & 0xF000) === 0), true, "masks");

// ── §4  assertQualityEvidence() implementation (checks 13–16) ─────────────────

section("§4 assertQualityEvidence() — enforcement function correctness");

// Full evidence passes for any HG group
const fullMask = 0x0FFF;
const hg1Pass  = assertQualityEvidence("HG-1",            fullMask);
const hg2aPass = assertQualityEvidence("HG-2A",           fullMask);
const hg2bPass = assertQualityEvidence("HG-2B",           fullMask);
const hgFinPass= assertQualityEvidence("HG-2B-financial",  fullMask);

check(13, "Full mask (0x0FFF) passes assertQualityEvidence for all four HG groups",
  hg1Pass.verdict === "PASS" && hg2aPass.verdict === "PASS" &&
  hg2bPass.verdict === "PASS" && hgFinPass.verdict === "PASS",
  true, "assert");

// Minimum HG-1 mask passes HG-1 but fails HG-2A
const hg1Min = assertQualityEvidence("HG-1",  hg1);
const hg1OnHg2a = assertQualityEvidence("HG-2A", hg1);

check(14, "HG-1 minimum mask (0x0302) passes HG-1 and fails HG-2A",
  hg1Min.verdict === "PASS" && hg1OnHg2a.verdict === "FAIL",
  true, "assert");

// AEG-Q-002: longitudinal bits in quality_mask_at_promotion must throw
let aegQ002Thrown = false;
try { assertQualityEvidence("HG-1", 0x1000); }
catch { aegQ002Thrown = true; }

check(15, "AEG-Q-002: longitudinal bits in quality_mask_at_promotion throw (enforcement active)",
  aegQ002Thrown, true, "assert");

// Confidence tiers
check(16, "quality_confidence: full mask=high, HG-1-min on HG-2A=medium, 0=unaudited",
  qualityConfidence("HG-2B-financial", fullMask) === "high" &&
  qualityConfidence("HG-2A", hg1)                === "medium" &&
  qualityConfidence("HG-1",  0)                  === "unaudited",
  true, "assert");

// ── §5  Promotion template integration (checks 17–20) ────────────────────────

section("§5 Promotion template integration — §5 quality gate added");

const templateText = existsSync(TEMPLATE_TS) ? readFileSync(TEMPLATE_TS, "utf-8") : "";

// Add §5 quality gate to the promotion template
const QUALITY_SECTION = `
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
//   console.log(\`  Missing: \${qualityResult.missing_bits.join(", ")}\`);
// }
`;

const hasQualitySection = templateText.includes("AEGIS-Q Quality evidence");
if (!hasQualitySection) {
  const insertBefore = "// ════════════════════════════════════════════════════════════════════════════\n// Summary + artifact";
  const updated = templateText.replace(insertBefore, QUALITY_SECTION + "\n" + insertBefore);
  writeFileSync(TEMPLATE_TS, updated);
}

const templateAfter = readFileSync(TEMPLATE_TS, "utf-8");

check(17, "promotion-template.ts has §5 AEGIS-Q quality gate section",
  templateAfter.includes("AEGIS-Q Quality evidence"), true, "template");

check(18, "promotion-template.ts references assertQualityEvidence() (commented example)",
  templateAfter.includes("assertQualityEvidence"), true, "template");

check(19, "promotion-template.ts documents quality_drift_score = null at promotion time (AEG-Q-003)",
  templateAfter.includes("quality_drift_score") || templateAfter.includes("AEG-Q-003"),
  true, "template");

// Verify quality_mask_at_promotion field belongs in the artifact
check(20, "promotion-template.ts documents quality_mask_at_promotion field for promotion artifact",
  templateAfter.includes("quality_mask_at_promotion"), true, "template");

// ── §6  Retroactive audit — carbonx + parali-central (checks 21–24) ──────────

section("§6 Retroactive quality audit — pre-AEG-Q-001 promotions annotated");

// Retroactive analysis: what quality_mask_at_promotion would have been
// for carbonx (HG-2B-financial, Batch 74) and parali-central (HG-2B, Batch 60)
// had Batch 89 doctrine been in force.
//
// Evidence definitively provable from audit artifacts:
//   Q-002 tests_passed:          YES — 7-run soak chain (Batches 66-73 / 53-59)
//   Q-009 audit_artifact_written:YES — batchN_promotion.json exists with verdict=PASS
//   Q-010 source_clean:          NO  — pre-Batch-78; AEG-PROV-001 not enforced
//                                       (carbonx repaired retroactively via Batch 75A)
//   Q-008 codex_updated:         NO  — codex enrichment was Batch 83, not at promotion
//   Q-012 human_reviewed:        UNKNOWN — no human_review_status field in artifacts
//   Q-001 typecheck:             UNKNOWN — not recorded in soak artifacts
//   Q-003 to Q-007, Q-011:       UNKNOWN — not recorded

// Conservative (only bits provable from artifact evidence):
const CARBONX_RETROACTIVE_MASK    = (1 << 1) | (1 << 8);  // tests + audit_artifact = 0x0102
const PARALI_RETROACTIVE_MASK     = (1 << 1) | (1 << 8);  // tests + audit_artifact = 0x0102

const carbonxRetro  = assertQualityEvidence("HG-2B-financial", CARBONX_RETROACTIVE_MASK);
const paraliRetro   = assertQualityEvidence("HG-2B",            PARALI_RETROACTIVE_MASK);

console.log(`\n  Retroactive quality analysis (conservative — only bits provable from artifacts):`);
console.log(`    carbonx-backend (HG-2B-financial):`);
console.log(`      quality_mask_at_promotion: 0x${CARBONX_RETROACTIVE_MASK.toString(16).padStart(4,"0")}`);
console.log(`      required:                  0x${hgFin.toString(16).padStart(4,"0")}`);
console.log(`      verdict:                   ${carbonxRetro.verdict}`);
console.log(`      missing_bits:              ${carbonxRetro.missing_bits.join(", ")}`);
console.log(`    parali-central (HG-2B):`);
console.log(`      quality_mask_at_promotion: 0x${PARALI_RETROACTIVE_MASK.toString(16).padStart(4,"0")}`);
console.log(`      required:                  0x${hg2b.toString(16).padStart(4,"0")}`);
console.log(`      verdict:                   ${paraliRetro.verdict}`);
console.log(`      missing_bits:              ${paraliRetro.missing_bits.join(", ")}`);
console.log(`\n  These are pre_AEG_Q_001_legacy promotions — not violations.`);
console.log(`  Doctrine was not in force at Batch 60 or Batch 74.`);
console.log(`  The retroactive audit documents the gap; it does not invalidate the promotions.`);

check(21, "carbonx retroactive mask (0x0102) fails HG-2B-financial — documents the quality gap",
  carbonxRetro.verdict, "FAIL", "retro");

check(22, "source_clean (Q-010) is in carbonx missing bits — confirms AEG-PROV-001 was the primary gap",
  carbonxRetro.missing_bits.includes("source_clean"), true, "retro");

check(23, "parali-central retroactive mask (0x0102) fails HG-2B — confirms same pre-doctrine gap",
  paraliRetro.verdict, "FAIL", "retro");

check(24, "quality_drift_score: computeQualityDriftScore() produces correct bit values",
  computeQualityDriftScore({
    idempotency_verified:   true,
    observability_verified: false,
    regression_clean:       true,
    production_fire_zero:   false,
  }), 0x5000,   // bits 12 + 14 = 0x1000 + 0x4000 = 0x5000
  "retro");

// ── Summary + artifact ────────────────────────────────────────────────────────

console.log("\n" + "─".repeat(72));
console.log(`\n  Passed: ${passed}/${passed + failed}`);
if (failed > 0) {
  for (const f of failures) console.log(`    ${f}`);
}
console.log("");

const verdict = failed === 0 ? "PASS" : "FAIL";

writeFileSync(
  join(AUDITS, "batch89_aegis_q_quality_evidence_doctrine.json"),
  JSON.stringify({
    audit_id:      "batch89-aegis-q-quality-evidence-doctrine",
    batch:         89,
    type:          "quality_doctrine",
    date:          "2026-05-05",
    checks_total:  passed + failed,
    checks_passed: passed,
    checks_failed: failed,
    verdict,
    safety_verdict:  verdict,
    quality_verdict: verdict,
    schema:          QUALITY_SCHEMA,
    enforcement_module: "src/enforcement/quality.ts",
    schema_file:     "quality/quality-mask-schema.json",
    doctrine: {
      line1: "Safety is permission. Quality is survival. Drift is the audit of time.",
      line2: "Safety says the agent may act. Quality says the work deserves to survive.",
      positioning: "AEGIS turns AI agent activity into governed, testable, auditable work.",
    },
    required_masks: {
      "HG-1":            `0x${hg1.toString(16).toUpperCase().padStart(4,"0")}`,
      "HG-2A":           `0x${hg2a.toString(16).toUpperCase().padStart(4,"0")}`,
      "HG-2B":           `0x${hg2b.toString(16).toUpperCase().padStart(4,"0")}`,
      "HG-2B-financial": `0x${hgFin.toString(16).toUpperCase().padStart(4,"0")}`,
    },
    superset_invariant: "HG-1 ⊂ HG-2A ⊂ HG-2B ⊂ HG-2B-financial (each tier requires strict superset of evidence)",
    retroactive_audit: {
      annotation: "pre_AEG_Q_001_legacy",
      note: "promotions before Batch 89 are legacy — not violations. Batch 89 draws the line.",
      carbonx_backend: {
        hg_group:                  "HG-2B-financial",
        promotion_batch:           74,
        quality_mask_retroactive:  `0x${CARBONX_RETROACTIVE_MASK.toString(16).padStart(4,"0")}`,
        required_mask:             `0x${hgFin.toString(16).padStart(4,"0")}`,
        retroactive_verdict:       carbonxRetro.verdict,
        known_missing:             carbonxRetro.missing_bits,
        primary_gap:               "source_clean (repaired retroactively via Batch 75A)",
      },
      parali_central: {
        hg_group:                  "HG-2B",
        promotion_batch:           60,
        quality_mask_retroactive:  `0x${PARALI_RETROACTIVE_MASK.toString(16).padStart(4,"0")}`,
        required_mask:             `0x${hg2b.toString(16).padStart(4,"0")}`,
        retroactive_verdict:       paraliRetro.verdict,
        known_missing:             paraliRetro.missing_bits,
        primary_gap:               "source_clean + codex_updated (both pre-doctrine)",
      },
    },
    next_batch: {
      batch90: "Quality audit on carbonx full promotion chain (Batches 62-74)",
      batch91: "Quality drift scanner — detect quality degradation post-promotion",
      batch92: "Fleet quality dashboard — quality_mask distribution across 61 services",
    },
    rules: ["AEG-Q-001", "AEG-Q-002", "AEG-Q-003"],
  }, null, 2) + "\n",
);

console.log(`  Schema:    quality/quality-mask-schema.json`);
console.log(`  Module:    src/enforcement/quality.ts`);
console.log(`  Template:  promotion-template.ts §5 added`);
console.log(`  Artifact:  audits/batch89_aegis_q_quality_evidence_doctrine.json`);
console.log(`  Verdict:   ${verdict}\n`);

if (verdict === "PASS") {
  console.log("  Safety says the agent may act. Quality says the work deserves to survive.\n");
}

if (verdict === "FAIL") process.exit(1);
