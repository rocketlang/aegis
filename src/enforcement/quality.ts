// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS-Q Quality Evidence Enforcement
// Schema: aegis-quality-16bit-v1
//
// Defines machine-verifiable quality capture for every AEGIS-governed service.
// Two time horizons — never conflate them:
//
//   quality_mask_at_promotion (bits 0–11): point-in-time evidence, set at the
//     moment of action. Verifiable by the promotion script.
//
//   quality_drift_score (bits 12–15): longitudinal evidence, set post-promotion
//     during the observation window. Never set at promotion time.
//
// Required masks by HG group form a strict superset chain:
//   HG-1 ⊂ HG-2A ⊂ HG-2B ⊂ HG-2B-financial
//
// Doctrine (AEG-Q-001):
//   Safety is permission. Quality is survival. Drift is the audit of time.
//
// @rule:AEG-Q-001 every promoted service must carry quality_mask_at_promotion
//   satisfying the required mask for its HG group
// @rule:AEG-Q-002 bits 12–15 (longitudinal) must never be set at promotion time
// @rule:AEG-Q-003 quality_drift_score is updated post-promotion only

export const QUALITY_SCHEMA  = "aegis-quality-16bit-v1";
export const QUALITY_VERSION = 1;
export const QUALITY_BATCH   = 89;

// ── Bit definitions ───────────────────────────────────────────────────────────

export interface QualityBit {
  id:          string;    // Q-001 to Q-016
  bit:         number;    // 0–15
  value:       number;    // 2^bit
  name:        string;
  horizon:     "point_in_time" | "longitudinal";
  description: string;
  verified_by: string;
}

export const QUALITY_BITS: QualityBit[] = [
  // ── Point-in-time (bits 0–11) — set at promotion ──────────────────────────
  { id:"Q-001", bit:0,  value:1,     horizon:"point_in_time", name:"typecheck_passed",
    description:"Type checker exits clean",
    verified_by:"tsc --noEmit exits 0" },
  { id:"Q-002", bit:1,  value:2,     horizon:"point_in_time", name:"tests_passed",
    description:"Test suite exits clean",
    verified_by:"test runner exits 0" },
  { id:"Q-003", bit:2,  value:4,     horizon:"point_in_time", name:"lint_passed",
    description:"Linter exits clean",
    verified_by:"eslint / biome exits 0" },
  { id:"Q-004", bit:3,  value:8,     horizon:"point_in_time", name:"no_unrelated_diff",
    description:"All changed files are within task scope",
    verified_by:"git diff --name-only ⊆ declared scope" },
  { id:"Q-005", bit:4,  value:16,    horizon:"point_in_time", name:"migration_verified",
    description:"No unguarded schema change",
    verified_by:"prisma migrate diff shows no DROP/ALTER COLUMN without migration" },
  { id:"Q-006", bit:5,  value:32,    horizon:"point_in_time", name:"rollback_verified",
    description:"Rollback path documented in audit artifact",
    verified_by:"audit artifact has rollback_path field" },
  { id:"Q-007", bit:6,  value:64,    horizon:"point_in_time", name:"docs_updated",
    description:"Service docs updated if code changed",
    verified_by:"doc hash changed when code changed" },
  { id:"Q-008", bit:7,  value:128,   horizon:"point_in_time", name:"codex_updated",
    description:"aegis_classification.classification_batch = this batch",
    verified_by:"codex.json classification_batch matches promotion batch" },
  { id:"Q-009", bit:8,  value:256,   horizon:"point_in_time", name:"audit_artifact_written",
    description:"Batch audit artifact exists and verdict=PASS",
    verified_by:"audits/batchN_*.json exists with verdict=PASS" },
  { id:"Q-010", bit:9,  value:512,   horizon:"point_in_time", name:"source_clean",
    description:"AEG-PROV-001: no dirty tree at promotion time",
    verified_by:"AEG-PROV-001 assertSourceControlProvenance passes without waiver" },
  { id:"Q-011", bit:10, value:1024,  horizon:"point_in_time", name:"no_secret_detected",
    description:"Secret scanner exits clean on diff",
    verified_by:"secret scanner exits 0 on git diff" },
  { id:"Q-012", bit:11, value:2048,  horizon:"point_in_time", name:"human_reviewed",
    description:"A human reviewed and approved before promotion",
    verified_by:"human_override_applied=true OR human_review_status=confirmed" },

  // ── Longitudinal (bits 12–15) — set post-promotion ────────────────────────
  { id:"Q-013", bit:12, value:4096,  horizon:"longitudinal", name:"idempotency_verified",
    description:"Re-run of the promotion script produces identical result",
    verified_by:"second run of batch script exits PASS" },
  { id:"Q-014", bit:13, value:8192,  horizon:"longitudinal", name:"observability_verified",
    description:"SENSE events fire as expected post-promotion",
    verified_by:"SENSE event audit confirms expected event schema" },
  { id:"Q-015", bit:14, value:16384, horizon:"longitudinal", name:"regression_clean",
    description:"No pre-existing passing tests broken post-promotion",
    verified_by:"test suite in 7-day window shows no new failures" },
  { id:"Q-016", bit:15, value:32768, horizon:"longitudinal", name:"production_fire_zero",
    description:"Zero incidents in 7-day observation window post-promotion",
    verified_by:"incident log shows 0 fires attributed to this service" },
];

// ── Required masks by HG group ────────────────────────────────────────────────
// Strict superset invariant: HG-1 ⊂ HG-2A ⊂ HG-2B ⊂ HG-2B-financial

export const HG_REQUIRED_QUALITY_MASK: Record<string, number> = {
  //                   bits required     hex       value
  "HG-1":             0x0302,  // {1,8,9}         tests + audit_artifact + source_clean
  "HG-2A":            0x0B83,  // HG-1+{0,7,11}   +typecheck + codex_updated + human_reviewed
  "HG-2B":            0x0FAB,  // HG-2A+{3,5,10}  +no_unrelated_diff + rollback + no_secret
  "HG-2B-financial":  0x0FFF,  // all 12 bits     complete point-in-time evidence
};

// ── Confidence tiers ──────────────────────────────────────────────────────────

export type QualityConfidence = "high" | "medium" | "low" | "unaudited";

export function qualityConfidence(
  hg_group: string,
  quality_mask_at_promotion: number,
): QualityConfidence {
  if (quality_mask_at_promotion === 0) return "unaudited";
  const required  = HG_REQUIRED_QUALITY_MASK[hg_group] ?? 0;
  const hg1Min    = HG_REQUIRED_QUALITY_MASK["HG-1"]!;
  if ((quality_mask_at_promotion & required) === required)  return "high";
  if ((quality_mask_at_promotion & hg1Min)   === hg1Min)    return "medium";
  return "low";
}

// ── assertQualityEvidence ─────────────────────────────────────────────────────

export interface QualityEvidenceResult {
  verdict:                    "PASS" | "FAIL";
  quality_mask_at_promotion:  number;
  quality_mask_required:      number;
  missing_bits:               string[];
  satisfied_bits:             string[];
  quality_confidence:         QualityConfidence;
  schema:                     string;
}

/**
 * Assert that a service's quality evidence satisfies the minimum required
 * for its HG group. Throws if quality_mask_at_promotion has longitudinal bits
 * set (AEG-Q-002 violation).
 *
 * @rule:AEG-Q-001
 * @rule:AEG-Q-002
 */
export function assertQualityEvidence(
  hg_group:                  string,
  quality_mask_at_promotion: number,
): QualityEvidenceResult {
  // AEG-Q-002: longitudinal bits must never be set at promotion time
  const longitudinalMask = 0xF000;
  if ((quality_mask_at_promotion & longitudinalMask) !== 0) {
    throw new Error(
      `AEG-Q-002: longitudinal bits (12–15) set in quality_mask_at_promotion=0x${quality_mask_at_promotion.toString(16)}. ` +
      `These must only appear in quality_drift_score, never at promotion time.`
    );
  }

  const required      = HG_REQUIRED_QUALITY_MASK[hg_group] ?? 0;
  const satisfied     = (quality_mask_at_promotion & required) === required;
  const pointInTime   = QUALITY_BITS.filter(b => b.horizon === "point_in_time");
  const missingBits   = pointInTime
    .filter(b => (required & b.value) !== 0 && (quality_mask_at_promotion & b.value) === 0)
    .map(b => b.name);
  const satisfiedBits = pointInTime
    .filter(b => (quality_mask_at_promotion & b.value) !== 0)
    .map(b => b.name);

  return {
    verdict:                   satisfied ? "PASS" : "FAIL",
    quality_mask_at_promotion,
    quality_mask_required:     required,
    missing_bits:              missingBits,
    satisfied_bits:            satisfiedBits,
    quality_confidence:        qualityConfidence(hg_group, quality_mask_at_promotion),
    schema:                    QUALITY_SCHEMA,
  };
}

// ── Drift update ──────────────────────────────────────────────────────────────

export interface QualityDriftUpdate {
  quality_drift_score:  number;
  updated_at:           string;
  observation_window:   string;
}

/**
 * Compute quality_drift_score from individual longitudinal bit states.
 * Called post-promotion, not at promotion time.
 *
 * @rule:AEG-Q-003
 */
export function computeQualityDriftScore(bits: {
  idempotency_verified:  boolean;
  observability_verified:boolean;
  regression_clean:      boolean;
  production_fire_zero:  boolean;
}): number {
  let score = 0;
  if (bits.idempotency_verified)   score |= 0x1000;
  if (bits.observability_verified) score |= 0x2000;
  if (bits.regression_clean)       score |= 0x4000;
  if (bits.production_fire_zero)   score |= 0x8000;
  return score;
}
