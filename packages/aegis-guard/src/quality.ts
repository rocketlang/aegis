// @rule:AEG-Q-001 — quality_mask_at_promotion: bits 0-11, point-in-time at promotion, immutable after
// @rule:AEG-Q-002 — quality_drift_score: bits 12-15, longitudinal, post-promotion only
// @rule:AEG-Q-003 — bits 12-15 must NEVER be set in quality_mask_at_promotion

export interface QualityEvidenceInput {
  typecheck_passed?: boolean;           // bit 0  — Q-001
  tests_passed?: boolean;               // bit 1  — Q-002
  lint_passed?: boolean;                // bit 2  — Q-003
  no_unrelated_diff?: boolean;          // bit 3  — Q-004
  migration_verified?: boolean;         // bit 4  — Q-005
  rollback_tested?: boolean;            // bit 5  — Q-006
  dependency_checked?: boolean;         // bit 6  — Q-007
  codex_updated?: boolean;              // bit 7  — Q-008
  audit_artifact_produced?: boolean;    // bit 8  — Q-009
  scope_confirmed?: boolean;            // bit 9  — Q-010
  no_secrets_exposed?: boolean;         // bit 10 — Q-011
  human_reviewed?: boolean;             // bit 11 — Q-012
}

const PROMOTION_BIT_MAP: Array<[keyof QualityEvidenceInput, number]> = [
  ['typecheck_passed',        0],
  ['tests_passed',            1],
  ['lint_passed',             2],
  ['no_unrelated_diff',       3],
  ['migration_verified',      4],
  ['rollback_tested',         5],
  ['dependency_checked',      6],
  ['codex_updated',           7],
  ['audit_artifact_produced', 8],
  ['scope_confirmed',         9],
  ['no_secrets_exposed',      10],
  ['human_reviewed',          11],
];

// @rule:AEG-Q-003 — bits 12-15 are never touched by this function (point-in-time only)
export function buildQualityMaskAtPromotion(evidence: QualityEvidenceInput): number {
  let mask = 0;
  for (const [field, bit] of PROMOTION_BIT_MAP) {
    if (evidence[field] === true) mask |= (1 << bit);
  }
  return mask;
}

export interface QualityDriftInput {
  idempotency_evidenced?: boolean;      // bit 12 — Q-013
  observability_evidenced?: boolean;    // bit 13 — Q-014
  regression_suite_pass?: boolean;      // bit 14 — Q-015
  production_fire_zero?: boolean;       // bit 15 — Q-016
}

const DRIFT_BIT_MAP: Array<[keyof QualityDriftInput, number]> = [
  ['idempotency_evidenced',   12],
  ['observability_evidenced', 13],
  ['regression_suite_pass',   14],
  ['production_fire_zero',    15],
];

// @rule:AEG-Q-002 — drift bits 12-15 only; never OR'd with promotion mask into a single field
export function buildQualityDriftScore(drift: QualityDriftInput): number {
  let score = 0;
  for (const [field, bit] of DRIFT_BIT_MAP) {
    if (drift[field] === true) score |= (1 << bit);
  }
  return score;
}

// HG group minimum quality mask requirements (promotion bits 0-11 only)
export const HG_REQUIRED_MASKS = {
  'HG-1':            0x0302,
  'HG-2A':           0x0B83,
  'HG-2B':           0x0FAB,
  'HG-2B-financial': 0x0FFF,
} as const;

export type HgGroup = keyof typeof HG_REQUIRED_MASKS;

export function meetsHgQualityRequirement(hgGroup: HgGroup, qualityMask: number): boolean {
  const required = HG_REQUIRED_MASKS[hgGroup];
  return (qualityMask & required) === required;
}
