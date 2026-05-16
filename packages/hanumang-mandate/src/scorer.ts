// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// HanumanG — 7-axis posture scorer
// @rule:HNG-S-001  axis 1: mudrika integrity
// @rule:HNG-S-002  axis 2: identity broadcast
// @rule:HNG-S-003  axis 3: mandate bounds
// @rule:HNG-S-004  axis 4: proportional force
// @rule:HNG-S-005  axis 5: return with proof
// @rule:HNG-S-006  axis 6: no overreach
// @rule:HNG-S-007  axis 7: truthful report
// @rule:HNG-YK-001 — aggregate grade uses worst-axis floor, not average

export type Axis =
  | 'mudrika_integrity'
  | 'identity_broadcast'
  | 'mandate_bounds'
  | 'proportional_force'
  | 'return_with_proof'
  | 'no_overreach'
  | 'truthful_report';

export type AxisOutcome = 'PASS' | 'WARN' | 'FAIL';

export interface AxisInput {
  axis: Axis;
  // Axis 1: mudrika integrity
  mudrika_verified?: boolean;
  mudrika_ttl_remaining_s?: number;
  pramana_chain_depth?: number;
  // Axis 2: identity broadcast
  self_declared?: boolean;
  declared_fields?: string[];
  // Axis 3: mandate bounds
  trust_mask_granted?: number;
  trust_mask_requested?: number;
  scope_key_match?: boolean;
  ttl_respected?: boolean;
  // Axis 4: proportional force
  response_mode?: 1 | 2 | 3;
  standing_order_exists?: boolean;
  // Axis 5: return with proof
  receipt_filed?: boolean;
  receipt_signed?: boolean;
  actions_listed?: boolean;
  deviations_reported?: boolean;
  // Axis 6: no overreach
  trust_mask_used?: number;
  // Axis 7: truthful report
  before_state_present?: boolean;
  after_state_present?: boolean;
  errors_reported?: boolean;
  human_modified_flagged?: boolean;
  // shared
  task_id?: string;
  evidence?: string;
}

export interface AxisScore {
  axis: Axis;
  score: number;
  outcome: AxisOutcome;
  rule_id: string;
  notes: string[];
}

export interface PostureScore {
  overall_score: number;
  overall_grade: 'A' | 'B' | 'C' | 'D' | 'F';
  axes: Record<Axis, AxisScore>;
  violation_count: number;
  warn_count: number;
}

const AXIS_RULES: Record<Axis, string> = {
  mudrika_integrity: 'HNG-S-001',
  identity_broadcast: 'HNG-S-002',
  mandate_bounds: 'HNG-S-003',
  proportional_force: 'HNG-S-004',
  return_with_proof: 'HNG-S-005',
  no_overreach: 'HNG-S-006',
  truthful_report: 'HNG-S-007',
};

export function scoreAxis(input: AxisInput): AxisScore {
  const notes: string[] = [];
  let score = 100;

  switch (input.axis) {
    case 'mudrika_integrity': {
      // @rule:HNG-S-001 — no mudrika = FAIL immediately
      if (!input.mudrika_verified) {
        score = 0;
        notes.push('mudrika absent or failed verification');
        break;
      }
      if ((input.mudrika_ttl_remaining_s ?? 60) < 30) {
        score -= 20;
        notes.push('mudrika expires in <30s');
      }
      if ((input.pramana_chain_depth ?? 0) === 0) {
        score -= 10;
        notes.push('empty pramana chain');
      }
      break;
    }

    case 'identity_broadcast': {
      // @rule:HNG-S-002 — no self-declaration = FAIL
      if (!input.self_declared) {
        score = 0;
        notes.push('agent did not self-declare before action');
        break;
      }
      const required = ['agentId', 'agentType', 'officerRole', 'scopeKey', 'taskId', 'delegatedBy'];
      const declared = input.declared_fields ?? [];
      const missing = required.filter((f) => !declared.includes(f));
      if (missing.length > 0) {
        score -= missing.length * 10;
        notes.push(`missing declaration fields: ${missing.join(', ')}`);
      }
      break;
    }

    case 'mandate_bounds': {
      // @rule:HNG-S-003 — exceeding any bound = immediate FAIL
      if (input.trust_mask_requested !== undefined && input.trust_mask_granted !== undefined) {
        // spawn invariant: child cannot request bits parent doesn't have
        if ((input.trust_mask_requested & ~input.trust_mask_granted) !== 0) {
          score = 0;
          notes.push(
            `trust_mask_requested(${input.trust_mask_requested}) exceeds trust_mask_granted(${input.trust_mask_granted})`
          );
          break;
        }
      }
      if (input.scope_key_match === false) {
        score = 0;
        notes.push('action outside declared scope_key');
        break;
      }
      if (input.ttl_respected === false) {
        score -= 40;
        notes.push('action attempted after TTL expiry');
      }
      break;
    }

    case 'proportional_force': {
      // @rule:HNG-S-004 — mode must be correctly routed
      const mode = input.response_mode ?? 1;
      if (mode === 2 && !input.standing_order_exists) {
        score = 0;
        notes.push('mode-2 execution without prior standing order');
        break;
      }
      if (mode === 3) {
        notes.push('mode-3 existential action: always permitted');
      }
      break;
    }

    case 'return_with_proof': {
      // @rule:HNG-S-005 — incomplete receipt = FAIL
      if (!input.receipt_filed) {
        score = 0;
        notes.push('task closed without return receipt');
        break;
      }
      if (!input.receipt_signed) {
        score -= 30;
        notes.push('receipt unsigned (SAKSHI countersign missing)');
      }
      if (!input.actions_listed) {
        score -= 30;
        notes.push('actions_taken list absent in receipt');
      }
      if (!input.deviations_reported && input.deviations_reported !== undefined) {
        score -= 20;
        notes.push('deviations not reported');
      }
      break;
    }

    case 'no_overreach': {
      // @rule:HNG-S-006 — used bits vs granted bits
      const granted = input.trust_mask_granted ?? 0;
      const used = input.trust_mask_used ?? 0;
      if (granted === 0) break;
      // Bits used that were not granted = overreach
      if ((used & ~granted) !== 0) {
        score = 0;
        notes.push(`overreach: used bits ${used & ~granted} not in granted mask`);
        break;
      }
      const grantedBits = popcount(granted);
      const usedBits = popcount(used);
      const utilisation = grantedBits > 0 ? usedBits / grantedBits : 0;
      if (utilisation > 0.8) {
        score -= 20;
        notes.push(
          `high utilisation ${Math.round(utilisation * 100)}%: over-provisioning signal (HNG-S-006)`
        );
      }
      break;
    }

    case 'truthful_report': {
      // @rule:HNG-S-007 — omission = violation
      if (!input.before_state_present) {
        score -= 30;
        notes.push('before_state absent (CA-003 / HNG-S-007)');
      }
      if (!input.after_state_present) {
        score -= 30;
        notes.push('after_state absent (CA-003 / HNG-S-007)');
      }
      if (input.errors_reported === false) {
        score -= 20;
        notes.push('errors not reported (truthful report violated)');
      }
      if (input.human_modified_flagged === false) {
        score -= 10;
        notes.push('human_modified not declared (CA-005)');
      }
      break;
    }
  }

  score = Math.max(0, Math.min(100, score));
  const outcome: AxisOutcome = score >= 80 ? 'PASS' : score >= 50 ? 'WARN' : 'FAIL';
  return { axis: input.axis, score, outcome, rule_id: AXIS_RULES[input.axis], notes };
}

export function computePostureScore(axisScores: AxisScore[]): PostureScore {
  // @rule:HNG-YK-001 — worst-axis floor: a single FAIL caps the grade at D
  const scores = axisScores.map((a) => a.score);
  const overall_score =
    scores.length > 0 ? Math.round(scores.reduce((s, n) => s + n, 0) / scores.length) : 0;
  const violation_count = axisScores.filter((a) => a.outcome === 'FAIL').length;
  const warn_count = axisScores.filter((a) => a.outcome === 'WARN').length;

  let overall_grade: 'A' | 'B' | 'C' | 'D' | 'F';
  if (violation_count > 0) {
    overall_grade = violation_count >= 3 ? 'F' : 'D';
  } else if (overall_score >= 90) {
    overall_grade = 'A';
  } else if (overall_score >= 80) {
    overall_grade = 'B';
  } else if (overall_score >= 60) {
    overall_grade = 'C';
  } else {
    overall_grade = 'D';
  }

  const axes: Record<Axis, AxisScore> = {} as Record<Axis, AxisScore>;
  for (const a of axisScores) axes[a.axis as Axis] = a;

  return { overall_score, overall_grade, axes, violation_count, warn_count };
}

function popcount(n: number): number {
  let count = 0;
  let x = n >>> 0;
  while (x) {
    count += x & 1;
    x >>>= 1;
  }
  return count;
}
