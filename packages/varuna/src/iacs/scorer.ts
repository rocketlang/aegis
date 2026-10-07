/**
 * IACS UR E26/E27 compliance scorer.
 * @rule:P2-001 Score all 25 capabilities from vessel state
 * @rule:VRN-001 IACS compliance assessment
 */

import type { IACSCapabilityResult, VesselState } from '../store/vessel.js';

import { IACS_CAPABILITIES } from './capabilities.js';

export interface IACSScore {
  pass: number;
  partial: number;
  fail: number;
  unknown: number;
  total: number;
  compliance_pct: number;
  critical_fails: string[];
  results: IACSCapabilityResult[];
}

// @rule:P2-001 Run all 25 capability assessments and persist to vessel state
export function runIACSScorer(vessel: VesselState): IACSScore {
  const now = Date.now();
  const results: IACSCapabilityResult[] = IACS_CAPABILITIES.map((cap) => {
    const { status, evidence } = cap.assess(vessel, now);
    return {
      cap_id: cap.cap_id,
      name: cap.name,
      iacs_clause: cap.iacs_clause,
      rule_id: cap.rule_id,
      status,
      evidence,
      assessed_at: now,
    };
  });

  vessel.iacs_audit = results;

  const pass = results.filter((r) => r.status === 'PASS').length;
  const partial = results.filter((r) => r.status === 'PARTIAL').length;
  const fail = results.filter((r) => r.status === 'FAIL').length;
  const unknown = results.filter((r) => r.status === 'UNKNOWN').length;
  const assessable = pass + partial + fail;
  const compliance_pct =
    assessable > 0 ? Math.round(((pass + partial * 0.5) / assessable) * 100) : 0;

  const critical_fails = results
    .filter((r) => r.status === 'FAIL')
    .map((r) => `${r.cap_id} ${r.name}`);

  return {
    pass,
    partial,
    fail,
    unknown,
    total: results.length,
    compliance_pct,
    critical_fails,
    results,
  };
}
