/**
 * aggregateFactors — fold normalized PostureFactors into one vessel posture.
 *
 * Detector-AGNOSTIC by design (VRN-P0-2 acceptance): adding a new detector family is a
 * new `*ToFactors` adapter + one registry line — this function never changes. Scoring
 * is consequence-weighted off the severity ladder (one catastrophic > many nuisance,
 * VRN-ARCH-010), not a flat count.
 *
 * @rule:VRN-ARCH-010 consequence-weighted posture
 * @rule:VRN-ARCH-007 the posture reports the data_source(s) it was built from
 */

import {
  isValidFactor,
  SEVERITY_RANK,
  SEVERITY_WEIGHT,
  type Actor,
  type DataSource,
  type PostureFactor,
  type Severity,
} from './types.js';

export interface VesselPosture {
  /** All valid factors, worst-severity first. */
  factors: PostureFactor[];
  count: number;
  by_severity: Record<Severity, number>;
  by_actor: Record<Actor, number>;
  /** Worst severity present, or null when clean. */
  worst_severity: Severity | null;
  /**
   * 0–100 posture deduction. A single catastrophic saturates to 100 — you cannot
   * "average away" a runaway-diesel precursor with clean reads. @rule:VRN-ARCH-010
   */
  deduction: number;
  /** Provenance set the posture was assembled from (honesty floor). */
  data_sources: DataSource[];
  /** Factors that were dropped for missing severity/actor/data_source (INF-VRN-019). */
  blocked: number;
}

const SEVERITIES: Severity[] = ['catastrophic', 'serious', 'moderate', 'nuisance'];
const ACTORS: Actor[] = ['insider', 'outsider', 'rogue_agent', 'unknown'];

export function aggregateFactors(input: Array<Partial<PostureFactor>>): VesselPosture {
  const valid: PostureFactor[] = [];
  let blocked = 0;
  for (const f of input) {
    if (isValidFactor(f)) valid.push(f);
    else blocked++;
  }

  const by_severity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  const by_actor = Object.fromEntries(ACTORS.map((a) => [a, 0])) as Record<Actor, number>;
  const sources = new Set<DataSource>();

  for (const f of valid) {
    by_severity[f.severity]++;
    by_actor[f.actor]++;
    sources.add(f.data_source);
  }

  // consequence-weighted deduction: any catastrophic → 100; else diminishing sum capped at 95.
  let deduction = 0;
  if (by_severity.catastrophic > 0) {
    deduction = 100;
  } else {
    let acc = 0;
    // worst-first so the dominant factor carries full weight, the rest diminish.
    const sorted = [...valid].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    sorted.forEach((f, i) => {
      acc += SEVERITY_WEIGHT[f.severity] * Math.pow(0.6, i);
    });
    deduction = Math.min(95, Math.round(acc));
  }

  const worst = SEVERITIES.find((s) => by_severity[s] > 0) ?? null;

  return {
    factors: valid.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]),
    count: valid.length,
    by_severity,
    by_actor,
    worst_severity: worst,
    deduction,
    data_sources: [...sources],
    blocked,
  };
}
