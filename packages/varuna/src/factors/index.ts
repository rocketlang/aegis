/**
 * Varuna factor seam — the one normalized surface the card, dashboard, and reconciler read.
 *
 * Adding a detector family = a new `<threat>.ts` adapter exporting `meta.verb` +
 * `<x>ToFactors()`, then one line in ADAPTERS here. aggregateFactors() never changes
 * (VRN-P0-2). The reconciler derives the codex can_do from ADAPTERS[].verb — code-truth,
 * cannot drift (VRN-ARCH-006).
 *
 * @rule:VRN-ARCH-001 one file per threat   @rule:VRN-ARCH-006 code-truth codex
 */

export * from './types.js';
export { aggregateFactors, type VesselPosture } from './aggregate.js';

import { meta as aisMeta, aisFindingsToFactors, type AisFinding } from './ais-spoof.js';
import { meta as modbusMeta, modbusAnomaliesToFactors } from './modbus-anomaly.js';
import { meta as nmeaMeta, nmeaAnomaliesToFactors } from './nmea-injection.js';
import { meta as runawayMeta, runawayToFactor, type RunawayPrecursor } from './runaway-sequence.js';
import type { FactorAdapterMeta } from './types.js';

export { modbusAnomaliesToFactors, runawayToFactor, nmeaAnomaliesToFactors, aisFindingsToFactors };
export type { AisFinding, RunawayPrecursor };

/**
 * The shipped detector-family surface. The reconciler reads `.verb` from each entry as
 * the codex can_do code-truth; declared verbs with no entry here are OVERCLAIMS.
 */
export const ADAPTERS: FactorAdapterMeta[] = [modbusMeta, runawayMeta, nmeaMeta, aisMeta];

/** Verbs that are code-truth (a real adapter exists). */
export const SHIPPED_VERBS: string[] = ADAPTERS.map((a) => a.verb);
