/**
 * Internal SENSE event emitter.
 * @rule:VRN-015 Every posture state change fires a SENSE event.
 * @rule:CA-003 All SENSE events carry before_snapshot + after_snapshot + delta.
 */

import { randomUUID } from 'crypto';

import type { FastifyBaseLogger } from 'fastify';

import { getVessel, type SenseEvent } from '../store/vessel.js';

export function emitSense(
  log: FastifyBaseLogger,
  params: {
    event_type: string;
    vessel_id: string;
    rule_id: string | null;
    severity: SenseEvent['severity'];
    before_snapshot: Record<string, unknown>;
    after_snapshot: Record<string, unknown>;
    delta: Record<string, unknown>;
  }
): SenseEvent {
  const event: SenseEvent = {
    id: randomUUID(),
    ...params,
    timestamp: Date.now(),
  };

  const vessel = getVessel(params.vessel_id);
  vessel.senseEvents.push(event);

  // Keep last 500 events per vessel
  if (vessel.senseEvents.length > 500) vessel.senseEvents.shift();

  log.info(
    {
      event_type: event.event_type,
      vessel_id: event.vessel_id,
      severity: event.severity,
      rule_id: event.rule_id,
    },
    'VRN SENSE'
  );

  return event;
}
