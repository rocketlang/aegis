/**
 * Background posture degradation monitor.
 * @rule:VRN-015 Continuous monitoring — score re-evaluated without user request
 * @rule:VRN-050 Living score — degrades automatically when telemetry changes
 * @rule:P3-003  Background cron fires vrn.posture.degraded when score drops > 10
 */

import type { FastifyBaseLogger } from 'fastify';

import { appendEdge } from '../edge/ledger.js';
import { computePostureScore } from '../posture/scorer.js';
import { emitSense } from '../sense/emit.js';
import { appendScoreHistory, getVessel, listVessels } from '../store/vessel.js';

const DEGRADATION_THRESHOLD = 10;
const TAXII_SYNC_EVERY_N_CYCLES = 6; // sync TAXII every 6 × interval = 30 min default

let cycleCount = 0;

// @rule:P3-003 Single monitor cycle — called on each interval tick
export async function runMonitorCycle(log: FastifyBaseLogger): Promise<void> {
  cycleCount++;
  const vessels = listVessels();
  let degraded = 0;

  for (const vessel_id of vessels) {
    const vessel = getVessel(vessel_id);
    const prev = vessel.postureScore;
    const { score: newScore, band, findings } = computePostureScore(vessel);

    // @rule:VRN-EDGE-001 persist the posture snapshot on-disk each cycle — the Box's
    // offline-first 24/7 record, survives power cycle, buffered until sync-on-connect.
    appendEdge({ vessel_id, posture_score: newScore, posture_band: band, kind: 'posture' });

    if (prev === null) {
      // First time scoring — just set, no degradation event
      vessel.postureScore = newScore;
      continue;
    }

    const delta = prev - newScore;
    if (delta >= DEGRADATION_THRESHOLD) {
      // @rule:P3-003 Checkpoint before overwrite, then fire degradation event
      appendScoreHistory(vessel, {
        posture_score: prev,
        posture_band: prev >= 80 ? 'GREEN' : prev >= 50 ? 'AMBER' : 'RED',
        iacs_pass: vessel.iacs_audit.filter((r) => r.status === 'PASS').length,
        iacs_fail: vessel.iacs_audit.filter((r) => r.status === 'FAIL').length,
        checkpoint_at: Date.now(),
        trigger: 'background_monitor_degradation',
      });

      vessel.postureScore = newScore;

      emitSense(log, {
        event_type: 'vrn.posture.degraded',
        vessel_id,
        rule_id: 'VRN-050',
        severity: band === 'RED' ? 'CRITICAL' : 'WARN',
        before_snapshot: {
          posture_score: prev,
          posture_band: prev >= 80 ? 'GREEN' : prev >= 50 ? 'AMBER' : 'RED',
        },
        after_snapshot: { posture_score: newScore, posture_band: band },
        delta: {
          score_delta: -delta,
          trigger_findings: findings.filter((f) => f.severity === 'CRITICAL').map((f) => f.rule_id),
        },
      });

      degraded++;
      log.warn(
        { vessel_id, prev, newScore, delta, band },
        '[monitor] posture degraded — vrn.posture.degraded emitted'
      );
    } else if (newScore !== prev) {
      // Minor change — update silently, no event
      vessel.postureScore = newScore;
    }
  }

  if (vessels.length > 0) {
    log.debug({ vessels: vessels.length, degraded, cycle: cycleCount }, '[monitor] cycle complete');
  }

  // TAXII sync every N cycles
  if (cycleCount % TAXII_SYNC_EVERY_N_CYCLES === 0) {
    await syncTAXIIFeed(log);
  }
}

// @rule:P3-002 TAXII feed sync — pull and correlate STIX indicators
async function syncTAXIIFeed(log: FastifyBaseLogger): Promise<void> {
  const taxiiUrl = process.env['TAXII_URL'] ?? 'http://localhost:4250';
  const endpoint = `${taxiiUrl}/taxii/api/collections/xshield-ioc/objects/`;

  try {
    const res = await fetch(endpoint, {
      headers: { Accept: 'application/taxii+json;version=2.1' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      log.debug({ status: res.status }, '[monitor] TAXII feed unavailable — skipping');
      return;
    }
    const body = (await res.json()) as { objects?: unknown[] };
    const objects = body.objects ?? [];
    if (objects.length > 0) {
      log.info({ count: objects.length }, '[monitor] TAXII indicators fetched — correlating');
      correlateSTIXIndicators(log, objects);
    }
  } catch {
    // TAXII endpoint not available — silent skip
  }
}

// @rule:P3-002 Heuristic STIX indicator correlation against vessel anomaly state
function correlateSTIXIndicators(log: FastifyBaseLogger, objects: unknown[]): void {
  const vessels = listVessels();

  for (const obj of objects) {
    if (typeof obj !== 'object' || obj === null) continue;
    const stix = obj as Record<string, unknown>;
    if (stix['type'] !== 'indicator') continue;

    const pattern = String(stix['pattern'] ?? '').toLowerCase();
    const indicatorId = String(stix['id'] ?? 'unknown');
    const name = String(stix['name'] ?? '');

    // Classify indicator by protocol keyword
    const affectsModbus =
      pattern.includes('modbus') || pattern.includes('fc:05') || pattern.includes('fc:06');
    const affectsNMEA =
      pattern.includes('nmea') || pattern.includes('gpgga') || pattern.includes('hehdt');
    const affectsAIS = pattern.includes('ais') || pattern.includes('mmsi');

    for (const vessel_id of vessels) {
      const vessel = getVessel(vessel_id);

      const hasModbusExposure = vessel.modbusAnomalies.length > 0 || !vessel.modbusBaselineLocked;
      const hasNMEAExposure =
        vessel.nmeaAnomalies.filter((a) => a.severity === 'CRITICAL').length > 0;
      const hasAISExposure = vessel.gpsAnomalies.filter((a) => a.type.includes('ais')).length > 0;

      if (
        (affectsModbus && hasModbusExposure) ||
        (affectsNMEA && hasNMEAExposure) ||
        (affectsAIS && hasAISExposure)
      ) {
        emitSense(log, {
          event_type: 'vrn.iacs_compliance.gap.found',
          vessel_id,
          rule_id: 'VRN-YK-007',
          severity: 'WARN',
          before_snapshot: { stix_correlated: false },
          after_snapshot: {
            stix_correlated: true,
            indicator_id: indicatorId,
            indicator_name: name,
          },
          delta: {
            affects_modbus: affectsModbus,
            affects_nmea: affectsNMEA,
            affects_ais: affectsAIS,
          },
        });

        log.warn(
          { vessel_id, indicator_id: indicatorId, name },
          '[monitor] STIX indicator correlated against vessel exposure'
        );
      }
    }
  }
}

// @rule:P3-003 Start background monitor — called after server listen
export function startBackgroundMonitor(
  log: FastifyBaseLogger,
  intervalMs = parseInt(process.env['MONITOR_INTERVAL_MS'] ?? '300000') // default 5 min
): NodeJS.Timeout {
  log.info({ intervalMs }, '[monitor] Background posture monitor started');
  return setInterval(() => {
    runMonitorCycle(log).catch((err) => {
      log.error({ err }, '[monitor] Cycle error');
    });
  }, intervalMs);
}
