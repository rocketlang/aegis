/**
 * AIS + GPS ingest routes.
 * @rule:VRN-035 AIS spoofing detection
 * @rule:VRN-036 GPS position-jump detection
 */

import type { FastifyInstance } from 'fastify';

import { getVessel } from '../store/vessel.js';

import { observeAIS, observeGPS } from './detector.js';

export async function registerAISRoutes(app: FastifyInstance): Promise<void> {
  // @rule:VRN-035 Ingest AIS message observation
  app.post<{
    Body: {
      vessel_id: string;
      mmsi: string;
      msg_type: number;
      lat: number;
      lon: number;
      timestamp?: number;
      own_ship?: boolean;
    };
  }>('/api/v1/ingest/ais', async (request, reply) => {
    const _start = Date.now();
    const { vessel_id, mmsi, msg_type, lat, lon, own_ship = false } = request.body;
    const timestamp = request.body.timestamp ?? Date.now();

    if (!vessel_id || !mmsi)
      return reply.status(400).send({ error: 'vessel_id and mmsi are required' });

    const result = observeAIS(app.log, {
      vessel_id,
      mmsi,
      msg_type,
      lat,
      lon,
      timestamp,
      own_ship,
    });
    const vessel = getVessel(vessel_id);

    return {
      ingested: true,
      vessel_id,
      mmsi,
      mmsi_count: vessel.mmsiRegistry.size,
      anomaly_detected: result.anomaly,
      anomaly_type: result.type ?? null,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // @rule:VRN-036 Ingest GPS/GNSS position observation
  app.post<{
    Body: { vessel_id: string; lat: number; lon: number; timestamp?: number };
  }>('/api/v1/ingest/gps', async (request, reply) => {
    const _start = Date.now();
    const { vessel_id, lat, lon } = request.body;
    const timestamp = request.body.timestamp ?? Date.now();

    if (!vessel_id) return reply.status(400).send({ error: 'vessel_id is required' });

    const result = observeGPS(app.log, vessel_id, { lat, lon, timestamp });

    return {
      ingested: true,
      vessel_id,
      lat,
      lon,
      anomaly_detected: result.anomaly,
      jump_nm: result.jump_nm ?? null,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/ais/status/:vesselId
  app.get<{ Params: { vesselId: string } }>('/api/v1/ais/status/:vesselId', async (request) => {
    const _start = Date.now();
    const vessel = getVessel(request.params.vesselId);
    return {
      vessel_id: request.params.vesselId,
      mmsi_count: vessel.mmsiRegistry.size,
      own_ship_mmsi: vessel.ownShipMmsi,
      last_gps: vessel.lastGpsPosition,
      last_ais: vessel.lastAisPosition,
      gps_anomalies: vessel.gpsAnomalies.slice(-20),
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  app.log.info('AIS/GPS routes registered: ingest + status (VARUNA-P1-007 to P1-009)');
}
