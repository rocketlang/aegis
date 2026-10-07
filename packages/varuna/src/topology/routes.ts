/**
 * Zone/conduit topology intake + vendor laptop alert.
 * @rule:VRN-002 Zone/conduit topology is the architectural truth
 * @rule:VRN-030 IEC 62443 zone model
 * @rule:VRN-029 Vendor laptop risk scoring
 */

import type { FastifyInstance } from 'fastify';

import { emitSense } from '../sense/emit.js';
import { getVessel, type VesselTopology } from '../store/vessel.js';

export async function registerTopologyRoutes(app: FastifyInstance): Promise<void> {
  // @rule:VRN-002 Import vessel network zone/conduit topology
  // @rule:VRN-030 IEC 62443 zone model — flat network = CRITICAL finding
  app.post<{
    Params: { vesselId: string };
    Body: VesselTopology;
  }>('/api/v1/topology/:vesselId', async (request) => {
    const _start = Date.now();
    const vessel_id = request.params.vesselId;
    const topo = request.body;

    // @rule:VRN-008 Flat network (no zones) = non-compliant
    const flat_network = !topo.zones || topo.zones.length < 2;
    const unenforced_conduits = (topo.conduits ?? []).filter((c) => !c.enforced);

    const vessel = getVessel(vessel_id);
    vessel.topology = { ...topo, vessel_id, imported_at: Date.now(), flat_network };

    if (flat_network) {
      emitSense(app.log, {
        event_type: 'vrn.iacs_compliance.gap.found',
        vessel_id,
        rule_id: 'VRN-008',
        severity: 'CRITICAL',
        before_snapshot: { segmented: false },
        after_snapshot: { flat_network: true, zones: topo.zones?.length ?? 0 },
        delta: {
          iacs_gap: 'IACS UR E27 §5.2 — network segmentation required',
          zones_found: topo.zones?.length ?? 0,
        },
      });
    }

    return {
      vessel_id,
      zones: topo.zones?.length ?? 0,
      conduits: topo.conduits?.length ?? 0,
      unenforced_conduits: unenforced_conduits.length,
      flat_network,
      imported_at: new Date().toISOString(),
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/topology/:vesselId
  app.get<{ Params: { vesselId: string } }>('/api/v1/topology/:vesselId', async (request) => {
    const _start = Date.now();
    const vessel = getVessel(request.params.vesselId);
    return {
      vessel_id: request.params.vesselId,
      topology: vessel.topology,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // @rule:VRN-029 Vendor laptop connection alert
  // @rule:VRN-YK-006 New device on OT VLAN during non-maintenance window = alert
  app.post<{
    Body: {
      vessel_id: string;
      device_mac: string;
      device_ip: string;
      connected_zone: string;
      maintenance_window?: boolean;
    };
  }>('/api/v1/ingest/new-device', async (request, reply) => {
    const _start = Date.now();
    const {
      vessel_id,
      device_mac,
      device_ip,
      connected_zone,
      maintenance_window = false,
    } = request.body;

    if (!vessel_id || !device_mac)
      return reply.status(400).send({ error: 'vessel_id and device_mac are required' });

    const is_ot_zone =
      connected_zone?.toLowerCase().includes('engine') ||
      connected_zone?.toLowerCase().includes('cargo') ||
      connected_zone?.toLowerCase().includes('ot');

    const severity = is_ot_zone && !maintenance_window ? 'CRITICAL' : 'WARN';

    emitSense(app.log, {
      event_type: 'vrn.vendor_laptop.connection.detected',
      vessel_id,
      rule_id: 'VRN-029',
      severity,
      before_snapshot: { new_device: false },
      after_snapshot: { new_device: true, device_mac, device_ip, zone: connected_zone },
      delta: { maintenance_window, is_ot_zone },
    });

    return {
      alerted: true,
      vessel_id,
      device_mac,
      connected_zone,
      severity,
      action:
        severity === 'CRITICAL'
          ? 'BLOCK_RECOMMENDED — trigger Vishvakarma package scan'
          : 'MONITOR',
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  app.log.info(
    'Topology routes registered: import + vendor laptop alert (VARUNA-P1-010 to P1-011)'
  );
}
