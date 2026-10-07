/**
 * Crew cyber role management + HanumanG sync.
 * @rule:VRN-005 Named crew cyber roles — not assumed
 * @rule:VRN-021 Crew cyber competency evidence
 * @rule:VRN-022 Notification chain completeness
 * @rule:P3-001  HanumanG crew role verification integration
 */

import type { FastifyInstance } from 'fastify';

import { getVessel } from '../store/vessel.js';

const HANUMANG_URL = process.env['HANUMANG_URL'] ?? 'http://localhost:4255';

export interface CrewRoleEntry {
  crew_id: string;
  name: string;
  role: 'cyber_officer' | 'dpa' | 'technical_superintendent' | 'captain' | 'officer';
  competency_drills: number;
  competency_evidence: string | null;
  notification_chain: boolean;
  registered_at: number;
}

// @rule:VRN-005 Crew role registry per vessel (in-memory Phase 1/2)
const crewRoleStore = new Map<string, Map<string, CrewRoleEntry>>();

function getCrewRoles(vessel_id: string): Map<string, CrewRoleEntry> {
  if (!crewRoleStore.has(vessel_id)) crewRoleStore.set(vessel_id, new Map());
  return crewRoleStore.get(vessel_id)!;
}

export async function registerCrewRoutes(app: FastifyInstance): Promise<void> {
  // POST /api/v1/crew/roles/:vesselId — register/update crew role
  app.post<{
    Params: { vesselId: string };
    Body: {
      crew_id: string;
      name: string;
      role: CrewRoleEntry['role'];
      competency_drills?: number;
      competency_evidence?: string;
      notification_chain?: boolean;
    };
  }>('/api/v1/crew/roles/:vesselId', async (request, reply) => {
    const _start = Date.now();
    const {
      crew_id,
      name,
      role,
      competency_drills = 0,
      competency_evidence = null,
      notification_chain = false,
    } = request.body;

    if (!crew_id || !name || !role)
      return reply.status(400).send({ error: 'crew_id, name, and role are required' });

    const vessel_id = request.params.vesselId;
    const entry: CrewRoleEntry = {
      crew_id,
      name,
      role,
      competency_drills,
      competency_evidence,
      notification_chain,
      registered_at: Date.now(),
    };

    getCrewRoles(vessel_id).set(crew_id, entry);

    // @rule:P3-001 Sync to HanumanG (graceful degradation — disabled/unavailable is OK)
    const hanumang_synced = await syncToHanumanG(vessel_id, entry, app.log);

    return {
      registered: true,
      vessel_id,
      crew_id,
      role,
      hanumang_synced,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/crew/roles/:vesselId — list crew roles
  app.get<{ Params: { vesselId: string } }>('/api/v1/crew/roles/:vesselId', async (request) => {
    const _start = Date.now();
    const vessel_id = request.params.vesselId;
    const roles = [...getCrewRoles(vessel_id).values()];

    // @rule:VRN-022 Notification chain completeness check
    const has_cyber_officer = roles.some((r) => r.role === 'cyber_officer');
    const has_dpa = roles.some((r) => r.role === 'dpa');
    const notification_chain_complete = roles.some((r) => r.notification_chain);
    const competency_gap = roles.filter((r) => r.competency_drills < 2).map((r) => r.name);

    // Update IACS CAP-04 (Least Privilege) assessment from UNKNOWN → PARTIAL/PASS
    const vessel = getVessel(vessel_id);
    const cap04 = vessel.iacs_audit.find((c) => c.cap_id === 'CAP-04');
    if (cap04 && roles.length > 0) {
      cap04.status = has_cyber_officer && has_dpa ? 'PASS' : 'PARTIAL';
      cap04.evidence = `${roles.length} crew roles registered. Cyber officer: ${has_cyber_officer}. DPA: ${has_dpa}.`;
      cap04.assessed_at = Date.now();
    }

    return {
      vessel_id,
      crew_count: roles.length,
      roles,
      compliance: {
        has_cyber_officer,
        has_dpa,
        notification_chain_complete,
        competency_gap,
        vrn_005_status:
          has_cyber_officer && has_dpa ? 'PASS' : roles.length > 0 ? 'PARTIAL' : 'FAIL',
        vrn_022_status: notification_chain_complete ? 'PASS' : 'FAIL',
      },
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  app.log.info('Crew routes registered: role management + HanumanG sync (VARUNA-P3-001)');
}

// @rule:P3-001 Sync to HanumanG agent registry when available
async function syncToHanumanG(
  vessel_id: string,
  entry: CrewRoleEntry,
  log: FastifyInstance['log']
): Promise<boolean> {
  try {
    const res = await fetch(`${HANUMANG_URL}/api/agents/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        context: 'xshieldai-varuna',
        vessel_id,
        crew_id: entry.crew_id,
        role: entry.role,
        competency_drills: entry.competency_drills,
        notification_chain: entry.notification_chain,
      }),
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    log.debug(
      { vessel_id, crew_id: entry.crew_id },
      '[crew] HanumanG not available — sync skipped'
    );
    return false;
  }
}
