/**
 * IACS UR E26/E27 compliance API.
 * @rule:P2-001 IACS 25-capability compliance score
 * @rule:CA-004 _meta on every resolver
 */

import { readFileSync } from 'node:fs';

import type { FastifyInstance } from 'fastify';

import { getVessel } from '../store/vessel.js';

import { IACS_CAPABILITIES } from './capabilities.js';
import { runIACSScorer } from './scorer.js';

// Notary base from the ports.json authority (R-008) — no port literal. The Evidence
// Notary registered at security.xshieldaiEvidenceNotary this session. Returns null when
// the authority is unreadable so the route degrades gracefully (notarization: null).
function notaryBase(): string | null {
  try {
    const p = JSON.parse(readFileSync('/root/.ankr/config/ports.json', 'utf8'));
    const port = p?.security?.xshieldaiEvidenceNotary;
    if (Number.isInteger(port)) return 'http://localhost:'.concat(String(port));
  } catch {
    /* authority unreadable */
  }
  return null;
}

export async function registerIACSRoutes(app: FastifyInstance): Promise<void> {
  // GET /api/v1/iacs/compliance/:vesselId — run full 25-capability assessment
  app.get<{ Params: { vesselId: string } }>(
    '/api/v1/iacs/compliance/:vesselId',
    async (request) => {
      const _start = Date.now();
      const vessel = getVessel(request.params.vesselId);
      const score = runIACSScorer(vessel);

      return {
        vessel_id: request.params.vesselId,
        iacs_compliance: {
          pass: score.pass,
          partial: score.partial,
          fail: score.fail,
          unknown: score.unknown,
          total: score.total,
          compliance_pct: score.compliance_pct,
        },
        critical_gaps: score.critical_fails,
        results: score.results,
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  // GET /api/v1/iacs/matrix — full capability + clause + MITRE mapping (static)
  app.get('/api/v1/iacs/matrix', async () => {
    const _start = Date.now();
    return {
      capabilities: IACS_CAPABILITIES.map((c) => ({
        cap_id: c.cap_id,
        name: c.name,
        iacs_clause: c.iacs_clause,
        rule_id: c.rule_id,
        mitre_technique_id: c.mitre_technique_id,
        mitre_technique_name: c.mitre_technique_name,
        description: c.description,
      })),
      total: IACS_CAPABILITIES.length,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/iacs/compliance/:vesselId/notarized — score, compose a class-verifiable
  // compliance deposition, and Ed25519-notarize it via the Evidence Notary. Tamper-evident,
  // independently verifiable. Degrades to notarization:null if the notary is unreachable.
  // @rule:P2-002 notarized IACS compliance report (IMO MSC.428(98) mandate)
  app.get<{ Params: { vesselId: string } }>(
    '/api/v1/iacs/compliance/:vesselId/notarized',
    async (request) => {
      const _start = Date.now();
      const vesselId = request.params.vesselId;
      const vessel = getVessel(vesselId);
      const score = runIACSScorer(vessel);

      const report =
        `VARUNA — IACS UR E26/E27 CYBER-COMPLIANCE REPORT\n` +
        `Vessel: ${vesselId}\n` +
        `Generated: ${new Date().toISOString()}\n` +
        `Standard: IMO MSC.428(98) cyber risk in the SMS · IACS UR E26 (ship) + E27 (onboard systems)\n\n` +
        `ASSESSMENT (25-capability)\n` +
        `  PASS ${score.pass} · PARTIAL ${score.partial} · FAIL ${score.fail} · UNKNOWN ${score.unknown} (of ${score.total})\n` +
        `  Compliance: ${score.compliance_pct}%\n\n` +
        `CRITICAL GAPS\n` +
        (score.critical_fails.length
          ? score.critical_fails.map((g: unknown) => `  • ${JSON.stringify(g)}`).join('\n')
          : '  (none)') +
        `\n\nMETHOD: automated posture assessment vs the vessel OT baseline; each capability cites its ` +
        `IACS clause + evidence. compute/quote/null — nothing guessed. Source is Varuna's witness ` +
        `(testbed unless a live vessel capture is wired).`;

      let notarization: unknown = null;
      const base = notaryBase();
      if (base) {
        try {
          const r = await fetch(base + '/notarize', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              pack: report,
              meta: { vessel_id: vesselId, type: 'iacs-compliance' },
            }),
          });
          if (r.ok) {
            const cert = (await r.json()) as { record?: { notaryId?: string }; signature?: string };
            notarization = {
              notaryId: cert.record?.notaryId,
              signature: cert.signature,
              record: cert.record,
              pubkey: base + '/pubkey',
              verify: base + '/verify',
            };
          }
        } catch {
          notarization = null; // notary unreachable — report still returned, unsigned
        }
      }

      return {
        vessel_id: vesselId,
        iacs_compliance: {
          pass: score.pass,
          partial: score.partial,
          fail: score.fail,
          unknown: score.unknown,
          total: score.total,
          compliance_pct: score.compliance_pct,
        },
        critical_gaps: score.critical_fails,
        report,
        notarization, // null if the notary was unreachable
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  app.log.info('IACS routes registered: compliance + matrix + notarized (VARUNA-P2-001/002)');
}
