// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Handshake route
// POST /api/v2/nallasetu/handshake — five-primitive protocol entry point
// @rule:NLS-016 500ms latency budget enforced at route level

import type { FastifyInstance } from "fastify";
import { conductHandshake } from "../handshake";
import type { HandshakeRequest } from "../types";

export function registerHandshakeRoutes(app: FastifyInstance): void {
  // @rule:NLS-016 latency budget — 500ms hard limit
  app.post("/api/v2/nallasetu/handshake", {
    config: { timeout: 500 },
  }, async (req, reply) => {
    const body = req.body as HandshakeRequest;

    if (!body?.initiator?.agent_id || !body?.responder_id || body?.scope_mask === undefined) {
      return reply.code(400).send({
        error: "Missing required fields: initiator.agent_id, responder_id, scope_mask",
        rule_ref: "NLS-001",
      });
    }

    const t0 = performance.now();
    const result = await conductHandshake(body);

    const statusMap: Record<string, number> = {
      session_issued:                  201,
      attestation_unverifiable:        401,
      no_common_capability:            409,
      scope_counter_proposed:          409,
      handshake_rate_limit_exceeded:   429,
      handshake_timeout:               504,
      attestation_format_incompatible: 400,
    };

    const status = statusMap[result.decision] ?? 500;
    // @rule:CA-004 telemetry minimum — _meta on every response
    return reply.code(status).send({
      ...result,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Math.round(performance.now() - t0),
        trust_mask_applied: body.scope_mask,
      },
    });
  });
}
