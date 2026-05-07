// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS-Shastra Machine Law Routes
// @rule:KAV-SHT-001 lawful action map endpoint — pre-planning constraint surface

import type { FastifyInstance } from "fastify";
import { generateLawfulActionMap } from "../../machine-law/lawful-action-map";

export function registerMachineLawRoutes(app: FastifyInstance): void {

  // ── POST /api/v2/machine-law/action-map ────────────────────────────────────
  // Generate a lawful action map for an agent before it begins planning.
  // Returns: lawful_actions, forbidden_actions, human_gate_actions, prompt_injection.
  //
  // Body: { agent_id: string, mission: string }
  app.post("/api/v2/machine-law/action-map", async (req, reply) => {
    const t0 = performance.now();
    const body = req.body as { agent_id?: string; mission?: string };

    const agentId = body.agent_id?.trim() ?? "";
    const mission = body.mission?.trim() ?? "unspecified mission";

    if (!agentId) {
      return reply.code(400).send({ error: "agent_id is required", rule: "KAV-SHT-001" });
    }

    const map = generateLawfulActionMap(agentId, mission);

    return reply.send({
      ...map,
      _meta: {
        computed_at: map.generated_at,
        duration_ms: Math.round((performance.now() - t0) * 1000) / 1000,
        trust_mask_applied: true,
        rule: "KAV-SHT-001",
        schema: "aegis-lawful-action-map-v1",
      },
    });
  });

  // ── GET /api/v2/machine-law/action-map/:agentId ────────────────────────────
  // Convenience GET for quick inspection (mission defaults to "unspecified").
  app.get("/api/v2/machine-law/action-map/:agentId", async (req, reply) => {
    const { agentId } = req.params as { agentId: string };
    const map = generateLawfulActionMap(agentId, "unspecified mission");
    return reply.send({
      ...map,
      _meta: {
        computed_at: map.generated_at,
        trust_mask_applied: true,
        rule: "KAV-SHT-001",
        schema: "aegis-lawful-action-map-v1",
      },
    });
  });
}
