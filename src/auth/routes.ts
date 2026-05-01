// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Aegis Authorization Layer — Fastify route handlers
//
// POST /api/v1/aegis/sdt/issue       — issue a new Scoped Delegation Token
// POST /api/v1/aegis/authorize       — 6-condition ABAC gate
// GET  /api/v1/aegis/authorize/:id   — poll human-in-loop escalation
// POST /api/v1/aegis/authorize/:id/decide — resolve an escalation (human action)
//
// @rule:AGS-001 @rule:AGS-008 @rule:AGS-010 @rule:AGS-015

import type { FastifyInstance } from "fastify";
import type { AuthorizeRequest, SdtIssueRequest } from "./types";
import { issueSdt } from "./sdt";
import { authorize, getEscalation, decideEscalation } from "./authorize";

export function registerAuthRoutes(app: FastifyInstance): void {

  // ── Issue a Scoped Delegation Token ────────────────────────────────────────
  app.post<{ Body: SdtIssueRequest }>("/api/v1/aegis/sdt/issue", async (req, reply) => {
    try {
      const body = req.body;
      if (!body?.agent_id || !body?.agent_class || !body?.spawner_id) {
        return reply.code(400).send({ error: "missing required fields: agent_id, agent_class, spawner_id" });
      }
      if (!body.task_scope || !Array.isArray(body.task_scope)) {
        return reply.code(400).send({ error: "task_scope must be a non-empty array" });
      }
      const result = issueSdt(body);
      return reply.code(201).send(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.startsWith("PARENT_NOT_FOUND") || msg.startsWith("PARENT_CHAIN_INVALID")) {
        return reply.code(422).send({ error: msg });
      }
      return reply.code(500).send({ error: "SDT issuance failed", detail: msg });
    }
  });

  // ── 6-condition ABAC authorize gate ───────────────────────────────────────
  app.post<{ Body: AuthorizeRequest }>("/api/v1/aegis/authorize", async (req, reply) => {
    try {
      const body = req.body;
      if (!body?.agent_token || !body?.resource || !body?.action) {
        return reply.code(400).send({ error: "missing required fields: agent_token, resource, action" });
      }
      const result = await authorize(body);
      // 202 for pending HIL; 200 for authorized/denied
      const code = result.status === "pending" ? 202 : 200;
      return reply.code(code).send(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.code(500).send({ error: "authorize failed", detail: msg });
    }
  });

  // ── Poll escalation status ────────────────────────────────────────────────
  app.get<{ Params: { id: string } }>("/api/v1/aegis/authorize/:id", async (req, reply) => {
    const esc = getEscalation(req.params.id);
    if (!esc) return reply.code(404).send({ error: "escalation not found" });
    return reply.send(esc);
  });

  // ── Resolve escalation (human decision) ───────────────────────────────────
  app.post<{ Params: { id: string }; Body: { decision: "approved" | "rejected" } }>(
    "/api/v1/aegis/authorize/:id/decide",
    async (req, reply) => {
      const { decision } = req.body ?? {};
      if (decision !== "approved" && decision !== "rejected") {
        return reply.code(400).send({ error: "decision must be 'approved' or 'rejected'" });
      }
      const updated = decideEscalation(req.params.id, decision);
      if (!updated) return reply.code(404).send({ error: "escalation not found or already decided" });
      return reply.send({ ok: true, decision });
    },
  );

  // ── SDT audit log query ───────────────────────────────────────────────────
  app.get<{ Querystring: { agent_id?: string; limit?: string } }>(
    "/api/v1/aegis/sdt/audit",
    async (req, reply) => {
      const { agent_id, limit = "50" } = req.query;
      const db = (await import("../core/db")).getDb();
      const rows = agent_id
        ? db.query<Record<string, unknown>, [string, number]>(
            "SELECT * FROM sdt_authorize_log WHERE agent_id = ? ORDER BY decided_at DESC LIMIT ?",
          ).all(agent_id, parseInt(limit, 10))
        : db.query<Record<string, unknown>, [number]>(
            "SELECT * FROM sdt_authorize_log ORDER BY decided_at DESC LIMIT ?",
          ).all(parseInt(limit, 10));
      return reply.send({ rows });
    },
  );
}
