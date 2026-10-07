// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Session management routes
// @rule:NLS-011 append-only — revoke updates status only, never deletes
// @rule:NLS-008 no credential reuse — expired sessions remain in DB

import type { FastifyInstance } from "fastify";
import {
  getSession, revokeSession, expireStale,
  getLastPramanaHash, appendPramanaChain,
} from "../db";
import { hashReceipt, pramanaWitness, policyHash } from "../crypto";
import { emitHandshakeSense } from "../sense";
import type { SessionReceipt } from "../types";

export function registerSessionRoutes(app: FastifyInstance): void {
  // GET /api/v2/nallasetu/sessions/:sessionId — lookup a session
  app.get("/api/v2/nallasetu/sessions/:sessionId", async (req, reply) => {
    const t0 = performance.now();
    const { sessionId } = req.params as { sessionId: string };
    const row = getSession(sessionId);
    if (!row) return reply.code(404).send({ error: "Session not found" });
    return reply.send({
      session_id: row.session_id,
      initiator_id: row.initiator_id,
      responder_id: row.responder_id,
      session_mask: row.session_mask,
      session_class: row.session_class,
      status: row.status,
      issued_at: row.issued_at,
      expires_at: row.expires_at,
      pramana_hash: row.pramana_hash,
      // @rule:CA-004 telemetry minimum
      _meta: { computed_at: new Date().toISOString(), duration_ms: Math.round(performance.now() - t0), trust_mask_applied: row.session_mask },
    });
  });

  // POST /api/v2/nallasetu/sessions/:sessionId/revoke — @rule:NLS-011
  app.post("/api/v2/nallasetu/sessions/:sessionId/revoke", async (req, reply) => {
    const t0 = performance.now();
    const { sessionId } = req.params as { sessionId: string };
    // @rule:CA-002 named consent — confirm_revoke_session: true required, no force:true pattern
    const body = req.body as { confirm_revoke_session?: boolean; reason?: string };
    if (!body?.confirm_revoke_session) {
      return reply.code(400).send({
        error: "confirm_revoke_session: true required — CA-002 named consent",
        rule_ref: "CA-002",
      });
    }
    const row = getSession(sessionId);

    if (!row) return reply.code(404).send({ error: "Session not found" });
    if (row.status !== "active") {
      return reply.code(409).send({ error: `Session already ${row.status}` });
    }

    const credential = JSON.parse(row.credential_json);
    const receiptHash = hashReceipt(credential.credential_hash, "revoked");
    const previousPramana = getLastPramanaHash();
    const pramanaHash = pramanaWitness(receiptHash, previousPramana);

    const receipt: SessionReceipt = {
      session_id: sessionId,
      initiator_id: row.initiator_id,
      responder_id: row.responder_id,
      session_mask: row.session_mask,
      outcome: "revoked",
      early_termination: true,
      termination_reason: body?.reason ?? "caller-requested",
      receipt_hash: receiptHash,
      pramana_witness: pramanaHash,
      issued_at: new Date().toISOString(),
      rule_ref: "NLS-010",
    };

    revokeSession(sessionId, JSON.stringify(receipt));
    appendPramanaChain(sessionId, receiptHash, pramanaHash);

    emitHandshakeSense("nallasetu.session.revoked", {
      session_id: sessionId,
      initiator_id: row.initiator_id,
      responder_id: row.responder_id,
      session_mask: row.session_mask,
      decision: "session_revoked",
      policy_hash: policyHash(),
      latency_ms: 0,
      rule_ref: "NLS-010/NLS-011",
    }, sessionId);

    return reply.send({
      decision: "session_revoked",
      receipt,
      policy_hash: policyHash(),
      // @rule:CA-004 telemetry minimum
      _meta: { computed_at: new Date().toISOString(), duration_ms: Math.round(performance.now() - t0), trust_mask_applied: row.session_mask },
    });
  });

  // POST /api/v2/nallasetu/sessions/expire-stale — maintenance endpoint
  app.post("/api/v2/nallasetu/sessions/expire-stale", async (_req, reply) => {
    const count = expireStale();
    return reply.send({ expired: count });
  });

  // GET /api/v2/nallasetu/pramana/tip — latest PRAMANA chain hash
  app.get("/api/v2/nallasetu/pramana/tip", async (_req, reply) => {
    return reply.send({ pramana_tip: getLastPramanaHash() });
  });
}
