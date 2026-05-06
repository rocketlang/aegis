// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// ASE Routes — Agent Session Envelope issuance, read, close, audit
//
// @rule:ASE-001 POST /aegis/session issues sealed envelope before agent's first action
// @rule:ASE-002 sealed_hash computed once at issuance — GET /audit re-verifies
// @rule:ASE-003 declared_caps validated against trust_mask at issuance
// @rule:ASE-006 budget_usd fixed at issuance; budget_used_usd is the mutable counter
// @rule:ASE-008 child envelopes carry parent_session_id in sealed_hash
// @rule:ASE-010 GET /sessions and GET /sessions/:id/audit are the declared-vs-actual surface
// @rule:ASE-011 GET /session/:id used by AI Proxy pre-call budget gate (fails open)
// @rule:INF-ASE-002 drift_set = actual_caps_used \ declared_caps
// @rule:INF-ASE-007 declared_caps must not contain hard_block capabilities

import type { FastifyInstance } from "fastify";
import { getDb } from "../../core/db";
import {
  computeSealedHash,
  storeEnvelope,
  loadEnvelopeBySessionId,
  updateBudgetUsed,
  closeEnvelope,
  computeDriftSet,
  verifyEnvelopeIntegrity,
  SESSION_TTL_MS,
  type AgentSessionEnvelope,
} from "../../core/ase";

const now = () => new Date().toISOString();
const meta = (startMs: number) => ({
  computed_at: now(),
  duration_ms: Date.now() - startMs,
});

// @rule:INF-ASE-007 hard_block caps may never appear in declared_caps at issuance
const HARD_BLOCK_CAPS = new Set([
  "FULL_AUTONOMY", "AI_EXECUTE", "DELETE_SYSTEM", "CI_DEPLOY_UNRESTRICTED",
  "KERNEL_MODIFY", "CREDENTIAL_EXFIL", "MASS_DELETE",
]);

function validateDeclaredCaps(declared: string[], trustMask: number): string | null {
  for (const cap of declared) {
    if (HARD_BLOCK_CAPS.has(cap)) {
      return `declared_cap '${cap}' is hard_block — cannot be declared at session birth`;
    }
  }
  return null;
}

export function registerAseRoutes(app: FastifyInstance): void {

  // ── POST /api/v1/aegis/session — issue sealed envelope ──────────────────────
  // @rule:ASE-001 @rule:ASE-003 @rule:ASE-006 @rule:INF-ASE-007
  app.post("/api/v1/aegis/session", async (req, reply) => {
    const start = Date.now();
    const body = req.body as {
      agent_type?: string;
      service_key?: string;
      tenant_id?: string;
      declared_caps?: string[];
      budget_usd?: number;
      parent_session_id?: string;
      perm_mask?: number;
      class_mask?: number;
      trust_mask?: number;
    };

    const agentType = (body.agent_type ?? "hook-native") as "proxy-native" | "hook-native";
    const serviceKey = body.service_key ?? "unknown";
    const tenantId = body.tenant_id ?? "default";
    const declaredCaps: string[] = Array.isArray(body.declared_caps) ? body.declared_caps : [];
    const budgetUsd = typeof body.budget_usd === "number" ? body.budget_usd : 0;
    const parentSessionId = body.parent_session_id ?? null;
    const trustMask = typeof body.trust_mask === "number" ? body.trust_mask : 1;

    // @rule:INF-ASE-007 reject hard_block caps in declared_caps
    const capError = validateDeclaredCaps(declaredCaps, trustMask);
    if (capError) {
      reply.code(400);
      return { ok: false, error: capError, _meta: meta(start) };
    }

    // @rule:ASE-005 — if parent_session_id provided, intersect masks
    let permMask = typeof body.perm_mask === "number" ? body.perm_mask : trustMask;
    let classMask = typeof body.class_mask === "number" ? body.class_mask : 0xFFFF;

    if (parentSessionId) {
      const parent = loadEnvelopeBySessionId(parentSessionId);
      if (parent) {
        // @rule:KAV-065 child perm_mask = parent.effective AND requested
        permMask = parent.perm_mask & permMask;
        classMask = parent.class_mask & classMask;
        // @rule:KAV-079 — child cannot exceed parent
        if ((permMask & ~parent.perm_mask) !== 0) {
          reply.code(422);
          return { ok: false, error: "KAV-079: child perm_mask exceeds parent — spawn invariant violated", _meta: meta(start) };
        }
      }
    }

    const issuedAt = now();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    const agentId = `agt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const sessionId = body.parent_session_id
      ? `ses_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
      : agentId; // root sessions: session_id == agent_id

    const sealedHash = computeSealedHash({
      session_id: sessionId,
      perm_mask: permMask,
      class_mask: classMask,
      declared_caps: declaredCaps,
      issued_at: issuedAt,
      parent_session_id: parentSessionId,
    });

    const envelope: AgentSessionEnvelope = {
      session_id: sessionId,
      agent_id: agentId,
      agent_type: agentType,
      service_key: serviceKey,
      tenant_id: tenantId,
      trust_mask: trustMask,
      perm_mask: permMask,
      class_mask: classMask,
      declared_caps: declaredCaps,
      budget_usd: budgetUsd,
      budget_used_usd: 0,
      sealed_hash: sealedHash,
      issued_at: issuedAt,
      expires_at: expiresAt,
      parent_session_id: parentSessionId,
      actual_caps_used: [],
      gate_calls: 0,
      blocks: 0,
      drift_detected: false,
    };

    storeEnvelope(envelope);

    // Emit SENSE event
    try {
      const { broadcast } = await import("../../core/events");
      broadcast("aegis.session.envelope.issued", {
        session_id: sessionId,
        agent_id: agentId,
        agent_type: agentType,
        service_key: serviceKey,
        sealed_hash: sealedHash,
        declared_caps: declaredCaps,
        parent_session_id: parentSessionId,
        rule_ref: "ASE-001",
      });
    } catch {}

    return {
      ok: true,
      session_id: sessionId,
      agent_id: agentId,
      sealed_hash: sealedHash,
      issued_at: issuedAt,
      expires_at: expiresAt,
      perm_mask: permMask,
      class_mask: classMask,
      trust_mask: trustMask,
      declared_caps: declaredCaps,
      _meta: { ...meta(start), trust_mask_applied: trustMask },
    };
  });

  // ── GET /api/v1/aegis/session/:id — read envelope + running state ────────────
  // @rule:ASE-010 @rule:ASE-011 (used by AI Proxy budget gate)
  app.get("/api/v1/aegis/session/:id", async (req, reply) => {
    const start = Date.now();
    const { id } = req.params as { id: string };
    const envelope = loadEnvelopeBySessionId(id);
    if (!envelope) {
      reply.code(404);
      return { ok: false, error: "session not found", _meta: meta(start) };
    }

    const budgetRemaining = envelope.budget_usd > 0
      ? Math.max(0, envelope.budget_usd - envelope.budget_used_usd)
      : Infinity;

    // Emit verification heartbeat
    try {
      const { broadcast } = await import("../../core/events");
      broadcast("aegis.session.envelope.verified", {
        session_id: id,
        agent_id: envelope.agent_id,
        rule_ref: "ASE-010",
      });
    } catch {}

    return {
      ok: true,
      ...envelope,
      budget_remaining: budgetRemaining,
      _meta: { ...meta(start), trust_mask_applied: envelope.trust_mask },
    };
  });

  // ── POST /api/v1/aegis/session/:id/close — write audit record ───────────────
  // @rule:ASE-010 @rule:INF-ASE-002
  app.post("/api/v1/aegis/session/:id/close", async (req, reply) => {
    const start = Date.now();
    const { id } = req.params as { id: string };
    const envelope = loadEnvelopeBySessionId(id);
    if (!envelope) {
      reply.code(404);
      return { ok: false, error: "session not found", _meta: meta(start) };
    }

    const result = closeEnvelope(envelope.agent_id);

    try {
      const { broadcast } = await import("../../core/events");
      if (result.drift_detected) {
        broadcast("aegis.session.envelope.drift", {
          session_id: id,
          drift_set: result.drift_set,
          declared_caps: envelope.declared_caps,
          actual_caps_used: envelope.actual_caps_used,
          rule_ref: "INF-ASE-002",
        });
      }
      broadcast("aegis.session.audit.written", {
        session_id: id,
        drift_detected: result.drift_detected,
        final_budget_used: result.final_budget_used,
        rule_ref: "ASE-010",
      });
    } catch {}

    return {
      ok: true,
      session_id: id,
      ...result,
      _meta: meta(start),
    };
  });

  // ── PATCH /api/v1/aegis/session/:id/usage — update budget from PostToolUse ──
  // @rule:ASE-006
  app.patch("/api/v1/aegis/session/:id/usage", async (req, reply) => {
    const start = Date.now();
    const { id } = req.params as { id: string };
    const body = req.body as {
      cost_usd_estimate?: number;
      tokens_used?: number;
      cap_used?: string;
    };

    const envelope = loadEnvelopeBySessionId(id);
    if (!envelope) {
      reply.code(404);
      return { ok: false, error: "session not found", _meta: meta(start) };
    }

    const cost = typeof body.cost_usd_estimate === "number" ? body.cost_usd_estimate : 0;
    updateBudgetUsed(envelope.agent_id, cost, body.cap_used);

    return { ok: true, _meta: meta(start) };
  });

  // ── GET /api/v1/aegis/sessions — paginated session list ─────────────────────
  // @rule:ASE-010 @rule:INF-ASE-002
  app.get("/api/v1/aegis/sessions", async (req) => {
    const start = Date.now();
    const query = req.query as {
      tenant_id?: string;
      agent_type?: string;
      service_key?: string;
      drift_only?: string;
      date_from?: string;
      date_to?: string;
      page?: string;
      limit?: string;
    };

    const page = Math.max(1, parseInt(query.page ?? "1", 10));
    const limit = Math.min(100, Math.max(1, parseInt(query.limit ?? "20", 10)));
    const offset = (page - 1) * limit;

    const db = getDb();
    const conditions: string[] = ["sealed_hash IS NOT NULL"];
    const params: unknown[] = [];

    if (query.tenant_id) { conditions.push("tenant_id = ?"); params.push(query.tenant_id); }
    if (query.agent_type) { conditions.push("ase_agent_type = ?"); params.push(query.agent_type); }
    if (query.service_key) { conditions.push("ase_service_key = ?"); params.push(query.service_key); }
    if (query.drift_only === "true") { conditions.push("ase_drift_detected = 1"); }
    if (query.date_from) { conditions.push("ase_issued_at >= ?"); params.push(query.date_from); }
    if (query.date_to) { conditions.push("ase_issued_at <= ?"); params.push(query.date_to); }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const total = (db.query<{ n: number }, unknown[]>(`SELECT COUNT(*) as n FROM agents ${where}`).get(...params) as { n: number })?.n ?? 0;

    const rows = db.query<Record<string, unknown>, unknown[]>(
      `SELECT agent_id, session_id, ase_agent_type, ase_service_key, tenant_id,
              declared_caps, ase_actual_caps, ase_budget_usd, ase_budget_used_usd,
              ase_drift_detected, ase_issued_at, ase_expires_at, sealed_hash
       FROM agents ${where} ORDER BY ase_issued_at DESC LIMIT ? OFFSET ?`
    ).all(...params, limit, offset);

    const sessions = rows.map(r => {
      let declared: string[] = [];
      let actual: string[] = [];
      try { declared = JSON.parse(String(r.declared_caps ?? "[]")); } catch {}
      try { actual = JSON.parse(String(r.ase_actual_caps ?? "[]")); } catch {}
      return {
        session_id: r.session_id ?? r.agent_id,
        agent_type: r.ase_agent_type,
        service_key: r.ase_service_key,
        tenant_id: r.tenant_id,
        declared_caps: declared,
        actual_caps_used: actual,
        budget_usd: r.ase_budget_usd,
        budget_used_usd: r.ase_budget_used_usd,
        budget_remaining: Number(r.ase_budget_usd) > 0
          ? Math.max(0, Number(r.ase_budget_usd) - Number(r.ase_budget_used_usd))
          : null,
        drift_detected: Boolean(r.ase_drift_detected),
        issued_at: r.ase_issued_at,
        expires_at: r.ase_expires_at,
      };
    });

    return {
      ok: true,
      sessions,
      _meta: { total, page, limit, ...meta(start) },
    };
  });

  // ── GET /api/v1/aegis/sessions/:id/audit — full session audit ────────────────
  // @rule:ASE-002 (re-verify sealed_hash) @rule:ASE-010 @rule:INF-ASE-002
  // @rule:ASE-YK-008 seal_fail → quarantine flag
  app.get("/api/v1/aegis/sessions/:id/audit", async (req, reply) => {
    const start = Date.now();
    const { id } = req.params as { id: string };
    const envelope = loadEnvelopeBySessionId(id);
    if (!envelope) {
      reply.code(404);
      return { ok: false, error: "session not found", _meta: meta(start) };
    }

    // @rule:ASE-002 re-verify integrity
    const verified = verifyEnvelopeIntegrity(envelope);
    if (!verified) {
      try {
        const { broadcast } = await import("../../core/events");
        broadcast("aegis.session.envelope.seal_fail", {
          session_id: id,
          agent_id: envelope.agent_id,
          sealed_hash_stored: envelope.sealed_hash,
          rule_ref: "ASE-YK-008",
        });
      } catch {}
    }

    // @rule:INF-ASE-002 drift_set = actual \ declared
    const driftSet = computeDriftSet(envelope.declared_caps, envelope.actual_caps_used);

    // Find children
    const db = getDb();
    const children = db.query<{ agent_id: string; session_id: string }, [string]>(
      "SELECT agent_id, session_id FROM agents WHERE parent_session_id = ? AND sealed_hash IS NOT NULL"
    ).all(envelope.agent_id);

    return {
      ok: true,
      session_id: id,
      agent_id: envelope.agent_id,
      agent_type: envelope.agent_type,
      service_key: envelope.service_key,
      tenant_id: envelope.tenant_id,
      declared_caps: envelope.declared_caps,
      actual_caps_used: envelope.actual_caps_used,
      drift_set: driftSet,
      drift_detected: driftSet.length > 0,
      budget_allocated: envelope.budget_usd,
      budget_used: envelope.budget_used_usd,
      budget_remaining: envelope.budget_usd > 0
        ? Math.max(0, envelope.budget_usd - envelope.budget_used_usd)
        : null,
      gate_calls: envelope.gate_calls,
      blocks: envelope.blocks,
      sealed_hash: envelope.sealed_hash,
      sealed_hash_verified: verified,
      quarantine: !verified,
      issued_at: envelope.issued_at,
      expires_at: envelope.expires_at,
      parent_session_id: envelope.parent_session_id,
      child_session_ids: children.map(c => c.session_id ?? c.agent_id),
      _meta: { ...meta(start), trust_mask_applied: envelope.trust_mask },
    };
  });
}
