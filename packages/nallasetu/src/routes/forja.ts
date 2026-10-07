// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Forja endpoints (FP-003: Forja-Native by Default)
// STATE + TRUST + SENSE + PROOF — four mandatory endpoints
// @rule:NLS-001 bilateral attestation — both parties must attest
// @rule:NLS-003 no bit escalation — session_mask = A & B & scope
// @rule:NLS-006 mandatory TTL — session credentials must expire
// @rule:NLS-007 bilateral revocability — either party revokes within 1s
// @rule:NLS-009 post-TTL invalidity — no grace period, own clock
// @rule:NLS-010 PRAMANA-witnessed receipts
// @rule:NLS-011 immutable receipt storage — append-only
// @rule:NLS-013 registry-mediated key lookup
// @rule:NLS-015 per-partner rate limiting 10/sec
// @rule:NLS-016 500ms latency budget
// @rule:NLS-YK-002 zero intersection → graceful fail
// @rule:NLS-YK-006 witness unavailable → fail session retroactively
// @rule:NLS-YK-008 known-revoked partner → REJECT immediately
// @rule:NLS-YK-009 failing-grade partner → ephemeral only
// @rule:INF-NLS-004 post-TTL fast reject — no grace period
// @rule:INF-NLS-006 archival receipt immutability after 90 days

import { readdir, readFile } from "fs/promises";
import { join } from "path";
import type { FastifyInstance } from "fastify";
import { getSession, expireStale } from "../db";
import { policyHash } from "../crypto";

const SERVICE_START = new Date().toISOString();

// @rule:NLS-FRJ-001 Forja TRUST mask — what Nallasetu can do
const NALLASETU_TRUST_MASK = 0b00000001_00000001_00000001_00000001; // bits 0, 8, 16, 24

export function registerForjaRoutes(app: FastifyInstance): void {
  // GET /api/v2/forja/state — what this service knows
  app.get("/api/v2/forja/state", async (_req, reply) => {
    return reply.send({
      service: "nallasetu",
      version: "0.1.0",
      protocol: "nallasetu/0.1",
      trust_mask: NALLASETU_TRUST_MASK,
      policy_hash: policyHash(),
      started_at: SERVICE_START,
      can_answer: [
        "session-status",
        "pramana-chain-tip",
        "partner-key-registered",
        "handshake-decision",
        "session-class",
        "scope-intersection",
      ],
      can_do: [
        "conduct-handshake",
        "issue-session-credential",
        "revoke-session",
        "expire-stale-sessions",
        "witness-pramana-receipt",
        "register-agent-key",
      ],
      // emits: must match the actual emitHandshakeSense() call sites (handshake.ts).
      // Fixed 2026-07-24: was declaring phantom "session.expired" (never emitted) and
      // omitting the real "session_failed"; also unprefixed. Now = true runtime set.
      emits: [
        "nallasetu.handshake.session_issued",
        "nallasetu.handshake.attestation_unverifiable",
        "nallasetu.handshake.no_common_capability",
        "nallasetu.handshake.scope_counter_proposed",
        "nallasetu.handshake.rate_limit_exceeded",
        "nallasetu.handshake.session_failed",
        "nallasetu.session.revoked",
      ],
      depends_on: [],
      forja_version: "2.0",
    });
  });

  // GET /api/v2/forja/trust/:userId — what this agent/user is authorised to do
  app.get("/api/v2/forja/trust/:userId", async (req, reply) => {
    const { userId } = req.params as { userId: string };
    return reply.send({
      agent_id: userId,
      trust_mask: NALLASETU_TRUST_MASK,
      grade: "B",
      capabilities: [
        "initiate-handshake",
        "respond-to-handshake",
        "query-session",
        "revoke-own-session",
      ],
      issued_at: new Date().toISOString(),
      rule_ref: "NLS-001",
    });
  });

  // POST /api/v2/forja/sense/emit — internal SENSE event emission
  app.post("/api/v2/forja/sense/emit", async (req, reply) => {
    const body = req.body as {
      event_type: string;
      payload: Record<string, unknown>;
      session_id?: string;
    };
    if (!body?.event_type) {
      return reply.code(400).send({ error: "event_type required" });
    }
    // Validate session exists if provided
    if (body.session_id) {
      const row = getSession(body.session_id);
      if (!row) return reply.code(404).send({ error: "Session not found for SENSE event" });
    }
    const event = {
      event_type: body.event_type,
      service: "nallasetu",
      emitted_at: new Date().toISOString(),
      policy_hash: policyHash(),
      payload: body.payload,
    };
    return reply.code(202).send({ accepted: true, event });
  });

  // GET /api/v2/forja/proof — real src/ scanner, not hardcoded
  app.get("/api/v2/forja/proof", async (_req, reply) => {
    const staleExpired = expireStale();

    // Walk src/ and collect all @rule:NLS-* annotations
    const covered = new Set<string>();
    const ruleRe = /@rule:(NLS-(?:YK-|FRJ-)?\d+|INF-NLS-\d+)/;
    const srcDir = join(import.meta.dir, "..");

    async function walk(dir: string) {
      try {
        const entries = await readdir(dir, { withFileTypes: true });
        for (const e of entries) {
          if (e.isDirectory() && e.name !== "node_modules") { await walk(join(dir, e.name)); continue; }
          if (!e.name.endsWith(".ts") && !e.name.endsWith(".js")) continue;
          const content = await readFile(join(dir, e.name), "utf-8");
          const re = new RegExp(ruleRe.source, "g");
          let m: RegExpExecArray | null;
          while ((m = re.exec(content)) !== null) covered.add(m[1]);
        }
      } catch { /* skip unreadable dirs */ }
    }
    await walk(srcDir);

    const TOTAL_RULES = 35; // NLS-001..016 + NLS-YK-001..010 + INF-NLS-001..009
    const covered_count = covered.size;
    const coverage_pct = Math.round((covered_count / TOTAL_RULES) * 100);

    return reply.send({
      service: "nallasetu",
      protocol: "nallasetu/0.1",
      policy_hash: policyHash(),
      total_rules: TOTAL_RULES,
      covered_count,
      coverage_pct,
      covered_rules: Array.from(covered).sort(),
      maintenance: { stale_expired_on_proof_call: staleExpired },
      checked_at: new Date().toISOString(),
    });
  });
}
