// SPDX-License-Identifier: AGPL-3.0-only
// AEGIS Dashboard — visitor scope routes (design: proposals/aegis-aface-pilot--brainstorm--formal--2026-11-13.md §7).
//
//   POST /api/v2/visitor/gate         a product asks: may this principal spend `cost` turns on this capability?
//                                      Opened by that product's token (visitor.tokens in ~/.aegis/config.json) and
//                                      nothing else (B2). The session guard lets the token through for this route only.
//   GET  /api/v2/visitor/principals    list principals (dashboard session)
//   GET  /api/v2/visitor/decisions     recent decisions (dashboard session)
//   POST /api/v2/visitor/quarantine    kill switch for one principal; reason + by required (dashboard session)
//   POST /api/v2/visitor/release       release; reason + by required (dashboard session)
//   POST /api/v2/visitor/grant         record a person's grant to an agent; scope only narrows (dashboard session)
// @rule:AFACE-010
import type { FastifyInstance } from "fastify";
import { getDb } from "../../core/db";
import { loadConfig } from "../../core/config";
import { VISITOR_GATE_ROUTE, decideVisit, ensureVisitorTables, recordGrant, setQuarantine, visitorTokenFor } from "../../visitor/visitor";

const visitorConfig = () => ((loadConfig() as any)?.visitor ?? {}) as { tokens?: Record<string, string>; products?: Record<string, unknown> };

function send(reply: any, e: any) {
  if (e && typeof e === "object" && "status" in e) return reply.code(e.status).send({ error: e.error });
  return reply.code(500).send({ error: "visitor gate failed" });
}

export function registerVisitorRoutes(app: FastifyInstance): void {
  let ready = false;
  const db = () => { const d = getDb(); if (!ready) { ensureVisitorTables(d); ready = true; } return d; };

  app.post(VISITOR_GATE_ROUTE, async (req, reply) => {
    const cfg = visitorConfig();
    const product = visitorTokenFor(req.headers["authorization"] as string | undefined, cfg.tokens);
    if (!product) return reply.code(401).send({ error: "a product token is required for this route" });
    try {
      const t0 = performance.now();
      const d = decideVisit(db(), product, (req.body ?? {}) as any, cfg.products);
      return reply.send({ ...d, _meta: { duration_ms: Math.round((performance.now() - t0) * 1000) / 1000 } });
    } catch (e) { return send(reply, e); }
  });

  app.get("/api/v2/visitor/principals", async (req, reply) => {
    const q = req.query as { product?: string };
    const rows = q.product
      ? db().prepare(`SELECT * FROM visitor_principals WHERE product = ? ORDER BY last_seen DESC LIMIT 500`).all(q.product)
      : db().prepare(`SELECT * FROM visitor_principals ORDER BY last_seen DESC LIMIT 500`).all();
    return reply.send({ principals: rows });
  });

  app.get("/api/v2/visitor/decisions", async (req, reply) => {
    const q = req.query as { limit?: string };
    const limit = Math.min(500, Math.max(1, parseInt(q.limit ?? "100", 10) || 100));
    return reply.send({ decisions: db().prepare(`SELECT * FROM visitor_decisions ORDER BY id DESC LIMIT ?`).all(limit) });
  });

  for (const [path, on] of [["/api/v2/visitor/quarantine", true], ["/api/v2/visitor/release", false]] as const) {
    app.post(path, async (req, reply) => {
      const b = (req.body ?? {}) as { product?: string; principal?: string; reason?: string; by?: string };
      try {
        const changed = setQuarantine(db(), String(b.product ?? ""), String(b.principal ?? ""), on, String(b.reason ?? ""), String(b.by ?? ""));
        return changed ? reply.send({ ok: true }) : reply.code(404).send({ error: "no such principal" });
      } catch (e) { return send(reply, e); }
    });
  }

  app.post("/api/v2/visitor/grant", async (req, reply) => {
    try { return reply.send({ ok: true, principal: recordGrant(db(), (req.body ?? {}) as any, visitorConfig().products) }); }
    catch (e) { return send(reply, e); }
  });
}
