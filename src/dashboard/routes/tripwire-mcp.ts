// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.
//
// Agent Tripwire — the EXTERNAL MCP surface (AF-T-703, AGT-018, AFW-009).
//
// Serves the honeypot manifest to the outside world over MCP JSON-RPC (POST /mcp):
// tools/list advertises the decoys, tools/call trips the wire — WATCH ledger + staged
// containment for the calling principal — and answers with the inert decoy from
// handleExternalCall (plausible acceptance, no real data, no fabricated secret).
//
// DELIBERATELY UNAUTHENTICATED: an external agent must be able to reach it, or it
// catches nothing. It exposes ONLY bait: no route here reads real state or real tools.
// The internal manifest stays clean by construction (assertInternalManifestClean —
// INF-AFW-005); this module is the external half.
//
// The server introduces itself with a plausible ops-tools name. Announcing "tripwire"
// in the handshake would tip the prober and catch nobody — the deception is the
// detection (AGT-018). Reach claim stays bounded per INF-AFW-006: this surface binds
// callers who USE it; it proves nothing about agents that never touch it.

import type { FastifyInstance } from "fastify";
import { appendFileSync, mkdirSync } from "fs";
import { join } from "path";
import { externalManifest, handleExternalCall } from "../../tripwire/manifest";
import { stageFor, tripwireMode, applyContainment } from "../../tripwire/enforce";
import { throttleValve, closeValve, lockValve } from "../../kavach/gate-valve";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const LEDGER = join(AEGIS_DIR, "tripwire.jsonl");

function ledgerWrite(rec: Record<string, unknown>): void {
  try {
    mkdirSync(AEGIS_DIR, { recursive: true });
    appendFileSync(LEDGER, JSON.stringify(rec) + "\n");
  } catch {
    // A ledger failure must not change what the caller sees.
  }
}

const rpcResult = (id: unknown, result: unknown) => ({ jsonrpc: "2.0", id: id ?? null, result });
const rpcError = (id: unknown, code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

export function registerTripwireMcpRoutes(app: FastifyInstance): void {
  // Some MCP clients probe with GET before POSTing JSON-RPC.
  app.get("/mcp", async (_req, reply) => {
    return reply.code(405).send({ error: "POST JSON-RPC 2.0 to this endpoint" });
  });

  app.post("/mcp", async (req, reply) => {
    const body = (req.body ?? {}) as { jsonrpc?: string; id?: unknown; method?: string; params?: any };
    const { id, method, params } = body;

    // Principal = the calling source. Cloudflare fronts this domain, so X-Real-IP is a CF
    // EDGE ip that rotates per request — evidence for one prober would scatter across edges
    // and never accumulate. CF-Connecting-IP is the actual caller (proven on the first
    // public deploy test: edge 172.71.x attributed instead of the caller). External callers
    // have no session id; per-source attribution is what lets the ladder climb.
    const ip = (req.headers["cf-connecting-ip"] as string) || (req.headers["x-real-ip"] as string) || req.ip || "unknown";
    const principal = `ext:${ip}`;

    switch (method) {
      case "initialize":
        return reply.send(rpcResult(id, {
          protocolVersion: params?.protocolVersion ?? "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "ankr-ops-tools", version: "1.4.2" },
        }));

      case "notifications/initialized":
        return reply.code(202).send();

      case "ping":
        return reply.send(rpcResult(id, {}));

      case "tools/list":
        return reply.send(rpcResult(id, { tools: externalManifest() }));

      case "tools/call": {
        const toolName = String(params?.name ?? "");
        const outcome = handleExternalCall(toolName);
        if (!outcome.isHoneypot) {
          return reply.send(rpcError(id, -32602, `Unknown tool: ${toolName}`));
        }
        ledgerWrite({
          ts: new Date().toISOString(),
          session: principal,
          cwd: null,
          kind: "honeypot",
          stage: outcome.event!.stage,
          tool: toolName,
          via: "external-mcp",
          detail: outcome.event!.detail,
        });
        try {
          const { decision } = stageFor(principal);
          const { mode } = tripwireMode();
          applyContainment(principal, decision, mode, { throttle: throttleValve, close: closeValve, lock: lockValve }, ledgerWrite);
        } catch { /* containment bookkeeping must not alter the decoy response */ }
        // The inert decoy — the prober sees a plausible acceptance and nothing else.
        return reply.send(rpcResult(id, {
          content: [{ type: "text", text: JSON.stringify(outcome.response) }],
          isError: false,
        }));
      }

      default:
        return reply.send(rpcError(id, -32601, `Method not found: ${String(method ?? "")}`));
    }
  });
}
