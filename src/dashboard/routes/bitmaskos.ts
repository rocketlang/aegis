// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// BMOS-Authorize — BitMaskOS inter-service authorization endpoint
//
// @rule:BMOS-002 child_mask = parent_mask & requested_mask — AND invariant
// @rule:BMOS-004 masks ARE the policy — no policy doc supersedes the mask at enforcement time
// @rule:BMOS-005 AnkrCodex / services.json is the single authoritative mask source
// @rule:BMOS-006 authorization is O(1) — one AND operation, no policy tree traversal
// @rule:BMI-002  BMOS-Authorize is the single inter-service authorization path
// @rule:BMI-003  mask source is services.json (with 60s version-validated cache)
// @rule:BMI-006  gate valve state is the enforcement oracle for agent queries

import type { FastifyInstance } from "fastify";
import { readFileSync, existsSync, statSync } from "fs";
import { join } from "path";
import { getDb } from "../../core/db";

// ── Bit schema constants (trust_mask bits 0-31, ankr-trust-32bit-v1) ──────────
// Bits 0-7: Universal
const BITS: Record<string, number> = {
  REGISTERED:       1 << 0,
  AUTHENTICATED:    1 << 1,
  READ:             1 << 2,
  WRITE:            1 << 3,
  EXEC_BASH:        1 << 4,
  NETWORK:          1 << 5,
  DB_READ:          1 << 6,
  DB_WRITE:         1 << 7,
  // Bits 8-15: Maritime8x
  MARITIME_READ:    1 << 8,
  MARITIME_WRITE:   1 << 9,
  EBL_CREATE:       1 << 10,
  EBL_VERIFY:       1 << 11,
  VOYAGE_READ:      1 << 12,
  VOYAGE_WRITE:     1 << 13,
  CREW_READ:        1 << 14,
  CREW_WRITE:       1 << 15,
  // Bits 16-23: Logistics
  FREIGHT_READ:     1 << 16,
  FREIGHT_WRITE:    1 << 17,
  CARGO_READ:       1 << 18,
  CARGO_WRITE:      1 << 19,
  CUSTOMS_READ:     1 << 20,
  CUSTOMS_WRITE:    1 << 21,
  COMPLIANCE_READ:  1 << 22,
  COMPLIANCE_WRITE: 1 << 23,
  // Bits 24-31: AGI autonomy
  SPAWN_AGENTS:     1 << 24,
  MEMORY_READ:      1 << 25,
  MEMORY_WRITE:     1 << 26,
  KNOWLEDGE_READ:   1 << 27,
  KNOWLEDGE_WRITE:  1 << 28,
  AUDIT_READ:       1 << 29,
  AUDIT_WRITE:      1 << 30,
  FULL_AUTONOMY:    1 << 31,
};

// ── Services.json mask cache ──────────────────────────────────────────────────
const SERVICES_JSON_PATH = join(process.env.HOME || "/root", ".ankr/config/services.json");
const CACHE_TTL_MS = 60_000;

interface MaskCache {
  masks: Record<string, { trust_mask: number; required_caller_mask: number }>;
  loaded_at: number;
  mtime: number;
}

let _cache: MaskCache | null = null;

// @rule:BMOS-005 services.json is authoritative — cache is validated by mtime every 60s
// @rule:BMI-003  in-memory cache required for 8µs latency target
function loadMasks(): MaskCache["masks"] {
  const now = Date.now();
  if (_cache && now - _cache.loaded_at < CACHE_TTL_MS) return _cache.masks;

  let mtime = 0;
  try { mtime = statSync(SERVICES_JSON_PATH).mtimeMs; } catch {}
  if (_cache && mtime === _cache.mtime && now - _cache.loaded_at < CACHE_TTL_MS * 5) {
    _cache.loaded_at = now;
    return _cache.masks;
  }

  const masks: MaskCache["masks"] = {};
  try {
    const raw = JSON.parse(readFileSync(SERVICES_JSON_PATH, "utf-8"));
    const svcs = raw.services ?? raw;
    for (const [key, val] of Object.entries(svcs as Record<string, Record<string, unknown>>)) {
      masks[key] = {
        trust_mask: typeof val.trust_mask === "number" ? val.trust_mask : 1,
        // @rule:BMI-005 default required_caller_mask=1 (registered bit) if not declared
        required_caller_mask: typeof val.required_caller_mask === "number" ? val.required_caller_mask : 1,
      };
    }
  } catch { /* file unreadable — return empty, caller gets mask=0 */ }

  _cache = { masks, loaded_at: now, mtime };
  return masks;
}

// ── Latency ring (p95 over last 100 calls) ───────────────────────────────────
const LATENCY_RING: number[] = [];
const LATENCY_RING_MAX = 100;

function recordLatency(us: number) {
  LATENCY_RING.push(us);
  if (LATENCY_RING.length > LATENCY_RING_MAX) LATENCY_RING.shift();
}

function p95LatencyUs(): number | null {
  if (LATENCY_RING.length === 0) return null;
  const sorted = [...LATENCY_RING].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length * 0.95)];
}

// ── Gate valve check for agent sessions ──────────────────────────────────────
// @rule:BMI-006 gate valve state = enforcement oracle; CLOSED/LOCKED → authorized=false always
function getEffectiveMaskForAgent(sessionId: string, declaredMask: number): number {
  try {
    const db = getDb();
    const row = db.query(
      "SELECT gate_valve_state FROM sessions WHERE session_id = ?"
    ).get(sessionId) as { gate_valve_state?: string } | null;
    const state = row?.gate_valve_state ?? "OPEN";
    if (state === "CLOSED" || state === "LOCKED") return 0;
    if (state === "CRACKED") return declaredMask & ~(BITS.SPAWN_AGENTS | BITS.EXEC_BASH);
    if (state === "THROTTLED") return declaredMask & ~BITS.SPAWN_AGENTS;
    return declaredMask;
  } catch {
    return declaredMask;
  }
}

// ── Route registration ────────────────────────────────────────────────────────
export function registerBitMaskOSRoutes(app: FastifyInstance): void {
  // Pre-warm cache at startup
  loadMasks();

  // POST /api/v2/authorize
  // @rule:BMOS-006 O(1) authorization — single AND operation, no traversal
  // @rule:BMI-002  this is the single inter-service authorization path
  app.post("/api/v2/authorize", async (req, reply) => {
    const t0 = performance.now();
    const body = req.body as {
      caller?: string;
      target?: string;
      capability?: string;
      // optional: agent session_id for gate valve check
      session_id?: string;
    };

    const caller = body?.caller ?? "";
    const target = body?.target ?? "";
    const capability = (body?.capability ?? "").toUpperCase();

    if (!caller || !target || !capability) {
      return reply.code(400).send({
        error: "caller, target, and capability are required",
        rule: "BMI-002",
      });
    }

    const masks = loadMasks();

    const callerEntry = masks[caller];
    const targetEntry = masks[target];

    // @rule:BMOS-014 unregistered caller has trust_mask=0 — cannot be authorized
    const callerMask = callerEntry?.trust_mask ?? 0;
    const targetRequiredMask = targetEntry?.required_caller_mask ?? 1;
    const capBit = BITS[capability] ?? 0;

    // Apply gate valve if session_id provided (agent query)
    const effectiveCallerMask = body?.session_id
      ? getEffectiveMaskForAgent(body.session_id, callerMask)
      : callerMask;

    // @rule:BMOS-006 authorization = one AND operation
    const resultMask = effectiveCallerMask & targetRequiredMask & (capBit || 0xFFFFFFFF);
    const authorized = capBit !== 0
      ? (resultMask & capBit) !== 0
      : (effectiveCallerMask & targetRequiredMask) !== 0;

    const latencyUs = Math.round((performance.now() - t0) * 1000);
    recordLatency(latencyUs);

    // @rule:BMOS-004 every authorization check is logged (witnessed bit)
    const now = new Date().toISOString();
    try {
      getDb().run(
        `INSERT INTO authorize_log (caller, target, capability, authorized, caller_mask, target_required_mask, result_mask, latency_us, called_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [caller, target, capability, authorized ? 1 : 0, callerMask, targetRequiredMask, resultMask, latencyUs, now]
      );
    } catch { /* log failure must never block the auth response */ }

    return reply.send({
      authorized,
      caller,
      target,
      capability,
      check: `(${caller}.trust_mask & ${target}.required_caller_mask${capBit ? ` & ${capability}_BIT` : ""}) ${authorized ? "!== 0" : "=== 0"}`,
      caller_mask: `0x${callerMask.toString(16).padStart(8, "0")}`,
      target_required_mask: `0x${targetRequiredMask.toString(16).padStart(8, "0")}`,
      result_mask: `0x${resultMask.toString(16).padStart(8, "0")}`,
      latency_us: latencyUs,
      _meta: {
        computed_at: now,
        duration_ms: latencyUs / 1000,
        trust_mask_applied: true,
        protocol: "bitmask-os-v1",
        rule: "BMOS-006",
      },
    });
  });

  // GET /api/v2/authorize/health
  // @rule:CA-004 telemetry minimum — resolvers return _meta with computed_at + duration_ms
  app.get("/api/v2/authorize/health", async (_req, reply) => {
    const masks = loadMasks();
    const p95 = p95LatencyUs();
    const now = new Date().toISOString();
    return reply.send({
      status: "ok",
      mask_cache_size: Object.keys(masks).length,
      last_cache_refresh: _cache ? new Date(_cache.loaded_at).toISOString() : null,
      p95_latency_us: p95,
      p95_target_us: 10_000,
      p95_ok: p95 !== null ? p95 <= 10_000 : null,
      call_count_in_ring: LATENCY_RING.length,
      services_json_path: SERVICES_JSON_PATH,
      services_json_readable: existsSync(SERVICES_JSON_PATH),
      protocol: "bitmask-os-v1",
      layer: 4,
      _meta: {
        computed_at: now,
        duration_ms: 0,
        trust_mask_applied: false,
      },
    });
  });

  // GET /api/v2/authorize/log?limit=50
  // @rule:BMOS-004 audit log is queryable — incident reconstruction in milliseconds
  app.get("/api/v2/authorize/log", async (req, reply) => {
    const limit = Math.min(Number((req.query as Record<string, string>).limit ?? 50), 500);
    try {
      const rows = getDb().query(
        "SELECT * FROM authorize_log ORDER BY id DESC LIMIT ?"
      ).all(limit);
      return reply.send({ log: rows, count: rows.length });
    } catch (e) {
      return reply.code(500).send({ error: String(e) });
    }
  });
}
