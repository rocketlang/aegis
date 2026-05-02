// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Enforcement Routes — /api/v2/enforcement/*
//
// Pilot scope: TIER-A services only (see src/enforcement/registry.ts)
// Default: AEGIS_RUNTIME_ENABLED=false, AEGIS_DRY_RUN=true → shadow mode
//
// @rule:AEG-E-001 — shadow → soft → hard; never skip
// @rule:AEG-E-005 — all decisions logged; log failure never blocks
// @rule:CA-004    — resolvers return _meta: { computed_at, duration_ms, trust_mask_applied }

import type { FastifyInstance } from "fastify";
import { evaluate, getEnforcementMode, isDryRun } from "../../enforcement/gate";
import { logDecision, logPath } from "../../enforcement/logger";
import {
  loadRegistry,
  pilotSet,
  registrySize,
  cacheAge,
  invalidateCache,
} from "../../enforcement/registry";
import type { AegisEnforcementRequest } from "../../enforcement/types";

export function registerEnforcementRoutes(app: FastifyInstance): void {
  // ── POST /api/v2/enforcement/gate ─────────────────────────────────────────
  // Primary gate endpoint — evaluate a service operation against registry
  app.post("/api/v2/enforcement/gate", async (req, reply) => {
    const t0 = performance.now();
    const body = req.body as Partial<AegisEnforcementRequest>;

    if (!body.service_id || !body.operation || !body.requested_capability) {
      return reply.code(400).send({
        error: "service_id, operation, and requested_capability are required",
        rule: "AEG-E-007",
      });
    }

    const decision = evaluate({
      service_id: body.service_id,
      operation: body.operation,
      requested_capability: body.requested_capability,
      caller_id: body.caller_id,
      session_id: body.session_id,
      metadata: body.metadata,
    });

    // @rule:AEG-E-005 log always, regardless of mode or decision
    logDecision(decision);

    const duration_ms = performance.now() - t0;

    return reply.send({
      ...decision,
      _meta: {
        computed_at: decision.timestamp,
        duration_ms: Math.round(duration_ms * 1000) / 1000,
        trust_mask_applied: decision.trust_mask > 0,
        enforcement_mode: decision.enforcement_mode,
        dry_run: decision.dry_run,
        pilot_scope: decision.pilot_scope,
        protocol: "aegis-enforcement-v1",
        rule: "AEG-E-001",
      },
    });
  });

  // ── POST /api/v2/enforcement/batch-gate ───────────────────────────────────
  // Evaluate multiple operations in one call (max 50)
  app.post("/api/v2/enforcement/batch-gate", async (req, reply) => {
    const t0 = performance.now();
    const body = req.body as { requests?: Partial<AegisEnforcementRequest>[] };

    const reqs = body.requests ?? [];
    if (!Array.isArray(reqs) || reqs.length === 0) {
      return reply.code(400).send({ error: "requests array is required" });
    }
    if (reqs.length > 50) {
      return reply.code(400).send({ error: "max 50 requests per batch" });
    }

    const results = reqs.map(r => {
      if (!r.service_id || !r.operation || !r.requested_capability) {
        return { error: "missing required fields", input: r };
      }
      const d = evaluate(r as AegisEnforcementRequest);
      logDecision(d);
      return d;
    });

    return reply.send({
      results,
      count: results.length,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Math.round((performance.now() - t0) * 1000) / 1000,
        trust_mask_applied: true,
        enforcement_mode: getEnforcementMode(),
        dry_run: isDryRun(),
        protocol: "aegis-enforcement-v1",
      },
    });
  });

  // ── GET /api/v2/enforcement/health ────────────────────────────────────────
  // Reports current mode, pilot set, registry state
  app.get("/api/v2/enforcement/health", async (_req, reply) => {
    const now = new Date().toISOString();
    const mode = getEnforcementMode();
    const dry = isDryRun();
    const registry = loadRegistry();

    const pilotServices = pilotSet();
    const pilotEntries = pilotServices.map(key => {
      const e = registry[key];
      return {
        service_id: key,
        trust_mask: e ? `0x${e.trust_mask.toString(16).padStart(8, "0")}` : "not-found",
        authority_class: e?.authority_class ?? "not-found",
        governance_blast_radius: e?.governance_blast_radius ?? "not-found",
        runtime_readiness_tier: e?.runtime_readiness.tier ?? "not-found",
        aegis_gate_overall: e?.aegis_gate.overall ?? "not-found",
      };
    });

    return reply.send({
      status: "ok",
      enforcement_mode: mode,
      dry_run: dry,
      aegis_runtime_enabled: process.env.AEGIS_RUNTIME_ENABLED !== "false",
      pilot_scope: {
        count: pilotServices.length,
        services: pilotEntries,
      },
      registry: {
        total_services: registrySize(),
        cache_age_ms: cacheAge(),
      },
      log_path: logPath(),
      _meta: {
        computed_at: now,
        duration_ms: 0,
        trust_mask_applied: false,
        protocol: "aegis-enforcement-v1",
        rule: "AEG-E-001",
      },
    });
  });

  // ── POST /api/v2/enforcement/registry/invalidate ──────────────────────────
  // Force registry cache refresh (e.g. after services.json update)
  app.post("/api/v2/enforcement/registry/invalidate", async (_req, reply) => {
    invalidateCache();
    return reply.send({
      invalidated: true,
      message: "Registry cache cleared — next gate call reloads from services.json",
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: 0,
        trust_mask_applied: false,
      },
    });
  });

  // ── GET /api/v2/enforcement/pilot/:service_id ─────────────────────────────
  // Probe a single TIER-A service's enforcement posture
  app.get("/api/v2/enforcement/pilot/:service_id", async (req, reply) => {
    const { service_id } = req.params as { service_id: string };
    const registry = loadRegistry();
    const entry = registry[service_id];

    if (!entry) {
      return reply.code(404).send({ error: `service '${service_id}' not in registry` });
    }

    const inPilot = pilotSet().includes(service_id);
    const mode = getEnforcementMode();

    // Run all 5 scenarios
    const scenarios = [
      { operation: "read", capability: "READ" },
      { operation: "write", capability: "WRITE" },
      { operation: "execute", capability: "EXECUTE" },
      { operation: "deploy", capability: "DEPLOY" },
      { operation: "approve", capability: "APPROVE" },
    ].map(s => {
      const d = evaluate({ service_id, operation: s.operation, requested_capability: s.capability });
      logDecision(d);
      return { operation: s.operation, decision: d.decision, reason: d.reason };
    });

    return reply.send({
      service_id,
      in_pilot_scope: inPilot,
      enforcement_mode: mode,
      dry_run: isDryRun(),
      trust_mask: `0x${entry.trust_mask.toString(16).padStart(8, "0")}`,
      authority_class: entry.authority_class,
      governance_blast_radius: entry.governance_blast_radius,
      runtime_readiness: entry.runtime_readiness,
      aegis_gate: entry.aegis_gate,
      scenario_results: scenarios,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: 0,
        trust_mask_applied: entry.trust_mask > 0,
        protocol: "aegis-enforcement-v1",
      },
    });
  });
}
