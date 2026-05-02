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
import { join } from "path";
import { evaluate, getEnforcementMode, isDryRun, getCanarySet } from "../../enforcement/gate";
import { logDecision, logPath } from "../../enforcement/logger";
import {
  loadRegistry,
  pilotSet,
  registrySize,
  cacheAge,
  invalidateCache,
} from "../../enforcement/registry";
import type { AegisEnforcementRequest } from "../../enforcement/types";
import { runAudit, writeAuditFiles } from "../../enforcement/replay";
import {
  approveToken,
  revokeToken,
  listPending,
  pendingCount,
  getApproval,
} from "../../enforcement/approval";

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

  // ── GET /api/v2/enforcement/audit ─────────────────────────────────────────
  // Read the decision log, detect false positives/negatives, report soft gate eligibility
  // @rule:AEG-E-009 — no soft enforcement until audit returns verdict=PASS
  app.get("/api/v2/enforcement/audit", async (req, reply) => {
    const t0 = performance.now();
    const query = req.query as Record<string, string>;

    const summary = runAudit();

    // Optionally write files if ?write=true
    if (query.write === "true") {
      const outDir = query.out_dir ?? join(process.env.HOME ?? "/root", ".aegis");
      try {
        writeAuditFiles(summary, outDir);
      } catch (e) {
        // non-fatal — still return audit result
      }
    }

    const duration_ms = performance.now() - t0;

    return reply.code(summary.audit_verdict === "PASS" ? 200 : summary.audit_verdict === "CONDITIONAL_PASS" ? 202 : 409).send({
      ...summary,
      _meta: {
        computed_at: summary.generated_at,
        duration_ms: Math.round(duration_ms * 1000) / 1000,
        trust_mask_applied: false,
        protocol: "aegis-audit-v1",
        rule: "AEG-E-009",
        soft_gate_eligible: summary.soft_gate_eligible,
        verdict: summary.audit_verdict,
      },
    });
  });

  // ── POST /api/v2/enforcement/audit/synthetic ───────────────────────────────
  // Generate synthetic traffic for all 12 TIER-A services across 5 scenarios
  // Use this to populate the decision log before running /audit
  app.post("/api/v2/enforcement/audit/synthetic", async (_req, reply) => {
    const t0 = performance.now();
    const scenarios = [
      { operation: "read",    requested_capability: "READ" },
      { operation: "write",   requested_capability: "WRITE" },
      { operation: "execute", requested_capability: "EXECUTE" },
      { operation: "deploy",  requested_capability: "DEPLOY" },
      { operation: "approve", requested_capability: "APPROVE" },
    ];

    const results: unknown[] = [];

    for (const svc of pilotSet()) {
      for (const scen of scenarios) {
        const d = evaluate({ service_id: svc, ...scen, caller_id: "aegis-synthetic-audit" });
        logDecision(d);
        results.push({ service_id: svc, operation: scen.operation, decision: d.decision });
      }
    }

    const duration_ms = performance.now() - t0;

    return reply.send({
      generated: results.length,
      services: pilotSet().length,
      scenarios: scenarios.length,
      results,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Math.round(duration_ms * 1000) / 1000,
        trust_mask_applied: true,
        note: "synthetic traffic logged — run GET /api/v2/enforcement/audit to analyse",
      },
    });
  });

  // ── GET /api/v2/enforcement/canary ────────────────────────────────────────
  // Canary health: which services are in soft enforcement, pending gate count
  app.get("/api/v2/enforcement/canary", async (_req, reply) => {
    const mode = getEnforcementMode();
    const canary = [...getCanarySet()];
    const pending = listPending();
    const registry = loadRegistry();

    const canaryStatus = canary.map(key => {
      const e = registry[key];
      return {
        service_id: key,
        in_registry: !!e,
        trust_mask: e ? `0x${e.trust_mask.toString(16).padStart(8, "0")}` : "not-found",
        authority_class: e?.authority_class ?? "not-found",
        governance_blast_radius: e?.governance_blast_radius ?? "not-found",
        runtime_readiness_tier: e?.runtime_readiness.tier ?? "not-found",
        aegis_gate_overall: e?.aegis_gate.overall ?? "not-found",
      };
    });

    return reply.send({
      enforcement_mode: mode,
      dry_run: isDryRun(),
      rollback_switch: "Set AEGIS_RUNTIME_ENABLED=false to return to shadow mode immediately",
      canary_services: canaryStatus,
      pending_gate_approvals: pending.length,
      enforcement_phase: mode === "shadow" ? "shadow" : "soft_canary",
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: 0,
        trust_mask_applied: false,
        protocol: "aegis-enforcement-v1",
        rule: "AEG-E-007",
      },
    });
  });

  // ── POST /api/v2/enforcement/approve/:token ────────────────────────────────
  // Approve a pending GATE decision. GATE = pause, not deny.
  // @rule:AEG-E-012 — GATE means pause; this endpoint is the continuation path
  // @rule:AEG-E-014 — approval_reason mandatory; blank is rejected
  app.post("/api/v2/enforcement/approve/:token", async (req, reply) => {
    const { token } = req.params as { token: string };
    const body = req.body as { approval_reason?: string; approved_by?: string } | undefined;

    const result = approveToken(
      token,
      body?.approval_reason ?? "",
      body?.approved_by ?? req.headers["x-aegis-approver"] as string ?? "anonymous",
    );

    if (!result.ok) {
      return reply.code(400).send({
        approved: false,
        error: result.error,
        rule: "AEG-E-014",
      });
    }

    // Log the approval as an ALLOW decision with bypass context
    const original = result.record!.original_decision;
    const approvalDecision = {
      ...original,
      decision: "ALLOW" as const,
      reason: `GATE approved: ${result.record!.approval_reason}`,
      bypass_reason: result.record!.approval_reason,
      bypassed_by: result.record!.approved_by,
      bypassed_at: result.record!.approved_at,
      timestamp: new Date().toISOString(),
    };
    logDecision(approvalDecision);

    return reply.send({
      approved: true,
      token,
      service_id: result.record!.service_id,
      operation: result.record!.operation,
      approval_reason: result.record!.approval_reason,
      approved_by: result.record!.approved_by,
      approved_at: result.record!.approved_at,
      original_decision: "GATE",
      resolved_decision: "ALLOW",
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: 0,
        trust_mask_applied: true,
        rule: "AEG-E-012",
      },
    });
  });

  // ── GET /api/v2/enforcement/approve/:token ────────────────────────────────
  // Check status of a gate approval token
  app.get("/api/v2/enforcement/approve/:token", async (req, reply) => {
    const { token } = req.params as { token: string };
    const record = getApproval(token);
    if (!record) return reply.code(404).send({ error: "token not found" });
    return reply.send({ token, status: record.status, service_id: record.service_id, expires_at: record.expires_at });
  });

  // ── DELETE /api/v2/enforcement/approve/:token ─────────────────────────────
  // Revoke a pending approval token (Captain's override)
  app.delete("/api/v2/enforcement/approve/:token", async (req, reply) => {
    const { token } = req.params as { token: string };
    const revoked = revokeToken(token);
    return reply.send({ revoked, token });
  });

  // ── GET /api/v2/enforcement/approve ───────────────────────────────────────
  // List all pending gate approvals
  app.get("/api/v2/enforcement/approve", async (_req, reply) => {
    const pending = listPending();
    return reply.send({
      pending_count: pending.length,
      pending: pending.map(r => ({
        token: r.token,
        service_id: r.service_id,
        operation: r.operation,
        requested_capability: r.requested_capability,
        created_at: r.created_at,
        expires_at: r.expires_at,
      })),
    });
  });
}

