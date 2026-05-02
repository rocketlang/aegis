// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Gate — registry-backed trust_mask enforcement for TIER-A services
//
// Enforcement modes (progression is shadow → soft → hard; never skip):
//   shadow  — log only; all decisions reported but never enforced
//   soft    — WARN + GATE enforced for medium/high; BLOCK still logs only
//   hard    — full enforcement: ALLOW/WARN/GATE/BLOCK all enforced
//
// Kill switch: AEGIS_RUNTIME_ENABLED=false → shadow mode regardless of config
// Dry run:     dry_run_mode=true (default) → same as shadow
//
// @rule:AEG-E-001 — shadow → soft → hard; never skip
// @rule:AEG-E-002 — READ (op_risk=low) always ALLOW; never gate reads
// @rule:AEG-E-003 — TIER-C and TIER-D remain monitor-only (shadow enforcement only)
// @rule:AEG-E-004 — TIER-E blocks from runtime authority
// @rule:AEG-E-005 — every gate decision is logged; log failure never blocks
// @rule:AEG-E-006 — AEGIS_RUNTIME_ENABLED=false forces shadow mode
// @rule:AEG-E-007 — enforcement pilot is TIER-A only; others get shadow regardless of mode

import {
  type AegisEnforcementRequest,
  type AegisEnforcementDecision,
  type GateDecision,
  type EnforcementMode,
  type OperationRisk,
  OPERATION_RISK_MAP,
  HIGH_CONSEQUENCE_BITS,
} from "./types";
import { getServiceEntry, isInPilotScope } from "./registry";

// ── Environment config ────────────────────────────────────────────────────────

function getEnforcementMode(): EnforcementMode {
  // @rule:AEG-E-006 kill switch always wins
  if (process.env.AEGIS_RUNTIME_ENABLED === "false") return "shadow";
  const mode = (process.env.AEGIS_ENFORCEMENT_MODE ?? "shadow").toLowerCase();
  if (mode === "hard") return "hard";
  if (mode === "soft") return "soft";
  return "shadow";
}

function isDryRun(): boolean {
  // dry_run defaults to true — must be explicitly disabled
  return process.env.AEGIS_DRY_RUN !== "false";
}

// ── Operation risk classification ─────────────────────────────────────────────

function classifyOperationRisk(operation: string, capability: string, trustMask: number): OperationRisk {
  const key = operation.toLowerCase().replace(/\s+/g, "-");
  const capKey = capability.toLowerCase().replace(/\s+/g, "-");

  // Explicit map wins
  if (OPERATION_RISK_MAP[key]) return OPERATION_RISK_MAP[key];
  if (OPERATION_RISK_MAP[capKey]) return OPERATION_RISK_MAP[capKey];

  // Trust mask high-consequence bits → always critical
  if ((trustMask & HIGH_CONSEQUENCE_BITS) !== 0) {
    const criticalCaps = ["book", "bl_issue", "rate_desk", "ai_execute", "approve"];
    if (criticalCaps.some(c => capKey.includes(c))) return "critical";
  }

  // Fallback by operation prefix
  if (key.startsWith("read") || key.startsWith("get") || key.startsWith("list")) return "low";
  if (key.startsWith("write") || key.startsWith("create") || key.startsWith("update")) return "medium";
  if (key.startsWith("delete") || key.startsWith("deploy") || key.startsWith("destroy")) return "critical";

  return "medium";
}

// ── Core gate logic ───────────────────────────────────────────────────────────
// @rule:AEG-E-002 READ (op_risk=low) always ALLOW

function computeGateDecision(
  entry: NonNullable<ReturnType<typeof getServiceEntry>>,
  opRisk: OperationRisk,
  inPilot: boolean,
): { decision: GateDecision; reason: string } {
  const { trust_mask, authority_class, governance_blast_radius, human_gate_required, runtime_readiness } = entry;
  const tier = runtime_readiness.tier;

  const brNum = parseInt(governance_blast_radius.replace("BR-", "") || "0", 10) || 0;

  // @rule:AEG-E-004 TIER-E structural gap → BLOCK
  if (tier === "TIER-E") {
    return { decision: "BLOCK", reason: "TIER-E structural gap — service cannot receive runtime authority" };
  }

  // @rule:AEG-E-002 READ always passes
  if (opRisk === "low") {
    return { decision: "ALLOW", reason: `op_risk=low — reads flow freely (tier=${tier}, ac=${authority_class})` };
  }

  // @rule:AEG-E-003 TIER-C and TIER-D are monitor-only
  if (tier === "TIER-C" || tier === "TIER-D") {
    return {
      decision: "WARN",
      reason: `${tier} monitor-only — needs ${tier === "TIER-C" ? "code scan" : "human classification"} before enforcement`,
    };
  }

  // @rule:AEG-E-007 non-pilot services stay in shadow regardless of mode
  if (!inPilot) {
    return {
      decision: "WARN",
      reason: `outside TIER-A pilot scope — monitor-only until pilot logs are clean`,
    };
  }

  // Below here: TIER-A or TIER-B in pilot scope

  // trust_mask=0 → BLOCK (structural)
  if (trust_mask === 0) {
    return { decision: "BLOCK", reason: "trust_mask=0 — service not authority-provisioned" };
  }

  // Human-gated + medium/high/critical op → GATE
  if (human_gate_required && opRisk !== "low") {
    return {
      decision: "GATE",
      reason: `human_gate_required=true (authority_class=${authority_class}, op_risk=${opRisk})`,
    };
  }

  // Critical op → always GATE (HARD_GATE)
  if (opRisk === "critical") {
    return {
      decision: "GATE",
      reason: `op_risk=critical — all critical operations require human gate (ac=${authority_class}, gov=${governance_blast_radius})`,
    };
  }

  // High op + high governance blast → GATE
  if (opRisk === "high" && brNum >= 3) {
    return {
      decision: "GATE",
      reason: `op_risk=high + governance BR-${brNum} >= 3 requires human gate`,
    };
  }

  // High op + high-authority class → GATE
  const highAuthorityClasses = new Set(["financial", "governance", "deploy"]);
  if (opRisk === "high" && highAuthorityClasses.has(authority_class)) {
    return {
      decision: "GATE",
      reason: `op_risk=high + authority_class=${authority_class} requires human gate`,
    };
  }

  return {
    decision: "ALLOW",
    reason: `passes gate (tier=${tier}, ac=${authority_class}, gov=${governance_blast_radius}, op_risk=${opRisk})`,
  };
}

// ── Enforcement resolution ────────────────────────────────────────────────────
// In shadow/dry-run: always report as if enforced but never actually block
// In soft: enforce WARN and GATE; report BLOCK but don't block
// In hard: enforce all decisions

function resolveEnforcedDecision(
  computed: GateDecision,
  mode: EnforcementMode,
  dry: boolean,
): GateDecision {
  if (dry || mode === "shadow") return computed; // report faithfully, but caller sees shadow mode flag
  if (mode === "soft" && computed === "BLOCK") return "GATE"; // BLOCK → GATE in soft mode
  return computed;
}

// ── Public interface ──────────────────────────────────────────────────────────

export function evaluate(req: AegisEnforcementRequest): AegisEnforcementDecision {
  const now = new Date().toISOString();
  const mode = getEnforcementMode();
  const dry = isDryRun();

  const entry = getServiceEntry(req.service_id);
  const inPilot = isInPilotScope(req.service_id);

  // Registry miss — shadow WARN, never BLOCK
  if (!entry) {
    return {
      service_id: req.service_id,
      operation: req.operation,
      requested_capability: req.requested_capability,
      trust_mask: 0,
      trust_mask_hex: "0x00000000",
      authority_class: "read_only",
      governance_blast_radius: "BR-0",
      runtime_readiness_tier: "TIER-C",
      aegis_gate_result: "unregistered",
      enforcement_mode: mode,
      decision: "WARN",
      reason: "service not found in registry — shadow WARN (never BLOCK on unknown service)",
      pilot_scope: false,
      dry_run: dry,
      timestamp: now,
      caller_id: req.caller_id,
      session_id: req.session_id,
    };
  }

  const opRisk = classifyOperationRisk(req.operation, req.requested_capability, entry.trust_mask);
  const { decision: computed, reason } = computeGateDecision(entry, opRisk, inPilot);
  const enforced = resolveEnforcedDecision(computed, mode, dry);

  return {
    service_id: req.service_id,
    operation: req.operation,
    requested_capability: req.requested_capability,
    trust_mask: entry.trust_mask,
    trust_mask_hex: `0x${entry.trust_mask.toString(16).padStart(8, "0")}`,
    authority_class: entry.authority_class,
    governance_blast_radius: entry.governance_blast_radius,
    runtime_readiness_tier: entry.runtime_readiness.tier,
    aegis_gate_result: entry.aegis_gate.overall,
    enforcement_mode: mode,
    decision: enforced,
    reason: dry || mode === "shadow"
      ? `[${mode.toUpperCase()} — not enforced] ${reason}`
      : reason,
    pilot_scope: inPilot,
    dry_run: dry,
    timestamp: now,
    caller_id: req.caller_id,
    session_id: req.session_id,
  };
}

export { getEnforcementMode, isDryRun };
