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
// @rule:AEG-E-011 — enforcement_phase recorded on every decision
// @rule:AEG-E-012 — GATE means pause, not deny; approval_token issued on GATE in soft/hard canary

import {
  type AegisEnforcementRequest,
  type AegisEnforcementDecision,
  type GateDecision,
  type EnforcementMode,
  type EnforcementPhase,
  type OperationRisk,
  OPERATION_RISK_MAP,
  HIGH_CONSEQUENCE_BITS,
  normalizeCapability,
} from "./types";
import { getServiceEntry, isInPilotScope } from "./registry";
import { issueApprovalToken } from "./approval";
import { applyHardGate, HARD_GATE_GLOBALLY_ENABLED } from "./hard-gate-policy";
import { level0Gate } from "./level0-gate";

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

// @rule:AEG-E-007 canary set is scoped to explicit service list; non-canary stays shadow
function getCanarySet(): Set<string> {
  const env = process.env.AEGIS_SOFT_CANARY_SERVICES ?? "";
  if (!env.trim()) return new Set([ // Batch 26: full TIER-A (12 services)
    "granthx", "stackpilot", "ankrclaw",
    "carbonx", "parali-central", "pramana",
    "ankr-doctor", "domain-capture", "ship-slm",
    "chief-slm", "chirpee", "puranic-os",
  ]);
  return new Set(env.split(",").map(s => s.trim()).filter(Boolean));
}

function isInCanary(serviceId: string): boolean {
  const mode = getEnforcementMode();
  if (mode === "shadow") return false;
  return getCanarySet().has(serviceId);
}

// @rule:AEG-E-011 — phase derived from mode + canary membership
function resolvePhase(mode: EnforcementMode, inCanary: boolean): EnforcementPhase {
  if (mode === "shadow") return "shadow";
  if (mode === "soft" && inCanary) return "soft_canary";
  if (mode === "soft") return "shadow"; // soft mode but not in canary → still shadow
  if (mode === "hard" && inCanary) return "hard";
  return "shadow";
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
// shadow:      report faithfully, never enforce — caller sees shadow flag
// soft canary: WARN enforced; GATE enforced (approval_token issued); BLOCK → GATE (log only)
// hard canary: full enforcement

function resolveEnforcedDecision(
  computed: GateDecision,
  phase: EnforcementPhase,
): GateDecision {
  if (phase === "shadow") return computed;
  if (phase === "soft_canary" && computed === "BLOCK") return "GATE"; // BLOCK → GATE; never hard-block in soft
  return computed;
}

// ── Public interface ──────────────────────────────────────────────────────────

export function evaluate(req: AegisEnforcementRequest): AegisEnforcementDecision {
  const now = new Date().toISOString();
  const mode = getEnforcementMode();
  const dry = isDryRun();
  const inCanary = isInCanary(req.service_id);
  const phase = resolvePhase(mode, inCanary);

  const entry = getServiceEntry(req.service_id);
  const inPilot = isInPilotScope(req.service_id);
  // @rule:AEG-E-008 — normalize capability before classification
  req = { ...req, requested_capability: normalizeCapability(req.requested_capability) };

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
      enforcement_phase: "shadow",
      decision: "WARN",
      reason: "service not found in registry — shadow WARN (never BLOCK on unknown service)",
      pilot_scope: false,
      in_canary: false,
      dry_run: dry,
      timestamp: now,
      caller_id: req.caller_id,
      session_id: req.session_id,
    };
  }

  // @rule:KAV-083 DAN Gate Level 0 — bitmask structural pre-filter before trust_mask gate
  // If agent_perm_mask and required_bit are provided in metadata, run Level 0 first.
  // A zero AND is structural proof — no human escalation path needed.
  const agentPermMask = typeof req.metadata?.agent_perm_mask === "number" ? req.metadata.agent_perm_mask : -1;
  const requiredBit = typeof req.metadata?.required_bit === "number" ? req.metadata.required_bit : 0;
  if (agentPermMask !== -1 && requiredBit !== 0) {
    const l0 = level0Gate(agentPermMask, requiredBit);
    if (l0.blocked) {
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
        enforcement_phase: phase,
        decision: "BLOCK" as GateDecision,
        reason: `[KAV-083 Level 0] ${l0.reason}`,
        pilot_scope: inPilot,
        in_canary: inCanary,
        dry_run: dry || phase === "shadow",
        timestamp: now,
        caller_id: req.caller_id,
        session_id: req.session_id,
      };
    }
  }

  const opRisk = classifyOperationRisk(req.operation, req.requested_capability, entry.trust_mask);
  const { decision: computed, reason } = computeGateDecision(entry, opRisk, inPilot);
  const enforced = resolveEnforcedDecision(computed, phase);

  // @rule:AEG-HG-003 — hard-gate overlay: applied after soft decision, per-service capability BLOCK
  // Kill switch (phase=shadow) always wins over hard-gate — AEG-E-006 takes precedence.
  // @rule:AEG-E-006 — AEGIS_RUNTIME_ENABLED=false forces shadow; hard-gate must not override that
  const hg = (HARD_GATE_GLOBALLY_ENABLED && phase !== "shadow")
    ? applyHardGate(req.service_id, enforced, req.requested_capability, req.operation)
    : null;

  const finalDecision = (hg?.hard_gate_applied ? hg.decision : enforced) as GateDecision;
  const finalPhase: EnforcementPhase = hg?.hard_gate_active ? "hard_gate" : phase;
  const finalReason = hg?.hard_gate_applied ? hg.reason : reason;

  const isShadow = finalPhase === "shadow" || dry;
  const reasonText = isShadow
    ? `[${finalPhase.toUpperCase()} — not enforced] ${finalReason}`
    : finalReason;

  const base: AegisEnforcementDecision = {
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
    enforcement_phase: finalPhase,
    decision: finalDecision,
    reason: reasonText,
    pilot_scope: inPilot,
    in_canary: inCanary,
    dry_run: dry || isShadow,
    timestamp: now,
    caller_id: req.caller_id,
    session_id: req.session_id,
    ...(hg?.hard_gate_active && {
      hard_gate_active: hg.hard_gate_active,
      hard_gate_applied: hg.hard_gate_applied,
      hard_gate_service: hg.hard_gate_service,
      hard_gate_policy_version: hg.policy_version,
    }),
  };

  // @rule:AEG-E-012 — GATE in active enforcement → issue approval_token
  // GATE = pause, not deny. Caller receives token + endpoint to continue.
  if (finalDecision === "GATE" && !isShadow && inCanary) {
    const approval = issueApprovalToken(base);
    base.approval_required = true;
    base.approval_token = approval.token;
    base.approval_endpoint = `/api/v2/enforcement/approve/${approval.token}`;
  }

  return base;
}

export { getEnforcementMode, isDryRun, getCanarySet };
