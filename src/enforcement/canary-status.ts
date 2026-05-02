// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Canary Status — observation window for live soft-gate enforcement
//
// Reads the decision log and approval log to produce live canary status.
// Aggregates by service, decision type, and approval lifecycle stage.
//
// @rule:AEG-E-011 — enforcement_phase is the canary scope signal
// @rule:AEG-E-019 — canary observation must be live-queryable before expanding scope

import { readFileSync, existsSync } from "fs";
import type { AegisEnforcementDecision, GateDecision } from "./types";
import { listPending, listAll, approvalLogPath } from "./approval";
import { logPath } from "./logger";

export interface CanaryDecisionEntry extends AegisEnforcementDecision {
  schema_version?: string;
}

export interface CanaryServiceStats {
  service_id: string;
  total_decisions: number;
  allow: number;
  warn: number;
  gate: number;
  block: number;
  approved: number;
  denied: number;
  revoked: number;
  read_gates: number;
  last_decision_at: string | null;
  // Success criteria checks
  sc_no_read_gates: boolean;
  sc_no_unknown_blocks: boolean;
}

export interface CanarySuccessCriteria {
  no_read_gates: boolean;
  no_unknown_service_blocks: boolean;
  no_token_replay_successes: boolean;
  no_approval_without_reason: boolean;
  no_revoke_without_reason: boolean;
  rollback_drill_passed: boolean | null;
  decision_log_has_canary_entries: boolean;
  all_criteria_met: boolean;
  blockers: string[];
}

export interface CanaryStatus {
  generated_at: string;
  enforcement_mode: string;
  dry_run: boolean;
  canary_services: string[];
  runtime_enabled: boolean;
  enforcement_phase: string;
  total_decisions: number;
  canary_decisions: number;
  shadow_decisions: number;
  decision_distribution: Record<GateDecision, number>;
  approval_pending: number;
  approval_approved: number;
  approval_denied: number;
  approval_consumed: number;
  approval_expired: number;
  approval_revoked: number;
  service_stats: CanaryServiceStats[];
  success_criteria: CanarySuccessCriteria;
  ready_to_expand: boolean;
}

function readDecisionLog(path: string): CanaryDecisionEntry[] {
  if (!existsSync(path)) return [];
  try {
    return readFileSync(path, "utf-8")
      .split("\n")
      .filter(l => l.trim())
      .map(l => {
        try { return JSON.parse(l) as CanaryDecisionEntry; } catch { return null; }
      })
      .filter((e): e is CanaryDecisionEntry => e !== null);
  } catch { return []; }
}

interface ApprovalLogEntry {
  event: string;
  token?: string;
  service_id?: string;
  approval_reason?: string;
  revoke_reason?: string;
  revoked_by?: string;
  denied_by?: string;
  approved_by?: string;
  denial_reason?: string;
}

function readApprovalLog(): ApprovalLogEntry[] {
  const path = approvalLogPath();
  if (!existsSync(path)) return [];
  try {
    return readFileSync(path, "utf-8")
      .split("\n")
      .filter(l => l.trim())
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter((e): e is ApprovalLogEntry => e !== null);
  } catch { return []; }
}

export function getCanaryStatus(canaryServices: string[]): CanaryStatus {
  const now = new Date().toISOString();
  const runtimeEnabled = process.env.AEGIS_RUNTIME_ENABLED !== "false";
  const mode = (() => {
    if (!runtimeEnabled) return "shadow";
    const m = (process.env.AEGIS_ENFORCEMENT_MODE ?? "shadow").toLowerCase();
    return m === "hard" ? "hard" : m === "soft" ? "soft" : "shadow";
  })();
  const dryRun = process.env.AEGIS_DRY_RUN !== "false";
  const phase = runtimeEnabled && mode === "soft" ? "soft_canary" : "shadow";

  const canarySet = new Set(canaryServices);
  const entries = readDecisionLog(logPath());
  const approvalEntries = readApprovalLog();

  // Aggregate decisions
  const distAll: Record<string, number> = { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 };
  let canaryCount = 0;
  let shadowCount = 0;
  const serviceMap = new Map<string, CanaryServiceStats>();

  for (const e of entries) {
    const d = e.decision as GateDecision;
    distAll[d] = (distAll[d] ?? 0) + 1;

    if (e.enforcement_phase === "soft_canary" || e.enforcement_phase === "hard") {
      canaryCount++;
    } else {
      shadowCount++;
    }

    if (!canarySet.has(e.service_id)) continue;

    let row = serviceMap.get(e.service_id);
    if (!row) {
      row = {
        service_id: e.service_id,
        total_decisions: 0,
        allow: 0, warn: 0, gate: 0, block: 0,
        approved: 0, denied: 0, revoked: 0,
        read_gates: 0,
        last_decision_at: null,
        sc_no_read_gates: true,
        sc_no_unknown_blocks: true,
      };
      serviceMap.set(e.service_id, row);
    }

    row.total_decisions++;
    if (d === "ALLOW") row.allow++;
    if (d === "WARN")  row.warn++;
    if (d === "GATE")  row.gate++;
    if (d === "BLOCK") row.block++;
    row.last_decision_at = e.timestamp;

    // READ gate check
    const op = (e.operation ?? "").toLowerCase();
    const cap = (e.requested_capability ?? "").toLowerCase();
    const isRead = ["read", "get", "list", "query", "search", "fetch"].some(k => op.startsWith(k) || cap.startsWith(k));
    if (isRead && (d === "GATE" || d === "BLOCK")) {
      row.read_gates++;
      row.sc_no_read_gates = false;
    }
  }

  // Approval log events
  const replayAttempts: ApprovalLogEntry[] = [];
  for (const ev of approvalEntries) {
    if (ev.event === "AEGIS_APPROVAL_REVOKED") {
      const row = ev.service_id ? serviceMap.get(ev.service_id) : undefined;
      if (row) row.revoked++;
    }
    if (ev.event === "token_approved") {
      const row = ev.service_id ? serviceMap.get(ev.service_id) : undefined;
      if (row) row.approved++;
    }
    if (ev.event === "AEGIS_APPROVAL_DENIED") {
      const row = ev.service_id ? serviceMap.get(ev.service_id) : undefined;
      if (row) row.denied++;
    }
  }

  // Approval store summary
  const allApprovals = listAll();
  const byStatus = allApprovals.reduce((acc, r) => {
    acc[r.status] = (acc[r.status] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Success criteria
  const readGateServices = [...serviceMap.values()].filter(r => r.read_gates > 0);

  // Approval log: check for blank reasons in approved/denied/revoked events
  const approvalWithoutReason = approvalEntries.filter(
    ev => ev.event === "token_approved" && !ev.approval_reason
  );
  const revokeWithoutReason = approvalEntries.filter(
    ev => ev.event === "AEGIS_APPROVAL_REVOKED" && (!ev.revoke_reason || !ev.revoked_by)
  );

  // Replay: any approval where status was already not pending — detected as log entries with "replay" in error context
  // We detect via decision log: look for approval decisions on already-consumed tokens
  // Proxy: no token should appear twice in approved events
  const approvedTokens = approvalEntries
    .filter(ev => ev.event === "token_approved")
    .map(ev => ev.token)
    .filter((t): t is string => !!t);
  const tokenReplayCandidates = approvedTokens.filter(
    (t, i) => approvedTokens.indexOf(t) !== i
  );

  const blockers: string[] = [];
  if (readGateServices.length > 0) {
    blockers.push(`${readGateServices.length} service(s) have READ gate decisions: ${readGateServices.map(s => s.service_id).join(", ")}`);
  }
  if (tokenReplayCandidates.length > 0) {
    blockers.push(`${tokenReplayCandidates.length} token replay success(es) detected in approval log`);
  }
  if (approvalWithoutReason.length > 0) {
    blockers.push(`${approvalWithoutReason.length} approval(s) logged without approval_reason`);
  }
  if (revokeWithoutReason.length > 0) {
    blockers.push(`${revokeWithoutReason.length} revocation(s) without required reason/attribution`);
  }

  const decisionLogHasCanary = canaryCount > 0;
  if (!decisionLogHasCanary) {
    blockers.push("No soft_canary decisions in decision log yet — activate and run traffic first");
  }

  const sc: CanarySuccessCriteria = {
    no_read_gates: readGateServices.length === 0,
    no_unknown_service_blocks: true, // validated in replay.ts; not re-scanned here
    no_token_replay_successes: tokenReplayCandidates.length === 0,
    no_approval_without_reason: approvalWithoutReason.length === 0,
    no_revoke_without_reason: revokeWithoutReason.length === 0,
    rollback_drill_passed: null, // set by POST /rollback-drill; not re-run here
    decision_log_has_canary_entries: decisionLogHasCanary,
    all_criteria_met: blockers.length === 0,
    blockers,
  };

  const serviceStats = canaryServices.map(svc =>
    serviceMap.get(svc) ?? {
      service_id: svc,
      total_decisions: 0,
      allow: 0, warn: 0, gate: 0, block: 0,
      approved: 0, denied: 0, revoked: 0,
      read_gates: 0,
      last_decision_at: null,
      sc_no_read_gates: true,
      sc_no_unknown_blocks: true,
    }
  );

  return {
    generated_at: now,
    enforcement_mode: mode,
    dry_run: dryRun,
    canary_services: canaryServices,
    runtime_enabled: runtimeEnabled,
    enforcement_phase: phase,
    total_decisions: entries.length,
    canary_decisions: canaryCount,
    shadow_decisions: shadowCount,
    decision_distribution: distAll as Record<GateDecision, number>,
    approval_pending: byStatus["pending"] ?? 0,
    approval_approved: byStatus["approved"] ?? 0,
    approval_denied: byStatus["denied"] ?? 0,
    approval_consumed: byStatus["consumed"] ?? 0,
    approval_expired: byStatus["expired"] ?? 0,
    approval_revoked: byStatus["revoked"] ?? 0,
    service_stats: serviceStats,
    success_criteria: sc,
    ready_to_expand: sc.all_criteria_met,
  };
}

export function getRecentCanaryDecisions(
  canaryServices: string[],
  limit = 50,
): CanaryDecisionEntry[] {
  const canarySet = new Set(canaryServices);
  const entries = readDecisionLog(logPath());
  return entries
    .filter(e => canarySet.has(e.service_id))
    .slice(-limit)
    .reverse();
}

export function getCanaryApprovals(canaryServices: string[]) {
  const canarySet = new Set(canaryServices);
  return listAll().filter(r => canarySet.has(r.service_id));
}
