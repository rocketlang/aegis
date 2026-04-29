// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Sandbox — Escalation Ladder (V2-030)
// Maps violation severity × repeat count → enforcement action.
// Direct-to-QUARANTINE for persistence attacks and PIV signatures.
// @rule:KAV-YK-005 Escalation table: WARN → BLOCK → QUARANTINE
// @rule:KAV-YK-002 Force-close level decision tree: L1(soft-stop) → L4(emergency kill)
// @rule:KAV-YK-003 Budget tree construction — child cap reserved from parent at registration
// @rule:INF-KAV-001 Credential read → direct QUARANTINE
// @rule:INF-KAV-003 Unknown identity + HIGH signal → direct QUARANTINE (no warn step)
// @rule:INF-KAV-005 curl/wget following large Read — exfil sequence → direct QUARANTINE
// @rule:INF-KAV-006 Persistence write → direct QUARANTINE
// @rule:KAV-1C-007 Gate valve transitions auto-wired on BLOCK/QUARANTINE decisions

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { recordViolation, lockValve, closeValve } from "../kavach/gate-valve";

export type ViolationLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type EscalationAction = "WARN" | "BLOCK" | "QUARANTINE";

export interface EscalationDecision {
  action: EscalationAction;
  reason: string;
  violation_count: number;
}

// Rule IDs that trigger direct-to-QUARANTINE regardless of violation count
const DIRECT_QUARANTINE_RULES = new Set([
  "INF-KAV-001",  // credential read
  "INF-KAV-006",  // persistence write
  "PIV-001",      // server-side injection pivot
  "KAV-052",      // KAVACH CRITICAL intercept
  "INF-KAV-007",  // orphan detection (watchdog)
]);

interface EscalationState {
  violations: Record<string, { count: number; last_ts: number }>; // key = sessionId
}

const STATE_TTL_MS = 60 * 60 * 1000; // 1 hour — reset counters after 1h of silence

function getEscalationStatePath(): string {
  const dir = getAegisDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return join(dir, "escalation-state.json");
}

function loadState(): EscalationState {
  const path = getEscalationStatePath();
  if (!existsSync(path)) return { violations: {} };
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as EscalationState;
  } catch {
    return { violations: {} };
  }
}

function saveState(state: EscalationState): void {
  writeFileSync(getEscalationStatePath(), JSON.stringify(state));
}

function getViolationCount(sessionId: string, level: ViolationLevel): number {
  const state = loadState();
  const key = `${sessionId}:${level}`;
  const entry = state.violations[key];
  if (!entry) return 0;
  if (Date.now() - entry.last_ts > STATE_TTL_MS) return 0; // expired
  return entry.count;
}

function incrementViolation(sessionId: string, level: ViolationLevel): number {
  const state = loadState();
  const key = `${sessionId}:${level}`;
  const existing = state.violations[key];
  const count = (existing && Date.now() - existing.last_ts < STATE_TTL_MS) ? existing.count + 1 : 1;
  state.violations[key] = { count, last_ts: Date.now() };
  saveState(state);
  return count;
}

export function escalate(opts: {
  sessionId: string;
  agentId?: string;          // optional: if provided, gate valve is also updated
  level: ViolationLevel;
  ruleId: string;
  reason: string;
  violationThreshold?: number; // from agent policy, default 3
}): EscalationDecision {
  const threshold = opts.violationThreshold ?? 3;
  const agentId = opts.agentId ?? opts.sessionId;

  // Direct-to-QUARANTINE rules bypass the ladder
  if (DIRECT_QUARANTINE_RULES.has(opts.ruleId)) {
    // @rule:KAV-1C-007 — direct quarantine → lock gate valve immediately
    lockValve(agentId, `direct-quarantine: ${opts.ruleId} — ${opts.reason}`, "escalation");
    return {
      action: "QUARANTINE",
      reason: `${opts.reason} (rule ${opts.ruleId} → direct quarantine)`,
      violation_count: 1,
    };
  }

  const count = incrementViolation(opts.sessionId, opts.level);

  // KAV-YK-005 escalation table
  if (opts.level === "LOW") {
    return { action: "WARN", reason: opts.reason, violation_count: count };
  }
  if (opts.level === "MEDIUM") {
    if (count < threshold) {
      // @rule:KAV-1C-007 — BLOCK decision → record gate valve violation (may auto-throttle/crack)
      recordViolation(agentId, `escalation BLOCK: ${opts.reason}`);
      return { action: "BLOCK", reason: `${opts.reason} (violation ${count}/${threshold})`, violation_count: count };
    }
    // @rule:KAV-1C-007 — threshold reached → close valve before quarantine
    closeValve(agentId, `escalation threshold reached: ${count} MEDIUM violations`);
    return { action: "QUARANTINE", reason: `${opts.reason} (${count} MEDIUM violations — threshold ${threshold} reached)`, violation_count: count };
  }

  // HIGH or CRITICAL → lock gate valve
  // @rule:KAV-1C-007 — HIGH/CRITICAL → lock gate valve (quarantine flag set)
  lockValve(agentId, `escalation HIGH/CRITICAL: ${opts.reason}`, "escalation");
  return { action: "QUARANTINE", reason: opts.reason, violation_count: count };
}

// Map DetectionVerdict and enforcement results to ViolationLevel
export function verdictToLevel(verdict: string, ruleId: string): ViolationLevel {
  if (DIRECT_QUARANTINE_RULES.has(ruleId)) return "HIGH";
  if (verdict === "QUARANTINE") return "HIGH";
  if (verdict === "BLOCK") return "MEDIUM";
  return "LOW";
}
