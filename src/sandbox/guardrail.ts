// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Sandbox — Guardrail Graduation State Machine
// @rule:KAV-084 Guardrail Graduation — G0 to G4 enforcement ladder
// Agent earns wider permissions through evidence of clean behavior, not time elapsed.
// Any violation degrades one level. Promotion requires consecutive clean runs at current level.

import { PERM } from "../kavach/perm-mask";

export type GuardrailLevel = 0 | 1 | 2 | 3 | 4;

export interface GuardrailRecord {
  agent_id: string;
  level: GuardrailLevel;        // current level (0 = most restricted, 4 = trusted)
  clean_runs: number;           // consecutive clean tool calls at current level
  violations: number;           // total violations (resets on degradation)
  last_promoted_at?: string;
  last_degraded_at?: string;
  rule_ref: "KAV-084";
}

// Consecutive clean runs required to advance from this level to the next
const PROMOTION_THRESHOLDS: Record<GuardrailLevel, number> = {
  0: 20,
  1: 50,
  2: 100,
  3: 200,
  4: Infinity,
};

// ── In-memory store (process-local; survives restarts via caller re-hydration) ──

const guardrailStore = new Map<string, GuardrailRecord>();

export function getGuardrailRecord(agentId: string): GuardrailRecord | undefined {
  return guardrailStore.get(agentId);
}

export function upsertGuardrailRecord(record: GuardrailRecord): void {
  guardrailStore.set(record.agent_id, record);
}

// ── State transitions ────────────────────────────────────────────────────────

/**
 * Record a clean tool call for an agent.
 * Advances level when consecutive clean_runs meets the promotion threshold.
 * @rule:KAV-084
 */
export function recordCleanRun(record: GuardrailRecord): GuardrailRecord {
  const updated: GuardrailRecord = { ...record, clean_runs: record.clean_runs + 1 };
  const threshold = PROMOTION_THRESHOLDS[updated.level];
  if (updated.clean_runs >= threshold && updated.level < 4) {
    updated.level = (updated.level + 1) as GuardrailLevel;
    updated.clean_runs = 0;
    updated.last_promoted_at = new Date().toISOString();
  }
  guardrailStore.set(updated.agent_id, updated);
  return updated;
}

/**
 * Record a violation for an agent.
 * Degrades level by one (floor 0) and resets clean_runs.
 * @rule:KAV-084
 */
export function recordViolation(record: GuardrailRecord): GuardrailRecord {
  const newLevel = Math.max(0, record.level - 1) as GuardrailLevel;
  const updated: GuardrailRecord = {
    ...record,
    level: newLevel,
    clean_runs: 0,
    violations: record.violations + 1,
    last_degraded_at: new Date().toISOString(),
  };
  guardrailStore.set(updated.agent_id, updated);
  return updated;
}

/**
 * Returns the bitmask of ADDITIONAL permissions granted at each guardrail level.
 * These are layered on top of the agent's base perm_mask by the calling enforcement code.
 *
 * G0: nothing extra — perm_mask as-is (no additional trust earned yet)
 * G1: READ without confirm queue
 * G2: READ + WRITE
 * G3: READ + WRITE + EXEC_BASH
 * G4: READ + WRITE + EXEC_BASH + NETWORK + EXTERNAL_API
 *     (still excludes DB_SCHEMA and PRIVILEGED — those require explicit grant)
 * @rule:KAV-084
 */
export function getEffectivePermExpansion(level: GuardrailLevel): number {
  switch (level) {
    case 0:
      return 0;
    case 1:
      return PERM.READ;
    case 2:
      return PERM.READ | PERM.WRITE;
    case 3:
      return PERM.READ | PERM.WRITE | PERM.EXEC_BASH;
    case 4:
      return PERM.READ | PERM.WRITE | PERM.EXEC_BASH | PERM.NETWORK | PERM.EXTERNAL_API;
  }
}
