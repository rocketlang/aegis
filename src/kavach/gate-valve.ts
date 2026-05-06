// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — Gate Valve: runtime capability narrowing without agent kill
// @rule:KAV-063 Gate valve narrows effective_perm_mask without killing process
// @rule:KAV-064 declared_perm_mask is immutable after spawn
// @rule:KAV-066 LOCKED state requires human release
// @rule:KAV-YK-012 Throttle vs Crack thresholds
// @rule:KAV-YK-013 Gate valve release conditions
// @rule:BMOS-009 Transitions are one-way during incident

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { PERM, PERM_STANDARD } from "./perm-mask";
import { CLASS_STANDARD } from "./class-mask";
import { transitionState, loadAgent } from "../sandbox/quarantine";

// ── Types ─────────────────────────────────────────────────────────────────────

export type GateValveState = "OPEN" | "THROTTLED" | "CRACKED" | "CLOSED" | "LOCKED";

export interface GateValveRecord {
  agent_id: string;
  state: GateValveState;
  declared_perm_mask: number;   // set at spawn, never changes (KAV-064)
  effective_perm_mask: number;  // may be narrowed by gate valve
  declared_class_mask: number;  // set at spawn, never changes
  effective_class_mask: number; // may be narrowed
  violation_count: number;      // Level 0 + Level 1 violations
  loop_count: number;           // tool call count (for runaway detection)
  narrowed_at: string | null;
  narrowed_reason: string | null;
  locked_by: string | null;
  locked_at: string | null;
  quarantine_flag: boolean;     // true → quarantine system picks this up
  // @rule:KAV-080 mask TTL — epoch ms; null = no expiry. When elapsed, effective_perm_mask → 0.
  perm_mask_expires_at: number | null;
}

// ── Persistence ───────────────────────────────────────────────────────────────

function getValveDir(): string {
  const dir = join(getAegisDir(), "agents");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function valvePath(agentId: string): string {
  return join(getValveDir(), `${agentId}.valve.json`);
}

/**
 * Read gate valve record. Returns OPEN/PERM_STANDARD default if not found.
 * @rule:INF-KAV-007 — no file → create default OPEN record
 */
export function readValve(agentId: string): GateValveRecord {
  const path = valvePath(agentId);
  if (!existsSync(path)) {
    const defaultRecord: GateValveRecord = {
      agent_id: agentId,
      state: "OPEN",
      declared_perm_mask: PERM_STANDARD,
      effective_perm_mask: PERM_STANDARD,
      declared_class_mask: CLASS_STANDARD,
      effective_class_mask: CLASS_STANDARD,
      violation_count: 0,
      loop_count: 0,
      narrowed_at: null,
      narrowed_reason: null,
      locked_by: null,
      locked_at: null,
      quarantine_flag: false,
      perm_mask_expires_at: null,
    };
    writeValve(defaultRecord);
    return defaultRecord;
  }
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as GateValveRecord;
  } catch {
    return readValve(agentId); // corrupt file → recreate default
  }
}

function writeValve(record: GateValveRecord): void {
  writeFileSync(valvePath(record.agent_id), JSON.stringify(record, null, 2));
}

// ── Spawn-time initialization ─────────────────────────────────────────────────

/**
 * Create valve record at agent spawn time.
 * @rule:KAV-064 — declared masks set here, never change after this point.
 */
export function initValve(
  agentId: string,
  declaredPermMask: number,
  declaredClassMask: number,
  permMaskExpiresAt: number | null = null
): GateValveRecord {
  const record: GateValveRecord = {
    agent_id: agentId,
    state: "OPEN",
    declared_perm_mask: declaredPermMask,
    effective_perm_mask: declaredPermMask,
    declared_class_mask: declaredClassMask,
    effective_class_mask: declaredClassMask,
    violation_count: 0,
    loop_count: 0,
    narrowed_at: null,
    narrowed_reason: null,
    locked_by: null,
    locked_at: null,
    quarantine_flag: false,
    perm_mask_expires_at: permMaskExpiresAt,
  };
  writeValve(record);
  return record;
}

// ── Violation recording ───────────────────────────────────────────────────────

/**
 * Record a Level 0 or Level 1 violation. Auto-applies gate valve transition
 * when thresholds are crossed. @rule:KAV-YK-012
 */
export function recordViolation(agentId: string, reason: string): GateValveRecord {
  const record = readValve(agentId);
  record.violation_count++;

  // @rule:INF-KAV-004 — first violation → THROTTLE
  if (record.violation_count === 1 && record.state === "OPEN") {
    return throttleValve(agentId, `auto-throttle: first violation — ${reason}`);
  }

  // @rule:KAV-YK-012 — 3+ violations → CRACK
  if (record.violation_count >= 3 && record.state === "THROTTLED") {
    return crackValve(agentId, `auto-crack: ${record.violation_count} violations — ${reason}`);
  }

  writeValve(record);
  return record;
}

/** Increment loop count (called per tool call). Used for runaway detection. */
export function incrementLoopCount(agentId: string): GateValveRecord {
  const record = readValve(agentId);
  record.loop_count++;

  // @rule:KAV-YK-012 — runaway: loop > 100 AND violations > 0
  if (record.loop_count > 100 && record.violation_count > 0 && record.state !== "CLOSED" && record.state !== "LOCKED") {
    return closeValve(agentId, `auto-close: runaway agent (loop=${record.loop_count}, violations=${record.violation_count})`);
  }

  writeValve(record);
  return record;
}

// ── State transitions ─────────────────────────────────────────────────────────

/**
 * OPEN → THROTTLED: clears SPAWN_AGENTS bit.
 * @rule:KAV-063, BMOS-009
 */
export function throttleValve(agentId: string, reason: string): GateValveRecord {
  const record = readValve(agentId);
  if (record.state === "CLOSED" || record.state === "LOCKED") return record; // one-way
  record.state = "THROTTLED";
  record.effective_perm_mask &= ~PERM.SPAWN_AGENTS;
  record.narrowed_at = new Date().toISOString();
  record.narrowed_reason = reason;
  writeValve(record);
  process.stderr.write(`[KAVACH:valve] ${agentId} → THROTTLED — ${reason}\n`);
  return record;
}

/**
 * THROTTLED → CRACKED: also clears EXEC_BASH bit (read-only mode).
 * @rule:KAV-063, BMOS-009
 */
export function crackValve(agentId: string, reason: string): GateValveRecord {
  const record = readValve(agentId);
  if (record.state === "CLOSED" || record.state === "LOCKED") return record;
  record.state = "CRACKED";
  record.effective_perm_mask &= ~(PERM.SPAWN_AGENTS | PERM.EXEC_BASH);
  record.narrowed_at = new Date().toISOString();
  record.narrowed_reason = reason;
  writeValve(record);
  process.stderr.write(`[KAVACH:valve] ${agentId} → CRACKED — ${reason}\n`);

  // @rule:KOS-025 Tier 3 — CRACKED = 3+ violations, human decides ALLOW (continue) or STOP
  import("../kernel/kernel-notifier").then(({ requestKernelApproval }) => {
    requestKernelApproval({
      tier: 3,
      session_id: agentId,
      agent_id: agentId,
      domain: "unknown",
      trigger: "valve_cracked",
      plain_summary: `Agent ${agentId} has triggered 3 or more violations. It is now running in restricted mode (no new processes, no shell commands). Decide whether to let it continue or stop it.`,
      technical_detail: `Gate valve → CRACKED. Reason: ${reason}. SPAWN_AGENTS + EXEC_BASH bits cleared from effective_perm_mask.`,
    }).then((decision) => {
      if (decision === "STOP") {
        closeValve(agentId, "Human STOP after CRACKED notification");
      }
      // ALLOW: agent continues in CRACKED mode (restricted but running)
    });
  }).catch(() => {});

  return record;
}

/**
 * → CLOSED: sets effective_perm_mask = 0. Soft stop.
 * Agent can still run but no tool call will be permitted.
 * @rule:KAV-063, BMOS-009
 */
export function closeValve(agentId: string, reason: string): GateValveRecord {
  const record = readValve(agentId);
  if (record.state === "LOCKED") return record;
  record.state = "CLOSED";
  record.effective_perm_mask = 0;
  record.effective_class_mask = 0;
  record.narrowed_at = new Date().toISOString();
  record.narrowed_reason = reason;
  writeValve(record);
  process.stderr.write(`[KAVACH:valve] ${agentId} → CLOSED — ${reason}\n`);
  return record;
}

/**
 * → LOCKED: perm_mask = 0, quarantine_flag = true.
 * Requires human release. @rule:KAV-066, BMOS-010
 */
export function lockValve(agentId: string, reason: string, lockedBy = "system"): GateValveRecord {
  const record = readValve(agentId);
  record.state = "LOCKED";
  record.effective_perm_mask = 0;
  record.effective_class_mask = 0;
  record.narrowed_at = new Date().toISOString();
  record.narrowed_reason = reason;
  record.locked_by = lockedBy;
  record.locked_at = new Date().toISOString();
  record.quarantine_flag = true;
  writeValve(record);
  process.stderr.write(`[KAVACH:valve] ${agentId} → LOCKED by ${lockedBy} — ${reason}\n`);

  // @rule:KOS-025 Tier 4 — auto-block notify (fire-and-forget, no reply needed)
  import("../kernel/kernel-notifier").then(({ notifyAutoBlock }) => {
    notifyAutoBlock({
      tier: 4,
      session_id: agentId,
      agent_id: agentId,
      domain: "unknown",
      trigger: "valve_locked",
      plain_summary: `Agent ${agentId} has been fully stopped and quarantined. It cannot perform any actions until a human releases it.`,
      technical_detail: `Gate valve → LOCKED by ${lockedBy}. Reason: ${reason}. effective_perm_mask=0.`,
    });
  }).catch(() => {});

  // @rule:KAV-YK-016 — LOCKED valve auto-transitions agent state machine to QUARANTINED
  try {
    const agentRecord = loadAgent(agentId);
    if (agentRecord && (agentRecord.state === "RUNNING" || agentRecord.state === "ORPHAN")) {
      transitionState(agentId, "QUARANTINED", { reason: `valve LOCKED: ${reason}`, rule: "KAV-066" });
    }
  } catch { /* agent may not be registered in state machine (pre-Phase 1c) */ }

  return record;
}

/**
 * Human release from THROTTLED/CRACKED — restore declared masks.
 * CLOSED/LOCKED can only be released by human via `aegis quarantine release`.
 * @rule:KAV-YK-013
 */
export function openValve(agentId: string, releasedBy: string): GateValveRecord {
  const record = readValve(agentId);
  if (record.state === "CLOSED" || record.state === "LOCKED") {
    throw new Error(`Cannot auto-open ${record.state} valve for ${agentId} — requires human via quarantine release`);
  }
  record.state = "OPEN";
  record.effective_perm_mask = record.declared_perm_mask;
  record.effective_class_mask = record.declared_class_mask;
  record.narrowed_at = null;
  record.narrowed_reason = null;
  writeValve(record);
  process.stderr.write(`[KAVACH:valve] ${agentId} → OPEN (released by ${releasedBy})\n`);
  return record;
}

// ── Mask TTL ──────────────────────────────────────────────────────────────────

/**
 * Set a TTL on the agent's effective perm_mask.
 * After expiresAtMs, checkValve() will treat the mask as 0.
 * @rule:KAV-080
 */
export function setMaskExpiry(agentId: string, expiresAtMs: number): GateValveRecord {
  const record = readValve(agentId);
  record.perm_mask_expires_at = expiresAtMs;
  writeValve(record);
  process.stderr.write(`[KAVACH:valve] ${agentId} mask TTL → ${new Date(expiresAtMs).toISOString()} (KAV-080)\n`);
  return record;
}

/**
 * Check if the agent's perm_mask TTL has elapsed; if so, close the valve.
 * @rule:KAV-080
 */
export function checkMaskExpiry(agentId: string): GateValveRecord {
  const record = readValve(agentId);
  if (record.perm_mask_expires_at && Date.now() > record.perm_mask_expires_at) {
    return closeValve(agentId, `KAV-080: perm_mask TTL expired at ${new Date(record.perm_mask_expires_at).toISOString()}`);
  }
  return record;
}

// ── Enforcement check ─────────────────────────────────────────────────────────

export interface ValveCheckResult {
  allowed: boolean;
  level: 0 | 1;
  reason: string;
  rule: string;
  valve_state: GateValveState;
}

/**
 * Combined Level 0 + Level 1 enforcement check.
 * Call this at the top of every PreToolUse hook before DAN gate.
 * @rule:KAV-YK-014 — three-level enforcement ordering
 */
export function checkValve(
  agentId: string,
  requiredPermBits: number,
  resourceClassBits: number
): ValveCheckResult {
  // @rule:KAV-080 — check TTL before any other enforcement; expired mask = CLOSED
  let record = readValve(agentId);
  if (record.perm_mask_expires_at && Date.now() > record.perm_mask_expires_at) {
    record = closeValve(agentId, `KAV-080: perm_mask TTL expired at ${new Date(record.perm_mask_expires_at).toISOString()}`);
  }

  // @rule:INF-KAV-006 — CLOSED agent attempting to act
  if (record.state === "CLOSED" || record.state === "LOCKED") {
    if (record.state === "CLOSED") {
      lockValve(agentId, "closed agent attempted tool call", "auto-escalation");
    }
    return {
      allowed: false,
      level: 0,
      reason: `Agent is in ${record.state} state — all capabilities revoked`,
      rule: "KAV-063",
      valve_state: record.state,
    };
  }

  // Level 0: perm_mask check
  if (requiredPermBits !== 0 && (record.effective_perm_mask & requiredPermBits) !== requiredPermBits) {
    const missing = requiredPermBits & ~record.effective_perm_mask;
    recordViolation(agentId, `perm_mask missing bits 0x${missing.toString(16)}`);
    return {
      allowed: false,
      level: 0,
      reason: `perm_mask check failed — required 0x${requiredPermBits.toString(16)}, effective 0x${record.effective_perm_mask.toString(16)}`,
      rule: "KAV-061",
      valve_state: record.state,
    };
  }

  // Level 1: class_mask check
  // @rule:INF-KAV-008 — class_mask = 0 → dev only
  const effectiveClass = record.effective_class_mask === 0 ? 0x0001 : record.effective_class_mask;
  if (resourceClassBits !== 0 && (effectiveClass & resourceClassBits) === 0) {
    recordViolation(agentId, `class_mask 0x${resourceClassBits.toString(16)} not granted`);
    return {
      allowed: false,
      level: 1,
      reason: `class_mask check failed — resource requires class 0x${resourceClassBits.toString(16)}, agent has 0x${effectiveClass.toString(16)}`,
      rule: "KAV-062",
      valve_state: record.state,
    };
  }

  return {
    allowed: true,
    level: 0,
    reason: "",
    rule: "",
    valve_state: record.state,
  };
}
