// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KAV-090 Swarm ceiling invariant — no member exceeds swarm_mask
// @rule:KAV-091 Coordinator grant — swarm_mask ⊆ coordinator.perm_mask at creation
// @rule:KAV-092 Triple AND at spawn — effective = child & parent & swarm_mask
// @rule:KAV-093 Cross-swarm interaction requires DAN Gate

import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "fs";
import { join } from "path";
import { randomBytes } from "crypto";
import { getAegisDir } from "../core/config";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SwarmRecord {
  swarm_id: string;           // UUID
  coordinator_id: string;     // agent who created the swarm — permanent owner
  swarm_mask: number;         // ceiling: (member.perm_mask & ~swarm_mask) == 0 for all members
  member_ids: string[];       // enrolled agent IDs (includes coordinator)
  created_at: string;
  expires_at: number | null;  // epoch ms; null = no TTL. Expiry blocks new enrollments; existing members retain agent TTL.
  rule_ref: "KAV-090";
}

export interface SwarmCreateResult {
  swarm: SwarmRecord;
  invariant_satisfied: boolean;
  coordinator_mask: number;
  rule_ref: "KAV-091";
}

export interface SwarmEnrollResult {
  enrolled: boolean;
  swarm_id: string;
  agent_id: string;
  effective_perm_mask: number;  // agent_requested & swarm_mask
  invariant_satisfied: boolean;
  rule_ref: "KAV-090";
}

// ── Persistence ───────────────────────────────────────────────────────────────

function swarmsDir(): string {
  const dir = join(getAegisDir(), "swarms");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function swarmPath(swarmId: string): string {
  return join(swarmsDir(), `${swarmId}.swarm.json`);
}

export function getSwarm(swarmId: string): SwarmRecord | null {
  const p = swarmPath(swarmId);
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf-8")) as SwarmRecord; } catch { return null; }
}

function saveSwarm(record: SwarmRecord): void {
  writeFileSync(swarmPath(record.swarm_id), JSON.stringify(record, null, 2));
}

// Find the swarm an agent belongs to (O(n) scan — acceptable for typical swarm count < 20)
export function getAgentSwarm(agentId: string): SwarmRecord | null {
  const dir = swarmsDir();
  try {
    const files = readdirSync(dir).filter((f) => f.endsWith(".swarm.json"));
    for (const file of files) {
      try {
        const record = JSON.parse(readFileSync(join(dir, file), "utf-8")) as SwarmRecord;
        if (record.member_ids.includes(agentId)) return record;
      } catch {}
    }
  } catch {}
  return null;
}

// ── Creation ──────────────────────────────────────────────────────────────────

// @rule:KAV-091 — coordinator cannot grant a swarm_mask exceeding its own perm_mask
export function createSwarm(
  coordinatorId: string,
  swarmMask: number,
  coordinatorPermMask: number,
  expiresAt: number | null = null
): SwarmCreateResult {
  const invariantSatisfied = (swarmMask & ~coordinatorPermMask) === 0;
  if (!invariantSatisfied) {
    throw new Error(
      `KAV-091: swarm invariant violated — swarm_mask 0x${swarmMask.toString(16)} exceeds coordinator 0x${coordinatorPermMask.toString(16)}`
    );
  }

  const swarmId = randomBytes(8).toString("hex");
  const record: SwarmRecord = {
    swarm_id: swarmId,
    coordinator_id: coordinatorId,
    swarm_mask: swarmMask,
    member_ids: [coordinatorId],  // coordinator is always a member
    created_at: new Date().toISOString(),
    expires_at: expiresAt,
    rule_ref: "KAV-090",
  };
  saveSwarm(record);
  process.stderr.write(`[KAVACH:swarm] created ${swarmId} coordinator=${coordinatorId} mask=0x${swarmMask.toString(16)} (KAV-091)\n`);

  return {
    swarm: record,
    invariant_satisfied: true,
    coordinator_mask: coordinatorPermMask,
    rule_ref: "KAV-091",
  };
}

// ── Enrollment ────────────────────────────────────────────────────────────────

// @rule:KAV-090 enroll an agent into a swarm; effective mask = agent_requested & swarm_mask
export function enrollAgent(
  swarmId: string,
  agentId: string,
  agentRequestedMask: number
): SwarmEnrollResult {
  const record = getSwarm(swarmId);
  if (!record) throw new Error(`KAV-090: swarm ${swarmId} not found`);

  // Check expiry — expired swarm blocks new enrollments
  if (record.expires_at && Date.now() > record.expires_at) {
    throw new Error(`KAV-090: swarm ${swarmId} is expired — no new enrollments`);
  }

  // Compute effective mask: agent cannot exceed swarm ceiling
  const effectiveMask = agentRequestedMask & record.swarm_mask;
  const invariantSatisfied = (effectiveMask & ~record.swarm_mask) === 0;

  // Add agent to member list (idempotent)
  if (!record.member_ids.includes(agentId)) {
    record.member_ids.push(agentId);
    saveSwarm(record);
  }

  process.stderr.write(
    `[KAVACH:swarm] enrolled ${agentId} into ${swarmId} effective_mask=0x${effectiveMask.toString(16)} (KAV-090)\n`
  );

  return {
    enrolled: true,
    swarm_id: swarmId,
    agent_id: agentId,
    effective_perm_mask: effectiveMask,
    invariant_satisfied,
    rule_ref: "KAV-090",
  };
}

// ── Invariant assertion ───────────────────────────────────────────────────────

export interface SwarmInvariantResult {
  swarm_id: string;
  valid: boolean;
  member_count: number;
  violations: Array<{ agent_id: string; perm_mask: number; swarm_mask: number }>;
  checked_at: string;
  rule_ref: "KAV-090";
}

// Re-check all swarm members still satisfy the ceiling invariant.
// Called by watchdog each poll. Requires gate-valve to read current perm_masks.
export function assertSwarmInvariant(
  swarmId: string,
  getAgentMask: (agentId: string) => number  // dependency-injected: readValve(id).effective_perm_mask
): SwarmInvariantResult {
  const record = getSwarm(swarmId);
  const checked_at = new Date().toISOString();
  if (!record) return { swarm_id: swarmId, valid: false, member_count: 0, violations: [], checked_at, rule_ref: "KAV-090" };

  const violations: Array<{ agent_id: string; perm_mask: number; swarm_mask: number }> = [];

  for (const memberId of record.member_ids) {
    try {
      const currentMask = getAgentMask(memberId);
      if ((currentMask & ~record.swarm_mask) !== 0) {
        violations.push({ agent_id: memberId, perm_mask: currentMask, swarm_mask: record.swarm_mask });
      }
    } catch { /* agent may no longer be active */ }
  }

  return {
    swarm_id: swarmId,
    valid: violations.length === 0,
    member_count: record.member_ids.length,
    violations,
    checked_at,
    rule_ref: "KAV-090",
  };
}

// ── Cross-swarm detection ─────────────────────────────────────────────────────

export interface CrossSwarmResult {
  same_swarm: boolean;
  caller_swarm_id: string | null;
  target_swarm_id: string | null;
  requires_dan_gate: boolean;
  rule_ref: "KAV-093";
}

// @rule:KAV-093 — check if caller and target are in the same swarm
export function checkCrossSwarm(callerAgentId: string, targetAgentId: string): CrossSwarmResult {
  const callerSwarm = getAgentSwarm(callerAgentId);
  const targetSwarm = getAgentSwarm(targetAgentId);

  const callerSwarmId = callerSwarm?.swarm_id ?? null;
  const targetSwarmId = targetSwarm?.swarm_id ?? null;

  // Both in same swarm (or both unaffiliated) — no gate needed
  if (callerSwarmId === targetSwarmId) {
    return { same_swarm: true, caller_swarm_id: callerSwarmId, target_swarm_id: targetSwarmId, requires_dan_gate: false, rule_ref: "KAV-093" };
  }

  // Cross-swarm: at least one is in a named swarm and they differ
  return { same_swarm: false, caller_swarm_id: callerSwarmId, target_swarm_id: targetSwarmId, requires_dan_gate: true, rule_ref: "KAV-093" };
}

// ── All active swarms (for watchdog) ─────────────────────────────────────────

export function listActiveSwarms(): SwarmRecord[] {
  const dir = swarmsDir();
  const records: SwarmRecord[] = [];
  try {
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".swarm.json"))) {
      try {
        const r = JSON.parse(readFileSync(join(dir, file), "utf-8")) as SwarmRecord;
        // Skip expired swarms that have no active members to check
        if (!r.expires_at || Date.now() <= r.expires_at) records.push(r);
      } catch {}
    }
  } catch {}
  return records;
}
