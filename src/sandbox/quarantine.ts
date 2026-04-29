// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Sandbox — Agent State Machine (V2-029)
// States: RUNNING | QUARANTINED | ORPHAN | ZOMBIE | FORCE_CLOSED | KILLED | COMPLETED
// File-backed registry: ~/.aegis/agents/{agent-id}.state.json
// @rule:KAV-004 Quarantine state and human release
// @rule:KAV-012 Orphan detection
// @rule:KAV-013 Zombie detection
// @rule:KAV-YK-005 Escalation → quarantine transition

import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import type { IdentityConfidence } from "./policy-loader";

// Lazy DB import — avoids pulling SQLite into every hook invocation context
function tryDbSync(record: AgentRecord): void {
  try {
    const { upsertAgent } = require("../core/db");
    upsertAgent({
      ...record,
      budget_pool_reserved: 0,
      stop_requested: 0,
    });
  } catch { /* DB unavailable or not yet initialized — file state is authoritative */ }
}

export type AgentState =
  | "RUNNING"
  | "QUARANTINED"
  | "ORPHAN"
  | "ZOMBIE"
  | "FORCE_CLOSED"
  | "KILLED"
  | "COMPLETED";

// Valid transitions per KAV-004, KAV-012, KAV-013
const VALID_TRANSITIONS: Record<AgentState, AgentState[]> = {
  RUNNING: ["QUARANTINED", "FORCE_CLOSED", "KILLED", "COMPLETED", "ZOMBIE"],
  QUARANTINED: ["RUNNING", "FORCE_CLOSED", "KILLED"],    // RUNNING only via human release
  ORPHAN: ["FORCE_CLOSED", "KILLED", "COMPLETED"],
  ZOMBIE: ["FORCE_CLOSED", "KILLED"],
  FORCE_CLOSED: [],
  KILLED: [],
  COMPLETED: [],
};

export interface AgentRecord {
  agent_id: string;
  state: AgentState;
  identity_confidence: IdentityConfidence;
  parent_id: string | null;
  session_id: string;
  depth: number;
  budget_cap_usd: number;
  budget_used_usd: number;
  tool_calls: number;
  loop_count: number;           // total PreToolUse calls — runaway detection (KAV-068)
  tools_declared: number;       // policy.tools_allowed.length; 0 = unrestricted (max surface) (KAV-068)
  violation_count: number;
  spawn_timestamp: string;
  last_seen: string;
  policy_path: string | null;
  quarantine_reason: string | null;
  quarantine_rule: string | null;
  release_reason: string | null;
  released_by: string | null;
  resume_manifest_path: string | null;
}

function getAgentsDir(): string {
  const dir = join(getAegisDir(), "agents");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function getStatePath(agentId: string): string {
  return join(getAgentsDir(), `${agentId}.state.json`);
}

export function loadAgent(agentId: string): AgentRecord | null {
  const path = getStatePath(agentId);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as AgentRecord;
  } catch {
    return null;
  }
}

export function saveAgent(record: AgentRecord): void {
  writeFileSync(getStatePath(record.agent_id), JSON.stringify(record, null, 2));
  tryDbSync(record);
}

export function createAgent(opts: {
  agent_id: string;
  identity_confidence: IdentityConfidence;
  parent_id: string | null;
  session_id: string;
  depth: number;
  budget_cap_usd: number;
  policy_path: string | null;
  tools_declared?: number;
}): AgentRecord {
  const record: AgentRecord = {
    agent_id: opts.agent_id,
    state: "RUNNING",
    identity_confidence: opts.identity_confidence,
    parent_id: opts.parent_id,
    session_id: opts.session_id,
    depth: opts.depth,
    budget_cap_usd: opts.budget_cap_usd,
    budget_used_usd: 0,
    tool_calls: 0,
    loop_count: 0,
    tools_declared: opts.tools_declared ?? 0,
    violation_count: 0,
    spawn_timestamp: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    policy_path: opts.policy_path,
    quarantine_reason: null,
    quarantine_rule: null,
    release_reason: null,
    released_by: null,
    resume_manifest_path: null,
  };
  saveAgent(record);
  return record;
}

export interface TransitionResult {
  success: boolean;
  error?: string;
  record: AgentRecord;
}

export function transitionState(
  agentId: string,
  targetState: AgentState,
  meta: {
    reason?: string;
    rule?: string;
    released_by?: string;
    resume_manifest_path?: string;
  } = {}
): TransitionResult {
  const record = loadAgent(agentId);
  if (!record) {
    return { success: false, error: `Agent ${agentId} not found`, record: {} as AgentRecord };
  }

  const allowed = VALID_TRANSITIONS[record.state];
  if (!allowed.includes(targetState)) {
    return {
      success: false,
      error: `Invalid transition ${record.state} → ${targetState} (allowed: ${allowed.join(", ") || "none"})`,
      record,
    };
  }

  record.state = targetState;
  record.last_seen = new Date().toISOString();

  if (targetState === "QUARANTINED") {
    record.quarantine_reason = meta.reason ?? null;
    record.quarantine_rule = meta.rule ?? null;
  }
  if (targetState === "RUNNING" && record.quarantine_reason) {
    // Released from quarantine
    record.release_reason = meta.reason ?? null;
    record.released_by = meta.released_by ?? null;
    record.quarantine_reason = null;
    record.quarantine_rule = null;
  }
  if (meta.resume_manifest_path) {
    record.resume_manifest_path = meta.resume_manifest_path;
  }

  saveAgent(record);
  return { success: true, record };
}

export function updateLastSeen(agentId: string): void {
  const record = loadAgent(agentId);
  if (!record || record.state !== "RUNNING") return;
  record.last_seen = new Date().toISOString();
  record.tool_calls++;
  record.loop_count = (record.loop_count ?? 0) + 1;
  saveAgent(record);
}

export function incrementViolation(agentId: string): number {
  const record = loadAgent(agentId);
  if (!record) return 0;
  record.violation_count++;
  saveAgent(record);
  return record.violation_count;
}

export function listAgents(filterState?: AgentState | AgentState[]): AgentRecord[] {
  const dir = getAgentsDir();
  const files = readdirSync(dir).filter((f) => f.endsWith(".state.json"));
  const records: AgentRecord[] = [];

  for (const f of files) {
    try {
      const rec = JSON.parse(readFileSync(join(dir, f), "utf-8")) as AgentRecord;
      if (!filterState) {
        records.push(rec);
      } else {
        const states = Array.isArray(filterState) ? filterState : [filterState];
        if (states.includes(rec.state)) records.push(rec);
      }
    } catch { /* skip corrupt files */ }
  }

  return records.sort((a, b) => b.spawn_timestamp.localeCompare(a.spawn_timestamp));
}
