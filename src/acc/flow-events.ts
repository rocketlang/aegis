// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Flow events — one private record per tool-call decision, carrying the flow fields (GTP-018, GTP-024;
// governed-turn-protocol spec §19, phase P1).
//
// PRIVATE BY CONSTRUCTION. These events describe real agent work on this machine, so they go to their
// own file, `<aegis dir>/flow-events.db`, never to acc-events.db: the public read-only cockpit streams
// acc-events.db with no login. They carry only the tool name, the decision, the rule id and the flow
// ids — never the tool's input, a path or the reason text. Writing never throws and never blocks a
// call; AEGIS_FLOW_EVENTS=off turns it off.
//
// The flow-field mapping mirrors @xshieldai/flow's fromClaudeHook until that package is published and
// aegis can depend on it (founder ruling 2026-10-15: the flow package is the home).

import { chmodSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { SqliteEventWriter } from "./bus";
import type { AccReceipt } from "./types";

export function defaultFlowEventsDbPath(): string {
  return join(process.env.AEGIS_DIR ?? join(homedir(), ".aegis"), "flow-events.db");
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim() : undefined);

/** Same mapping as @xshieldai/flow fromClaudeHook: session = flow, tool call = turn, subagent or prompt = parent. */
export function flowFieldsFromHook(input: Record<string, unknown>): Pick<AccReceipt, "flow_id" | "turn_id" | "parent_turn_id"> {
  const session = str(input.session_id);
  if (!session) return {};
  const prompt = str(input.prompt_id), tool = str(input.tool_use_id), agent = str(input.agent_id);
  const out: Pick<AccReceipt, "flow_id" | "turn_id" | "parent_turn_id"> = { flow_id: `cc:${session}` };
  if (tool) out.turn_id = `tool:${tool}`;
  else if (prompt) out.turn_id = `prompt:${prompt}`;
  if (tool) out.parent_turn_id = agent ? `agent:${agent}` : prompt ? `prompt:${prompt}` : undefined;
  if (out.parent_turn_id === undefined) delete out.parent_turn_id;
  return out;
}

export interface ToolDecision {
  /** Process exit code of the hook: 0 = allowed, 2 = blocked. */
  exitCode: number;
  /** Set when the shield recorded a block with a rule (emitBlock). */
  ruleId?: string;
  verdict?: string;
  category?: string;
}

/** The event for one tool-call decision, or null when there is nothing to record (no session, not PreToolUse). */
export function toolDecisionEvent(input: Record<string, unknown>, d: ToolDecision, now = new Date()): AccReceipt | null {
  const event = str(input.hook_event_name);
  if (event !== undefined && event !== "PreToolUse") return null;
  const flow = flowFieldsFromHook(input);
  if (!flow.flow_id) return null;
  const tool = str(input.tool_name) ?? "unknown";
  const verdict = d.verdict ?? (d.exitCode === 2 ? "BLOCKED" : d.exitCode === 0 ? "ALLOWED" : `EXIT_${d.exitCode}`);
  return {
    receipt_id: `aegis-tool-${now.getTime().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    primitive: "aegis",
    event_type: "tool.decided",
    emitted_at: now.toISOString(),
    agent_id: str(input.agent_id),
    verdict,
    rules_fired: d.ruleId ? [d.ruleId] : undefined,
    summary: tool.slice(0, 120),
    payload: { hook: "PreToolUse", ...(d.category ? { category: d.category } : {}), ...(str(input.agent_type) ? { agent_type: str(input.agent_type) } : {}) },
    ...flow,
  };
}

/** Writes one decision to the private flow store. Never throws. */
export function recordToolDecision(input: Record<string, unknown>, d: ToolDecision, path = defaultFlowEventsDbPath()): void {
  if (process.env.AEGIS_FLOW_EVENTS === "off") return;
  try {
    const e = toolDecisionEvent(input, d);
    if (!e) return;
    const fresh = !existsSync(path);
    const w = new SqliteEventWriter({ path });
    try { w.write(e); } finally { w.close(); }
    // Real activity: readable by this account only.
    if (fresh) for (const f of [path, `${path}-wal`, `${path}-shm`]) { try { chmodSync(f, 0o600); } catch {} }
  } catch {
    // a record we could not write must never change the decision
  }
}
