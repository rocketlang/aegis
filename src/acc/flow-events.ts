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

// ── Reading flows back (P1c: the login-only flow page) ─────────────────────────────────────────────

export interface FlowSummary {
  flow_id: string;
  first_at: string;
  last_at: string;
  turns: number;
  blocked: number;
  subagents: number;
}

const isBlock = (v?: string): boolean => !!v && v !== "ALLOWED";

/** One line per flow, most recent first. Pure: give it the events. */
export function summariseFlows(events: AccReceipt[], limit = 50): FlowSummary[] {
  const by = new Map<string, FlowSummary & { _agents: Set<string> }>();
  for (const e of events) {
    if (!e.flow_id) continue;
    let s = by.get(e.flow_id);
    if (!s) { s = { flow_id: e.flow_id, first_at: e.emitted_at, last_at: e.emitted_at, turns: 0, blocked: 0, subagents: 0, _agents: new Set() }; by.set(e.flow_id, s); }
    if (e.emitted_at < s.first_at) s.first_at = e.emitted_at;
    if (e.emitted_at > s.last_at) s.last_at = e.emitted_at;
    s.turns++;
    if (isBlock(e.verdict)) s.blocked++;
    if (e.parent_turn_id?.startsWith("agent:")) s._agents.add(e.parent_turn_id);
  }
  return [...by.values()]
    .map(({ _agents, ...s }) => ({ ...s, subagents: _agents.size }))
    .sort((a, b) => (a.last_at < b.last_at ? 1 : -1))
    .slice(0, limit);
}

export interface FlowBranch {
  /** `prompt:<id>`, `agent:<id>`, or `(no parent)` for a turn that named none. */
  parent: string;
  kind: "prompt" | "subagent" | "other";
  agent_type?: string;
  first_at: string;
  turns: AccReceipt[];
}

/**
 * The flow as a tree: the flow, then one branch per parent (each prompt of the main agent and each
 * subagent) in the order it first acted, then that parent's turns in order. A subagent is not yet tied
 * to the prompt that started it: the hook input carries no link (recorded as a P2 item).
 */
export function buildFlowTree(events: AccReceipt[]): FlowBranch[] {
  const by = new Map<string, FlowBranch>();
  const sorted = [...events].sort((a, b) => (a.emitted_at < b.emitted_at ? -1 : a.emitted_at > b.emitted_at ? 1 : 0));
  for (const e of sorted) {
    const parent = e.parent_turn_id ?? "(no parent)";
    let b = by.get(parent);
    if (!b) {
      const kind = parent.startsWith("prompt:") ? "prompt" : parent.startsWith("agent:") ? "subagent" : "other";
      b = { parent, kind, first_at: e.emitted_at, turns: [] };
      by.set(parent, b);
    }
    const at = (e.payload as { agent_type?: unknown } | undefined)?.agent_type;
    if (b.kind === "subagent" && !b.agent_type && typeof at === "string") b.agent_type = at;
    b.turns.push(e);
  }
  return [...by.values()];
}

/** Reads the private store. Opens it only to read; returns [] if it does not exist yet. */
export function readFlowEvents(opts: { flowId?: string; limit?: number; path?: string } = {}): AccReceipt[] {
  const path = opts.path ?? defaultFlowEventsDbPath();
  if (!existsSync(path)) return [];
  const w = new SqliteEventWriter({ path });
  try {
    return opts.flowId ? w.queryByFlow(opts.flowId, opts.limit ?? 2000) : w.queryLatest(opts.limit ?? 5000);
  } finally {
    w.close();
  }
}
