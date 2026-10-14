// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// @xshieldai/flow — one agentic flow, end to end.
//
// The Governed Turn Protocol (GTP) governs one turn over HTTP. This package carries GTP's flow identity
// to the boundaries that are not HTTP (tool calls, subagents, subprocesses, MCP) and to the event every
// xShieldAI package emits, so the separate guardrails can be read, and later enforced, as one flow.
// Rules: governed-turn-protocol spec §19 (GTP-017…026).
//
// This is P1: identity and narrowing, no enforcement of its own. Pure functions, no I/O.

/** The five optional flow fields an event may carry (GTP-024). Added, never changed. */
export interface FlowFields {
  /** The flow: GTP's `chain`. One per root of authority (GTP-017, GTP-018). */
  flow_id?: string;
  /** This turn (one governed action). */
  turn_id?: string;
  /** The turn or agent this one descends from. Absent only on the first turn of a flow. */
  parent_turn_id?: string;
  /** The Mudrika mandate at the root of the flow, when one is known (GTP-017). */
  mandate_id?: string;
  /** The session this turn runs under: an ASE seal or a nallasetu credential reference. */
  session_ref?: string;
}

export const FLOW_FIELDS = ["flow_id", "turn_id", "parent_turn_id", "mandate_id", "session_ref"] as const;

/** A refusal always names its rule (GTP-005, GTP-026). */
export class FlowRefusal extends Error {
  constructor(readonly rule: string, message: string) {
    super(`${rule}: ${message}`);
    this.name = "FlowRefusal";
  }
}

const isMask = (m: unknown): m is number => typeof m === "number" && Number.isInteger(m) && m >= 0 && m <= 0xffffffff;

/**
 * GTP-020: every hop narrows. The child's ceiling is the parent's effective mask AND what was requested.
 * Masks are 32-bit unsigned integers; anything else is refused rather than coerced.
 */
export function narrow(parentEffective: number, requested: number): number {
  if (!isMask(parentEffective)) throw new FlowRefusal("GTP-020", `parent mask ${String(parentEffective)} is not a 32-bit unsigned integer`);
  if (!isMask(requested)) throw new FlowRefusal("GTP-020", `requested mask ${String(requested)} is not a 32-bit unsigned integer`);
  return (parentEffective & requested) >>> 0;
}

/** True when `child` holds no bit that `parent` lacks (the spawn invariant, KAV-065). */
export function isWithin(child: number, parent: number): boolean {
  return isMask(child) && isMask(parent) && ((child & ~parent) >>> 0) === 0;
}

/**
 * GTP-021: a hop that names a parent which cannot be found is refused. Missing lineage is never a root.
 * `parent` is what the caller's own store returned for the named id (null/undefined = not found).
 */
export function narrowFromParent(
  parentId: string,
  parent: { effective_mask: number } | null | undefined,
  requested: number,
): number {
  if (!parent) throw new FlowRefusal("GTP-021", `parent ${JSON.stringify(parentId)} cannot be found; refusing instead of treating it as a root`);
  return narrow(parent.effective_mask, requested);
}

/**
 * Add flow fields to an event. Only fields that are set are added, and a field the event already
 * carries is never overwritten (GTP-024, GTP-YK-011). Returns a new object.
 */
export function stamp<T extends object>(event: T, flow: FlowFields): T & FlowFields {
  const out = { ...event } as Record<string, unknown>;
  for (const k of FLOW_FIELDS) {
    const v = flow[k];
    if (typeof v === "string" && v !== "" && out[k] === undefined) out[k] = v;
  }
  return out as T & FlowFields;
}

/** The fields of a Claude Code hook input this package reads (all optional, all untrusted strings). */
export interface ClaudeHookInput {
  session_id?: unknown;
  prompt_id?: unknown;
  tool_use_id?: unknown;
  agent_id?: unknown;
  hook_event_name?: unknown;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() !== "" ? v.trim() : undefined);

/**
 * Flow fields for one Claude Code hook call (GTP-018), from the fields Claude Code sends:
 *   flow   = the session            (`cc:<session_id>`)
 *   turn   = the tool call          (`tool:<tool_use_id>`), or the prompt for a prompt hook
 *   parent = the subagent that made the call (`agent:<agent_id>`) when there is one,
 *            otherwise the prompt it answers (`prompt:<prompt_id>`)
 * A hook input with no session id gives no flow: an empty object, never a made-up id.
 */
export function fromClaudeHook(input: ClaudeHookInput | null | undefined): FlowFields {
  const session = str(input?.session_id);
  if (!session) return {};
  const prompt = str(input?.prompt_id);
  const tool = str(input?.tool_use_id);
  const agent = str(input?.agent_id);
  const flow: FlowFields = { flow_id: `cc:${session}` };
  if (tool) flow.turn_id = `tool:${tool}`;
  else if (prompt) flow.turn_id = `prompt:${prompt}`;
  if (tool) {
    if (agent) flow.parent_turn_id = `agent:${agent}`;
    else if (prompt) flow.parent_turn_id = `prompt:${prompt}`;
  }
  return flow;
}

// ── P3: the mandate as the root of a flow (GTP-017, GTP-019, GTP-022) ──────────────────────────────

/** The fields of a mandate this package reads. Same names as a hanumang Mudrika (@xshieldai/hanumang-mandate). */
export interface MandateLike {
  mudrika_id: string;
  trust_mask: number;
  issued_at: string;
  ttl_seconds: number;
}

export type MandateStatus = "valid" | "expired" | "revoked" | "missing" | "malformed";

/**
 * GTP-017 / GTP-022. A flow's root is valid only while its mandate exists, is well formed, has not
 * expired and has not been revoked. `revoked` is the set of revoked mandate ids the caller keeps.
 */
export function mandateStatus(
  mandate: MandateLike | null | undefined,
  opts: { now?: Date; revoked?: ReadonlySet<string> } = {},
): MandateStatus {
  if (!mandate) return "missing";
  const issued = Date.parse(mandate.issued_at);
  if (typeof mandate.mudrika_id !== "string" || mandate.mudrika_id === "" || !isMask(mandate.trust_mask) ||
      !Number.isFinite(issued) || !Number.isInteger(mandate.ttl_seconds) || mandate.ttl_seconds <= 0) return "malformed";
  if (opts.revoked?.has(mandate.mudrika_id)) return "revoked";
  const now = (opts.now ?? new Date()).getTime();
  return now >= issued + mandate.ttl_seconds * 1000 ? "expired" : "valid";
}

/**
 * GTP-019: the ceiling of a turn is computed, never declared: the mandate's mask AND every narrower
 * layer that is present (the session envelope, a cross-org session, the parent turn). No mandate, no
 * ceiling: refused (GTP-017).
 */
export function effectiveCeiling(layers: {
  mandate?: number | null;
  envelope?: number | null;
  session?: number | null;
  parent?: number | null;
}): number {
  if (layers.mandate === undefined || layers.mandate === null) {
    throw new FlowRefusal("GTP-017", "no mandate: a flow has no root of authority, so it has no ceiling");
  }
  let m = narrow(0xffffffff, layers.mandate);
  for (const k of ["envelope", "session", "parent"] as const) {
    const v = layers[k];
    if (v !== undefined && v !== null) m = narrow(m, v);
  }
  return m;
}
