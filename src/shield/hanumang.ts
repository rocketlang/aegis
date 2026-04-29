// AEGIS Shield — HanumanG 7-Axis Agent Delegation Check
// Validates every Agent tool spawn against 7 trust axes.
// An agent that fails any axis is blocked at spawn time.
// @rule:KAV-015 HanumanG delegation chain validation

export interface HanumanGAxes {
  identity: boolean;        // Axis 1 — agent has a declared or resolvable identity
  authorization: boolean;   // Axis 2 — explicit delegation from a known parent
  scope: boolean;           // Axis 3 — declared scope is narrower than or equal to parent scope
  budget: boolean;          // Axis 4 — child budget fits within parent's remaining budget
  depth: boolean;           // Axis 5 — delegation depth within configured limit
  purpose: boolean;         // Axis 6 — purpose statement is present and coherent (non-empty)
  revocability: boolean;    // Axis 7 — parent retains capability to revoke the child
}

export interface HanumanGResult {
  passed: boolean;
  axes: HanumanGAxes;
  failed_axes: string[];
  reason: string;
}

export interface SpawnContext {
  // From tool input (parsed from Claude Code PreToolUse JSON)
  agent_description?: string;          // the "description" field in Agent tool call
  prompt?: string;                     // the "prompt" field in Agent tool call
  // From AEGIS session state
  parent_agent_id?: string;
  parent_budget_remaining_usd?: number;
  child_budget_cap_usd?: number;
  parent_depth?: number;
  max_depth?: number;
  parent_tools_allowed?: string[];     // empty = all tools
  child_tools_requested?: string[];    // from prompt analysis — optional
}

const MAX_DEPTH_DEFAULT = 5;

export function checkHanumanG(ctx: SpawnContext): HanumanGResult {
  const maxDepth = ctx.max_depth ?? MAX_DEPTH_DEFAULT;
  const parentDepth = ctx.parent_depth ?? 0;

  const axes: HanumanGAxes = {
    // Axis 1 — identity: description or prompt provides a non-empty, non-trivial agent label
    identity: !!(ctx.agent_description && ctx.agent_description.trim().length > 3),

    // Axis 2 — authorization: parent is known (has an ID in the session registry)
    // In PreToolUse context the spawning agent IS the parent — we trust the session registry
    // knows who is spawning. If parent_agent_id is unknown, treat as not authorized.
    authorization: !!(ctx.parent_agent_id && ctx.parent_agent_id !== "unknown"),

    // Axis 3 — scope: if parent has a tool restriction, child cannot exceed it
    // If parent has no restriction (empty list) scope is unrestricted → child inherits freely
    scope: (() => {
      if (!ctx.parent_tools_allowed || ctx.parent_tools_allowed.length === 0) return true;
      if (!ctx.child_tools_requested || ctx.child_tools_requested.length === 0) return true;
      // All requested tools must be in parent's allowed list
      return ctx.child_tools_requested.every((t) => ctx.parent_tools_allowed!.includes(t));
    })(),

    // Axis 4 — budget: child budget must fit within parent's remaining
    budget: (() => {
      if (ctx.child_budget_cap_usd === undefined || ctx.parent_budget_remaining_usd === undefined) return true;
      return ctx.child_budget_cap_usd <= ctx.parent_budget_remaining_usd;
    })(),

    // Axis 5 — depth: delegation chain must not exceed max_depth
    depth: parentDepth < maxDepth,

    // Axis 6 — purpose: prompt must be non-empty (no purpose = unknown intent = unsafe)
    purpose: !!(ctx.prompt && ctx.prompt.trim().length > 10),

    // Axis 7 — revocability: AEGIS itself is the revocation mechanism — always true when AEGIS is running
    // In a future version, this checks if the parent's session is still live in the registry
    revocability: true,
  };

  const AXIS_NAMES: Record<keyof HanumanGAxes, string> = {
    identity: "identity (Axis 1)",
    authorization: "authorization (Axis 2)",
    scope: "scope (Axis 3)",
    budget: "budget (Axis 4)",
    depth: `depth (Axis 5 — depth ${parentDepth + 1} exceeds max ${maxDepth})`,
    purpose: "purpose (Axis 6)",
    revocability: "revocability (Axis 7)",
  };

  const failed_axes = (Object.keys(axes) as Array<keyof HanumanGAxes>)
    .filter((k) => !axes[k])
    .map((k) => AXIS_NAMES[k]);

  const passed = failed_axes.length === 0;

  const reason = passed
    ? "HanumanG: all 7 axes pass — agent spawn authorized"
    : `HanumanG: spawn blocked — failed axes: ${failed_axes.join(", ")}`;

  return { passed, axes, failed_axes, reason };
}
