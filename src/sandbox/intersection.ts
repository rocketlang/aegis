// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Sandbox — Parent-wins Policy Intersection (V2-028)
// At spawn time, compute the effective policy as INTERSECT(parent, child).
// Parent always wins on restrictions — a child cannot grant itself more scope.
// @rule:KAV-YK-007 Parent-wins intersection
// @rule:KAV-015 Delegation chain scope enforcement
// @rule:KAV-065 child perm_mask = parent.effective & requested (AND invariant)

import type { AgentPolicy } from "./policy-schema";
import { computeChildPermMask, detectEscalation } from "../kavach/perm-mask";

export interface IntersectionResult {
  effective_policy: AgentPolicy;
  policy_conflict_resolved: boolean;
  narrowed_fields: string[];
  escalation_detected: boolean; // true → child requested bits parent doesn't have
}

// @rule:KAV-092 opts.swarm_mask applies triple AND when spawning into a swarm
export function intersectPolicies(
  parent: AgentPolicy,
  child: AgentPolicy,
  opts: { swarm_mask?: number } = {}
): IntersectionResult {
  const narrowed: string[] = [];

  // Array fields: effective = intersection (only items in BOTH lists, or use parent if child is empty/broader)
  function intersectArrays(field: keyof AgentPolicy, parentArr: string[], childArr: string[]): string[] {
    if (parentArr.length === 0 && childArr.length === 0) return [];
    if (parentArr.length === 0) {
      // Parent unrestricted — child's list applies
      return childArr;
    }
    if (childArr.length === 0) {
      // Child unrestricted — parent's restriction applies (parent wins)
      narrowed.push(field as string);
      return parentArr;
    }
    // Both have lists — intersection (only what both allow)
    const result = childArr.filter((v) => parentArr.includes(v));
    if (result.length < childArr.length) narrowed.push(field as string);
    return result;
  }

  // Boolean: false wins (if either restricts, result is restricted)
  function intersectBool(field: string, parentVal: boolean, childVal: boolean): boolean {
    if (!parentVal && childVal) { narrowed.push(field); return false; }
    return parentVal && childVal;
  }

  // Numeric: min value wins (tighter budget/depth)
  function intersectMin(field: string, parentVal: number, childVal: number, zeroMeansInherited = false): number {
    if (zeroMeansInherited) {
      if (parentVal === 0 && childVal === 0) return 0;
      if (parentVal === 0) return childVal;
      if (childVal === 0) return parentVal;
    }
    if (parentVal < childVal) { narrowed.push(field); return parentVal; }
    return childVal;
  }

  // @rule:KAV-065 — perm_mask: child = parent.effective & requested (AND invariant)
  // @rule:KAV-079 spawn invariant proof event
  // @rule:KAV-092 triple AND when swarm context present: child & parent & swarm_mask
  let baseChildMask = computeChildPermMask(parent.perm_mask, child.perm_mask);
  const escalationDetected = detectEscalation(parent.perm_mask, child.perm_mask);
  if ((baseChildMask & ~parent.perm_mask) !== 0) throw new Error("KAV-079: spawn invariant violated");
  // Apply swarm ceiling if context carries one
  const swarmMask = opts.swarm_mask;
  if (typeof swarmMask === "number" && swarmMask !== 0) {
    baseChildMask = baseChildMask & swarmMask;
  }
  const childPermMask = baseChildMask;
  if (childPermMask < child.perm_mask) narrowed.push("perm_mask");

  // class_mask: AND intersection — child cannot access classes parent doesn't have
  const childClassMask = parent.class_mask & child.class_mask;
  if (childClassMask < child.class_mask) narrowed.push("class_mask");

  const effective: AgentPolicy = {
    schema_version: "aegis-agent-policy-v1",
    agent_id: child.agent_id,
    perm_mask: childPermMask,
    class_mask: childClassMask,

    // Tool lists
    tools_allowed: intersectArrays("tools_allowed", parent.tools_allowed, child.tools_allowed),
    tools_denied: Array.from(new Set([...parent.tools_denied, ...child.tools_denied])), // union of denied

    // Path lists
    path_scope: intersectArrays("path_scope", parent.path_scope, child.path_scope),
    path_deny: Array.from(new Set([...parent.path_deny, ...child.path_deny])), // union of denied

    // Bash lists
    bash_allowlist: intersectArrays("bash_allowlist", parent.bash_allowlist, child.bash_allowlist),
    bash_denylist: Array.from(new Set([...parent.bash_denylist, ...child.bash_denylist])), // union

    // DB scope
    db_scope: intersectArrays("db_scope", parent.db_scope, child.db_scope),

    // Booleans — false wins
    network_allowed: intersectBool("network_allowed", parent.network_allowed, child.network_allowed),

    // Numerics — min wins
    budget_cap_usd: intersectMin("budget_cap_usd", parent.budget_cap_usd, child.budget_cap_usd, true),
    max_depth: intersectMin("max_depth", parent.max_depth - 1, child.max_depth), // parent depth decremented for child
    violation_threshold: intersectMin("violation_threshold", parent.violation_threshold, child.violation_threshold),
  };

  return {
    effective_policy: effective,
    policy_conflict_resolved: narrowed.length > 0,
    narrowed_fields: narrowed,
    escalation_detected: escalationDetected,
  };
}

// @rule:KAV-079 spawn invariant proof event
// @rule:KAV-092 extended with swarm_mask when spawning into a swarm
export interface SpawnProof {
  event: "spawn.invariant_check";
  parent_mask: number;
  child_requested_mask: number;
  swarm_mask: number | null;      // null if not a swarm spawn
  effective_child_mask: number;
  invariant_check: string;
  invariant_satisfied: boolean;
  swarm_id: string | null;        // null if not a swarm spawn
  checked_at: string;
  rule_ref: "KAV-079";
}

export function buildSpawnProof(
  parent: AgentPolicy,
  child: AgentPolicy,
  effective: number,
  swarmCtx: { swarm_id: string; swarm_mask: number } | null = null
): SpawnProof {
  const baseCheck = `${effective} & ~${parent.perm_mask} == 0`;
  const swarmCheck = swarmCtx ? ` && ${effective} & ~${swarmCtx.swarm_mask} == 0` : "";
  return {
    event: "spawn.invariant_check",
    parent_mask: parent.perm_mask,
    child_requested_mask: child.perm_mask,
    swarm_mask: swarmCtx?.swarm_mask ?? null,
    effective_child_mask: effective,
    invariant_check: baseCheck + swarmCheck,
    invariant_satisfied: (effective & ~parent.perm_mask) === 0 &&
      (swarmCtx ? (effective & ~swarmCtx.swarm_mask) === 0 : true),
    swarm_id: swarmCtx?.swarm_id ?? null,
    checked_at: new Date().toISOString(),
    rule_ref: "KAV-079",
  };
}
