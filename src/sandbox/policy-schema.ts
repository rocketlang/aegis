// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Sandbox — aegis-agent-policy-v1 Schema
// Every agent operates within a declared policy. Policy files live in ~/.aegis/agents/{agent-id}.json
// @rule:KAV-006 Path scope enforcement
// @rule:KAV-007 Tool and command allowlist
// @rule:KAV-YK-007 Deny-first precedence
// @rule:KAV-061 perm_mask — Level 0 bitmask enforcement gate
// @rule:KAV-062 class_mask — Level 1 resource class enforcement gate

import { PERM_STANDARD } from "../kavach/perm-mask";
import { CLASS_STANDARD } from "../kavach/class-mask";

export const POLICY_SCHEMA_VERSION = "aegis-agent-policy-v1";

export interface AgentPolicy {
  schema_version: "aegis-agent-policy-v1";
  agent_id: string;

  // Phase 1c: bitmask capability gates (Level 0 + Level 1)
  perm_mask: number;    // 32-bit capability bitmask — what this agent may do (KAV-061)
  class_mask: number;   // 9-bit resource class bitmask — what resource classes it may touch (KAV-062)

  // Tool allowlist/denylist — empty tools_allowed = all allowed
  tools_allowed: string[];   // if non-empty: ONLY these tools permitted
  tools_denied: string[];    // always blocked regardless of tools_allowed

  // Filesystem scope — paths are prefix-matched
  path_scope: string[];      // allowed path prefixes (empty = all allowed)
  path_deny: string[];       // blocked path prefixes (checked first — deny-first per KAV-006)

  // Bash command lists — first token of command is matched
  bash_allowlist: string[];  // if non-empty: ONLY these commands permitted
  bash_denylist: string[];   // always blocked regardless of bash_allowlist

  // Database scope — database names only
  db_scope: string[];        // allowed database names (empty = unrestricted)

  // Network
  network_allowed: boolean;  // false = block all outbound network Bash commands

  // Budget
  budget_cap_usd: number;    // 0 = inherit from parent session

  // Delegation depth
  max_depth: number;         // 0 = may not spawn further agents

  // Escalation thresholds before auto-quarantine
  violation_threshold: number; // number of MEDIUM violations before QUARANTINE (default: 3)
}

export const DEFAULT_POLICY: Omit<AgentPolicy, "agent_id"> = {
  schema_version: "aegis-agent-policy-v1",
  perm_mask: PERM_STANDARD,
  class_mask: CLASS_STANDARD,
  tools_allowed: [],
  tools_denied: [],
  path_scope: [],
  path_deny: [],
  bash_allowlist: [],
  bash_denylist: [],
  db_scope: [],
  network_allowed: true,
  budget_cap_usd: 0,
  max_depth: 3,
  violation_threshold: 3,
};

export interface PolicyValidationResult {
  valid: boolean;
  errors: string[];
}

export function validatePolicy(raw: unknown): PolicyValidationResult {
  const errors: string[] = [];

  if (!raw || typeof raw !== "object") {
    return { valid: false, errors: ["Policy must be a JSON object"] };
  }

  const p = raw as Record<string, unknown>;

  if (p.schema_version !== POLICY_SCHEMA_VERSION) {
    errors.push(`schema_version must be "${POLICY_SCHEMA_VERSION}" — got: ${p.schema_version}`);
  }
  if (typeof p.agent_id !== "string" || !p.agent_id) {
    errors.push("agent_id must be a non-empty string");
  }

  const arrayFields = ["tools_allowed", "tools_denied", "path_scope", "path_deny", "bash_allowlist", "bash_denylist", "db_scope"] as const;
  for (const field of arrayFields) {
    if (!Array.isArray(p[field])) {
      errors.push(`${field} must be an array`);
    } else {
      const arr = p[field] as unknown[];
      if (arr.some((v) => typeof v !== "string")) {
        errors.push(`${field} must contain only strings`);
      }
    }
  }

  if (typeof p.network_allowed !== "boolean") errors.push("network_allowed must be a boolean");
  if (typeof p.budget_cap_usd !== "number" || p.budget_cap_usd < 0) errors.push("budget_cap_usd must be a non-negative number");
  if (typeof p.max_depth !== "number" || p.max_depth < 0) errors.push("max_depth must be a non-negative integer");
  if (typeof p.violation_threshold !== "number" || p.violation_threshold < 1) errors.push("violation_threshold must be >= 1");

  return { valid: errors.length === 0, errors };
}

export function makeDefaultPolicy(agentId: string, overrides: Partial<AgentPolicy> = {}): AgentPolicy {
  return {
    ...DEFAULT_POLICY,
    agent_id: agentId,
    ...overrides,
  };
}
