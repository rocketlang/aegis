// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS-Shastra — Lawful Action Map Generator
//
// Translates an agent's perm_mask + class_mask + AgentPolicy into a
// pre-planning constraint map the agent receives BEFORE it starts work.
//
// The agent should not discover forbidden paths by hitting a wall.
// It receives a lawful universe before it begins to plan.
// Capability is not authority.
//
// @rule:KAV-SHT-001 lawful action map generated before agent planning begins
// @rule:KAV-SHT-004 default decision is deny — only explicit allow/gate entries are enumerated
// @rule:KAV-YK-007  deny-first precedence (inherited from sandbox policy)

import { resolveAgentId, loadPolicyOrDefault } from "../sandbox/policy-loader";
import { PERM } from "../kavach/perm-mask";
import { CLASS } from "../kavach/class-mask";
import { hashPolicy } from "./policy-hash";
import type { AgentPolicy } from "../sandbox/policy-schema";

// ── Action taxonomy ───────────────────────────────────────────────────────────

interface ActionDef {
  action: string;
  perm_bit: number;
  authority_class: string;
  human_gate_classes: number;  // class_mask bits that force HUMAN_GATE even if perm allows
  description: string;
}

// Every agent action mapped to a perm bit, authority class, and the resource
// class bits that elevate it to human_gate regardless of perm.
const ACTION_DEFS: ActionDef[] = [
  {
    action: "read_file",
    perm_bit: PERM.READ,
    authority_class: "read_only",
    human_gate_classes: CLASS.SECRET,
    description: "Read any file the OS permits",
  },
  {
    action: "write_file",
    perm_bit: PERM.WRITE,
    authority_class: "internal_write",
    human_gate_classes: CLASS.PROD | CLASS.SECRET | CLASS.INFRA | CLASS.FINANCIAL,
    description: "Write or edit a file",
  },
  {
    action: "create_file",
    perm_bit: PERM.FS_CREATE,
    authority_class: "internal_write",
    human_gate_classes: CLASS.PROD | CLASS.INFRA,
    description: "Create new files or directories",
  },
  {
    action: "delete_file",
    perm_bit: PERM.FS_DELETE,
    authority_class: "governance",
    human_gate_classes: CLASS.PROD | CLASS.DEMO | CLASS.INFRA | CLASS.FINANCIAL | CLASS.MARITIME,
    description: "Delete files or directories",
  },
  {
    action: "execute_bash",
    perm_bit: PERM.EXEC_BASH,
    authority_class: "execution",
    human_gate_classes: CLASS.PROD | CLASS.INFRA,
    description: "Run shell commands",
  },
  {
    action: "spawn_agent",
    perm_bit: PERM.SPAWN_AGENTS,
    authority_class: "execution",
    human_gate_classes: CLASS.PROD,
    description: "Spawn sub-agents",
  },
  {
    action: "network_call",
    perm_bit: PERM.NETWORK,
    authority_class: "external_call",
    human_gate_classes: CLASS.FINANCIAL | CLASS.PERSONAL,
    description: "Make outbound network requests",
  },
  {
    action: "db_read",
    perm_bit: PERM.DB_READ,
    authority_class: "read_only",
    human_gate_classes: CLASS.PROD | CLASS.FINANCIAL | CLASS.PERSONAL,
    description: "Read from databases",
  },
  {
    action: "db_write",
    perm_bit: PERM.DB_WRITE,
    authority_class: "internal_write",
    human_gate_classes: CLASS.PROD | CLASS.FINANCIAL | CLASS.MARITIME,
    description: "Write to databases (INSERT / UPDATE)",
  },
  {
    action: "db_schema_change",
    perm_bit: PERM.DB_SCHEMA,
    authority_class: "governance",
    human_gate_classes: CLASS.PROD | CLASS.DEMO | CLASS.FINANCIAL | CLASS.MARITIME,
    description: "Alter database schema (DROP / ALTER / TRUNCATE)",
  },
  {
    action: "service_operation",
    perm_bit: PERM.SERVICE_OP,
    authority_class: "deploy",
    human_gate_classes: CLASS.PROD | CLASS.MARITIME | CLASS.FINANCIAL,
    description: "Start / stop / restart services via ankr-ctl",
  },
  {
    action: "read_secret",
    perm_bit: PERM.SECRET_READ,
    authority_class: "governance",
    human_gate_classes: CLASS.SECRET,
    description: "Read .env files or credential stores",
  },
  {
    action: "write_config",
    perm_bit: PERM.CONFIG_WRITE,
    authority_class: "governance",
    human_gate_classes: CLASS.INFRA | CLASS.ANKR_INTERNAL | CLASS.PROD,
    description: "Write configuration files (ports.json, services.json, etc.)",
  },
  {
    action: "git_write",
    perm_bit: PERM.GIT_WRITE,
    authority_class: "deploy",
    human_gate_classes: CLASS.PROD,
    description: "git commit / push / reset (write operations)",
  },
  {
    action: "external_api_call",
    perm_bit: PERM.EXTERNAL_API,
    authority_class: "external_call",
    human_gate_classes: CLASS.FINANCIAL | CLASS.PERSONAL | CLASS.MARITIME,
    description: "Call external APIs (non-Bash, direct tool call)",
  },
  {
    action: "privileged_operation",
    perm_bit: PERM.PRIVILEGED,
    authority_class: "governance",
    human_gate_classes: 0x1FF,  // all classes
    description: "sudo / root-level operations",
  },
  {
    action: "production_access",
    perm_bit: PERM.PRODUCTION,
    authority_class: "governance",
    human_gate_classes: CLASS.PROD,
    description: "Direct access to production-class resources",
  },
];

// ── Resource class names ──────────────────────────────────────────────────────

const CLASS_NAMES: Array<{ bit: number; name: string; label: string }> = [
  { bit: CLASS.DEV,          name: "dev",           label: "development resources" },
  { bit: CLASS.DEMO,         name: "demo",          label: "demo environments" },
  { bit: CLASS.PROD,         name: "production",    label: "production databases and live services" },
  { bit: CLASS.SECRET,       name: "secrets",       label: "credentials and .env files" },
  { bit: CLASS.MARITIME,     name: "maritime",      label: "vessel data and maritime telemetry" },
  { bit: CLASS.FINANCIAL,    name: "financial",     label: "payment records and invoices" },
  { bit: CLASS.PERSONAL,     name: "personal_data", label: "PII and personal data" },
  { bit: CLASS.INFRA,        name: "infrastructure", label: "docker, nginx, system config" },
  { bit: CLASS.ANKR_INTERNAL, name: "ankr_internal", label: "codex.json, services.json, ports.json" },
];

// ── Output types ──────────────────────────────────────────────────────────────

export interface LawfulEntry {
  action: string;
  description: string;
  resource_classes: string[];
}

export interface ForbiddenEntry {
  action: string;
  description: string;
  reason: string;
}

export interface HumanGateEntry {
  action: string;
  description: string;
  resource_classes: string[];
  authority_class: string;
  reason: string;
}

export interface LawfulActionMap {
  agent_id: string;
  mission: string;
  policy_hash: string;
  generated_at: string;
  rule_ref: "KAV-SHT-001";
  summary: {
    lawful_count: number;
    forbidden_count: number;
    human_gate_count: number;
    default: "deny";
  };
  lawful_actions: LawfulEntry[];
  forbidden_actions: ForbiddenEntry[];
  human_gate_actions: HumanGateEntry[];
  // Ready to prepend to the agent's system prompt
  prompt_injection: string;
}

// ── Generator ─────────────────────────────────────────────────────────────────

/**
 * Generate the lawful action map for an agent before it begins planning.
 * Reads perm_mask + class_mask + AgentPolicy and produces three lists:
 *   - lawful_actions  — the agent may proceed
 *   - forbidden_actions — the agent must not propose these
 *   - human_gate_actions — the agent must produce an approval packet, not execute
 *
 * @rule:KAV-SHT-001
 */
export function generateLawfulActionMap(
  agentId: string,
  mission: string,
): LawfulActionMap {
  const identity = resolveAgentId({ envAgentId: agentId });
  const policy = loadPolicyOrDefault(identity);
  return generateLawfulActionMapFromPolicy(agentId, mission, policy);
}

/**
 * Same as generateLawfulActionMap but accepts a pre-loaded policy.
 * Useful when the caller already holds the policy (avoids double load).
 */
export function generateLawfulActionMapFromPolicy(
  agentId: string,
  mission: string,
  policy: AgentPolicy,
): LawfulActionMap {
  const ph = hashPolicy(policy);
  const lawful: LawfulEntry[] = [];
  const forbidden: ForbiddenEntry[] = [];
  const gated: HumanGateEntry[] = [];

  for (const def of ACTION_DEFS) {
    const permAllowed = (policy.perm_mask & def.perm_bit) !== 0;

    if (!permAllowed) {
      // perm_mask says no — unconditionally forbidden
      forbidden.push({
        action: def.action,
        description: def.description,
        reason: `perm_mask does not grant ${def.action} (bit 0x${def.perm_bit.toString(16)})`,
      });
      continue;
    }

    // perm allows — now check which resource classes are lawful vs gated
    const gateClasses: string[] = [];
    const allowClasses: string[] = [];

    for (const cls of CLASS_NAMES) {
      if ((policy.class_mask & cls.bit) === 0) continue;  // class not in scope — skip silently (access denied by class_mask)
      if ((def.human_gate_classes & cls.bit) !== 0) {
        gateClasses.push(cls.name);
      } else {
        allowClasses.push(cls.name);
      }
    }

    if (allowClasses.length > 0) {
      lawful.push({
        action: def.action,
        description: def.description,
        resource_classes: allowClasses,
      });
    }

    if (gateClasses.length > 0) {
      gated.push({
        action: def.action,
        description: def.description,
        resource_classes: gateClasses,
        authority_class: def.authority_class,
        reason: `${def.authority_class} action on ${gateClasses.join(", ")} requires human approval`,
      });
    }
  }

  const prompt_injection = buildPromptInjection(agentId, mission, lawful, forbidden, gated, ph);

  return {
    agent_id: agentId,
    mission,
    policy_hash: ph,
    generated_at: new Date().toISOString(),
    rule_ref: "KAV-SHT-001",
    summary: {
      lawful_count: lawful.length,
      forbidden_count: forbidden.length,
      human_gate_count: gated.length,
      default: "deny",
    },
    lawful_actions: lawful,
    forbidden_actions: forbidden,
    human_gate_actions: gated,
    prompt_injection,
  };
}

// ── Prompt injection builder ──────────────────────────────────────────────────

function buildPromptInjection(
  agentId: string,
  mission: string,
  lawful: LawfulEntry[],
  forbidden: ForbiddenEntry[],
  gated: HumanGateEntry[],
  policyHash: string,
): string {
  const lines: string[] = [
    `# AEGIS-Shastra Machine Law (policy_hash: ${policyHash})`,
    `# Agent: ${agentId} | Mission: ${mission}`,
    `# Default: DENY — only actions listed below are lawful.`,
    ``,
    `## LAWFUL — you may plan and execute these actions:`,
  ];

  for (const e of lawful) {
    lines.push(`- ${e.action} on [${e.resource_classes.join(", ")}]`);
  }

  if (forbidden.length > 0) {
    lines.push(``, `## FORBIDDEN — do NOT propose these actions:`);
    for (const e of forbidden) {
      lines.push(`- ${e.action} — ${e.reason}`);
    }
  }

  if (gated.length > 0) {
    lines.push(``, `## HUMAN-GATE — produce an approval packet instead of executing:`);
    for (const e of gated) {
      lines.push(`- ${e.action} on [${e.resource_classes.join(", ")}] — ${e.reason}`);
    }
    lines.push(``, `For human-gate actions: output a JSON approval packet with fields:`,
      `  { "gate_request": true, "action": "...", "resource": "...", "mission": "...", "authority_class": "..." }`);
  }

  lines.push(``, `Rule reference: KAV-SHT-001 / AEGIS-Shastra`);

  return lines.join("\n");
}
