// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Sandbox — Policy Enforcers
// Four enforcers: path scope, tool allowlist, bash command, DB scope.
// Deny-first precedence throughout (KAV-006).
// @rule:KAV-006 Path scope enforcement — deny-first
// @rule:KAV-007 Tool and Bash command allowlist
// @rule:KAV-005 DB scope enforcement
// @rule:KAV-YK-004 Bash first-token extraction

import type { AgentPolicy } from "./policy-schema";

export interface EnforcementResult {
  allowed: boolean;
  reason: string;
  rule: string;
}

const PASS: EnforcementResult = { allowed: true, reason: "", rule: "" };

// ────────────────────────────────────────────────────────────
// Path scope enforcer (V2-024)
// ────────────────────────────────────────────────────────────

export function enforcePathScope(policy: AgentPolicy, filePath: string): EnforcementResult {
  const normalized = filePath.replace(/\/+/g, "/");

  // Deny list checked first (deny-first per KAV-006)
  for (const denied of policy.path_deny) {
    if (normalized.startsWith(denied) || normalized.includes(denied)) {
      return { allowed: false, reason: `Path "${filePath}" is in path_deny list (prefix: ${denied})`, rule: "KAV-006" };
    }
  }

  // If allowlist is empty → all paths allowed (minus deny list above)
  if (policy.path_scope.length === 0) return PASS;

  // Allowlist non-empty → path must match at least one prefix
  for (const allowed of policy.path_scope) {
    if (normalized.startsWith(allowed) || normalized.includes(allowed)) return PASS;
  }

  return { allowed: false, reason: `Path "${filePath}" is outside agent's path_scope`, rule: "KAV-006" };
}

// ────────────────────────────────────────────────────────────
// Tool allowlist enforcer (V2-025)
// ────────────────────────────────────────────────────────────

export function enforceToolAllowlist(policy: AgentPolicy, toolName: string): EnforcementResult {
  // Check deny list first
  if (policy.tools_denied.includes(toolName)) {
    return { allowed: false, reason: `Tool "${toolName}" is in tools_denied`, rule: "KAV-007" };
  }

  // If allowlist is empty → all tools allowed
  if (policy.tools_allowed.length === 0) return PASS;

  // Allowlist non-empty → tool must be in list
  if (policy.tools_allowed.includes(toolName)) return PASS;

  return { allowed: false, reason: `Tool "${toolName}" is not in tools_allowed`, rule: "KAV-007" };
}

// ────────────────────────────────────────────────────────────
// Bash command enforcer (V2-026)
// ────────────────────────────────────────────────────────────

export function enforceBashCommand(policy: AgentPolicy, command: string): EnforcementResult {
  const firstToken = extractFirstToken(command);
  if (!firstToken) return PASS;

  // Denylist checked first
  for (const denied of policy.bash_denylist) {
    if (firstToken === denied || firstToken.startsWith(denied + " ") || command.trimStart().startsWith(denied)) {
      return { allowed: false, reason: `Bash command "${firstToken}" is in bash_denylist`, rule: "KAV-007" };
    }
  }

  // Network check
  const NETWORK_COMMANDS = ["curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync", "ftp"];
  if (!policy.network_allowed && NETWORK_COMMANDS.includes(firstToken)) {
    return { allowed: false, reason: `Network command "${firstToken}" blocked (network_allowed: false)`, rule: "KAV-007" };
  }

  // If allowlist is empty → all commands allowed (after denylist check)
  if (policy.bash_allowlist.length === 0) return PASS;

  // Allowlist non-empty → command must be in list (default-deny per KAV-YK-004)
  for (const allowed of policy.bash_allowlist) {
    if (firstToken === allowed || command.trimStart().startsWith(allowed + " ") || command.trimStart().startsWith(allowed + "\n")) {
      return PASS;
    }
  }

  return { allowed: false, reason: `Bash command "${firstToken}" is not in bash_allowlist`, rule: "KAV-007" };
}

// ────────────────────────────────────────────────────────────
// DB scope enforcer (V2-027)
// ────────────────────────────────────────────────────────────

export function enforceDbScope(policy: AgentPolicy, command: string): EnforcementResult {
  if (policy.db_scope.length === 0) return PASS; // unrestricted

  const dbName = extractDbName(command);
  if (!dbName) return PASS; // can't detect a DB operation — allow

  if (policy.db_scope.includes(dbName)) return PASS;

  return { allowed: false, reason: `Database "${dbName}" is not in agent's db_scope`, rule: "KAV-005" };
}

// ────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────

function extractFirstToken(command: string): string {
  const trimmed = command.trimStart();
  // Handle env prefix: VAR=val cmd → cmd
  const envPrefixStripped = trimmed.replace(/^([A-Z_]+=\S+\s+)+/, "");
  // Handle sudo/env/nice wrappers
  const afterWrappers = envPrefixStripped.replace(/^(sudo|env|nice|ionice|time)\s+/, "");
  const token = afterWrappers.split(/\s+/)[0];
  // Strip path prefix (e.g. /usr/bin/curl → curl)
  return token?.split("/").pop() ?? "";
}

function extractDbName(command: string): string | null {
  // psql --dbname=foo | psql -d foo | psql foo | pg_dump foo
  const patterns = [
    /--dbname[=\s]+(\S+)/,
    /-d\s+(\S+)/,
    /\bpsql\s+(?:\S+\s+)*(\w+)\s*$/,
    /\bpg_dump\s+(\w+)/,
    /\bpg_restore\s+.*-d\s+(\S+)/,
  ];
  for (const pat of patterns) {
    const m = command.match(pat);
    if (m) return m[1].replace(/["']/g, "");
  }
  return null;
}
