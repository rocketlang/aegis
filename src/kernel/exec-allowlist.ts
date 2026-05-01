// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-046 exec allowlist: agent_type → permitted binary paths
// @rule:KOS-047 auto-ALLOW/DENY execve from allowlist — no Telegram escalation (too fast)
// @rule:KOS-048 unknown binary = DENY by default (KOS-046)
// @rule:KOS-049 strict_exec=false → execve stays ALLOW (opt-in, not default)

export interface ExecAllowEntry {
  path: string;      // absolute path or glob prefix (ends with *)
  note: string;
}

export interface ExecAllowlist {
  agent_type: string;
  strict_exec: boolean;
  allow: ExecAllowEntry[];
}

// Resolved binary set — populated at session start by resolveExecAllowlist()
export interface ResolvedExecAllowlist {
  agent_type: string;
  paths: Set<string>;          // exact absolute paths
  prefixes: string[];          // prefix entries (path ends with *)
}

// @rule:KOS-046 declarative per agent_type — never inferred from runtime state
const _CLAUDE_CODE: ExecAllowEntry[] = [
  { path: "/usr/bin/bun",        note: "Bun runtime" },
  { path: "/usr/local/bin/bun",  note: "Bun runtime (local install)" },
  { path: "/root/.bun/bin/bun",  note: "Bun runtime (user install)" },
  { path: "/usr/bin/node",       note: "Node.js" },
  { path: "/usr/local/bin/node", note: "Node.js (local)" },
  { path: "/usr/bin/python3",    note: "Python 3" },
  { path: "/usr/bin/python",     note: "Python 2 compat shim" },
  { path: "/usr/bin/git",        note: "Git" },
  { path: "/usr/bin/sh",         note: "POSIX shell (pipe execution)" },
  { path: "/bin/sh",             note: "POSIX shell (pipe execution)" },
  { path: "/usr/bin/bash",       note: "Bash" },
  { path: "/bin/bash",           note: "Bash" },
  { path: "/usr/bin/cat",        note: "File read utility" },
  { path: "/usr/bin/grep",       note: "Pattern search" },
  { path: "/usr/bin/find",       note: "File search" },
  { path: "/usr/bin/sed",        note: "Stream edit" },
  { path: "/usr/bin/awk",        note: "Text processing" },
  { path: "/usr/bin/jq",         note: "JSON processing" },
  { path: "/usr/bin/curl",       note: "HTTP client" },
  { path: "/usr/bin/ls",         note: "Directory listing" },
  { path: "/bin/ls",             note: "Directory listing" },
];

const AGENT_ALLOWLISTS: Record<string, ExecAllowEntry[]> = {
  "claude-code": _CLAUDE_CODE,

  "maritime": [
    ..._CLAUDE_CODE,
    { path: "/usr/bin/gpsd",           note: "GNSS daemon" },
    { path: "/usr/local/bin/gpsd",     note: "GNSS daemon (local)" },
    { path: "/usr/bin/modpoll",        note: "Modbus poll tool" },
    { path: "/usr/local/bin/modpoll",  note: "Modbus poll tool (local)" },
    { path: "/usr/bin/ais-decoder",    note: "AIS message decoder" },
  ],

  "logistics": [..._CLAUDE_CODE],

  "ot": [
    { path: "/usr/bin/python3",        note: "Python 3 (OT scripts)" },
    { path: "/usr/local/bin/python3",  note: "Python 3 (local)" },
    { path: "/usr/bin/modpoll",        note: "Modbus poll" },
    { path: "/usr/local/bin/modpoll",  note: "Modbus poll (local)" },
    { path: "/usr/bin/sh",             note: "POSIX shell" },
    { path: "/bin/sh",                 note: "POSIX shell" },
  ],

  "finance": [..._CLAUDE_CODE],
};

// @rule:KOS-046 entry point — build typed allowlist for a given agent_type
export function buildExecAllowlist(agentType: string, strictExec = false): ExecAllowlist {
  const allow = AGENT_ALLOWLISTS[agentType] ?? AGENT_ALLOWLISTS["claude-code"];
  return { agent_type: agentType, strict_exec: strictExec, allow };
}

// @rule:KOS-047 resolve allowlist to Set<string> for O(1) lookup
export function resolveExecAllowlist(allowlist: ExecAllowlist): ResolvedExecAllowlist {
  const paths = new Set<string>();
  const prefixes: string[] = [];

  for (const entry of allowlist.allow) {
    if (entry.path.endsWith("*")) {
      prefixes.push(entry.path.slice(0, -1));
    } else {
      paths.add(entry.path);
    }
  }

  return { agent_type: allowlist.agent_type, paths, prefixes };
}

// @rule:KOS-048 deny unknown binary — no default-open
export function isExecAllowed(resolved: ResolvedExecAllowlist, binaryPath: string): boolean {
  if (resolved.paths.has(binaryPath)) return true;
  return resolved.prefixes.some((p) => binaryPath.startsWith(p));
}

export function serialiseExecAllowlist(allowlist: ExecAllowlist): string {
  return JSON.stringify(allowlist, null, 2);
}
