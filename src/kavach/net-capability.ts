// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — network capability-over-target (AF-T-704, ANU-I-007, AFW-YK-002).
//
// The ANU-I-006 shape applied to egress: (network-capable invocation) ∧ ¬(target
// declared) ⇒ judge on the resolved host's class. This is the COOPERATIVE-face twin of
// the kernel egress allowlist (KOS-042): the kernel binds jailed agents by IP; this
// binds hook-governed sessions by NAME, from the same declarations, before the socket
// ever opens. It is the control whose absence the RubyGems-class incident describes —
// an agent crawling/exfiltrating to hosts nobody declared.
//
// CEILING (state it, never round up): this reads the COMMAND TEXT. A network call made
// from inside an interpreter (`python -c "urllib..."`, a script file, a compiled tool)
// is invisible here — that traffic belongs to the kernel face. A client set is listed,
// not inferred; an unlisted client is a gap to add, not a proof of safety.

import { buildEgressPolicy } from "../kernel/egress-policy";

// Clients whose presence makes a command network-capable. Documented set (RT-001-style:
// the label is authored, not guessed by the gate under test).
const NET_CLIENTS =
  /\b(curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|telnet)\b/;

// git subcommands that talk to a remote. `git commit`/`status` are local and never match.
const GIT_REMOTE = /\bgit\s+(?:-C\s+\S+\s+)?(clone|fetch|pull|push|remote\s+update|ls-remote)\b/;

export function isNetworkCapableInvocation(command: string): boolean {
  return NET_CLIENTS.test(command) || GIT_REMOTE.test(command);
}

/**
 * Hosts a command names. Deliberately conservative: only shapes whose host position is
 * unambiguous. `null` in the list means "a network target exists but cannot be resolved
 * from the text" (e.g. `curl "$URL"`) — UNKNOWN, never waved past (ANU-004).
 */
export function resolveTargetHosts(command: string): (string | null)[] {
  const hosts = new Set<string>();
  let sawUnresolvable = false;

  // scheme://host[:port]/...  (http, https, ftp, git, ssh)
  for (const m of command.matchAll(/\b(?:https?|ftp|git|ssh):\/\/(?:[^\s\/@'"]*@)?([A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\])(?::\d+)?/g)) {
    hosts.add(m[1].replace(/^\[|\]$/g, ""));
  }
  // ssh/sftp: the first non-flag argument is the host
  for (const m of command.matchAll(/\b(?:ssh|sftp)\s+(?:-\S+\s+)*(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9][A-Za-z0-9._-]*)/g)) {
    hosts.add(m[1]);
  }
  // scp/rsync: the remote is whichever argument carries `[user@]host:path` (`:` not `://`)
  if (/\b(?:scp|rsync)\b/.test(command)) {
    for (const m of command.matchAll(/(?:^|[\s='"])(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9][A-Za-z0-9._-]*):(?!\/\/)/g)) {
      hosts.add(m[1]);
    }
  }
  // nc/ncat/netcat host port
  for (const m of command.matchAll(/\b(?:nc|ncat|netcat)\s+(?:-\S+\s+)*([A-Za-z0-9][A-Za-z0-9._-]*)\s+\d+/g)) {
    hosts.add(m[1]);
  }

  // A network client invoked with a variable/quoted-expansion target: the capability is
  // present, the target is not in the text.
  if (isNetworkCapableInvocation(command) && hosts.size === 0) sawUnresolvable = true;
  if (/\b(?:curl|wget)\b[^|&;]*\$\{?[A-Z_]/.test(command)) sawUnresolvable = true;

  const out: (string | null)[] = [...hosts];
  if (sawUnresolvable) out.push(null);
  return out;
}

export type HostClass = "loopback" | "private" | "declared" | "undeclared";

// The trusted internal suffixes this box serves — cooperative-face extension of the
// kernel declarations (which are exact FQDNs for jailed agents). A suffix here means
// "ours": first-party surface, not the open internet.
const TRUSTED_SUFFIXES = ["ankr.in", "mari8x.com", "xshieldai.com", "digimitra.guru", "ankrlabs.org", "ankrforge.in", "ankr.digital"];

/** The declared hostname universe for the cooperative face: kernel policy names + our suffixes. */
export function declaredHosts(): { exact: Set<string>; suffixes: string[] } {
  const exact = new Set<string>();
  // Same declarations the kernel compiles from (general domain, registered-services bit set
  // so localhost entries are present). Names only — the cooperative face judges names.
  for (const e of buildEgressPolicy(1 << 6, "general").allow) exact.add(e.host.toLowerCase());
  return { exact, suffixes: TRUSTED_SUFFIXES };
}

const PRIVATE_IP = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;

export function classifyHost(host: string, declared = declaredHosts()): HostClass {
  const h = host.toLowerCase();
  if (h === "localhost" || h === "127.0.0.1" || h === "::1" || h.startsWith("127.")) return "loopback";
  if (PRIVATE_IP.test(h)) return "private";
  if (declared.exact.has(h)) return "declared";
  if (declared.suffixes.some((s) => h === s || h.endsWith("." + s))) return "declared";
  return "undeclared";
}

export interface NetVerdict {
  verdict: "PERMIT" | "REFUSE" | "UNKNOWN";
  detail: string;
  source: string;
  stage?: "enforce" | "observe";
}

/**
 * The ANU-I-007 decision, pure and injectable. Ships FULLY OBSERVE (AFW-006): unlike
 * ANU-I-006 there is no branch with a positive low-FP identification yet — sessions
 * legitimately curl hosts nobody has declared (docs, APIs under evaluation), so every
 * branch collects shadow evidence first. Promotion is graded later on ledger data,
 * exactly the AF-R-005 procedure. @rule:AFW-YK-002 @rule:AFW-006
 */
export function netTargetVerdict(command: string, declared = declaredHosts()): NetVerdict {
  const src = "command text + egress declarations (kernel policy names + trusted suffixes)";
  const targets = resolveTargetHosts(command);
  if (targets.length === 0) {
    return { verdict: "PERMIT", detail: "no network target named", source: src, stage: "observe" };
  }

  const undeclared = targets.filter((t): t is string => t !== null && classifyHost(t, declared) === "undeclared");
  const unresolvable = targets.includes(null);

  if (undeclared.length > 0) {
    return {
      verdict: "REFUSE",
      detail: `network-capable invocation names undeclared external host(s): ${undeclared.join(", ")} — not in the egress declarations`,
      source: src,
      stage: "observe",
    };
  }
  if (unresolvable) {
    return {
      verdict: "UNKNOWN",
      detail: "network-capable invocation whose target host cannot be resolved from the command text",
      source: src,
      stage: "observe",
    };
  }
  return { verdict: "PERMIT", detail: `all named hosts are loopback/private/declared`, source: src, stage: "observe" };
}
