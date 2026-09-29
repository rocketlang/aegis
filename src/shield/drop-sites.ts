// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS — drop-site vocabulary (AF-T-709).
//
// Hosts whose PURPOSE is to accept an anonymous upload and hand back a link, or to capture
// an inbound request for someone else to read: paste bins, file drops, request catchers,
// out-of-band callback domains. An agent naming one of these is a POSITIVE identification
// of the exfil sink — the low-false-positive branch AFW-006 was waiting for, so the
// ANU-I-007 drop-site branch ENFORCES while the general undeclared-host branch observes.
//
// Direction is not inferred: fetching FROM a paste bin (a staged payload) is refused too.
//
// CEILING (state it, never round up): this is a LIST. A sink not listed here falls back to
// the general undeclared-host branch (observe + warn), and a host resolved at runtime
// (`curl "$URL"`, a script file) is invisible to a command-text check — that traffic
// belongs to the kernel egress face. An unlisted sink is a gap to add, not proof of safety.
// @rule:AFW-YK-002 @rule:FP-018

/** Registrable domains. A host matches the entry itself or any subdomain of it. */
export const DROP_SITES: readonly string[] = [
  // paste bins
  "paste.ee", "pastebin.com", "hastebin.com", "hastebin.skyra.pw", "dpaste.org", "dpaste.com",
  "paste.rs", "ix.io", "sprunge.us", "termbin.com", "clbin.com", "ghostbin.co", "rentry.co",
  "justpaste.it", "controlc.com", "privatebin.net", "pastes.io", "paste.mozilla.org",
  // anonymous file drops
  "transfer.sh", "0x0.st", "file.io", "catbox.moe", "gofile.io", "bashupload.com",
  "oshi.at", "tmpfiles.org", "filebin.net", "temp.sh", "uguu.se", "pixeldrain.com",
  // request catchers / out-of-band callbacks
  "webhook.site", "requestbin.net", "requestcatcher.com", "pipedream.net", "beeceptor.com",
  "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me",
  "burpcollaborator.net", "oastify.com", "canarytokens.com", "dnslog.cn",
];

export function isDropSite(host: string, sites: readonly string[] = DROP_SITES): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return sites.some((s) => h === s || h.endsWith("." + s));
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Every drop-site host named anywhere in the text — with or without a scheme (`ix.io`,
 * `curl -T f transfer.sh/f`, `requests.post('https://paste.ee/api')`). Label-boundary
 * anchored: `notpaste.ee.example` and `mypaste.ee` do not match.
 */
export function dropSitesNamed(text: string, sites: readonly string[] = DROP_SITES): string[] {
  if (!sites.length) return [];
  const alt = sites.map(escapeRe).join("|");
  const re = new RegExp(`(?<![A-Za-z0-9-])((?:[A-Za-z0-9-]+\\.)*(?:${alt}))(?![A-Za-z0-9-]|\\.[A-Za-z0-9])`, "gi");
  const out = new Set<string>();
  for (const m of text.matchAll(re)) out.add(m[1].toLowerCase());
  return [...out];
}
