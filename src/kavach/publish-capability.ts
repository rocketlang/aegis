// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — publish capability-over-mandate (AF-T-707, AFW-012, ANU-I-010).
//
// AFW-012: an outward write (package publish, release push, registry upload) is a GATED
// CAPABILITY, never a side effect. It requires a declared mandate — a named consent a
// human granted ahead of time (`aegis publish-mandate grant <artifact> --reason ...`) —
// and it leaves a provenance record linking artifact, principal, and mandate. This is the
// malicious-package step of the RubyGems-class chain: nothing on this box publishes to a
// registry because an agent decided to.
//
// Ships OBSERVE (AFW-006). The designed flow once enforced: a founder-directed publish is
// preceded by one grant command; everything else refuses. UNKNOWN artifact refuses
// (ANU-004) unless a wildcard mandate is live.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
export const PUBLISH_MANDATES_FILE = join(AEGIS_DIR, "publish-mandates.json");

// The outward-write verbs, a documented set (RT-001-style — authored, not inferred).
// `git push` belongs to the egress face; `npm install` is inbound; neither is here.
const PUBLISH_FORMS: { re: RegExp; kind: string }[] = [
  { re: /\b(?:npm|yarn|pnpm|bun)\s+publish\b/, kind: "npm-package" },
  { re: /\bgem\s+push\b/, kind: "gem" },
  { re: /\b(?:twine|python3?\s+-m\s+twine)\s+upload\b/, kind: "pypi" },
  { re: /\bcargo\s+publish\b/, kind: "crate" },
  { re: /\bdocker\s+push\b/, kind: "docker-image" },
  { re: /\bgh\s+release\s+(?:create|upload)\b/, kind: "gh-release" },
];

export function isPublishInvocation(command: string): { publish: boolean; kind: string | null } {
  for (const f of PUBLISH_FORMS) if (f.re.test(command)) return { publish: true, kind: f.kind };
  return { publish: false, kind: null };
}

/**
 * Best-effort artifact name from the command text. null = "a publish, but the artifact is
 * not in the text" (cwd-implicit npm publish, env-var tag) — judged UNKNOWN unless a
 * wildcard mandate is live (ANU-004: unknown never defaults to permission).
 */
export function resolvePublishArtifact(command: string): string | null {
  let m = /\bdocker\s+push\s+(['"]?)([^\s'"]+)\1/.exec(command);
  if (m) return m[2];
  m = /\bgem\s+push\s+(['"]?)([^\s'"]+\.gem)\1/.exec(command);
  if (m) return m[2];
  m = /\bgh\s+release\s+(?:create|upload)\s+(['"]?)([^\s'"]+)\1/.exec(command);
  if (m) return m[2];
  // npm/yarn/pnpm/bun publish <folder-or-tarball> (no arg = cwd, unresolvable from text)
  m = /\b(?:npm|yarn|pnpm|bun)\s+publish\s+(['"]?)([^\s'"-][^\s'"]*)\1/.exec(command);
  if (m) return m[2];
  return null;
}

export interface PublishMandate {
  artifact: string;      // exact name, a prefix ending in '*', or '*' (any)
  reason: string;
  granted_by: string;
  granted_at: string;
  expires_at: string;    // ISO — a mandate is always bounded in time
}

export function readMandates(now = Date.now()): PublishMandate[] {
  try {
    if (!existsSync(PUBLISH_MANDATES_FILE)) return [];
    const all = JSON.parse(readFileSync(PUBLISH_MANDATES_FILE, "utf-8")) as PublishMandate[];
    return all.filter((m) => Date.parse(m.expires_at) > now);
  } catch {
    return []; // an unreadable mandate file grants nothing (ANU-004)
  }
}

export function writeMandates(mandates: PublishMandate[]): void {
  mkdirSync(AEGIS_DIR, { recursive: true });
  writeFileSync(PUBLISH_MANDATES_FILE, JSON.stringify(mandates, null, 2));
}

export function mandateFor(artifact: string | null, mandates: PublishMandate[]): PublishMandate | null {
  for (const m of mandates) {
    if (m.artifact === "*") return m;
    if (artifact === null) continue;
    if (m.artifact.endsWith("*") ? artifact.startsWith(m.artifact.slice(0, -1)) : artifact === m.artifact) return m;
  }
  return null;
}

export interface PublishVerdict {
  verdict: "PERMIT" | "REFUSE" | "UNKNOWN";
  detail: string;
  source: string;
  stage?: "enforce" | "observe";
}

/** The ANU-I-010 decision, pure over the mandate snapshot. @rule:AFW-012 @rule:AFW-006 */
export function publishVerdict(command: string, mandates: PublishMandate[]): PublishVerdict {
  const src = "command text + publish-mandates.json";
  const { kind } = isPublishInvocation(command);
  const artifact = resolvePublishArtifact(command);
  const mandate = mandateFor(artifact, mandates);

  if (mandate) {
    return {
      verdict: "PERMIT",
      detail:
        `publish (${kind}) of ${artifact ?? "cwd-implicit artifact"} under mandate ` +
        `"${mandate.artifact}" granted by ${mandate.granted_by} (${mandate.reason}; expires ${mandate.expires_at})`,
      source: src,
      stage: "observe",
    };
  }
  if (artifact === null) {
    return {
      verdict: "UNKNOWN",
      detail: `publish (${kind}) whose artifact cannot be resolved from the command text and no wildcard mandate is live — grant one: aegis publish-mandate grant '<name>' --reason "..."`,
      source: src,
      stage: "observe",
    };
  }
  return {
    verdict: "REFUSE",
    detail: `publish (${kind}) of ${artifact} with NO live mandate — an outward write is a gated capability, never a side effect (AFW-012). Grant: aegis publish-mandate grant '${artifact}' --reason "..."`,
    source: src,
    stage: "observe",
  };
}
