// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS — typed credential markers (AF-T-709).
//
// A bare "credential present: true" cannot tell a destination's OWN auth token (every call to
// a paste API carries one) from a third-party secret being carried out. So each marker is
// TYPED and carries a short hash — never the value — so two sightings can be matched without
// the ledger itself becoming a secret store:
//
//   third-party-secret  a value with a known provider shape (sk-ant-, ghp_, AKIA, PEM, …)
//   destination-auth    an unshaped value in an auth position (-H "X-Auth-Token: …", -u, Bearer)
//   credential-path     the command itself names a credential file (.env, id_rsa, .aws/credentials)
//
// CEILING: shapes are a LIST; an unshaped secret outside an auth position is invisible, and a
// secret read at runtime (`$(cat .env)`) is seen only as the credential-path it names.
// @rule:FP-018 @rule:KAV-020

import { createHash } from "crypto";

export type CredentialKind = "third-party-secret" | "destination-auth" | "credential-path";

export interface CredentialMarker {
  kind: CredentialKind;
  rule: string;
  /** first 12 hex of sha256(value) — correlates sightings, never reveals the value */
  hash12: string;
}

const SHAPES: ReadonlyArray<{ id: string; re: RegExp }> = [
  { id: "CM-ANTHROPIC", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { id: "CM-OPENAI", re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { id: "CM-GITHUB", re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/g },
  { id: "CM-AWS", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "CM-SLACK", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { id: "CM-GOOGLE", re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { id: "CM-GROQ", re: /\bgsk_[A-Za-z0-9]{20,}/g },
  { id: "CM-HF", re: /\bhf_[A-Za-z0-9]{30,}/g },
  { id: "CM-STRIPE", re: /\b[rs]k_live_[A-Za-z0-9]{20,}/g },
  { id: "CM-JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  // the whole block (to END, or to end of text), so redaction removes the body, not just the header
  { id: "CM-PEM", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
];

// Auth positions — the value group is what a destination would read as its own credential.
const AUTH_POSITIONS: ReadonlyArray<{ id: string; re: RegExp }> = [
  { id: "CM-AUTH-HEADER", re: /(?:x-auth-token|x-api-key|api-key|authorization)\s*:\s*(?:bearer\s+|token\s+|basic\s+)?([^\s'"]{6,})/gi },
  { id: "CM-AUTH-USER", re: /(?:^|\s)(?:-u|--user)\s+['"]?([^\s'"]+:[^\s'"]+)/g },
  { id: "CM-AUTH-QUERY", re: /[?&](?:api_?key|key|token|access_token)=([^\s&'"]{6,})/gi },
];

// Credential files named in the command text — basename-anchored, so `.env.example` and
// `envelope.ts` do not match (the Read-path detector's substring over-flag is not repeated).
const CRED_FILES = /(?:^|[\s/'"=<@(])(\.env(?:\.(?:local|prod|production|development|dev|staging))?|id_(?:rsa|ed25519|ecdsa|dsa)|\.aws\/credentials|\.npmrc|\.pypirc|\.netrc|\.git-credentials|credentials\.json|service-account[\w-]*\.json)(?=$|[\s'")|;&>])/g;

const hash12 = (v: string) => createHash("sha256").update(v).digest("hex").slice(0, 12);

export function credentialMarkers(text: string): CredentialMarker[] {
  const out: CredentialMarker[] = [];
  const seen = new Set<string>();
  const add = (kind: CredentialKind, rule: string, value: string) => {
    const h = hash12(value);
    const k = `${kind}:${h}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ kind, rule, hash12: h });
  };
  const shapedValues = new Set<string>();
  for (const s of SHAPES) {
    for (const m of text.matchAll(s.re)) { shapedValues.add(m[0]); add("third-party-secret", s.id, m[0]); }
  }
  for (const p of AUTH_POSITIONS) {
    for (const m of text.matchAll(p.re)) {
      const v = m[1];
      // A provider-shaped value in an auth header is still that provider's secret.
      if ([...shapedValues].some((s) => v.includes(s))) continue;
      if (/^\$\{?[A-Za-z_]/.test(v)) continue; // env-var reference, not a literal
      add("destination-auth", p.id, v);
    }
  }
  for (const m of text.matchAll(CRED_FILES)) add("credential-path", "CM-CRED-FILE", m[1]);
  return out;
}

/** "third-party-secret(CM-AWS #1a2b3c4d5e6f), credential-path(CM-CRED-FILE #…)" — for details/ledger. */
export function renderMarkers(markers: CredentialMarker[]): string {
  return markers.map((m) => `${m.kind}(${m.rule} #${m.hash12})`).join(", ");
}

/**
 * Replace every shaped secret and auth-position value with `[REDACTED:<rule>:#<hash12>]`.
 * Applied before a command is written to a ledger or echoed in a reason: a refusal must not
 * copy the key it just stopped into a plaintext file (a fix relocates trust — name where).
 */
export function redactSecrets(text: string): string {
  let t = text;
  for (const s of SHAPES) t = t.replace(s.re, (v) => `[REDACTED:${s.id}:#${hash12(v)}]`);
  for (const p of AUTH_POSITIONS) {
    t = t.replace(p.re, (whole, v: string) =>
      v.startsWith("[REDACTED:") || /^\$\{?[A-Za-z_]/.test(v) ? whole : whole.replace(v, `[REDACTED:${p.id}:#${hash12(v)}]`));
  }
  return t;
}
