// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-052 SQL firewall — destructive SQL in request body → ESCALATE
// @rule:KOS-053 PII firewall — bulk PII patterns in request body → DENY + redact
// @rule:KOS-054 EchoLeak response filter — markdown image URL to non-allowlisted domain → REDACT
// @rule:KOS-056 BCC injection — declared To ≠ actual API To params → DENY
// @rule:KOS-075 DPDP §8(5)/§9 PII enforcement — runs after KOS-053, before ALLOW

import { scanDpdp } from "../compliance/dpdp-firewall";

export type FirewallAction = "ALLOW" | "DENY" | "ESCALATE" | "REDACT";

export interface FirewallVerdict {
  action: FirewallAction;
  rule: string;
  detail: string;
  redacted?: string;   // present when action === "REDACT"
}

// ── SQL Escalation (KOS-052) ─────────────────────────────────────────────────

const SQL_ESCALATE: Array<{ re: RegExp; rule: string; detail: string }> = [
  {
    re: /\bDROP\s+TABLE\b/i,
    rule: "KOS-052a",
    detail: "DROP TABLE — table destruction, all rows unrecoverable",
  },
  {
    re: /\bDROP\s+DATABASE\b/i,
    rule: "KOS-052b",
    detail: "DROP DATABASE — full database destroyed, all tables gone",
  },
  {
    re: /\bTRUNCATE\s+TABLE\b/i,
    rule: "KOS-052c",
    detail: "TRUNCATE TABLE — all rows deleted atomically, no rollback",
  },
  {
    re: /\bDELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1/i,
    rule: "KOS-052d",
    detail: "DELETE WHERE 1=1 — unconditional table wipe pattern",
  },
  {
    // DELETE FROM table; or DELETE FROM table -- (no WHERE clause at all)
    re: /\bDELETE\s+FROM\s+\w+\s*(?:--|;)\s*$/im,
    rule: "KOS-052e",
    detail: "DELETE without WHERE — full table wipe",
  },
  {
    re: /\bALTER\s+TABLE\b.*\bDROP\s+COLUMN\b/is,
    rule: "KOS-052f",
    detail: "ALTER TABLE DROP COLUMN — irreversible schema change, column data permanently lost",
  },
];

// ── PII Detection (KOS-053) ──────────────────────────────────────────────────

// Indian PAN: 5 uppercase letters + 4 digits + 1 uppercase letter
const PAN_RE = /\b([A-Z]{5}[0-9]{4}[A-Z])\b/g;
// Aadhaar: 12 digits (may be grouped with spaces or hyphens; first digit 2-9)
const AADHAAR_RE = /\b([2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b/g;
// US SSN: NNN-NN-NNNN (not 000, 666, or 900–999 prefix)
const SSN_RE = /\b((?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4})\b/g;
// Email addresses
const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
const PII_BULK_EMAIL_THRESHOLD = 5;

// ── EchoLeak (KOS-054) ───────────────────────────────────────────────────────

// Matches: ![alt](https://domain.tld/path)
const MD_IMAGE_RE = /!\[[^\]]*\]\((https?:\/\/([^/)\s]+)[^)]*)\)/g;

// Known safe inline image domains (data: URIs are handled separately)
// Anything NOT in this set that appears in LLM response markdown is a leak vector.
// Conservative by design — add legitimate CDN hosts as needed via config.
const SAFE_IMAGE_HOSTS = new Set<string>([
  "cdn.jsdelivr.net",
  "raw.githubusercontent.com",
  "user-images.githubusercontent.com",
  "avatars.githubusercontent.com",
  "shields.io",
]);

// ── BCC Injection (KOS-056) ──────────────────────────────────────────────────

// Detects undisclosed BCC recipients in email API call bodies.
// Pattern: request body contains declared "to" recipients but also hidden "bcc" field.
const BCC_FIELD_RE = /"bcc"\s*:\s*\[/i;
const TO_FIELD_RE = /"to"\s*:\s*\[/i;

// ── Public API ───────────────────────────────────────────────────────────────

// @rule:KOS-052 + KOS-053 + KOS-056
// Check request body before forwarding to upstream LLM API.
export function checkRequestBody(body: string, _domain: string): FirewallVerdict {
  if (!body) return { action: "ALLOW", rule: "none", detail: "empty body" };

  // SQL escalation check (KOS-052)
  for (const { re, rule, detail } of SQL_ESCALATE) {
    if (re.test(body)) {
      return { action: "ESCALATE", rule, detail };
    }
  }

  // BCC injection check (KOS-056) — must have both "to" and "bcc" fields
  if (TO_FIELD_RE.test(body) && BCC_FIELD_RE.test(body)) {
    return {
      action: "DENY",
      rule: "KOS-056",
      detail: "BCC injection detected — request declares To recipients but also contains undisclosed BCC field",
    };
  }

  // PII detection (KOS-053) — collect all matches, deny if bulk threshold exceeded
  const pans = [...body.matchAll(PAN_RE)];
  if (pans.length >= 3) {
    const redacted = body.replace(PAN_RE, "[PAN-REDACTED]");
    return { action: "DENY", rule: "KOS-053a", detail: `PAN detected (${pans.length} occurrences)`, redacted };
  }

  const aadhars = [...body.matchAll(AADHAAR_RE)];
  if (aadhars.length >= 2) {
    const redacted = body.replace(AADHAAR_RE, "[AADHAAR-REDACTED]");
    return { action: "DENY", rule: "KOS-053b", detail: `Aadhaar detected (${aadhars.length} occurrences)`, redacted };
  }

  const ssns = [...body.matchAll(SSN_RE)];
  if (ssns.length >= 2) {
    const redacted = body.replace(SSN_RE, "[SSN-REDACTED]");
    return { action: "DENY", rule: "KOS-053c", detail: `SSN detected (${ssns.length} occurrences)`, redacted };
  }

  const emails = [...body.matchAll(EMAIL_RE)];
  if (emails.length >= PII_BULK_EMAIL_THRESHOLD) {
    const redacted = body.replace(EMAIL_RE, "[EMAIL-REDACTED]");
    return {
      action: "DENY",
      rule: "KOS-053d",
      detail: `Bulk email exfiltration pattern (${emails.length} addresses in single request)`,
      redacted,
    };
  }

  // @rule:KOS-075 DPDP §8(5)/§9 scan — runs after KOS-053, catches DPDP-specific patterns
  const dpdpResult = scanDpdp(body);
  if (!dpdpResult.clean && dpdpResult.violation) {
    const v = dpdpResult.violation;
    return {
      action: v.action,
      rule: `KOS-075-${v.section}`,
      detail: v.detail,
      ...(v.redacted ? { redacted: v.redacted } : {}),
    };
  }

  return { action: "ALLOW", rule: "none", detail: "request body clean" };
}

// @rule:KOS-054 EchoLeak response filter
// Inspect LLM response body for markdown image URLs to non-allowlisted domains.
// Returns REDACT verdict with sanitised body when triggered, else ALLOW.
export function checkResponseBody(body: string, upstreamHost: string): FirewallVerdict {
  if (!body) return { action: "ALLOW", rule: "none", detail: "empty response body" };

  // Extract the actual domain from upstreamHost URL (may be full URL or just host)
  let upstreamDomain = "";
  try {
    upstreamDomain = new URL(upstreamHost).hostname;
  } catch {
    upstreamDomain = upstreamHost;
  }

  // Reset regex state (global regex with exec() maintains state)
  MD_IMAGE_RE.lastIndex = 0;

  const leakMatches: string[] = [];
  let match: RegExpExecArray | null;

  while ((match = MD_IMAGE_RE.exec(body)) !== null) {
    const imgUrl  = match[1];  // full URL
    const imgHost = match[2];  // domain
    if (
      imgHost !== upstreamDomain &&
      !SAFE_IMAGE_HOSTS.has(imgHost) &&
      !imgHost.endsWith("." + upstreamDomain)
    ) {
      leakMatches.push(imgUrl);
    }
  }

  if (leakMatches.length === 0) {
    return { action: "ALLOW", rule: "none", detail: "response body clean" };
  }

  // Redact: replace the offending markdown images with a kavachos notice
  MD_IMAGE_RE.lastIndex = 0;
  const redacted = body.replace(MD_IMAGE_RE, (fullMatch, imgUrl, imgHost) => {
    if (
      imgHost === upstreamDomain ||
      SAFE_IMAGE_HOSTS.has(imgHost) ||
      imgHost.endsWith("." + upstreamDomain)
    ) {
      return fullMatch;
    }
    return `[image redacted by KavachOS KOS-054 — external render-path blocked: ${imgHost}]`;
  });

  return {
    action: "REDACT",
    rule: "KOS-054",
    detail: `EchoLeak: ${leakMatches.length} external image URL(s) in LLM response (${leakMatches.slice(0, 3).join(", ")})`,
    redacted,
  };
}
