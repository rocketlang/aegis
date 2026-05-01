// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// DPDP — Digital Personal Data Protection Act 2023 (India)
// §8(5): Data fiduciaries must implement technical measures to ensure data accuracy
//        and prevent unauthorised processing.
// §9:    Special provisions — children's personal data must not be processed without
//        verifiable parental consent; profiling of children is prohibited.
//
// This module adds DPDP rule tags to PII firewall violations and extends
// the proxy firewall with §9 children's data detection.
//
// @rule:KOS-075 DPDP §8(5)/§9 PII enforcement in Tier-1 proxy firewall

export type DpdpSection = "§8(5)" | "§9";

export interface DpdpViolation {
  section: DpdpSection;
  title: string;
  pattern_matched: string;
  action: "DENY" | "REDACT";
  rule_ref: "KOS-075";
  detail: string;
  redacted?: string;
}

export interface DpdpScanResult {
  violation: DpdpViolation | null;
  clean: boolean;
}

// ── §8(5) — General PII (extends proxy/firewall.ts patterns with DPDP tags) ─

// Indian PAN — §8(5) data accuracy + unauthorised processing
const PAN_RE = /\b([A-Z]{5}[0-9]{4}[A-Z])\b/g;
// Aadhaar — §8(5) + Aadhaar Act §29 additional protection
const AADHAAR_RE = /\b([2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b/g;
// Passport number (Indian) — G/H/J/K/L/M/N/P + 7 digits
const PASSPORT_RE = /\b([GHJKLMNP][0-9]{7})\b/g;
// Mobile (Indian) — 10 digits starting 6-9
const MOBILE_RE = /\b([6-9][0-9]{9})\b/g;

// ── §9 — Children's data ──────────────────────────────────────────────────────

// "minor", "child", "under 18", "age < 18", DOB combined with PII context
// These are heuristics — a full §9 system requires semantic understanding.
// We flag the presence of child-context keywords alongside PII as a §9 risk signal.
const CHILD_CONTEXT_RE =
  /\b(minor|child|under.18|age.?[<≤].?18|date.of.birth|dob|born.in|juvenile|underage)\b/i;

// Device/behavioural tracking of children (§9 profiling prohibition)
const CHILD_PROFILING_RE =
  /\b(screen.time|app.usage|location.history|behaviour.profile|interest.profile)\b/i;

// ── Scanner ───────────────────────────────────────────────────────────────────

// @rule:KOS-075
export function scanDpdp(body: string): DpdpScanResult {
  // §9 — children's profiling (highest priority)
  if (CHILD_CONTEXT_RE.test(body) && CHILD_PROFILING_RE.test(body)) {
    return {
      violation: {
        section: "§9",
        title: "Children's personal data — profiling prohibited",
        pattern_matched: "child-context + behavioural-tracking co-occurrence",
        action: "DENY",
        rule_ref: "KOS-075",
        detail:
          "DPDP §9: profiling or tracking of minors is prohibited without verifiable parental consent. " +
          "Request body contains both child-context keywords and behavioural tracking patterns.",
      },
      clean: false,
    };
  }

  // §8(5) — PAN bulk exposure
  const pans = [...body.matchAll(PAN_RE)];
  if (pans.length >= 2) {
    const redacted = body.replace(PAN_RE, "[PAN-§8(5)-REDACTED]");
    return {
      violation: {
        section: "§8(5)",
        title: "PAN data — unauthorised processing prevention",
        pattern_matched: "Indian PAN number",
        action: "DENY",
        rule_ref: "KOS-075",
        detail: `DPDP §8(5): ${pans.length} PAN numbers detected. Bulk PAN exposure is an unauthorised processing risk.`,
        redacted,
      },
      clean: false,
    };
  }

  // §8(5) — Aadhaar exposure (single instance is already a violation)
  const aadhars = [...body.matchAll(AADHAAR_RE)];
  if (aadhars.length >= 1) {
    const redacted = body.replace(AADHAAR_RE, "[AADHAAR-§8(5)-REDACTED]");
    return {
      violation: {
        section: "§8(5)",
        title: "Aadhaar — sensitive personal data",
        pattern_matched: "Aadhaar number (12-digit)",
        action: "DENY",
        rule_ref: "KOS-075",
        detail: `DPDP §8(5) + Aadhaar Act §29: ${aadhars.length} Aadhaar number(s) detected. Any Aadhaar exposure without explicit consent is prohibited.`,
        redacted,
      },
      clean: false,
    };
  }

  // §8(5) — Passport bulk exposure
  const passports = [...body.matchAll(PASSPORT_RE)];
  if (passports.length >= 2) {
    const redacted = body.replace(PASSPORT_RE, "[PASSPORT-§8(5)-REDACTED]");
    return {
      violation: {
        section: "§8(5)",
        title: "Passport data — sensitive personal data",
        pattern_matched: "Indian passport number",
        action: "REDACT",
        rule_ref: "KOS-075",
        detail: `DPDP §8(5): ${passports.length} passport numbers detected. Redacted to prevent unauthorised processing.`,
        redacted,
      },
      clean: false,
    };
  }

  return { violation: null, clean: true };
}

// DPDP compliance status for the report
export interface DpdpComplianceStatus {
  standard: "DPDP-2023";
  sections_covered: DpdpSection[];
  pii_firewall_active: boolean;
  children_data_protection: boolean;
  note: string;
}

export function getDpdpStatus(): DpdpComplianceStatus {
  return {
    standard: "DPDP-2023",
    sections_covered: ["§8(5)", "§9"],
    pii_firewall_active: true,
    children_data_protection: true,
    note:
      "§8(5): PAN, Aadhaar, Passport patterns active in Tier-1 proxy firewall. " +
      "§9: Child-context + behavioural-tracking co-occurrence detection active. " +
      "Full §9 compliance requires semantic consent verification — heuristic detection only at this layer.",
  };
}
