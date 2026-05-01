// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// RBI Master Direction — IT Framework for NBFC Sector (2017, updated)
// Named policy bundle mapping KAVACH controls to RBI requirements.
//
// @rule:KOS-074 RBI §3.10/§15/§16 as named policy bundle

export interface RbiRequirement {
  section: string;
  title: string;
  requirement: string;
  kavach_control: string;
  implementation_rules: string[];
  status: "implemented" | "partial" | "not_applicable";
  evidence_source: string;
}

export interface RbiBundle {
  standard: "RBI-IT-NBFC-2017";
  generated_at: string;
  requirements: RbiRequirement[];
  overall_coverage_pct: number;
  implemented_count: number;
  partial_count: number;
}

// @rule:KOS-074
export const RBI_REQUIREMENTS: RbiRequirement[] = [
  {
    section: "§3.10",
    title: "Audit Trail",
    requirement:
      "All privileged access, configuration changes, and system events must be logged with tamper-evident audit trails. Logs must be retained for a minimum period and be available for regulatory inspection.",
    kavach_control:
      "PRAMANA SHA-256 receipt chain (kernel-receipt.ts) + kavach_approvals log. " +
      "Every DAN gate event and kernel violation sealed with HMAC-chained receipt. " +
      "S3 Object Lock anchoring provides 7-year tamper-evident retention (KOS-T041).",
    implementation_rules: ["KOS-005", "KOS-012", "KOS-071", "KOS-T041"],
    status: "implemented",
    evidence_source: "Article 15 evidence report (PRAMANA chain) + kavach_approvals table",
  },
  {
    section: "§15",
    title: "Information Security",
    requirement:
      "Implement access controls, least-privilege principles, incident detection and response. " +
      "Privileged actions must require human authorization. Security events must be recorded.",
    kavach_control:
      "perm_mask (32-bit least-privilege) + class_mask (resource class enforcement) + " +
      "DAN gate L1-L4 (human authorization for irreversible actions) + " +
      "Falco anomaly detection + mudrika identity (KOS-060) for per-agent authentication.",
    implementation_rules: ["KAV-061", "KAV-062", "KAV-052", "KOS-060", "KOS-013"],
    status: "implemented",
    evidence_source: "Article 14 evidence report (DAN gate log) + gate-valve audit",
  },
  {
    section: "§16",
    title: "Data Security",
    requirement:
      "Encryption in transit and at rest. PII detection and minimization. " +
      "Data classification with access controls. Secret material must not be exposed to unauthorized systems.",
    kavach_control:
      "PII proxy firewall (KOS-053): blocks/redacts Indian PAN, Aadhaar, SSN, email bulk exfil. " +
      "CLASS_SECRET class_mask bit blocks agent reads of .env/credentials files. " +
      "DPDP §8(5)/§9 enforcement layer (KOS-075). " +
      "mudrika credential stored mode 0o600 — not readable by other agents.",
    implementation_rules: ["KOS-053", "KAV-062", "KOS-075", "KOS-060"],
    status: "implemented",
    evidence_source: "proxy/firewall.ts PII scan + class_mask CLASS_SECRET enforcement",
  },
  {
    section: "§4.1",
    title: "IT Governance",
    requirement:
      "Board-approved IT strategy. Risk ownership defined. IT decisions documented.",
    kavach_control:
      "codex.json capability manifest + LOGICS docs (SHASTRA/YUKTI/VIVEKA) serve as " +
      "machine-readable IT governance documentation. Forja PROOF endpoint provides coverage audit.",
    implementation_rules: ["KOS-072"],
    status: "partial",
    evidence_source: "Article 17 evidence report (codex.json + proof coverage)",
  },
  {
    section: "§11",
    title: "Business Continuity",
    requirement:
      "BCP/DR documented and tested. Recovery time objectives defined. Regular restore drills.",
    kavach_control:
      "Automated weekly restore drills (AEGIS watchdog). Resume manifests written for " +
      "force-closed agents. Panic button (POST /api/kill) for emergency full stop.",
    implementation_rules: ["KAV-019", "KAV-061"],
    status: "partial",
    evidence_source: "watchdog drill logs + resume manifests in ~/.aegis/agents/",
  },
];

// @rule:KOS-074
export function getRbiBundle(): RbiBundle {
  const implemented = RBI_REQUIREMENTS.filter((r) => r.status === "implemented").length;
  const partial = RBI_REQUIREMENTS.filter((r) => r.status === "partial").length;
  const total = RBI_REQUIREMENTS.length;
  const coveragePct = Math.round(((implemented + partial * 0.5) / total) * 100);

  return {
    standard: "RBI-IT-NBFC-2017",
    generated_at: new Date().toISOString(),
    requirements: RBI_REQUIREMENTS,
    overall_coverage_pct: coveragePct,
    implemented_count: implemented,
    partial_count: partial,
  };
}
