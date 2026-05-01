// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// EU AI Act Article 17 — Quality Management System evidence collector
// Article 17 requires: technical documentation proving the system was designed and
// built according to its stated purpose with a quality management system.
// Forja PROOF coverage + codex.json capability manifest = Article 17 documentation.
//
// @rule:KOS-072 Article 17: Forja PROOF export + codex.json manifest as QMS artifact

import { readFileSync, existsSync } from "fs";
import { join } from "path";

export interface Article17Evidence {
  article: "17";
  title: "Quality Management System";
  effective_date: "2026-08-02";
  generated_at: string;
  proof_coverage: ProofCoverage;
  capability_manifest: CapabilityManifest;
  logics_docs: string[];
  compliant: boolean;
  compliance_note: string;
}

export interface ProofCoverage {
  rule_count: number;
  annotation_style: string;
  proof_coverage_pct: number;
  annotation_sweep_status: string;
  logics_docs: string[];
  source: "codex.json";
}

export interface CapabilityManifest {
  service: string;
  version: string;
  can_answer: string[];
  can_do: string[];
  capability_audit_summary: Record<string, "built" | "partial" | "planned" | "unknown">;
  trust_mask: number;
  claw_mask: number;
  claude_ankr_mask: number;
  k_mask: number;
  forja_endpoints: string[];
  source: "codex.json";
}

// @rule:KOS-072
export function collectArticle17Evidence(): Article17Evidence {
  // codex.json is the single source of truth for capability and proof state
  const codexPaths = [
    join(process.cwd(), "codex.json"),
    join(__dirname, "../../..", "codex.json"),   // /root/aegis/codex.json
    "/root/aegis/codex.json",
  ];

  let codex: Record<string, unknown> = {};
  for (const p of codexPaths) {
    if (existsSync(p)) {
      try { codex = JSON.parse(readFileSync(p, "utf-8")); break; } catch {}
    }
  }

  const proofConfig = (codex.proof_config as Record<string, unknown>) ?? {};
  const capAudit = (codex.capability_audit as Record<string, unknown>) ?? {};

  // Summarise capability_audit — built / partial / planned / unknown
  const auditSummary: Record<string, "built" | "partial" | "planned" | "unknown"> = {};
  for (const [key, val] of Object.entries(capAudit)) {
    if (typeof val === "string") {
      if (val.startsWith("✅")) auditSummary[key] = "built";
      else if (val.includes("partial") || val.startsWith("🔶")) auditSummary[key] = "partial";
      else if (val.includes("planned") || val.startsWith("❌")) auditSummary[key] = "planned";
      else auditSummary[key] = "unknown";
    } else if (typeof val === "object" && val !== null) {
      const status = (val as Record<string, string>).status;
      auditSummary[key] = (status === "built" || status === "partial" || status === "planned") ? status : "unknown";
    }
  }

  const builtCount = Object.values(auditSummary).filter((s) => s === "built").length;
  const totalCount = Object.keys(auditSummary).length;
  const proofCoveragePct = Number(proofConfig.proof_coverage ?? proofConfig.coverage_pct ?? 0);
  const logicsDocs = (proofConfig.logics_docs as string[] | undefined) ?? [];

  const proof: ProofCoverage = {
    rule_count: Number(proofConfig.rule_count ?? proofConfig.rules_seeded ?? 0),
    annotation_style: (proofConfig.annotation_style as string) ?? "@rule:KOS-NNN",
    proof_coverage_pct: proofCoveragePct,
    annotation_sweep_status: (proofConfig.annotation_sweep_status as string) ?? "unknown",
    logics_docs: logicsDocs,
    source: "codex.json",
  };

  const manifest: CapabilityManifest = {
    service: (codex.service_key as string) ?? (codex.service as string) ?? "ankr-aegis",
    version: (codex.version as string) ?? "unknown",
    can_answer: (codex.can_answer as string[]) ?? [],
    can_do: (codex.can_do as string[]) ?? [],
    capability_audit_summary: auditSummary,
    trust_mask: Number(codex.trust_mask ?? 0),
    claw_mask: Number(codex.claw_mask ?? 0),
    claude_ankr_mask: Number(codex.claude_ankr_mask ?? 0),
    k_mask: Number(codex.k_mask ?? 0),
    forja_endpoints: [
      codex.forja_state, codex.forja_trust, codex.forja_sense, codex.forja_proof,
    ].filter(Boolean) as string[],
    source: "codex.json",
  };

  // Compliant if: proof coverage ≥ 80% AND at least 80% of capabilities are "built"
  const capCoverage = totalCount > 0 ? Math.round((builtCount / totalCount) * 100) : 0;
  const compliant = proofCoveragePct >= 80 && (totalCount === 0 || capCoverage >= 80);

  return {
    article: "17",
    title: "Quality Management System",
    effective_date: "2026-08-02",
    generated_at: new Date().toISOString(),
    proof_coverage: proof,
    capability_manifest: manifest,
    logics_docs: logicsDocs,
    compliant,
    compliance_note: compliant
      ? `PROOF coverage ${proofCoveragePct}% ≥ 80%. ${builtCount}/${totalCount} capabilities built. QMS documented.`
      : `PROOF coverage ${proofCoveragePct}% or capability build rate ${capCoverage}% below 80% threshold.`,
  };
}
