// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// oracle/brief.ts — Session-Oracle Phase 3 (SOR-T-301 to SOR-T-302)
// Generates a 5-8 line service health brief from baseline + probe data.
// Written to {session_id}.brief.md; latest.brief.md symlink updated atomically.
//
// @rule:SOR-YK-005 brief is the delivery channel from oracle to Claude
// @rule:SOR-YK-006 latest.brief.md symlink is the session-start pickup point

import type { ProbeResult } from "./probe";

export interface BaselineSummary {
  session_id:       string;
  service_key:      string | null;
  detection_method: string;
  detected:         boolean;
  k_mask:           number | null;
  trust_mask:       number | null;
  docs_present:     string[];
  docs_missing:     string[];
}

export function generateBrief(
  baseline: BaselineSummary,
  probe:    ProbeResult | null
): string {
  const lines: string[] = [];
  const key = baseline.service_key ?? "unknown";

  if (!baseline.detected || baseline.k_mask === null) {
    lines.push(`[AEGIS] Service: ${key} | codex not found — check path in services.json`);
    if (baseline.docs_missing.length > 0) {
      lines.push(`[AEGIS] Docs missing: ${baseline.docs_missing.join(", ")}`);
    }
    lines.push(`[AEGIS] Detection method: ${baseline.detection_method}`);
    lines.push(`[AEGIS] Baseline captured — delta will compute on codex creation`);
    return lines.join("\n");
  }

  const kmask  = baseline.k_mask;
  const binary = kmask.toString(2).padStart(8, "0");

  if (baseline.docs_missing.length > 0) {
    lines.push(`[AEGIS] Service: ${key} | k_mask=${kmask} (0b${binary}) — missing: ${baseline.docs_missing.join(", ")}`);
  } else {
    lines.push(`[AEGIS] Service: ${key} | k_mask=${kmask} (0b${binary}) — all 5 docs present`);
  }

  if (probe) {
    if (probe.high_count > 0) {
      lines.push(`[AEGIS] Capability drift: ${probe.high_count} HIGH — run reconfirm before deep work`);
      const highItem = probe.items.find(i => i.severity === "HIGH");
      if (highItem) {
        lines.push(`[AEGIS] Recommendation: resolve overclaim — ${highItem.detail}`);
      }
    } else if (probe.medium_count > 0) {
      lines.push(`[AEGIS] Sync drift: ${probe.medium_count} MEDIUM — can_do/can_answer mismatch with services.json`);
      lines.push(`[AEGIS] Recommendation: sync codex.json ↔ services.json can_do at session close`);
    } else {
      lines.push(`[AEGIS] Service state verified — all k_mask bits confirmed against ground truth`);
    }
  }

  lines.push(`[AEGIS] Baseline captured (method: ${baseline.detection_method}) → delta computed at session close`);

  return lines.join("\n");
}
