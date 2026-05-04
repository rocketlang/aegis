// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Provenance Enforcement — AEG-PROV-001
//
// Enforces that hard-gate promotions run against committed source code.
// A promotion may only proceed if:
//   (a) the target service's source repo is clean (no uncommitted changes), OR
//   (b) the promotion artifact carries an explicit DirtyTreeWaiver.
//
// Derived from the carbonx source-control gap discovered post-Batch 74.
// Documented in: aegis/audits/batch75a_carbonx_source_control_provenance_repair.json
//
// @rule:AEG-PROV-001 no hard-gate promotion may rely on uncommitted source changes
//   unless the promotion artifact explicitly records a dirty-tree waiver.

import { execSync } from "child_process";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DirtyTreeWaiver {
  reason: string;
  authorized_by: string;
  waiver_id: string;
  acknowledged_risk: string; // explicit acknowledgment — must not be blank
}

export interface ProvenanceResult {
  rule: "AEG-PROV-001";
  repo_path: string;
  source_tree_clean: boolean;
  uncommitted_files: string[];
  waiver: DirtyTreeWaiver | null;
  waiver_applied: boolean;
  promotion_permitted: boolean;
  checked_at: string;
}

export class ProvenanceError extends Error {
  readonly rule = "AEG-PROV-001";
  readonly uncommitted_files: string[];
  constructor(repoPath: string, files: string[]) {
    super(
      `AEG-PROV-001: promotion blocked — ${files.length} uncommitted file(s) in ${repoPath}. ` +
      `Commit all changes or supply an explicit DirtyTreeWaiver.`,
    );
    this.name = "ProvenanceError";
    this.uncommitted_files = files;
  }
}

// ── Implementation ────────────────────────────────────────────────────────────

function gitStatus(repoPath: string): string[] {
  try {
    const out = execSync("git status --porcelain", {
      cwd: repoPath,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return out.trim().split("\n").filter(Boolean);
  } catch {
    return [`ERROR: could not run git status in ${repoPath}`];
  }
}

/**
 * Inspect the source repo and return a ProvenanceResult.
 * Never throws — suitable for logging/reporting.
 */
export function checkSourceTree(repoPath: string): ProvenanceResult {
  const uncommitted = gitStatus(repoPath);
  return {
    rule: "AEG-PROV-001",
    repo_path: repoPath,
    source_tree_clean: uncommitted.length === 0,
    uncommitted_files: uncommitted,
    waiver: null,
    waiver_applied: false,
    promotion_permitted: uncommitted.length === 0,
    checked_at: new Date().toISOString(),
  };
}

/**
 * Assert clean source tree before promotion. Throws ProvenanceError
 * if the tree is dirty and no waiver is supplied.
 *
 * @rule:AEG-PROV-001
 *
 * Usage:
 *   const prov = assertCleanSourceTree("/root/apps/my-service");
 *   // or with waiver:
 *   const prov = assertCleanSourceTree("/root/apps/my-service", {
 *     reason: "hotfix committed to branch but not merged yet",
 *     authorized_by: "founder",
 *     waiver_id: "waiver-2026-05-05-001",
 *     acknowledged_risk: "audited by Batch 75A pattern; will repair post-promotion",
 *   });
 *
 * The returned ProvenanceResult must be embedded in the promotion audit artifact.
 */
export function assertCleanSourceTree(
  repoPath: string,
  waiver?: DirtyTreeWaiver,
): ProvenanceResult {
  const result = checkSourceTree(repoPath);

  if (result.source_tree_clean) {
    return { ...result, promotion_permitted: true };
  }

  // Dirty tree
  if (!waiver) {
    throw new ProvenanceError(repoPath, result.uncommitted_files);
  }

  if (!waiver.reason || !waiver.authorized_by || !waiver.acknowledged_risk) {
    throw new ProvenanceError(repoPath, result.uncommitted_files);
  }

  // Waiver is valid — record it and permit
  return {
    ...result,
    waiver,
    waiver_applied: true,
    promotion_permitted: true,
  };
}

/**
 * Validate that a ProvenanceResult embedded in an audit artifact is well-formed.
 * Use in convergence audits to verify promotion artifacts contain provenance evidence.
 */
export function validateProvenanceArtifact(
  artifact: Record<string, unknown>,
): { valid: boolean; reason: string } {
  const prov = artifact.provenance as Record<string, unknown> | undefined;
  if (!prov) {
    return { valid: false, reason: "no provenance field in artifact" };
  }
  if (prov.rule !== "AEG-PROV-001") {
    return { valid: false, reason: "provenance.rule is not AEG-PROV-001" };
  }
  if (typeof prov.promotion_permitted !== "boolean") {
    return { valid: false, reason: "provenance.promotion_permitted missing" };
  }
  if (!prov.promotion_permitted) {
    return { valid: false, reason: "provenance.promotion_permitted=false — promotion was blocked" };
  }
  if (!prov.source_tree_clean && !prov.waiver_applied) {
    return { valid: false, reason: "dirty tree with no recorded waiver — AEG-PROV-001 violation" };
  }
  return { valid: true, reason: "provenance field is well-formed and permitted" };
}
