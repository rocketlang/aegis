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
import { existsSync } from "fs";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DirtyTreeWaiver {
  reason: string;
  authorized_by: string;
  waiver_id: string;
  acknowledged_risk: string; // explicit acknowledgment — must not be blank
}

// Multi-repo waiver — richer than DirtyTreeWaiver; includes approver + expiry
export interface RepoWaiver {
  reason: string;
  approver: string;          // name/role of the human authorising the waiver
  expiry: string;            // ISO date — waiver is void after this date
  waiver_id: string;
  acknowledged_risk: string;
}

export interface RepoSpec {
  name: string;
  path: string;
  required_commits?: string[];    // commit hashes that must appear in repo history
  allowed_dirty_paths?: string[]; // only these paths are permitted to be dirty
  waiver?: RepoWaiver;
}

export interface RepoProvenanceResult {
  name: string;
  path: string;
  exists: boolean;
  head: string;               // HEAD commit hash at check time
  clean: boolean;
  dirty_files: string[];
  waiver: RepoWaiver | null;
  waiver_applied: boolean;
  required_commits_present: boolean;
}

export interface SourceControlProvenance {
  rule: "AEG-PROV-001";
  verified: boolean;
  batch: number | string;
  service_id: string;
  repos: RepoProvenanceResult[];
  dirty_tree_waiver_used: boolean;
  promotion_permitted: boolean;
  source_control_provenance_failed: boolean;
  checked_at: string;
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
 * Accepts both the single-repo `provenance` field and the multi-repo
 * `source_control_provenance` field.
 */
export function validateProvenanceArtifact(
  artifact: Record<string, unknown>,
): { valid: boolean; reason: string } {
  // Multi-repo format (Batch 78+)
  const scp = artifact.source_control_provenance as Record<string, unknown> | undefined;
  if (scp) {
    if (scp.rule !== "AEG-PROV-001") {
      return { valid: false, reason: "source_control_provenance.rule is not AEG-PROV-001" };
    }
    if (!scp.verified) {
      return { valid: false, reason: "source_control_provenance.verified=false" };
    }
    if (!scp.promotion_permitted) {
      return { valid: false, reason: "source_control_provenance.promotion_permitted=false" };
    }
    if (scp.source_control_provenance_failed) {
      return { valid: false, reason: "source_control_provenance_failed=true — promotion blocked" };
    }
    return { valid: true, reason: "source_control_provenance field is well-formed (multi-repo)" };
  }

  // Legacy single-repo format (Batch 77 and earlier)
  const prov = artifact.provenance as Record<string, unknown> | undefined;
  if (!prov) {
    return { valid: false, reason: "no provenance or source_control_provenance field in artifact" };
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
  return { valid: true, reason: "provenance field is well-formed (single-repo)" };
}

// ── Multi-repo provenance (Batch 78+) ─────────────────────────────────────────

function gitHead(repoPath: string): string {
  try {
    return execSync("git rev-parse HEAD", {
      cwd: repoPath,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return "ERROR";
  }
}

function gitCommitInHistory(repoPath: string, sha: string): boolean {
  try {
    const result = execSync(`git log --format="%H"`, {
      cwd: repoPath,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return result.split("\n").some(h => h.trim().startsWith(sha));
  } catch {
    return false;
  }
}

/**
 * Multi-repo provenance check for promotion scripts (Batch 78+).
 *
 * Checks all repos in the promotion scope. Throws ProvenanceError if any
 * repo is dirty without a waiver. Returns a SourceControlProvenance block
 * to embed under `source_control_provenance` in the promotion artifact.
 *
 * @rule:AEG-PROV-001
 *
 * Usage in a promotion script:
 *   const scp = assertSourceControlProvenance({
 *     repos: [
 *       { name: "aegis",    path: "/root/aegis" },
 *       { name: "my-svc",  path: "/root/apps/my-svc" },
 *     ],
 *     batch: 79,
 *     service_id: "my-svc",
 *   });
 *   // Embed in artifact: source_control_provenance: scp
 */
export function assertSourceControlProvenance({
  repos,
  batch,
  service_id,
}: {
  repos: RepoSpec[];
  batch: number | string;
  service_id: string;
}): SourceControlProvenance {
  const results: RepoProvenanceResult[] = [];
  const dirtyWithoutWaiver: string[] = [];
  let anyWaiverUsed = false;

  for (const spec of repos) {
    if (!existsSync(spec.path)) {
      results.push({
        name: spec.name,
        path: spec.path,
        exists: false,
        head: "NOT_FOUND",
        clean: false,
        dirty_files: [`ERROR: repo not found at ${spec.path}`],
        waiver: null,
        waiver_applied: false,
        required_commits_present: false,
      });
      dirtyWithoutWaiver.push(spec.path);
      continue;
    }

    const head = gitHead(spec.path);
    const allDirty = gitStatus(spec.path);

    // If allowed_dirty_paths supplied, only files outside those prefixes matter
    const effectiveDirty = spec.allowed_dirty_paths
      ? allDirty.filter(line =>
          !spec.allowed_dirty_paths!.some(p => line.includes(p)))
      : allDirty;

    const isClean = effectiveDirty.length === 0;

    // Check required commits
    const requiredCommitsPresent = !spec.required_commits ||
      spec.required_commits.every(sha => gitCommitInHistory(spec.path, sha));

    if (!isClean && !spec.waiver) {
      dirtyWithoutWaiver.push(`${spec.name} (${spec.path})`);
    }
    if (!isClean && spec.waiver) {
      anyWaiverUsed = true;
    }

    results.push({
      name: spec.name,
      path: spec.path,
      exists: true,
      head,
      clean: isClean,
      dirty_files: effectiveDirty,
      waiver: spec.waiver ?? null,
      waiver_applied: !isClean && !!spec.waiver,
      required_commits_present: requiredCommitsPresent,
    });
  }

  if (dirtyWithoutWaiver.length > 0) {
    const allDirtyFiles = results
      .filter(r => !r.clean && !r.waiver_applied)
      .flatMap(r => r.dirty_files);
    throw new ProvenanceError(dirtyWithoutWaiver.join(", "), allDirtyFiles);
  }

  return {
    rule: "AEG-PROV-001",
    verified: true,
    batch,
    service_id,
    repos: results,
    dirty_tree_waiver_used: anyWaiverUsed,
    promotion_permitted: true,
    source_control_provenance_failed: false,
    checked_at: new Date().toISOString(),
  };
}
