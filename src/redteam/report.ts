// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AF-T-203 — the attack-report artifact: the deliverable a posture scan hands back (and, on a
// schedule, what a quarterly subscription sends, AF-T-404). It is machine-readable JSON with
// provenance: the sha256 of the exact ruleset scored, and a content digest over the whole
// report so any later edit is detectable by re-hashing (the PRAMANA discipline — confirm by
// re-reading the bytes). This is tamper-EVIDENCE, not a cryptographic signature: an Ed25519
// signature belongs to the hosted ledger (AF-T-403), and calling a bare hash "signed" would
// overclaim. Pure; the caller supplies the ruleset text and the report.

import { createHash } from "crypto";
import type { RedteamReport, Gap, FalsePositive, PostureScore } from "./runner";
import { scorePosture } from "./runner";

export const ATTACK_REPORT_SCHEMA = "ankr-agent-firewall-attack-report-v1";

export interface AttackReport {
  schema: typeof ATTACK_REPORT_SCHEMA;
  generatedAt: string;
  target: string;
  rulesetSha256: string;
  posture: PostureScore;
  summary: {
    dangerousTried: number;
    catchableGaps: number;
    ceilingGaps: number;
    controlsTried: number;
    falsePositives: number;
    catchableAsr: number;
    fpr: number;
  };
  catchableGaps: Gap[];
  ceilingGaps: Gap[];
  falsePositives: FalsePositive[];
  /** sha256 over the canonical form of every field above — recompute to detect any edit. */
  digest: string;
}

/** Deterministic JSON: object keys sorted at every level, so the digest is reproducible. */
function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + stable(o[k])).join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export function buildAttackReport(
  report: RedteamReport,
  opts: { target: string; rulesetContent: string; now?: Date },
): AttackReport {
  const body: Omit<AttackReport, "digest"> = {
    schema: ATTACK_REPORT_SCHEMA,
    generatedAt: (opts.now ?? new Date()).toISOString(),
    target: opts.target,
    rulesetSha256: sha256(opts.rulesetContent),
    posture: scorePosture(report),
    summary: {
      dangerousTried: report.dangerousTried,
      catchableGaps: report.catchableGaps.length,
      ceilingGaps: report.ceilingGaps.length,
      controlsTried: report.controlsTried,
      falsePositives: report.falsePositives.length,
      catchableAsr: report.catchableAsr,
      fpr: report.fpr,
    },
    catchableGaps: report.catchableGaps,
    ceilingGaps: report.ceilingGaps,
    falsePositives: report.falsePositives,
  };
  return { ...body, digest: sha256(stable(body)) };
}

/** Recompute the digest over everything but `digest` and compare — a mismatch means the
 *  report was edited after it was produced. */
export function verifyAttackReport(r: AttackReport): { intact: boolean; recomputed: string } {
  const { digest, ...body } = r;
  const recomputed = sha256(stable(body));
  return { intact: recomputed === digest, recomputed };
}
