// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis quarterly-report [--since 90d] [--out <file.json>] [--prev <file.json>] [--dir <repo>]`
// — AF-T-404, answerability-led (AF-R-012). Gathers what already exists (touched, chain
// rehearsal, destructive posture, shield + exfil faces, ci-audit), composes ONE digest-
// sealed report, and when --prev is given renders the diff a subscriber actually reads.
// Regressions print loudly; the exit code stays 0 — CI gates live in `redteam`/`ci-audit`.

import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { composeQuarterly, diffQuarterly, renderQuarterly, type QuarterlyReport } from "../../redteam/quarterly";
import { aggregateTouched, parseSince } from "../../kavach/touched";
import { runChainRehearsal } from "../../redteam/chain-rehearsal";
import { runRedteam, scorePosture } from "../../redteam/runner";
import { runShieldFace } from "../../redteam/shield-face";
import { runExfilFace } from "../../redteam/exfil-face";
import { auditWorkflowsDir, readCiDeclarations } from "../../kavach/ci-audit";
import { loadShieldRules } from "../../shield/injection-detector";
import type { DestructiveRules } from "../../kavach/destructive-verdict";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const readLines = (p: string): string[] => {
  try { return existsSync(p) ? readFileSync(p, "utf-8").split("\n") : []; } catch { return []; }
};

export default async function quarterlyReport(args: string[]): Promise<void> {
  const flag = (name: string): string | undefined => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };

  const now = Date.now();
  const since = parseSince(flag("--since") ?? "90d", now);
  if (since === null) {
    process.stderr.write("usage: aegis quarterly-report [--since 90d] [--out <file.json>] [--prev <file.json>] [--dir <repo>]\n");
    process.exit(1);
  }

  const rulesPath = join(AEGIS_DIR, "destructive-rules.json");
  if (!existsSync(rulesPath)) {
    process.stderr.write(`[QUARTERLY] live destructive rules not found at ${rulesPath}\n`);
    process.exit(1);
  }
  const destructiveRules = JSON.parse(readFileSync(rulesPath, "utf-8")) as DestructiveRules;
  const shieldRules = loadShieldRules();
  const dir = flag("--dir") ?? process.cwd();

  const redteam = runRedteam(destructiveRules);
  const report = composeQuarterly({
    touched: aggregateTouched(readLines(join(AEGIS_DIR, "anumati.jsonl")), readLines(join(AEGIS_DIR, "tripwire.jsonl")), since, now),
    rehearsal: runChainRehearsal(destructiveRules),
    redteam,
    posture: scorePosture(redteam),
    shield: runShieldFace(shieldRules),
    exfil: runExfilFace(shieldRules),
    ci: auditWorkflowsDir(dir, readCiDeclarations(dir)),
  });

  let diff;
  const prevPath = flag("--prev");
  if (prevPath) {
    try {
      diff = diffQuarterly(JSON.parse(readFileSync(prevPath, "utf-8")) as QuarterlyReport, report);
    } catch (e: any) {
      process.stderr.write(`[QUARTERLY] could not read previous report ${prevPath}: ${e?.message}\n`);
    }
  }

  process.stdout.write(renderQuarterly(report, diff));

  const outPath = flag("--out");
  if (outPath) {
    writeFileSync(outPath, JSON.stringify(report, null, 2));
    process.stdout.write(`\nreport written: ${outPath} (digest ${report.digest.slice(0, 16)}…)\n`);
  }
  process.exit(0);
}
