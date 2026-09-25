// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis redteam [--rules <path>] [--target <dir>]` — run the destructive-gate robustness
// harness against a rule set, print the posture score + report, and exit non-zero iff a
// CATCHABLE gap or a false positive exists (regex-ceiling gaps are reported but never fail,
// being a documented limit, not a regression). Reads only; runs nothing. @rule:RT-002
//
//   --rules <path>   score one ruleset file (default: this box's live rules).
//   --target <dir>   AF-T-201: score a BUYER's setup — discover their destructive ruleset
//                    inside <dir> at the conventional locations. This is the buyer-facing form.

import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { runRedteam, renderReport, isClean } from "../../redteam/runner";
import { buildAttackReport } from "../../redteam/report";
import { BENIGN_CORPUS } from "../../redteam/benign-corpus";
import { runShieldFace, renderShieldFace, shieldFaceClean } from "../../redteam/shield-face";
import { loadShieldRules } from "../../shield/injection-detector";
import type { DestructiveRules } from "../../kavach/destructive-verdict";

/** Conventional locations a destructive ruleset lives at, relative to a target directory. */
const TARGET_RULE_LOCATIONS = [
  "destructive-rules.json",
  ".aegis/destructive-rules.json",
  "rules/destructive-rules.json",
];

export function discoverRuleset(targetDir: string): string | null {
  for (const rel of TARGET_RULE_LOCATIONS) {
    const p = join(targetDir, rel);
    if (existsSync(p)) return p;
  }
  return null;
}

export default async function redteam(args: string[]): Promise<void> {
  // AF-T-301 — the shield face (injection + persistence). `--face shield` runs it against the
  // live shield rules; a miss or a robustness gap fails, benign over-flags are reported.
  const faceFlag = args.indexOf("--face");
  if (faceFlag >= 0 && args[faceFlag + 1] === "shield") {
    const report = runShieldFace(loadShieldRules());
    process.stdout.write(renderShieldFace(report));
    process.exit(shieldFaceClean(report) ? 0 : 1);
  }
  // AF-T-706 — the exfil face (credential-read + exfil-sequence), driven through the pure
  // decision fns; a miss or a scenario mismatch fails, benign over-flags are reported.
  if (faceFlag >= 0 && args[faceFlag + 1] === "exfil") {
    const { runExfilFace, renderExfilFace, exfilFaceClean } = await import("../../redteam/exfil-face");
    const report = runExfilFace(loadShieldRules());
    process.stdout.write(renderExfilFace(report));
    process.exit(exfilFaceClean(report) ? 0 : 1);
  }

  const targetFlag = args.indexOf("--target");
  const rulesFlag = args.indexOf("--rules");

  let rulesPath: string | null;
  if (targetFlag >= 0 && args[targetFlag + 1]) {
    const dir = args[targetFlag + 1];
    rulesPath = discoverRuleset(dir);
    if (!rulesPath) {
      process.stderr.write(
        `[REDTEAM] no destructive ruleset found under ${dir} (looked for ${TARGET_RULE_LOCATIONS.join(", ")})\n`,
      );
      process.exit(1);
    }
    process.stderr.write(`[REDTEAM] scoring target ${dir} — ruleset ${rulesPath}\n`);
  } else {
    rulesPath = rulesFlag >= 0 && args[rulesFlag + 1]
      ? args[rulesFlag + 1]
      : join(process.env.HOME || "/root", ".aegis", "destructive-rules.json");
  }

  if (!existsSync(rulesPath)) {
    process.stderr.write(`[REDTEAM] destructive-rules.json not found at ${rulesPath}\n`);
    process.exit(1);
  }
  const rulesetContent = readFileSync(rulesPath, "utf-8");
  const rules = JSON.parse(rulesetContent) as DestructiveRules;

  // AF-T-204 — precision corpus: a buyer's own command log (observed) if given, else the
  // built-in representative set. One command per line for a supplied file; blanks/#-comments
  // are still commands here (a comment executes nothing — a good gate must permit it).
  const bcFlag = args.indexOf("--benign-corpus");
  let precisionCorpus = BENIGN_CORPUS.map((b) => ({ cmd: b.cmd, category: b.category }));
  let precisionSource: "representative" | "observed" = "representative";
  if (bcFlag >= 0 && args[bcFlag + 1]) {
    const lines = readFileSync(args[bcFlag + 1], "utf-8").split("\n").map((l) => l.trimEnd()).filter((l) => l.length);
    precisionCorpus = lines.map((cmd) => ({ cmd, category: "observed" }));
    precisionSource = "observed";
  }

  const report = runRedteam(rules, { precisionCorpus, precisionSource });
  process.stdout.write(renderReport(report));

  // AF-T-203 — write the content-addressed report artifact when asked.
  const reportFlag = args.indexOf("--report");
  if (reportFlag >= 0 && args[reportFlag + 1]) {
    const target = targetFlag >= 0 && args[targetFlag + 1] ? args[targetFlag + 1] : rulesPath;
    const artifact = buildAttackReport(report, { target, rulesetContent });
    writeFileSync(args[reportFlag + 1], JSON.stringify(artifact, null, 2));
    process.stderr.write(`[REDTEAM] report written → ${args[reportFlag + 1]} (digest ${artifact.digest.slice(0, 16)}…)\n`);
  }

  process.exit(isClean(report) ? 0 : 1);
}
