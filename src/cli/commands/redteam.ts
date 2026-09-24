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

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { runRedteam, renderReport, isClean } from "../../redteam/runner";
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
  const rules = JSON.parse(readFileSync(rulesPath, "utf-8")) as DestructiveRules;
  const report = runRedteam(rules);
  process.stdout.write(renderReport(report));
  process.exit(isClean(report) ? 0 : 1);
}
