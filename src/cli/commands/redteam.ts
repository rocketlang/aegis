// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis redteam` — run the destructive-gate robustness harness against the SAME rules the
// live hook loads, print the report, and exit non-zero if any gap or false positive is
// found so CI can gate on it. Reads only; runs nothing. @rule:RT-002

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { runRedteam, renderReport } from "../../redteam/runner";
import type { DestructiveRules } from "../../kavach/destructive-verdict";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const RULES_PATH = join(AEGIS_DIR, "destructive-rules.json");

export default async function redteam(_args: string[]): Promise<void> {
  if (!existsSync(RULES_PATH)) {
    process.stderr.write(`[REDTEAM] destructive-rules.json not found at ${RULES_PATH}\n`);
    process.exit(1);
  }
  const rules = JSON.parse(readFileSync(RULES_PATH, "utf-8")) as DestructiveRules;
  const report = runRedteam(rules);
  process.stdout.write(renderReport(report));
  // A gap (a dangerous variant not refused) or a false positive is a failure worth a red CI.
  process.exit(report.gaps.length === 0 && report.falsePositives.length === 0 ? 0 : 1);
}
