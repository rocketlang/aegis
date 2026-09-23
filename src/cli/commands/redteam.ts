// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis redteam [--rules <path>]` — run the destructive-gate robustness harness against a
// rule set, print the report, and exit non-zero iff a CATCHABLE gap or a false positive
// exists (regex-ceiling gaps are reported but never fail, being a documented limit, not a
// regression). Defaults to the live rules; --rules points CI at a committed fixture so the
// check is hermetic. Reads only; runs nothing. @rule:RT-002

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { runRedteam, renderReport, isClean } from "../../redteam/runner";
import type { DestructiveRules } from "../../kavach/destructive-verdict";

export default async function redteam(args: string[]): Promise<void> {
  const flag = args.indexOf("--rules");
  const rulesPath = flag >= 0 && args[flag + 1]
    ? args[flag + 1]
    : join(process.env.HOME || "/root", ".aegis", "destructive-rules.json");

  if (!existsSync(rulesPath)) {
    process.stderr.write(`[REDTEAM] destructive-rules.json not found at ${rulesPath}\n`);
    process.exit(1);
  }
  const rules = JSON.parse(readFileSync(rulesPath, "utf-8")) as DestructiveRules;
  const report = runRedteam(rules);
  process.stdout.write(renderReport(report));
  process.exit(isClean(report) ? 0 : 1);
}
