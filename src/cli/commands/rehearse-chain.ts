// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis rehearse-chain [--report <out.json>]` — AF-T-711. Walks the RubyGems-class
// incident chain against the live gates' pure decision functions and writes the evidence
// pack the circulation note cites. Exit 1 if any step fails to refuse-or-alert.

import { readFileSync, writeFileSync, existsSync } from "fs";
import { join } from "path";
import { runChainRehearsal, renderChainRehearsal } from "../../redteam/chain-rehearsal";
import type { DestructiveRules } from "../../kavach/destructive-verdict";

export default async function rehearseChain(args: string[]): Promise<void> {
  const rulesPath = join(process.env.HOME || "/root", ".aegis", "destructive-rules.json");
  if (!existsSync(rulesPath)) {
    process.stderr.write(`[REHEARSE] live destructive rules not found at ${rulesPath}\n`);
    process.exit(1);
  }
  const rules = JSON.parse(readFileSync(rulesPath, "utf-8")) as DestructiveRules;

  const report = runChainRehearsal(rules);
  process.stdout.write(renderChainRehearsal(report));

  const ri = args.indexOf("--report");
  if (ri >= 0 && args[ri + 1]) {
    writeFileSync(args[ri + 1], JSON.stringify(report, null, 2));
    process.stdout.write(`\nevidence pack written: ${args[ri + 1]} (digest ${report.digest.slice(0, 16)}…)\n`);
  }
  process.exit(report.all_pass ? 0 : 1);
}
