// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis anumati-review [--ledger <path>] [--min-days N]` — the AF-R-002 revisit tool. Reads
// the shadow ledger and reports whether the ANU-I-006 UNKNOWN branch has enough real evidence
// to weigh promoting it to enforce. Reads only; decides nothing. @rule:AFW-006

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { reviewAnumatiLedger, renderLedgerReview } from "../../kavach/anumati-ledger-review";

export default async function anumatiReview(args: string[]): Promise<void> {
  const lf = args.indexOf("--ledger");
  const ledger = lf >= 0 && args[lf + 1] ? args[lf + 1] : join(process.env.HOME || "/root", ".aegis", "anumati.jsonl");
  const mf = args.indexOf("--min-days");
  const minDays = mf >= 0 && args[mf + 1] ? Number(args[mf + 1]) : 7;

  if (!existsSync(ledger)) {
    process.stdout.write(`# ANU-I-006 UNKNOWN-branch review\n\nNo ledger at ${ledger} — nothing observed yet. KEEP_OBSERVING.\n`);
    process.exit(0);
  }
  const lines = readFileSync(ledger, "utf-8").split("\n");
  const review = reviewAnumatiLedger(lines, { minDays });
  process.stdout.write(renderLedgerReview(review));
  // Exit 0 always — this is a report, not a gate. The recommendation is on stdout.
  process.exit(0);
}
