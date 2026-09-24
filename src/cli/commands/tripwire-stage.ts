// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis tripwire-stage <principal> [--prior <stage>] [--verified]` — AF-T-605. Gathers a
// principal's tripwire evidence from the ledger and reports the staged containment decision.
// Reports the stage; it does NOT itself throttle/quarantine/revoke (that enforcement is a
// separate wiring step, a founder ruling). `--verified` asserts a human-verified capture — the
// only path to revoke, never inferred. @rule:AFW-011

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { containmentStage, type Stage, STAGE_ORDER } from "../../tripwire/containment";

const LEDGER = join(process.env.HOME || "/root", ".aegis", "tripwire.jsonl");

function evidenceFor(principal: string): { hits: number; distinctKinds: number } {
  let hits = 0;
  const kinds = new Set<string>();
  if (existsSync(LEDGER)) {
    for (const line of readFileSync(LEDGER, "utf-8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const r = JSON.parse(line);
        if (String(r.session) === principal) { hits++; if (r.kind) kinds.add(String(r.kind)); }
      } catch { /* skip */ }
    }
  }
  return { hits, distinctKinds: kinds.size };
}

export default async function tripwireStage(args: string[]): Promise<void> {
  const principal = args.find((a) => !a.startsWith("--"));
  if (!principal) { process.stderr.write("usage: aegis tripwire-stage <principal> [--prior <stage>] [--verified]\n"); process.exit(1); }

  const pi = args.indexOf("--prior");
  const prior = (pi >= 0 && STAGE_ORDER.includes(args[pi + 1] as Stage) ? args[pi + 1] : "watch") as Stage;
  const verifiedCapture = args.includes("--verified");

  const ev = evidenceFor(principal);
  const d = containmentStage({ ...ev, verifiedCapture }, prior);

  process.stdout.write(
    `# Agent Tripwire — containment stage for ${principal}\n\n` +
    `Evidence: ${ev.hits} hit(s), ${ev.distinctKinds} distinct kind(s); prior stage ${prior}${verifiedCapture ? "; VERIFIED CAPTURE asserted" : ""}\n` +
    `**Stage: ${d.stage.toUpperCase()}**${d.heldAtPrior ? " (held — never de-escalates on its own)" : ""}\n` +
    `Reason: ${d.reason}\n` +
    (d.stage === "revoke" ? "" : "\nNote: this reports the stage; enforcing it (throttle/quarantine/revoke) is a separate wiring step behind a founder ruling.\n"),
  );
  process.exit(0);
}
