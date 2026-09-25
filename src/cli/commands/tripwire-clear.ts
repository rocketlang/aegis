// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis tripwire-clear <principal> --reason "..."` — the HUMAN de-escalation path (AF-T-702).
// The ladder never walks back on its own (AFW-011); this records a clear, after which only
// tripwire evidence NEWER than the clear counts toward the principal's stage. It does not
// reopen a CLOSED/LOCKED valve — that stays with `aegis quarantine release` (KAV-066): clearing
// the evidence and releasing the actuator are two decisions, deliberately not one command.

import { writeClear, stageFor } from "../../tripwire/enforce";

export default async function tripwireClear(args: string[]): Promise<void> {
  const principal = args.find((a) => !a.startsWith("--"));
  const ri = args.indexOf("--reason");
  const reason = ri >= 0 ? args[ri + 1] : undefined;
  if (!principal || !reason) {
    process.stderr.write('usage: aegis tripwire-clear <principal> --reason "why the evidence is judged benign"\n');
    process.exit(1);
  }

  const before = stageFor(principal);
  writeClear(principal, process.env.USER || "human", reason);
  const after = stageFor(principal);

  process.stdout.write(
    `# Tripwire clear — ${principal}\n\n` +
    `Stage before: ${before.decision.stage} (${before.hits} hit(s), ${before.distinctKinds} kind(s))\n` +
    `Stage after:  ${after.decision.stage} — only evidence newer than this clear now counts\n` +
    `Reason recorded: ${reason}\n\n` +
    `Note: a CLOSED/LOCKED valve is NOT reopened by a clear — release it explicitly if intended.\n`,
  );
  process.exit(0);
}
