// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis tripwire-mode [observe|enforce]` — the sealed containment-mode switch (AF-T-702).
// No argument prints the current mode. Setting writes value + seal together (ANU-007: never
// `echo enforce >` the file). Default and unsealed state are OBSERVE (AFW-006): enforcement
// that arms the valve against live sessions must be a sealed human decision, and a hand edit
// can never conjure it.

import { tripwireMode, writeTripwireMode } from "../../tripwire/enforce";

export default async function tripwireModeCmd(args: string[]): Promise<void> {
  const want = args.find((a) => !a.startsWith("--"));
  if (want && want !== "observe" && want !== "enforce") {
    process.stderr.write("usage: aegis tripwire-mode [observe|enforce]\n");
    process.exit(1);
  }
  if (want === "observe" || want === "enforce") {
    writeTripwireMode(want);
    process.stdout.write(`tripwire containment mode sealed: ${want}\n`);
    if (want === "enforce") {
      process.stdout.write("enforce = a throttle/quarantine/revoke stage now narrows the principal's valve. Rollback: aegis tripwire-mode observe\n");
    }
    process.exit(0);
  }
  const { mode, note } = tripwireMode();
  process.stdout.write(`tripwire containment mode: ${mode}${note ? ` (${note})` : ""}\n`);
  process.exit(0);
}
