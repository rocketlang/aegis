// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis attest <path...> [--baseline <hex>] [--relative <dir>]
//
// Measure an agent's code/config files into one digest — the "what is running" of attestation. With
// no --baseline it prints the digest (pin this for an approved build). With --baseline it compares and
// exits non-zero on a mismatch (tampered or a different build). This is meant to be run by the
// LAUNCHER over the agent's files before exec — not by the agent about itself (see src/core/attest.ts
// for why self-measurement can lie; hardware/remote attestation is the ceiling).
//
// Exit: 0 digest printed, or matches baseline · 1 does NOT match baseline · 3 no files / broke.

import { measureFiles } from "../../core/attest";

export default async function attest(args: string[]): Promise<void> {
  const flagIdx = (n: string) => args.indexOf(n);
  const baselineI = flagIdx("--baseline");
  const relativeI = flagIdx("--relative");
  const baseline = baselineI >= 0 ? args[baselineI + 1] : null;
  const relative = relativeI >= 0 ? args[relativeI + 1] : undefined;
  const paths = args.filter((a, i) =>
    !a.startsWith("--") && i !== baselineI + 1 && i !== relativeI + 1);

  if (paths.length === 0) {
    process.stderr.write("usage: aegis attest <path...> [--baseline <hex>] [--relative <dir>]\n");
    process.exit(3);
  }

  const m = measureFiles(paths, relative);
  const missing = m.manifest.filter((e) => e.sha256 === "MISSING");
  process.stdout.write(`digest: ${m.digest}\n`);
  process.stdout.write(`files:  ${m.manifest.length}${missing.length ? ` (${missing.length} MISSING)` : ""}\n`);

  if (!baseline) {
    process.stdout.write("note: no --baseline given — pin this digest for the approved build, then pass it as --baseline to attest.\n");
    process.exit(0);
  }
  if (m.digest === baseline) {
    process.stdout.write("ATTESTED — digest matches the pinned baseline.\n");
    process.exit(0);
  }
  process.stderr.write(`REFUSED — digest does not match the baseline (${baseline.slice(0, 12)}…). Tampered code/config, or a different build.\n`);
  process.exit(1);
}
