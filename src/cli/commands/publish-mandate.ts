// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis publish-mandate grant <artifact> --reason "..." [--ttl-hours N]` | `list` | `revoke <artifact>`
// — the named consent behind the publish gate (AF-T-707, AFW-012). A mandate names WHAT may
// be published (exact name, `prefix*`, or `*`), why, by whom, and until when (default 24h —
// a mandate is a window, never a standing power). The only sanctioned writer of
// publish-mandates.json (which is a PROTECTED source — ANU-I-005 refuses hand edits).

import { readMandates, writeMandates, PUBLISH_MANDATES_FILE, type PublishMandate } from "../../kavach/publish-capability";

export default async function publishMandate(args: string[]): Promise<void> {
  const sub = args[0];

  if (sub === "list") {
    const live = readMandates();
    if (!live.length) { process.stdout.write("no live publish mandates\n"); process.exit(0); }
    for (const m of live) {
      process.stdout.write(`${m.artifact} — by ${m.granted_by}, "${m.reason}", expires ${m.expires_at}\n`);
    }
    process.exit(0);
  }

  if (sub === "grant") {
    const artifact = args[1];
    const ri = args.indexOf("--reason");
    const reason = ri >= 0 ? args[ri + 1] : undefined;
    if (!artifact || artifact.startsWith("--") || !reason) {
      process.stderr.write('usage: aegis publish-mandate grant <artifact|prefix*|*> --reason "..." [--ttl-hours N]\n');
      process.exit(1);
    }
    const ti = args.indexOf("--ttl-hours");
    const ttlH = ti >= 0 ? Number(args[ti + 1]) : 24;
    if (!Number.isFinite(ttlH) || ttlH <= 0 || ttlH > 24 * 14) {
      process.stderr.write("--ttl-hours must be a number in (0, 336] — a mandate is a window, never a standing power\n");
      process.exit(1);
    }
    const now = Date.now();
    const mandate: PublishMandate = {
      artifact,
      reason,
      granted_by: process.env.USER || "human",
      granted_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttlH * 3600e3).toISOString(),
    };
    // readMandates() drops the expired, so a grant also compacts the file.
    writeMandates([...readMandates(now).filter((m) => m.artifact !== artifact), mandate]);
    process.stdout.write(`mandate granted: ${artifact} until ${mandate.expires_at} (${PUBLISH_MANDATES_FILE})\n`);
    if (artifact === "*") process.stdout.write("NOTE: '*' permits ANY artifact while live — prefer naming the artifact.\n");
    process.exit(0);
  }

  if (sub === "revoke") {
    const artifact = args[1];
    if (!artifact) { process.stderr.write("usage: aegis publish-mandate revoke <artifact>\n"); process.exit(1); }
    const live = readMandates();
    const kept = live.filter((m) => m.artifact !== artifact);
    if (kept.length === live.length) { process.stderr.write(`no live mandate named ${artifact}\n`); process.exit(1); }
    writeMandates(kept);
    process.stdout.write(`mandate revoked: ${artifact}\n`);
    process.exit(0);
  }

  process.stderr.write("usage: aegis publish-mandate grant|list|revoke\n");
  process.exit(1);
}
