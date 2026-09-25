// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis touched [--since 24h|7d|<ISO>] [--json]` — the answerability report (AF-T-709,
// AFW-YK-009). One command over the ledgers: per principal, what was refused, what the
// staged invariants observed, what was published (provenance), what tripwires saw, and
// whether each active principal's kernel receipt chain still verifies.
//
// CEILING, printed every time (PRA-004): the host computes this about itself — same-host
// evidence survives a lying agent, not a compromised host. And an empty row means nothing
// LEDGERED, not nothing happened: the ledgers see tool-route + tripwire-visible activity.

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { aggregateTouched, parseSince, type TouchedReport } from "../../kavach/touched";

const AEGIS_DIR = join(process.env.HOME || "/root", ".aegis");
const readLines = (p: string): string[] => {
  try { return existsSync(p) ? readFileSync(p, "utf-8").split("\n") : []; } catch { return []; }
};

async function receiptChain(principal: string): Promise<string> {
  try {
    const { verifyReceiptChain } = await import("../../kernel/merkle-ledger");
    const v = verifyReceiptChain(principal) as { valid?: boolean; receipt_count?: number; broken_at?: string | null };
    if ((v.receipt_count ?? 0) === 0) return "no kernel receipts";
    return v.valid ? `chain INTACT (${v.receipt_count} receipts)` : `chain BROKEN at ${v.broken_at ?? "?"} — treat this principal's story as tampered`;
  } catch {
    return "receipt store unavailable";
  }
}

export default async function touched(args: string[]): Promise<void> {
  const si = args.indexOf("--since");
  const spec = si >= 0 ? args[si + 1] : "24h";
  const now = Date.now();
  const since = parseSince(spec ?? "24h", now);
  if (since === null) {
    process.stderr.write("usage: aegis touched [--since 24h|7d|90m|<ISO>] [--json]\n");
    process.exit(1);
  }

  const report: TouchedReport = aggregateTouched(
    readLines(join(AEGIS_DIR, "anumati.jsonl")),
    readLines(join(AEGIS_DIR, "tripwire.jsonl")),
    since,
    now,
  );

  const chains: Record<string, string> = {};
  for (const p of report.principals) chains[p.principal] = await receiptChain(p.principal);

  if (args.includes("--json")) {
    process.stdout.write(JSON.stringify({ ...report, receipt_chains: chains }, null, 2) + "\n");
    process.exit(0);
  }

  let out = `# aegis touched — ${report.since} → ${report.until}\n\n`;
  if (!report.principals.length) {
    out += "No ledgered activity in the window.\n";
  }
  for (const p of report.principals) {
    const a = p.anumati, t = p.tripwire;
    out += `## ${p.principal}\n`;
    out += `- anumati: ${a.enforced_refusals} enforced refusal(s); observations: ${
      Object.entries(a.observations).map(([k, v]) => `${k}×${v}`).join(", ") || "none"}\n`;
    if (a.provenance.length) {
      out += `- outward writes (provenance):\n${a.provenance.map((x) => `    - [${x.verdict}] ${x.detail.slice(0, 140)}`).join("\n")}\n`;
    }
    if (t.hits || t.containment.length) {
      out += `- tripwire: ${t.hits} tell(s) [${t.kinds.join(", ")}]${
        t.containment.length ? `; containment: ${t.containment.map((c) => `${c.stage}${c.applied ? " (APPLIED)" : " (observe)"}`).join(" → ")}` : ""}\n`;
    }
    if (a.sample_targets.length) out += `- sample targets: ${a.sample_targets.map((s) => `\`${s}\``).join(" · ")}\n`;
    out += `- kernel receipts: ${chains[p.principal]}\n\n`;
  }
  out += `Totals: ${report.totals.anumati_rows} anumati row(s), ${report.totals.tripwire_rows} tripwire row(s)` +
    (report.totals.unparseable ? `, ${report.totals.unparseable} unparseable line(s) SKIPPED (they are not evidence)` : "") + `\n\n`;
  out += `CEILING (PRA-004): computed by this host about itself — survives a lying agent, not a compromised\n` +
    `host. An empty row means nothing LEDGERED (tool-route + tripwire visibility), never "nothing happened".\n`;

  process.stdout.write(out);
  process.exit(0);
}
