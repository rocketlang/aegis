// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis outward-record [--days N] [--json]`
//
// What the person did with the outward acts put to them, per kind and lane, from ~/.aegis/outward.jsonl
// (ANU-018). Read-only. It reports the numbers a loosening would rest on; it loosens nothing.
//
// Exit: 0 printed · 3 broke.

import { readOutwardLedger } from "../../kavach/outward";
import { outwardRecord, approvalRate, LAPSE_MS } from "../../kavach/outward-record";

export default async function outwardRecordCmd(args: string[]): Promise<void> {
  try {
    const i = args.indexOf("--days");
    const days = i >= 0 ? Number(args[i + 1]) : NaN;
    if (i >= 0 && !(Number.isFinite(days) && days > 0)) throw new Error("--days needs a positive number");
    const now = new Date();
    const since = Number.isFinite(days) ? new Date(now.getTime() - days * 86_400_000) : undefined;
    const rows = outwardRecord(readOutwardLedger(), { now, since });
    if (args.includes("--json")) {
      process.stdout.write(JSON.stringify({ since: since?.toISOString() ?? null, lapse_minutes: LAPSE_MS / 60_000, rows: rows.map((r) => ({ ...r, approval_rate: approvalRate(r) })) }) + "\n");
      process.exit(0);
    }
    process.stdout.write(`Outward record${since ? ` since ${since.toISOString().slice(0, 10)}` : ""}. One count per proposal. An ask unanswered after ${LAPSE_MS / 60_000} min is lapsed.\n`);
    if (!rows.length) process.stdout.write("No outward act in the ledger.\n");
    for (const r of rows) {
      const rate = approvalRate(r);
      process.stdout.write(
        `${r.kind} ${r.budget_key ?? "(no lane)"}: ${r.proposals} proposal(s), ${r.sent} sent, ${r.refused} refused; ` +
        `asked ${r.asked}: ${r.approved} approved, ${r.declined} declined, ${r.cleared} cleared by a later judgement, ${r.lapsed} lapsed, ${r.waiting} waiting` +
        `${rate === null ? "" : ` (approved ${Math.round(rate * 100)}%)`}; ${r.redrafts} redraft(s); ${r.with_why} of ${r.proposals} said why\n`);
    }
    process.stdout.write("Approvals given for an act that was never run again show as lapsed. This report changes nothing.\n");
    process.exit(0);
  } catch (e: any) {
    process.stderr.write(`outward-record broke: ${e?.message ?? e}\n`);
    process.exit(3);
  }
}
