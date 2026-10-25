// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis outward-decline <proposal_hash> --reason "<why not>" [--kind send] [--json]`
//
// The person says no to one exact outward act (ANU-019). Ledgered in ~/.aegis/outward.jsonl as a
// "declined" row; the act is then refused before hand-off, even if its code was approved. A changed
// draft is a new act, and should name this one as `supersedes` (ANU-018).
//
// Exit: 0 declined · 2 refused (an agent session, no such act, no reason) · 3 broke.
//
// Who: refused when CLAUDE_CODE_SESSION_ID is set, so the record's "declined" means a person's no.
// Ceiling: an agent that clears the variable can write the row; that only stops its own act.

import { declinedEntry, isDeclined, ledgerOutward, readOutwardLedger } from "../../kavach/outward";

const flag = (args: string[], k: string): string | undefined => {
  const i = args.indexOf(k);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : undefined;
};

export default async function outwardDecline(args: string[]): Promise<void> {
  const json = args.includes("--json");
  const say = (o: Record<string, unknown>, code: number): never => {
    if (json) process.stdout.write(JSON.stringify(o) + "\n");
    else for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null) process.stdout.write(`${k}: ${v}\n`);
    process.exit(code);
  };
  try {
    const hash = args.find((a) => /^[0-9a-f]{64}$/.test(a));
    const reason = flag(args, "--reason")?.trim() ?? "";
    const kind = flag(args, "--kind") ?? "send";
    if (!hash) {
      process.stderr.write(`usage: aegis outward-decline <proposal_hash> --reason "<why not>" [--kind send] [--json]\n`);
      process.exit(3);
    }
    if (process.env.CLAUDE_CODE_SESSION_ID?.trim()) say({ declined: false, reason: "ANU-019: declining is the person's, at their own terminal; an agent session does not write it" }, 2);
    if (!reason) say({ declined: false, reason: "give --reason: the record is for reading later" }, 2);
    const ledger = readOutwardLedger();
    if (!ledger.some((e) => e.event === "decided" && e.kind === kind && e.proposal_hash === hash)) {
      say({ declined: false, reason: `no ${kind} proposal ${hash.slice(0, 16)}… in the outward ledger` }, 2);
    }
    if (isDeclined(ledger, kind, hash!)) say({ declined: true, proposal_hash: hash, note: "already declined" }, 0);
    ledgerOutward(declinedEntry(kind, hash!, reason, null));
    say({ declined: true, kind, proposal_hash: hash, reason }, 0);
  } catch (e: any) {
    process.stderr.write(`outward-decline broke: ${e?.message ?? e}\n`);
    process.exit(3);
  }
}
