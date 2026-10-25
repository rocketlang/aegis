// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// `aegis outward-send (--proposal '<json>' | --proposal-file <path>) [--dry-run] [--json]`
//
// One message through the send guard (ANU-I-012) to ankr-mailer. Judged against the live send
// mandates (`aegis outward-mandate grant send …`), judged again just before hand-off, asked of the
// person when a check asks (code for `aegis approve-destructive <code>`), then sent by the mailer.
// Every decision is ledgered in ~/.aegis/outward.jsonl. --dry-run judges only: nothing is sent and
// nothing is ledgered (a dry run must not spend the day's budget).
//
// Exit: 0 sent (or, with --dry-run, would be permitted) · 1 the mailer failed · 2 refused, or waiting
// for the person · 3 broke. Never falls back to sending some other way.
//
// Who is acting: CLAUDE_CODE_SESSION_ID names an agent session, whose aegis flow mandate must judge
// valid (ANU-012). With none set the run is taken as a person's at their own terminal. Ceiling: an
// agent that clears the variable looks like a person, and is then bound by the mandate alone, which
// only a person can grant (KAV-101).

import { readFileSync } from "fs";
import {
  judgeOutward, executeOutward, decidedEntry, ledgerOutward, readOutwardMandates, readOutwardLedger, aegisApprovals,
  type OutwardContext, type OutwardDecision,
} from "../../kavach/outward";
import { sendPlugin, type SendProposal } from "../../kavach/outward-send";
import { mailerEffector, mailerUrl } from "../../kavach/outward-mailer";
import { mandateForCall } from "../../kavach/mandate";

const flag = (args: string[], k: string): string | undefined => {
  const i = args.indexOf(k);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : undefined;
};

export function sessionFlow(env = process.env): { session: string | null; flowStatus: string; flowDetail?: string } {
  const session = env.CLAUDE_CODE_SESSION_ID?.trim() || null;
  if (!session) return { session: null, flowStatus: "valid" }; // a person at their own terminal
  const f = mandateForCall(session);
  return f.status === "valid"
    ? { session, flowStatus: "valid" }
    : { session, flowStatus: f.status, flowDetail: `ANU-012: agent session ${session.slice(0, 8)}… has a flow mandate that is ${f.status}` };
}

function summary(d: OutwardDecision): Record<string, unknown> {
  return {
    verdict: d.verdict, ask: d.ask, stage: d.stage, proposal_hash: d.proposal_hash, mandate_id: d.mandate_id, why: d.why, supersedes: d.supersedes,
    refusals: d.refusals.map((r) => `${r.id}: ${r.detail}`),
    observations: d.observations.map((r) => `${r.id}: ${r.detail}`),
    asked: d.asked.map((r) => `${r.id}: ${r.detail}`),
  };
}

export default async function outwardSend(args: string[]): Promise<void> {
  const json = args.includes("--json");
  const dry = args.includes("--dry-run");
  const say = (o: Record<string, unknown>, code: number): never => {
    if (json) process.stdout.write(JSON.stringify(o) + "\n");
    else {
      for (const [k, v] of Object.entries(o)) {
        if (Array.isArray(v)) { if (v.length) process.stdout.write(`${k}:\n${v.map((x) => `  - ${x}`).join("\n")}\n`); }
        else if (v !== undefined && v !== null) process.stdout.write(`${k}: ${v}\n`);
      }
    }
    process.exit(code);
  };

  let proposal: SendProposal;
  try {
    const inline = flag(args, "--proposal");
    const file = flag(args, "--proposal-file");
    if ((inline ? 1 : 0) + (file ? 1 : 0) !== 1) throw new Error("give exactly one of --proposal or --proposal-file");
    proposal = JSON.parse(inline ?? readFileSync(file!, "utf8"));
  } catch (e: any) {
    process.stderr.write(`usage: aegis outward-send (--proposal '<json>' | --proposal-file <path>) [--dry-run] [--json]\n${e?.message ?? e}\n`);
    process.exit(3);
  }

  try {
    const who = sessionFlow();
    const ctx = (): OutwardContext<unknown> => ({
      session_id: who.session, now: new Date(), mandates: readOutwardMandates(), ledger: readOutwardLedger(),
      flowStatus: who.flowStatus, flowDetail: who.flowDetail,
    });
    const d = judgeOutward(sendPlugin, proposal!, ctx());
    const base = summary(d);
    if (d.stage === "observe" && d.observations.length) base.note = "send is in OBSERVE: the observations above would refuse once the founder promotes it";

    if (dry) say({ ...base, dry_run: true, sent: false }, d.verdict === "PERMIT" ? 0 : 2);

    ledgerOutward(decidedEntry(d, who.session));
    if (d.verdict !== "PERMIT") say({ ...base, sent: false }, 2);

    let effector;
    try { effector = mailerEffector(mailerUrl()); } catch (e: any) { say({ ...base, sent: false, reason: e?.message ?? String(e) }, 2); }
    const r = await executeOutward(sendPlugin, proposal!, d, effector!, await aegisApprovals(), { fresh: ctx, session: who.session });
    if (r.done) say({ ...base, sent: true, ref: r.ref }, 0);
    else say({
      ...base, sent: false, reason: r.reason,
      approval_code: r.approval_code,
      next: r.approval_code ? `a person approves in their own terminal: aegis approve-destructive ${r.approval_code} — then run this send again; or says no: aegis outward-decline ${d.proposal_hash} --reason "<why not>"` : undefined,
    }, r.reason.startsWith("effector ") ? 1 : 2);
  } catch (e: any) {
    process.stderr.write(`outward-send broke: ${e?.message ?? e}\n`);
    process.exit(3);
  }
}
