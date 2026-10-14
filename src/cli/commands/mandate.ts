// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis mandate — the roots of authority of this machine's flows (governed-turn-protocol §19, P3).
//
//   aegis mandate list              every mandate, newest first, with its status
//   aegis mandate show <id>         one mandate (the principal's identifier is shown in part)
//   aegis mandate revoke <id> [why] revoke it: every later call in that flow is refused in enforce mode
//                                   (recorded in monitor mode), and it is never reissued in that session
//
// @rule:GTP-022 revocation is a person's act. It writes into the aegis directory, which the shield keeps
// tool calls out of: run it from your own terminal. Exit: 0 done · 1 not found / bad input.

import { judgeMandate, listMandates, loadMandateById, revokeMandate, revokedIds } from "../../kavach/mandate";
import type { Mandate } from "../../kavach/mandate";

const partial = (p: string): string => p.replace(/\d(?=\d{4})/g, "•");
const expires = (m: Mandate): string => new Date(Date.parse(m.issued_at) + m.ttl_seconds * 1000).toISOString();

export default async function mandate(args: string[]): Promise<void> {
  const [sub, id, ...rest] = args;
  const revoked = revokedIds();
  if (!sub || sub === "list") {
    const all = listMandates();
    if (all.length === 0) { console.log("no mandates on this machine yet (one is issued at a session's first tool call)"); return; }
    for (const m of all) console.log(`${m.mudrika_id}  ${judgeMandate(m, new Date(), revoked).padEnd(9)}  ${m.agent_id}  mask=${m.trust_mask}  expires ${expires(m)}`);
    return;
  }
  if (sub === "show" || sub === "revoke") {
    const m = id ? loadMandateById(id) : null;
    if (!m) { console.error(`no mandate ${id ?? "(none given)"}`); process.exit(1); }
    if (sub === "show") {
      console.log(JSON.stringify({ ...m, principal_id: partial(m.principal_id), signature: m.signature ? "(present)" : "(missing)", status: judgeMandate(m, new Date(), revoked), expires_at: expires(m) }, null, 2));
      return;
    }
    if (revoked.has(m.mudrika_id)) { console.log(`${m.mudrika_id} was already revoked`); return; }
    const by = process.env.SUDO_USER ?? process.env.USER ?? "unknown";
    revokeMandate(m.mudrika_id, by, rest.join(" "));
    console.log(`revoked ${m.mudrika_id} (${m.agent_id}). In enforce mode every later call in that flow is refused (GTP-022); in monitor mode it is recorded.`);
    return;
  }
  console.error("usage: aegis mandate [list | show <id> | revoke <id> [reason]]");
  process.exit(1);
}
