// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis flow-receipts — the chain of signed flow receipts (governed-turn-protocol §19, P5, gap 3).
//
//   aegis flow-receipts verify   walk the whole chain: order, links, file hashes, signatures
//                                exit 0 holds · 1 broken (each break named) · 3 could not check
//   aegis flow-receipts head     the newest link, {seq, hash}: the value to publish in a public log
//
// Publishing the head is what makes cutting the end of the chain visible. Sending it is a person's step.

import { verifyChain } from "../../kavach/receipt-chain";

export default async function flowReceipts(args: string[]): Promise<void> {
  const sub = args[0] ?? "verify";
  let c;
  try { c = verifyChain(); } catch (e) { console.error(`could not check: ${(e as Error).message}`); process.exit(3); }
  if (sub === "head") {
    console.log(JSON.stringify(c.head ?? { seq: 0, hash: null }));
    process.exit(0);
  }
  if (sub === "verify") {
    if (c.ok) console.log(`chain holds: ${c.count} receipt(s)${c.head ? `, head seq ${c.head.seq} ${c.head.hash}` : ""}`);
    else { console.log(`chain BROKEN (${c.problems.length} problem(s) in ${c.count} receipt(s)):`); for (const p of c.problems) console.log(`  - ${p}`); }
    process.exit(c.ok ? 0 : 1);
  }
  console.error("usage: aegis flow-receipts [verify | head]");
  process.exit(3);
}
