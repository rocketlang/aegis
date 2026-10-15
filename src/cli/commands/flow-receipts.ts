// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis flow-receipts — the chain of signed flow receipts (governed-turn-protocol §19, P5, gap 3).
//
//   aegis flow-receipts verify                 walk the chain: order, links, hashes, signatures, and that every
//                                              head once published is still in place
//                                              exit 0 holds · 1 broken (each break named) · 3 could not check
//   aegis flow-receipts head                   the newest link, {seq, hash}
//   aegis flow-receipts keygen --out <file>    make the anchoring key (ECDSA P-256), owner-only; prints the
//                                              public half to publish. Refuses to overwrite. A person's step.
//   aegis flow-receipts anchor --key <file> [--dry-run] [--url <log>]
//                                              publish the head in Sigstore's public log (Rekor). Refuses a
//                                              broken chain or a key others can read; checks the log's reply
//                                              holds our hash under our key. Every entry is permanent and public.
//                                              exit 0 anchored (or already) · 1 the log refused · 2 refused here · 3 broke

import { verifyChain } from "../../kavach/receipt-chain";
import { REKOR_URL, loadKey, makeKey, readAnchors, recordAnchor, sendHead } from "../../kavach/public-anchor";

const flag = (args: string[], name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

export default async function flowReceipts(args: string[]): Promise<void> {
  const sub = args[0] ?? "verify";

  if (sub === "keygen") {
    const out = flag(args, "--out");
    if (!out) { console.error("usage: aegis flow-receipts keygen --out <file>"); process.exit(3); }
    try {
      const { publicPem, fingerprint } = makeKey(out);
      console.log(`key written to ${out} (owner-only). Fingerprint ${fingerprint}. Public half, to publish:\n${publicPem}`);
      process.exit(0);
    } catch (e) { console.error(String((e as Error).message)); process.exit(2); }
  }

  let c;
  try { c = verifyChain(); } catch (e) { console.error(`could not check: ${(e as Error).message}`); process.exit(3); }

  if (sub === "head") { console.log(JSON.stringify(c.head ?? { seq: 0, hash: null })); process.exit(0); }

  if (sub === "verify") {
    if (c.ok) console.log(`chain holds: ${c.count} receipt(s)${c.head ? `, head seq ${c.head.seq} ${c.head.hash}` : ""}; ${readAnchors().length} head(s) published`);
    else { console.log(`chain BROKEN (${c.problems.length} problem(s) in ${c.count} receipt(s)):`); for (const p of c.problems) console.log(`  - ${p}`); }
    process.exit(c.ok ? 0 : 1);
  }

  if (sub === "anchor") {
    const keyPath = flag(args, "--key") ?? process.env.AEGIS_FLOW_ANCHOR_KEY;
    const url = flag(args, "--url") ?? REKOR_URL;
    const dry = args.includes("--dry-run");
    if (!c.ok) { console.error(`refused: the chain does not verify (${c.problems.length} problem(s)); run 'aegis flow-receipts verify'`); process.exit(2); }
    if (!c.head) { console.log("nothing to anchor: the chain is empty"); process.exit(0); }
    if (readAnchors().some((a) => a.seq === c.head!.seq && a.hash === c.head!.hash)) { console.log(`head seq ${c.head.seq} is already anchored`); process.exit(0); }
    if (!keyPath) { console.error("refused: no key (--key <file> or AEGIS_FLOW_ANCHOR_KEY)"); process.exit(2); }
    let key: string;
    try { key = loadKey(keyPath); } catch (e) { console.error(`refused: ${(e as Error).message}`); process.exit(2); }
    if (dry) { console.log(`dry run: would publish head seq ${c.head.seq} ${c.head.hash} to ${url}. Nothing was sent.`); process.exit(0); }
    const r = sendHead(c.head.hash, key!, url);
    if (!r.ok || !r.entry) { console.error(`not anchored: ${r.problems.join("; ")}`); process.exit(1); }
    recordAnchor({ seq: c.head.seq, hash: c.head.hash, uuid: r.entry.uuid, log_index: r.entry.index, integrated_time: r.entry.at, log: url, at: new Date().toISOString() });
    console.log(`anchored head seq ${c.head.seq} ${c.head.hash}: log entry ${r.entry.index ?? r.entry.uuid}`);
    process.exit(0);
  }

  console.error("usage: aegis flow-receipts [verify | head | keygen --out <file> | anchor --key <file> [--dry-run] [--url <log>]]");
  process.exit(3);
}
