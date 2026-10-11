// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.

// aegis ledger-pin --from <public key file> [--socket <path>] [--replace] [--unchecked]
//
// A PERSON runs this, as root, once, after the ledger authority is set up. It puts the authority's
// public key at /etc/aegis/ledger-signing.pub, the one place a gate reads it from that nothing in the
// environment or the aegis home can replace. Until that file exists a gate cannot tell the authority's
// answer from anyone else's, and says so on every refusal.
//
// Through 2.17.0 nothing in the package did this step: it was one sentence in the changelog, so an
// install with an authority ran unchecked (pointed out by Andrey Lazarev, 11 October 2026).
//
// WHAT IT CHECKS BEFORE WRITING
//   - the key file is a regular file (not a link) that only its owner can write;
//   - the authority at the socket says this is its key, and that it answers with receipts (2.16.3 or
//     later). A gate with a pinned key refuses the answers of an older authority, every one.
//   - no other key is pinned already (--replace to change it).
//
// WHERE THE TRUST SITS: the key comes from the file YOU name, never from the socket. The socket is found
// through the environment or a pointer file the gates' own account can write, so what answers there is
// only asked "is this your key"; a false authority can say no, or say yes to a key you chose, and
// neither gets its own key pinned. --unchecked skips the question (for a box where the authority is not
// running yet). Where the agent runs as root, the pinned file is one it can rewrite.
//
// Exit: 0 pinned (or already pinned to this key) · 1 refused, with the reason · 3 broke.

import { chownSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { createHash, createPublicKey } from "crypto";
import { dirname } from "path";
import { PINNED_LEDGER_KEY_PATH, ledgerSocket } from "../../core/refusal-ledger";
import { remoteLedgerStatus } from "../../kavach/approver-client";

const say = (s: string) => process.stdout.write(`[ledger-pin] ${s}\n`);
const refuse = (s: string): never => { process.stderr.write(`[ledger-pin] NOT PINNED — ${s}\n`); process.exit(1); };
const same = (a: string, b: string) => a.replace(/\s+/g, "") === b.replace(/\s+/g, "");

export function keyFingerprint(pem: string): string {
  return createHash("sha256").update(createPublicKey(pem).export({ type: "spki", format: "der" })).digest("hex").slice(0, 16);
}

export default async function ledgerPin(args: string[]): Promise<void> {
  const flag = (n: string) => { const i = args.indexOf(n); return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined; };
  const from = flag("--from");
  // --to is for tests and for packaging into an image; a gate reads only the system path.
  const to = flag("--to") || PINNED_LEDGER_KEY_PATH;
  const replace = args.includes("--replace"), unchecked = args.includes("--unchecked");
  try {
    if (!from) refuse("name the authority's public key file: aegis ledger-pin --from <authority store>/ledger-signing.pub");
    if (to === PINNED_LEDGER_KEY_PATH && typeof process.getuid === "function" && process.getuid() !== 0) {
      refuse(`${PINNED_LEDGER_KEY_PATH} is a system file; run this as root. (A key the gates' own account could write would pin nothing.)`);
    }
    if (!existsSync(from!)) refuse(`no file at ${from}`);
    const st = lstatSync(from!);
    if (!st.isFile()) refuse(`${from} is not a regular file (a link is not followed: name the file itself)`);
    if (st.mode & 0o022) refuse(`${from} can be written by its group or by anyone (mode ${(st.mode & 0o777).toString(8)}); a key anyone can replace is not a key to pin`);
    // Run through sudo from the agent's own account, a key file that account owns is the agent's to have written.
    const cameFrom = parseInt(process.env.SUDO_UID || "", 10);
    if (Number.isFinite(cameFrom) && cameFrom !== 0 && st.uid === cameFrom && !args.includes("--own-file")) {
      refuse(`${from} belongs to the account you came from (uid ${cameFrom}). The authority's key is written by the authority's account, in its own folder. If this really is the file: --own-file.`);
    }
    const pem = readFileSync(from!, "utf-8");
    let fp: string;
    try { fp = keyFingerprint(pem); } catch { return refuse(`${from} is not a public key`); }

    if (!unchecked) {
      const socket = flag("--socket") || ledgerSocket();
      if (!socket) refuse("no authority socket is configured, so the authority could not be asked whether this is its key. Name it with --socket, or pass --unchecked if the authority is not running yet.");
      const status = await remoteLedgerStatus(socket!).catch(() => null);
      if (!status) refuse(`nothing answered at ${socket}. Start the authority first, or pass --unchecked.`);
      if (typeof status!.public_key !== "string" || !same(status!.public_key as string, pem)) {
        refuse(`what answers at ${socket} says its key is another one. Either that is not this authority, or ${from} is not its key. Nothing was written.`);
      }
      if (status!.receipts !== true) {
        refuse(`the authority at ${socket} is older than 2.16.3: it answers without a signed row, and a gate with a pinned key would refuse every answer as not signed. Upgrade the authority first.`);
      }
    }

    if (existsSync(to)) {
      const cur = readFileSync(to, "utf-8");
      if (same(cur, pem)) { say(`already pinned: ${to} holds this key (${fp})`); process.exit(0); }
      if (!replace) refuse(`${to} already holds ANOTHER key. Changing the pinned key changes whose answers every gate on this box believes. If that is what you mean: --replace.`);
    }
    mkdirSync(dirname(to), { recursive: true, mode: 0o755 });
    const tmp = `${to}.${process.pid}.tmp`;
    writeFileSync(tmp, pem, { mode: 0o644 });
    if (to === PINNED_LEDGER_KEY_PATH) { try { chownSync(tmp, 0, 0); } catch { /* already root's */ } }
    renameSync(tmp, to);
    say(`the key file ${from} belongs to uid ${st.uid}`);
    say(`pinned ${fp} at ${to}${unchecked ? " — the authority was NOT asked whether this is its key" : ""}`);
    say("every gate on this box now checks the authority's answer against it; an answer that does not verify is written as NOT signed and said on stderr");
    if (typeof process.getuid === "function" && process.getuid() === 0) say("note: an agent that runs as root can rewrite this file. The pin holds against an agent under another account.");
    process.exit(0);
  } catch (e) {
    process.stderr.write(`[ledger-pin] BROKE — ${(e as Error).message}\n`);
    process.exit(3);
  }
}
