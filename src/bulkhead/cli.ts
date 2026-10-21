// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis bulkhead <command>   (also: bun src/bulkhead/cli.ts <command>)
//
//   serve                                  run the bulkhead process on <dir>/bulkhead.sock
//   send  <token.json> <message.json>      send a FINDING / REQUEST / ACK
//   read  <token.json>                     read your messages (you are tainted by each one)
//   drop  <token.json> <message_id>        drop a taint early (written in the bell book)
//   close <compartment> "<reason>"         close every door of a compartment (anyone may close)
//   open  <door-or-compartment>            a PERSON re-opens it: raises its open epoch in doors.json (BLK-012)
//   status
//   verify                                 re-walk the bell book and each party's copy: exit 0 holds · 1 broken · 3 broke
//
// Doors between parties (P3, BLK-014..016):
//   party-terms <door-id>                  print the terms our doors file declares, for the other party to sign
//   party-keygen <prefix>                  THE OTHER PARTY, on its own machine: writes <prefix>.key (0600) and <prefix>.pub
//   party-sign <terms.json> <prefix>.key   THE OTHER PARTY: prints the signed declaration to send back
// A person then places <prefix>.pub at <dir>/parties/<party>/party.pub and the declaration at
// <dir>/parties/<party>/declarations/<door-id>.json (the shield refuses tool writes there, KAV-096).
//
// Directory: $AEGIS_BULKHEAD_DIR, else <aegis dir>/bulkhead (~/.aegis/bulkhead).

import { existsSync, readdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { verifyBellBook } from "./bell-book";
import { loadDoors, raiseOpenEpoch } from "./doors";
import { keygen, partiesDir, signTerms, termsOf } from "./parties";
import { call } from "./server";

export function bulkheadDir(): string {
  return process.env.AEGIS_BULKHEAD_DIR || join(getAegisDir(), "bulkhead");
}

export async function main(argv: string[]): Promise<void> {
  const dir = bulkheadDir();
  const [cmd, a, b] = argv;
  const json = (p: string) => JSON.parse(readFileSync(p, "utf-8"));
  const print = (x: unknown) => console.log(JSON.stringify(x, null, 2));
  try {
    switch (cmd) {
      case "serve": {
        const { Bulkhead } = await import("./bulkhead");
        const { sdtIdentity } = await import("./identity");
        const { serve } = await import("./server");
        const bh = new Bulkhead({ dir, identity: await sdtIdentity(), onAlarm: (x) => process.stderr.write(`[bulkhead] ALARM ${x.rule ?? ""} ${x.text}\n`) });
        serve(bh);
        process.stderr.write(`[bulkhead] serving on ${join(dir, "bulkhead.sock")} (doors: ${bh.doorsPath})\n`);
        return;
      }
      case "send": return print(await call(dir, { op: "send", token: json(a), message: json(b) }));
      case "read": return print(await call(dir, { op: "read", token: json(a) }));
      case "drop": return print(await call(dir, { op: "drop", token: json(a), message_id: b }));
      case "close": return print(await call(dir, { op: "close", compartment: a, reason: b, by: process.env.USER ?? "unknown" }));
      case "open": {
        if (!a) { console.error("usage: aegis bulkhead open <door-or-compartment>"); process.exit(2); }
        const epoch = raiseOpenEpoch(join(dir, "doors.json"), a);
        return print({ ok: true, id: a, open_epoch: epoch, note: "takes effect on the bulkhead's next decision" });
      }
      case "status": return print(await call(dir, { op: "status" }));
      case "verify": {
        const v = verifyBellBook(join(dir, "bell-book.jsonl"));
        // @rule:BLK-016 each party's copy is its own chain, walked the same way
        const pd = partiesDir(dir);
        const copies: Record<string, ReturnType<typeof verifyBellBook>> = {};
        if (existsSync(pd)) for (const p of readdirSync(pd)) {
          const f = join(pd, p, "bell-book.jsonl");
          if (existsSync(f)) copies[p] = verifyBellBook(f);
        }
        print(Object.keys(copies).length ? { ...v, copies } : v);
        process.exit(v.holds && Object.values(copies).every((c) => c.holds) ? 0 : 1);
      }
      case "party-terms": {
        const door = loadDoors(join(dir, "doors.json")).doors.find((d) => d.id === a);
        if (!door) { console.error(`no door ${a} in the doors file`); process.exit(2); }
        return print(termsOf(door));
      }
      case "party-keygen": {
        if (!a) { console.error("usage: aegis bulkhead party-keygen <prefix>"); process.exit(2); }
        if (existsSync(a + ".key")) { console.error(`${a}.key exists; not overwritten`); process.exit(2); }
        const k = keygen();
        writeFileSync(a + ".key", k.privateKey, { mode: 0o600 });
        writeFileSync(a + ".pub", k.publicKey);
        return print({ ok: true, private_key: a + ".key", public_key: a + ".pub", note: "keep the .key; send only the .pub" });
      }
      case "party-sign": {
        if (!a || !b) { console.error("usage: aegis bulkhead party-sign <terms.json> <prefix>.key"); process.exit(2); }
        return print(signTerms(json(a), readFileSync(b, "utf-8")));
      }
      default:
        console.error("usage: aegis bulkhead serve|send|read|drop|close|open|status|verify|party-terms|party-keygen|party-sign");
        process.exit(2);
    }
  } catch (e) {
    console.error(`bulkhead: ${(e as Error).message}`);
    process.exit(3);
  }
}

if (import.meta.main) await main(process.argv.slice(2));
